"""API: CrowdSec virtual patching rules (hub.py) and uploads in parts (uploads.py) for the hub and the OWASP CRS."""
import os
import re
import shutil

from .. import hub, uploads, util
from .server import ApiError, json_response

V = '/api/v1'


def _words(s):
    return [w for w in re.findall(r'[a-z0-9]+', (s or '').lower()) if len(w) >= 3]


def _related(rule, products):
    """The confirmed software a rule's label or description names (every word of the product's name appears)."""
    text = ' '.join([rule.get('label') or '', rule.get('description') or '', rule.get('name') or '']).lower()
    have = set(re.findall(r'[a-z0-9]+', text))
    out = []
    for p in products:
        w = _words(p['name'])
        if w and all(x in have for x in w):
            out.append({'name': p['name'], 'sites': p['sites']})
    return out


def _products(app):
    from .. import software
    names = [r['name'] for r in app.db.q('SELECT DISTINCT name FROM software WHERE confirmed=1 ORDER BY name')]
    return [{'name': n, 'sites': software.hosts_of(app.db, n)} for n in names]


def hub_status(app, req):
    idx = hub.read_index(app.cfg) or {}
    products = _products(app)
    rules = []
    for r in idx.get('rules') or []:
        rel = _related(r, products)
        rules.append({k: r.get(k) for k in ('name', 'path', 'label', 'description', 'cves', 'cwes', 'product', 'behavior',
                                            'confidence', 'ok', 'reason', 'details', 'rule_count', 'change', 'sha256')}
                     | {'related': rel})
    st = hub.read_status(app.cfg)
    return json_response(200, {
        'enabled': bool(app.cfg['hub']['enabled']), 'status': st, 'commit': idx.get('commit'), 'source': idx.get('source'),
        'synced_at': idx.get('synced_at'), 'previous_commit': idx.get('previous_commit'), 'counts': idx.get('counts') or {},
        'removed': idx.get('removed') or [], 'license_sha256': idx.get('license_sha256'),
        'requested': os.path.exists(os.path.join(hub.hub_dir(app.cfg), hub.REQUEST)) or st.get('state') == 'running',
        'related_count': sum(1 for r in rules if r['related']), 'rules': rules})


def hub_rule(app, req):
    """One rule: the hub's text as it is (shown as text), the converted ModSecurity rule or why there is none."""
    name = req.query.get('name') or ''
    idx = hub.read_index(app.cfg) or {}
    r = next((x for x in idx.get('rules') or [] if x.get('name') == name), None)
    if r is None:
        raise ApiError(404, 'not_found')
    return json_response(200, dict(r, related=_related(r, _products(app)), commit=idx.get('commit')))


def hub_license(app, req):
    idx = hub.read_index(app.cfg) or {}
    return json_response(200, {'license': idx.get('license') or '', 'commit': idx.get('commit'), 'sha256': idx.get('license_sha256')})


def hub_sync(app, req):
    """Admin: download the newest commit now (when switched on in Settings)."""
    if not app.cfg['hub']['enabled']:
        raise ApiError(409, 'hub_off', 'switch on the CrowdSec rules in Settings first, or upload an archive')
    try:
        hub.request_sync(app.cfg)
    except OSError as e:
        raise ApiError(500, 'request_failed', str(e)[:200])
    app.audit.log('hub.sync_requested', req.user['username'], 'user', req.client_ip, 'ok')
    return json_response(202, {'requested': True})


# --- uploads in parts ------------------------------------------------------------------------------------------------

def _upload_error(e):
    return ApiError(e.status, e.code, e.code.replace('_', ' '), **e.details)


def upload_start(app, req):
    b = req.body()
    try:
        out = uploads.start(app.cfg, b.get('kind'), b.get('name'), b.get('size'), str(b.get('sha256') or '').lower(),
                            req.user['username'])
    except uploads.UploadError as e:
        raise _upload_error(e)
    app.audit.log('upload.started', req.user['username'], 'user', req.client_ip, 'ok', kind=b.get('kind'), name=b.get('name'),
                  size=b.get('size'), sha256=b.get('sha256'), upload_id=out['id'])
    return json_response(201, out)


def upload_chunk(app, req):
    b = req.body()
    idx = b.get('index')
    if not isinstance(idx, int) or isinstance(idx, bool):
        raise ApiError(400, 'bad_request', 'index: the number of the piece, from 0')
    try:
        out = uploads.chunk(app.cfg, req.params['id'], idx, b.get('data'), req.user['username'])
    except uploads.UploadError as e:
        raise _upload_error(e)
    return json_response(200, out)


def upload_finish(app, req):
    """The whole file is here and matches: hand it to the job that reads it (the hub sync or the CRS check)."""
    b = req.body()
    uid = req.params['id']
    try:
        path, meta = uploads.finish(app.cfg, uid, req.user['username'])
    except uploads.UploadError as e:
        app.audit.log('upload.refused', req.user['username'], 'user', req.client_ip, 'denied', reason=e.code, upload_id=uid)
        raise _upload_error(e)
    try:
        if meta['kind'] == 'hub':
            dest = os.path.join(hub.hub_dir(app.cfg), hub.UPLOAD_DIR)
            os.makedirs(dest, mode=0o750, exist_ok=True)
            shutil.move(path, os.path.join(dest, meta['name']))
            hub.request_sync(app.cfg, 'upload')
        else:
            from .. import crsupdate
            if not crsupdate.UPLOAD_NAME.match(meta['name']):
                raise ApiError(422, 'invalid_name', 'expected coreruleset-<version>-minimal.tar.gz')
            asc = str(b.get('asc') or '')
            if not asc.strip().startswith('-----BEGIN PGP SIGNATURE-----') or len(asc) > 16384:
                raise ApiError(422, 'signature_required', 'the .asc signature file of the release is required')
            dest = os.path.join(app.cfg['crs']['dir'], crsupdate.UPLOAD_DIR)
            shutil.rmtree(dest, ignore_errors=True)
            os.makedirs(dest, mode=0o750)
            shutil.move(path, os.path.join(dest, meta['name']))
            with open(os.path.join(dest, meta['name'] + '.asc'), 'w', encoding='ascii', errors='replace') as fh:
                fh.write(asc)
            crsupdate.request_check(app.cfg)
    finally:
        uploads.discard(app.cfg, uid)
    app.audit.log('upload.finished', req.user['username'], 'user', req.client_ip, 'ok', kind=meta['kind'], name=meta['name'],
                  size=meta['size'], sha256=meta['sha256'], upload_id=uid)
    return json_response(202, {'accepted': True, 'kind': meta['kind'], 'name': meta['name'], 'at': util.iso(util.now())})


def register(router):
    R = router.add
    R('GET', V + '/hub', hub_status, ('role', 'viewer', 'rules:read'))
    R('GET', V + '/hub/rule', hub_rule, ('role', 'viewer', 'rules:read'))
    R('GET', V + '/hub/license', hub_license, ('role', 'viewer', 'rules:read'))
    R('POST', V + '/hub/sync', hub_sync, ('admin',))
    R('POST', V + '/uploads', upload_start, ('admin',))
    R('POST', V + '/uploads/{id}/chunk', upload_chunk, ('admin',))
    R('POST', V + '/uploads/{id}/finish', upload_finish, ('admin',))
