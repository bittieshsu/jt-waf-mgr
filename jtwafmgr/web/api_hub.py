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
    """The confirmed software a rule is about: its product (the label before " - ") or its name names every word of the
    product's name. Not the description: it mentions other software in passing ("an RCE through Lua")."""
    label = rule.get('label') or ''
    about = rule.get('product') or (label.split(' - ')[0] if label else '') or (rule.get('description') or '' if not label else '')
    text = ' '.join([about, (rule.get('name') or '').replace('-', ' ')]).lower()
    have = set(re.findall(r'[a-z0-9]+', text))
    out = []
    for p in products:
        w = _words(p['name'])
        if w and all(x in have for x in w):
            out.append({'name': p['name'], 'sites': p['sites']})
    return out


def _relation(rule, products):
    """(profile, related): the rule's scope and technologies, and the confirmed software it is about -- by its name
    ({'name', 'sites'}) or, for a cross-application rule, by a technology its stack runs on ({'name': tech, 'via': [...],
    'sites', 'tech': True})."""
    from .. import techstack
    prof = techstack.rule_profile(rule)
    rel = _related(rule, products)
    if prof['scope'] == 'cross':
        named = {p['name'] for p in rel}
        for t in techstack.related_by_tech(prof['match'], products):
            if not set(t['via']) <= named:
                rel.append(dict(t, tech=True))
    return prof, rel


def _products(app):
    from .. import software
    names = [r['name'] for r in app.db.q('SELECT DISTINCT name FROM software WHERE confirmed=1 ORDER BY name')]
    return [{'name': n, 'sites': software.hosts_of(app.db, n)} for n in names]


OPEN_STATES = ('checking', 'pending_approval', 'approved', 'applying')


def _in_use(app, idx):
    """The CrowdSec rules in the managed files ({name: ...}) and the changes still open for them ({name: ...})."""
    import json
    shas = {r.get('name'): r.get('sha256') for r in idx.get('rules') or []}
    applied, open_ = {}, {}
    wf = getattr(app, 'workflow', None)
    if wf is None:
        return applied, open_
    for it in wf.managed.items():
        if it['kind'] != 'crowdsec':
            continue
        try:
            sp = json.loads(it['spec'] or '{}')
        except ValueError:
            continue
        name = sp.get('name')
        if name in applied:
            # in force twice (two changes for the same rule, before 0.4.98): shown so a person can remove one
            applied[name].setdefault('others', []).append({'item_id': it['id'], 'rule_id': it['rule_id'],
                                                           'change_id': it.get('change_id'), 'hosts': sp.get('hosts') or [],
                                                           'all_sites': bool(sp.get('all_sites'))})
            continue
        applied[name] = {'item_id': it['id'], 'rule_id': it['rule_id'], 'rule_count': sp.get('rule_count') or 1,
                         'enabled': bool(it['enabled']), 'sha256': sp.get('sha256'), 'commit': sp.get('commit'),
                         'hosts': sp.get('hosts') or [], 'all_sites': bool(sp.get('all_sites')), 'source': sp.get('source'),
                         'change_id': it.get('change_id'),
                         'upstream': ('removed' if name not in shas else 'same' if shas[name] == sp.get('sha256') else 'changed')}
    by_item = {a['item_id']: n for n, a in applied.items()}
    for c in app.db.q("SELECT id, op, kind, item_id, state, spec FROM changes WHERE (kind='crowdsec' OR op='bundle') "
                      "AND state IN (%s) ORDER BY id" % ','.join('?' * len(OPEN_STATES)), OPEN_STATES):
        try:
            spec = json.loads(c['spec'] or '{}')
            # several rules applied at once from this page are one change (a bundle): each of its rules is on its way
            ops = (spec.get('ops') or []) if c['op'] == 'bundle' else \
                [{'op': c['op'], 'kind': c['kind'], 'item_id': c['item_id'], 'spec': spec}]
        except (ValueError, AttributeError):
            continue
        for b in ops:
            if not isinstance(b, dict) or b.get('kind') not in ('crowdsec', None):
                continue
            name = (b.get('spec') or {}).get('name') if isinstance(b.get('spec'), dict) else None
            name = name or by_item.get(b.get('item_id'))
            if name and (b.get('kind') == 'crowdsec' or b.get('item_id') in by_item):
                open_.setdefault(name, {'change_id': c['id'], 'op': b.get('op'), 'state': c['state']})
    return applied, open_


def hub_status(app, req):
    idx = hub.read_index(app.cfg) or {}
    products = _products(app)
    applied, open_ = _in_use(app, idx)
    rules = []
    for r in idx.get('rules') or []:
        prof, rel = _relation(r, products)
        rules.append({k: r.get(k) for k in ('name', 'path', 'label', 'description', 'cves', 'cwes', 'product', 'behavior',
                                            'confidence', 'ok', 'reason', 'details', 'rule_count', 'change', 'sha256',
                                            'tests_reason', 'fp_warning')}
                     | {'related': rel, 'scope': prof['scope'], 'techs': prof['techs'],
                        'tests': sum(1 for t in r.get('tests') or [] if t.get('expect', 'refuse') == 'refuse'),
                        'applied': applied.get(r.get('name')), 'open_change': open_.get(r.get('name'))})
    names = {r.get('name') for r in idx.get('rules') or []}
    st = hub.read_status(app.cfg)
    return json_response(200, {
        'enabled': bool(app.cfg['hub']['enabled']), 'status': st, 'commit': idx.get('commit'), 'source': idx.get('source'),
        'synced_at': idx.get('synced_at'), 'previous_commit': idx.get('previous_commit'), 'counts': idx.get('counts') or {},
        'removed': idx.get('removed') or [], 'license_sha256': idx.get('license_sha256'),
        # synced by an older version: no upstream tests in it yet, so nothing can be proposed until the next sync
        'outdated_index': bool(idx.get('commit')) and idx.get('format') != hub.INDEX_FORMAT,
        'requested': os.path.exists(os.path.join(hub.hub_dir(app.cfg), hub.REQUEST)) or st.get('state') == 'running',
        'related_count': sum(1 for r in rules if r['related']), 'cross_count': sum(1 for r in rules if r['scope'] == 'cross'),
        'rules': rules,
        'applied_count': len(applied), 'outdated_count': sum(1 for a in applied.values() if a['upstream'] != 'same'),
        'applied_removed': [dict(a, name=n, open_change=open_.get(n)) for n, a in sorted(applied.items()) if n not in names]})


def hub_rule(app, req):
    """One rule: the hub's text as it is (shown as text), the converted ModSecurity rule or why there is none."""
    name = req.query.get('name') or ''
    idx = hub.read_index(app.cfg) or {}
    r = next((x for x in idx.get('rules') or [] if x.get('name') == name), None)
    if r is None:
        raise ApiError(404, 'not_found')
    applied, open_ = _in_use(app, idx)
    prof, rel = _relation(r, _products(app))
    return json_response(200, dict(r, related=rel, scope=prof['scope'], techs=prof['techs'], commit=idx.get('commit'),
                                   applied=applied.get(name), open_change=open_.get(name)))


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
    """The whole file is here and matches: hand it to the job that reads it (the hub sync, the CRS check, or the nginx
    update check for a ModSecurity module)."""
    b = req.body()
    uid = req.params['id']
    try:
        path, meta = uploads.finish(app.cfg, uid, req.user['username'])
    except uploads.UploadError as e:
        app.audit.log('upload.refused', req.user['username'], 'user', req.client_ip, 'denied', reason=e.code, upload_id=uid)
        raise _upload_error(e)
    extra = {}
    try:
        if meta['kind'] == 'nginxmod':
            from . import api_nginxup
            extra['nginx_package'] = api_nginxup.receive_module(app, path, meta, b, req.user['username'])
        elif meta['kind'] == 'hub':
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
                  size=meta['size'], sha256=meta['sha256'], upload_id=uid, **extra)
    return json_response(202, dict(extra, accepted=True, kind=meta['kind'], name=meta['name'], at=util.iso(util.now())))


def register(router):
    R = router.add
    R('GET', V + '/hub', hub_status, ('role', 'viewer', 'rules:read'))
    R('GET', V + '/hub/rule', hub_rule, ('role', 'viewer', 'rules:read'))
    R('GET', V + '/hub/license', hub_license, ('role', 'viewer', 'rules:read'))
    R('POST', V + '/hub/sync', hub_sync, ('admin',))
    R('POST', V + '/uploads', upload_start, ('admin',))
    R('POST', V + '/uploads/{id}/chunk', upload_chunk, ('admin',))
    R('POST', V + '/uploads/{id}/finish', upload_finish, ('admin',))
