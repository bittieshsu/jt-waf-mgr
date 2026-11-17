"""API: getting ready for the next nginx update (nginxmod.py: is the module loaded and will it keep up; nginxup.py: the
next nginx package tried with the waiting module)."""
import json
import os
import re
import shutil

from .. import nginxmod, nginxup, util
from .server import ApiError, json_response

V = '/api/v1'
DESC_KEYS = {'module': str, 'sha256': str, 'nginx_version': str, 'nginx_package': str, 'connector': str,
             'libmodsecurity': str, 'os': str, 'arch': str, 'built_at': str, 'source': str}


def update_status(app, req):
    st = nginxmod.status(app)
    lvl, why = nginxmod.level(st)
    up = st.get('update') or {}
    job = nginxup.read_status(app.cfg)
    waiting = []
    mroot = os.path.join(nginxup.base(app.cfg), 'modules')
    for n in sorted(os.listdir(mroot)) if os.path.isdir(mroot) else []:
        p = os.path.join(mroot, n)
        meta = {}
        try:
            with open(os.path.join(p, 'module.json'), encoding='utf-8') as fh:
                meta = json.load(fh)
        except (OSError, ValueError):
            pass
        waiting.append({'for': n, 'sha256': meta.get('sha256'), 'uploaded_by': meta.get('uploaded_by'),
                        'uploaded_at': meta.get('uploaded_at'), 'os': meta.get('os'), 'connector': meta.get('connector'),
                        'libmodsecurity': meta.get('libmodsecurity')})
    return json_response(200, {
        'level': lvl, 'reason': why, 'nginx_version': st.get('nginx_version'), 'modules': st.get('modules'),
        'modsecurity_module': st.get('modsecurity_module'), 'static': st.get('static'), 'load': st.get('load'),
        'package': up.get('nginx_package'), 'installed': up.get('installed'), 'candidate': up.get('candidate'),
        'update': up.get('update'), 'held': up.get('held'), 'supported': up.get('supported'),
        'hand_built': up.get('hand_built') or [], 'module_packages': [m for m in up.get('modules') or [] if m.get('package')],
        'check': job, 'waiting': waiting, 'checked_at': st.get('checked_at')})


def update_check(app, req):
    """Admin: try the next nginx package with the waiting module now."""
    try:
        nginxup.request_check(app.cfg)
    except OSError as e:
        raise ApiError(500, 'request_failed', str(e)[:200])
    app.audit.log('nginx.update_check_requested', req.user['username'], 'user', req.client_ip, 'ok')
    return json_response(202, {'requested': True})


def receive_module(app, path, meta, body, actor):
    """An uploaded module (from upload_finish): keep it for the nginx package version it was built for, then try it."""
    desc = body.get('description')
    if desc is not None:
        if isinstance(desc, str):
            try:
                desc = json.loads(desc)
            except ValueError:
                raise ApiError(422, 'invalid_description', 'module.json is not JSON')
        if not isinstance(desc, dict):
            raise ApiError(422, 'invalid_description', 'module.json must be an object')
        desc = {k: util.clip(str(v), 200) for k, v in desc.items() if k in DESC_KEYS and isinstance(v, (str, int, float))}
        if desc.get('sha256') and desc['sha256'].lower() != meta['sha256']:
            raise ApiError(422, 'description_mismatch', 'the module is not the one module.json describes (SHA-256)')
    else:
        desc = {}
    with open(path, 'rb') as fh:
        if fh.read(4) != b'\x7fELF':
            raise ApiError(422, 'not_a_module', 'not a shared object (ELF) file')
    target = str(body.get('nginx_package') or desc.get('nginx_package') or '')
    if not target:
        up = nginxmod.status(app).get('update') or {}
        target = up.get('candidate') or ''
    try:
        mdir = nginxup.module_dir(app.cfg, target)
    except ValueError:
        raise ApiError(422, 'no_target', 'which nginx package is the module for? (module.json from the build script, or nginx_package)')
    tmp = mdir + '.new'
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, mode=0o750)
    shutil.move(path, os.path.join(tmp, nginxup.MODULE_NAME))
    desc.update(sha256=meta['sha256'], uploaded_by=actor, uploaded_at=util.iso(util.now()), nginx_package=target)
    with open(os.path.join(tmp, 'module.json'), 'w', encoding='utf-8') as fh:
        json.dump(desc, fh, ensure_ascii=False)
    shutil.rmtree(mdir, ignore_errors=True)
    os.replace(tmp, mdir)
    nginxup.request_check(app.cfg)
    return target


def register(router):
    R = router.add
    R('GET', V + '/nginx/update', update_status, ('role', 'viewer', 'rules:read'))
    R('POST', V + '/nginx/update/check', update_check, ('admin',))
