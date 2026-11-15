"""Settings export and import: the settings people change in the web interface (uisettings.EDITABLE: servers,
notification channels, log destinations, policies...) and the change workflow's settings, as one JSON file.

- Export: every value; a secret (API key, password, token) only as "set" or "not set", unless the export is asked
  for with the secrets (a fresh one-time code in the web interface; the file then says so).
- Import: a preview first -- every setting of the file next to the current value, whether it differs, whether this
  version knows it, whether the value would be accepted. Then only the settings picked are written, all of them or
  none (each checked before any is stored, then the same checks as any save), each audited, plus one
  settings.imported record naming the file's program version and node.
"""
import json
import time

from . import __version__, uisettings, util

FORMAT = 'jt-waf-mgr-settings'
FORMAT_VERSION = 1
MAX_BYTES = 2 * 1024 * 1024


class ImportError_(Exception):
    def __init__(self, code, **details):
        super().__init__(code)
        self.code, self.details = code, details


def _wf(app):
    return getattr(app, 'workflow', None)


def export(app, secrets=False):
    cfg = app.cfg
    ui, secret_state = {}, {}
    for k, (kind, _) in uisettings.EDITABLE.items():
        sec, name = k.split('.', 1)
        v = cfg.data.get(sec, {}).get(name)
        if kind == 'secret':
            if secrets and v:
                ui[k] = v
            secret_state[k] = bool(v)
        else:
            ui[k] = v
    wf = _wf(app)
    return {'format': FORMAT, 'format_version': FORMAT_VERSION, 'program': 'jt-waf-mgr', 'version': __version__,
            'node_id': cfg['node']['id'], 'exported_at': util.iso(time.time()), 'with_secrets': bool(secrets),
            'settings': ui, 'secrets_set': secret_state, 'workflow': wf.settings() if wf else {}}


def parse(raw):
    """The file's JSON (bytes or str) as a dict, or ImportError_."""
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) > MAX_BYTES:
            raise ImportError_('too_large')
        raw = raw.decode('utf-8', 'replace')
    try:
        d = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        raise ImportError_('not_json')
    if not isinstance(d, dict) or d.get('format') != FORMAT:
        raise ImportError_('not_a_settings_file')
    if not isinstance(d.get('settings', {}), dict) or not isinstance(d.get('workflow', {}), dict):
        raise ImportError_('not_a_settings_file')
    return d


def _same(a, b):
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def preview(app, data):
    """[{key, area ('settings' | 'workflow'), group, current, incoming, same, known, secret, valid, error}], file facts."""
    cfg = app.cfg
    items = []
    for k, v in sorted((data.get('settings') or {}).items()):
        known = k in uisettings.EDITABLE
        secret = known and uisettings.EDITABLE[k][0] == 'secret'
        cur = None
        if known:
            sec, name = k.split('.', 1)
            cur = cfg.data.get(sec, {}).get(name)
        it = {'key': k, 'area': 'settings', 'group': k.split('.', 1)[0], 'known': known, 'secret': secret,
              'current': ('(set)' if cur else '') if secret else cur, 'incoming': '(set)' if secret and v else v,
              'same': known and _same(cur, v), 'valid': known, 'error': None if known else 'unknown_setting'}
        if known:
            try:
                uisettings._validate(k, v)
            except uisettings.SettingError as e:
                it.update(valid=False, error=e.code)
        items.append(it)
    wf = _wf(app)
    for k, v in sorted((data.get('workflow') or {}).items()):
        known = bool(wf) and k in wf.settings()
        cur = wf.setting(k) if known else None
        it = {'key': k, 'area': 'workflow', 'group': 'workflow', 'known': known, 'secret': False, 'current': cur,
              'incoming': v, 'same': known and _same(cur, v), 'valid': known, 'error': None if known else 'unknown_setting'}
        if known:
            from .changes import ChangeError
            try:
                wf.check_setting(k, v)
            except ChangeError as e:
                it.update(valid=False, error=e.code)
        items.append(it)
    # a server address that changes needs its key in the same import (a stored key never goes to another server)
    incoming = data.get('settings') or {}
    for uk, sks in uisettings.BOUND.items():
        u = next((i for i in items if i['area'] == 'settings' and i['key'] == uk), None)
        if u and not u['same'] and any(not incoming.get(sk) for sk in sks):
            u['needs'] = [sk for sk in sks]
    facts = {k: data.get(k) for k in ('version', 'node_id', 'exported_at', 'with_secrets')}
    return {'file': facts, 'items': items}


def apply(app, data, keys, actor, src_ip=None):
    """Write the picked settings (`keys`: "settings:<key>" / "workflow:<key>", or bare setting keys). All or nothing.
    Returns {settings: [changed keys], workflow: [changed keys]}."""
    pv = {(i['area'], i['key']): i for i in preview(app, data)['items']}
    picked = []
    for k in keys or []:
        area, _, key = k.partition(':') if ':' in k else ('settings', '', k)
        it = pv.get((area, key))
        if not it:
            raise ImportError_('not_in_file', key=k)
        if not it['known']:
            raise ImportError_('unknown_setting', key=k)
        if not it['valid']:
            raise ImportError_('invalid_value', key=k, reason=it['error'])
        picked.append((area, key))
    if not picked:
        raise ImportError_('nothing_picked')
    ui = {k: data['settings'][k] for a, k in picked if a == 'settings'}
    wfv = {k: data['workflow'][k] for a, k in picked if a == 'workflow'}
    wf = _wf(app)
    # check every workflow value first: the ui settings are stored by set_many, which checks its own batch whole
    for k, v in wfv.items():
        wf.check_setting(k, v)
    try:
        changed = uisettings.set_many(app, ui, actor, src_ip=src_ip) if ui else []
    except uisettings.SettingError as e:
        raise ImportError_(e.code, **e.details)
    wf_changed = []
    for k, v in wfv.items():
        old = wf.setting(k)
        if _same(old, v):
            continue
        wf.set_setting(k, v, actor)
        app.audit.log('settings.changed', actor, src_ip=src_ip, key='workflow.' + k, old=old, new=v)
        wf_changed.append(k)
    app.audit.log('settings.imported', actor, src_ip=src_ip, picked=len(picked), changed=len(changed) + len(wf_changed),
                  file_version=util.clip(str(data.get('version') or ''), 20), file_node=util.clip(str(data.get('node_id') or ''), 64))
    return {'settings': changed, 'workflow': wf_changed}
