"""Application protection sets (0.5.33): ready-made confident blocks for one application, written from its publicly
known vulnerabilities and the attacks seen against it (data/protection-sets.json; the first one is Synology DSM).

A set applies to the sites the software list names for its application (guessed or confirmed). For one site a person
picks the rules (the recommended ones are ticked) and the program proposes them as ONE change (a bundle of confident
blocks, scoped to that site, each tagged protset "<set>/<rule>"): the usual static checks, the evidence, the sandbox
with the tests each rule brings (attack requests refused, ordinary ones let through), and a person's approval -- a
protection set is never applied by itself. A rule a later version writes differently shows as "update"; applying the
update modifies the rule in place.

Plain data and the existing change flow; no network."""
import json
import os
import re

from . import reasons, software, util
from . import __version__

DATA_FILE = os.path.join(os.path.dirname(__file__), 'data', 'protection-sets.json')
ID_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,39}$')
SPEC_KEYS = ('target', 'header', 'arg', 'regex', 'exceptions', 'msg', 'reference', 'source')
# 0.5.48: a set can also bring an exclusion for a known false positive of the application (kind "exclusion"). An
# exclusion loosens, so a change carrying one needs a person's approval with a one-time code like any loosening one.
# default "crs_blocks": ticked only when the CRS score refuses outside requests on this host (with the CRS only
# logging the false positive does no harm, and the exclusion would only remove inspection).
EXCL_KEYS = ('path', 'method', 'source', 'action', 'tag', 'targets', 'rule_ids', 'body_processor', 'content_type', 'content_type_not',
             'content_type_missing')
KINDS = ('confident_block', 'exclusion')


class ProtsetError(Exception):
    def __init__(self, code, status=422, **details):
        super().__init__(code)
        self.code, self.status, self.details = code, status, details


def load(path=DATA_FILE):
    """[{id, app, rules: [{id, default, needs, spec, tests, refs, cves}]}] -- checked once, a broken entry is dropped."""
    try:
        with open(path, encoding='utf-8') as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return []
    out = []
    for s in d.get('sets') or []:
        if not isinstance(s, dict) or not ID_RE.match(str(s.get('id') or '')) or not s.get('app'):
            continue
        rules = []
        for r in s.get('rules') or []:
            if not isinstance(r, dict) or not ID_RE.match(str(r.get('id') or '')) or not isinstance(r.get('spec'), dict):
                continue
            kind = r.get('kind') or 'confident_block'
            if kind not in KINDS:
                continue
            default = r.get('default', True)
            default = default if default in ('crs_blocks', 'photos_fix') else bool(default)
            keys = EXCL_KEYS if kind == 'exclusion' else SPEC_KEYS
            rules.append({'id': r['id'], 'kind': kind, 'default': default, 'needs': list(r.get('needs') or []),
                          'spec': {k: v for k, v in r['spec'].items() if k in keys},
                          'tests': [t for t in r.get('tests') or [] if isinstance(t, dict)],
                          'refs': [str(x) for x in r.get('refs') or []][:20], 'cves': [str(x) for x in r.get('cves') or []][:60]})
        out.append({'id': s['id'], 'app': str(s['app']), 'rules': rules})
    return out


def find(set_id, path=DATA_FILE):
    for s in load(path):
        if s['id'] == set_id:
            return s
    return None


def _tag(set_id, rule_id):
    return '%s/%s' % (set_id, rule_id)


def _same(applied, rule, host):
    """The applied spec is what this version writes for the rule (same target, parameter, expression, exceptions)."""
    want = dict(rule['spec'], host={'mode': 'exact', 'value': host})
    if rule.get('kind') == 'exclusion':
        return all(applied.get(k) == want.get(k) for k in ('path', 'method', 'action', 'tag')) and \
            all((applied.get(k) or '') == (want.get(k) or '') for k in ('content_type', 'content_type_not',
                                                                       'content_type_missing')) and \
            (applied.get('body_processor') or '') == (want.get('body_processor') or '') and \
            list(applied.get('targets') or []) == list(want.get('targets') or []) and \
            list(applied.get('rule_ids') or []) == list(want.get('rule_ids') or []) and \
            (applied.get('source') or 'all') == (want.get('source') or 'all')
    return all((applied.get(k) or '') == (want.get(k) or '') for k in ('target', 'header', 'arg', 'regex', 'source')) and \
        list(applied.get('exceptions') or []) == list(want.get('exceptions') or [])


def _applied(app):
    """{(tag, host): {'item_id', 'enabled', 'spec'}} of the managed rules that came from a protection set."""
    out = {}
    for it in app.workflow.managed.items():
        try:
            spec = json.loads(it['spec'] or '{}')
        except ValueError:
            continue
        tag = spec.get('protset')
        host = (spec.get('host') or {}).get('value') if (spec.get('host') or {}).get('mode') == 'exact' else None
        if tag and host:
            out[(tag, host)] = {'item_id': it['id'], 'enabled': bool(it['enabled']), 'spec': spec, 'rule_id': it['rule_id']}
    return out


def _pending(app):
    """{(tag, host): change id} of the open changes that carry a protection set rule."""
    from .changes import FINAL
    out = {}
    for r in app.db.q('SELECT id, op, spec FROM changes WHERE state NOT IN (%s) ORDER BY id' % ','.join('?' * len(FINAL)),
                      FINAL):
        try:
            spec = json.loads(r['spec'] or '{}')
        except ValueError:
            continue
        specs = [o.get('spec') or {} for o in spec.get('ops') or []] if r['op'] == 'bundle' else [spec]
        for sp in specs:
            tag = sp.get('protset') if isinstance(sp, dict) else None
            host = (sp.get('host') or {}).get('value') if isinstance(sp, dict) else None
            if tag and host:
                out[(tag, host)] = r['id']
    return out


PHOTOS_FIX_RE = re.compile(r'multipart/form-data;\s*\$1')


def photos_fix(app, host):
    """0.5.48: the site's nginx configuration passes Synology Photos for iOS uploads ("multipart/form-data; charset=
    utf-8; boundary=...", which ModSecurity does not parse) to a loopback server with the Content-Type in standard form
    (the Synology example on the sites page writes it). Without it, refusing uninspected bodies from outside refuses
    those uploads."""
    try:
        n, _ = app.site.load()
    except Exception:          # noqa: BLE001
        return False
    seen = set()
    for s in n.servers():
        if host not in s['server_names'] or s['file'] in seen:
            continue
        seen.add(s['file'])
        try:
            with open(s['file'], encoding='utf-8', errors='replace') as fh:
                if PHOTOS_FIX_RE.search(fh.read(4 * 1024 * 1024)):
                    return True
        except OSError:
            continue
    return False


def _default(rule, crs_blocks, app=None, host=None):
    if rule['default'] == 'crs_blocks':
        return crs_blocks
    if rule['default'] == 'photos_fix':
        return bool(app is not None and host and photos_fix(app, host))
    return rule['default']


def status(app, path=DATA_FILE):
    """The sets whose application the software list names, with each site and the state of each rule there:
    available | applied | update | disabled | pending (change_id)."""
    from . import scoreblock
    applied, pending = _applied(app), _pending(app)
    crs_blocks = None
    out = []
    for s in load(path):
        hosts = software.hosts_of(app.db, s['app'])
        if hosts and crs_blocks is None and any(r['default'] == 'crs_blocks' for r in s['rules']):
            crs_blocks = scoreblock.external_blocks(app)
        sites = []
        for h in hosts:
            rows = []
            for r in s['rules']:
                key = (_tag(s['id'], r['id']), h)
                st, extra = 'available', {}
                if key in pending:
                    st, extra = 'pending', {'change_id': pending[key]}
                elif key in applied:
                    a = applied[key]
                    st = 'disabled' if not a['enabled'] else ('applied' if _same(a['spec'], r, h) else 'update')
                    extra = {'rule_id': a['rule_id']}
                need = [n for n in r['needs'] if h not in software.hosts_of(app.db, n)]
                rows.append(dict({'id': r['id'], 'kind': r['kind'], 'state': st,
                                  'default': bool(_default(r, crs_blocks, app, h)),
                                  'default_when': r['default'] if isinstance(r['default'], str) else None,
                                  'needs': r['needs'],
                                  'needs_missing': need, 'refs': r['refs'], 'cves': r['cves'],
                                  'target': r['spec'].get('target'), 'arg': r['spec'].get('arg') or '',
                                  'header': r['spec'].get('header') or '',
                                  'regex': r['spec'].get('regex'),
                                  'path': (r['spec'].get('path') or {}).get('value') or '',
                                  'targets': r['spec'].get('targets') or [], 'tag': r['spec'].get('tag') or '',
                                  'action': r['spec'].get('action') or '', 'rule_ids': r['spec'].get('rule_ids') or [],
                                  'body_processor': r['spec'].get('body_processor') or '',
                                  'content_type': r['spec'].get('content_type') or '',
                                  'content_type_not': r['spec'].get('content_type_not') or '',
                                  'content_type_missing': bool(r['spec'].get('content_type_missing'))},
                                 **extra))
            sites.append({'host': h, 'rules': rows})
        out.append({'id': s['id'], 'app': s['app'], 'sites': sites, 'rule_count': len(s['rules'])})
    for s in out:
        s['crs_blocks'] = crs_blocks
    return out


def _tests(rule, host):
    out = []
    for t in rule['tests']:
        t = {k: v for k, v in t.items() if k in ('path', 'method', 'headers', 'body', 'expect', 'source')}
        t['host'] = host
        t.setdefault('source', 'external')
        out.append(t)
    return out


def propose(app, set_id, host, rule_ids, actor, via='user', role=None, owner=None, path=DATA_FILE):
    """One change (a bundle) with the picked rules of a set for one site. Rules already applied as this version
    writes them, or waiting in an open change, are left out; an applied rule written differently is modified."""
    s = find(set_id, path)
    if not s:
        raise ProtsetError('unknown_set', 404)
    if not isinstance(host, str) or host not in software.hosts_of(app.db, s['app']):
        raise ProtsetError('host_not_listed', 422, app=s['app'])
    if not isinstance(rule_ids, list) or not rule_ids or not all(isinstance(x, str) for x in rule_ids):
        raise ProtsetError('no_rules')
    by_id = {r['id']: r for r in s['rules']}
    unknown = [x for x in rule_ids if x not in by_id]
    if unknown:
        raise ProtsetError('unknown_rule', 422, rules=unknown[:10])
    applied, pending = _applied(app), _pending(app)
    ops, tests, names = [], [], []
    for rid in dict.fromkeys(rule_ids):
        r = by_id[rid]
        key = (_tag(set_id, rid), host)
        if key in pending:
            continue
        spec = dict(r['spec'], host={'mode': 'exact', 'value': host}, protset=_tag(set_id, rid))
        kind = r['kind']
        spec.setdefault('source', 'all' if kind == 'exclusion' else 'external')
        if key in applied:
            a = applied[key]
            same = _same(a['spec'], r, host)
            if same and a['enabled']:
                continue
            # switched off by a person and unchanged: switched on again; written differently: rewritten in place
            ops.append({'op': 'enable', 'item_id': a['item_id']} if same else
                       {'op': 'modify', 'kind': kind, 'spec': spec, 'item_id': a['item_id']})
        else:
            ops.append({'op': 'add', 'kind': kind, 'spec': spec})
        tests += _tests(r, host)
        names.append(rid)
    if not ops:
        raise ProtsetError('nothing_to_do', 409)
    blocks = [n for n in names if by_id[n]['kind'] != 'exclusion']
    excl = [n for n in names if by_id[n]['kind'] == 'exclusion']
    reason = reasons.text('protset', app=s['app'], host=host, version=__version__, rules=', '.join(blocks)) if blocks \
        else ''
    if excl:
        reason = (reason + '\n' if reason else '') + reasons.text('protset_excl', rules=', '.join(excl))
    cid = app.workflow.propose_bundle(ops, util.clip(reason, 2000), actor, via, tests=tests[:50], role=role, owner=owner)
    app.audit.log('protset.proposed', actor, 'token' if via == 'api' else 'user', None, 'ok', set=set_id, host=host,
                  rules=names, change_id=cid)
    return cid
