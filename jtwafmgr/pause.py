"""Pausing the WAF to troubleshoot a site (an administrator, a fresh one-time code and a reason): ModSecurity only
detects -- it keeps logging what it would refuse, refuses nothing -- for every site or for chosen sites, for 1, 3, 12 or
24 hours or until resumed. "Resume" puts back exactly what was there: only the pause rules change, never the other rules.

Two managed rules at the top of the "before CRS" file, with fixed ids (waf.pause_ids): one for every site, one for the
listed sites (each with its own end time). Nothing paused: the rules stay as no-ops, so pausing and resuming are plain
edits of the same two rules -- each one a version like any change (history, rollback), applied at once: no sandbox run
and no second person (it is the switch for when something is wrong now). The IP block list and nginx's own rules
(country `if`s, `deny`) are not ModSecurity and stay in force.

Ends by themselves: the change worker resumes what has run out (a tightening, applied without asking).
"""
import json
import re
import threading

from . import util
from .changes import ChangeError
from .rulegen import pause_ids

DURATIONS = (1, 3, 12, 24, 0)          # hours; 0: until someone resumes it
REASON_MIN = 5
BUSY = ('checking', 'approved', 'applying')
RETRY_AFTER = 600                      # a pause change that failed to apply: the automatic end waits this long to retry
_lock = threading.Lock()               # the web service's requests and the change worker propose one at a time


def match_mode(app):
    """'txid' when nginx gives ModSecurity "$host-$request_id" as the transaction id (the site nginx chose, which a
    full URL in the request line cannot hide behind another Host header), else 'host' (the Host header)."""
    try:
        n, _ = app.site.load()
        from .nginxconf import walk
        for d, ctx in walk(n.tree):
            if d.name == 'modsecurity_transaction_id' and d.args and len(ctx) <= 1:
                return 'txid' if d.args[0].strip('"\'').startswith('$host-$request_id') else 'host'
    except Exception:       # noqa: BLE001 -- an unreadable configuration: the Host header
        pass
    return 'host'


def _items(wf):
    a, s = pause_ids(wf.cfg)
    by = {it['rule_id']: it for it in wf.managed.items() if it['kind'] == 'pause'}
    return by.get(a), by.get(s)


def _spec(it):
    return json.loads(it['spec']) if it else {}


BLOCKING = re.compile(r'(?i)(?:^|[,"\s])(?:deny|drop|block|redirect(?::|\b))|ctl:\s*ruleEngine\s*=\s*On')


def also_remove(app):
    """Rules that refuse on their own but sit in the exclusion range (which a pause keeps, for the exclusions and the
    masking): taken out one by one too."""
    lo, hi = app.cfg['waf']['exclusion_range']
    out = set()
    for it in app.workflow.managed.items():
        if it['enabled'] and it.get('rule_id') and lo <= it['rule_id'] <= hi and BLOCKING.search(it['text'] or ''):
            out.add(it['rule_id'])
    try:
        _, m = app.site.load()
        for r in m.rules:
            acts = getattr(r, 'actions', None) or []
            if r.id is not None and lo <= r.id <= hi and any(
                    k in ('deny', 'drop', 'block', 'redirect') or (k == 'ctl' and re.match(r'(?i)ruleEngine\s*=\s*On', str(v)))
                    for k, v in acts):
                out.add(r.id)
    except Exception:       # noqa: BLE001 -- the managed rules above are what matters most
        pass
    return sorted(out)[:100]


def state(wf, now=None):
    """What is paused now: {'all': {...} | None, 'sites': [{host, since, until, by, reason}], 'busy': change id | None}."""
    now = now or util.now()
    a, s = _items(wf)
    sa, ss = _spec(a), _spec(s)
    out = {'all': None, 'sites': [], 'busy': None, 'durations': list(DURATIONS)}
    if sa.get('active'):
        out['all'] = {k: sa.get(k) for k in ('since', 'until', 'by', 'reason')}
    out['sites'] = [x for x in ss.get('sites') or []]
    for x in [out['all']] + out['sites']:
        if x:
            x['since_at'] = util.iso(x['since']) if x.get('since') else None
            x['until_at'] = util.iso(x['until']) if x.get('until') else None
            x['left_seconds'] = int(x['until'] - now) if x.get('until') else None
    r = wf.db.one("SELECT id FROM changes WHERE kind='pause' AND state IN ('checking','approved','applying') ORDER BY id DESC LIMIT 1")
    out['busy'] = r[0] if r else None
    out['active'] = bool(out['all'] or out['sites'])
    out['adopted'] = wf.managed.adopted()
    f = wf.db.one("SELECT id, state, error, updated_at FROM changes WHERE kind='pause' ORDER BY id DESC LIMIT 1")
    out['last_failed'] = ({'change_id': f['id'], 'state': f['state'], 'error': (f['error'] or '')[:300], 'at': util.iso(f['updated_at'])}
                          if f and f['state'] in ('failed', 'apply_failed') else None)
    return out


def _ops(wf, new_all, new_sites):
    """The bundle that turns the two pause rules into the given state (only what differs)."""
    ida, ids_ = pause_ids(wf.cfg)
    a, s = _items(wf)
    occupied = {it['rule_id']: it['kind'] for it in wf.managed.items(include_deleted=True) if it.get('rule_id')}
    for rid in (ida, ids_):
        if occupied.get(rid) not in (None, 'pause'):
            raise ChangeError('pause_ids_in_use', 409, rule_id=rid)
    tomb = {it['rule_id'] for it in wf.managed.items(include_deleted=True) if it.get('deleted') and it['kind'] == 'pause'}
    ops = []
    for it, rid, spec in ((a, ida, new_all), (s, ids_, new_sites)):
        if spec is None:
            continue
        if it is None and rid in tomb:
            # a re-adoption left the pause rule as a tombstone: its id is never handed out again
            raise ChangeError('pause_ids_in_use', 409, rule_id=rid)
        if it is None:
            ops.append({'op': 'add', 'kind': 'pause', 'rule_id': rid, 'spec': spec})
        elif _spec(it) != dict(spec, first=True) or not it['enabled']:
            ops.append({'op': 'modify', 'kind': 'pause', 'item_id': it['id'], 'rule_id': rid, 'spec': spec})
    return ops


def _propose(wf, ops, direction, reason, actor, event):
    """One change for the pause rules: built and statically checked like any rule, then applied at once. `event` (the
    audit action and its details) is written when the apply program reports the result: only what really happened is
    told."""
    from . import rulegen
    if not ops:
        raise ChangeError('no_effect')
    if not wf.managed.adopted():
        raise ChangeError('not_adopted', 409)       # the managed files are not loaded yet: a pause would do nothing
    if wf.db.one("SELECT 1 FROM changes WHERE kind='pause' AND state IN ('checking','approved','applying')"):
        raise ChangeError('pause_busy', 409)
    built = []
    for o in ops:
        try:
            spec, text, _ = rulegen.build('pause', o['spec'], o['rule_id'], wf.cfg)
        except rulegen.SpecError as e:
            raise ChangeError('invalid_spec', 422, field=e.field, reason=e.code, **e.details)
        built.append({'op': o['op'], 'kind': 'pause', 'item_id': o.get('item_id'), 'rule_id': o['rule_id'], 'spec': spec,
                      'direction': direction, 'text': text})
    text = '\n\n'.join('# %s pause %s\n%s' % (b['op'], b['rule_id'], b['text']) for b in built)
    spec = {'ops': [{k: b[k] for k in ('op', 'kind', 'item_id', 'rule_id', 'spec', 'direction')} for b in built],
            'pause': True, 'event': event}
    return wf._insert('bundle', 'pause', None, None, spec, direction, reason, actor, 'user', text, [], actor)


def applied(app, r, ok, summary=''):
    """The apply program's answer for a pause change (called from the change worker): the audit record and with it the
    notification -- 'waf.paused' / 'waf.resumed' when it is in force, 'waf.pause_apply_failed' when it is not."""
    ev = json.loads(r['spec'] or '{}').get('event') or {}
    action, details = ev.get('action'), dict(ev.get('details') or {}, change_id=r['id'])
    if not action:
        return
    if ok:
        app.audit.log(action, ev.get('actor') or r['proposed_by'], 'system' if r['proposed_by'] == 'system' else 'user',
                      None, 'ok', **details)
    else:
        app.audit.log('waf.pause_apply_failed', r['proposed_by'], 'system', None, 'error', severity='crit',
                      wanted=action, error=(summary or '')[:300], **details)


def start(app, scope, host, hours, reason, actor):
    """Pause every site (scope 'all') or one site. Returns the change id."""
    wf = app.workflow
    if hours not in DURATIONS:
        raise ChangeError('invalid_duration', 422, allowed=list(DURATIONS))
    reason = ' '.join(str(reason or '').split())[:300]
    if len(reason) < REASON_MIN:
        raise ChangeError('note_required')
    with _lock:
        now = util.now()
        entry = {'since': now, 'until': (now + hours * 3600) if hours else None, 'by': actor, 'reason': reason}
        st = state(wf, now)
        extra = also_remove(app)
        if scope == 'all':
            ops = _ops(wf, dict(entry, scope='all', active=True, also_remove=extra), None)
            what = 'all'
        elif scope == 'site':
            h = str(host or '').strip().lower().rstrip('.')
            sites = [x for x in st['sites'] if x['host'] != h]
            sites.append(dict(entry, host=h))
            ops = _ops(wf, None, {'scope': 'sites', 'match': match_mode(app), 'also_remove': extra, 'sites': [_clean(x) for x in sites]})
            what = h
        else:
            raise ChangeError('invalid_scope', 422)
        event = {'action': 'waf.paused', 'actor': actor,
                 'details': {'scope': scope, 'host': what if scope == 'site' else None, 'hours': hours,
                             'until': util.iso(entry['until']) if entry['until'] else None, 'reason': reason}}
        return _propose(wf, ops, 'loosen', 'WAF paused (%s, %s): %s' % (what, ('%d h' % hours) if hours else 'until resumed', reason),
                        actor, event)


def resume(app, actor, host=None, all_=False, reason=''):
    """Resume one site (host), every site's pause (all_=False, host=None: the "every site" pause only) or everything
    (all_=True). Returns the change id, or None when nothing was paused."""
    with _lock:
        return _resume(app, actor, host, all_, reason)


def _resume(app, actor, host, all_, reason):
    wf = app.workflow
    st = state(wf)
    new_all = new_sites = None
    if all_ or host is None:
        if st['all']:
            new_all = {'scope': 'all', 'active': False}
    if all_:
        if st['sites']:
            new_sites = {'scope': 'sites', 'sites': []}
    elif host is not None:
        h = str(host).strip().lower().rstrip('.')
        left = [x for x in st['sites'] if x['host'] != h]
        if len(left) == len(st['sites']):
            raise ChangeError('not_paused', 404)
        new_sites = {'scope': 'sites', 'match': match_mode(app), 'also_remove': also_remove(app), 'sites': [_clean(x) for x in left]}
    ops = _ops(wf, new_all, new_sites)
    if not ops:
        return None
    what = 'everything' if all_ else (host or 'all sites')
    event = {'action': 'waf.resumed', 'actor': actor, 'details': {'what': what, 'reason': reason or None}}
    return _propose(wf, ops, 'tighten', 'WAF resumed (%s)%s' % (what, (': ' + reason) if reason else ''), actor, event)


def _clean(x):
    return {k: x[k] for k in ('host', 'since', 'until', 'by', 'reason') if x.get(k) is not None}


REMIND_EVERY = 86400


def _remind(app, st, now):
    """A pause with no end: a reminder once a day while it lasts."""
    forever = ([st['all']] if st['all'] and not st['all'].get('until') else []) + [x for x in st['sites'] if not x.get('until')]
    if not forever:
        return
    first = min(x.get('since') or now for x in forever)
    last = float(app.db.get_meta('pause.reminded_at') or 0)
    if now - first < REMIND_EVERY or now - last < REMIND_EVERY:
        return
    app.db.set_meta('pause.reminded_at', str(now))
    what = ', '.join(('all sites' if x is st['all'] else x['host']) for x in forever)
    app.audit.log('waf.still_paused', 'system', 'system', None, 'ok', what=what,
                  since=util.iso(first), reason=forever[0].get('reason'))


def expire(app, now=None):
    """Resume what has run out (called by the change worker). Returns the change id or None."""
    wf = app.workflow
    now = now or util.now()
    st = state(wf, now)
    if st['busy']:
        return None
    _remind(app, st, now)
    f = wf.db.one("SELECT state, updated_at FROM changes WHERE kind='pause' ORDER BY id DESC LIMIT 1")
    if f and f['state'] in ('failed', 'apply_failed') and util.now() - f['updated_at'] < RETRY_AFTER:
        return None                     # the last one did not apply: no reload (and notification) every 20 seconds
    a = st['all']
    new_all = {'scope': 'all', 'active': False} if a and a.get('until') and a['until'] <= now else None
    keep = [x for x in st['sites'] if not (x.get('until') and x['until'] <= now)]
    new_sites = {'scope': 'sites', 'sites': [_clean(x) for x in keep]} if len(keep) != len(st['sites']) else None
    if new_all is None and new_sites is None:
        return None
    if new_sites is not None:
        new_sites.update(match=match_mode(app), also_remove=also_remove(app))
    gone = (['all sites'] if new_all else []) + [x['host'] for x in st['sites'] if x not in keep]
    event = {'action': 'waf.resumed', 'actor': 'system', 'details': {'what': ', '.join(gone), 'expired': True}}
    with _lock:
        try:
            return _propose(wf, _ops(wf, new_all, new_sites), 'tighten', 'WAF pause ended: ' + ', '.join(gone), 'system', event)
        except ChangeError:
            return None
