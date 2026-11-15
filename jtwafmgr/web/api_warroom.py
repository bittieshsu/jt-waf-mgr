"""The war room board (/warroom, a page of its own): a snapshot of the last 30 minutes and the events since, every few
seconds. Read only, for viewers (token scope events:read).

What leaves here is what a wall may show: the country of the source (GeoIP or the registries' lists), the site (an
alias for a site nginx serves only to internal networks), the outcome and how it was decided, the time. Never the
address, the path, the query or a header -- the fields are not in the answer at all.

- GET /warroom/snapshot          the window, its totals, per country and minute, the latest events, the collector's
                                 state, the destination; the same answer for every screen for a few seconds
- GET /warroom/events?after=<id> the events after an id (up to 500, oldest first, `more` when there are more), with the
                                 server time (a heartbeat when there is none)
"""
import threading
import time

from .. import util
from .server import ApiError, json_response

V = '/api/v1'
WINDOW = 30 * 60
LATEST = 30
BATCH = 500
CACHE_SECONDS = 4
_cache = {}
_lock = threading.Lock()


_alias = {'at': 0.0, 'map': None}


def _hosts_alias(app):
    """{site name: alias} for the sites nginx serves only to internal networks (their names stay off the wall);
    worked out again at most once a minute (every screen asks every few seconds)."""
    if _alias['map'] is not None and time.monotonic() - _alias['at'] < 60:
        return _alias['map']
    out = _hosts_alias_now(app)
    _alias.update(at=time.monotonic(), map=out)
    return out


def _hosts_alias_now(app):
    out, n = {}, 0
    try:
        n_conf, _ = app.site.load()
        for s in n_conf.servers():
            if s.get('reach') != 'internal':
                continue
            for name in s['server_names']:
                if name and name != '_' and name.lower() not in out:
                    n += 1
                    out[name.lower()] = 'internal-%d' % n
    except Exception:          # noqa: BLE001 -- unreadable nginx configuration: every name an alias, to be safe
        return None
    return out


def _host(alias, host):
    h = (host or '').lower()
    if alias is None:
        return 'site'
    return alias.get(h, h)


def _cc(api, ip, origin):
    if origin == 'internal':
        return 'LAN'
    g = api.geo(ip)
    if not g:
        return '?'
    if g.get('scope') == 'internal':
        return 'LAN'
    return (g.get('cc') or '?').upper()


def _event(api, alias, r):
    return {'id': r['id'], 'ts': util.iso(r['ts']), 'cc': _cc(api, r['src_ip'], r['origin']), 'origin': r['origin'],
            'host': _host(alias, r['host']), 'outcome': r['outcome'], 'decided_by': r['decided_by'] or ''}


def destination(cfg):
    w = cfg.data.get('warroom') or {}
    try:
        lat, lon = float(w.get('dest_lat')), float(w.get('dest_lon'))
    except (TypeError, ValueError):
        return None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180) or not (w.get('dest_label') or '').strip():
        return None
    return {'label': w['dest_label'].strip()[:40], 'lat': lat, 'lon': lon}


def _collector(app):
    st = app.tailer.stats if getattr(app, 'tailer', None) else {}
    last = st.get('last_event_ts')
    if last is None:
        row = app.db.one('SELECT MAX(ts) FROM events')
        last = row[0] if row else None
    lag = int(util.now() - st['last_read']) if st.get('last_read') else None
    running = bool(getattr(app, 'tailer', None) and st.get('error') is None)
    return {'running': running, 'lag_seconds': lag, 'last_event_at': util.iso(last) if last else None,
            # stopped: the collector does not run or has not read for over 2 minutes
            'stopped': (not running) or (lag is not None and lag > 120)}


def _snapshot(app):
    from . import api
    now = util.now()
    since = now - WINDOW
    alias = _hosts_alias(app)
    hw = app.db.one('SELECT MAX(id) FROM events')[0] or 0
    rows = app.db.q('SELECT id, ts, host, src_ip, origin, outcome, decided_by FROM events WHERE ts>=? AND id<=? ORDER BY id',
                    (since, hw))
    countries, minutes, srcs = {}, {}, {}
    flow = {}                                  # origin -> decision -> n (decision: how the WAF decided, or logged)
    sites = {}                                 # site (alias) -> {events, blocked, logged, buckets[15] of 2 minutes}
    score_only = {}                            # site -> events blocked by the CRS score alone (where users get caught)
    totals = {'events': 0, 'blocked': 0, 'logged': 0, 'external': 0, 'internal': 0, 'unlocated': 0}
    decided = {}
    first_min = int(since // 60)
    for r in rows:
        totals['events'] += 1
        oc = 'blocked' if r['outcome'] == 'blocked' else 'logged'
        totals[oc] += 1
        totals['internal' if r['origin'] == 'internal' else 'external'] += 1
        decided[r['decided_by'] or ''] = decided.get(r['decided_by'] or '', 0) + 1
        dec = 'logged' if oc == 'logged' else (r['decided_by'] if r['decided_by'] in ('confident', 'fallback', 'score') else 'other')
        org = 'internal' if r['origin'] == 'internal' else 'external'
        flow.setdefault(org, {})[dec] = flow.setdefault(org, {}).get(dec, 0) + 1
        host = _host(alias, r['host'])
        st = sites.setdefault(host, {'host': host, 'events': 0, 'blocked': 0, 'logged': 0, 'buckets': [0] * 15})
        st['events'] += 1
        st[oc] += 1
        st['buckets'][min(14, max(0, int((r['ts'] - since) // 120)))] += 1
        if dec == 'score':
            score_only[host] = score_only.get(host, 0) + 1
        m = int(r['ts'] // 60) - first_min
        b = minutes.setdefault(m, {'blocked': 0, 'logged': 0})
        b[oc] += 1
        cc = _cc(api, r['src_ip'], r['origin'])
        if cc == 'LAN':
            continue
        if cc == '?':
            totals['unlocated'] += 1
            continue
        c = countries.setdefault(cc, {'cc': cc, 'events': 0, 'blocked': 0, 'logged': 0})
        c['events'] += 1
        c[oc] += 1
        srcs.setdefault(cc, set()).add(r['src_ip'])
    for cc, c in countries.items():
        c['sources'] = len(srcs.get(cc, ()))
    # the newest by event time (ids follow the order the collector read them in)
    latest = [_event(api, alias, r) for r in sorted(rows, key=lambda r: (r['ts'], r['id']))[-LATEST:]][::-1]
    return {
        'now': util.iso(now), 'window_start': util.iso(since), 'window_end': util.iso(now), 'window_seconds': WINDOW,
        'node_id': app.cfg['node']['id'], 'high_water_id': hw, 'collector': _collector(app),
        'totals': dict(totals, countries=len(countries)), 'decided_by': decided,
        'countries': sorted(countries.values(), key=lambda c: (-c['events'], c['cc'])),
        'minutes': [{'t': util.iso((first_min + i) * 60), **minutes.get(i, {'blocked': 0, 'logged': 0})} for i in range(31)],
        'latest': latest, 'destination': destination(app.cfg),
        'flow': flow, 'score_only': sorted(({'host': h, 'events': n} for h, n in score_only.items()), key=lambda x: -x['events']),
        'sites': sorted(sites.values(), key=lambda x: (-x['events'], x['host']))[:40],
        'watched': sorted({_host(alias, h) for h in app.cfg['waf'].get('focus_sites') or []} - set(sites)),
        'rotate_seconds': int((app.cfg.data.get('warroom') or {}).get('rotate_seconds') or 25)}


def snapshot(app, req):
    """One answer for every screen within CACHE_SECONDS (a wall of TVs does not multiply the work)."""
    key = app.cfg['node']['id']
    with _lock:
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
            return json_response(200, hit[1])
    out = _snapshot(app)
    with _lock:
        _cache[key] = (time.monotonic(), out)
    return json_response(200, out)


def events(app, req):
    from . import api
    try:
        after = int(req.query.get('after', '0'))
    except ValueError:
        raise ApiError(400, 'bad_request', 'after: an event id')
    if after < 0:
        raise ApiError(400, 'bad_request', 'after: an event id')
    alias = _hosts_alias(app)
    rows = app.db.q('SELECT id, ts, host, src_ip, origin, outcome, decided_by FROM events WHERE id>? ORDER BY id LIMIT ?',
                    (after, BATCH + 1))
    more = len(rows) > BATCH
    rows = rows[:BATCH]
    hw = rows[-1]['id'] if rows else after
    return json_response(200, {'now': util.iso(util.now()), 'after': after, 'high_water_id': hw, 'more': more,
                               'collector': _collector(app), 'events': [_event(api, alias, r) for r in rows]})


def ops(app, req):
    """The work around the WAF, for the last two pages of the board: the latest event analysis, the threat intelligence,
    open alerts and changes on their way. Ids, kinds, states and times only (no path, reason or summary text: those
    can carry what an outsider sent)."""
    from .. import analyst, intel
    now = util.now()
    r = app.db.one('SELECT * FROM analyst_runs ORDER BY id DESC LIMIT 1')
    run = None
    if r:
        sm = analyst.run_summary(r)
        run = {k: sm.get(k) for k in ('id', 'started_at', 'finished_at', 'seconds', 'candidates', 'proposals', 'verdicts',
                                       'events_scanned', 'error', 'window_hours')}
        run['error'] = bool(run['error'])
    day = app.db.one('SELECT COUNT(*) n, SUM(error IS NOT NULL) e FROM analyst_runs WHERE started_at>=?', (now - 86400,))
    try:
        threats = intel.threats(app.db, limit=500)
    except Exception:          # noqa: BLE001 -- intel tables missing on an old database: the card stays empty
        threats = []
    open_t = [t for t in threats if t.get('status') == 'open']
    lr = app.db.one('SELECT * FROM intel_runs ORDER BY id DESC LIMIT 1') if threats is not None else None
    sw = app.db.one('SELECT SUM(confirmed=1) c, SUM(confirmed=0) u FROM software')
    alerts_open = [{'id': a['id'], 'kind': a['kind'], 'severity': a['severity'], 'created_at': util.iso(a['created_at'])}
                   for a in app.db.q("SELECT id, kind, severity, created_at FROM alerts WHERE state='open' ORDER BY id DESC LIMIT 20")]

    def chg(state, since=None):
        q = 'SELECT id, op, kind, direction, state, updated_at, proposed_by FROM changes WHERE state' + (
            ' IN (%s)' % ','.join('?' * len(state)) if isinstance(state, tuple) else '=?')
        args = state if isinstance(state, tuple) else (state,)
        if since:
            q += ' AND updated_at>=?'
            args = args + (since,)
        return [{'id': c['id'], 'op': c['op'], 'kind': c['kind'], 'direction': c['direction'], 'state': c['state'],
                 'updated_at': util.iso(c['updated_at']), 'by': 'analyst' if c['proposed_by'] == 'analyst' else
                 'intel' if c['proposed_by'] == 'intel' else 'person'}
                for c in app.db.q(q + ' ORDER BY id DESC LIMIT 12', args)]
    return json_response(200, {
        'now': util.iso(now),
        'analysis': {'latest': run, 'runs_24h': day['n'] or 0, 'errors_24h': day['e'] or 0,
                     'enabled': bool(app.cfg['analyst'].get('enabled'))},
        'intel': {'enabled': bool(app.cfg['intel'].get('enabled')),
                  'last_run_at': util.iso(lr['finished_at'] or lr['started_at']) if lr else None,
                  'open': len(open_t), 'affected': sum(1 for t in open_t if t.get('affected') == 'yes'),
                  'unknown': sum(1 for t in open_t if t.get('affected') == 'unknown'),
                  'exploited': sum(1 for t in open_t if t.get('exploited')),
                  'patched_by_rule': sum(1 for t in open_t if t.get('patch_change_id')),
                  'software_confirmed': (sw['c'] or 0) if sw else 0, 'software_unconfirmed': (sw['u'] or 0) if sw else 0,
                  'top': [{'id': t['id'], 'product': t['product'], 'severity': t.get('severity'), 'affected': t.get('affected'),
                           'exploited': bool(t.get('exploited'))} for t in open_t[:5]]},
        'alerts': alerts_open,
        'changes': {'checking': chg(('checking', 'approved', 'applying')), 'pending': chg('pending_approval'),
                    'applied': chg('applied', now - 86400)}})


def register(router):
    R = router.add
    R('GET', V + '/warroom/snapshot', snapshot, ('role', 'viewer', 'events:read'))
    R('GET', V + '/warroom/events', events, ('role', 'viewer', 'events:read'))
    R('GET', V + '/warroom/ops', ops, ('role', 'viewer', 'events:read'))
