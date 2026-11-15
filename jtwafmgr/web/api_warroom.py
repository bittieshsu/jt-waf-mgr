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
    totals = {'events': 0, 'blocked': 0, 'logged': 0, 'external': 0, 'internal': 0, 'unlocated': 0}
    decided = {}
    first_min = int(since // 60)
    for r in rows:
        totals['events'] += 1
        oc = 'blocked' if r['outcome'] == 'blocked' else 'logged'
        totals[oc] += 1
        totals['internal' if r['origin'] == 'internal' else 'external'] += 1
        decided[r['decided_by'] or ''] = decided.get(r['decided_by'] or '', 0) + 1
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


def register(router):
    R = router.add
    R('GET', V + '/warroom/snapshot', snapshot, ('role', 'viewer', 'events:read'))
    R('GET', V + '/warroom/events', events, ('role', 'viewer', 'events:read'))
