"""Whether the WAF works, for a monitoring system (GET /api/v1/health; the LibreNMS / Nagios plugin
check_jt_waf_mgr reads it). Read-only and cheap enough to ask every minute: it uses the results the background
checks already keep and never runs `nginx -t`, a full hash of the program or the audit chain.

Each check: ok | warning | critical, with a short English message (the plugin words it in its own language by
the check's name). The overall status is the worst one.
"""
import re
import time

from . import __version__, util

OK, WARNING, CRITICAL = 'ok', 'warning', 'critical'
ORDER = {OK: 0, WARNING: 1, CRITICAL: 2}
COLLECTOR_LAG = 300                 # seconds without reading the audit log: the events stop arriving


def _check(name, status, message='', **detail):
    d = {'name': name, 'status': status, 'message': message}
    d.update({k: v for k, v in detail.items() if v is not None})
    return d


def nginx_pid_file(app):
    """The pid file nginx writes (its `pid` directive, else the Debian / Ubuntu default)."""
    try:
        n, _ = app.site.load()
        for d in n.tree:
            if d.name == 'pid' and d.args:
                return d.args[0]
    except Exception:       # noqa: BLE001 -- an unreadable configuration is reported by the other checks
        pass
    return '/run/nginx.pid'


def nginx_running(pid_file):
    """True / False, or None when it cannot be told (the pid file is not readable)."""
    try:
        with open(pid_file) as fh:
            pid = int(fh.read().strip() or 0)
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return None
    if pid <= 0:
        return False
    try:
        with open('/proc/%d/comm' % pid) as fh:
            return fh.read().strip().startswith('nginx')
    except OSError:
        return False


def _nginx(app):
    pf = nginx_pid_file(app)
    up = nginx_running(pf)
    if up is None:
        return _check('nginx', WARNING, 'pid file not readable', pid_file=pf)
    return _check('nginx', OK if up else CRITICAL, 'running' if up else 'not running', pid_file=pf)


def _switches_on(m):
    """Rules that turn blocking on for the request they match (ctl:ruleEngine=On): an engine set to detection only
    then still refuses what these rules pick (confident blocks, the score refusal for outside sources)."""
    n = 0
    for r in m.rules:
        acts = list(r.all_actions()) if hasattr(r, 'all_actions') else (getattr(r, 'actions', None) or [])
        for k, v in acts:            # every element of a chain: the switch is often on the last one
            if k == 'ctl' and re.match(r'(?i)\s*ruleEngine\s*=\s*On\b', str(v)):
                n += 1
                break
    return n


def _modsecurity(app):
    _, m = app.site.load()
    c = m.crs_status()
    mode = c.get('engine_mode')
    on = _switches_on(m) if mode == 'DetectionOnly' else 0
    if mode == 'On':
        st, msg = OK, 'blocking'
    elif mode == 'DetectionOnly' and on:
        st, msg = OK, 'blocking through rules (engine set to detection only)'
    elif mode == 'DetectionOnly':
        st, msg = WARNING, 'detection only: nothing is blocked'
    else:
        st, msg = CRITICAL, 'engine off' if mode == 'Off' else 'no ModSecurity configuration found'
    if st == OK and not c.get('rule_count'):
        st, msg = WARNING, 'no CRS rules loaded'
    return _check('modsecurity', st, msg, engine_mode=mode, crs_version=c.get('version'), rule_count=c.get('rule_count'),
                  blocking_rules=on or None)


def _managed(app):
    m = app.workflow.managed
    if not m.adopted():
        return _check('managed_rules', OK, 'not adopted (read-only mode)', adopted=False)
    disk = m.disk_state()
    if disk.get('drift'):
        return _check('managed_rules', CRITICAL, 'managed rule files changed outside jt-waf-mgr', adopted=True,
                      files=sorted(p for p, f in disk['files'].items() if f.get('drift')))
    cur = m.current_version()
    return _check('managed_rules', OK, 'as last applied', adopted=True, version=cur['version'] if cur else None)


def _last_apply(app):
    r = app.db.one("SELECT id, state, updated_at FROM changes WHERE state IN ('applied', 'apply_failed', 'rolled_back') "
                   "ORDER BY updated_at DESC LIMIT 1")
    if not r:
        return _check('last_apply', OK, 'nothing applied yet')
    bad = r['state'] != 'applied' and util.now() - r['updated_at'] < 86400
    return _check('last_apply', WARNING if bad else OK, '%s (change #%d)' % (r['state'], r['id']), change=r['id'],
                  state=r['state'], at=util.iso(r['updated_at']))


def _collector(app):
    st = app.tailer.stats if app.tailer else {}
    if app.tailer:
        last_read, err = st.get('last_read'), st.get('error')
    else:   # asked from another process (the command line): the service's progress in the database
        r = app.db.one('SELECT MAX(updated) FROM collector_state')
        last_read, err = (r[0] if r and r[0] else None), None
    lag = int(time.time() - last_read) if last_read else None
    if err:
        return _check('collector', CRITICAL, 'cannot read the audit log: %s' % util.clip(str(err), 120), lag_seconds=lag)
    if lag is None or lag > COLLECTOR_LAG:
        return _check('collector', CRITICAL, 'not reading the audit log', lag_seconds=lag)
    return _check('collector', OK, 'reading', lag_seconds=lag)


def _blocks(app):
    if not app.cfg['blocks']['enabled']:
        return _check('ip_blocks', OK, 'not enabled', enabled=False)
    st = app.blocks.status()
    if not st['included']:
        return _check('ip_blocks', WARNING, 'the list file is not included in nginx', enabled=True)
    if st['applied'].get('ok') is False:
        return _check('ip_blocks', WARNING, 'the last write of the list failed', enabled=True)
    if not st['in_sync']:
        return _check('ip_blocks', WARNING, 'the list file differs from the active blocks', enabled=True)
    return _check('ip_blocks', OK, 'loaded', enabled=True)


def _program(app):
    mon = app.monitor
    prog = mon.state.get('program') if mon else None
    if not prog:
        return _check('program_integrity', OK, 'not checked yet')
    s = prog.get('status')
    return _check('program_integrity', OK if s == 'ok' else CRITICAL if s == 'failed' else WARNING, str(s or 'unknown'))


def _chain(app):
    mon = app.monitor
    ch = mon.state.get('chain') if mon else None
    if not ch:
        return _check('audit_chain', OK, 'not checked yet')
    return _check('audit_chain', OK if ch.get('ok') else CRITICAL, 'ok' if ch.get('ok') else 'broken')


def _outside(app):
    r = app.db.one("SELECT id, ts FROM config_snapshots WHERE cause='outside' ORDER BY id DESC LIMIT 1")
    if r and util.now() - r['ts'] < 86400:
        return _check('config_changes', WARNING, 'nginx or ModSecurity configuration changed outside jt-waf-mgr',
                      snapshot=r['id'], at=util.iso(r['ts']))
    return _check('config_changes', OK, 'no outside change in 24 hours')


def _analyst(app):
    if not app.cfg['analyst']['enabled']:
        return _check('analyst', OK, 'not enabled', enabled=False)
    rows = app.db.q('SELECT error FROM analyst_runs WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 2')
    if len(rows) == 2 and all(r['error'] for r in rows):
        return _check('analyst', WARNING, 'the last two runs failed', error=util.clip(rows[0]['error'], 120))
    return _check('analyst', OK, 'ok', enabled=True)


def _paused(app):
    from . import pause
    st = pause.state(app.workflow)
    if st['all']:
        return _check('waf_pause', WARNING, 'paused on every site (detection only)', until=st['all'].get('until_at'))
    if st['sites']:
        return _check('waf_pause', WARNING, 'paused on %d site(s) (detection only)' % len(st['sites']),
                      sites=[x['host'] for x in st['sites']][:50])
    return _check('waf_pause', OK, 'not paused')


CHECKS = (_nginx, _modsecurity, _paused, _managed, _last_apply, _collector, _blocks, _program, _chain, _outside, _analyst)


def metrics(app):
    now = util.now()
    db = app.db

    def n(sql, args=()):
        r = db.one(sql, args)
        return r[0] if r and r[0] is not None else 0
    last = (app.tailer.stats if app.tailer else {}).get('last_event_ts') or n('SELECT MAX(ts) FROM events') or None
    return {
        'events_1h': n('SELECT COUNT(*) FROM events WHERE ts>=?', (now - 3600,)),
        'blocked_1h': n("SELECT COUNT(*) FROM events WHERE ts>=? AND outcome='blocked'", (now - 3600,)),
        'blocked_24h': n("SELECT COUNT(*) FROM events WHERE ts>=? AND outcome='blocked'", (now - 86400,)),
        'last_event_age_seconds': int(now - last) if last else None,
        'ip_blocks_active': n("SELECT COUNT(*) FROM ip_blocks WHERE state='active' AND expires_at>?", (now,)),
        'open_alerts': n("SELECT COUNT(*) FROM alerts WHERE state='open'"),
        'pending_changes': n("SELECT COUNT(*) FROM changes WHERE state='pending_approval'"),
    }


def health(app):
    checks = []
    for fn in CHECKS:
        try:
            checks.append(fn(app))
        except Exception as e:      # noqa: BLE001 -- one check that cannot run is a warning; the others still run
            checks.append(_check(fn.__name__[1:], WARNING, 'check failed: %s' % type(e).__name__))
    worst = max((c['status'] for c in checks), key=ORDER.get, default=OK)
    try:
        mx = metrics(app)
    except Exception:       # noqa: BLE001
        mx = {}
    return {'status': worst, 'version': __version__, 'node_id': app.cfg['node']['id'], 'checked_at': util.iso(util.now()),
            'problems': [c['name'] for c in checks if c['status'] != OK], 'checks': checks, 'metrics': mx}
