"""Support bundle (0.5.48): the WAF events of a time range with everything needed to tell why each request was
refused or logged, in one zip a site can send to whoever helps it (a false positive to analyse, a rule to fix).

What goes in:
- events.ndjson: each event as the event page shows it (site, method, path, query, status, outcome, who decided,
  score, the rules it matched and ModSecurity's own match data: the variable, the matched value). Sensitive values
  were masked before they were ever stored; request bodies are not stored.
- rules.json: the text of every rule those events matched, where it comes from (OWASP CRS file and line, the
  ModSecurity base file, a jt-waf-mgr managed rule and its change) -- the CRS version is in manifest.json.
- managed/: the rule files jt-waf-mgr manages; modsecurity.json: the engine mode, body limits, the CRS threshold
  and paranoia levels, the decision summary (what refuses and what only logs, per source).
- vhosts/: the nginx server blocks of the sites in the events (masked like the "view configuration" page).
- system-check.json, changes.json (the changes of the range), software.json, manifest.json (versions, options, the
  SHA-256 of each file), README.txt.

What never goes in: passwords, tokens, keys, settings secrets, the audit trail, access logs, request bodies.
Source addresses are replaced by stable pseudonyms by default (ip-1, ip-2... the same address keeps its name, an
internal address says so); site names can be replaced too (site-1.invalid...). Building is read-only."""
import hashlib
import io
import ipaddress
import json
import os
import re
import time
import zipfile

from . import __version__, util

MAX_DAYS = 31
MAX_EVENTS = 20000
SETTINGS = ('SecRuleEngine', 'SecRequestBodyAccess', 'SecRequestBodyLimit', 'SecRequestBodyNoFilesLimit',
            'SecRequestBodyLimitAction', 'SecRequestBodyInMemoryLimit', 'SecPcreMatchLimit', 'SecAuditEngine',
            'SecAuditLogParts', 'SecArgumentsLimit')

README = """jt-waf-mgr support bundle
=========================

Made by jt-waf-mgr {version} on {node} at {at}, by {by}.
Range: {since} .. {until}   Events: {n}{more}   Outcome: {outcome}
Source addresses: {ips}   Site names: {hosts}

events.ndjson       one event per line: what was requested, the outcome, the rules matched and their match data
rules.json          the text and origin of every rule in those events (CRS version in manifest.json)
managed/            the rule files jt-waf-mgr manages on this host
modsecurity.json    engine mode, body limits, CRS threshold and paranoia levels, what refuses and what only logs
vhosts/             the nginx server blocks of those sites (secrets masked)
system-check.json   the system check at the time of the bundle
changes.json        the changes of the range (proposed, applied, failed)
software.json       the software list (threat intelligence)
manifest.json       versions, the options used, the SHA-256 of each file

Not included: passwords, tokens, keys, settings secrets, the audit trail, access logs, request bodies.
Check the files before you send them on.
"""


class BundleError(Exception):
    def __init__(self, code, status=422, **details):
        super().__init__(code)
        self.code, self.status, self.details = code, status, details


class _Pseudo:
    """Stable replacement names: the same value always gets the same name within one bundle."""

    def __init__(self, prefix, fmt, internal=()):
        self.prefix, self.fmt, self.internal, self.map = prefix, fmt, internal, {}

    def name(self, value, internal=False):
        if value not in self.map:
            self.map[value] = self.fmt % (len(self.map) + 1) + ('-internal' if internal else '')
        return self.map[value]


def _internal(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def _replace_ips(text, pairs):
    """Each address as a whole token only (192.0.2.1 is not a part of 192.0.2.10 or of 10.192.0.2.1)."""
    for value, name in sorted(pairs, key=lambda p: -len(p[0])):
        text = re.sub(r'(?<![0-9A-Fa-f.:])%s(?![0-9A-Fa-f:]|\.[0-9])' % re.escape(value), name, text)
    return text


def _replace_all(text, pairs):
    """Replaces every value by its name, longest first (a value inside a longer one), as written and as a regex
    escape (rules and nginx write site names as ^nas\\.example\\.com$)."""
    for value, name in sorted(pairs, key=lambda p: -len(p[0])):
        if not value:
            continue
        text = text.replace(value, name)
        esc = re.escape(value)
        if esc != value:
            text = text.replace(esc, re.escape(name))
            text = text.replace(esc.replace('\\', '\\\\'), re.escape(name).replace('\\', '\\\\'))   # inside JSON
    return text


def _rule_info(app, m, rid):
    r = app.site.rule(rid)
    if r is None:
        return {'id': rid, 'found': False}
    out = {'id': rid, 'found': True, 'file': r.file, 'line': r.line, 'text': util.clip(r.text or '', 8000)}
    try:
        out['source'] = m.source_of(r)
        out['category'] = m.category_of(r)
    except Exception:          # noqa: BLE001
        pass
    it = app.workflow.managed.item_by_rule(rid)
    if it:
        out['managed'] = {'item_id': it['id'], 'kind': it['kind'], 'change_id': it.get('change_id'),
                          'enabled': bool(it['enabled']), 'deleted': bool(it['deleted'])}
    return out


def build(app, since, until, by, host=None, src_ip=None, outcome='all', anon_ips=True, anon_hosts=False, ids=None):
    """Returns (zip bytes, info). since/until: epoch seconds. outcome: 'blocked' | 'all'."""
    from .web.api import event_full
    from . import compliance, vhostconf
    now = util.now()
    if until is None:
        until = now
    if since is None:
        since = until - 86400
    if not (isinstance(since, (int, float)) and isinstance(until, (int, float))) or since >= until:
        raise BundleError('invalid_range')
    if until - since > MAX_DAYS * 86400:
        raise BundleError('range_too_long', max_days=MAX_DAYS)
    if outcome not in ('blocked', 'all'):
        raise BundleError('invalid_outcome')
    sql, args = 'SELECT * FROM events WHERE ts>=? AND ts<?', [since, until]
    net_filter = None
    if host:
        sql += ' AND host=?'
        args.append(str(host)[:255])
    if src_ip:
        try:
            net = ipaddress.ip_network(str(src_ip), strict=False)
        except ValueError:
            raise BundleError('invalid_src_ip')
        if net.num_addresses == 1:
            sql += ' AND src_ip=?'
            args.append(str(net.network_address))
        else:
            net_filter = net
    if outcome == 'blocked':
        sql += " AND outcome='blocked'"
    if ids:
        if not isinstance(ids, list) or len(ids) > 1000 or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids):
            raise BundleError('invalid_ids')
        sql += ' AND id IN (%s)' % ','.join('?' * len(ids))
        args += ids
    rows = app.db.q(sql + ' ORDER BY ts DESC LIMIT ?', args + [MAX_EVENTS + 1])
    if net_filter is not None:
        rows = [r for r in rows if _ip_in(r['src_ip'], net_filter)]
    more = len(rows) > MAX_EVENTS
    rows = rows[:MAX_EVENTS]
    events = [event_full(r) for r in rows]
    nets = app.cfg.internal_networks

    _, m = app.site.load()
    rule_ids = sorted({int(x) for e in events for x in (e.get('rule_ids') or []) if str(x).isdigit()})
    rules = [_rule_info(app, m, rid) for rid in rule_ids[:500]]
    crs = m.crs_status()
    modsec = {'crs': {k: crs.get(k) for k in ('version', 'engine_mode', 'inbound_threshold', 'outbound_threshold',
                                              'blocking_paranoia_level', 'detection_paranoia_level', 'rule_count')},
              'settings': {k: m.setting(k) for k in SETTINGS}}
    try:
        from . import decision
        d = decision.model(app)
        modsec['decision'] = {'summary': d.get('summary'), 'facts': d.get('facts')}
    except Exception as e:     # noqa: BLE001
        modsec['decision'] = {'error': type(e).__name__}

    files = {}
    mg = app.workflow.managed
    for p in ('before', 'after'):
        try:
            with open(mg.path(p), encoding='utf-8', errors='replace') as fh:
                files['managed/%s-crs.conf' % p] = fh.read(4 * 1024 * 1024)
        except OSError:
            pass
    hosts = sorted({e['host'] for e in events if e.get('host')})
    n, _ = app.site.load()
    for s in n.servers():
        names = [x for x in s['server_names'] if x in hosts]
        if not names:
            continue
        try:
            b = vhostconf.site_block(app, s['file'], s['line'])
        except Exception:      # noqa: BLE001
            continue
        files['vhosts/%s-%d.conf' % (re.sub(r'[^A-Za-z0-9._-]', '_', names[0]), s['line'])] = \
            '# %s line %d\n%s\n' % (b['file'], b['line'], b['text'])
    try:
        check = compliance.system_check(app)
    except Exception as e:     # noqa: BLE001
        check = {'error': type(e).__name__}
    changes = [dict(r) for r in app.db.q(
        'SELECT id, state, op, kind, direction, rule_id, proposed_by, proposed_via, created_at, updated_at, '
        'applied_version, reason FROM changes WHERE updated_at>=? AND created_at<? ORDER BY id', (since, until))]
    for c in changes:
        c['reason'] = util.clip(c['reason'] or '', 2000)
        c['created_at'], c['updated_at'] = util.iso(c['created_at']), util.iso(c['updated_at'])
    software = [dict(r) for r in app.db.q('SELECT name, version, hosts, kind, source, confirmed FROM software ORDER BY name')]

    files['events.ndjson'] = ''.join(json.dumps(e, ensure_ascii=False) + '\n' for e in events)
    files['rules.json'] = json.dumps(rules, ensure_ascii=False, indent=1)
    files['modsecurity.json'] = json.dumps(modsec, ensure_ascii=False, indent=1, default=str)
    files['system-check.json'] = json.dumps(check, ensure_ascii=False, indent=1, default=str)
    files['changes.json'] = json.dumps(changes, ensure_ascii=False, indent=1)
    files['software.json'] = json.dumps(software, ensure_ascii=False, indent=1)

    if anon_ips:
        ips = _Pseudo('ip', 'ip-%d')
        for e in events:
            ip = e.get('src_ip')
            if ip:
                ips.name(ip, _internal(ip, nets))
        files = {k: _replace_ips(v, list(ips.map.items())) for k, v in files.items()}
    if anon_hosts:
        hs = _Pseudo('site', 'site-%d.invalid')
        for h in hosts:
            hs.name(h)
        pairs = list(hs.map.items())
        files = {(_replace_all(k, pairs) if k.startswith('vhosts/') else k): _replace_all(v, pairs)
                 for k, v in files.items()}

    at = util.iso(now)
    manifest = {'program': 'jt-waf-mgr', 'version': __version__, 'node': app.cfg['node']['id'], 'created_at': at,
                'created_by': by, 'since': util.iso(since), 'until': util.iso(until), 'events': len(events),
                'more_events_left_out': more, 'outcome': outcome, 'host': ('(pseudonymised)' if anon_hosts else host) if host else None,
                'src_ip': ('(pseudonymised)' if anon_ips else src_ip) if src_ip else None,
                'pseudonymised': {'source_addresses': bool(anon_ips), 'site_names': bool(anon_hosts)},
                'nginx': app.site.nginx_version(), 'crs': crs.get('version'), 'engine': crs.get('engine_mode'),
                'files': {k: hashlib.sha256(v.encode('utf-8')).hexdigest() for k, v in sorted(files.items())}}
    files['manifest.json'] = json.dumps(manifest, ensure_ascii=False, indent=1)
    files['README.txt'] = README.format(version=__version__, node=app.cfg['node']['id'], at=at, by=by,
                                        since=util.iso(since), until=util.iso(until), n=len(events),
                                        more=' (more in the range: narrow it)' if more else '', outcome=outcome,
                                        ips='pseudonymised' if anon_ips else 'as recorded',
                                        hosts='pseudonymised' if anon_hosts else 'as recorded')
    buf = io.BytesIO()
    stamp = time.localtime(now)[:6]
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name in ['README.txt', 'manifest.json'] + sorted(k for k in files if k not in ('README.txt', 'manifest.json')):
            zi = zipfile.ZipInfo('jt-waf-mgr-support/' + name, date_time=stamp)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, files[name])
    data = buf.getvalue()
    info = {'events': len(events), 'more': more, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'files': len(files), 'name': 'jt-waf-mgr-support-%s-%s.zip' % (
                re.sub(r'[^A-Za-z0-9_-]', '_', str(app.cfg['node']['id']))[:40], time.strftime('%Y%m%d-%H%M%S', time.localtime(now)))}
    return data, info


def _ip_in(ip, net):
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def audit(app, by, info, via, client=None, **opts):
    """One audit record per bundle made (opts: the filters used; src_ip there is the filter, not the client)."""
    if 'src_ip' in opts:
        opts['filter_src_ip'] = opts.pop('src_ip')
    app.audit.log('support.bundle', by, via, client, 'ok', severity='warning', events=info['events'], size=info['size'],
                  sha256=info['sha256'], **opts)
