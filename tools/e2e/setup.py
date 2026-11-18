"""Synthetic environment for tools/e2e/e2e.cjs: events, GeoIP test databases, accounts with TOTP, a token.
Test data only (documentation address ranges, example.com)."""
import json
import sys, time, os, random
import os.path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from jtwafmgr import config, auth, util
from jtwafmgr.app import App
from jtwafmgr.collector.auditlog import Tailer
from tests.helpers import record
from tests import mmdb_writer
R = sys.argv[1]
os.makedirs(R + '/geoip', exist_ok=True)
mmdb_writer.write(R + '/geoip/GeoLite2-City.mmdb', {
  '203.0.113.0/26': {'country': {'iso_code': 'JP', 'names': {'en': 'Japan'}}, 'city': {'names': {'en': 'Tokyo'}}},
  '203.0.113.64/26': {'country': {'iso_code': 'US', 'names': {'en': 'United States'}}},
  '198.51.100.0/24': {'country': {'iso_code': 'DE', 'names': {'en': 'Germany'}}},
  '192.0.2.0/24': {'country': {'iso_code': 'TW', 'names': {'en': 'Taiwan'}}}})
mmdb_writer.write(R + '/geoip/GeoLite2-ASN.mmdb', {
  '203.0.113.0/24': {'autonomous_system_number': 64500, 'autonomous_system_organization': 'Example Hosting'},
  '198.51.100.0/24': {'autonomous_system_number': 64501, 'autonomous_system_organization': 'Documentation Net'}}, database_type='GeoLite2-ASN')
random.seed(7)
now = time.time()
lines = []
hosts = ['app.example.com', 'sso.example.com', 'shop.example.com', 'www.example.com']
for i in range(260):
    ip = random.choice(['203.0.113.%d' % random.randint(1, 120), '198.51.100.%d' % random.randint(1, 50), '192.0.2.%d' % random.randint(1, 20), '192.168.77.%d' % random.randint(1, 9)])
    blocked = random.random() < 0.45
    rules = random.choice([[930110, 949110], [942100, 949110], [941100], [920350], [913100, 949110]])
    lines.append(record(host=random.choice(hosts), uri=random.choice(['/wp-login.php', '/index.php?id=1%27', '/../etc/passwd', '/search?q=<script>', '/']),
                        ip=ip, status=403 if blocked else 200, engine='Enabled', rules=rules, ts=now - random.randint(60, 6 * 86400)))
# the last half hour (the war room's window): a separate random stream, the events above stay the same
wr = random.Random(11)
for i in range(40):
    ip = wr.choice(['203.0.113.%d' % wr.randint(1, 120), '198.51.100.%d' % wr.randint(1, 50), '192.0.2.%d' % wr.randint(1, 20)])
    lines.append(record(host=wr.choice(hosts), uri=wr.choice(['/wp-login.php', '/.env', '/']), ip=ip, status=403 if wr.random() < .55 else 200,
                        engine='Enabled', rules=wr.choice([[930110, 949110], [913100, 949110], [920350]]), ts=now - wr.randint(30, 25 * 60)))
# a small flood: the same probe 8 times within a minute from one source (the events list folds it into one row)
for i in range(8):
    lines.append(record(host='shop.example.com', uri='/xmlrpc.php', method='POST', ip='203.0.113.201', status=403, engine='Enabled',
                        rules=[913100, 949110], ts=now - 300 - i * 6))
open(R + '/modsec_audit.log', 'w').write('\n'.join(lines) + '\n')
cfg = config.load(R + '/config.toml')
app = App(cfg)
app.tailer = Tailer(cfg, app.db); app.tailer.poll()
a = app.auth
PW = 'Smoke-Passw0rd-1'
sec = {}
for u, role in (('admin', 'admin'), ('approver', 'approver'), ('viewer', 'viewer'), ('oper', 'operator')):
    a.create_user(u, role, password=PW)
    if role in ('admin', 'approver'):
        s, _ = a.totp_setup(u)
        a.totp_enable(u, auth.totp_code(s, int(time.time() // 30) - 1))
        sec[u] = s
for i in range(30):
    app.audit.log('test.action', 'admin', src_ip='192.0.2.10', n=i)
a.create_token('wazuh-sync', ['events:read'], ['192.0.2.0/24'], None, 'admin')
app.monitor.check_chain(); app.monitor.backup()
# notifications and alerts (synthetic; nothing is sent: the notify unit does not run here)
from jtwafmgr import alerts, uisettings
# the war room's destination (a synthetic location): the maps draw arcs and tracers to it
uisettings.set_many(app, {'warroom.dest_label': 'EDGE', 'warroom.dest_lat': '25.03', 'warroom.dest_lon': '121.56'}, 'admin')
uisettings.set_many(app, {'notify.enabled': True, 'notify.base_url': 'https://waf.example.com', 'notify.webhook_enabled': True,
                          'notify.webhook_url': 'https://hooks.example.com/waf', 'notify.webhook_secret': 'e2e-signing-secret-0123456789',
                          'llm.enabled': True, 'llm.url': 'http://192.0.2.10:8080/v1', 'llm.model': 'example-model',
                          'analyst.enabled': True, 'analyst.window_hours': 168}, 'admin')
# one synthetic analysis run (no LLM here): what the analysis page and its summary show
cands = [
    {'id': 'c1', 'path': '/.env', 'events': 14, 'sources': 9, 'hosts': ['app.example.com', 'shop.example.com'], 'host_count': 2,
     'families': ['lfi'], 'rules': [{'id': 930130, 'msg': 'Restricted File Access Attempt', 'hits': 14}], 'statuses': {'404': 11, '200': 3},
     'variants': ['/.env'], 'blocked_by_score': 2, 'logged': 12, 'answered_2xx': 3, 'internal_users': 0, 'methods': {'GET': 14},
     'first_seen': '2026-11-10T01:00:00+00:00', 'last_seen': '2026-11-12T01:00:00+00:00'},
    {'id': 'c2', 'path': '/wp-login.php', 'events': 22, 'sources': 12, 'hosts': ['www.example.com'], 'host_count': 1,
     'families': ['scanner'], 'rules': [{'id': 913100, 'msg': 'Found User-Agent associated with security scanner', 'hits': 9}],
     'statuses': {'404': 22}, 'variants': ['/wp-login.php'], 'blocked_by_score': 0, 'logged': 22, 'answered_2xx': 0,
     'internal_users': 0, 'methods': {'GET': 20, 'POST': 2}, 'first_seen': '2026-11-10T03:00:00+00:00', 'last_seen': '2026-11-12T02:00:00+00:00'},
    {'id': 'f1', 'type': 'false_positive', 'host': 'shop.example.com', 'path': '/api/notes', 'events': 12, 'sources': 5,
     'internal_sources': 3, 'methods': {'POST': 12}, 'variants': ['/api/notes'], 'families': ['xss'],
     'rules': [{'id': 941100, 'msg': 'XSS Attack Detected via libinjection', 'hits': 12, 'targets': ['ARGS:body'], 'matched': ['<p>hello</p>']}],
     'first_seen': '2026-11-11T08:00:00+00:00', 'last_seen': '2026-11-12T08:00:00+00:00'}]
verdicts = [
    {'id': 'c1', 'verdict': 'attack_probe', 'confidence': 0.95, 'reason': 'Environment file probe; no site serves it.', 'regex': '^/\\.env$', 'label': 'env file probe', 'problem': None},
    {'id': 'c2', 'verdict': 'attack_probe', 'confidence': 0.9, 'reason': 'WordPress login probe; these sites do not run WordPress.', 'regex': '^/wp-login\\.php$', 'label': 'wordpress login probe', 'problem': None},
    {'id': 'f1', 'verdict': 'false_positive', 'confidence': 0.9, 'reason': 'Rich-text editor content (HTML) of the notes API.', 'regex': None, 'label': None, 'problem': None}]
app.db.x("INSERT INTO analyst_runs(node_id, started_at, finished_at, trigger, window_hours, model, llm_seconds, prompt_chars, candidates, "
         "verdicts, proposals, skipped, usage, alerts, events_scanned) VALUES ('waf1', ?, ?, 'timer', 168, 'example-model', 61.4, 8200, ?, ?, '[]', ?, "
         "'{\"prompt_tokens\": 2400, \"completion_tokens\": 900}', '[]', 260)",
         (now - 3600, now - 3500, json.dumps(cands), json.dumps(verdicts),
          json.dumps([{'id': 'c1', 'path': '/.env', 'reason': 'not_adopted'}, {'id': 'c2', 'path': '/wp-login.php', 'reason': 'not_adopted'},
                      {'id': 'f1', 'host': 'shop.example.com', 'path': '/api/notes', 'reason': 'not_adopted'}])))
alerts.raise_alert(app.db, app.audit, 'analyst', 'attack_passed', 'critical', 'attack_passed:/.env',
                   {'path': '/.env', 'host': 'app.example.com', 'count': 3, 'reason': '<b>not markup</b> probe answered 200'}, link='/analysis')
alerts.raise_alert(app.db, app.audit, 'analyst', 'false_positive', 'warning', 'false_positive:shop.example.com/api/notes',
                   {'path': '/api/notes', 'host': 'shop.example.com', 'count': 12, 'reason': 'rich text editor content'}, link='/changes')
# request volume (traffic.py): a week of hourly counts for three synthetic sites, with a daily rhythm
import math
h0 = int(now // 3600) * 3600
for i in range(7 * 24, 0, -1):
    hr = h0 - i * 3600
    day = 0.55 + 0.45 * math.sin((time.localtime(hr).tm_hour - 6) / 24 * 2 * math.pi)
    for host, base, err in (('www.example.com', 900, 2), ('shop.example.com', 420, 6), ('api.example.com', 260, 1)):
        tot = int(base * day) + (i * 37 % 41)
        s4, s5 = tot // 12 + i % 7, err + (i % 5 == 0) * err * 3
        s3 = tot // 9
        app.db.x('INSERT INTO traffic_hourly(hour, host, total, s2xx, s3xx, s4xx, s5xx, s403, s444, s429, external, bytes) '
                 'VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', (hr, host, tot, tot - s3 - s4 - s5, s3, s4, s5, s4 // 3, i % 4, i % 3,
                                                       int(tot * 0.8), tot * 18000))
app.db.set_meta('traffic_polled_at', now - 30)
# temporary IP blocks: two from a mail host's fail2ban (an API token), one by hand
if cfg['blocks']['enabled']:
    app.blocks.add('203.0.113.66', 86400, 'mail2/zimbra-webmail', '4 failed logins in 24 h', 'mail2', via='token', token_id='e2etoken')
    app.blocks.add('203.0.113.67', 3600, 'mail2/zimbra-webmail', '5 failed logins in 24 h', 'mail2', via='token', token_id='e2etoken')
    app.blocks.add('192.0.2.0/24', 7 * 86400, 'ui', 'scanner range', 'admin', role='admin')
# changes in every state and from every kind of proposer (rows only: this environment is not adopted), and the alerts
# an operator sees on a busy day -- synthetic, for the pages and the project site's screenshots
def chg(op, kind, rid, spec, direction, state, reason, by, via, ago, text, owner=None):
    app.db.x('INSERT INTO changes(op, kind, item_id, rule_id, spec, direction, state, reason, proposed_by, proposed_via, created_at, '
             'updated_at, base_version, rule_text, checks, tests, evidence_override, applied_version, error, proposed_owner) '
             "VALUES (?,?,NULL,?,?,?,?,?,?,?,?,?,1,?,'{}','[]',0,NULL,NULL,?)",
             (op, kind, rid, json.dumps(spec), direction, state, reason, by, via, now - ago, now - ago + 120, text, owner or by))
def blockrule(rid, rx, msg):
    return ('SecRule REQUEST_FILENAME "@rx %s" "id:%d,phase:1,pass,log,msg:\'jt confident block: %s\',tag:\'jt-confident-block\'"' % (rx, rid, msg))
for i, (rx, label, ago, state) in enumerate([
        (r'^/server/config\.json$', 'config file probe', 2400, 'pending_approval'),
        (r'^/kube-config\.yaml$', 'kubernetes config probe', 2500, 'pending_approval'),
        (r'^/aws-secrets\.json$', 'cloud secret probe', 2600, 'pending_approval'),
        (r'^/ai_config\.json$', 'ai config probe', 5400, 'pending_approval'),
        (r'^/env\.old$', 'env backup probe', 5500, 'applied')]):
    chg('add', 'confident_block', 10260 - i, {'target': 'path', 'regex': rx, 'source': 'external', 'msg': 'jt analyst: ' + label,
        'host': {'mode': 'any'}}, 'tighten', state,
        'Probe for %s from outside only; no internal user, never answered 2xx.\n[jt analyst] model example-model, confidence 0.95. '
        'Last 168h, external sources only: 6 events, 3 sources.' % rx.strip('^$').replace('\\', ''), 'analyst', 'api', ago,
        blockrule(10260 - i, rx, 'jt analyst: ' + label), owner='analyst')
chg('add', 'confident_block', 10224, {'target': 'header', 'header': 'Upgrade', 'regex': '(?i)h2c', 'source': 'external',
    'msg': 'h2c upgrade request'}, 'tighten', 'applied', 'Block requests that ask to upgrade to h2c.', 'admin', 'user', 7200,
    'SecRule REQUEST_HEADERS:Upgrade "@rx (?i)h2c" "id:10224,phase:1,pass,log,msg:\'jt confident block: h2c upgrade request\'"')
# the DNS check: what synthetic internal and external servers answered, and one PTR name (no DNS is asked)
if cfg['dns']['enabled']:
    os.makedirs(cfg['dns']['dir'], exist_ok=True)
    def _ans(addr):
        return {'rcode': 'NOERROR', 'addrs': [addr], 'cname': []} if addr else {'rcode': 'NXDOMAIN', 'addrs': [], 'cname': []}
    names = {'app.example.com': ('192.168.77.10', None), 'intranet.example.com': ('192.168.77.11', None),
             'intra.example.com': ('192.168.77.11', None), 'static.example.com': ('198.51.100.20', '198.51.100.20')}
    with open(os.path.join(cfg['dns']['dir'], 'results.json'), 'w') as fh:
        json.dump({'checked_at': util.iso(now - 600), 'checked_epoch': now - 600, 'internal': ['192.0.2.53'], 'external': ['198.51.100.53'],
                   'wildcards': {}, 'names': {n: {'internal': {'192.0.2.53': _ans(i)}, 'external': {'198.51.100.53': _ans(e)},
                                                  'class': 'public' if e else 'internal_only', 'public_private': False}
                                              for n, (i, e) in names.items()}}, fh)
    with open(os.path.join(cfg['dns']['dir'], 'ptr.json'), 'w') as fh:
        json.dump({'203.0.113.9': {'name': 'scanner9.example.net', 'confirmed': True, 'at': now - 600}}, fh)
# IP reputation: synthetic lists and online answers (nothing is downloaded or asked)
if cfg['iprep']['enabled']:
    d = cfg['iprep']['dir']
    os.makedirs(os.path.join(d, 'lists'), exist_ok=True)
    lists = {'cins': ['203.0.113.9/32', '198.51.100.77/32'], 'firehol_level1': ['203.0.113.0/26'], 'tor_exit': ['198.51.100.200/32'],
             'spamhaus_drop': ['192.0.2.128/25'], 'blocklist_de': ['203.0.113.9/32']}
    for lid, nets in lists.items():
        with open(os.path.join(d, 'lists', lid + '.txt'), 'w') as fh:
            fh.write('\n'.join(nets) + '\n')
    with open(os.path.join(d, 'manifest.json'), 'w') as fh:
        json.dump({lid: {'at': now - 3 * 3600, 'count': len(n), 'sha256': '0' * 64, 'bytes': 100, 'error': None}
                   for lid, n in lists.items()}, fh)
    with open(os.path.join(d, 'online.json'), 'w') as fh:
        json.dump({'203.0.113.9': {'at': now - 600,
                                   'internetdb': {'ports': [22, 80, 8080], 'tags': ['scanner'], 'vulns': ['CVE-2099-0001'],
                                                  'vulns_total': 1, 'hostnames': ['scanner9.example.net'], 'cpes': []},
                                   'misp': {'count': 3, 'to_ids': 3, 'weight': 'high', 'tags': ['tlp:white'],
                                            'first': util.iso(now - 9 * 86400), 'last': util.iso(now - 86400),
                                            'events': [{'id': '412', 'info': 'firehol_level1', 'weight': 'high', 'threat_level': 'undefined', 'date': ''},
                                                       {'id': '88', 'info': 'IPsum level 1', 'weight': 'info', 'threat_level': 'undefined', 'date': ''}]}}}, fh)
    with open(os.path.join(d, 'status.json'), 'w') as fh:
        json.dump({'ran_at': util.iso(now - 600), 'ok': True}, fh)
# country blocks: synthetic registry lists (documentation ranges stand in for countries) and one waiting rule
if cfg['countries']['enabled']:
    from tests.test_countries import stage
    from jtwafmgr import rulegen
    stage(cfg['countries']['dir'])
    cspec, ctext, _ = rulegen.build('country', {'host': {'mode': 'exact', 'value': 'shop.example.com'}, 'mode': 'allow',
                                                'countries': ['TW', 'JP']}, 10300, app.cfg)
    chg('add', 'country', 10300, cspec, 'tighten', 'pending_approval', 'shop.example.com serves customers in Taiwan and Japan only.',
        'approver', 'user', 1800, ctext)
    # one country limit in place (app.example.com: Taiwan and Japan), for the sites page and its "modify" link
    aspec, atext, _ = rulegen.build('country', {'host': {'mode': 'exact', 'value': 'app.example.com'}, 'mode': 'allow',
                                                'countries': ['TW', 'JP']}, 10301, app.cfg)
    app.db.x("INSERT INTO managed_rules(rule_id, kind, placement, position, spec, text, comment, enabled, deleted, origin, "
             "created_by, created_at, updated_at, change_id) VALUES (10301, 'country', 'before', 900, ?, ?, '', 1, 0, 'created', "
             "'approver', ?, ?, NULL)", (json.dumps(aspec), atext, now - 7200, now - 7200))
chg('add', 'confident_block', 10230, {'target': 'ua', 'regex': '(?i)sqlmap', 'source': 'external', 'msg': 'sqlmap'}, 'tighten',
    'pending_approval', 'SOAR playbook: sqlmap user agent seen on shop.example.com.', 'soar-playbook', 'api', 900,
    'SecRule REQUEST_HEADERS:User-Agent "@rx (?i)sqlmap" "id:10230,phase:1,pass,log,msg:\'jt confident block: sqlmap\'"', owner='admin')
chg('add', 'exclusion', 10120, {'host': {'mode': 'exact', 'value': 'shop.example.com'}, 'path': {'mode': 'exact', 'value': '/api/notes'},
    'action': 'remove_target', 'rule_ids': [941100], 'targets': ['ARGS:body']}, 'loosen', 'applied',
    'Rich-text notes are HTML by design (941100 on ARGS:body).', 'approver', 'user', 86400,
    'SecRule REQUEST_FILENAME "@streq /api/notes" "id:10120,phase:1,pass,nolog,ctl:ruleRemoveTargetById=941100;ARGS:body"')
for kind, sev, ded, det, ago in (
        ('config_outside', 'critical', 'config_outside:1', {'event': 'config.changed_outside', 'reason': 'nginx.conf changed outside jt-waf-mgr'}, 1500),
        ('attack_in_progress', 'warning', 'attack_in_progress:1', {'path': '/ai_config.json, /bitbucket-pipelines.yml, /config.yaml, /public/config.json, /settings.py.bak',
         'host': 'app.example.com', 'reason': 'Several sources probe secret and backup files on app.example.com in a short time.'}, 3000),
        ('attack_in_progress', 'warning', 'attack_in_progress:2', {'path': '/.kube/config, /auth.json, /config.ini, /.environment, /config.inc.php',
         'host': 'www.example.com', 'reason': 'Scans for configuration files across several sites.'}, 3100),
        ('traffic_spike', 'warning', 'traffic_spike:shop.example.com', {'host': 'shop.example.com', 'reason': '6200 requests in the hour from 14:00, 8.4 times the usual 740 an hour'}, 4200),
        ('crs_update', 'warning', 'crs_update:4.31.0', {'reason': 'OWASP CRS 4.31.0 downloaded and verified; compare it in the sandbox and propose it'}, 9000)):
    aid = alerts.raise_alert(app.db, app.audit, 'analyst' if kind.startswith('attack') else ('traffic' if kind.startswith('traffic') else 'system'),
                             kind, sev, ded, det, link='/alerts')
    app.db.x('UPDATE alerts SET created_at=?, last_seen=? WHERE dedup=?', (now - ago, now - ago, ded))
# threat intelligence: a confirmed software list, one search, what it found (all made up)
from jtwafmgr import software as _sw  # noqa: E402
for name, ver, hosts in (('nginx', '1.22.1-9+deb12u2', []), ('OWASP CRS', '4.30.0', []), ('Keycloak', '26.0.5', ['sso.example.com']),
                         ('Nextcloud', '30.0.2', ['files.example.com'])):
    _sw.save(app.db, 'admin', name, ver, hosts)
_sw.save(app.db, 'admin', 'Grafana', '', ['mon.example.com'], confirmed_flag=False)
_th = [{'id': 'CVE-2026-90001', 'product': 'Keycloak', 'our_version': '26.0.5', 'summary': 'Example: a crafted redirect_uri lets an attacker take over a session.',
        'affected_versions': '< 26.0.7', 'fixed_version': '26.0.7', 'affected': 'yes', 'exploited': True, 'exploited_evidence': 'Example KEV entry',
        'severity': 'critical', 'attack_vector': 'url', 'request_pattern': 'GET /realms/*/protocol/openid-connect/auth with redirect_uri containing a second scheme',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2026-90001']},
       {'id': 'CVE-2026-90002', 'product': 'nginx', 'our_version': '1.22.1-9+deb12u2', 'summary': 'Example: memory disclosure in a module that is not loaded here.',
        'affected_versions': '1.25.0 - 1.27.3', 'fixed_version': '1.27.4', 'affected': 'no', 'exploited': False, 'exploited_evidence': '',
        'severity': 'medium', 'attack_vector': 'header', 'request_pattern': '', 'references': ['https://nginx.org/en/security_advisories.html']}]
_rid = app.db.x("INSERT INTO intel_runs(node_id, started_at, finished_at, trigger, provider, model, tokens_in, tokens_out, searches, fetched, threats, note) "
                "VALUES ('waf1', ?, ?, 'schedule', 'openai', 'local-model', 48200, 3100, ?, ?, ?, 'Two relevant vulnerabilities.')",
                (now - 5400, now - 5100, json.dumps(['Keycloak 26.0 vulnerability 2026', 'nginx security advisory 2026']),
                 json.dumps(['https://nvd.nist.gov/vuln/detail/CVE-2026-90001']), json.dumps(_th))).lastrowid
for t in _th:
    app.db.x('INSERT INTO intel_threats(cve, product, first_seen, last_seen, last_run, affected, exploited, severity, details) VALUES (?,?,?,?,?,?,?,?,?)',
             (t['id'], t['product'], now - 5100, now - 5100, _rid, t['affected'], 1 if t['exploited'] else 0, t['severity'], json.dumps(t)))
# CrowdSec Hub rules (synthetic files in the hub's format): one to propose for Keycloak, one in use on Nextcloud whose
# upstream file changed since, one that does not convert, one without a usable test
from jtwafmgr import hub as _hub, rulegen as _rg  # noqa: E402


def _hubrule(name, label, cve, cond):
    return ('name: example/%s\ndescription: "%s (synthetic)"\nrules:\n%s\nlabels:\n  type: exploit\n  label: "%s"\n'
            '  classification:\n   - cve.%s\n' % (name, label, cond, label, cve)).encode()


_uri = '  - and:\n    - zones:\n      - URI\n      transform:\n      - lowercase\n      match:\n        type: endsWith\n        value: %s\n' \
       '    - zones:\n      - ARGS\n      variables:\n      - %s\n      match:\n        type: contains\n        value: "%s"'
_tpl = ('id: x\ninfo:\n  name: x\nhttp:\n  - raw:\n      - |\n        GET %s HTTP/1.1\n        Host: {{Hostname}}\n\n'
        '    matchers:\n      - type: status\n        status:\n          - 403\n')
_files = {'LICENSE': b'MIT License\n\nCopyright (c) 2020 crowdsecurity (example)\n\nPermission is hereby granted, free of charge, to any person obtaining a copy (synthetic)\n'}
for _n, _l, _c, _cond, _t in (
        ('vpatch-keycloak-redirect', 'Keycloak - Account takeover', 'CVE-2026-90001', _uri % ('/protocol/openid-connect/auth', 'redirect_uri', '://evil'),
         '/realms/a/protocol/openid-connect/auth?redirect_uri=https://evil.example.net/'),
        ('vpatch-nextcloud-upload', 'Nextcloud - RCE', 'CVE-2026-90003', _uri % ('/apps/files/ajax/upload.php', 'dir', '../'),
         '/apps/files/ajax/upload.php?dir=../../config'),
        ('vpatch-grafana-render', 'Grafana - SSRF', 'CVE-2026-90004', '  - zones:\n      - RESPONSE_BODY\n    match:\n      type: contains\n      value: x', None),
        ('vpatch-shop-sqli', 'Example Shop - SQL injection', 'CVE-2026-90005', _uri % ('/cart.php', 'id', 'union select'), None),
        # cross-application (0.4.92): a flaw of PHP (related to Nextcloud through its stack) and one of React (no site
        # known to run it: offered for all sites)
        ('vpatch-php2shell', 'PHP2Shell - RCE', 'CVE-2026-90006', _uri % ('.php', 'cmd', 'system('), '/index.php?cmd=system(id)'),
        ('vpatch-react-rce', 'React - RCE', 'CVE-2026-90007', _uri % ('/', 'action', '__proto__'), '/?action=__proto__')):
    _files['appsec-rules/crowdsecurity/%s.yaml' % _n] = _hubrule(_n, _l, _c, _cond)
    if _t:
        _files['.appsec-tests/%s/config.yaml' % _n] = ('appsec-rules:\n  - ./appsec-rules/crowdsecurity/%s.yaml\nnuclei_template: t.yaml\n' % _n).encode()
        _files['.appsec-tests/%s/t.yaml' % _n] = (_tpl % _t).encode()
_old_nc = _files['appsec-rules/crowdsecurity/vpatch-nextcloud-upload.yaml']
_files['appsec-rules/crowdsecurity/vpatch-nextcloud-upload.yaml'] = _old_nc.replace(b'value: "../"', b'value: ".."')
os.makedirs(cfg['hub']['dir'], exist_ok=True)
_idx = _hub.build_index(_files, 'c0ffee0000000000000000000000000000000001', 'github', cfg['waf']['hub_range'][0], now - 3600)
with open(os.path.join(cfg['hub']['dir'], 'index.json'), 'w') as fh:
    json.dump(_idx, fh)
with open(os.path.join(cfg['hub']['dir'], 'status.json'), 'w') as fh:
    json.dump({'at': util.iso(now - 3600), 'state': 'ok', 'commit': _idx['commit'], 'counts': _idx['counts']}, fh)
_old = next(r for r in _hub.build_index(dict(_files, **{'appsec-rules/crowdsecurity/vpatch-nextcloud-upload.yaml': _old_nc}),
                                        'c0ffee0000000000000000000000000000000000', 'github', 10400)['rules']
            if r['name'] == 'example/vpatch-nextcloud-upload')
_hspec, _htext, _ = _rg.build('crowdsec', {'name': _old['name'], 'yaml': _old['yaml'], 'sha256': _old['sha256'],
                                           'commit': 'c0ffee0000000000000000000000000000000000', 'hosts': ['files.example.com'],
                                           'source': 'external', 'license': _idx['license'], 'tests': _old['tests']}, 10400, app.cfg)
app.db.x("INSERT INTO managed_rules(rule_id, kind, placement, position, spec, text, comment, enabled, deleted, origin, "
         "created_by, created_at, updated_at, change_id) VALUES (10400, 'crowdsec', 'before', 950, ?, ?, '', 1, 0, 'created', "
         "'approver', ?, ?, NULL)", (json.dumps(_hspec), _htext, now - 86400 * 3, now - 86400 * 3))
# an AI analysis of the first event (made up)
_e1 = app.db.one('SELECT id FROM events ORDER BY id LIMIT 1')['id']
app.db.x("INSERT INTO event_analyses(event_id, requested_by, requested_at, lang, started_at, finished_at, model, verdict, confidence, action, details) "
         "VALUES (?, 'admin', ?, 'en', ?, ?, 'local-model', 'attack', 0.86, 'block_ip', ?)",
         (_e1, now - 900, now - 890, now - 870, json.dumps({'verdict': 'attack', 'confidence': 0.86, 'action': 'block_ip',
          'summary': 'A scanner probing for secret files: five different file names in two minutes, all answered 404, no other site use.',
          'evidence': ['5 probes for secret files within 2 minutes', 'no internal user requests this path', 'the source hit 3 sites'],
          'action_reason': 'the source keeps probing; a 24-hour block stops it'})))
# a day of periodic reviews (synthetic events above; stored only, nothing sent)
from jtwafmgr import review  # noqa: E402
for k in range(8, 0, -1):
    rid, _ = review.run(app, 'schedule', now - k * 3 * 3600 + 60, notify=False)
    app.db.x('UPDATE reviews SET created_at=? WHERE id=?', (now - k * 3 * 3600 + 60, rid))
# 0.4.100: an nginx update waiting for approval (its page must ask for a one-time code) and the nginx advisories
_now = time.time()
_cid = app.db.x("INSERT INTO changes(op, kind, spec, direction, state, reason, proposed_by, proposed_via, created_at, updated_at, "
                "rule_text, tests) VALUES ('nginx','system',?, 'neutral','pending_approval',?, 'cli:approver','user',?,?,'','[]')",
                (json.dumps({'installed': '1.30.6-1~bookworm', 'target': '1.30.7-1~bookworm'}),
                 'nginx 1.30.6 -> 1.30.7 (synthetic)', _now, _now)).lastrowid
open(R + '/nginx-change', 'w').write(str(_cid))
os.makedirs(os.path.join(R, 'nginxup'), exist_ok=True)
_iss = [('Infinite loop while reading the request body over TLS 1.3', 'major', ['CVE-2099-0101'], None, True),
        ('Buffer overflow when using alias with try_files', 'minor', ['CVE-2099-0102'], 'alias', True),
        ('Memory corruption in HTTP/2 flow control', 'major', ['CVE-2099-0103'], 'http2', False),
        ('Use-after-free during response processing in the resolver', 'medium', ['CVE-2099-0104'], 'resolver', False)]
json.dump({'state': 'ready', 'installed': '1.30.6-1~bookworm', 'candidate': '1.30.7-1~bookworm', 'target': '1.30.7-1~bookworm',
           'security': {'version': '1.30.6', 'exact': True, 'fixed_by_candidate': True, 'major_in_use': True,
                        'issues': [{'title': a, 'severity': b, 'cves': c, 'feature': f, 'in_use': u, 'fixed_in': ['1.30.7+'],
                                    'advisory': '', 'candidate_fixes': True} for a, b, c, f, u in _iss]}},
          open(os.path.join(R, 'nginxup', 'status.json'), 'w'))
json.dump(sec, open(R + '/totp.json', 'w'))
print('events', app.db.one('SELECT COUNT(*) n FROM events')['n'])
