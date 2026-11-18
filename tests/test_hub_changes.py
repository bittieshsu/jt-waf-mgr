"""CrowdSec Hub rules as changes (phase 2) and as virtual patches of the threat intelligence (phase 3): the hub's test
requests, the rule text, the workflow, the API. The hub files here are synthetic, in the hub's format."""
import base64
import hashlib
import json
import os
import time
import unittest

from jtwafmgr import changes, auth, hub, intel, miniyaml, rulegen, sandbox
from jtwafmgr.app import App
from jtwafmgr.changes import ChangeError
from tests.helpers import TempEnv, jload
from tests.test_hub import ZIMBRA

TWO = b"""name: crowdsecurity/vpatch-two-ways
description: "Two ways in (synthetic)"
rules:
  - or:
    - zones:
      - URI
      match:
        type: equals
        value: /a.php
    - zones:
      - HEADERS
      variables:
      - x-exploit
      match:
        type: contains
        value: boom
labels:
  label: "Example App - RCE"
  classification:
   - cve.CVE-2099-0002
"""

MIT = ('MIT License\n\nCopyright (c) example \\ test\n\nPermission is hereby granted, free of charge, to any person obtaining '
       'a copy (synthetic)\n')

TEMPLATE_RAW = b"""id: CVE-2099-0001
info:
  name: test
http:
  - raw:
      - |
        POST /public/error.jsp HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Content-Length: 99

        errCode=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E
      - |
        GET /public/error.jsp?errCode=<svg/onload=alert(1)> HTTP/1.1
        Host: {{Hostname}}
        Referer: https://{{Hostname}}/

    cookie-reuse: true
    matchers:
      - type: status
        status:
          - 403
"""

TEMPLATE_PATH = b"""id: x
info:
  name: x
http:
  - method: POST
    path:
      - "{{BaseURL}}/a.php"
      - "{{BaseURL}}/b.php"
    headers:
      Content-Type: application/json
      X-Exploit: boom
    body: '{{hex_decode("00ff10")}}'
    matchers:
      - type: dsl
        condition: and
        dsl:
          - "status_code_2 == 403"
"""


def tests_dir(name, rule, template):
    return {'.appsec-tests/%s/config.yaml' % name: (
        'appsec-rules:\n  - ./appsec-rules/crowdsecurity/base-config.yaml\n  - ./%s\nnuclei_template: t.yaml\n' % rule).encode(),
        '.appsec-tests/%s/t.yaml' % name: template}


class TestNuclei(unittest.TestCase):
    def test_raw_requests(self):
        t = hub.nuclei_tests(miniyaml.loads(TEMPLATE_RAW))
        self.assertEqual(len(t), 2)
        self.assertEqual(t[0]['method'], 'POST')
        self.assertEqual(t[0]['body'], 'errCode=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E')
        self.assertNotIn('Content-Length', t[0]['headers'])           # sent with the real length
        self.assertNotIn('Host', t[0]['headers'])
        self.assertEqual(t[1]['headers']['Referer'], 'https://%s/' % hub.TEST_HOST)
        # a path with characters an HTTP client cannot send as they are: not taken
        self.assertEqual(t[1]['path'], '/public/error.jsp?errCode=<svg/onload=alert(1)>')

    def test_paths_numbered_matcher_and_binary_body(self):
        t = hub.nuclei_tests(miniyaml.loads(TEMPLATE_PATH))
        self.assertEqual([x['path'] for x in t], ['/b.php'])           # only request 2 must be refused
        self.assertEqual(base64.b64decode(t[0]['body_b64']), b'\x00\xff\x10')

    def test_refused_shapes(self):
        for bad, why in ((TEMPLATE_RAW.replace(b'- 403', b'- 200'), 'test_matchers'),
                         (TEMPLATE_RAW.replace(b'{{Hostname}}/', b'{{nonce}}/'), 'test_placeholder'),
                         (TEMPLATE_RAW.replace(b'{{Hostname}}/', b'{{generate_java_gadget("dns", "x")}}/'), 'test_placeholder'),
                         (TEMPLATE_RAW.replace(b'POST /public', b'PROPFIND /public'), 'test_method'),
                         (TEMPLATE_RAW.replace(b'cookie-reuse: true', b'payloads: {}'), 'test_request_keys'),
                         (TEMPLATE_RAW.replace(b'GET /public', b'GET http://x/public'), 'test_path')):
            with self.assertRaises(hub.Unsupported) as cm:
                hub.nuclei_tests(miniyaml.loads(bad))
            self.assertEqual(cm.exception.why, why)

    def test_requests_to_let_through_helpers_and_groups(self):
        """0.4.92: "status_code_3 == 404" -- an ordinary request the rule must let through; nuclei's random helpers,
        nested and in variables naming each other; {{BaseURL}} alone; annotations; several request groups."""
        doc = miniyaml.loads(b"""id: x
info:
  name: x
variables:
  rid: "{{to_lower(rand_text_alphanumeric(8))}}"
  cb: "{{interactsh-url}}"
  both: "{{rid}}-{{base64(cb)}}"
http:
  - raw:
      - |
        @timeout: 20s
        POST {{BaseURL}} HTTP/1.1
        X-Request-Id: {{rid}}
        X-Both: {{both}}
        Content-Type: application/x-www-form-urlencoded

        class.module.classLoader.x={{rand_base(4)}}&n={{rand_int(1, 9)}}
      - |
        GET /foo/ HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: dsl
        condition: and
        dsl:
          - 'status_code_1 == 403'
          - 'status_code_2 == 404'
  - method: GET
    path:
      - "{{BaseURL}}"
    headers:
      Accept: ../../../../etc/passwd{{
    matchers:
      - type: status
        status:
          - 403
""")
        t = hub.nuclei_tests(doc)
        self.assertEqual([(x['method'], x['path'], x['expect']) for x in t],
                         [('POST', '/', 'refuse'), ('GET', '/', 'refuse'), ('GET', '/foo/', 'pass')])
        self.assertEqual(t[0]['headers']['X-Request-Id'], 'jtwafran')
        self.assertEqual(t[0]['headers']['X-Both'], 'jtwafran-' + base64.b64encode(hub.OAST_HOST.encode()).decode())
        self.assertEqual(t[0]['body'], 'class.module.classLoader.x=jtwa&n=1')
        self.assertEqual(t[1]['headers']['Accept'], '../../../../etc/passwd{{')
        self.assertEqual(hub._test_case('GET', '/', [('User-Agent', '')], None, {})['headers'], {})   # none sent
        # only requests to let through: no proof of the rule
        with self.assertRaises(hub.Unsupported) as cm:
            hub.nuclei_tests(miniyaml.loads(TEMPLATE_PATH.replace(b'status_code_2 == 403', b'status_code_2 == 404')))
        self.assertEqual(cm.exception.why, 'test_matchers')
        # a variable naming itself: refused, not a loop
        with self.assertRaises(hub.Unsupported):
            hub.nuclei_tests(miniyaml.loads(TEMPLATE_RAW.replace(b'info:', b'variables:\n  a: "{{a}}"\ninfo:').replace(
                b'{{Hostname}}/', b'{{a}}/')))

    def test_index_links_tests_to_rules(self):
        files = {'LICENSE': b'MIT License\n\nCopyright (c) example\n', 'appsec-rules/crowdsecurity/vpatch-zimbra.yaml': ZIMBRA,
                 'appsec-rules/crowdsecurity/two.yaml': TWO}
        files.update(tests_dir('zimbra', 'appsec-rules/crowdsecurity/vpatch-zimbra.yaml', TEMPLATE_RAW))
        files.update(tests_dir('two', 'appsec-rules/crowdsecurity/two.yaml', TEMPLATE_RAW.replace(b'403', b'404')))
        idx = hub.build_index(files, 'a' * 40, 'test', 10400)
        by = {r['name']: r for r in idx['rules']}
        self.assertEqual(len(by['example/vpatch-zimbra-xss']['tests']), 2)
        self.assertEqual((by['crowdsecurity/vpatch-two-ways']['tests'], by['crowdsecurity/vpatch-two-ways']['tests_reason']),
                         ([], 'test_matchers'))
        self.assertTrue(hub._wanted('.appsec-tests/zimbra/t.yaml'))
        self.assertFalse(hub._wanted('.appsec-tests/zimbra/../../x.yaml'))
        self.assertFalse(hub._wanted('.appsec-tests/a/b/c.yaml'))

    def test_an_older_index_is_read_again_for_the_same_commit(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        cfg = env.cfg
        os.makedirs(hub.hub_dir(cfg))
        with open(os.path.join(hub.hub_dir(cfg), 'index.json'), 'w') as fh:
            json.dump({'commit': 'a' * 40, 'rules': []}, fh)                        # 0.4.89: no tests, no format
        asked = []

        def fetch(url, limit, accept=None):
            asked.append(url)
            if url.endswith('/commits/master'):
                return json.dumps({'sha': 'a' * 40}).encode()
            if '/git/trees/' in url:
                return json.dumps({'tree': [{'type': 'blob', 'path': 'appsec-rules/crowdsecurity/vpatch-zimbra.yaml'},
                                            {'type': 'blob', 'path': '.appsec-tests/zimbra/config.yaml'},
                                            {'type': 'blob', 'path': '.appsec-tests/zimbra/t.yaml'},
                                            {'type': 'blob', 'path': 'LICENSE'}]}).encode()
            if url.endswith('/LICENSE'):
                return b'MIT License\n'
            if url.endswith('config.yaml'):
                return tests_dir('zimbra', 'appsec-rules/crowdsecurity/vpatch-zimbra.yaml', b'')['.appsec-tests/zimbra/config.yaml']
            if url.endswith('t.yaml'):
                return TEMPLATE_RAW
            return ZIMBRA
        hub.request_sync(cfg)
        st = hub.run(cfg, log=lambda m: None, fetch=fetch)
        self.assertEqual(st['state'], 'ok', st)
        idx = hub.read_index(cfg)
        self.assertEqual((idx['format'], len(idx['rules'][0]['tests'])), (hub.INDEX_FORMAT, 2))
        hub.request_sync(cfg)
        self.assertTrue(hub.run(cfg, log=lambda m: None, fetch=fetch).get('unchanged'))   # now the same commit is enough

    def test_review_fixes_in_the_conversion(self):
        raw = b'id: x\ninfo:\n  name: x\nhttp:\n  - raw:\n      - "POST /up HTTP/1.1\\r\\nHost: {{Hostname}}\\r\\nReferer: {{BaseURL}}/a\\r\\n\\r\\n--b\\r\\nx\\r\\n--b--\\r\\n"\n    matchers:\n      - type: status\n        status:\n          - 403\n'
        [t] = hub.nuclei_tests(miniyaml.loads(raw))
        self.assertEqual(t['body'], '--b\r\nx\r\n--b--\r\n')                     # the body's CRLFs kept
        self.assertEqual(t['headers']['Referer'], 'http://%s/a' % hub.TEST_HOST)   # a URL outside the path
        with self.assertRaises(hub.Unsupported):
            hub._test_case('GET', '/a\U0001F600', [], None, {})
        odd = TWO.replace(b'value: boom', b'value: "bo\\x85om"').replace(b'\\x85', '\x85'.encode())
        self.assertFalse(hub.convert(miniyaml.loads(odd))['ok'])
        self.assertTrue(hub.url_header_only(TWO.decode()))
        self.assertFalse(hub.url_header_only(ZIMBRA.decode()))                    # a parameter: never by itself
        _, red, _ = rulegen.build('redaction', {'fields': ['pin']}, 10150, TempEnv().cfg)
        self.assertIn('ctl:ruleRemoveTargetByTag=crowdsec-hub;ARGS_POST:pin', red)
        self.assertIn('ctl:ruleRemoveTargetByTag=crowdsec-hub;ARGS:json.pin', red)


class TestRuleText(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.cfg = self.env.cfg

    def spec(self, raw=TWO, **kw):
        s = {'name': miniyaml.loads(raw)['name'], 'yaml': raw.decode(), 'sha256': hashlib.sha256(raw).hexdigest(),
             'commit': 'b' * 40, 'hosts': ['www.example.com', 'App.example.com'], 'source': 'external',
             'license': MIT, 'tests': []}
        s.update(kw)
        return s

    def test_sites_sources_ids_and_licence(self):
        norm, text, pl = rulegen.build('crowdsec', self.spec(), 10400, self.cfg)
        self.assertEqual(pl, 'before')
        self.assertEqual(norm['rule_count'], 2)
        self.assertEqual(norm['hosts'], ['app.example.com', 'www.example.com'])
        self.assertEqual(rulegen.check_raw_text(text, cfg=self.cfg), [10400, 10401])
        rules = [ln for ln in text.splitlines() if not ln.startswith('#')]
        self.assertIn('REQUEST_HEADERS:Host|UNIQUE_ID "@rx ^(?:app\\.example\\.com|www\\.example\\.com)', rules[0])
        import re as _re
        rx = _re.compile(rules[0].split('"@rx ', 1)[1].rsplit('" ', 1)[0])
        self.assertTrue(rx.search('app.example.com:443') and rx.search('www.example.com-' + 'a' * 32))
        self.assertFalse(rx.search('evil.example.com') or rx.search('app.example.com.evil.net'))
        _, t2, _ = rulegen.build('crowdsec', self.spec(license='MIT License with exec: something'), 10400, self.cfg)
        self.assertIn('# licence: https://github.com/crowdsecurity/hub/blob/' + 'b' * 40 + '/LICENSE', t2)
        self.assertIn('id:10400,phase:2', rules[1])
        self.assertTrue(any('REMOTE_ADDR "!@ipMatch' in ln for ln in rules))
        self.assertIn('# Copyright (c) example / test', text)        # no backslash can join a line to the next
        self.assertIn('commit ' + 'b' * 40, text)
        self.assertEqual(rulegen.direction('add', 'crowdsec'), 'tighten')
        self.assertEqual(rulegen.direction('delete', 'crowdsec'), 'loosen')

    def test_all_sites(self):
        """0.4.92: a framework's flaw for every site: no Host condition; sites named as well is refused."""
        norm, text, _ = rulegen.build('crowdsec', self.spec(hosts=[], all_sites=True), 10400, self.cfg)
        self.assertTrue(norm['all_sites'])
        self.assertEqual(rulegen.check_raw_text(text, cfg=self.cfg), [10400, 10401])
        self.assertNotIn('REQUEST_HEADERS:Host', text)
        self.assertIn('for: all sites', text)
        self.assertTrue(any('REMOTE_ADDR "!@ipMatch' in ln for ln in text.splitlines()))     # still outside only
        with self.assertRaises(rulegen.SpecError) as cm:
            rulegen.build('crowdsec', self.spec(all_sites=True), 10400, self.cfg)
        self.assertEqual(cm.exception.code, 'all_sites_with_hosts')
        with self.assertRaises(rulegen.SpecError):                  # "all_sites": "yes" is not True
            rulegen.build('crowdsec', self.spec(hosts=[], all_sites='yes'), 10400, self.cfg)

    def test_refusals(self):
        for kw, field in (({'sha256': 'c' * 64}, 'sha256'), ({'hosts': []}, 'hosts'), ({'hosts': ['bad host']}, 'hosts'),
                          ({'source': 'internal'}, 'source'), ({'name': 'example/other'}, 'yaml')):
            with self.assertRaises(rulegen.SpecError) as cm:
                rulegen.build('crowdsec', self.spec(**kw), 10400, self.cfg)
            self.assertEqual(cm.exception.field, field, kw)
        with self.assertRaises(rulegen.SpecError):                   # past the end of the range
            rulegen.build('crowdsec', self.spec(), self.cfg['waf']['hub_range'][1], self.cfg)


class FakeSandbox:
    def __init__(self, ok=True):
        self.ok, self.seen = ok, []

    @staticmethod
    def available():
        return True

    def run_change(self, r, files, tests, managed, samples=None, items=None):
        self.seen.append(tests)
        return {'ok': self.ok, 'cases': len(tests), 'failed': 0 if self.ok else 1,
                'results': [{'origin': 'upstream' if t.get('upstream') else 'test', 'ok': self.ok} for t in tests]}


class TestWorkflow(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.mdir = os.path.join(self.env.dir, 'managed')
        self.spool = os.path.join(self.env.dir, 'spool')
        from jtwafmgr import config
        self.env.cfg = config.load(None, {
            'paths': dict(self.env.cfg['paths']), 'server': {'secure_cookies': False}, 'syslog': {'enabled': False},
            'collector': {'backfill_rotated': False}, 'waf': {'focus_sites': []},
            'hub': {'dir': os.path.join(self.env.dir, 'hub'), 'enabled': True},
            'managed': {'dir': self.mdir, 'spool': self.spool, 'sandbox_dir': os.path.join(self.env.dir, 'sbx')},
            'evidence': {'access_logs': [os.path.join(self.env.dir, '*access.log')]}})
        self.app = App(self.env.cfg)
        self.wf = self.app.workflow
        self.wf.set_setting('sandbox.required', False, 'test')
        a = self.app.auth
        a.create_user('op', 'operator', password='a long test password')
        a.create_user('boss', 'admin', password='a long test password')
        self.secret, _ = a.totp_setup('boss')
        a.totp_enable('boss', auth.totp_code(self.secret, int(time.time() // 30)))
        files = {'LICENSE': MIT.encode(), 'appsec-rules/crowdsecurity/vpatch-zimbra.yaml': ZIMBRA,
                 'appsec-rules/crowdsecurity/two.yaml': TWO}
        files.update(tests_dir('zimbra', 'appsec-rules/crowdsecurity/vpatch-zimbra.yaml', TEMPLATE_RAW))
        files.update(tests_dir('two', 'appsec-rules/crowdsecurity/two.yaml', TEMPLATE_PATH))
        self.write_index(files)
        self.adopt()

    def write_index(self, files):
        os.makedirs(self.env.cfg['hub']['dir'], exist_ok=True)
        idx = hub.build_index(files, 'a' * 40, 'test', 10400)
        with open(os.path.join(self.env.cfg['hub']['dir'], 'index.json'), 'w') as fh:
            json.dump(idx, fh)

    def fake_apply(self):
        for n in sorted(os.listdir(self.spool)):
            if not n.endswith('.req'):
                continue
            req = jload(os.path.join(self.spool, n))
            os.makedirs(self.mdir, exist_ok=True)
            for p, f in (('before', 'before-crs.conf'), ('after', 'after-crs.conf')):
                with open(os.path.join(self.mdir, f), 'w') as fh:
                    fh.write(req['files'][p])
            with open(os.path.join(self.spool, n[:-4] + '.result'), 'w') as fh:
                json.dump({'request_id': n[:-4], 'version': req['version'], 'change_id': req['change_id'], 'result': 'ok',
                           'step': 'done', 'summary': 'test'}, fh)
            os.unlink(os.path.join(self.spool, n))
        self.wf.collect_results()

    def approve(self, cid, note='checked the CrowdSec rule'):
        self.app.db.x('UPDATE users SET totp_last_step=0 WHERE username=?', ('boss',))
        self.wf.approve(cid, self.app.auth.user_row('boss'), auth.totp_code(self.secret, int(time.time() // 30)), note)

    def adopt(self):
        cid = self.wf.propose_adoption('boss')
        self.wf.run_checks(cid)
        self.wf.set_setting('approval.single_admin_mode', True, 'boss')
        self.approve(cid, 'adopting the existing rule files')
        self.fake_apply()

    def test_all_sites_and_requests_to_let_through(self):
        """0.4.92: proposed for all sites (sent to a name no site has; never applied by itself); the hub's ordinary
        requests must not match the rule (whatever else refuses them)."""
        files = {'LICENSE': MIT.encode(), 'appsec-rules/crowdsecurity/two.yaml': TWO}
        files.update(tests_dir('two', 'appsec-rules/crowdsecurity/two.yaml', TEMPLATE_PATH.replace(
            b'"status_code_2 == 403"', b'"status_code_2 == 403"\n          - "status_code_1 == 404"')))
        self.write_index(files)
        cid = self.wf.propose('add', 'crowdsec', {'name': 'crowdsecurity/vpatch-two-ways', 'all_sites': True,
                                                  'hosts': ['app.example.com']}, 'Spring-like flaw: every site', 'op')
        r = self.wf.get(cid)
        spec = json.loads(r['spec'])
        self.assertEqual((spec['all_sites'], spec['hosts']), (True, []))
        tests = json.loads(r['tests'])
        self.assertEqual([(t['host'], t['path'], t['expect']) for t in tests],
                         [(hub.TEST_HOST, '/b.php', 403), (hub.TEST_HOST, '/a.php', 'any')])
        self.assertEqual(tests[1]['absent_rules'], [10400, 10401])
        self.assertNotIn('present_any_rules', tests[1])
        self.assertIn('all sites', changes.summarize('crowdsec', spec, 'add'))
        # a person cannot send what only the system sets
        with self.assertRaises(changes.ChangeError):
            changes._check_tests([{'host': 'a.example.com', 'path': '/', 'expect': 'any', 'source': 'external',
                                   'absent_rules': [1]}])

    def test_wrong_types_are_422_not_500(self):
        """jt-wazuh-mgr 2026-11-18: an exclusion with "host": "chat.example.com" (a string, not {mode, value}) gave 500."""
        for spec, reason in (({'host': 'chat.example.com', 'path': {'mode': 'exact', 'value': '/json/messages'},
                               'rule_ids': [930120], 'targets': ['ARGS:url']}, 'invalid_host_format'),
                             ({'host': {'mode': 'exact', 'value': 'chat.example.com'}, 'path': '/json/messages',
                               'rule_ids': [930120], 'targets': ['ARGS:url']}, 'invalid_path_format'),
                             ({'host': {'mode': 'exact', 'value': 'chat.example.com'}, 'rule_ids': 930120,
                               'targets': ['ARGS:url']}, 'invalid_rule_ids'),
                             (['not', 'an', 'object'], None)):
            with self.assertRaises(ChangeError) as cm:
                self.wf.propose('add', 'exclusion', spec, 'false positive', 'op')
            self.assertEqual(cm.exception.status, 422, spec)
            if reason:
                self.assertEqual(cm.exception.details.get('reason'), reason, spec)

    def test_propose_apply_update_remove(self):
        cid = self.wf.propose('add', 'crowdsec', {'name': 'crowdsecurity/vpatch-two-ways', 'hosts': ['app.example.com'],
                                                  'yaml': 'name: forged', 'tests': []}, 'block the RCE', 'op')
        r = self.wf.get(cid)
        spec = json.loads(r['spec'])
        self.assertEqual(spec['sha256'], hashlib.sha256(TWO).hexdigest())      # the index's file, not the request's
        self.assertEqual((r['direction'], r['rule_id'], spec['rule_count']), ('tighten', 10400, 2))
        tests = json.loads(r['tests'])
        self.assertEqual(len(tests), 1)
        self.assertEqual((tests[0]['host'], tests[0]['expect'], tests[0]['present_any_rules']), ('app.example.com', 403, [10400, 10401]))
        self.assertEqual(base64.b64decode(tests[0]['body_b64']), b'\x00\xff\x10')
        # the next rule starts after both ids of the first
        c2 = self.wf.propose('add', 'crowdsec', {'name': 'example/vpatch-zimbra-xss', 'hosts': ['mail.example.com']}, 'xss', 'op')
        self.assertEqual(self.wf.get(c2)['rule_id'], 10402)
        self.wf.cancel(c2, self.app.auth.user_row('op'))
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval', self.wf.get(cid)['checks'])
        self.approve(cid)
        self.fake_apply()
        with open(os.path.join(self.mdir, 'before-crs.conf')) as fh:
            body = fh.read()
        self.assertIn('id:10400,phase:2', body)
        self.assertIn('id:10401,phase:2', body)
        self.assertIn('# Copyright (c) example', body)
        # the API shows it in use; the rules list names CrowdSec as the author
        from jtwafmgr.web import api_hub
        applied, _ = api_hub._in_use(self.app, hub.read_index(self.env.cfg))
        a = applied['crowdsecurity/vpatch-two-ways']
        self.assertEqual((a['rule_id'], a['rule_count'], a['upstream']), (10400, 2, 'same'))
        # the hub changes the rule: an update keeps the sites and ids; one more "or" branch would need a new id
        files = {'appsec-rules/crowdsecurity/two.yaml': TWO.replace(b'boom', b'bang')}
        files.update(tests_dir('two', 'appsec-rules/crowdsecurity/two.yaml', TEMPLATE_PATH.replace(b'boom', b'bang')))
        self.write_index(files)
        applied, _ = api_hub._in_use(self.app, hub.read_index(self.env.cfg))
        self.assertEqual(applied['crowdsecurity/vpatch-two-ways']['upstream'], 'changed')
        c3 = self.wf.propose('modify', None, {}, 'the hub updated the rule', 'op', item_id=a['item_id'])
        r3 = self.wf.get(c3)
        self.assertEqual(json.loads(r3['spec'])['hosts'], ['app.example.com'])
        self.assertIn('bang', r3['rule_text'])
        self.assertEqual(r3['direction'], 'loosen')                 # a different rule: a person looks at it
        self.wf.cancel(c3, self.app.auth.user_row('op'))
        c4 = self.wf.propose('delete', None, {}, 'software updated', 'op', item_id=a['item_id'])
        self.assertEqual(self.wf.get(c4)['direction'], 'loosen')

    def test_refusals(self):
        for spec, code in (({'name': 'example/none', 'hosts': ['a.example.com']}, 'hub_rule_not_found'),
                           ({'name': 'crowdsecurity/vpatch-two-ways', 'hosts': []}, 'invalid_spec')):
            with self.assertRaises(ChangeError) as cm:
                self.wf.propose('add', 'crowdsec', spec, 'x', 'op')
            self.assertEqual(cm.exception.code, code)
        # a rule without the hub's own tests cannot be proposed (nothing shows the converted rule works)
        files = {'appsec-rules/crowdsecurity/two.yaml': TWO}
        self.write_index(files)
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose('add', 'crowdsec', {'name': 'crowdsecurity/vpatch-two-ways', 'hosts': ['a.example.com']}, 'x', 'op')
        self.assertEqual(cm.exception.code, 'hub_no_tests')
        # a person's own tests may not claim the system's fields
        with self.assertRaises(ChangeError):
            self.wf.propose('add', 'redaction', {'fields': ['pin']}, 'x', 'op', tests=[
                {'host': 'a.example.com', 'path': '/', 'source': 'external', 'expect': 403, 'present_any_rules': [1]}])

    def test_bundle_reserves_each_run(self):
        cid = self.wf.propose_bundle([{'op': 'add', 'kind': 'crowdsec', 'spec': {'name': 'crowdsecurity/vpatch-two-ways', 'hosts': ['a.example.com']}},
                                      {'op': 'add', 'kind': 'crowdsec', 'spec': {'name': 'example/vpatch-zimbra-xss', 'hosts': ['m.example.com']}}],
                                     'two hub rules', 'op')
        ops = json.loads(self.wf.get(cid)['spec'])['ops']
        self.assertEqual([o['rule_id'] for o in ops], [10400, 10402])
        self.assertEqual(len(json.loads(self.wf.get(cid)['tests'])), 3)
        self.assertEqual(self.wf.managed.next_rule_id('crowdsec'), 10403)

    def test_intel_proposes_and_applies_exploited(self):
        self.wf.sandbox = FakeSandbox()
        self.wf.set_setting('apply.auto_tighten_intel', True, 'boss')
        now = time.time()
        from jtwafmgr import software
        orig = software.hosts_of
        software.hosts_of = lambda db, name: ['app.example.com'] if name == 'Example App' else []
        self.addCleanup(setattr, software, 'hosts_of', orig)
        for cve, exploited in (('CVE-2099-0002', 1), ('CVE-2099-0001', 0)):
            self.app.db.x("INSERT INTO intel_threats(cve, product, first_seen, last_seen, affected, exploited, severity, details) "
                          "VALUES (?, 'Example App', ?, ?, 'yes', ?, 'critical', '{}')", (cve, now, now, exploited))
        out = intel.propose_hub_patches(self.app, 1, log=lambda *a: None)
        self.assertEqual(len(out), 2)
        by = {self.app.db.one('SELECT cve FROM intel_threats WHERE patch_change_id=?', (c,))['cve']: c for c in out}
        for c in out:
            self.wf.run_checks(c)
        self.assertEqual(self.wf.get(by['CVE-2099-0002'])['state'], 'applying')        # exploited: applied at once
        self.assertEqual(self.wf.get(by['CVE-2099-0001'])['state'], 'pending_approval')
        self.assertEqual(intel.propose_hub_patches(self.app, 2, log=lambda *a: None), [])  # nothing proposed twice

    def test_intel_never_applies_a_rule_the_hub_warns_about(self):
        self.wf.sandbox = FakeSandbox()
        self.wf.set_setting('apply.auto_tighten_intel', True, 'boss')
        files = {'appsec-rules/crowdsecurity/two.yaml': TWO.replace(b'Two ways in', b'Can cause false positives')}
        files.update(tests_dir('two', 'appsec-rules/crowdsecurity/two.yaml', TEMPLATE_PATH))
        self.write_index(files)
        from jtwafmgr import software
        orig = software.hosts_of
        software.hosts_of = lambda db, name: ['app.example.com']
        self.addCleanup(setattr, software, 'hosts_of', orig)
        now = time.time()
        self.app.db.x("INSERT INTO intel_threats(cve, product, first_seen, last_seen, affected, exploited, severity, details) "
                      "VALUES ('CVE-2099-0002', 'Example App', ?, ?, 'yes', 1, 'critical', '{}')", (now, now))
        [c] = intel.propose_hub_patches(self.app, 1, log=lambda *a: None)
        self.wf.run_checks(c)
        self.assertEqual(self.wf.get(c)['state'], 'pending_approval')

    def test_ids_never_shared_and_intel_adds_missing_sites(self):
        cid = self.wf.propose('add', 'crowdsec', {'name': 'crowdsecurity/vpatch-two-ways', 'hosts': ['app.example.com']}, 'x', 'op')
        self.wf.run_checks(cid)
        self.approve(cid)
        self.fake_apply()
        with self.assertRaises(ChangeError) as cm:                    # one item per rule
            self.wf.propose('add', 'crowdsec', {'name': 'crowdsecurity/vpatch-two-ways', 'hosts': ['b.example.com']}, 'x', 'op')
        self.assertEqual(cm.exception.code, 'hub_rule_in_use')
        from jtwafmgr import software
        orig = software.hosts_of
        software.hosts_of = lambda db, name: ['app.example.com', 'b.example.com']
        self.addCleanup(setattr, software, 'hosts_of', orig)
        now = time.time()
        self.app.db.x("INSERT INTO intel_threats(cve, product, first_seen, last_seen, affected, exploited, severity, details) "
                      "VALUES ('CVE-2099-0002', 'Example App', ?, ?, 'yes', 1, 'critical', '{}')", (now, now))
        [c] = intel.propose_hub_patches(self.app, 1, log=lambda *a: None)
        r = self.wf.get(c)
        self.assertEqual((r['op'], json.loads(r['spec'])['hosts']), ('modify', ['app.example.com', 'b.example.com']))
        self.assertEqual(intel.propose_hub_patches(self.app, 2, log=lambda *a: None), [])    # linked now
        self.wf.run_checks(c)
        self.wf.reject(c, self.app.auth.user_row('boss'), 'not now')
        # a bundle growing the rule in use and adding another: no id handed out twice
        files = {'appsec-rules/crowdsecurity/two.yaml': TWO.replace(b'labels:', b'  - zones:\n    - METHOD\n    match:\n      type: equals\n      value: TRACE\nlabels:'),
                 'appsec-rules/crowdsecurity/vpatch-zimbra.yaml': ZIMBRA}
        files.update(tests_dir('two', 'appsec-rules/crowdsecurity/two.yaml', TEMPLATE_PATH))
        files.update(tests_dir('zimbra', 'appsec-rules/crowdsecurity/vpatch-zimbra.yaml', TEMPLATE_RAW))
        self.write_index(files)
        item = next(it for it in self.wf.managed.items() if it['kind'] == 'crowdsec')
        b = self.wf.propose_bundle([{'op': 'modify', 'item_id': item['id'], 'spec': {}},
                                    {'op': 'add', 'kind': 'crowdsec', 'spec': {'name': 'example/vpatch-zimbra-xss', 'hosts': ['m.example.com']}}],
                                   'grow and add', 'op')
        ops = json.loads(self.wf.get(b)['spec'])['ops']
        self.assertEqual((ops[0]['spec']['rule_count'], ops[1]['rule_id']), (3, 10403))


class TestEvaluate(unittest.TestCase):
    def test_refused_by_another_rule_is_no_proof(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        case = {'host': 'a.example.com', 'path': '/', 'expect': 403, 'present_any_rules': [10400, 10401], 'origin': 'upstream'}
        bad = sandbox.evaluate([case], [{'status': 403, 'rules': [949110, 10201]}], env.cfg)
        good = sandbox.evaluate([case], [{'status': 403, 'rules': [10401, 949110]}], env.cfg)
        self.assertFalse(bad['ok'])
        self.assertTrue(good['ok'])
        # a request the rule must let through: refused by another rule is fine, matched by the rule is not
        let = {'host': 'a.example.com', 'path': '/', 'expect': 'any', 'absent_rules': [10400, 10401], 'origin': 'upstream'}
        self.assertTrue(sandbox.evaluate([let], [{'status': 403, 'rules': [10205, 10299]}], env.cfg)['ok'])
        self.assertTrue(sandbox.evaluate([let], [{'status': 200, 'rules': []}], env.cfg)['ok'])
        self.assertFalse(sandbox.evaluate([let], [{'status': 403, 'rules': [10401, 949110]}], env.cfg)['ok'])
        self.assertFalse(sandbox.evaluate([let], [{'status': 'error:timeout', 'rules': []}], env.cfg)['ok'])


class TestTechStack(unittest.TestCase):
    def test_scope_and_technologies(self):
        from jtwafmgr import techstack as T
        P = lambda label, name='crowdsecurity/vpatch-CVE-2099-1', product=None: T.rule_profile(
            {'name': name, 'label': label, 'product': product if product is not None else label.split(' - ')[0]})
        self.assertEqual(P('Spring4Shell - RCE')['scope'], 'cross')
        self.assertEqual(P('Spring4Shell - RCE')['techs'], ['Spring'])
        self.assertEqual(P('React - RCE')['techs'], ['React'])
        self.assertEqual(P('PHP2Shell - RCE')['techs'], ['PHP'])
        self.assertEqual(P('Laravel Debug Mode - Exposure', 'crowdsecurity/vpatch-laravel-debug-mode')['scope'], 'cross')
        self.assertEqual(P('Environment File - Exposure', 'crowdsecurity/vpatch-env-access')['scope'], 'cross')
        self.assertEqual(P('Zimbra Collaboration (ZCS) - XSS')['scope'], 'app')
        self.assertEqual(P('PHPSHE - SQL Injection')['scope'], 'app')                 # an application, not PHP
        lp = P('LearnPress - PHP Object Injection')                                   # a WordPress plugin
        self.assertEqual((lp['scope'], lp['techs']), ('app', []))
        self.assertEqual(P('x', 'crowdsecurity/crs-exclusion-plugin-nextcloud', '')['scope'], 'none')
        self.assertEqual(P('Log4Shell - RCE')['match'], ['Log4j', 'Java'])           # bundled by Java applications
        self.assertEqual(P('Spring - Path Traversal')['match'], ['Spring'])          # not every Java application
        self.assertEqual(T.app_techs('LibreNMS / Observium'), ['PHP', 'Laravel'])
        self.assertEqual(T.app_techs('Zulip'), ['Python', 'Django'])
        self.assertEqual(T.app_techs('Next.js'), ['Next.js', 'React', 'Node.js'])  # a technology entered by a person
        prods = [{'name': 'Zimbra', 'sites': ['mail.example.com']}, {'name': 'Nextcloud', 'sites': ['cloud.example.com']},
                 {'name': 'LibreNMS / Observium', 'sites': ['nms.example.com']}]
        rel = T.related_by_tech(['PHP'], prods)
        self.assertEqual(rel, [{'name': 'PHP', 'via': ['Nextcloud', 'LibreNMS / Observium'],
                                'sites': ['cloud.example.com', 'nms.example.com']}])
        self.assertEqual(T.related_by_tech(['Log4j', 'Java'], prods)[0]['via'], ['Zimbra'])


if __name__ == '__main__':
    unittest.main()
