"""Threat intelligence (intel.py) and the software list (software.py), against fake LLM and MCP servers: the tool
loop of both providers, what is kept from the answer, alerts for exploited vulnerabilities, the budget, fetch_url's
limits, the guesses from packages and access logs, the API."""
import http.server
import json
import os
import threading
import time
import unittest

from jtwafmgr import auth, intel, software
from jtwafmgr.app import App
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv
from tests.test_api import PW, Client

ANSWER = {'notes': 'checked', 'threats': [
    {'id': 'CVE-2026-11111', 'product': 'Example CMS', 'summary': 'path traversal in the upload handler',
     'affected_versions': '< 3.2.1', 'fixed_version': '3.2.1', 'our_version': '3.1.0', 'affected': 'yes', 'exploited': True,
     'exploited_evidence': 'CISA KEV', 'severity': 'critical', 'attack_vector': 'url',
     'request_pattern': 'POST /upload.php with ../ in the filename parameter', 'references': ['https://nvd.nist.gov/vuln/detail/CVE-2026-11111']},
    {'id': 'CVE-2026-22222', 'product': 'Something Else', 'summary': 'not ours', 'affected_versions': '', 'fixed_version': '',
     'our_version': '', 'affected': 'yes', 'exploited': True, 'exploited_evidence': '', 'severity': 'critical',
     'attack_vector': 'url', 'request_pattern': '', 'references': ['https://example.com/x']},
    {'id': 'not-an-id', 'product': 'nginx', 'summary': 'invented', 'affected_versions': '', 'fixed_version': '', 'our_version': '',
     'affected': 'unknown', 'exploited': False, 'exploited_evidence': '', 'severity': 'low', 'attack_vector': 'unknown',
     'request_pattern': '', 'references': ['https://nginx.org/']},
    {'id': 'CVE-2026-33333', 'product': 'nginx', 'summary': 'no references', 'affected_versions': '', 'fixed_version': '',
     'our_version': '', 'affected': 'unknown', 'exploited': False, 'exploited_evidence': '', 'severity': 'low',
     'attack_vector': 'unknown', 'request_pattern': '', 'references': ['http://insecure.example.com/']},
    {'id': 'cve-2026-44444', 'product': 'NGINX', 'summary': 'request smuggling', 'affected_versions': '1.20-1.27',
     'fixed_version': '1.27.4', 'our_version': '1.22.1', 'affected': 'unknown', 'exploited': False, 'exploited_evidence': '',
     'severity': 'high', 'attack_vector': 'header', 'request_pattern': 'two Content-Length headers',
     'references': ['https://nginx.org/en/security_advisories.html', 'javascript:alert(1)']}]}


class Fake(http.server.BaseHTTPRequestHandler):
    """One server for all fakes: /v1/chat/completions (OpenAI), /v1/messages (Anthropic), /mcp (MCP)."""
    script = []          # replies for the LLM, in order
    seen = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length') or 0)) or b'{}')
        Fake.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
        if self.path == '/mcp':
            if body.get('method') == 'notifications/initialized':
                self.send_response(202)
                self.end_headers()
                return
            if body.get('method') == 'initialize':
                res = {'protocolVersion': intel.MCP_PROTOCOL, 'capabilities': {}, 'serverInfo': {'name': 'fake'}}
            else:
                res = {'content': [{'type': 'text', 'text': 'Example CMS 3.2.1 fixes CVE-2026-11111 (exploited) '
                                                            'https://nvd.nist.gov/vuln/detail/CVE-2026-11111'}]}
            data = ('event: message\ndata: %s\n\n' % json.dumps({'jsonrpc': '2.0', 'id': body.get('id'), 'result': res})).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Mcp-Session-Id', 'sess-1')
            self.end_headers()
            self.wfile.write(data)
            return
        reply = Fake.script.pop(0) if Fake.script else {'error': 'no more'}
        status = reply.pop('_status', 200) if isinstance(reply, dict) else 200
        data = json.dumps(reply).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def openai_reply(content=None, calls=None):
    m = {'role': 'assistant', 'content': content}
    if calls:
        m['tool_calls'] = [{'id': 'c%d' % i, 'type': 'function', 'function': {'name': n, 'arguments': json.dumps(a)}}
                           for i, (n, a) in enumerate(calls)]
    return {'choices': [{'message': m}], 'usage': {'prompt_tokens': 1000, 'completion_tokens': 200}}


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fake)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = 'http://127.0.0.1:%d' % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Fake.script, Fake.seen = [], []
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        self.app.cfg.data['notify']['enabled'] = True
        self.app.cfg.data['notify']['webhook_enabled'] = True
        self.app.cfg.data['notify']['webhook_url'] = 'https://hooks.example.com/x'
        self.app.cfg.data['intel'].update(enabled=True, provider='openai', url=self.url + '/v1', model='m', api_key='k',
                                          search='mcp', mcp_url=self.url + '/mcp', max_rounds=5, timeout_seconds=60)
        software.save(self.app.db, 'test', 'Example CMS', '3.1.0')
        software.save(self.app.db, 'test', 'nginx', '1.22.1')
        software.save(self.app.db, 'test', 'Unconfirmed App', '1.0', confirmed_flag=False)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()


class TestRun(Base):
    def test_openai_tool_loop_and_what_is_kept(self):
        self.app.cfg.data['intel']['patches'] = False        # virtual patches: TestPatches
        Fake.script = [openai_reply(calls=[('web_search', {'query': 'Example CMS CVE'}),
                                           ('fetch_url', {'url': 'http://nvd.nist.gov/x'})]),
                       openai_reply(content=json.dumps(ANSWER))]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        r = self.app.db.one('SELECT * FROM intel_runs WHERE id=?', (rid,))
        self.assertIsNone(r['error'])
        self.assertEqual((r['tokens_in'], r['tokens_out']), (2000, 400))
        self.assertEqual(json.loads(r['searches']), ['Example CMS CVE'])
        kept = json.loads(r['threats'])
        self.assertEqual([t['id'] for t in kept], ['CVE-2026-11111', 'CVE-2026-44444'])
        ng = kept[1]
        self.assertEqual((ng['product'], ng['our_version']), ('nginx', '1.22.1'))      # our list, not the model's
        self.assertEqual(ng['references'], ['https://nginx.org/en/security_advisories.html'])
        # what went to the model: confirmed products only, nothing about sites
        first = [b for p, h, b in Fake.seen if p == '/v1/chat/completions'][0]
        user = first['messages'][1]['content']
        self.assertIn('Example CMS 3.1.0', user)
        self.assertNotIn('Unconfirmed App', user)
        tool_msgs = [m for m in [b for p, h, b in Fake.seen if p == '/v1/chat/completions'][1]['messages'] if m['role'] == 'tool']
        self.assertIn('only https', tool_msgs[1]['content'])                          # fetch_url refused http
        # exploited and affecting our version: a critical alert; new threats: a notification
        a = self.app.db.one("SELECT * FROM alerts WHERE kind='exploited_vulnerability'")
        self.assertEqual(a['severity'], 'critical')
        self.assertTrue(self.app.db.one("SELECT 1 FROM notifications WHERE event='intel.new_threats'"))
        # the same threats again: nothing new, no second alert
        Fake.script = [openai_reply(content=json.dumps(ANSWER))]
        intel.run(self.app, 'manual', log=lambda m: None)
        self.assertEqual(self.app.db.one("SELECT COUNT(*) FROM alerts WHERE kind='exploited_vulnerability'")[0], 1)
        self.assertEqual(self.app.db.one("SELECT COUNT(*) FROM intel_threats")[0], 2)

    def test_handled_threat_raises_no_alert(self):
        a = dict(ANSWER, threats=[dict(ANSWER['threats'][0], exploited=False)])
        Fake.script = [openai_reply(content=json.dumps(a))]
        intel.run(self.app, 'manual', log=lambda m: None)
        tid = self.app.db.one('SELECT id FROM intel_threats')['id']
        intel.set_status(self.app.db, self.app.audit, tid, 'handled', 'alice')
        Fake.script = [openai_reply(content=json.dumps(ANSWER))]           # now exploited, but a person handled it
        intel.run(self.app, 'manual', log=lambda m: None)
        self.assertIsNone(self.app.db.one("SELECT 1 FROM alerts WHERE kind='exploited_vulnerability'"))

    def test_failure_and_budget(self):
        Fake.script = [{'_status': 401, 'error': 'bad key'}]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        self.assertTrue(self.app.db.one('SELECT error FROM intel_runs WHERE id=?', (rid,))['error'].startswith('unauthorized'))
        self.assertTrue(self.app.db.one("SELECT 1 FROM notifications WHERE event='intel.failed'"))
        self.app.cfg.data['intel']['daily_tokens'] = 100
        self.app.db.x('UPDATE intel_runs SET tokens_in=500')
        self.assertEqual(intel.over_budget(self.app.cfg, self.app.db), 'daily_tokens')
        self.assertIsNone(intel.run(self.app, 'manual', log=lambda m: None))

    def test_not_ready_and_due(self):
        self.app.cfg.data['intel']['enabled'] = False
        self.assertIsNone(intel.run_job(self.app, log=lambda m: None) and None)
        self.assertEqual(intel.readiness(self.app.cfg), 'disabled')
        self.app.cfg.data['intel'].update(enabled=True, url='', model='')
        self.app.cfg.data['llm'].update(url=self.url + '/v1', model='local-model', api_key='k1')   # the first tier's server
        self.assertIsNone(intel.readiness(self.app.cfg))
        self.assertEqual(intel.openai_target(self.app.cfg), (self.url + '/v1', 'local-model', 'k1'))
        Fake.script = [openai_reply(content=json.dumps({'notes': '', 'threats': []}))]
        self.assertIsNotNone(intel.run_job(self.app, log=lambda m: None))         # first run: due
        self.assertIsNone(intel.run_job(self.app, log=lambda m: None))            # not due again yet
        intel.request_run(self.app.cfg)
        Fake.script = [openai_reply(content=json.dumps({'notes': '', 'threats': []}))]
        self.assertIsNotNone(intel.run_job(self.app, log=lambda m: None))         # asked
        self.assertFalse(os.path.exists(intel.request_file(self.app.cfg)))

    def test_anthropic_loop(self):
        c = self.app.cfg.data['intel']
        c.update(provider='anthropic', url=self.url, model='')
        msg = lambda content, stop: {'content': content, 'stop_reason': stop, 'usage': {'input_tokens': 300, 'output_tokens': 50}}  # noqa: E731
        Fake.script = [msg([{'type': 'tool_use', 'id': 't1', 'name': 'web_search', 'input': {'query': 'nginx CVE'}}], 'tool_use'),
                       msg([{'type': 'server_tool_use', 'id': 's1', 'name': 'web_search', 'input': {'query': 'x'}}], 'pause_turn'),
                       msg([{'type': 'text', 'text': json.dumps(ANSWER)}], 'end_turn')]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        r = self.app.db.one('SELECT * FROM intel_runs WHERE id=?', (rid,))
        self.assertIsNone(r['error'])
        self.assertEqual(r['model'], intel.ANTHROPIC_MODEL)
        calls = [(h, b) for p, h, b in Fake.seen if p == '/v1/messages']
        h, b = calls[0]
        self.assertEqual(h.get('anthropic-version'), intel.ANTHROPIC_VERSION)
        self.assertEqual(h.get('x-api-key'), 'k')
        self.assertNotIn('fallbacks', b)                        # only on the Anthropic API itself
        self.assertEqual(b['output_config']['format']['type'], 'json_schema')
        self.assertNotIn('temperature', b)
        self.assertEqual(calls[1][1]['messages'][-1]['content'][0]['type'], 'tool_result')
        self.assertEqual(calls[2][1]['messages'][-1]['role'], 'assistant')          # pause_turn: resent as is
        self.assertEqual(json.loads(r['searches']), ['nginx CVE', 'x'])
        self.assertEqual(len(json.loads(r['threats'])), 2)
        # the provider's own search tools
        c['search'] = 'provider'
        tools = intel.Session(self.app.cfg).anthropic_tools()
        self.assertEqual([t['type'] for t in tools], ['web_search_20260209', 'web_fetch_20260209'])
        self.assertIn('nvd.nist.gov', tools[1]['allowed_domains'])

    def test_anthropic_refusal(self):
        self.app.cfg.data['intel'].update(provider='anthropic', url=self.url)
        Fake.script = [{'content': [], 'stop_reason': 'refusal', 'stop_details': {'category': 'cyber'}, 'usage': {}}]
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        self.assertTrue(self.app.db.one('SELECT error FROM intel_runs WHERE id=?', (rid,))['error'].startswith('refused'))

    def test_no_confirmed_software(self):
        self.app.db.x('UPDATE software SET confirmed=0')
        rid = intel.run(self.app, 'manual', log=lambda m: None)
        self.assertEqual(self.app.db.one('SELECT note FROM intel_runs WHERE id=?', (rid,))['note'], 'no confirmed software')
        self.assertFalse([1 for p, h, b in Fake.seen if p.startswith('/v1')])


class TestPatches(Base):
    T = {'id': 'CVE-2026-11111', 'product': 'Example CMS', 'references': ['https://nvd.nist.gov/vuln/detail/CVE-2026-11111']}

    def good(self, **k):
        return dict({'possible': True, 'target': 'path', 'header': '', 'regex': '^/upload\\.php/\\.\\./',
                     'attack_examples': ['/upload.php/../etc/passwd'], 'benign_examples': ['/upload.php', '/index.php'],
                     'explanation': 'x'}, **k)

    def test_spec_checks(self):
        samples = [{'host': 'cms.example.com', 'method': 'GET', 'path': '/news/2026/11/hello?page=2'}]
        spec, tests = intel._patch_spec(self.good(), self.T, samples, ['cms.example.com'])
        self.assertEqual((spec['target'], spec['host'], spec['source']), ('path', {'mode': 'exact', 'value': 'cms.example.com'}, 'external'))
        self.assertEqual(tests, [{'expect': 403, 'source': 'external', 'host': 'cms.example.com', 'path': '/upload.php/../etc/passwd'}])
        self.assertEqual(intel._patch_spec(self.good(), self.T, samples, [])[0]['host']['mode'], 'any')
        for bad, code in ((dict(possible=False), 'not_possible'), (dict(regex='upload'), 'not_anchored'),
                          (dict(regex='^/(a+)+$', attack_examples=['/aaa']), 'regex_redos'),
                          (dict(attack_examples=['/other']), 'misses_examples'),
                          (dict(regex='^/'), 'matches_normal'), (dict(regex='^/news/'), 'misses_examples'),
                          (dict(regex='^/news/', attack_examples=['/news/x']), 'matches_normal'),
                          (dict(target='header', header='Cookie', regex='x', attack_examples=['x']), 'bad_header'),
                          (dict(target='header', header='X-Api-Version', regex='', attack_examples=['x']), 'bad_regex'),
                          (dict(target='header', header='User-Agent', regex='mozilla', attack_examples=['mozilla/5']), 'matches_normal')):
            with self.assertRaises(intel.IntelError) as cm:
                intel._patch_spec(self.good(**bad), self.T, samples, [])
            self.assertEqual(cm.exception.code, code, bad)

    def test_propose(self):
        now = time.time()
        det = dict(self.T, attack_vector='url', request_pattern='../ in the path after upload.php', summary='traversal', our_version='3.1.0')
        for cve, exploited, vector in (('CVE-2026-11111', 1, 'url'), ('CVE-2026-22222', 1, 'url'), ('CVE-2026-33333', 1, 'body')):
            self.app.db.x("INSERT INTO intel_threats(cve, product, first_seen, last_seen, affected, exploited, severity, details) "
                          "VALUES (?, 'Example CMS', ?, ?, 'yes', ?, 'critical', ?)",
                          (cve, now, now, exploited, json.dumps(dict(det, id=cve, attack_vector=vector))))
        seen = []

        def propose(op, kind, spec, reason, actor, **k):
            seen.append((kind, spec, actor, k.get('owner')))
            return 77

        self.app.workflow.propose = propose
        answers = iter([self.good(), dict(self.good(), possible=False)])
        out, a, b = intel.propose_patches(self.app, 1, ask=lambda *x: (next(answers), 10, 5), log=lambda m: None)
        self.assertEqual((out, a, b), ([77], 20, 10))
        self.assertEqual(seen[0][0], 'confident_block')
        self.assertEqual((seen[0][2], seen[0][3]), ('intel', 'intel'))
        rows = {r['cve']: r for r in self.app.db.q('SELECT * FROM intel_threats')}
        self.assertEqual(rows['CVE-2026-11111']['patch_change_id'], 77)
        self.assertEqual(rows['CVE-2026-22222']['patch_note'], 'not_possible')
        self.assertEqual(rows['CVE-2026-33333']['patch_note'], '')          # a body attack: no URL / header patch
        # exploited, affects us, and no rule could be written: a person decides now
        self.assertTrue(self.app.db.one("SELECT 1 FROM alerts WHERE dedup LIKE 'intel-patch:CVE-2026-22222%'"))
        # the patch is in force and a person updated the software: the patch may go
        self.app.db.x("INSERT INTO changes(id, op, kind, spec, direction, state, proposed_by, created_at, updated_at, rule_id) "
                      "VALUES (77, 'add', 'confident_block', '{}', 'tighten', 'applied', 'intel', 0, 0, 10260)")
        self.assertEqual(intel.remind_removal(self.app), 0)
        self.app.db.x("UPDATE software SET version='3.2.1' WHERE name='Example CMS'")
        self.assertEqual(intel.remind_removal(self.app), 1)
        self.assertTrue(self.app.db.one("SELECT 1 FROM alerts WHERE dedup LIKE 'intel-remove:CVE-2026-11111%'"))
        # tried once: not again
        out, _, _ = intel.propose_patches(self.app, 2, ask=lambda *x: (self.good(), 1, 1), log=lambda m: None)
        self.assertEqual(out, [])


class TestFetch(unittest.TestCase):
    def test_limits(self):
        doms = ['nvd.nist.gov']
        self.assertIn('only https', intel.fetch_url('http://nvd.nist.gov/', doms))
        self.assertIn('not on the list', intel.fetch_url('https://evil.example.com/', doms))
        self.assertIn('not on the list', intel.fetch_url('https://nvd.nist.gov.evil.example.com/', doms))
        self.assertIn('public addresses', intel.fetch_url('https://nvd.nist.gov/', doms, resolve=lambda h, p: False))
        self.assertTrue(intel.allowed('services.nvd.nist.gov', doms))
        self.assertFalse(intel.allowed('xnvd.nist.gov', doms))

    def test_html_text(self):
        t = intel.html_text('<html><head><title>x</title><script>evil()</script></head><body><h1>CVE-1</h1><p>a&amp;b</p></body></html>')
        self.assertNotIn('evil', t)
        self.assertIn('CVE-1', t)
        self.assertIn('a&b', t)

    def test_mcp_sse(self):
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fake)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            m = intel.Mcp('http://127.0.0.1:%d/mcp' % srv.server_address[1])
            out = m.call('web_search', {'query': 'q'})
            self.assertIn('CVE-2026-11111', out)
            self.assertEqual(m.session, 'sess-1')
        finally:
            srv.shutdown()
            srv.server_close()


class TestSoftware(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def test_dpkg(self):
        p = os.path.join(self.env.dir, 'status')
        with open(p, 'w') as fh:
            fh.write('Package: nginx\nStatus: install ok installed\nVersion: 1.22.1-9\n\n'
                     'Package: openssl\nStatus: deinstall ok config-files\nVersion: 3.0.1\n\n'
                     'Package: libmodsecurity3t64\nStatus: install ok installed\nVersion: 3.0.14-1build2\n')
        self.assertEqual(software.dpkg_packages(p), {'nginx': '1.22.1-9', 'libmodsecurity3t64': '3.0.14-1build2'})

    def test_logs_and_refresh(self):
        d = os.path.join(self.env.dir, 'tr')
        os.makedirs(d, exist_ok=True)
        lines = [json.dumps({'vhost': 'sso.example.com', 'path': '/realms/x/protocol/openid-connect/token', 'http_status': 200})] * 4
        lines += [json.dumps({'vhost': 'www.example.com', 'path': '/wp-content/x.css', 'http_status': 404})] * 5   # probes
        lines += ['192.0.2.1 - - [14/Nov/2026:10:00:00 +0800] "GET /remote.php/dav/files/a HTTP/1.1" 207 10 "-" "x"'] * 3
        with open(os.path.join(d, 'files.example.com.access.log'), 'w') as fh:
            fh.write('\n'.join(lines[8:]) + '\n')
        with open(os.path.join(d, 'access.log'), 'w') as fh:
            fh.write('\n'.join(lines[:9]) + '\n')
        self.app.cfg.data['traffic']['logs'] = [d + '/*access.log']
        found = software.scan_logs(self.app.cfg)
        self.assertEqual(found['Keycloak'], {'sso.example.com': 4})
        self.assertNotIn('WordPress', found)
        self.assertEqual(found['Nextcloud'], {'files.example.com': 3})
        out = software.refresh(self.app, 'alice')
        self.assertGreaterEqual(out['added'], 2)
        rows = {r['name']: r for r in software.listing(self.app.db)}
        self.assertFalse(rows['Keycloak']['confirmed'])
        self.assertEqual(rows['Keycloak']['hosts'], ['sso.example.com'])
        self.assertEqual(software.confirmed(self.app.db), [])
        software.save(self.app.db, 'alice', 'Keycloak', '26.0.5', sid=rows['Keycloak']['id'])
        self.assertEqual(software.confirmed(self.app.db), [{'name': 'Keycloak', 'version': '26.0.5'}])
        software.refresh(self.app, 'alice')                               # a person's entry stays
        self.assertEqual(software.confirmed(self.app.db), [{'name': 'Keycloak', 'version': '26.0.5'}])

    def test_validation(self):
        for name, ver in (('<script>', '1'), ('ok', 'a b'), ('', '1')):
            with self.assertRaises(software.SoftwareError):
                software.save(self.app.db, 'a', name, ver)
        software.save(self.app.db, 'a', 'Grafana', '11.2.0')
        with self.assertRaises(software.SoftwareError):
            software.save(self.app.db, 'a', 'Grafana', '11.2.0')


class TestIntelApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = TempEnv()
        cls.app = App(cls.env.cfg)
        a = cls.app.auth
        a.create_user('viewer1', 'viewer', password=PW)
        a.create_user('admin1', 'admin', password=PW)
        cls.secret, _ = a.totp_setup('admin1')
        a.totp_enable('admin1', auth.totp_code(cls.secret, int(time.time() // 30)))
        cls.srv, _ = start_background(cls.app)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.env.cleanup()

    def admin(self):
        self.app.db.x("UPDATE users SET totp_last_step=0 WHERE username='admin1'")
        c = Client(self.port)
        self.assertEqual(c.login('admin1', totp=auth.totp_code(self.secret, int(time.time() // 30)))[0], 200)
        return c

    def test_software_and_run(self):
        v = Client(self.port)
        self.assertEqual(v.login('viewer1')[0], 200)
        st, obj, _ = v.req('GET', '/api/v1/intel')
        self.assertEqual(st, 200)
        self.assertEqual(obj['status']['not_ready_reason'], 'disabled')
        self.assertEqual(v.req('POST', '/api/v1/intel/software', {'name': 'Grafana', 'version': '11.2.0'})[0], 403)
        c = self.admin()
        st, obj, _ = c.req('POST', '/api/v1/intel/software', {'name': 'Grafana', 'version': '11.2.0', 'hosts': ['mon.example.com']})
        self.assertEqual(st, 201, obj)
        sid = obj['software'][0]['id']
        self.assertTrue(obj['software'][0]['confirmed'])
        self.assertEqual(c.req('POST', '/api/v1/intel/software', {'name': 'Grafana', 'version': '1'})[0], 409)
        self.assertEqual(c.req('POST', '/api/v1/intel/software', {'name': 'x<y', 'version': '1'})[0], 400)
        st, obj, _ = c.req('PATCH', '/api/v1/intel/software/%d' % sid, {'version': '11.3.0', 'confirmed': False})
        self.assertEqual((st, obj['software'][0]['version'], obj['software'][0]['confirmed']), (200, '11.3.0', False))
        st, obj, _ = c.req('POST', '/api/v1/intel/software/guess', {})
        self.assertEqual(st, 200)
        self.assertIn('added', obj)
        self.assertEqual(c.req('POST', '/api/v1/intel/run', {})[0], 409)          # not switched on
        self.assertEqual(c.req('DELETE', '/api/v1/intel/software/%d' % sid)[0], 200)
        self.assertEqual(c.req('DELETE', '/api/v1/intel/software/%d' % sid)[0], 404)
        self.assertEqual(c.req('POST', '/api/v1/intel/threats/999', {'status': 'handled'})[0], 404)
        for action in ('software.added', 'software.changed', 'software.guessed', 'software.removed'):
            self.assertTrue(self.app.db.one('SELECT 1 FROM audit WHERE action=?', (action,)), action)


if __name__ == '__main__':
    unittest.main()
