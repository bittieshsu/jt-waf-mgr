"""HTTP/2 / HTTP/3 off for a while and back on (protooff.py, 0.4.98): the plan, the marked lines, the root program's own
checks and rollback, the workflow (and the nginx update job proposing it for a major advisory)."""
import json
import os
import shutil
import tempfile
import unittest

from jtwafmgr import config, nginxup, protooff
from jtwafmgr.app import App
from jtwafmgr.apply import Applier, Fail
from jtwafmgr.changes import ChangeError
from tests.helpers import TempEnv

NGINX = """events {}
http {
    include %(d)s/vhost/*.conf;
}
"""
A = """server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;   # v6
    server_name a.example.com;
    location / { proxy_pass http://127.0.0.1:9000; }
}
"""
B = """server {
    listen 443 ssl;
    http2 on;
    listen 443 quic reuseport;
    http3 on;
    server_name b.example.com;
    location / { proxy_pass http://127.0.0.1:9001; }
}
"""


def tree(d, b=B):
    os.makedirs(os.path.join(d, 'vhost'), exist_ok=True)
    for name, text in (('nginx.conf', NGINX % {'d': d}), ('vhost/a.conf', A), ('vhost/b.conf', b)):
        with open(os.path.join(d, name), 'w') as fh:
            fh.write(text)


def rd(p):
    with open(p) as fh:
        return fh.read()


class TestPlan(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='jtwaf-proto-')
        self.addCleanup(shutil.rmtree, self.d, True)
        tree(self.d)
        self.cfg = config.load(None, {'paths': {'nginx_conf': os.path.join(self.d, 'nginx.conf')}})

    def test_off_and_back_exactly(self):
        p = protooff.plan(self.cfg, 'http2', 'off')
        self.assertEqual(len(p['edits']), 3)
        st = protooff.state(self.cfg)
        self.assertEqual((st['http2']['on'], st['http3']['on']), (3, 2))
        for f, es in {e['file']: [x for x in p['edits'] if x['file'] == e['file']] for e in p['edits']}.items():
            new = protooff.edit(rd(f), protooff.with_change(dict(p, edits=es), 7))
            with open(f, 'w') as fh:
                fh.write(new)
        a = rd(os.path.join(self.d, 'vhost/a.conf'))
        self.assertIn('    listen 443 ssl;  # jt-waf-mgr: http2 off (change #7): listen 443 ssl http2;\n', a)
        self.assertIn('    listen [::]:443 ssl;  # jt-waf-mgr: http2 off (change #7): listen [::]:443 ssl http2;   # v6\n', a)
        self.assertIn('    # jt-waf-mgr: http2 off (change #7): http2 on;\n', rd(os.path.join(self.d, 'vhost/b.conf')))
        st = protooff.state(self.cfg)
        self.assertEqual((st['http2']['on'], st['http2']['off_by_us'], st['http2']['change_ids']), (0, 3, [7]))
        back = protooff.plan(self.cfg, 'http2', 'on')
        for f in {e['file'] for e in back['edits']}:
            new = protooff.edit(rd(f), [e for e in back['edits'] if e['file'] == f])
            with open(f, 'w') as fh:
                fh.write(new)
        self.assertEqual(rd(os.path.join(self.d, 'vhost/b.conf')), B)
        self.assertEqual(rd(os.path.join(self.d, 'vhost/a.conf')), A)            # its comment too
        with self.assertRaises(protooff.PlanError) as cm:
            protooff.plan(self.cfg, 'http2', 'on')
        self.assertEqual(cm.exception.code, 'nothing_to_do')

    def test_shared_snippet_case_and_crlf(self):
        """0.4.98 review: a snippet included by several servers is edited once; "ON" counts; CRLF stays CRLF."""
        os.makedirs(os.path.join(self.d, 'snippets'))
        with open(os.path.join(self.d, 'snippets/h2.conf'), 'w', newline='') as fh:
            fh.write('http2 ON;\r\n')
        with open(os.path.join(self.d, 'vhost/b.conf'), 'w') as fh:
            fh.write('server {\n    listen 443 ssl;\n    include %s/snippets/h2.conf;\n    server_name b.example.com;\n}\n'
                     'server {\n    listen 8443 ssl;\n    include %s/snippets/h2.conf;\n    server_name c.example.com;\n}\n'
                     % (self.d, self.d))
        p = protooff.plan(self.cfg, 'http2', 'off')
        self.assertEqual(sorted(os.path.basename(e['file']) for e in p['edits']), ['a.conf', 'a.conf', 'h2.conf'])
        self.assertEqual(protooff.state(self.cfg)['http2']['on'], 3)
        f = os.path.join(self.d, 'snippets/h2.conf')
        with open(f, newline='') as fh:
            text = fh.read()
        new = protooff.edit(text, protooff.with_change(dict(p, edits=[e for e in p['edits'] if e['file'] == f]), 3))
        self.assertEqual(new, '# jt-waf-mgr: http2 off (change #3): http2 ON;\r\n')
        _, n, _ = protooff.signature(self.cfg, 'http2')
        self.assertEqual(n, 3)                          # lines, not inclusions

    def test_only_lines_of_applied_changes_go_back(self):
        with open(os.path.join(self.d, 'vhost/b.conf'), 'w') as fh:
            fh.write('server {\n    listen 443 ssl;\n    # jt-waf-mgr: http2 off (change #4): http2 on;\n'
                     '    # jt-waf-mgr: http2 off (change #9): http2 on;\n    server_name b.example.com;\n}\n')
        p = protooff.plan(self.cfg, 'http2', 'on', from_changes=[4])
        self.assertEqual([e['line'] for e in p['edits']], [3])
        self.assertEqual(protooff.state(self.cfg, from_changes=[4])['http2']['off_by_us'], 1)
        with self.assertRaises(protooff.PlanError):
            protooff.plan(self.cfg, 'http2', 'on', from_changes=[])

    def test_quic_only_server_refused(self):
        with open(os.path.join(self.d, 'vhost/b.conf'), 'w') as fh:
            fh.write('server {\n    listen 443 quic;\n    http3 on;\n    server_name b.example.com;\n}\n')
        with self.assertRaises(protooff.PlanError) as cm:
            protooff.plan(self.cfg, 'http3', 'off')
        self.assertEqual(cm.exception.code, 'quic_only_server')    # nginx would listen on port 80 for it

    def test_quic_listen_goes_whole(self):
        p = protooff.plan(self.cfg, 'http3', 'off')
        news = sorted(e['new'].strip() for e in p['edits'])
        self.assertEqual(news, ['# jt-waf-mgr: http3 off (change #0): http3 on;',
                                '# jt-waf-mgr: http3 off (change #0): listen 443 quic reuseport;'])

    def test_refusals(self):
        with open(os.path.join(self.d, 'vhost/b.conf'), 'w') as fh:
            fh.write(B.replace('    listen 443 ssl;\n    http2 on;', '    listen 443 ssl;\n    http2\n        on;'))
        with self.assertRaises(protooff.PlanError) as cm:
            protooff.plan(self.cfg, 'http2', 'off')
        self.assertEqual(cm.exception.code, 'line_shape')                     # not on a line of its own: by hand
        with self.assertRaises(protooff.PlanError):
            protooff.plan(self.cfg, 'spdy', 'off')
        # a marked line edited by hand since: not put back by guess
        tree(self.d)
        with open(os.path.join(self.d, 'vhost/a.conf'), 'w') as fh:
            fh.write('server {\n    listen 8443 ssl;  # jt-waf-mgr: http2 off (change #7): listen 443 ssl http2;\n'
                     '    server_name a.example.com;\n}\n')
        with self.assertRaises(protooff.PlanError) as cm:
            protooff.plan(self.cfg, 'http2', 'on')
        self.assertEqual(cm.exception.code, 'marked_line_changed')
        # a marked line whose "original" is not one of the directives this switches: never written back
        with open(os.path.join(self.d, 'vhost/a.conf'), 'w') as fh:
            fh.write('server {\n    # jt-waf-mgr: http2 off (change #7): include /etc/passwd;\n}\n')
        with self.assertRaises(protooff.PlanError) as cm:
            protooff.plan(self.cfg, 'http2', 'on')
        self.assertEqual(cm.exception.code, 'marked_line_shape')


class TestRoot(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='jtwaf-proto-')
        self.addCleanup(shutil.rmtree, self.d, True)
        tree(self.d)
        self.cfg = config.load(None, {'paths': {'nginx_conf': os.path.join(self.d, 'nginx.conf'), 'nginx_bin': '/bin/true'},
                                      'managed': {'dir': os.path.join(self.d, 'managed'), 'spool': os.path.join(self.d, 'spool'),
                                                  'apply_state': os.path.join(self.d, 'state')}})
        self.ap = Applier(self.cfg)
        self.ap.check_binary = lambda: None
        self.ap.reload = lambda wait: 'reloaded (test)'
        self.ap.test_config = lambda: 'ok'
        self.ap.health = lambda urls: {u: 200 for u in urls}
        self.ap.program_refusal = lambda: None

    def run_req(self, req):
        os.makedirs(self.cfg['managed']['spool'], exist_ok=True)
        with open(os.path.join(self.cfg['managed']['spool'], 'proto-c%d.req' % req['change_id']), 'w') as fh:
            json.dump(req, fh)
        self.ap.process()
        with open(os.path.join(self.cfg['managed']['spool'], 'proto-c%d.result' % req['change_id'])) as fh:
            return json.load(fh)

    def req(self, feature='http2', mode='off', cid=5):
        p = protooff.plan(self.cfg, feature, mode, from_changes=[5] if mode == 'on' else None)
        return {'action': 'proto', 'change_id': cid, 'feature': feature, 'mode': mode,
                'edits': protooff.with_change(p, cid), 'health_urls': []}

    def test_write_and_back(self):
        res = self.run_req(self.req())
        self.assertEqual((res['result'], res['action'], res['change_id']), ('ok', 'proto', 5), res)
        self.assertEqual(protooff.state(self.cfg)['http2']['on'], 0)
        r = self.req('http2', 'on', 6)
        r['from_changes'] = [5]
        res = self.run_req(r)
        self.assertEqual(res['result'], 'ok', res)
        self.assertEqual(rd(os.path.join(self.d, 'vhost/b.conf')), B)

    def test_drift_and_tampering_refused(self):
        r = self.req()
        r['edits'][0] = dict(r['edits'][0], new='    include /etc/passwd;')         # not what root plans
        res = self.run_req(r)
        self.assertEqual((res['result'], res['step']), ('failed', 'drift'))
        r = self.req()
        with open(os.path.join(self.d, 'vhost/a.conf'), 'a') as fh:
            fh.write('# edited meanwhile\n')
        res = self.run_req(r)
        self.assertEqual((res['result'], res['step']), ('failed', 'drift'))
        self.assertIn('http2;', rd(os.path.join(self.d, 'vhost/a.conf')))

    def test_change_id_must_be_a_positive_number(self):
        for bad in (-1, 0, True):
            r = self.req(cid=5)
            r['change_id'] = bad
            os.makedirs(self.cfg['managed']['spool'], exist_ok=True)
            with open(os.path.join(self.cfg['managed']['spool'], 'proto-c5.req'), 'w') as fh:
                json.dump(r, fh)
            self.ap.process()
            with open(os.path.join(self.cfg['managed']['spool'], 'proto-c5.result')) as fh:
                self.assertEqual(json.load(fh)['result'], 'failed')
        self.assertIn('http2;', rd(os.path.join(self.d, 'vhost/a.conf')))

    def test_failed_test_puts_back(self):
        def bad():
            raise Fail('nginx -t', 'broken')
        self.ap.test_config = bad
        res = self.run_req(self.req('http3'))
        self.assertEqual(res['result'], 'failed')
        self.assertIn('put back', res['summary'])
        self.assertEqual(rd(os.path.join(self.d, 'vhost/b.conf')), B)


class TestWorkflow(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.d = os.path.join(self.env.dir, 'ng')
        tree(self.d)
        self.env.cfg.data['paths']['nginx_conf'] = os.path.join(self.d, 'nginx.conf')
        self.app = App(self.env.cfg, start_collector=False)
        self.addCleanup(self.app.db.release)
        self.wf = self.app.workflow
        self.sent = []
        self.wf._write_request = lambda req: self.sent.append(req)

    def test_person_proposes_and_approves(self):
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_proto('http2', 'off', 'advisory', 'op', role='operator')
        self.assertEqual(cm.exception.code, 'forbidden')
        cid = self.wf.propose_proto('http2', 'off', 'advisory', 'appr', role='approver')
        r = self.wf.get(cid)
        self.assertEqual((r['op'], r['direction']), ('proto', 'tighten'))
        self.assertIn('(change #%d)' % cid, r['rule_text'])         # 0.5.2: its own number, not "change #0"
        self.assertNotIn('(change #0)', r['rule_text'])
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_proto('http3', 'off', 'again', 'appr', role='approver')
        self.assertEqual(cm.exception.code, 'proto_change_pending')
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval', self.wf.get(cid)['checks'])
        self.assertEqual(self.sent, [])                                      # a person's: waits for approval

    def test_advisory_switches_off_by_itself_and_back(self):
        a = {'version': '1.30.6', 'exact': True, 'issues': [{'title': 'Memory corruption in HTTP/2 flow control', 'severity': 'major',
                                                             'cves': ['CVE-2099-0002'], 'feature': 'http2', 'in_use': True}]}
        got = nginxup.mitigate(self.app, a, log=lambda m: None)
        self.assertEqual((got['feature'], got['mode']), ('http2', 'off'))
        self.wf.run_checks(got['change_id'])
        self.assertEqual(self.wf.get(got['change_id'])['state'], 'applying')     # auto_mitigate (default on)
        self.assertEqual(self.sent[0]['action'], 'proto')
        self.assertIn('change #%d' % got['change_id'], self.sent[0]['edits'][0]['new'])
        # applied (as the root program would), then nginx updated: no advisory left -> back on as it was
        for f in {e['file'] for e in self.sent[0]['edits']}:
            new = protooff.edit(rd(f), [e for e in self.sent[0]['edits'] if e['file'] == f])
            with open(f, 'w') as fh:
                fh.write(new)
        self.wf._handle_site_result({'result': 'ok', 'files': {}}, self.wf.get(got['change_id']), op='proto')
        # still vulnerable, the feature now off (0.4.98 review: no flapping back on before the update)
        self.assertIsNone(nginxup.mitigate(self.app, dict(a, issues=[dict(a['issues'][0], in_use=False)]), log=lambda m: None))
        back = nginxup.mitigate(self.app, {'version': '1.30.7', 'exact': True, 'issues': []}, log=lambda m: None)
        self.assertEqual((back['feature'], back['mode']), ('http2', 'on'))
        # switched off by the setting: proposed, a person approves
        self.app.db.x("UPDATE changes SET state='cancelled' WHERE id=?", (back['change_id'],))
        self.env.cfg.data['nginxup']['auto_mitigate'] = False
        again = nginxup.mitigate(self.app, {'version': '1.30.7', 'exact': True, 'issues': []}, log=lambda m: None)
        self.wf.run_checks(again['change_id'])
        self.assertEqual(self.wf.get(again['change_id'])['state'], 'pending_approval')

    def test_distribution_package_and_people_named_like_the_job(self):
        a = {'version': '1.22.1', 'exact': False, 'issues': [{'title': 'HTTP/2', 'severity': 'major', 'cves': [],
                                                              'feature': 'http2', 'in_use': True}]}
        got = nginxup.mitigate(self.app, a, log=lambda m: None)
        self.wf.run_checks(got['change_id'])
        self.assertEqual(self.wf.get(got['change_id'])['state'], 'pending_approval')   # backports: a person decides
        from jtwafmgr import auth
        self.assertIn('nginxup', auth.RESERVED_NAMES)

    def test_medium_advisory_or_unused_feature_left_alone(self):
        a = {'version': '1.30.6', 'issues': [{'title': 'Use-after-free in HTTP/3', 'severity': 'medium', 'cves': [],
                                              'feature': 'http3', 'in_use': True}]}
        self.assertIsNone(nginxup.mitigate(self.app, a, log=lambda m: None))


if __name__ == '__main__':
    unittest.main()
