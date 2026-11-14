"""ModSecurity on / off for one site (sitewaf.py): the plan, the one marked line, the root program's own checks and
its rollback, the change workflow and the API."""
import json
import os
import shutil
import tempfile
import time
import unittest

from jtwafmgr import auth, config, sitewaf
from jtwafmgr.apply import Applier, Fail
from jtwafmgr.app import App
from jtwafmgr.changes import ChangeError
from tests.helpers import TempEnv

NGINX = """events {}
http {
    modsecurity off;
    modsecurity_rules_file %(d)s/modsec/main.conf;
    include %(d)s/vhost/*.conf;
}
"""
A = """server {
    listen 80;
    server_name a.example.com;
    return 301 https://a.example.com$request_uri;
}
server {
    listen 443 ssl;
    server_name a.example.com www.a.example.com;
    location / { proxy_pass http://127.0.0.1:9000; }
}
"""
B = """server {
    listen 443 ssl;
    server_name b.example.com;
    include %(d)s/snippets/modsec-on.conf;   # by hand
    location / { proxy_pass http://127.0.0.1:9001; }
}
"""
C = """server {
    listen 443 ssl;
    server_name c.example.com;
    modsecurity off;
    location / { proxy_pass http://127.0.0.1:9002; }
}
"""


def tree(d, with_snippet=True):
    for sub in ('vhost', 'snippets', 'modsec'):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    for name, text in (('nginx.conf', NGINX), ('vhost/a.conf', A), ('vhost/b.conf', B if with_snippet else ''),
                       ('vhost/c.conf', C), ('modsec/main.conf', '# rules\n')):
        with open(os.path.join(d, name), 'w') as fh:
            fh.write(text % {'d': d})
    if with_snippet:
        with open(os.path.join(d, 'snippets/modsec-on.conf'), 'w') as fh:
            fh.write('# include inside a server{} to run the WAF for that vhost\nmodsecurity on;\n')


class TestPlan(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='jtwaf-site-')
        tree(self.d)
        self.cfg = config.load(None, {'paths': {'nginx_conf': os.path.join(self.d, 'nginx.conf')},
                                      'managed': {'dir': os.path.join(self.d, 'managed')}})

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_enable_disable_round_trip(self):
        p = sitewaf.plan(self.cfg, 'A.example.com', 'enable')
        self.assertEqual([(os.path.basename(b['file']), b['line']) for b in p['blocks']], [('a.conf', 6)])   # not the redirect
        self.assertEqual((p['snippet'], p['snippet_text']), (os.path.join(self.d, 'snippets/modsec-on.conf'), None))
        f = os.path.join(self.d, 'vhost/a.conf')
        new = sitewaf.edit(A, [6], 'enable', p['snippet'], 12)
        self.assertIn('include %s;  %s (change #12)' % (p['snippet'], sitewaf.MARK), new.splitlines()[6])
        with open(f, 'w') as fh:
            fh.write(new)
        with self.assertRaises(sitewaf.PlanError) as cm:
            sitewaf.plan(self.cfg, 'a.example.com', 'enable')
        self.assertEqual(cm.exception.code, 'nothing_to_do')
        d = sitewaf.plan(self.cfg, 'a.example.com', 'disable')
        self.assertEqual(len(d['blocks']), 1)
        self.assertEqual(sitewaf.edit(new, [6], 'disable', None, 13), A)          # exactly as before
        with self.assertRaises(sitewaf.PlanError):
            sitewaf.edit(new, [6], 'enable', p['snippet'], 14)                   # marked already

    def test_refusals(self):
        for host, mode, code in (('b.example.com', 'enable', 'nothing_to_do'), ('b.example.com', 'disable', 'not_switched_on_here'),
                                 ('c.example.com', 'enable', 'switched_off_by_hand'), ('x.example.com', 'enable', 'nothing_to_do'),
                                 ('bad host', 'enable', 'invalid_request'), ('a.example.com', 'maybe', 'invalid_request')):
            with self.assertRaises(sitewaf.PlanError) as cm:
                sitewaf.plan(self.cfg, host, mode)
            self.assertEqual(cm.exception.code, code, (host, mode))

    def test_odd_line_breaks_do_not_move_the_line(self):
        """A form feed or U+2028 in a comment is not a line break for nginx: the edit lands in the planned block."""
        f = os.path.join(self.d, 'vhost/a.conf')
        with open(f, 'w', newline='') as fh:
            fh.write('# \x0c\x0c\x0c\x0c \u2028 notes\n' + A)
        p = sitewaf.plan(self.cfg, 'a.example.com', 'enable')
        self.assertEqual([b['line'] for b in p['blocks']], [7])
        with open(f, encoding='utf-8', newline='') as fh:
            new = sitewaf.edit(fh.read(), [7], 'enable', p['snippet'], 3)
        self.assertTrue(sitewaf.split_lines(new)[7].lstrip().startswith('include '))
        self.assertIn('listen 443 ssl;', sitewaf.split_lines(new)[8])
        with open(f, 'w', newline='') as fh:
            fh.write('# a\rb\n' + A)                                      # a lone CR: refused
        with self.assertRaises(sitewaf.PlanError) as cm:
            sitewaf.plan(self.cfg, 'a.example.com', 'enable')
        self.assertEqual(cm.exception.code, 'unusual_line_endings')

    def test_disable_only_a_waf_switch(self):
        f = os.path.join(self.d, 'vhost/a.conf')
        tls = os.path.join(self.d, 'snippets/tls.conf')
        with open(tls, 'w') as fh:
            fh.write('ssl_protocols TLSv1.3;\n')
        lines = sitewaf.split_lines(A)
        lines.insert(6, '    include %s;  %s (change #9)\n' % (tls, sitewaf.MARK))   # a marked line copied by hand
        with open(f, 'w') as fh:
            fh.write(''.join(lines))
        with self.assertRaises(sitewaf.PlanError) as cm:
            sitewaf.plan(self.cfg, 'a.example.com', 'disable')
        self.assertEqual(cm.exception.code, 'marked_line_not_a_waf_switch')

    def test_managed_snippet_without_others(self):
        shutil.rmtree(self.d)
        tree(self.d, with_snippet=False)
        p = sitewaf.plan(self.cfg, 'a.example.com', 'enable')
        self.assertEqual(p['snippet'], os.path.join(self.d, 'managed', sitewaf.MANAGED_SNIPPET))
        self.assertEqual(p['snippet_text'].splitlines()[-1], 'modsecurity on;')    # the http block names the rules file
        os.makedirs(os.path.dirname(p['snippet']), exist_ok=True)
        with open(p['snippet'], 'w') as fh:
            fh.write(p['snippet_text'] + "modsecurity_rules 'SecRuleEngine Off';\n")     # edited by hand
        with self.assertRaises(sitewaf.PlanError) as cm:
            sitewaf.plan(self.cfg, 'a.example.com', 'enable')
        self.assertEqual(cm.exception.code, 'managed_snippet_changed')


class TestRoot(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='jtwaf-site-')
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

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def run_req(self, req):
        os.makedirs(self.cfg['managed']['spool'], exist_ok=True)
        with open(os.path.join(self.cfg['managed']['spool'], 'site-c%d.req' % req['change_id']), 'w') as fh:
            json.dump(req, fh)
        self.ap.process()
        with open(os.path.join(self.cfg['managed']['spool'], 'site-c%d.result' % req['change_id'])) as fh:
            return json.load(fh)

    def req(self, mode='enable', cid=5):
        p = sitewaf.plan(self.cfg, 'a.example.com', mode)
        return {'action': 'site_waf', 'change_id': cid, 'mode': mode, 'host': 'a.example.com', 'blocks': p['blocks'],
                'snippet': p['snippet'], 'health_urls': []}

    def test_write_and_back(self):
        res = self.run_req(self.req())
        self.assertEqual((res['result'], res['action'], res['change_id']), ('ok', 'site_waf', 5))
        with open(os.path.join(self.d, 'vhost/a.conf')) as fh:
            self.assertIn(sitewaf.MARK + ' (change #5)', fh.read())
        res = self.run_req(self.req('disable', 6))
        self.assertEqual(res['result'], 'ok')
        with open(os.path.join(self.d, 'vhost/a.conf')) as fh:
            self.assertEqual(fh.read(), A)

    def test_drift_refused(self):
        r = self.req()
        with open(os.path.join(self.d, 'vhost/a.conf'), 'a') as fh:
            fh.write('# edited meanwhile\n')
        res = self.run_req(r)
        self.assertEqual((res['result'], res['step']), ('failed', 'drift'))

    def test_changed_between_check_and_write(self):
        """certbot or a person edits the file while the health URLs are checked: nothing is written."""
        f = os.path.join(self.d, 'vhost/a.conf')

        def health(urls):
            with open(f, 'w') as fh:
                fh.write('# moved\n' + A)
            return {}
        self.ap.health = health
        res = self.run_req(self.req())
        self.assertEqual((res['result'], res['step']), ('failed', 'drift'))
        with open(f) as fh:
            self.assertNotIn(sitewaf.MARK, fh.read())

    def test_result_reports_file_hashes(self):
        import hashlib
        res = self.run_req(self.req())
        f = os.path.realpath(os.path.join(self.d, 'vhost/a.conf'))
        with open(f, 'rb') as fh:
            self.assertEqual(res['files'][f], hashlib.sha256(fh.read()).hexdigest())

    def test_failed_test_puts_back(self):
        def bad():
            raise Fail('nginx -t', 'broken')
        self.ap.test_config = bad
        res = self.run_req(self.req())
        self.assertEqual(res['result'], 'failed')
        self.assertIn('put back', res['summary'])
        with open(os.path.join(self.d, 'vhost/a.conf')) as fh:
            self.assertEqual(fh.read(), A)

    def test_outside_dir_refused(self):
        r = self.req()
        r['blocks'] = [dict(b, file='/etc/passwd') for b in r['blocks']]
        res = self.run_req(r)
        self.assertEqual(res['result'], 'failed')


class TestWorkflow(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.d = os.path.join(self.env.dir, 'ng')
        tree(self.d)
        self.env.cfg = config.load(None, {
            'paths': dict(self.env.cfg['paths'], nginx_conf=os.path.join(self.d, 'nginx.conf')), 'server': {'secure_cookies': False},
            'syslog': {'enabled': False}, 'collector': {'backfill_rotated': False},
            'managed': {'dir': os.path.join(self.env.dir, 'managed'), 'spool': os.path.join(self.env.dir, 'spool'),
                        'sandbox_dir': os.path.join(self.env.dir, 'sbx')},
            'evidence': {'access_logs': [os.path.join(self.env.dir, '*access.log')]}})
        self.app = App(self.env.cfg)
        self.wf = self.app.workflow
        self.wf.set_setting('sandbox.required', False, 'test')

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def test_propose_check_send(self):
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_site_waf('enable', 'a.example.com', 'protect a', 'op', role='operator')
        self.assertEqual(cm.exception.code, 'forbidden')
        cid = self.wf.propose_site_waf('enable', 'a.example.com', 'protect a', 'appr', role='approver')
        r = self.wf.get(cid)
        self.assertEqual((r['op'], r['direction']), ('site_waf', 'tighten'))
        self.assertIn(sitewaf.MARK, r['rule_text'])
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_site_waf('enable', 'a.example.com', 'again', 'appr', role='approver')
        self.assertEqual(cm.exception.code, 'site_change_pending')
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval', self.wf.get(cid)['checks'])
        # the file changed after the proposal: checks fail
        with open(os.path.join(self.d, 'vhost/a.conf'), 'a') as fh:
            fh.write('# edited\n')
        self.app.db.x("UPDATE changes SET state='checking' WHERE id=?", (cid,))
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'failed')
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='change.proposed'"))

    def test_attribution_only_while_unchanged(self):
        import hashlib
        f = os.path.realpath(os.path.join(self.d, 'vhost/a.conf'))
        with open(f, 'rb') as fh:
            sha = hashlib.sha256(fh.read()).hexdigest()
        now = time.time()
        self.app.db.x("INSERT INTO changes(op, kind, spec, direction, state, proposed_by, created_at, updated_at, checks) "
                      "VALUES ('site_waf', 'site_waf', '{}', 'tighten', 'applied', 'appr', ?, ?, ?)",
                      (now, now, json.dumps({'applied_files': {f: sha}})))
        mon = self.app.monitor
        self.assertTrue(mon._site_waf_files({'ts': now - 60}, [f]))
        with open(f, 'a') as fh:
            fh.write('# someone else, later\n')
        self.assertFalse(mon._site_waf_files({'ts': now - 60}, [f]))
        self.assertFalse(mon._site_waf_files({'ts': now - 60}, [os.path.join(self.d, 'snippets/modsec-on.conf')]))


if __name__ == '__main__':
    unittest.main()
