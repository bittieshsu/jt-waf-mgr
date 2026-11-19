"""nginx's own security advisories (nginxsec.py, 0.4.98) and the root apt refresh for nginx's repository (aptrefresh.py).

Flaws in nginx itself happen before ModSecurity sees a request: an alert says "update nginx", the verified update is
proposed, and threat intelligence entries for nginx are decided by the advisories (a version already fixed is set aside).
"""
import json
import os
import tempfile
import time
import unittest

from jtwafmgr import aptrefresh, nginxsec, nginxup
from tests.helpers import TempEnv

PAGE = '''<html><body><div id="content"><h2>nginx security advisories</h2><ul>
<li><p>Use-after-free during response processing in resolver<br>Severity: medium<br><a href="https://advisory.example.com/K1">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-2099-0001">CVE-2099-0001</a><br>Not vulnerable: 1.31.9+, 1.30.7+<br>Vulnerable: 0.6.18-1.31.8</p></li>
<li><p>Memory corruption in HTTP/2 flow control<br>Severity: <b>major</b><br><a href="https://advisory.example.com/K2">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-2099-0002">CVE-2099-0002</a><br>Not vulnerable: 1.31.9+, 1.30.7+<br>Vulnerable: 1.9.5-1.31.8</p></li>
<li><p>Use-after-free in HTTP/3<br>Severity: medium<br><a href="https://advisory.example.com/K3">Advisory</a><br><a href="https://www.cve.org/CVERecord?id=CVE-CVE-2099-0003">CVE-CVE-2099-0003</a><br>Not vulnerable: 1.31.9+, 1.30.7+<br>Vulnerable: 1.25.0-1.31.8</p></li>
<li><p>Buffer overflow when using alias with rewrite<br>Severity: medium<br><a href="https://www.cve.org/CVERecord?id=CVE-2099-0004">CVE-2099-0004</a><br>Not vulnerable: 1.31.7+, 1.30.6+<br>Vulnerable: 0.6.0-1.31.6</p></li>
<li><p>An issue in logging<br>Severity: none<br><a href="https://www.cve.org/CVERecord?id=CVE-2009-0006">CVE-2009-0006</a><br>Not vulnerable: none<br>Vulnerable: all</p></li>
<li><p>Old one<br>Severity: major<br><a href="https://www.cve.org/CVERecord?id=CVE-2009-0005">CVE-2009-0005</a><br>Not vulnerable: 0.8.15+, 0.7.64+<br>Vulnerable: 0.1.0-0.8.14</p></li>
</ul></div></body></html>'''

CONF = '''events {}
http {
    resolver 192.0.2.53;
    server {
        listen 443 ssl;
        http2 on;
        server_name a.example.com;
        location /files/ { alias /srv/files/; }
    }
}
'''


class TestAdvisories(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.conf = os.path.join(self.env.dir, 'nginx.conf')
        with open(self.conf, 'w') as fh:
            fh.write(CONF)
        self.env.cfg.data['paths']['nginx_conf'] = self.conf

    def test_parse_and_versions(self):
        advs = nginxsec.parse(PAGE)
        self.assertEqual([a['cves'] for a in advs], [['CVE-2099-0001'], ['CVE-2099-0002'], ['CVE-2099-0003'],
                                                      ['CVE-2099-0004'], ['CVE-2009-0006'], ['CVE-2009-0005']])   # "CVE-CVE-" typo read
        h2 = advs[1]
        self.assertEqual((h2['severity'], h2['not_vulnerable'], h2['vulnerable']), ('major', ['1.31.9+', '1.30.7+'], ['1.9.5-1.31.8']))
        self.assertEqual(h2['advisory'], 'https://advisory.example.com/K2')
        self.assertTrue(nginxsec.is_vulnerable('1.30.6', h2))
        self.assertFalse(nginxsec.is_vulnerable('1.30.7', h2))         # fixed in its branch
        self.assertTrue(nginxsec.is_vulnerable('1.31.8', h2))
        self.assertFalse(nginxsec.is_vulnerable('1.32.0', h2))         # later than the newest fix
        self.assertTrue(nginxsec.is_vulnerable('1.28.0', h2))          # an older branch without a fix
        self.assertFalse(nginxsec.is_vulnerable('1.9.4', h2))          # before the range
        self.assertFalse(nginxsec.is_vulnerable('1.30.6', advs[3]))    # fixed by the version we have
        self.assertIsNone(nginxsec.is_vulnerable('x', h2))
        self.assertEqual(nginxsec.upstream('1.30.6-1~bookworm'), ('1.30.6', True))      # nginx.org: the release itself
        self.assertEqual(nginxsec.upstream('1.22.1-9+deb12u2'), ('1.22.1', False))      # a distribution's: backports

    def test_features_from_the_configuration(self):
        f = nginxsec.features(self.env.cfg)
        self.assertEqual(f, {'http2': True, 'resolver': True, 'alias': True})
        advs = nginxsec.parse(PAGE)
        a = nginxsec.assess(self.env.cfg, '1.30.6-1~bookworm', '1.30.7-1~bookworm', advs)
        by = {i['cves'][0]: i for i in a['issues']}
        self.assertEqual(sorted(by), ['CVE-2099-0001', 'CVE-2099-0002', 'CVE-2099-0003'])
        self.assertEqual((by['CVE-2099-0002']['in_use'], by['CVE-2099-0003']['in_use']), (True, False))   # no HTTP/3 here
        self.assertTrue(a['major_in_use'] and a['fixed_by_candidate'])
        # HTTP/2 switched off: that advisory no longer counts as in use
        with open(self.conf, 'w') as fh:
            fh.write(CONF.replace('http2 on;', '# http2 on;'))
        a = nginxsec.assess(self.env.cfg, '1.30.6-1~bookworm', None, advs)
        self.assertFalse(a['major_in_use'])

    def test_a_distribution_package_with_the_fix_in_its_change_log(self):
        advs = nginxsec.parse(PAGE)
        fixed = {'CVE-2099-0002'}
        a = nginxsec.assess(self.env.cfg, '1.28.3-2ubuntu1.12', None, advs,
                            distro=lambda cve: 'fixed' if cve in fixed else 'not_listed')
        by = {i['cves'][0]: i for i in a['issues']}
        self.assertTrue(by['CVE-2099-0002']['backported'])
        self.assertFalse(by['CVE-2099-0002']['in_use'])             # HTTP/2 is used, but the fix is in
        self.assertFalse(by['CVE-2099-0001']['backported'])
        # nginx.org's own package is the release itself: its version decides, nothing is read
        a = nginxsec.assess(self.env.cfg, '1.30.6-1~bookworm', None, advs, distro=lambda cve: self.fail('read'))
        self.assertFalse(any(i['backported'] for i in a['issues']))

    def _app(self):
        from jtwafmgr.app import App
        return App(self.env.cfg, start_collector=False)

    def test_alert_threats_and_update_proposed(self):
        app = self._app()
        now = time.time()
        rows = {}
        for cve in ('CVE-2099-0002', 'CVE-2099-0004'):
            rows[cve] = app.db.x('INSERT INTO intel_threats(cve, product, first_seen, last_seen, affected, exploited, severity, '
                                 'details) VALUES (?,?,?,?,?,?,?,?)',
                                 (cve, 'nginx', now, now, 'yes', 0, 'high',
                                  json.dumps({'id': cve, 'our_version': '1.30.6-1~bookworm'}))).lastrowid
        st = {'installed': '1.30.6-1~bookworm', 'candidate': '1.30.7-1~bookworm', 'state': 'ready', 'target': '1.30.7-1~bookworm'}
        proposed = []
        app.workflow.propose_nginx = lambda reason, actor, role=None, auto=False: (proposed.append((actor, role, reason, auto)), 99)[1]
        a = nginxup.security(app, st, log=lambda m: None, get=lambda url: PAGE)
        self.assertTrue(a['major_in_use'])
        al = app.db.one("SELECT kind, severity, details FROM alerts WHERE kind='nginx_security'")
        self.assertEqual((al['kind'], al['severity']), ('nginx_security', 'critical'))
        d = json.loads(al['details'])
        self.assertEqual((d['cves'], d['ready'], d['not_in_use']), (['CVE-2099-0001', 'CVE-2099-0002'], True, ['Use-after-free in HTTP/3']))
        self.assertEqual((st['proposed_change'], proposed[0][:2], proposed[0][3]), (99, ('nginxup', 'admin'), True))
        self.assertIn('CVE-2099-0002', proposed[0][2])
        # the threat for a CVE fixed by our version is set aside; the one we are vulnerable to stays, noted
        r4 = app.db.one('SELECT status, affected, details FROM intel_threats WHERE id=?', (rows['CVE-2099-0004'],))
        self.assertEqual((r4['status'], r4['affected'], json.loads(r4['details'])['nginx_advisory']['result']), ('ignored', 'no', 'no'))
        r2 = app.db.one('SELECT status, details FROM intel_threats WHERE id=?', (rows['CVE-2099-0002'],))
        self.assertEqual((r2['status'], json.loads(r2['details'])['nginx_advisory']['result']), ('open', 'yes'))
        # 0.4.100: another list of advisories for the same version replaces the open alert (not a second one beside it)
        app.db.x("UPDATE alerts SET dedup='nginx-security:1.30.6:CVE-2009-0006,CVE-2099-0002' WHERE kind='nginx_security'")
        nginxsec.raise_alerts(app, st, log=lambda m: None)
        rows = app.db.q("SELECT state, dedup FROM alerts WHERE kind='nginx_security' ORDER BY id")
        self.assertEqual([r['state'] for r in rows], ['handled', 'open'])
        # the page cannot be read: the last list is kept
        self.assertEqual(len(nginxsec.refresh(self.env.cfg, get=lambda url: '<html></html>', log=lambda m: None)), 6)
        # switched off: nothing is read or raised
        self.env.cfg.data['nginxup']['advisories'] = False
        self.assertIsNone(nginxup.security(app, st, log=lambda m: None, get=lambda url: self.fail('read')))

    def test_module_names_and_a_hostile_page(self):
        self.assertEqual(nginxsec.feature_of({'title': 'Use-after-free in ngx_http_mp4_module'}), 'mp4')
        self.assertEqual(nginxsec.feature_of({'title': 'Memory disclosure in ngx_mail_smtp_module'}), 'mail')
        self.assertIsNone(nginxsec.feature_of({'title': 'Infinite loop while reading client request body over TLS 1.3'}))
        import time as _t
        t0 = _t.time()
        self.assertEqual(nginxsec.parse('<li><p>' * 120000), [])                 # no closing tags: still quick
        self.assertLess(_t.time() - t0, 5)

    def test_page_is_text_only(self):
        evil = PAGE.replace('Memory corruption in HTTP/2 flow control', '<script>x()</script>Memory <img src=x>corruption in HTTP/2')
        a = nginxsec.parse(evil)[1]
        self.assertNotIn('<', a['title'])


class TestAptRefresh(unittest.TestCase):
    POLICY = '''nginx:
  Installed: 1.30.6-1~bookworm
  Candidate: 1.30.6-1~bookworm
  Version table:
 *** 1.30.6-1~bookworm 500
        500 http://nginx.org/packages/debian bookworm/nginx amd64 Packages
        100 /var/lib/dpkg/status
     1.22.1-9+deb12u2 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
'''

    def test_only_the_lists_that_name_nginx_repositories(self):
        urls = aptrefresh.repo_urls(self.POLICY)
        self.assertEqual(urls, ['http://nginx.org/packages/debian', 'http://deb.debian.org/debian'])
        d = tempfile.mkdtemp(prefix='jtwaf-test-apt-')
        self.addCleanup(__import__('shutil').rmtree, d, True)
        files = {'nginx.list': 'deb [signed-by=/usr/share/keyrings/nginx.gpg] http://nginx.org/packages/debian bookworm nginx\n',
                 'other.list': 'deb http://repo.example.com/debian bookworm main\n',
                 'commented.list': '# deb http://nginx.org/packages/debian bookworm nginx\n'}
        for n, text in files.items():
            with open(os.path.join(d, n), 'w') as fh:
                fh.write(text)
        found = aptrefresh.source_files(['http://nginx.org/packages/debian'], roots=(os.path.join(d, '*.list'),))
        self.assertEqual([os.path.basename(f) for f in found], ['nginx.list'])
        ran = []

        class R:
            def __init__(self, out='', rc=0):
                self.stdout, self.stderr, self.returncode = out, '', rc
        orig = aptrefresh.source_files
        aptrefresh.source_files = lambda urls: found
        self.addCleanup(setattr, aptrefresh, 'source_files', orig)

        def run(cmd, **kw):
            ran.append(cmd)
            if cmd[0] == 'apt-get':
                parts = [c for c in cmd if c.startswith('Dir::Etc::sourceparts=')]
                self.assertEqual(os.listdir(parts[0].split('=', 1)[1]), ['00.list'])      # a copy, only that list
            return R(self.POLICY)
        self.assertEqual(aptrefresh.refresh('nginx', run=run, log=lambda m: None), 0)
        self.assertEqual([c[:2] for c in ran], [['apt-cache', 'policy'], ['apt-get', 'update']])
        self.assertIn('Dir::Etc::sourcelist=/dev/null', ran[1])


if __name__ == '__main__':
    unittest.main()
