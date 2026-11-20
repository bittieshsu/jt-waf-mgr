"""The servers behind the sites (backends.py, 0.5.17): their web server and PHP versions, read from the back-end host
itself (nginx does not pass a proxied server's Server header on), listed in the software list, and a back-end nginx
compared with nginx.org's advisories (an alert: jt-waf-mgr does not update that host)."""
import json
import os
import shutil
import unittest

from jtwafmgr import backends, nginxsec, software
from jtwafmgr.app import App
from tests.helpers import FIXTURE_SITE, TempEnv
from tests.test_nginxsec import PAGE

EXTRA = '''upstream pool {
    server 192.0.2.31:8443;
    server 192.0.2.32:8443 backup;
    server unix:/run/app.sock;
}
server {
    listen 443 ssl;
    server_name pool.example.com;
    location / { proxy_pass https://pool; }
    location /var/ { proxy_pass http://$backend; }
    location /out/ { proxy_pass http://203.0.113.9; }
}
server {
    listen 443 ssl;
    server_name self.example.com;
    location / { proxy_pass http://127.0.0.1:8095; }
}
'''


class TestBackends(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(server={'listen': '127.0.0.1:8095'}, intel={'backend_versions': True})
        site = os.path.join(self.env.dir, 'site')
        shutil.copytree(FIXTURE_SITE, site)
        with open(os.path.join(site, 'vhost', 'pool.example.com.conf'), 'w') as fh:
            fh.write(EXTRA)
        self.env.cfg.data['paths']['nginx_conf'] = os.path.join(site, 'nginx.conf')
        self.app = App(self.env.cfg)
        self.answers = {}
        self.asked = []

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def ask(self, scheme, address, port, host, timeout=4):
        self.asked.append((scheme, address, port, host))
        return self.answers.get((address, port))

    def rows(self):
        return [r for r in software.listing(self.app.db) if r['kind'] == 'backend']

    def test_headers(self):
        self.assertEqual(backends.read_headers({'server': 'nginx/1.22.1', 'x-powered-by': 'PHP/8.2.29'}),
                         [('nginx', '1.22.1'), ('PHP', '8.2.29')])
        self.assertEqual(backends.read_headers({'server': 'Apache/2.4.57 (Debian)'}), [('Apache HTTP Server', '2.4.57')])
        self.assertEqual(backends.read_headers({'server': 'nginx'}), [])                 # server_tokens off: no version
        self.assertEqual(backends.read_headers({'server': 'Microsoft-IIS/10.0'}), [('Microsoft IIS', '10.0')])
        self.assertEqual(backends.read_headers({'server': 'nginx/1.2.3<script>'}), [('nginx', '1.2.3')])
        self.assertEqual(backends.read_headers({}), [])

    def test_targets(self):
        ts = {(t['scheme'], t['address'], t['port']): t['sites'] for t in backends.targets(self.app)}
        self.assertEqual(ts[('http', '192.0.2.10', 8080)], ['app.example.com'])
        self.assertEqual(ts[('http', '192.0.2.20', 80)], ['intra.example.com', 'intranet.example.com'])
        self.assertEqual(ts[('https', '192.0.2.31', 8443)], ['pool.example.com'])           # an upstream group
        self.assertIn(('https', '192.0.2.32', 8443), ts)
        addrs = {k[1] for k in ts}
        self.assertFalse(any(a.startswith('127.') for a in addrs))                         # this program itself
        self.assertFalse(any('$' in a for a in addrs))                                     # a variable
        # a public address is never asked (a name resolving outside the local network neither)
        self.assertEqual(backends._resolve('8.8.8.8'), None)
        self.assertEqual(backends._resolve('192.0.2.10'), '192.0.2.10')
        self.assertEqual(backends._resolve('fe80::1'), None)
        self.assertIsNone(backends._split('unix:/run/x.sock'))
        self.assertEqual(backends._split('https://h.example.com/x'), ('https', 'h.example.com', 443))

    def test_detect_lists_and_keeps_current(self):
        self.answers = {('192.0.2.10', 8080): {'server': 'nginx/1.22.1', 'x-powered-by': 'PHP/8.2.29'},
                        ('192.0.2.20', 80): {'server': 'Apache/2.4.57 (Debian)'},
                        ('192.0.2.31', 8443): {'server': 'nginx/1.22.1'}}
        st = backends.detect(self.app, ask=self.ask, log=lambda *a: None)
        self.assertEqual(st['answered'], 3)
        rows = {(r['name'], r['version']): r for r in self.rows()}
        self.assertEqual(rows[('nginx', '1.22.1')]['hosts'], ['app.example.com', 'pool.example.com'])
        self.assertEqual(rows[('PHP', '8.2.29')]['hosts'], ['app.example.com'])
        self.assertEqual(rows[('Apache HTTP Server', '2.4.57')]['hosts'], ['intra.example.com', 'intranet.example.com'])
        self.assertTrue(all(r['source'] == 'probe' and not r['confirmed'] for r in rows.values()))
        self.assertIn('192.0.2.10:8080', rows[('nginx', '1.22.1')]['evidence'])
        # Host is the site's name; the request is only `GET /`
        self.assertIn(('http', '192.0.2.10', 8080, 'app.example.com'), self.asked)
        # a person confirms; the back-end is updated: the version follows, the confirmation stays
        nid = rows[('nginx', '1.22.1')]['id']
        software.confirm_all(self.app.db, 'alice')
        self.answers[('192.0.2.10', 8080)] = {'server': 'nginx/1.24.0'}
        self.answers[('192.0.2.31', 8443)] = {'server': 'nginx/1.24.0'}
        backends.detect(self.app, ask=self.ask, log=lambda *a: None)
        rows = {(r['name'], r['version']): r for r in self.rows()}
        self.assertEqual(rows[('nginx', '1.24.0')]['id'], nid)
        self.assertTrue(rows[('nginx', '1.24.0')]['confirmed'])
        self.assertNotIn(('PHP', '8.2.29'), rows)                     # no longer said: gone
        # a host that does not answer keeps what it had
        self.answers.pop(('192.0.2.20', 80))
        backends.detect(self.app, ask=self.ask, log=lambda *a: None)
        rows = {(r['name'], r['version']): r for r in self.rows()}
        self.assertIn(('Apache HTTP Server', '2.4.57'), rows)
        # two versions of one product behind different sites: two entries, no site in both
        self.answers[('192.0.2.31', 8443)] = {'server': 'nginx/1.26.2'}
        backends.detect(self.app, ask=self.ask, log=lambda *a: None)
        rows = {(r['name'], r['version']): r for r in self.rows()}
        self.assertEqual(rows[('nginx', '1.24.0')]['hosts'], ['app.example.com'])
        self.assertEqual(rows[('nginx', '1.26.2')]['hosts'], ['pool.example.com'])
        # confirmed back-end entries go to the search as any other (the product and its versions only)
        software.confirm_all(self.app.db, 'alice')
        line = {x['name']: x['version'] for x in software.confirmed(self.app.db)}
        self.assertIn('1.24.0', line['nginx'])
        self.assertNotIn('192.0.2', json.dumps(software.confirmed(self.app.db)))

    def test_person_entries_and_deletes(self):
        self.answers = {('192.0.2.10', 8080): {'server': 'nginx/1.22.1'}, ('192.0.2.20', 80): {'server': 'nginx/1.22.1'}}
        backends.detect(self.app, ask=self.ask, log=lambda *a: None)
        r = self.rows()[0]
        # a person deletes it: not listed again for those sites
        software.delete(self.app.db, r['id'])
        backends.detect(self.app, ask=self.ask, log=lambda *a: None)
        self.assertEqual(self.rows(), [])
        # this host's own nginx and a back-end nginx are different programs: both listed, and a person may edit one
        self.app.db.x("INSERT INTO software(name, version, hosts, kind, source, confirmed, evidence, notes, updated_at, updated_by) "
                      "VALUES ('nginx', '1.30.7', '[]', 'host', 'guess', 1, '', '', 0, 'x')")
        self.app.db.set_meta(backends.DISMISSED_KEY, '[]')
        backends.detect(self.app, ask=self.ask, log=lambda *a: None)
        b = self.rows()[0]
        software.save(self.app.db, 'alice', 'nginx', '1.22.1-9+deb12u2', hosts=b['hosts'], sid=b['id'])
        mine = [x for x in software.listing(self.app.db) if x['id'] == b['id']][0]
        self.assertEqual(mine['source'], 'person')
        backends.detect(self.app, ask=self.ask, log=lambda *a: None)           # the person's entry stays as it is
        mine = [x for x in software.listing(self.app.db) if x['id'] == b['id']][0]
        self.assertEqual(mine['version'], '1.22.1-9+deb12u2')
        self.assertEqual([x for x in self.rows() if x['source'] == 'probe'], [])
        # a virtual patch for this host's own nginx is not narrowed to the back-end sites
        self.assertEqual(software.hosts_of(self.app.db, 'nginx'), [])
        # "guess again" leaves the back-end entries alone and keeps this host's own nginx as it was
        software.refresh(self.app, 'alice', fetch=lambda *a, **k: None)
        self.assertTrue(any(x['id'] == b['id'] for x in software.listing(self.app.db)))

    def test_off_and_offline(self):
        self.assertFalse(__import__('jtwafmgr.config', fromlist=['DEFAULTS']).DEFAULTS['intel']['backend_versions'])
        self.assertIsNone(backends.probe('http', '192.0.2.10', 8080, 'app.example.com'))   # tests never ask

    def test_backend_nginx_alert_and_threats(self):
        nginxsec.refresh(self.env.cfg, get=lambda u: PAGE, log=lambda *a: None)
        self.answers = {('192.0.2.10', 8080): {'server': 'nginx/1.30.6'}}
        backends.detect(self.app, ask=self.ask, log=lambda *a: None)
        raised = nginxsec.backend_alerts(self.app, log=lambda *a: None)
        self.assertEqual(len(raised), 1)
        a = self.app.db.one("SELECT * FROM alerts WHERE kind='backend_security'")
        d = json.loads(a['details'])
        self.assertEqual(a['severity'], 'warning')                  # the features it uses are not known here
        self.assertEqual(d['installed'], '1.30.6')
        self.assertEqual(d['sites'], ['app.example.com'])
        self.assertIn('CVE-2099-0002', d['cves'])
        self.assertNotIn('CVE-2009-0006', d['cves'])                # "Severity: none"
        self.assertNotIn('CVE-2099-0004', d['cves'])                # fixed in 1.30.6
        from jtwafmgr import notify
        self.assertIn('1.30.6', notify.alert_text('zh-TW', d))
        self.assertIn('app.example.com', notify.alert_text('en', d))
        # the update of this host's nginx does not handle it (another kind); the back-end updated does
        self.answers = {('192.0.2.10', 8080): {'server': 'nginx/1.30.7'}}
        backends.detect(self.app, ask=self.ask, log=lambda *a: None)
        self.assertEqual(nginxsec.backend_alerts(self.app, log=lambda *a: None), [])
        a = self.app.db.one('SELECT * FROM alerts WHERE id=?', (a['id'],))
        self.assertEqual(a['state'], 'handled')
        # a threat for nginx is set aside by the advisories only when no nginx here (or behind) is affected
        self.answers = {('192.0.2.10', 8080): {'server': 'nginx/1.30.6'}}
        backends.detect(self.app, ask=self.ask, log=lambda *a: None)
        self.app.db.x("INSERT INTO intel_threats(cve, product, affected, details, status, first_seen, last_seen) "
                      "VALUES ('CVE-2099-0002', 'nginx', 'unknown', '{}', 'open', 0, 0)")
        self.assertEqual(nginxsec.decide_threats(self.app, installed='1.30.7-1~bookworm', log=lambda *a: None), [])
        self.answers = {('192.0.2.10', 8080): {'server': 'nginx/1.30.7'}}
        backends.detect(self.app, ask=self.ask, log=lambda *a: None)
        self.assertEqual(len(nginxsec.decide_threats(self.app, installed='1.30.7-1~bookworm', log=lambda *a: None)), 1)


if __name__ == '__main__':
    unittest.main()
