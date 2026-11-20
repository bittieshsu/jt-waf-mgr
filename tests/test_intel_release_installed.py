"""0.5.20: the notice of a security release closes by itself once the release is installed (nginx 1.30.7 and
ModSecurity 3.0.17 were announced, installed through approved changes, and their notices stayed open)."""
import json
import unittest

from jtwafmgr import alerts, intel
from jtwafmgr.app import App
from tests.helpers import TempEnv


class TestReleaseInstalled(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def sw(self, name, version, kind='host', hosts=()):
        self.app.db.x("INSERT INTO software(name, version, hosts, kind, source, confirmed, evidence, notes, updated_at, updated_by) "
                      "VALUES (?,?,?,?, 'guess', 1, '', '', 0, 'x')", (name, version, json.dumps(list(hosts)), kind))

    def notice(self, product, title, key):
        return alerts.raise_alert(self.app.db, self.app.audit, 'intel', 'security_release', 'warning', key,
                                  {'msg': 'intel_release', 'product': product, 'title': title, 'release_at': ''})

    def state(self, aid):
        return self.app.db.one('SELECT state, note FROM alerts WHERE id=?', (aid,))

    def test_installed_releases_close_their_notices(self):
        self.sw('nginx', '1.30.7-1~bookworm')
        self.sw('libmodsecurity (ModSecurity v3)', '3.0.17')
        self.sw('OpenSSL', '3.5.4')
        self.sw('PHP', '8.4.14', kind='backend', hosts=['a.example.com'])
        self.sw('PHP', '8.4.15', kind='backend', hosts=['b.example.com'])
        a = self.notice('nginx', 'nginx 1.30.7 security release (multiple CVEs, published 2026-11-18)', 'r1')
        b = self.notice('libmodsecurity (ModSecurity v3)', 'ModSecurity 3.0.17 security release', 'r2')
        c = self.notice('OpenSSL', 'OpenSSL 4.1.1/4.0.4/3.5.10 releases scheduled for 1 December 2026', 'r3')
        d = self.notice('PHP', 'Upcoming Critical PHP Security Release', 'r4')
        e = self.notice('PHP', 'PHP 8.4.15 and 8.3.28 released', 'r5')
        self.app.db.x("UPDATE alerts SET details=json_set(details, '$.products', 'Nextcloud') WHERE id=?", (e,))
        self.sw('Nextcloud', '30.0.2', kind='site', hosts=['a.example.com', 'b.example.com'])
        f = self.notice('Grafana', 'Grafana 12.3.1 security release', 'r6')
        done = intel.close_installed_releases(self.app, log=lambda *x: None)
        self.assertEqual(sorted(done), sorted([a, b]))
        self.assertIn('1.30.7-1~bookworm', self.state(a)['note'])
        self.assertEqual(self.state(c)['state'], 'open')        # 3.5.4 is older than 3.5.10 on its branch
        self.assertEqual(self.state(d)['state'], 'open')        # no version named
        self.assertEqual(self.state(e)['state'], 'open')        # one PHP host still at 8.4.14
        self.assertEqual(self.state(f)['state'], 'open')        # not in the list
        # the last PHP host updated: closed
        self.app.db.x("UPDATE software SET version='8.4.15' WHERE name='PHP'")
        self.assertEqual(intel.close_installed_releases(self.app, log=lambda *x: None), [e])
        # a later branch counts; a distribution's version that is not plain numbers says nothing
        self.sw('Keycloak', '26.4.0')
        g = self.notice('Keycloak', 'Keycloak 26.3.5 security release', 'r7')
        self.sw('Roundcube', '1.6.5+dfsg-1+deb12u5a')
        h = self.notice('Roundcube', 'Roundcube 1.6.11 security update', 'r8')
        self.assertEqual(intel.close_installed_releases(self.app, log=lambda *x: None), [g])
        self.assertEqual(self.state(h)['state'], 'open')
        self.assertEqual(self.app.db.one("SELECT COUNT(*) n FROM audit WHERE action='alert.handled'")['n'], 4)
        # 0.5.22: a title naming the affected version ("and earlier", "->") does not close on it
        self.sw('Grafana', '12.3.0')
        i = self.notice('Grafana', 'Grafana 12.3.0 and earlier: security release', 'r9')
        self.sw('Gitea / Forgejo', '1.22.3')
        j = self.notice('Gitea / Forgejo', 'Gitea 1.22.3 -> 1.22.4 security release', 'r10')
        self.assertEqual(intel.close_installed_releases(self.app, log=lambda *x: None), [])
        self.assertEqual((self.state(i)['state'], self.state(j)['state']), ('open', 'open'))
        # a language known only from back-ends: closed only when every site of the applications on it said
        self.sw('PHP2', '8.4.16', kind='backend', hosts=['a.example.com'])
        k = self.notice('PHP2', 'PHP2 8.4.15 released', 'r11')
        self.app.db.x("UPDATE alerts SET details=json_set(details, '$.products', 'Nextcloud') WHERE id=?", (k,))
        self.assertEqual(intel.close_installed_releases(self.app, log=lambda *x: None), [])     # b.example.com unknown


if __name__ == '__main__':
    unittest.main()
