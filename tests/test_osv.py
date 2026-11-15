"""OSV queries (osv.py): off by default, only package name, version and release sent, answers cached a day."""
import json
import os
import unittest

from jtwafmgr import osv, software
from jtwafmgr.app import App
from tests.helpers import TempEnv


class TestOsv(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        d = self.env.dir
        self.osr = os.path.join(d, 'os-release')
        with open(self.osr, 'w') as fh:
            fh.write('ID=debian\nVERSION_ID="12"\nVERSION="12 (bookworm)"\n')
        self.status = os.path.join(d, 'status')
        with open(self.status, 'w') as fh:
            fh.write('Package: openssh-server\nStatus: install ok installed\nSource: openssh\nVersion: 1:9.2p1-2+deb12u3\n\n'
                     'Package: nginx\nStatus: install ok installed\nVersion: 1.22.1-9\n')
        software.save(self.app.db, 'test', 'OpenSSH', '9.2p1')
        self.app.db.x("UPDATE software SET evidence='dpkg: openssh-server 1:9.2p1-2+deb12u3' WHERE name='OpenSSH'")
        software.save(self.app.db, 'test', 'Example CMS', '3.1')        # not a package: not asked about

    def tearDown(self):
        self.app.stop()
        self.env.cleanup()

    def test_off_by_default(self):
        self.assertEqual(osv.lookup(self.app.cfg, self.app.db, post=lambda *a: self.fail('asked'),
                                    os_release=self.osr, dpkg_status=self.status), {})

    def test_query_and_cache(self):
        self.app.cfg.data['intel']['osv'] = True
        sent = []

        def post(url, body, timeout):
            sent.append(body)
            return {'vulns': [{'id': 'DEBIAN-CVE-2026-1111', 'aliases': ['CVE-2026-1111'], 'summary': 'x', 'modified': '2026-11-01'}]}
        out = osv.lookup(self.app.cfg, self.app.db, post=post, os_release=self.osr, dpkg_status=self.status, log=lambda m: None)
        self.assertEqual(sent, [{'package': {'name': 'openssh', 'ecosystem': 'Debian:12'}, 'version': '1:9.2p1-2+deb12u3'}])
        self.assertEqual(out['OpenSSH']['vulns'][0]['cves'], ['CVE-2026-1111'])
        self.assertNotIn('Example CMS', out)
        self.assertEqual(oct(os.stat(osv.cache_path(self.app.cfg)).st_mode & 0o777), '0o600')
        osv.lookup(self.app.cfg, self.app.db, post=post, os_release=self.osr, dpkg_status=self.status, log=lambda m: None)
        self.assertEqual(len(sent), 1)                                   # a day's cache
        with open(self.osr, 'w') as fh:
            fh.write('ID=fedora\nVERSION_ID=40\n')
        self.assertEqual(osv.lookup(self.app.cfg, self.app.db, post=post, os_release=self.osr, dpkg_status=self.status), {})

    def test_ecosystem_names(self):
        with open(self.osr, 'w') as fh:
            fh.write('ID=ubuntu\nVERSION_ID="24.04"\nVERSION="24.04.5 LTS (Noble Numbat)"\n')
        self.assertEqual(osv.ecosystem(self.osr), 'Ubuntu:24.04:LTS')


if __name__ == '__main__':
    unittest.main()
