"""A distribution's package carries backported fixes (distropkg.py, 0.4.99): its installed change log decides."""
import gzip
import json
import os
import time
import unittest

from jtwafmgr import distropkg
from tests.helpers import TempEnv

STATUS = '''Package: libbrotli1
Status: install ok installed
Source: brotli
Version: 1.0.9-2+deb12u1

Package: libexample0
Status: install ok installed
Source: example
Version: 2.4.1-3

Package: libold9
Status: deinstall ok config-files
Version: 1.0-1

Package: libgone1
Status: install ok installed
Source: gone
Version: 3.0-1
'''

BROTLI_LOG = '''brotli (1.0.9-2+deb12u1) bookworm-security; urgency=medium

  * Fix CVE-2099-11111: out-of-bounds write.

 -- Example Maintainer <maint@example.com>  Fri, 23 Oct 2099 10:13:41 -0300

brotli (1.0.9-2) unstable; urgency=medium

  * Revert the fix for CVE-2099-22222 (regression).
'''


class TestDistroPackage(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(intel={'nvd': True})
        self.addCleanup(self.env.cleanup)
        d = self.env.dir
        self.status = os.path.join(d, 'status')
        with open(self.status, 'w') as fh:
            fh.write(STATUS)
        self.doc = os.path.join(d, 'doc')
        for pkg, text in (('libbrotli1', BROTLI_LOG), ('libexample0', 'example (2.4.1-3) unstable\n  * Nothing.\n')):
            os.makedirs(os.path.join(self.doc, pkg))
            with gzip.open(os.path.join(self.doc, pkg, 'changelog.Debian.gz'), 'wt') as fh:
                fh.write(text)
        self.orig = (distropkg.DPKG_STATUS, distropkg.DOC_DIR)
        distropkg.DPKG_STATUS, distropkg.DOC_DIR = self.status, self.doc
        self.addCleanup(lambda: (setattr(distropkg, 'DPKG_STATUS', self.orig[0]), setattr(distropkg, 'DOC_DIR', self.orig[1])))

    def test_check(self):
        c = distropkg.check
        self.assertEqual(c('Brotli', '1.0.9-2+deb12u1', 'CVE-2099-11111'), {'result': 'fixed', 'package': 'libbrotli1'})
        self.assertEqual(c('Brotli', '1.0.9-2+deb12u1', 'CVE-2099-1111'), {'result': 'not_listed', 'package': 'libbrotli1'})  # not a prefix
        self.assertEqual(c('Brotli', '1.0.9-2+deb12u1', 'CVE-2099-33333')['result'], 'not_listed')
        self.assertEqual(c('Brotli', '1.0.9-2+deb12u1', 'CVE-2099-22222')['result'], 'unknown')   # a fix taken back
        self.assertEqual(c('Brotli', '1.0.9-2+deb12u2', 'CVE-2099-11111')['result'], 'unknown')     # not the installed version
        self.assertEqual(c('Gone', '3.0-1', 'CVE-2099-11111'), {'result': 'unknown', 'package': 'libgone1'})   # no change log here
        self.assertIsNone(c('Old', '1.0-1', 'CVE-2099-11111'))                   # only its configuration left: not installed
        self.assertEqual(c('Example', '2.4.1-3~bpo12+1', 'CVE-2099-11111')['result'], 'unknown')   # names its distribution
        self.assertIsNone(c('Odoo', '18.0-20260404', 'CVE-2099-11111'))        # another host's application, not a package
        self.assertIsNone(c('Example', '2.4-1', 'CVE-2099-11111'))
        self.assertIsNone(c('Brotli', '1.0.9', 'CVE-2099-11111'))                 # the upstream release itself
        self.assertIsNone(c('Zimbra', '10.1.20, 10.1.21', 'CVE-2099-11111'))
        self.assertIsNone(c('Brotli', '1.0.9-2+deb12u1', 'GHSA-xxxx'))

    def test_threat_set_aside_and_alert_handled(self):
        from jtwafmgr import alerts, intel
        from jtwafmgr.app import App
        app = App(self.env.cfg, start_collector=False)
        now = time.time()
        rows = {}
        for cve, ver in (('CVE-2099-11111', '1.0.9-2+deb12u1'), ('CVE-2099-33333', '1.0.9-2+deb12u1')):
            t = {'id': cve, 'product': 'Brotli', 'our_version': ver, 'affected': 'yes', 'exploited': True}
            rows[cve] = app.db.x('INSERT INTO intel_threats(cve, product, first_seen, last_seen, affected, exploited, severity, details) '
                                 'VALUES (?,?,?,?,?,?,?,?)', (cve, 'Brotli', now, now, 'yes', 1, 'critical', json.dumps(t))).lastrowid
            alerts.raise_alert(app.db, app.audit, 'intel', 'exploited_vulnerability', 'critical', 'intel:%s:Brotli' % cve,
                               {'reason': 'test'}, link='/intel')
        self.assertEqual(intel.retire_by_distro(app, log=lambda m: None), [rows['CVE-2099-11111']])
        r = app.db.one('SELECT status, affected, details FROM intel_threats WHERE id=?', (rows['CVE-2099-11111'],))
        d = json.loads(r['details'])
        self.assertEqual((r['status'], r['affected'], d['distro_check']['result'], d['affected_model']), ('ignored', 'no', 'fixed', 'yes'))
        a = app.db.one("SELECT state, note FROM alerts WHERE dedup='intel:CVE-2099-11111:Brotli'")
        self.assertEqual(a['state'], 'handled')
        self.assertIn('libbrotli1', a['note'])
        # not in the change log: the distribution has not fixed it -- stays, noted
        r = app.db.one('SELECT status, details FROM intel_threats WHERE id=?', (rows['CVE-2099-33333'],))
        self.assertEqual((r['status'], json.loads(r['details'])['distro_check']['result']), ('open', 'not_listed'))
        self.assertEqual(app.db.one("SELECT state FROM alerts WHERE dedup='intel:CVE-2099-33333:Brotli'")['state'], 'open')
        self.assertEqual(intel.retire_by_distro(app, log=lambda m: None), [])

    def test_unknown_is_not_urgent(self):
        from jtwafmgr import intel
        t = {'id': 'CVE-2099-11111', 'product': 'Gone', 'our_version': '3.0-1', 'affected': 'yes', 'exploited': True}
        self.assertTrue(intel.is_urgent(t))
        distropkg.apply(t)
        self.assertEqual(t['distro_check']['result'], 'unknown')
        self.assertFalse(intel.is_urgent(t))          # "check the distribution's advisory", not the urgent path
        t = {'id': 'CVE-2099-11111', 'product': 'Brotli', 'our_version': '1.0.9-2+deb12u1', 'affected': 'yes', 'exploited': True}
        distropkg.apply(t)
        self.assertEqual(t['affected'], 'no')
        self.assertFalse(intel.is_urgent(t))


if __name__ == '__main__':
    unittest.main()
