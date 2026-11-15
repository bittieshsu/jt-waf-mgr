"""The CISA KEV catalog (kev.py): off by default, checked before it replaces the copy, used to mark "exploited"."""
import json
import os
import unittest

from jtwafmgr import kev
from tests.helpers import TempEnv


def catalog(n=600, extra=()):
    vulns = [{'cveID': 'CVE-2020-%05d' % i, 'vendorProject': 'Vendor%d' % i, 'product': 'Product %d' % i,
              'vulnerabilityName': 'x', 'dateAdded': '2024-01-01', 'knownRansomwareCampaignUse': 'Unknown'} for i in range(n)]
    vulns += list(extra)
    return json.dumps({'catalogVersion': '2026.11.15', 'vulnerabilities': vulns}).encode()


class TestKev(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.cfg = self.env.cfg

    def tearDown(self):
        self.env.cleanup()

    def test_off_by_default_downloads_nothing(self):
        called = []
        self.assertEqual(kev.update(self.cfg, get=lambda u, t: called.append(u)), 'off')
        self.assertEqual(called, [])
        self.assertEqual(kev.ids(self.cfg), set())

    def test_update_checks_and_replaces(self):
        self.cfg.data['intel']['kev'] = True
        extra = [{'cveID': 'CVE-2026-11111', 'vendorProject': 'Example', 'product': 'Example CMS', 'dateAdded': '2026-11-10',
                  'knownRansomwareCampaignUse': 'Known'},
                 {'cveID': 'CVE-2026-22222', 'vendorProject': 'Synacor', 'product': 'Zimbra Collaboration Suite (ZCS)', 'dateAdded': '2026-11-01'}]
        self.assertEqual(kev.update(self.cfg, get=lambda u, t: catalog(extra=extra), log=lambda m: None), 'updated')
        self.assertEqual(oct(os.stat(kev.path(self.cfg)).st_mode & 0o777), '0o600')
        self.assertIn('CVE-2026-11111', kev.ids(self.cfg))
        self.assertEqual(kev.update(self.cfg, get=lambda u, t: b'', log=lambda m: None), 'fresh')   # once a day
        m = kev.matching(self.cfg, [{'name': 'Example CMS', 'version': '3.1'}, {'name': 'Zimbra', 'version': ''}])
        self.assertEqual([x['cve'] for x in m], ['CVE-2026-11111', 'CVE-2026-22222'])
        self.assertTrue(m[0]['ransomware'])
        self.assertEqual(kev.status(self.cfg)['entries'], 602)

    def test_odd_downloads_keep_the_copy(self):
        self.cfg.data['intel']['kev'] = True
        for raw in (b'<html>maintenance</html>', json.dumps({'vulnerabilities': []}).encode(), catalog(n=10)):
            self.assertTrue(kev.update(self.cfg, get=lambda u, t, r=raw: r, log=lambda m: None).startswith('failed:'))
        self.assertFalse(os.path.exists(kev.path(self.cfg)))


if __name__ == '__main__':
    unittest.main()
