"""NVD scores (nvd.py): off by default, only the CVE id sent, spaced, cached; the official severity wins."""
import os
import unittest

from jtwafmgr import nvd
from tests.helpers import TempEnv

ANSWER = {'vulnerabilities': [{'cve': {
    'id': 'CVE-2026-11111', 'published': '2026-11-01T00:00:00.000', 'vulnStatus': 'Analyzed',
    'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL',
                                                'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}}]},
    'weaknesses': [{'description': [{'lang': 'en', 'value': 'CWE-78'}]}]}}]}


class TestNvd(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.cfg = self.env.cfg

    def tearDown(self):
        self.env.cleanup()

    def test_off_by_default(self):
        t = [{'id': 'CVE-2026-11111', 'severity': 'medium'}]
        self.assertEqual(nvd.enrich(self.cfg, t, get=lambda u, to: self.fail('asked')), 0)
        self.assertNotIn('nvd', t[0])

    def test_enrich_spacing_and_cache(self):
        self.cfg.data['intel']['nvd'] = True
        asked, slept = [], []
        t = [{'id': 'CVE-2026-11111', 'severity': 'medium'}, {'id': 'GHSA-xxxx-yyyy-zzzz', 'severity': 'low'},
             {'id': 'CVE-2026-22222', 'severity': 'high'}]
        n = nvd.enrich(self.cfg, t, get=lambda u, to: (asked.append(u), ANSWER)[1], sleep=slept.append, log=lambda m: None)
        self.assertEqual(n, 2)                                        # GHSA ids are not asked about
        self.assertTrue(all('cveId=CVE-' in u for u in asked))
        self.assertEqual(slept, [nvd.SPACING])                        # NVD's rate limit
        self.assertEqual((t[0]['severity'], t[0]['severity_model'], t[0]['nvd']['score'], t[0]['nvd']['cwe']), ('critical', 'medium', 9.8, ['CWE-78']))
        self.assertEqual(oct(os.stat(nvd.cache_path(self.cfg)).st_mode & 0o777), '0o600')
        t2 = [{'id': 'CVE-2026-11111', 'severity': 'low'}]
        self.assertEqual(nvd.enrich(self.cfg, t2, get=lambda u, to: self.fail('asked again'), sleep=slept.append, log=lambda m: None), 0)
        self.assertEqual(t2[0]['severity'], 'critical')


if __name__ == '__main__':
    unittest.main()
