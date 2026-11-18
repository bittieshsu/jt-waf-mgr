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

    def test_versions_outside_nvd_ranges_do_not_affect_us(self):
        """0.4.96 (user 2026-11-18, CVE-2025-48700 in Zimbra 10.1.20): NVD's CPE ranges rule a version out."""
        conf = [{'nodes': [{'cpeMatch': [
            {'vulnerable': True, 'criteria': 'cpe:2.3:a:example:zimbra_collaboration_suite:*:*:*:*:*:*:*:*',
             'versionStartIncluding': '10.1.0', 'versionEndExcluding': '10.1.4'},
            {'vulnerable': True, 'criteria': 'cpe:2.3:a:example:zimbra_collaboration_suite:8.8.15:p1:*:*:*:*:*:*'},
            {'vulnerable': False, 'criteria': 'cpe:2.3:o:example:linux:-:*:*:*:*:*:*:*'}]}]}]
        ans = {'vulnerabilities': [dict(ANSWER['vulnerabilities'][0]['cve'], configurations=conf)]}
        ans = {'vulnerabilities': [{'cve': ans['vulnerabilities'][0]}]}
        self.cfg.data['intel']['nvd'] = True
        t = [{'id': 'CVE-2026-11111', 'product': 'Zimbra', 'our_version': '10.1.20', 'affected': 'unknown', 'severity': 'high'},
             {'id': 'CVE-2026-11111', 'product': 'Zimbra', 'our_version': '10.1.2', 'affected': 'unknown', 'severity': 'high'},
             {'id': 'CVE-2026-11111', 'product': 'Zimbra', 'our_version': '8.8.15', 'affected': 'unknown', 'severity': 'high'},
             {'id': 'CVE-2026-11111', 'product': 'Nextcloud', 'our_version': '1.0', 'affected': 'unknown', 'severity': 'high'}]
        nvd.enrich(self.cfg, t, get=lambda u, to: ans, sleep=lambda s: None, log=lambda m: None)
        self.assertEqual((t[0]['affected'], t[0]['affected_model'], t[0]['version_check']['result']), ('no', 'unknown', 'no'))
        self.assertIn('10.1.0 – <10.1.4', t[0]['version_check']['ranges'])
        self.assertEqual((t[1]['affected'], t[1]['version_check']['result']), ('unknown', 'yes'))   # never made urgent by itself
        self.assertNotIn('version_check', t[2])               # 8.8.15 with an unknown patch level: not decided
        # NVD names another product only (0.4.98): said, never set aside, and no longer the urgent path
        self.assertEqual((t[3]['affected'], t[3]['version_check']['result'], t[3]['version_check']['products']),
                         ('unknown', 'elsewhere', ['example zimbra_collaboration_suite']))
        from jtwafmgr import intel
        self.assertFalse(intel.is_urgent(dict(t[3], exploited=True)))
        self.assertTrue(intel.is_urgent(dict(t[1], exploited=True)))
        self.assertNotIn('cpes', t[0]['nvd'])                 # the ranges are not stored with every threat
        # 0.4.97: a distribution package -- the upstream release decides "outside" only (fixes are backported)
        brotli = [{'vendor': 'google', 'product': 'brotli', 'version': '*', 'update': '*', 'si': '1.0.3', 'se': '', 'ei': '',
                   'ee': '1.0.10'}]
        self.assertEqual(nvd.version_check('Brotli', '1.0.9-2+deb12u1', brotli)['distro'], True)
        self.assertEqual(nvd.version_check('Brotli', '1.1.0-2+deb13u1', brotli)['result'], 'no')
        self.assertEqual(nvd.version_check('OpenSSH', '1:9.2p1-2+deb12u10', brotli)['result'], 'elsewhere')
        # the vendor's other product (a desktop client) is no comparison for ours
        self.assertEqual(nvd.version_check('Nextcloud', '34.0.5', [{'vendor': 'nextcloud', 'product': 'desktop', 'version': '*',
                                                                     'update': '*', 'si': '', 'se': '', 'ei': '', 'ee': '3.0'}])['result'],
                         'elsewhere')
        self.assertIsNone(nvd.version_check('Zimbra', 'unknown', [{'vendor': 'x', 'product': 'zimbra', 'version': '*',
                                                                   'update': '*', 'si': '', 'se': '', 'ei': '', 'ee': '1.0'}]))


if __name__ == '__main__':
    unittest.main()


class TestRetireByVersion(unittest.TestCase):
    def test_open_threat_ruled_out_by_nvd_is_set_aside_with_its_alert(self):
        import json
        import time
        from jtwafmgr import alerts, intel
        from jtwafmgr.app import App
        env = TempEnv(intel={'nvd': True})
        self.addCleanup(env.cleanup)
        app = App(env.cfg, start_collector=False)
        now = time.time()
        os.makedirs(os.path.dirname(nvd.cache_path(env.cfg)), exist_ok=True)
        with open(nvd.cache_path(env.cfg), 'w') as fh:
            json.dump({'CVE-2025-48700': {'at': now, 'info': {'cwe': [], 'cpes': [
                {'vendor': 'example', 'product': 'zimbra_collaboration_suite', 'version': '*', 'update': '*',
                 'si': '10.1.0', 'se': '', 'ei': '', 'ee': '10.1.4'}]}}}, fh)
        details = {'id': 'CVE-2025-48700', 'product': 'Zimbra', 'our_version': '10.1.20', 'affected': 'unknown', 'exploited': True}
        tid = app.db.x('INSERT INTO intel_threats(cve, product, first_seen, last_seen, affected, exploited, severity, details) '
                       'VALUES (?,?,?,?,?,?,?,?)', ('CVE-2025-48700', 'Zimbra', now, now, 'unknown', 1, 'medium',
                                                    json.dumps(details))).lastrowid
        alerts.raise_alert(app.db, app.audit, 'intel', 'exploited_vulnerability', 'warning', 'intel-check:CVE-2025-48700:Zimbra',
                           {'reason': 'test'}, link='/intel')
        self.assertEqual(intel.retire_by_version(app, log=lambda m: None), [tid])
        r = app.db.one('SELECT status, affected, details FROM intel_threats WHERE id=?', (tid,))
        self.assertEqual((r['status'], r['affected'], json.loads(r['details'])['version_check']['result']), ('ignored', 'no', 'no'))
        a = app.db.one("SELECT state, note FROM alerts WHERE dedup='intel-check:CVE-2025-48700:Zimbra'")
        self.assertEqual(a['state'], 'handled')
        self.assertIn('10.1.0 – <10.1.4', a['note'])
        self.assertEqual(intel.retire_by_version(app, log=lambda m: None), [])     # nothing left open
