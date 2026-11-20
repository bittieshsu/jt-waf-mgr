"""0.5.8: the threat intelligence that missed PHP's announced security release of 2026-11-19 (CVE-2026-115560):
the program's own search for every product and the language / framework it is built on, announced releases as
alerts and a search again once they are out, virtual patches on a parameter's name (a multipart upload part), and
host package versions that follow the installed package."""
import json
import os
import tempfile
import time
import unittest

from jtwafmgr import evidence, intel, notify, rulegen, software
from jtwafmgr.app import App
from tests.helpers import TempEnv

PHP_NOTICE = {
    'product': 'PHP', 'title': 'Security releases for all supported branches', 'release_at': '2026-11-19T14:00:00Z',
    'ids': ['CVE-2026-115560', 'not-an-id'], 'summary': 'critical issues in non-default setups',
    'mitigation': 'set session.upload_progress.enabled=0 and restart PHP workers',
    'references': ['https://www.php.net/', 'http://insecure.example.com/']}


class Base(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        software.save(self.app.db, 'test', 'Nextcloud', '34.0.5', hosts=['cloud.example.com'])
        software.save(self.app.db, 'test', 'Z-Push', '', hosts=['push.example.com'])
        software.save(self.app.db, 'test', 'nginx', '1.30.6-1~bookworm')

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()


class TestSweep(Base):
    def test_every_product_and_language_once(self):
        qs = intel.sweep_queries(software.confirmed(self.app.db), time.mktime((2026, 11, 19, 12, 0, 0, 0, 0, -1)))
        names = [q.split(' security advisory ')[0] for q in qs]
        self.assertIn('PHP', names)                     # Nextcloud and Z-Push are built on it: asked once
        self.assertEqual(names.count('PHP'), 1)
        self.assertTrue({'Nextcloud', 'Z-Push', 'nginx'} <= set(names))
        self.assertTrue(all(q.endswith('November 2026') for q in qs))
        many = [{'name': 'Product %d' % i} for i in range(50)]
        self.assertEqual(len(intel.sweep_queries(many, time.time())), intel.SWEEP_MAX)


class TestAnnouncements(Base):
    def test_language_notice_reaches_its_applications(self):
        anns = intel.clean_announcements({'announcements': [PHP_NOTICE, dict(PHP_NOTICE, product='Ruby'),
                                                            dict(PHP_NOTICE, references=['http://x.example.com/'])]},
                                         software.confirmed(self.app.db))
        self.assertEqual(len(anns), 1)                  # Ruby: nothing here built on it; no https reference: dropped
        a = anns[0]
        self.assertEqual((a['product'], a['products']), ('PHP', ['Nextcloud', 'Z-Push']))
        self.assertEqual(a['ids'], ['CVE-2026-115560'])
        self.assertEqual(a['references'], ['https://www.php.net/'])
        self.assertEqual(a['at'], 1795096800)

    def test_alert_and_a_search_after_the_release(self):
        anns = intel.clean_announcements({'announcements': [PHP_NOTICE]}, software.confirmed(self.app.db))
        before = anns[0]['at'] - 3600
        intel.announce(self.app, 7, anns, before, log=lambda m: None)
        intel.announce(self.app, 8, anns, before + 60, log=lambda m: None)            # seen again: one alert, one re-check
        rows = self.app.db.q("SELECT * FROM alerts WHERE kind='security_release'")
        self.assertEqual(len(rows), 1)
        d = json.loads(rows[0]['details'])
        self.assertEqual((d['msg'], d['products'], d['hosts']), ('intel_release', 'Nextcloud, Z-Push',
                                                                 ['cloud.example.com', 'push.example.com']))
        self.assertIn('upload_progress', notify.alert_text('zh-TW', d))
        self.assertEqual(len(intel._read_rechecks(self.app.cfg)), 1)
        self.assertEqual(intel.rechecks_due(self.app.cfg, anns[0]['at']), [])         # not out yet
        due = anns[0]['at'] + intel.RECHECK_AFTER
        self.assertEqual(len(intel.rechecks_due(self.app.cfg, due)), 1)
        self.assertEqual(len(intel.rechecks_due(self.app.cfg, due, mark=True)), 1)
        self.assertEqual(intel.rechecks_due(self.app.cfg, due + 60), [])               # one search covers it

    def test_no_time_or_long_out_is_no_notice(self):
        # 0.5.9: the model offered releases already installed here (nginx 1.30.7, ModSecurity 3.0.17), without a time
        anns = intel.clean_announcements({'announcements': [dict(PHP_NOTICE, release_at=''),
                                                            dict(PHP_NOTICE, release_at='2026-11-01T00:00:00Z')]},
                                         software.confirmed(self.app.db))
        intel.announce(self.app, 9, anns, 1795096800, log=lambda m: None)
        self.assertIsNone(self.app.db.one("SELECT 1 FROM alerts WHERE kind='security_release'"))
        self.assertEqual(intel._read_rechecks(self.app.cfg), [])

    def test_a_date_alone_is_the_end_of_that_day(self):
        # 0.5.24: "2026-11-19" was 00:00 UTC -- a release that evening was dropped as long out
        import calendar
        self.assertEqual(intel._release_time('2026-11-19'), calendar.timegm((2026, 11, 19, 0, 0, 0)) + 36 * 3600 - 1)
        self.assertEqual(intel._release_time('2026-11-19T14:00:00Z'), calendar.timegm((2026, 11, 19, 14, 0, 0)))

    def test_search_service_that_does_not_search(self):
        self.assertFalse(intel.search_alert(self.app, 1, 25, 10, 'http://search.example.com/mcp'))
        self.assertFalse(intel.search_alert(self.app, 1, 3, 3, 'http://search.example.com/mcp'))     # too few to say
        self.assertTrue(intel.search_alert(self.app, 1, 25, 21, 'http://search.example.com/mcp'))
        r = self.app.db.one("SELECT id, details FROM alerts WHERE dedup='intel-search-empty'")
        d = json.loads(r['details'])
        self.assertIn('search.example.com', notify.alert_text('en', d))
        # 0.5.21: one alert while it lasts (it was one a day); an older day-keyed one stays the one, a second is merged
        db = self.app.db
        db.x("UPDATE alerts SET dedup='intel-search-empty:2026-11-20' WHERE id=?", (r['id'],))
        db.x("INSERT INTO alerts(created_at, last_seen, source, kind, severity, dedup, details, link) "
             "VALUES (1, 1, 'intel', 'other', 'warning', 'intel-search-empty:2026-11-21', '{}', '/intel')")
        self.assertTrue(intel.search_alert(self.app, 2, 25, 24, 'http://search.example.com/mcp'))
        rows = db.q("SELECT id, state, count, note FROM alerts WHERE dedup LIKE 'intel-search-empty%' ORDER BY id")
        self.assertEqual([(x['state'], x['count']) for x in rows], [('open', 2), ('handled', 1)])
        self.assertIn('#%d' % r['id'], rows[1]['note'])
        # the searches give pages again: handled
        self.assertFalse(intel.search_alert(self.app, 3, 25, 2, 'http://search.example.com/mcp'))
        self.assertEqual(db.one('SELECT state FROM alerts WHERE id=?', (r['id'],))['state'], 'handled')
        self.assertIn('again', db.one('SELECT note FROM alerts WHERE id=?', (r['id'],))['note'])

        class S:
            def __init__(self):
                self.searches = []

            def run_tool(self, name, args):
                self.searches.append(args['query'])
                return '【摘要】PHP is a language' if 'PHP' in args['query'] else 'Result https://example.com/advisory'
        out, asked, empty = intel.sweep(S(), software.confirmed(self.app.db), time.time(), log=lambda m: None)
        self.assertEqual((asked - empty, empty), (len(out), 1))

    def test_old_answers_without_announcements(self):
        self.assertEqual(intel.clean_announcements({'threats': [], 'notes': ''}, []), [])
        self.assertEqual(intel.clean_announcements(None, []), [])


class TestArgNamePatch(Base):
    T = {'id': 'CVE-2026-115560', 'product': 'Nextcloud', 'references': ['https://www.php.net/']}

    def patch(self, **k):
        return dict({'possible': True, 'target': 'arg_name', 'header': '', 'regex': '^php_session_upload_progress$',
                     'attack_examples': ['php_session_upload_progress'], 'benign_examples': ['file', 'title'],
                     'explanation': 'the upload progress field'}, **k)

    def test_spec_and_tests(self):
        samples = [{'host': 'cloud.example.com', 'method': 'GET', 'path': '/index.php?dir=/&page=2'}]
        spec, tests = intel._patch_spec(self.patch(), self.T, samples, ['cloud.example.com'])
        self.assertEqual((spec['target'], spec['host']), ('arg_name', {'mode': 'exact', 'value': 'cloud.example.com'}))
        refused = [t for t in tests if t['expect'] == 403]
        self.assertEqual(len(refused), 2)
        self.assertIn('name="php_session_upload_progress"', refused[0]['body'])
        self.assertTrue(refused[0]['headers']['Content-Type'].startswith('multipart/form-data; boundary='))
        self.assertEqual(refused[1]['body'], 'php_session_upload_progress=1&a=1')
        ok = [t for t in tests if t['expect'] == 200]
        self.assertEqual(len(ok), 1)                    # an ordinary upload to the same place goes through
        from jtwafmgr.changes import _check_tests
        _check_tests(tests)

    def test_refused_specs(self):
        samples = [{'host': 'cloud.example.com', 'method': 'GET', 'path': '/index.php?requesttoken=x&dir=/'}]
        for bad, why in ((dict(regex='php_session_upload_progress'), 'not_anchored'),
                         (dict(regex='^(?:file|php_session_upload_progress)$', attack_examples=['php_session_upload_progress']),
                          'matches_normal'),
                         (dict(regex='^requesttoken$', attack_examples=['requesttoken']), 'matches_normal')):
            with self.assertRaises(intel.IntelError) as e:
                intel._patch_spec(self.patch(**bad), self.T, samples, ['cloud.example.com'])
            self.assertEqual(e.exception.code, why)

    def test_rule_is_phase_two_before_the_score_rule(self):
        spec, tests = intel._patch_spec(self.patch(), self.T, [], ['cloud.example.com'])
        norm, text, placement = rulegen.build('confident_block', dict(spec, before_rule_id=10298), 10250, self.app.cfg)
        self.assertIn('SecRule ARGS_NAMES "@rx ^php_session_upload_progress$"', text)
        self.assertIn('phase:2', text)
        self.assertNotIn('phase:1', text)
        self.assertEqual((norm['before_rule_id'], placement), (10298, 'before'))
        # a path rule stays in phase 1 and takes no anchor
        norm, text, _ = rulegen.build('confident_block', {'target': 'path', 'regex': '^/x$', 'msg': 'x',
                                                          'before_rule_id': 10298}, 10251, self.app.cfg)
        self.assertIn('phase:1', text)
        self.assertNotIn('before_rule_id', norm)

    def test_no_evidence_in_the_access_logs(self):
        view = evidence.Evidence.rule_view({'target': 'arg_name', 'regex': '^a$'})
        self.assertIsNone(view)


class TestHostVersions(Base):
    def test_installed_package_version_is_followed(self):
        st = tempfile.NamedTemporaryFile('w', delete=False, suffix='.status')
        st.write('Package: nginx\nStatus: install ok installed\nVersion: 1.30.7-1~bookworm\n\n')
        st.close()
        self.addCleanup(os.unlink, st.name)
        self.app.db.x("UPDATE software SET source='guess', kind='host' WHERE name='nginx'")
        self.assertEqual(software.sync_host_versions(self.app, log=lambda m: None, path=st.name), ['nginx'])
        r = self.app.db.one("SELECT version, confirmed FROM software WHERE name='nginx'")
        self.assertEqual((r['version'], r['confirmed']), ('1.30.7-1~bookworm', 1))
        self.assertEqual(software.sync_host_versions(self.app, log=lambda m: None, path=st.name), [])
        # a person's entry is theirs
        self.app.db.x("UPDATE software SET source='person', version='1.30.0' WHERE name='nginx'")
        self.assertEqual(software.sync_host_versions(self.app, log=lambda m: None, path=st.name), [])


if __name__ == '__main__':
    unittest.main()
