"""0.5.10: a page or a text handed to the threat intelligence ("analyze this"), each source asked about on its own,
and threat intelligence virtual patches the access logs cannot check applied without a person (the user, 2026-11-20:
fully automatic, no administrator approval)."""
import json
import os
import time
import unittest
from unittest import mock

from jtwafmgr import intel, software
from jtwafmgr.app import App
from tests.helpers import TempEnv

ARTICLE = ('PHP warns of critical security flaws affecting all supported versions; fixes coming November 19. '
           'CVE-2026-115560 is a remote code execution vector in session upload progress handling. ' * 6)
FOUND = {'threats': [{'id': 'CVE-2026-115560', 'product': 'PHP', 'summary': 'RCE in session upload progress',
                      'affected_versions': 'all supported branches', 'fixed_version': '', 'our_version': '', 'affected': 'yes',
                      'exploited': False, 'exploited_evidence': '', 'severity': 'critical', 'attack_vector': 'body',
                      'request_pattern': 'a multipart upload with a field named PHP_SESSION_UPLOAD_PROGRESS',
                      'references': [], 'preconditions': '', 'conditions_met': 'unknown'}],
         'announcements': []}


class Base(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        self.app.cfg.data['intel'].update(enabled=True, provider='openai', url='http://127.0.0.1:9/v1', model='m',
                                          search='mcp', mcp_url='http://127.0.0.1:9/mcp', patches=False)
        software.save(self.app.db, 'test', 'Nextcloud', '34.0.5', hosts=['cloud.example.com'])
        software.save(self.app.db, 'test', 'Keycloak', '26.0.5', hosts=['sso.example.com'])

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()


class TestSubmit(Base):
    def request(self):
        with open(intel.request_file(self.app.cfg)) as fh:
            return fh.read()

    def test_clean_url(self):
        self.assertEqual(intel.clean_url('https://news.example.com/a.html?fbclid=IwY2x&utm_source=fb&id=7'),
                         'https://news.example.com/a.html?id=7')
        for bad in ('http://news.example.com/', 'ftp://x.example.com/', 'https://', 'https://a.example.com/\nx'):
            with self.assertRaises(intel.IntelError):
                intel.clean_url(bad)

    def test_submit_and_the_request(self):
        sid = intel.submit(self.app, 'appr', url='https://news.example.com/php?fbclid=x', src_ip='192.0.2.5')
        r = self.app.db.one('SELECT * FROM intel_submissions WHERE id=?', (sid,))
        self.assertEqual((r['url'], r['state'], r['created_by']), ('https://news.example.com/php', 'pending', 'appr'))
        self.assertTrue(self.request().startswith('submission'))
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='intel.submitted'"))
        # a whole search asked for is never turned into the smaller one
        intel.request_run(self.app.cfg)
        intel.submit(self.app, 'appr', text='PHP CVE-2026-115560 ...')
        self.assertTrue(self.request().startswith('search'))
        for bad in ({}, {'url': 'http://x.example.com/'}, {'text': 'x' * (intel.SUBMIT_TEXT + 1)}):
            with self.assertRaises(intel.IntelError):
                intel.submit(self.app, 'appr', **bad)

    def run_submissions(self, page):
        calls = []

        def ask(cfg, system, user, schema, name):
            calls.append(user)
            return (FOUND if 'CVE-2026-115560' in user else {'threats': [], 'announcements': []}), 100, 20
        with mock.patch.object(intel, 'fetch_url', lambda url, domains, **k: page if domains == ['news.example.com'] else 'refused'):
            rid = intel.run(self.app, 'submission', mode='submissions', log=lambda m: None, focus_ask=ask,
                            ask=lambda *a: self.fail('no whole search in a submissions run'))
        return rid, calls

    def test_a_page_is_read_and_its_threat_reaches_the_applications_built_on_php(self):
        sid = intel.submit(self.app, 'appr', url='https://news.example.com/php-flaws?fbclid=x')
        rid, calls = self.run_submissions(ARTICLE)
        self.assertEqual(len(calls), 1)
        self.assertIn('Nextcloud 34.0.5 (built on: PHP)', calls[0])
        run = self.app.db.one('SELECT * FROM intel_runs WHERE id=?', (rid,))
        self.assertEqual((run['trigger'], run['error']), ('submission', None))
        self.assertEqual(json.loads(run['searches']), [])                  # no search of its own
        rows = self.app.db.q("SELECT * FROM intel_threats WHERE cve='CVE-2026-115560'")
        self.assertEqual([r['product'] for r in rows], ['Nextcloud'])     # Keycloak is Java
        d = json.loads(rows[0]['details'])
        self.assertEqual((d['affected'], d['attack_vector']), ('unknown', 'body'))   # the PHP version here is not known
        self.assertIn('https://news.example.com/php-flaws', d['references'])
        s = self.app.db.one('SELECT * FROM intel_submissions WHERE id=?', (sid,))
        self.assertEqual(s['state'], 'done')
        self.assertEqual(json.loads(s['result'])['threats'], ['CVE-2026-115560 Nextcloud'])

    def test_a_page_that_shows_nothing_to_a_program(self):
        sid = intel.submit(self.app, 'appr', url='https://news.example.com/login-wall')
        self.run_submissions('Log in to continue')
        s = self.app.db.one('SELECT * FROM intel_submissions WHERE id=?', (sid,))
        self.assertEqual(s['state'], 'failed')
        self.assertIn('paste its text', s['error'])

    def test_a_text_handed_in(self):
        sid = intel.submit(self.app, 'appr', text=ARTICLE)
        self.run_submissions('')
        self.assertEqual(self.app.db.one('SELECT state FROM intel_submissions WHERE id=?', (sid,))[0], 'done')

    def test_the_job_runs_submissions_without_the_whole_search(self):
        now = time.time()
        self.app.db.x("INSERT INTO intel_runs(node_id, started_at, finished_at, trigger, provider, model) "
                      "VALUES ('n', ?, ?, 'schedule', 'openai', 'm')", (now - 600, now - 500))
        intel.submit(self.app, 'appr', text=ARTICLE)
        with mock.patch.object(intel, 'run_test'), mock.patch.object(intel, 'run', return_value=9) as r:
            intel.run_job(self.app, log=lambda m: None)
        self.assertEqual((r.call_args.args[1], r.call_args.kwargs.get('mode')), ('submission', 'submissions'))
        # a submissions run is not the periodic search: it does not push the next one back
        self.app.db.x("INSERT INTO intel_runs(node_id, started_at, trigger, provider, model) VALUES ('n', ?, 'submission', 'openai', 'm')",
                      (now,))
        self.app.db.x("UPDATE intel_runs SET started_at=? WHERE trigger='schedule'", (now - 7 * 3600,))
        with mock.patch.object(intel, 'run_test'), mock.patch.object(intel, 'run', return_value=9) as r:
            intel.run_job(self.app, log=lambda m: None)
        self.assertEqual(r.call_args.args[1], 'schedule')


class TestFocus(Base):
    def test_sources_worth_a_question(self):
        swept = [('nginx security advisory November 2026', 'nginx 1.30.7 fixes CVE-2026-123007 https://nginx.org/'),
                 ('PHP security advisory November 2026', 'PHP warns of critical flaws https://www.php.net/'),
                 ('Keycloak security advisory November 2026', 'Keycloak release notes https://www.keycloak.org/')]
        got = intel.focus_sources(swept, software.confirmed(self.app.db))
        self.assertEqual([g[0] for g in got], ['search results for "PHP security advisory November 2026"',
                                               'search results for "nginx security advisory November 2026"'])

    def test_one_failed_question_leaves_the_others(self):
        answers = iter([intel.IntelError('http_502'), FOUND])

        def ask(*a):
            x = next(answers)
            if isinstance(x, Exception):
                raise x
            return x, 10, 5
        sess = intel.Session(self.app.cfg)
        th, an = intel.focus(self.app.cfg, sess, software.confirmed(self.app.db),
                             [('a', 'x'), ('https://news.example.com/b', 'y')], time.time(), ask=ask, log=lambda m: None)
        self.assertEqual([(t['product'], t['_src']) for t in th], [('Nextcloud', 1)])
        self.assertIn('https://news.example.com/b', th[0]['references'])


class TestFullyAutomatic(Base):
    def change(self, by, target='arg_name', evidence=None):
        spec = {'target': target, 'regex': '^php_session_upload_progress$', 'msg': 'virtual patch', 'source': 'external',
                'host': {'mode': 'any', 'value': ''}}
        checks = {'evidence': evidence or {'ok': True, 'skipped': 'request bodies are not in the access log', 'complete': False}}
        now = time.time()
        return self.app.db.x("INSERT INTO changes(op, kind, spec, direction, state, reason, proposed_by, created_at, updated_at, checks) "
                             "VALUES ('add', 'confident_block', ?, 'tighten', 'pending_approval', 'r', ?, ?, ?, ?)",
                             (json.dumps(spec), by, now, now, json.dumps(checks))).lastrowid

    def auto(self, cid):
        wf = self.app.workflow
        with mock.patch.object(wf, '_queue_apply') as q:
            wf._maybe_auto_apply(cid)
        return q.called

    def test_intel_patch_the_logs_cannot_check_goes_without_a_person(self):
        self.assertTrue(self.auto(self.change('intel')))
        self.assertTrue(self.auto(self.change('intel', target='header')))
        # the event analysis' blocks still need clean evidence (or a person)
        self.assertFalse(self.auto(self.change('analyst')))
        # evidence that was checked and is not clean: a person decides
        self.assertFalse(self.auto(self.change('intel', target='path',
                                               evidence={'ok': True, 'external_success': 3, 'internal_other': 0})))


if __name__ == '__main__':
    unittest.main()
