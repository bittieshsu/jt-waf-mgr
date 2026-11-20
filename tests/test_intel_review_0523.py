"""0.5.23: fixes from an independent review of 0.5.10-0.5.16 (threat intelligence)."""
import json
import time
import unittest

from jtwafmgr import intel
from jtwafmgr.app import App
from tests.helpers import TempEnv

PRODUCTS = [{'name': 'Nextcloud', 'version': '30.0.2'}]


class TestReview(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def test_a_stopped_run_answers_what_was_handed_in(self):
        db, now = self.app.db, time.time()
        rid = db.x("INSERT INTO intel_runs(node_id, started_at, trigger, provider, model) VALUES (?, ?, 'submission', 'openai', 'm')",
                   (self.env.cfg['node']['id'], now - 4000)).lastrowid
        sid = db.x("INSERT INTO intel_submissions(url, text, state, run_id, created_by, created_at) VALUES ('', 'x', 'running', ?, 'alice', ?)",
                   (rid, now - 4000)).lastrowid
        self.assertEqual(intel.interrupted(db, self.env.cfg, now), 1)
        r = db.one('SELECT state, error FROM intel_submissions WHERE id=?', (sid,))
        self.assertEqual(r['state'], 'failed')
        self.assertIn('interrupted', r['error'])

    def test_a_pasted_text_can_name_a_threat(self):
        t = {'id': 'CVE-2099-0201', 'product': 'Nextcloud', 'summary': 's', 'affected_versions': '<31', 'fixed_version': '31',
             'our_version': '30.0.2', 'affected': 'yes', 'exploited': False, 'references': []}
        self.assertEqual(intel.clean({'threats': [t]}, PRODUCTS), [])                     # a search result needs its page
        self.assertEqual([x['id'] for x in intel.clean({'threats': [t]}, PRODUCTS, need_refs=False)], ['CVE-2099-0201'])

    def test_a_page_that_refuses_programs_leaves_the_pasted_text(self):
        class S:
            fetched, cisa_ids = [], set()

            def fetch(self, url, domains):
                return 'error: HTTP 403 Forbidden'
        r = {'url': 'https://news.example.com/a', 'text': 'Nextcloud CVE-2099-0201 ...', 'created_by': 'alice'}
        self.assertEqual(intel._read_submission(S(), r), ('https://news.example.com/a', r['text']))
        with self.assertRaises(intel.IntelError):
            intel._read_submission(S(), dict(r, text=''))

    def test_a_crowdsec_rule_applied_in_a_bundle_is_named(self):
        db, now = self.app.db, time.time()
        spec = {'ops': [{'op': 'add', 'kind': 'crowdsec', 'spec': {'name': 'crowdsecurity/vpatch-x'}},
                        {'op': 'add', 'kind': 'crowdsec', 'spec': {'name': 'crowdsecurity/vpatch-y'}}]}
        cid = db.x("INSERT INTO changes(op, kind, spec, direction, state, reason, proposed_by, created_at, updated_at) "
                   "VALUES ('bundle', 'bundle', ?, 'tighten', 'applied', 'r', 'alice', ?, ?)", (json.dumps(spec), now, now)).lastrowid
        for rid, name, cve in ((10401, 'crowdsecurity/vpatch-x', 'CVE-2099-0301'), (10402, 'crowdsecurity/vpatch-y', 'CVE-2099-0302')):
            db.x("INSERT INTO managed_rules(rule_id, kind, placement, position, spec, text, origin, created_by, created_at, updated_at, change_id) "
                 "VALUES (?, 'crowdsec', 'before', 1, ?, '', 'jt-waf-mgr', 'alice', ?, ?, ?)",
                 (rid, json.dumps({'name': name, 'yaml': 'labels:\n  classification:\n   - cve.%s\n' % cve}), now, now, cid))
        tid = db.x("INSERT INTO intel_threats(cve, product, affected, details, status, first_seen, last_seen, patch_change_id) "
                   "VALUES ('CVE-2099-0302', 'Nextcloud', 'yes', '{}', 'open', 0, 0, ?)", (cid,)).lastrowid
        self.assertEqual(intel.unlink_patches(db), 0)                 # still in force: kept
        self.assertEqual(intel.patch_rule(db, tid), 10402)
        db.x("UPDATE managed_rules SET deleted=1")
        self.assertEqual(intel.unlink_patches(db), 1)
        self.assertIsNone(intel.patch_rule(db, tid))


if __name__ == '__main__':
    unittest.main()
