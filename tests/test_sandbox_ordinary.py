"""An ordinary test request of a confident block that the rules in place already refuse (0.5.47): e.g. a protection
set's WebDAV request on a site whose CRS does not allow WebDAV methods. It is judged against the configuration as it
is, and fails only when the change's own rules match it; an exclusion's ordinary test is never excused."""
import json
import unittest
from unittest import mock

from jtwafmgr import sandbox
from jtwafmgr.app import App
from tests.helpers import TempEnv

SPEC = {'target': 'path', 'regex': '^/config(?:/|$)', 'msg': 'config', 'source': 'external',
        'host': {'mode': 'exact', 'value': 'files.example.com'}}


class TestOrdinaryRequests(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        self.sb = self.app.workflow.sandbox

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def tests(self):
        return [{'expect': 403, 'source': 'external', 'host': 'files.example.com', 'path': '/config/config.php'},
                {'expect': 200, 'source': 'external', 'host': 'files.example.com', 'path': '/remote.php/dav/files/a/',
                 'method': 'PROPFIND'}]

    def test_a_block_s_ordinary_test_carries_its_rule_ids(self):
        r = {'op': 'add', 'kind': 'confident_block', 'direction': 'tighten', 'rule_id': 10250, 'spec': json.dumps(SPEC)}
        c = [x for x in self.sb.cases_for(r, self.tests(), []) if x['origin'] == 'test' and x['expect'] == 200][0]
        self.assertEqual(c['absent_rules'], [10250])

    def test_an_exclusion_s_does_not(self):
        r = {'op': 'add', 'kind': 'exclusion', 'direction': 'loosen', 'rule_id': 10150, 'spec': json.dumps({})}
        c = [x for x in self.sb.cases_for(r, [self.tests()[1]], []) if x['origin'] == 'test'][0]
        self.assertNotIn('absent_rules', c)

    def run_change(self, r, before, after):
        calls = []

        def fake_run(files, cases):
            calls.append(files)
            return after(cases) if files else before(cases)
        with mock.patch.object(self.sb, 'run', side_effect=fake_run), \
                mock.patch.object(self.sb, 'replacements', return_value={'x': 'y'}):
            return self.sb.run_change(r, {}, self.tests(), None)

    def test_refused_already_is_not_the_change_s_doing(self):
        r = {'op': 'add', 'kind': 'confident_block', 'direction': 'tighten', 'rule_id': 10250, 'spec': json.dumps(SPEC)}
        crs = {'status': 403, 'rules': [911100, 949110]}
        out = self.run_change(r, lambda cs: [crs for _ in cs],
                              lambda cs: [{'status': 200, 'rules': []} if c['source'] == 'internal' else
                                          {'status': 403, 'rules': [10250, 949110]} if 'config' in c['path'].lower()
                                          else crs for c in cs])
        bad = [x for x in out['results'] if not x['ok']]
        self.assertEqual(bad, [], bad)

    def test_its_own_rule_matching_still_fails(self):
        r = {'op': 'add', 'kind': 'confident_block', 'direction': 'tighten', 'rule_id': 10250, 'spec': json.dumps(SPEC)}
        out = self.run_change(r, lambda cs: [{'status': 403, 'rules': [911100, 949110]} for _ in cs],
                              lambda cs: [{'status': 403, 'rules': [10250, 949110]} for _ in cs])
        self.assertFalse(out['ok'])


if __name__ == '__main__':
    unittest.main()
