"""A confident block on an uninspected body (body_unchecked) is checked against ModSecurity's own records of the bodies
it could not inspect (0.5.44): 0.5.43 skipped the check, and a block on all sites refused requests of a web mail
client whose SOAP JSON ModSecurity could not parse. Synthetic data only (example.com, documentation addresses)."""
import unittest

from jtwafmgr import util
from jtwafmgr.db import Database
from jtwafmgr.evidence import Evidence
from tests.helpers import TempEnv


class TestBodyErrorEvidence(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.env.cfg.data['evidence']['catch_all_hosts'] = []
        self.db = Database(self.env.cfg['paths']['db'])
        self.ev = Evidence(self.env.cfg, self.db)
        self.n = 0

    def tearDown(self):
        self.env.cleanup()

    def event(self, host, path, status=200, ip='203.0.113.5', rule_ids=',200002,', origin='external'):
        self.n += 1
        self.db.x('INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, status, outcome, '
                  "rule_ids, local_rule_ids, families, message, matches) VALUES ('n1', ?, ?, ?, 'POST', ?, '', ?, ?, ?, "
                  "'logged', ?, ',,', ',,', 'Failed to parse request body.', '[]')",
                  ('e%d' % self.n, util.now(), host, path, ip, origin, status, rule_ids))

    def spec(self, **kw):
        return dict({'target': 'body_unchecked', 'msg': 'body', 'host': {'mode': 'any'}, 'source': 'external'}, **kw)

    def test_answered_unparsable_bodies_fail_the_check(self):
        for _ in range(3):
            self.event('mail.example.com', '/service/soap/SaveDraftRequest')
        r = self.ev.block_evidence(self.spec())
        self.assertFalse(r['ok'])
        self.assertTrue(r['complete'])
        self.assertEqual(r['external_success'], 3)
        self.assertEqual(r['external_success_samples'][0]['path'], '/service/soap/SaveDraftRequest')

    def test_exception_and_host_leave_them_out(self):
        self.event('mail.example.com', '/service/soap/SendMsgRequest')
        self.assertTrue(self.ev.block_evidence(self.spec(exceptions=['^/service/soap(?:/|$)']))['ok'])
        self.assertTrue(self.ev.block_evidence(self.spec(host={'mode': 'exact', 'value': 'www.example.com'}))['ok'])

    def test_refused_and_other_rules_do_not_count(self):
        self.event('www.example.com', '/', status=403)           # a scanner, refused anyway
        self.event('www.example.com', '/', rule_ids=',930130,')    # not an uninspected body
        r = self.ev.block_evidence(self.spec())
        self.assertTrue(r['ok'])
        self.assertEqual(r['external_hits'], 1)

    def test_inside_counts(self):
        self.event('mail.example.com', '/service/soap/GetPrefsRequest', ip='192.168.77.20', origin='internal')
        self.assertFalse(self.ev.block_evidence(self.spec())['ok'])

    def test_bundle_uses_it(self):
        self.event('mail.example.com', '/service/soap/SaveDraftRequest')
        import json
        r = self.ev.check({'op': 'bundle', 'kind': 'bundle', 'rule_id': None, 'spec': json.dumps(
            {'ops': [{'op': 'add', 'kind': 'confident_block', 'spec': self.spec(), 'rule_id': 10500}]})})
        self.assertFalse(r['ok'])


if __name__ == '__main__':
    unittest.main()
