"""A second range for confident blocks (0.5.44): a protection set takes one id per rule and site, and the first range
(97 ids) ran out on a host with Nextcloud and three Zimbra site names. New ids go on in the second range; both count
as confident everywhere a rule id is judged."""
import copy
import unittest
from unittest import mock

from jtwafmgr import config as config_mod
from jtwafmgr.app import App
from jtwafmgr.collector.auditlog import Parser
from tests.helpers import TempEnv


class TestSecondRange(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def test_ids_go_on_in_the_second_range(self):
        m = self.app.workflow.managed
        lo, hi = self.env.cfg['waf']['confident_range']
        with mock.patch.object(type(m), 'occupied_ids', return_value=set(range(lo, hi + 1))):
            self.assertEqual(m.next_rule_id('confident_block'), 11000)
        with mock.patch.object(type(m), 'occupied_ids', return_value=set(range(lo, hi + 1)) | {11000, 11001}):
            self.assertEqual(m.next_rule_id('confident_block'), 11002)
        with mock.patch.object(type(m), 'occupied_ids', return_value={lo + 3}):
            self.assertEqual(m.next_rule_id('confident_block'), lo + 4)        # the first range while it has room

    def test_full_when_both_are(self):
        m = self.app.workflow.managed
        lo, hi = self.env.cfg['waf']['confident_range']
        with mock.patch.object(type(m), 'occupied_ids', return_value=set(range(lo, hi + 1)) | {12999}):
            with self.assertRaises(ValueError):
                m.next_rule_id('confident_block')
        self.env.cfg.data['waf']['confident_range2'] = []
        with mock.patch.object(type(m), 'occupied_ids', return_value=set(range(lo, hi + 1))):
            with self.assertRaises(ValueError):
                m.next_rule_id('confident_block')

    def test_other_kinds_keep_their_range(self):
        m = self.app.workflow.managed
        lo, hi = self.env.cfg['waf']['exclusion_range']
        with mock.patch.object(type(m), 'occupied_ids', return_value=set(range(lo, hi + 1))):
            with self.assertRaises(ValueError):
                m.next_rule_id('exclusion')

    def test_judged_confident(self):
        cfg = self.env.cfg
        self.assertTrue(config_mod.is_confident(cfg, 10250))
        self.assertTrue(config_mod.is_confident(cfg, 11500))
        self.assertFalse(config_mod.is_confident(cfg, 10450))         # CrowdSec
        self.assertFalse(config_mod.is_confident(cfg, 13000))
        self.assertEqual(Parser(cfg).confident[1], (11000, 12999))

    def test_config_checks_the_range(self):
        data = copy.deepcopy(self.env.cfg.data)
        for bad in ([10450, 10460], [10250, 11000], [20000, 20010], [12000, 11000]):
            data2 = dict(data, waf=dict(data['waf'], confident_range2=bad))
            with self.assertRaises(config_mod.ConfigError, msg=bad):
                config_mod.Config(data2)
        config_mod.Config(dict(data, waf=dict(data['waf'], confident_range2=[])))


if __name__ == '__main__':
    unittest.main()
