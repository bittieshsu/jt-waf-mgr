"""0.5.37: a host adopted without a site rule file had no rule turning tx.jt_block into the critical anomaly score, so
its confident blocks only logged (revproxy2's first protection set: every attack request answered 200 in the
sandbox). The managed before file carries that system rule when no item has its id; one a person deleted stays out."""
import unittest

from jtwafmgr.managed import Managed

CB = {'placement': 'before', 'position': 1, 'kind': 'confident_block', 'rule_id': 10200, 'enabled': 1,
      'text': 'SecRule REQUEST_FILENAME "@rx ^/x$" "id:10200,phase:1,pass,setvar:tx.jt_block=1"'}


class TestScoreRule(unittest.TestCase):
    def test_written_when_missing(self):
        f = Managed.render([CB], 1, score_rule=10298)
        self.assertIn('SecRule TX:JT_BLOCK "@eq 1"', f['before'])
        self.assertIn("id:10298,phase:2", f['before'])
        self.assertLess(f['before'].index('id:10200'), f['before'].index('id:10298'))     # after the blocks
        self.assertNotIn('id:10298', f['after'])

    def test_not_twice_and_not_against_a_person(self):
        own = dict(CB, rule_id=10298, position=2, kind='raw', text='SecRule TX:JT_BLOCK "@eq 1" "id:10298,phase:2,pass"')
        self.assertEqual(Managed.render([CB, own], 1, score_rule=10298)['before'].count('id:10298'), 1)
        self.assertNotIn('id:10298', Managed.render([CB, dict(own, deleted=1)], 1, score_rule=10298)['before'])

    def test_site_rules_acting_on_the_mark(self):
        deny = dict(CB, rule_id=10299, position=3, kind='raw',
                    text='SecRule TX:JT_BLOCK "@eq 1" "id:10299,phase:2,deny,status:403,log"')
        self.assertNotIn('id:10298', Managed.render([CB, deny], 1, score_rule=10298)['before'])

    def test_nothing_to_score(self):
        self.assertNotIn('id:10298', Managed.render([], 1, score_rule=10298)['before'])
        self.assertNotIn('id:10298', Managed.render([dict(CB, kind='exclusion')], 1, score_rule=10298)['before'])
        self.assertNotIn('id:10298', Managed.render([CB], 1)['before'])          # no id given: as before


if __name__ == '__main__':
    unittest.main()
