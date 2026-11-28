"""0.5.48: the CRS score refusing outside requests -- told from the decision model, proposed as one change, with the
Synology Photos false positive excluded for DSM sites (scoreblock.py)."""
import json
import os
import re
import shutil
import unittest

from jtwafmgr import protsets, reasons, scoreblock, software
from jtwafmgr.app import App
from tests.helpers import FIXTURE_SITE, TempEnv
from tests.test_protsets import TestFlow


def site_without_score_rule(d):
    """The fixture site as a fresh adoption leaves it: no rule turning the CRS score into a refusal (10297)."""
    site = os.path.join(d, 'site-noscore')
    shutil.copytree(FIXTURE_SITE, site, symlinks=True)
    p = os.path.join(site, 'modsec', 'local-after-crs.conf')
    with open(p, encoding='utf-8') as fh:
        text = fh.read()
    text = re.sub(r'# External over the threshold.*?ctl:ruleEngine=On"\n', '', text, flags=re.S)
    assert '10297' not in text
    with open(p, 'w', encoding='utf-8') as fh:
        fh.write(text)
    return os.path.join(site, 'nginx.conf')


class TestDetect(unittest.TestCase):
    def test_fixture_refuses_outside(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        app = App(env.cfg)
        self.addCleanup(app.db.release)
        scoreblock._cache['m'] = None
        self.assertTrue(scoreblock.external_blocks(app))
        st = scoreblock.status(app)
        self.assertTrue(st['blocks'])
        self.assertFalse(st['can_propose'])
        with self.assertRaises(scoreblock.ScoreBlockError) as e:
            scoreblock.propose(app, 'alice', role='admin')
        self.assertEqual(e.exception.code, 'already_blocks')

    def test_without_the_rule_only_logs(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        env.cfg['paths']['nginx_conf'] = site_without_score_rule(env.dir)
        app = App(env.cfg)
        self.addCleanup(app.db.release)
        scoreblock._cache['m'] = None
        self.assertFalse(scoreblock.external_blocks(app))
        st = scoreblock.status(app)
        self.assertEqual(st['rule_id'], 10297)
        self.assertTrue(st['can_propose'])


class TestPropose(TestFlow):
    """Adopted from the fixture site without its score rule (a fresh ModSecurity)."""

    def site_conf(self):
        import tempfile
        d = tempfile.mkdtemp(prefix='jtwaf-test-site-')
        self.addCleanup(shutil.rmtree, d, True)
        return site_without_score_rule(d)

    def use_noscore_site(self):
        scoreblock._cache['m'] = None

    def test_status_and_propose(self):      # (the inherited protection set test: it runs on the fixture site)
        pass

    def test_propose_plain(self):
        self.use_noscore_site()
        cid = scoreblock.propose(self.app, 'boss', role='admin')
        ch = self.wf.get(cid)
        self.assertEqual(ch['op'], 'bundle')
        self.assertEqual(ch['direction'], 'tighten')
        ops = json.loads(ch['spec'])['ops']
        self.assertEqual([o['kind'] for o in ops], ['raw'])
        text = ops[0]['spec']['text']
        self.assertIn('id:10297', text)
        self.assertIn('TX:BLOCKING_INBOUND_ANOMALY_SCORE', text)
        self.assertIn('ctl:ruleEngine=On', text)
        self.assertIn("tag:'jt-score-block'", text)
        tests = json.loads(ch['tests'])
        self.assertEqual(sorted(t['expect'] for t in tests), [200, 403, 403])
        self.assertEqual([p['key'] for p in reasons.parse(ch['reason'])], ['scoreblock'])
        self.assertTrue(self.app.db.one("SELECT id FROM audit WHERE action='scoreblock.proposed'"))
        with self.assertRaises(scoreblock.ScoreBlockError) as e:       # one is waiting already
            scoreblock.propose(self.app, 'boss', role='admin')
        self.assertEqual(e.exception.code, 'pending')
        self.assertEqual(scoreblock.status(self.app)['pending'], cid)

    def test_propose_with_synology_photos(self):
        self.use_noscore_site()
        software.save(self.app.db, 'alice', 'Synology DSM', '7.4', hosts=['app.example.com'])
        software.save(self.app.db, 'alice', 'Synology Photos', '', hosts=['app.example.com'])
        # while the CRS only logs, the protection set does not tick the exclusion
        st = [x for x in protsets.status(self.app) if x['id'] == 'synology-dsm'][0]
        excl = [r for r in st['sites'][0]['rules'] if r['id'] == 'photos-ml-labels'][0]
        self.assertEqual(excl['kind'], 'exclusion')
        self.assertFalse(excl['default'])
        self.assertFalse(st['crs_blocks'])
        cid = scoreblock.propose(self.app, 'boss', role='admin')
        ch = self.wf.get(cid)
        self.assertEqual(ch['direction'], 'loosen')          # the exclusion loosens: a one-time code to approve
        ops = json.loads(ch['spec'])['ops']
        self.assertEqual(ops[0]['kind'], 'raw')
        self.assertTrue(all(o['kind'] == 'exclusion' for o in ops[1:]))
        tags = {o['spec']['protset'] for o in ops[1:]}
        self.assertTrue({'synology-dsm/photos-ml-labels', 'synology-dsm/dsm-api-names', 'synology-dsm/dsm-json-data',
                         'synology-dsm/dsm-body-as-form'} <= tags, tags)
        ex = [o['spec'] for o in ops if o['spec'].get('protset') == 'synology-dsm/photos-ml-labels'][0]
        self.assertEqual(ex['protset'], 'synology-dsm/photos-ml-labels')
        self.assertEqual(ex['host'], {'mode': 'exact', 'value': 'app.example.com'})
        self.assertEqual(ex['path'], {'mode': 'exact', 'value': '/webapi/entry.cgi'})
        self.assertEqual(ex['tag'], 'attack-rce')
        self.assertEqual(ex['targets'], ['ARGS:raw_data', 'ARGS:additional'])
        tests = json.loads(ch['tests'])
        self.assertTrue(any(t['host'] == 'app.example.com' and 'raw_data=' in (t.get('body') or '') and t['expect'] == 200
                            for t in tests))
        self.assertTrue(any('cat+%2Fetc%2Fpasswd' in (t.get('body') or '') and t['expect'] == 403 for t in tests))
        self.assertEqual([p['key'] for p in reasons.parse(ch['reason'])], ['scoreblock', 'scoreblock_apps'])
        # the static checks pass (the raw rule tightens, the exclusion is narrow)
        from tests.test_hub_changes import FakeSandbox
        self.wf.sandbox = FakeSandbox()
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval', json.loads(self.wf.get(cid)['checks'] or '{}'))
        # the protection set sees the exclusion waiting in that change
        st = [x for x in protsets.status(self.app) if x['id'] == 'synology-dsm'][0]
        excl = [r for r in st['sites'][0]['rules'] if r['id'] == 'photos-ml-labels'][0]
        self.assertEqual((excl['state'], excl.get('change_id')), ('pending', cid))

    def test_protset_ticks_the_exclusion_when_the_crs_refuses(self):
        scoreblock._cache['m'] = None
        scoreblock._cache['m'], scoreblock._cache['value'] = self.app.site.load()[1], True     # as if it refused
        software.save(self.app.db, 'alice', 'Synology DSM', '7.4', hosts=['app.example.com'])
        software.save(self.app.db, 'alice', 'Synology Photos', '', hosts=['app.example.com'])
        st = [x for x in protsets.status(self.app) if x['id'] == 'synology-dsm'][0]
        self.assertTrue(st['crs_blocks'])
        excl = [r for r in st['sites'][0]['rules'] if r['id'] == 'photos-ml-labels'][0]
        self.assertTrue(excl['default'])
        cid = protsets.propose(self.app, 'synology-dsm', 'app.example.com', ['photos-ml-labels'], 'boss', role='admin')
        ch = self.wf.get(cid)
        self.assertEqual(ch['direction'], 'loosen')
        self.assertEqual([p['key'] for p in reasons.parse(ch['reason'])], ['protset_excl'])


if __name__ == '__main__':
    unittest.main()
