"""The dashboard's list of what is not installed or not turned on yet (jtwafmgr/readiness.py, GET /readiness).
Synthetic data only."""
import os
import tempfile
import unittest

from jtwafmgr import readiness
from jtwafmgr.app import App
from tests.helpers import TempEnv


def keys(items, level=None):
    return [i['key'] for i in items if level is None or i['level'] == level]


class TestReadiness(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.app = App(self.env.cfg)
        self.addCleanup(self.app.stop)

    def test_fresh_settings_name_every_missing_feature(self):
        items = readiness.items(self.app, installed=False)
        self.assertIn('notify_off', keys(items, 'important'))
        self.assertIn('hub_off', keys(items, 'important'))
        for k in ('analyst_off', 'intel_off', 'iprep_off', 'countries_off', 'blocks_off'):
            self.assertIn(k, keys(items, 'suggested'))
        self.assertNotIn('apply_off', keys(items))                    # not installed under systemd: nothing to say
        self.assertNotIn('crs_missing', keys(items))                  # the fixture site loads the CRS
        levels = [i['level'] for i in items]
        self.assertEqual(levels, sorted(levels, key=lambda x: x != 'important'))   # important first
        hub = next(i for i in items if i['key'] == 'hub_off')
        self.assertEqual(hub['link'], '/crowdsec')                    # 0.5.32: turned on on its own page
        self.assertNotIn('single_admin_off', keys(items))             # no approver at all here: not this case

    def test_protection_set_not_applied(self):
        """0.5.34: a DSM site with recommended protection rules not applied: important, with its counts."""
        from jtwafmgr import software
        self.assertNotIn('protset_available', keys(readiness.items(self.app, installed=False)))
        software.save(self.app.db, 'alice', 'Synology DSM', '', hosts=['nas.example.com'])
        it = next(i for i in readiness.items(self.app, installed=False) if i['key'] == 'protset_available')
        self.assertEqual(it['level'], 'important')
        self.assertEqual(it['link'], '/protection')
        self.assertEqual(it['details']['app'], 'Synology DSM')
        self.assertEqual(it['details']['hosts'], 'nas.example.com')
        self.assertGreaterEqual(it['details']['n'], 8)

    def test_turned_on_features_drop_out(self):
        c = self.app.cfg.data
        c['notify']['enabled'] = True
        self.assertIn('notify_off', keys(readiness.items(self.app, installed=False)))   # on, but no channel
        c['notify']['zulip_enabled'] = True
        for sec in ('hub', 'llm', 'analyst', 'intel', 'iprep', 'countries', 'blocks'):
            c[sec]['enabled'] = True
        self.assertEqual(keys(readiness.items(self.app, installed=False)), ['not_adopted']
                         if not self.app.workflow.managed.adopted() else [])

    def test_no_crs_and_no_waf_site(self):
        with tempfile.TemporaryDirectory() as d:
            conf = os.path.join(d, 'nginx.conf')
            with open(conf, 'w') as fh:
                fh.write('http { server { listen 443; server_name a.example.com; } }\n')
            self.app.cfg.data['paths']['nginx_conf'] = conf
            self.app.site._nginx = None
            orig = readiness.APPLY_PATH
            readiness.APPLY_PATH = os.path.join(d, 'jt-waf-mgr-apply.path')    # never the host's own (G10)
            try:
                items = readiness.items(self.app, installed=True)
            finally:
                readiness.APPLY_PATH = orig
        self.assertEqual(keys(items, 'important')[:2], ['crs_missing', 'not_adopted'])
        self.assertIn('no_waf_site', keys(items, 'important'))
        self.assertIn('apply_off', keys(items, 'important'))          # installed, apply path not armed here

    def test_crs_progress_and_single_admin(self):
        import json
        from jtwafmgr import crsupdate
        with tempfile.TemporaryDirectory() as d:
            conf = os.path.join(d, 'nginx.conf')
            with open(conf, 'w') as fh:
                fh.write('http { server { listen 443; server_name a.example.com; } }\n')
            self.app.cfg.data['paths']['nginx_conf'] = conf
            self.app.site._nginx = None
            self.app.cfg.data['crs']['manage'] = True
            os.makedirs(self.app.cfg['crs']['dir'], exist_ok=True)
            with open(crsupdate.status_path(self.app.cfg), 'w') as fh:
                json.dump({'state': 'ready', 'staged': {'version': '4.30.0'}}, fh)
            it = readiness.items(self.app, installed=False)[0]
            self.assertEqual((it['key'], it['details']), ('crs_staged', {'version': '4.30.0'}))
            self.app.db.x("INSERT INTO changes(op, kind, spec, direction, state, proposed_by, created_at, updated_at) "
                          "VALUES ('crs', 'crs', '{}', 'neutral', 'proposed', 'solo', 0, 0)")
            it = readiness.items(self.app, installed=False)[0]
            self.assertEqual(it['key'], 'crs_pending')
            self.assertTrue(it['link'].startswith('/changes/'))
        self.app.auth.create_user('solo', 'admin', password='Solo-Passw0rd-1')
        self.assertIn('single_admin_off', keys(readiness.items(self.app, installed=False), 'important'))
        self.app.workflow.set_setting('approval.single_admin_mode', True, 'test')
        self.assertNotIn('single_admin_off', keys(readiness.items(self.app, installed=False)))


if __name__ == '__main__':
    unittest.main()


class TestScoreBlockReadiness(unittest.TestCase):
    """0.5.48: an adopted host whose CRS score refuses nothing from outside -- named, with the one-click proposal."""

    def test_crs_log_only_named_with_action(self):
        from jtwafmgr import scoreblock
        from tests.test_scoreblock import site_without_score_rule
        env = TempEnv()
        self.addCleanup(env.cleanup)
        env.cfg['paths']['nginx_conf'] = site_without_score_rule(env.dir)
        app = App(env.cfg)
        self.addCleanup(app.stop)
        scoreblock._cache['m'] = None
        app.workflow.managed.adopted = lambda: True          # (adoption itself is tested elsewhere)
        it = next(i for i in readiness.items(app, installed=False) if i['key'] == 'crs_log_only')
        self.assertEqual((it['level'], it['link'], it['action']), ('important', None, 'scoreblock'))

    def test_fixture_refuses_outside_nothing_to_say(self):
        from jtwafmgr import scoreblock
        env = TempEnv()
        self.addCleanup(env.cleanup)
        app = App(env.cfg)
        self.addCleanup(app.stop)
        scoreblock._cache['m'] = None
        app.workflow.managed.adopted = lambda: True
        ks = keys(readiness.items(app, installed=False))
        self.assertNotIn('crs_log_only', ks)
        self.assertNotIn('crs_log_only_pending', ks)
