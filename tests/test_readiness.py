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
        self.assertEqual((hub['link'], hub['hash']), ('/admin/settings', '#uiset-hub'))

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


if __name__ == '__main__':
    unittest.main()
