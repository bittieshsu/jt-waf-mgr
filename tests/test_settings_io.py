"""Settings export and import (settings_io.py and its API)."""
import json
import time
import unittest

from jtwafmgr import auth, settings_io
from jtwafmgr.app import App
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv
from tests.test_api import PW, Client


class TestSettingsIo(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.app.stop()
        self.env.cleanup()

    def test_export_leaves_secrets_out_unless_asked(self):
        from jtwafmgr import uisettings
        uisettings.set_many(self.app, {'llm.url': 'http://198.51.100.5:8080/v1', 'llm.api_key': 'sk-test-1234567890'}, 'alice')
        d = settings_io.export(self.app)
        self.assertEqual(d['format'], settings_io.FORMAT)
        self.assertNotIn('llm.api_key', d['settings'])
        self.assertTrue(d['secrets_set']['llm.api_key'])
        self.assertNotIn('sk-test', json.dumps(d))
        self.assertIn('sandbox.required', d['workflow'])
        d2 = settings_io.export(self.app, secrets=True)
        self.assertEqual(d2['settings']['llm.api_key'], 'sk-test-1234567890')
        self.assertTrue(d2['with_secrets'])
        # the preview never compares a secret with the file: a right guess and a wrong one look the same
        for guess in ('sk-test-1234567890', 'sk-wrong-000000000'):
            d2['settings']['llm.api_key'] = guess
            it = next(i for i in settings_io.preview(self.app, d2)['items'] if i['key'] == 'llm.api_key')
            self.assertEqual((it['same'], it['current'], it['incoming']), (False, '(set)', '(set)'))

    def test_preview_and_partial_import(self):
        d = settings_io.export(self.app)
        d['settings']['review.keep_days'] = 30
        d['settings']['traffic.keep_days'] = 40
        d['settings']['no.such_setting'] = 1
        d['settings']['review.interval_hours'] = 'x'
        d['workflow']['apply.auto_tighten_daily_limit'] = 5
        pv = settings_io.preview(self.app, d)
        by = {(i['area'], i['key']): i for i in pv['items']}
        self.assertFalse(by[('settings', 'review.keep_days')]['same'])
        self.assertTrue(by[('settings', 'geoip.enabled')]['same'])
        self.assertFalse(by[('settings', 'no.such_setting')]['known'])
        self.assertFalse(by[('settings', 'review.interval_hours')]['valid'])
        # only what is picked is written
        done = settings_io.apply(self.app, d, ['settings:review.keep_days', 'workflow:apply.auto_tighten_daily_limit'], 'alice')
        self.assertEqual(done, {'settings': ['review.keep_days'], 'workflow': ['apply.auto_tighten_daily_limit']})
        self.assertEqual(self.app.cfg['review']['keep_days'], 30)
        self.assertNotEqual(self.app.cfg['traffic']['keep_days'], 40)
        self.assertEqual(self.app.workflow.setting('apply.auto_tighten_daily_limit'), 5)
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='settings.imported'"))
        # all or nothing: one bad value and nothing is written
        d['settings']['review.keep_days'] = 60
        with self.assertRaises(settings_io.ImportError_):
            settings_io.apply(self.app, d, ['review.keep_days', 'review.interval_hours'], 'alice')
        self.assertEqual(self.app.cfg['review']['keep_days'], 30)
        with self.assertRaises(settings_io.ImportError_):
            settings_io.apply(self.app, d, ['no.such_setting'], 'alice')
        with self.assertRaises(settings_io.ImportError_):
            settings_io.parse('{"format": "something else"}')


class TestSettingsIoApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = TempEnv()
        cls.app = App(cls.env.cfg)
        a = cls.app.auth
        a.create_user('admin1', 'admin', password=PW)
        a.create_user('viewer1', 'viewer', password=PW)
        cls.secret, _ = a.totp_setup('admin1')
        a.totp_enable('admin1', auth.totp_code(cls.secret, int(time.time() // 30)))
        cls.srv, _ = start_background(cls.app)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.app.stop()
        cls.env.cleanup()

    def admin(self):
        self.app.db.x("UPDATE users SET totp_last_step=0 WHERE username='admin1'")
        c = Client(self.port)
        st, obj = c.login('admin1', totp=auth.totp_code(self.secret, int(time.time() // 30)))
        self.assertEqual(st, 200, obj)
        self.app.db.x("UPDATE users SET totp_last_step=0 WHERE username='admin1'")
        return c

    def test_flow(self):
        v = Client(self.port)
        v.login('viewer1')
        self.assertEqual(v.req('POST', '/api/v1/settings/export', {})[0], 403)
        c = self.admin()
        st, d, _ = c.req('POST', '/api/v1/settings/export', {})
        self.assertEqual(st, 200)
        self.assertEqual(c.req('POST', '/api/v1/settings/export', {'secrets': True, 'totp': '000000'})[0], 403)
        d['settings']['review.keep_days'] = 21
        st, pv, _ = c.req('POST', '/api/v1/settings/import/preview', {'file': d})
        self.assertEqual(st, 200)
        self.assertTrue(any(i['key'] == 'review.keep_days' and not i['same'] for i in pv['items']))
        self.assertEqual(c.req('POST', '/api/v1/settings/import', {'file': d, 'keys': ['review.keep_days'], 'totp': ''})[0], 403)
        st, r, _ = c.req('POST', '/api/v1/settings/import', {'file': d, 'keys': ['review.keep_days'],
                                                           'totp': auth.totp_code(self.secret, int(time.time() // 30))})
        self.assertEqual((st, r['changed']['settings']), (200, ['review.keep_days']))
        self.assertEqual(self.app.cfg['review']['keep_days'], 21)


if __name__ == '__main__':
    unittest.main()
