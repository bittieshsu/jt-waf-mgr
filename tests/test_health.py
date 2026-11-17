"""GET /api/v1/health (health.py): what a monitoring system sees. Synthetic data only."""
import os
import tempfile
import unittest

from jtwafmgr import health
from jtwafmgr.app import App
from tests.helpers import TempEnv


class TestHealth(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.app = App(self.env.cfg)
        self.addCleanup(self.app.stop)

    def by_name(self, out):
        return {c['name']: c for c in out['checks']}

    def test_nginx_pid(self):
        d = tempfile.mkdtemp(dir=self.env.dir)
        pf = os.path.join(d, 'nginx.pid')
        self.assertFalse(health.nginx_running(pf))                    # no pid file: not running
        with open(pf, 'w') as fh:
            fh.write('%d\n' % os.getpid())                              # a live process, but not nginx
        self.assertFalse(health.nginx_running(pf))
        with open(pf, 'w') as fh:
            fh.write('x')
        self.assertIsNone(health.nginx_running(pf))                  # not a pid: cannot tell

    def test_overall_status_is_the_worst_check(self):
        orig = health.CHECKS
        self.addCleanup(setattr, health, 'CHECKS', orig)
        health.CHECKS = (lambda app: health._check('a', 'ok'), lambda app: health._check('b', 'warning', 'x'))
        out = health.health(self.app)
        self.assertEqual((out['status'], out['problems']), ('warning', ['b']))

        def _boom(app):
            raise RuntimeError('x')
        health.CHECKS = (lambda app: health._check('a', 'critical'), _boom)
        out = health.health(self.app)
        self.assertEqual(out['status'], 'critical')
        self.assertEqual(self.by_name(out)['boom']['status'], 'warning')     # a check that cannot run: warning

    def test_checks_on_the_fixture(self):
        out = self.by_name(health.health(self.app))
        for name in ('nginx', 'modsecurity', 'managed_rules', 'last_apply', 'collector', 'ip_blocks',
                     'program_integrity', 'audit_chain', 'config_changes', 'analyst'):
            self.assertIn(name, out)
        self.assertEqual(out['managed_rules']['status'], 'ok')          # not adopted: read-only mode
        self.assertEqual(out['ip_blocks']['status'], 'ok')
        self.app.db.x("INSERT INTO config_snapshots(ts, digest, cause, files) VALUES (strftime('%s','now'), 'd', 'outside', '{}')")
        self.assertEqual(self.by_name(health.health(self.app))['config_changes']['status'], 'warning')

    def test_detection_only_engine_with_rules_that_switch_blocking_on(self):
        from types import SimpleNamespace as NS
        m = NS(rules=[NS(actions=[('id', '10205'), ('ctl', 'ruleEngine=On'), ('deny', '')])], crs_status=lambda: {
            'engine_mode': 'DetectionOnly', 'rule_count': 600, 'version': '4.30.0'})
        orig = self.app.site.load
        self.addCleanup(setattr, self.app.site, 'load', orig)
        self.app.site.load = lambda: (None, m)
        c = health._modsecurity(self.app)
        self.assertEqual((c['status'], c['blocking_rules']), ('ok', 1))
        m.rules = [NS(actions=[('id', '10150'), ('ctl', 'ruleRemoveById=942100')])]
        self.assertEqual(health._modsecurity(self.app)['status'], 'warning')

    def test_analyst_two_failures(self):
        self.app.cfg['analyst']['enabled'] = True
        for err in ('http_502: x', 'http_502: y'):
            self.app.db.x("INSERT INTO analyst_runs(node_id, started_at, finished_at, trigger, window_hours, model, error) "
                          "VALUES ('n', 1, 2, 'timer', 1, 'm', ?)", (err,))
        self.assertEqual(self.by_name(health.health(self.app))['analyst']['status'], 'warning')
        self.app.db.x("INSERT INTO analyst_runs(node_id, started_at, finished_at, trigger, window_hours, model) "
                      "VALUES ('n', 3, 4, 'timer', 1, 'm')")
        self.assertEqual(self.by_name(health.health(self.app))['analyst']['status'], 'ok')


if __name__ == '__main__':
    unittest.main()
