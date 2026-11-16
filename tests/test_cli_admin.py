"""Administration from the command line (cli_admin.py): the same rules as the web interface, the person named."""
import contextlib
import io
import json
import os
import tempfile
import unittest

from jtwafmgr import cli
from jtwafmgr.app import App
from tests.helpers import TempEnv


class TestCliAdmin(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.conf = os.path.join(self.env.dir, 'config.toml')
        with open(self.conf, 'w') as fh:
            fh.write('[paths]\ndb = "%s"\naudit_log = "%s"\nnginx_conf = "%s"\n[syslog]\nenabled = false\n'
                     '[integrity]\nanchor_file = "%s"\n[backup]\ndir = "%s"\n[managed]\napply_state = "%s"\n'
                     '[blocks]\nenabled = true\nfile = "%s"\n[auth]\npassword_min_classes = 0\n'
                     % (self.env.cfg['paths']['db'], self.env.audit_log, self.env.cfg['paths']['nginx_conf'],
                        os.path.join(self.env.dir, 'a.jsonl'), os.path.join(self.env.dir, 'b'),
                        os.path.join(self.env.dir, 'st'), os.path.join(self.env.dir, 'blocked-ips.conf')))
        app = App(self.env.cfg)
        app.auth.create_user('alice', 'approver', password='a long test password')
        app.auth.create_user('vic', 'viewer', password='a long test password')
        app.auth.create_user('root1', 'admin', password='a long test password')
        app.stop()

    def tearDown(self):
        self.env.cleanup()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(['--config', self.conf] + list(args))
        return rc, out.getvalue(), err.getvalue()

    def test_blocks(self):
        rc, _, err = self.run_cli('blocks', 'add', '203.0.113.44', '--reason', 'probe')
        self.assertEqual(rc, 1)
        self.assertIn('--as USER', err)                              # a write names a person
        self.assertEqual(self.run_cli('blocks', 'add', '203.0.113.44', '--reason', 'probe', '--as', 'vic')[0], 1)   # a viewer cannot
        rc, out, err = self.run_cli('blocks', 'add', '203.0.113.44', '--reason', 'probe', '--ttl', '2h', '--as', 'alice')
        self.assertEqual(rc, 0, err)
        bid = json.loads(out)['id']
        rc, out, _ = self.run_cli('blocks', 'list', '--json')
        self.assertIn('203.0.113.44', [i['ip'] for i in json.loads(out)])
        rc, out, err = self.run_cli('blocks', 'extend', str(bid), '--ttl', '3d', '--reason', 'still probing', '--as', 'alice')
        self.assertEqual(rc, 0, err)
        rc, out, err = self.run_cli('blocks', 'remove', str(bid), '--note', 'done', '--as', 'alice')
        self.assertEqual((rc, out.strip()), (0, 'removed 1'), err)
        app = App(self.env.cfg)
        try:
            r = app.db.one("SELECT actor, src_ip FROM audit WHERE action='block.add' ORDER BY id DESC LIMIT 1")
            self.assertEqual((r['actor'], r['src_ip']), ('alice', 'cli'))
        finally:
            app.stop()

    def test_alerts_changes_tokens(self):
        app = App(self.env.cfg)
        try:
            from jtwafmgr import alerts
            aid = alerts.raise_alert(app.db, app.audit, 'test', 'other', 'warning', 'cli-test', {'reason': 'x'}, notify=False)
        finally:
            app.stop()
        rc, out, _ = self.run_cli('alerts', 'list', '--json')
        self.assertIn(aid, [a['id'] for a in json.loads(out)])
        rc, out, err = self.run_cli('alerts', 'handle', str(aid), '--note', 'checked', '--as', 'alice')
        self.assertEqual((rc, json.loads(out)['state']), (0, 'handled'), err)
        rc, out, _ = self.run_cli('changes', 'list')
        self.assertEqual(rc, 0)
        self.assertEqual(self.run_cli('changes', 'approve', '999', '--as', 'alice')[0], 1)
        self.assertEqual(self.run_cli('tokens', 'list')[0], 0)

    def test_settings(self):
        rc, out, _ = self.run_cli('settings', 'show', 'review.')
        self.assertEqual(rc, 0)
        self.assertIn('review.keep_days', out)
        self.assertEqual(self.run_cli('settings', 'set', 'review.keep_days=45', '--as', 'alice')[0], 1)   # admin only
        rc, out, err = self.run_cli('settings', 'set', 'review.keep_days=45', 'workflow.apply.auto_tighten_daily_limit=4', '--as', 'root1')
        self.assertEqual(rc, 0, err)
        # the settings never go to the terminal: export needs a file
        for extra in ((), ('--secrets', '--as', 'root1')):
            rc, out, err = self.run_cli('settings', 'export', *extra)
            self.assertEqual(rc, 1)
            self.assertIn('-o FILE', err + out)
            self.assertNotIn('review.keep_days', out)
        f = os.path.join(self.env.dir, 'settings.json')
        rc, out, _ = self.run_cli('settings', 'export', '-o', f)
        self.assertEqual(oct(os.stat(f).st_mode & 0o777), '0o600')
        with open(f) as fh:
            d = json.load(fh)
        self.assertEqual(d['settings']['review.keep_days'], 45)
        d['settings']['review.keep_days'] = 50
        d['settings']['traffic.keep_days'] = 70
        with open(f, 'w') as fh:
            json.dump(d, fh)
        rc, out, _ = self.run_cli('settings', 'import', f, '--only', 'review', '--dry-run')
        self.assertIn('1 setting(s) would be written', out)
        rc, out, err = self.run_cli('settings', 'import', f, '--only', 'review', '--as', 'root1')
        self.assertEqual(rc, 0, err)
        app = App(self.env.cfg)
        try:
            from jtwafmgr import uisettings
            uisettings.apply(app.cfg, app.db)
            self.assertEqual((app.cfg['review']['keep_days'], app.cfg['traffic']['keep_days'] != 70), (50, True))
            self.assertEqual(app.workflow.setting('apply.auto_tighten_daily_limit'), 4)
        finally:
            app.stop()


class TestServiceCanRead(unittest.TestCase):
    """jt-waf-mgr check: the command line runs without the service's extra groups; readability is judged by them."""

    def test_by_the_groups_the_service_gets(self):
        import grp
        from unittest import mock
        from jtwafmgr.cli import _service_can_read
        with tempfile.TemporaryDirectory() as d:
            logs = os.path.join(d, 'logs')
            os.mkdir(logs, 0o750)
            f = os.path.join(logs, 'audit.log')
            open(f, 'w').close()
            os.chmod(f, 0o640)
            group = grp.getgrgid(os.stat(f).st_gid).gr_name
            dropins = os.path.join(d, 'jt-waf-mgr.service.d')
            os.mkdir(dropins)
            with open(os.path.join(dropins, '10-log-group.conf'), 'w') as fh:
                fh.write('[Service]\nSupplementaryGroups=%s\n' % group)
            os.chmod(d, 0o755)
            with mock.patch('jtwafmgr.cli.os.access', return_value=False):
                self.assertTrue(_service_can_read(f, dropins))
                with open(os.path.join(dropins, '10-log-group.conf'), 'w') as fh:
                    fh.write('[Service]\n')
                self.assertFalse(_service_can_read(f, dropins))
                os.chmod(f, 0o644)
                os.chmod(logs, 0o755)
                self.assertTrue(_service_can_read(f, dropins))       # readable by all
                os.chmod(logs, 0o700)
                self.assertFalse(_service_can_read(f, dropins))      # but the directory is closed
                # a directory only the service's group opens: the file's own permissions cannot be seen from here
                # (here: a mocked stat), so the service having read the file lately answers
                real_stat = os.stat

                def hidden(p, *a, **k):
                    if p == f:
                        raise PermissionError(13, 'denied')
                    return real_stat(p, *a, **k)
                os.chmod(logs, 0o750)
                with open(os.path.join(dropins, '10-log-group.conf'), 'w') as fh:
                    fh.write('[Service]\nSupplementaryGroups=%s\n' % group)
                with mock.patch('jtwafmgr.cli.os.stat', side_effect=hidden):
                    import time
                    self.assertTrue(_service_can_read(f, dropins, last_read=time.time() - 60))
                    self.assertIsNone(_service_can_read(f, dropins, last_read=None))     # cannot tell: no problem raised


if __name__ == '__main__':
    unittest.main()
