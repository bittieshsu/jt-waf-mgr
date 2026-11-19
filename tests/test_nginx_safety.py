"""0.5.1: the way back from an nginx update (roll back, another module), the backup to keep, and nginx security
updates applied by themselves (off by default, a one-time code to switch on). Synthetic data only."""
import gzip
import io
import json
import os
import tarfile
import time
import unittest

from jtwafmgr import auth, nginxbackup, nginxswap, nginxup
from tests.helpers import TempEnv

OLD, NEW = '1.30.6-1~bookworm', '1.30.7-1~bookworm'


class Req:
    def __init__(self, body=None, user=None):
        self._b = body or {}
        self.user = user or {'username': 'boss', 'role': 'admin'}
        self.client_ip = '192.0.2.10'
        self.params = {}

    def body(self):
        return self._b


class Base(unittest.TestCase):
    def setUp(self):
        from jtwafmgr.app import App
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.app = App(self.env.cfg, start_collector=False)
        self.wf = self.app.workflow
        self.wf.setting = lambda k, _s=self.wf.setting: (['https://app.example.com/'] if k == 'health.urls' else _s(k))
        saved = nginxswap.trusted_modules
        self.addCleanup(setattr, nginxswap, 'trusted_modules', saved)
        self.trusted = {'a' * 64}
        nginxswap.trusted_modules = lambda path=None: self.trusted

    def applied_update(self):
        now = time.time()
        spec = {'mode': 'update', 'package': 'nginx', 'installed': OLD, 'target': NEW, 'module_sha256': 'b' * 64}
        cid = self.app.db.x("INSERT INTO changes(op, kind, spec, direction, state, reason, proposed_by, created_at, updated_at) "
                            "VALUES ('nginx','system',?,'neutral','applied','r','nginxup',?,?)", (json.dumps(spec), now, now)).lastrowid
        nginxup._write_status(self.env.cfg, {'state': 'current', 'installed': NEW, 'package': 'nginx'})
        return cid


class TestRollbackAndModule(Base):
    def test_rollback_proposal(self):
        from jtwafmgr.changes import ChangeError
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_nginx_rollback('broke a site', 'boss', role='admin')
        self.assertEqual(cm.exception.code, 'nothing_to_roll_back')
        upd = self.applied_update()
        with self.assertRaises(ChangeError):
            self.wf.propose_nginx_rollback('broke a site', 'boss', role='approver')      # an administrator only
        wb = self.wf.nginx_way_back()
        self.assertEqual((wb['change_id'], wb['installed_by_it'], wb['back_to'], wb['matches']), (upd, NEW, OLD, True))
        cid = self.wf.propose_nginx_rollback('broke a site', 'boss', role='admin')
        r = self.wf.get(cid)
        spec = json.loads(r['spec'])
        self.assertEqual((spec['mode'], spec['from_change'], spec['installed'], spec['target']), ('rollback', upd, NEW, OLD))
        self.wf._nginx_checks(cid, r)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval')
        self.assertEqual(self.wf.approval_needs(self.wf.get(cid), 'boss'), {'totp': True, 'note_min': 4})
        # the request carries only the change to undo: root finds the files itself
        self.wf._send_nginx(cid, self.wf.get(cid))
        with open(os.path.join(self.env.cfg['managed']['spool'], 'nginx-c%d.req' % cid)) as fh:
            req = json.load(fh)
        self.assertEqual((req['mode'], req['from_change']), ('rollback', upd))
        self.assertNotIn('module_sha256', req)
        nginxswap.check_request(req)

    def test_nginx_changed_since(self):
        from jtwafmgr.changes import ChangeError
        self.applied_update()
        nginxup._write_status(self.env.cfg, {'state': 'current', 'installed': '1.30.8-1~bookworm'})
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_nginx_rollback('broke a site', 'boss', role='admin')
        self.assertEqual(cm.exception.code, 'nginx_changed_since')

    def test_module_switch(self):
        from jtwafmgr.changes import ChangeError
        nginxup._write_status(self.env.cfg, {'state': 'current', 'installed': NEW, 'package': 'nginx'})
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_nginx_module('c' * 64, 'libmodsecurity 3.0.9 build', 'boss', role='admin')
        self.assertEqual(cm.exception.code, 'module_not_trusted')
        cid = self.wf.propose_nginx_module('A' * 64, 'libmodsecurity 3.0.9 build', 'boss', role='admin')
        spec = json.loads(self.wf.get(cid)['spec'])
        self.assertEqual((spec['mode'], spec['installed'], spec['target'], spec['module_sha256']), ('module', NEW, NEW, 'a' * 64))
        with self.assertRaises(ChangeError) as cm:          # one nginx change at a time
            self.wf.propose_nginx_module('a' * 64, 'again', 'boss', role='admin')
        self.assertEqual(cm.exception.code, 'nginx_change_pending')


class TestAutoUpdate(Base):
    def ready(self):
        d = nginxup.module_dir(self.env.cfg, NEW)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, nginxup.MODULE_NAME), 'wb') as fh:
            fh.write(b'\x7fELF module')
        sha = nginxup.sha256_file(os.path.join(d, nginxup.MODULE_NAME))
        nginxup._write_status(self.env.cfg, {'state': 'ready', 'mode': 'update', 'package': 'nginx', 'installed': OLD,
                                             'candidate': NEW, 'target': NEW, 'module_sha256': sha, 'package_sha256': 'c' * 64})

    def test_off_by_default_waits_for_a_person(self):
        self.ready()
        self.assertFalse(self.env.cfg['nginxup']['auto_update'])
        cid = self.wf.propose_nginx('advisory', 'nginxup', role='admin', auto=True)
        self.wf._nginx_checks(cid, self.wf.get(cid))
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval')

    def test_on_applies_by_itself(self):
        self.ready()
        self.env.cfg.data['nginxup']['auto_update'] = True
        cid = self.wf.propose_nginx('advisory', 'nginxup', role='admin', auto=True)
        self.wf._nginx_checks(cid, self.wf.get(cid))
        self.assertIn(self.wf.get(cid)['state'], ('approved', 'applying'))
        self.assertTrue(self.app.db.one("SELECT 1 FROM change_log WHERE change_id=? AND action='auto_approved'", (cid,)))
        # a person's proposal (or one without the job's flag) never goes by itself
        self.app.db.x("UPDATE changes SET state='applied' WHERE id=?", (cid,))
        cid2 = self.wf.propose_nginx('by hand', 'boss', role='admin', auto=True)
        self.wf._nginx_checks(cid2, self.wf.get(cid2))
        self.assertEqual(self.wf.get(cid2)['state'], 'pending_approval')

    def test_switching_on_takes_a_code(self):
        from jtwafmgr.web import api
        from jtwafmgr.web.server import ApiError
        self.app.auth.create_user('boss', 'admin', password='a long test password')
        sec, _ = self.app.auth.totp_setup('boss')
        self.app.auth.totp_enable('boss', auth.totp_code(sec, int(time.time() // 30) - 1))
        with self.assertRaises(ApiError) as cm:
            api.ui_settings_patch(self.app, Req({'nginxup.auto_update': True}))
        self.assertEqual(cm.exception.code, 'totp_required')
        self.assertFalse(self.app.cfg['nginxup']['auto_update'])
        r = api.ui_settings_patch(self.app, Req({'nginxup.auto_update': True, 'totp': auth.totp_code(sec, int(time.time() // 30))}))
        self.assertIn('nginxup.auto_update', json.loads(r.body)['changed'])
        self.assertTrue(self.app.cfg['nginxup']['auto_update'])
        r = api.ui_settings_patch(self.app, Req({'nginxup.auto_update': False}))      # off again: no code needed
        self.assertFalse(self.app.cfg['nginxup']['auto_update'])


class TestBackup(Base):
    def test_archive_leaves_keys_out(self):
        import shutil
        d = os.path.join(self.env.dir, 'nginx-copy')         # a copy of the fixture: the fixture itself stays as it is
        shutil.copytree(os.path.dirname(self.env.cfg['paths']['nginx_conf']), d)
        conf = os.path.join(d, 'nginx.conf')
        self.env.cfg.data['paths']['nginx_conf'] = conf
        os.makedirs(os.path.join(d, 'ssl'), exist_ok=True)
        files = {'ssl/site.key': b'secret', 'ssl/bundle.pem': ('-----BEGIN ' + 'PRIVATE KEY-----\nx\n').encode(),
                 'ssl/cert.pem': b'-----BEGIN CERTIFICATE-----\nx\n', '.htpasswd': b'u:x'}
        for n, b in files.items():
            with open(os.path.join(d, n), 'wb') as fh:
                fh.write(b)
        path, info = nginxbackup.build(self.env.cfg, {'package': 'nginx', 'installed': NEW, 'held': True})
        self.addCleanup(os.unlink, path)
        with tarfile.open(path) as tar:
            names = tar.getnames()
            restore = tar.extractfile('RESTORE.txt').read().decode()
            manifest = tar.extractfile('MANIFEST.sha256').read().decode()
        self.assertIn('nginx/ssl/cert.pem', names)
        for n in ('ssl/site.key', 'ssl/bundle.pem', '.htpasswd'):
            self.assertNotIn('nginx/' + n, names)
            self.assertIn(n, restore)                    # named among what was left out
        self.assertIn('nginx/' + os.path.basename(conf), manifest)
        self.assertIn('nginx 1.30.7-1~bookworm (held)', restore)
        self.assertEqual(restore.count('apt-mark hold nginx'), 3)          # the manual steps in full, in all three languages
        self.assertGreater(info['files'], 0)
        self.assertEqual(info['skipped'], 3)


if __name__ == '__main__':
    unittest.main()


class TestModuleNote(unittest.TestCase):
    def test_note_from_module_json(self):
        import tempfile
        from jtwafmgr import cli
        d = tempfile.mkdtemp(prefix='jtwaf-test-note-')
        self.addCleanup(__import__('shutil').rmtree, d, True)
        so = os.path.join(d, 'ngx_http_modsecurity_module.so')
        open(so, 'wb').close()
        self.assertEqual(cli._module_note(so, 'a' * 64), 'ngx_http_modsecurity_module.so')        # no description
        with open(os.path.join(d, 'module.json'), 'w') as fh:
            json.dump({'sha256': 'A' * 64, 'nginx_package': NEW, 'libmodsecurity': 'libmodsecurity3=3.0.9', 'os': 'debian-12'}, fh)
        self.assertEqual(cli._module_note(so, 'a' * 64), 'nginx 1.30.7-1~bookworm / libmodsecurity3 3.0.9 / debian-12')
        self.assertEqual(cli._module_note(so, 'b' * 64), 'ngx_http_modsecurity_module.so')        # describes another file
