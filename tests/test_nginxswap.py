"""The root side of an nginx update (nginxswap.py). apt, dpkg, systemctl and the nginx processes are simulated; no
package is downloaded or installed and no process is signalled."""
import hashlib
import json
import os
import shutil
import tempfile
import unittest

from jtwafmgr import nginxswap

PKG, OLD, NEW = 'nginx', '1.30.6-1~bookworm', '1.30.7-1~bookworm'


def sha(b):
    return hashlib.sha256(b).hexdigest()


class FakeApplier:
    def __init__(self, state):
        self.state, self.nginx = state, '/usr/sbin/nginx'

    @staticmethod
    def master_pid():
        return 100

    @staticmethod
    def swap_busy():
        return False

    @staticmethod
    def stored_health_urls():
        return ['https://www.example.com/']


class Fake:
    """apt-cache / dpkg / systemctl / nginx -T answers; records what was run."""

    def __init__(self, t, index, installed=OLD, candidate=NEW, unit=None):
        self.t, self.index, self.installed, self.candidate, self.unit = t, index, installed, candidate, unit
        self.calls = []
        self.depends, self.owner = 'libc6 (>= 2.34), libssl3 (>= 3.0.0)', PKG
        self.dependents = 'ii |nginx|, libc6 (>= 2.34)\nii |certbot|, python3\n'

    def __call__(self, cmd, cwd=None, timeout=300):
        self.calls.append(cmd)
        if cmd[:2] == ['apt-cache', 'policy']:
            return 0, '%s:\n  Installed: %s\n  Candidate: %s\n' % (cmd[2], self.installed, self.candidate)
        if cmd[:2] == ['apt-cache', 'show']:
            v = cmd[2].split('=', 1)[1]
            return (0, 'Package: nginx\nVersion: %s\nArchitecture: amd64\nDepends: %s\nSHA256: %s\n'
                    % (v, self.depends, self.index[v])) if v in self.index else (100, '')
        if cmd[:2] == ['dpkg-query', '-S']:
            return 0, '%s: %s\n' % (self.owner, cmd[2])
        if cmd[:2] == ['dpkg-query', '-W']:
            return (0, 'ii |' + self.installed) if len(cmd) > 3 else (0, self.dependents)
        if cmd[:2] == ['dpkg', '--print-architecture']:
            return 0, 'amd64\n'
        if cmd[0] == 'dpkg-deb':
            os.makedirs(os.path.join(cmd[3], 'usr', 'sbin'))
            open(os.path.join(cmd[3], 'usr', 'sbin', 'nginx'), 'w').close()
            return 0, ''
        if cmd[1:] == ['-V']:
            return 0, 'configure arguments: --prefix=/etc/nginx'
        if cmd[1:] == ['-T']:
            return 0, 'load_module modules/ngx_http_modsecurity_module.so;\n'
        if cmd[:2] == ['systemctl', 'start']:
            return self.unit() if self.unit else (0, '')
        return 0, ''


class Base(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix='jtwaf-test-swap-')
        self.addCleanup(shutil.rmtree, self.t, True)
        saved = (nginxswap._run, nginxswap.module_target, nginxswap.trusted_modules, nginxswap.as_nobody)
        self.addCleanup(lambda: (setattr(nginxswap, '_run', saved[0]), setattr(nginxswap, 'module_target', saved[1]),
                                 setattr(nginxswap, 'trusted_modules', saved[2]), setattr(nginxswap, 'as_nobody', saved[3])))
        self.trusted = set()
        nginxswap.trusted_modules = lambda path=None: self.trusted
        # the re-test as nobody needs root to drop to nobody: here it runs try_module directly
        nginxswap.as_nobody = lambda try_module, nginx_bin, module, work=None: try_module(nginx_bin, module)
        self.job = os.path.join(self.t, 'job')
        self.state = os.path.join(self.t, 'state')
        os.makedirs(os.path.join(self.job, 'modules', NEW))
        os.makedirs(os.path.join(self.job, 'debs'))
        os.makedirs(self.state)
        self.mod = b'\x7fELF new module'
        self.trusted.add(sha(self.mod))
        self.put(os.path.join(self.job, 'modules', NEW, nginxswap.MODULE_NAME), self.mod)
        self.put(os.path.join(nginxswap.store_dir(self.state), sha(self.mod) + '.so'), self.mod)    # root's copy
        self.debs = {NEW: b'new package', OLD: b'old package'}
        for v, b in self.debs.items():
            self.put(os.path.join(self.job, 'debs', 'nginx_%s_amd64.deb' % v), b)
        self.index = {v: sha(b) for v, b in self.debs.items()}
        self.target = os.path.join(self.t, 'modules', nginxswap.MODULE_NAME)
        self.put(self.target, b'\x7fELF old module')
        nginxswap.module_target = lambda nginx_bin: self.target
        self.tried = []

    @staticmethod
    def put(p, b):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'wb') as fh:
            fh.write(b)

    def req(self, **kw):
        r = {'change_id': 7, 'mode': 'update', 'package': PKG, 'version': NEW, 'module_sha256': sha(self.mod),
             'health_urls': ['https://www.example.com/']}
        r.update(kw)
        return r

    def try_module(self, ok=True):
        def f(nginx_bin, module, others=()):
            self.tried.append(nginx_bin)
            return ok, 'detail'
        return f

    def prepare(self, req=None, fake=None, ok=True):
        nginxswap._run = fake or Fake(self.t, self.index)
        return nginxswap.prepare(FakeApplier(self.state), req or self.req(), self.job, self.try_module(ok), [])


class TestPrepare(Base):
    def unit_ok(self):
        def unit():
            base = nginxswap.work_dir(self.state)
            self.request_mode = os.stat(os.path.join(base, 'request.json')).st_mode
            with open(os.path.join(base, 'request.json')) as fh:
                self.plan = json.load(fh)
            with open(os.path.join(base, 'result.json'), 'w') as fh:
                json.dump({'result': 'ok', 'previous': OLD, 'backup': self.plan['work'], 'log': ['swapped']}, fh)
            return 0, ''
        return unit

    def test_everything_checked_then_step_two(self):
        fake = Fake(self.t, self.index, unit=self.unit_ok())
        res = self.prepare(fake=fake)
        self.assertEqual(res['result'], 'ok')
        self.assertTrue(self.tried[0].endswith('/unpacked/usr/sbin/nginx'))         # the new package's nginx
        p = self.plan
        self.assertEqual((p['package'], p['version'], p['previous'], p['target']), (PKG, NEW, OLD, self.target))
        self.assertEqual(p['health_urls'], ['https://www.example.com/'])            # root's own list, not the request's
        for k in ('module', 'new_deb', 'old_deb'):                                   # root's own copies
            self.assertTrue(p[k].startswith(nginxswap.work_dir(self.state)))
            self.assertEqual(os.stat(p[k]).st_mode & 0o777, 0o600)
        self.assertIn(['systemctl', 'start', nginxswap.UNIT], fake.calls)
        self.assertEqual(self.request_mode & 0o777, 0o600)                       # step 2 takes only root's own file
        self.assertFalse(os.path.exists(os.path.join(nginxswap.work_dir(self.state), 'request.json')))

    def assertRefused(self, step, **kw):
        with self.assertRaises(nginxswap.SwapFail) as cm:
            self.prepare(**kw)
        self.assertEqual(cm.exception.step, step, cm.exception.summary)
        return cm.exception.summary

    def test_refusals(self):
        self.assertRefused('preflight', fake=Fake(self.t, self.index, candidate='1.30.8-1~bookworm'))   # apt moved on
        self.assertRefused('trust', req=self.req(module_sha256='a' * 64))           # a hash root never trusted
        self.trusted.add('a' * 64)
        self.assertRefused('trust', req=self.req(module_sha256='a' * 64))           # trusted, but root has no copy
        self.put(os.path.join(nginxswap.store_dir(self.state), 'a' * 64 + '.so'), b'other')
        self.assertRefused('module', req=self.req(module_sha256='a' * 64))          # root's copy changed
        self.assertRefused('package', fake=Fake(self.t, dict(self.index, **{NEW: 'b' * 64})))       # not apt's file
        self.assertIn('no way back', self.assertRefused('package', fake=Fake(self.t, {NEW: self.index[NEW]})))
        self.assertRefused('verify', ok=False)
        self.trusted.clear()                                                         # root never trusted it
        self.assertIn('nginx-module-trust', self.assertRefused('trust'))
        self.trusted.add(sha(self.mod))
        f = Fake(self.t, self.index)
        f.owner = 'openssl'                                                          # not the package of nginx
        self.assertRefused('preflight', fake=f)
        f = Fake(self.t, self.index)
        f.depends = 'nginx-common (= 1.30.7-1), libc6'                               # Debian's split packaging
        self.assertIn('not supported', self.assertRefused('preflight', fake=f))
        f = Fake(self.t, self.index)
        f.dependents += 'ii |nginx-module-njs|, nginx (= 1.30.6-1~bookworm)\n'        # installed, needs today's nginx
        self.assertIn('not supported', self.assertRefused('preflight', fake=f))
        for bad in ({'package': 'nginx; rm'}, {'version': '../x'}, {'mode': 'other'}, {'change_id': '7'}):
            with self.assertRaises(nginxswap.SwapFail):
                nginxswap.check_request(self.req(**bad))

    def test_links_are_not_followed(self):
        p = os.path.join(self.job, 'debs', 'nginx_%s_amd64.deb' % NEW)
        os.unlink(p)
        os.symlink(self.target, p)
        self.assertRefused('files')

    def test_the_service_users_module_file_is_never_used(self):
        # jtwaf swaps the file in its own directory after the trust: root still uses its own copy
        self.put(os.path.join(self.job, 'modules', NEW, nginxswap.MODULE_NAME), b'\x7fELF evil')
        res = self.prepare(fake=Fake(self.t, self.index, unit=TestPrepare.unit_ok(self)))
        self.assertEqual(res['result'], 'ok')
        with open(self.plan['module'], 'rb') as fh:
            self.assertEqual(fh.read(), self.mod)

    def test_unit_without_result(self):
        with self.assertRaises(nginxswap.SwapFail) as cm:
            self.prepare(fake=Fake(self.t, self.index, unit=lambda: (1, 'failed')))
        self.assertEqual(cm.exception.step, 'install')
        self.assertTrue(cm.exception.half)          # nobody knows how far it got: a critical alert, a person looks

    def test_finish_uses_the_installed_nginx(self):
        os.rename(os.path.join(self.job, 'modules', NEW), os.path.join(self.job, 'modules', OLD))
        fake = Fake(self.t, self.index, installed=OLD, candidate=OLD, unit=self.unit_ok())
        self.prepare(req=self.req(mode='finish', version=OLD), fake=fake)
        self.assertEqual(self.tried, ['/usr/sbin/nginx'])
        self.assertIsNone(self.plan['new_deb'])
        self.assertFalse(any(c[:2] == ['apt-cache', 'show'] for c in fake.calls))


class TestTrust(unittest.TestCase):
    def test_list_must_be_roots_alone(self):
        t = tempfile.mkdtemp(prefix='jtwaf-test-swap-')
        self.addCleanup(shutil.rmtree, t, True)
        p = os.path.join(t, 'trusted-modules.sha256')
        with open(p, 'w') as fh:
            fh.write('%s  2026-11-18 built here\nnot-a-hash\n' % ('a' * 64))
        os.chmod(t, 0o755)
        os.chmod(p, 0o640)
        got = nginxswap.trusted_modules(p)
        self.assertEqual(got, {'a' * 64} if os.geteuid() == 0 else set())        # someone else's file: nothing
        os.chmod(p, 0o666)
        self.assertEqual(nginxswap.trusted_modules(p), set())                       # writable by others: nothing
        os.symlink(p, p + '.link')
        self.assertEqual(nginxswap.trusted_modules(p + '.link'), set())

    @unittest.skipUnless(os.geteuid() == 0, 'root only')
    def test_trust_adds_once(self):
        t = tempfile.mkdtemp(prefix='jtwaf-test-swap-')
        self.addCleanup(shutil.rmtree, t, True)
        os.chmod(t, 0o755)
        m = os.path.join(t, 'm.so')
        with open(m, 'wb') as fh:
            fh.write(b'\x7fELF x')
        lst = os.path.join(t, 'list')
        state = os.path.join(t, 'state')
        with self.assertRaises(nginxswap.SwapFail):
            nginxswap.trust(m, 'b' * 64, state, '', lst)                         # not the hash the build printed
        self.assertFalse(os.path.exists(lst))
        h = nginxswap.trust(m, sha(b'\x7fELF x'), state, 'note; rm -rf /', lst)
        nginxswap.trust(m, h, state, '', lst)
        with open(os.path.join(nginxswap.store_dir(state), h + '.so'), 'rb') as fh:
            self.assertEqual(fh.read(), b'\x7fELF x')                            # root's own copy
        with open(lst) as fh:
            lines = fh.read().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith(h) and ';' not in lines[0])
        with open(m, 'wb') as fh:
            fh.write(b'#!/bin/sh')
        with self.assertRaises(nginxswap.SwapFail):
            nginxswap.trust(m, sha(b'#!/bin/sh'), state, '', lst)
        os.unlink(m)
        os.symlink(lst, m)
        with self.assertRaises(nginxswap.SwapFail):                                  # links are not followed
            nginxswap.trust(m, h, state, '', lst)


class TestModuleTarget(unittest.TestCase):
    def test_main_level_only_and_includes(self):
        t = tempfile.mkdtemp(prefix='jtwaf-test-swap-')
        self.addCleanup(shutil.rmtree, t, True)
        os.makedirs(os.path.join(t, 'modules-enabled'))
        with open(os.path.join(t, 'nginx.conf'), 'w') as fh:
            fh.write('user www-data;\ninclude %s/modules-enabled/*.conf;\n# load_module modules/old_modsecurity.so;\n'
                     'http {\n  include conf.d/*.conf;\n}\n' % t)
        with open(os.path.join(t, 'modules-enabled', '50-mod-http-modsecurity.conf'), 'w') as fh:
            fh.write('load_module modules/ngx_http_modsecurity_module.so;\n')
        saved = nginxswap._run
        self.addCleanup(setattr, nginxswap, '_run', saved)
        # nginx -t fails (the case that matters): only -V answers
        nginxswap._run = lambda cmd, cwd=None, timeout=300: (1, 'configure arguments: --prefix=%s --conf-path=%s/nginx.conf' % (t, t))
        self.assertEqual(nginxswap.module_target('/usr/sbin/nginx'),
                         os.path.realpath(os.path.join(t, 'modules', 'ngx_http_modsecurity_module.so')))


class TestSwap(Base):
    def setUp(self):
        super().setUp()
        saved = (nginxswap.master, nginxswap.exe, nginxswap.hot_upgrade, nginxswap.nginx_t, nginxswap.held)
        self.addCleanup(lambda: (setattr(nginxswap, 'master', saved[0]), setattr(nginxswap, 'exe', saved[1]),
                                 setattr(nginxswap, 'hot_upgrade', saved[2]), setattr(nginxswap, 'nginx_t', saved[3]),
                                 setattr(nginxswap, 'held', saved[4])))
        self.pid = [100]
        nginxswap.master = lambda: self.pid[0]
        nginxswap.exe = lambda pid: '/usr/sbin/nginx'
        nginxswap.nginx_t = lambda nginx: True
        nginxswap.held = lambda pkg: True
        self.work = os.path.join(nginxswap.work_dir(self.state), 'c7')
        os.makedirs(self.work)
        for n, b in ((nginxswap.MODULE_NAME, self.mod), ('new.deb', b'n'), ('old.deb', b'o')):
            self.put(os.path.join(self.work, n), b)
        self.plan = {'change_id': 7, 'mode': 'update', 'package': PKG, 'version': NEW, 'previous': OLD, 'work': self.work,
                     'module': os.path.join(self.work, nginxswap.MODULE_NAME), 'target': self.target,
                     'new_deb': os.path.join(self.work, 'new.deb'), 'old_deb': os.path.join(self.work, 'old.deb'),
                     'health_urls': ['https://www.example.com/'], 'nginx': '/usr/sbin/nginx'}

    def dpkg(self, ok=True, moves=True, old_ok=True):
        fake = Fake(self.t, self.index)
        run = fake.__call__
        self.inst = [OLD]

        def f(cmd, cwd=None, timeout=300):
            if cmd[0] == 'dpkg' and '-i' in cmd:
                fake.calls.append(cmd)
                old = cmd[-1].endswith('old.deb')
                if (old and not old_ok) or (not old and not ok):
                    if not old:
                        self.inst[0] = NEW                # unpacked, then failed
                    return 1, 'dpkg: error'
                self.inst[0] = OLD if old else NEW
                if moves:
                    self.pid[0] += 1                      # the package moved nginx to the new program itself
                return 0, ''
            if cmd[:2] == ['dpkg-query', '-W'] and len(cmd) > 3:
                return 0, 'ii |' + self.inst[0]
            return run(cmd, cwd, timeout)
        f.calls = fake.calls
        nginxswap._run = f
        return f

    def module_now(self):
        with open(self.target, 'rb') as fh:
            return fh.read()

    def test_update(self):
        f = self.dpkg()
        res = nginxswap.swap(self.plan, lambda urls: {u: 200 for u in urls}, [])
        self.assertEqual(res['result'], 'ok')
        self.assertEqual(self.module_now(), self.mod)
        self.assertIn(['dpkg', '--force-confold', '--force-confdef', '-i', self.plan['new_deb']], f.calls)
        self.assertIn(['apt-mark', 'hold', PKG], f.calls)

    def test_package_does_not_move_nginx(self):
        self.dpkg(moves=False)
        moved = []

        def hot():
            moved.append(1)
            self.pid[0] += 1
            return self.pid[0]
        nginxswap.hot_upgrade = hot
        nginxswap.swap(self.plan, lambda urls: {u: 200 for u in urls}, [])
        self.assertEqual(moved, [1])

    def test_health_changes_put_everything_back(self):
        f = self.dpkg()
        seen = []

        def health(urls):
            seen.append(1)
            return {u: 200 if len(seen) == 1 else 502 for u in urls}
        with self.assertRaises(nginxswap.SwapFail) as cm:
            nginxswap.swap(self.plan, health, [])
        self.assertEqual(cm.exception.step, 'health')
        self.assertIn('previous package reinstalled', cm.exception.summary)
        self.assertEqual(self.module_now(), b'\x7fELF old module')
        self.assertIn(['dpkg', '--force-confold', '--force-confdef', '-i', self.plan['old_deb']], f.calls)
        self.assertIn(['apt-mark', 'hold', PKG], f.calls)

    def test_old_package_cannot_go_back(self):
        # the new program stays on disk: so does the new module that matches it (never a mismatched pair)
        self.dpkg(old_ok=False)
        with self.assertRaises(nginxswap.SwapFail) as cm:
            nginxswap.swap(self.plan, lambda urls: {u: 502 if self.inst[0] == NEW else 200 for u in urls}, [])
        self.assertIn('NOT reinstalled', cm.exception.summary)
        self.assertEqual(self.module_now(), self.mod)
        self.assertTrue(self.plan['half'])

    def test_dpkg_fails(self):
        self.dpkg(ok=False, moves=False)
        with self.assertRaises(nginxswap.SwapFail) as cm:
            nginxswap.swap(self.plan, lambda urls: {u: 200 for u in urls}, [])
        self.assertEqual(cm.exception.step, 'install')
        self.assertEqual(self.module_now(), b'\x7fELF old module')


if __name__ == '__main__':
    unittest.main()


class TestApplyRequests(unittest.TestCase):
    def test_hold_only_the_package_nginx_comes_from(self):
        from jtwafmgr.apply import Applier, Fail
        from tests.helpers import TempEnv
        env = TempEnv()
        self.addCleanup(env.cleanup)
        saved = nginxswap.owner
        self.addCleanup(setattr, nginxswap, 'owner', saved)
        nginxswap.owner = lambda nginx_bin: 'nginx'
        a = Applier(env.cfg)
        self.assertEqual(a.check_nginx({'action': 'nginx_hold', 'package': 'nginx'})['package'], 'nginx')
        for bad in ('openssl', 'libc6', '', None):
            with self.assertRaises(Fail):
                a.check_nginx({'action': 'nginx_hold', 'package': bad})


class TestWayBack(TestPrepare):
    """0.5.1: back to the package and module before an applied change -- from what root kept itself."""

    OLDMOD = b'\x7fELF module before'

    def kept(self, record=True, change=5):
        d = os.path.join(nginxswap.work_dir(self.state), 'c%d-20261119-000000-x' % change)
        for n, b in (('new.deb', self.debs[NEW]), ('old.deb', self.debs[OLD]), (nginxswap.MODULE_NAME, self.mod),
                     ('previous-' + nginxswap.MODULE_NAME, self.OLDMOD)):
            self.put(os.path.join(d, n), b)
        if record:
            with open(os.path.join(d, nginxswap.DONE), 'w') as fh:
                json.dump({'mode': 'update', 'package': PKG, 'version': NEW, 'previous': OLD, 'module_sha256': sha(self.mod),
                           'previous_module_sha256': sha(self.OLDMOD), 'old_deb_sha256': sha(self.debs[OLD]),
                           'new_deb_sha256': sha(self.debs[NEW])}, fh)
        self.put(self.target, self.mod)             # that change's module runs now
        return d

    def fake(self, installed=NEW):
        f = Fake(self.t, self.index, installed=installed, unit=self.unit_ok())
        run = f.__call__
        debs = self.debs

        def g(cmd, cwd=None, timeout=300):
            if cmd[:2] == ['dpkg-deb', '-f']:
                with open(cmd[2], 'rb') as fh:
                    b = fh.read()
                return 0, {'Version': NEW if b == debs[NEW] else OLD, 'Package': PKG}[cmd[3]]
            return run(cmd, cwd, timeout)
        g.calls = f.calls
        return g

    def rb(self, **kw):
        return {'change_id': 9, 'mode': 'rollback', 'package': PKG, 'from_change': 5, **kw}

    def test_rollback_takes_the_kept_files(self):
        self.kept()
        res = self.prepare(req=self.rb(), fake=self.fake())
        self.assertEqual(res['result'], 'ok')
        p = self.plan
        self.assertEqual((p['mode'], p['version'], p['previous']), ('rollback', OLD, NEW))
        for k, want in (('new_deb', self.debs[OLD]), ('old_deb', self.debs[NEW]), ('module', self.OLDMOD)):
            with open(p[k], 'rb') as fh:
                self.assertEqual(fh.read(), want, k)
        self.assertTrue(self.tried[0].endswith('/unpacked/usr/sbin/nginx'))     # the previous nginx with its module

    def test_kept_by_an_older_version_without_a_record(self):
        self.kept(record=False)
        self.assertEqual(self.prepare(req=self.rb(), fake=self.fake())['result'], 'ok')
        self.assertEqual(self.plan['version'], OLD)

    def test_rollback_refusals(self):
        self.kept()
        self.assertIn('skip what came after', self.assertRefused('preflight', req=self.rb(), fake=self.fake(installed='1.30.8-1~bookworm')))
        self.put(self.target, b'\x7fELF another module')
        self.assertIn('module in place', self.assertRefused('preflight', req=self.rb(), fake=self.fake()))
        self.assertIn('kept nothing', self.assertRefused('preflight', req=self.rb(from_change=6), fake=self.fake()))
        with self.assertRaises(nginxswap.SwapFail):
            nginxswap.check_request(self.rb(from_change=-1))

    def test_module_switch_keeps_nginx(self):
        self.put(self.target, b'\x7fELF old module')
        res = self.prepare(req=self.req(mode='module', version=OLD), fake=Fake(self.t, self.index, installed=OLD, unit=self.unit_ok()))
        self.assertEqual(res['result'], 'ok')
        self.assertEqual((self.plan['new_deb'], self.plan['old_deb'], self.plan['version']), (None, None, OLD))
        self.assertRefused('preflight', req=self.req(mode='module', version=NEW), fake=Fake(self.t, self.index, installed=OLD))

    def test_prune_keeps_the_way_back(self):
        base = nginxswap.work_dir(self.state)
        keep = self.kept(change=1)
        os.utime(keep, (1, 1))                      # the oldest of all
        for i in range(2, 8):
            os.makedirs(os.path.join(base, 'c%d-x' % i))
            os.utime(os.path.join(base, 'c%d-x' % i), (i, i))
        nginxswap.prune(base)
        left = sorted(os.listdir(base))
        self.assertIn(os.path.basename(keep), left)
        self.assertEqual(len([x for x in left if x.startswith('c')]), 5)       # 4 newest attempts + the way back


class TestSwapRecordsTheWayBack(TestSwap):
    def test_done_written_and_module_switch_moves_nginx_twice_on_failure(self):
        self.dpkg()
        nginxswap.swap(self.plan, lambda urls: {u: 200 for u in urls}, [])
        with open(os.path.join(self.work, nginxswap.DONE)) as fh:
            done = json.load(fh)
        self.assertEqual((done['version'], done['previous'], done['module_sha256']), (NEW, OLD, sha(self.mod)))
        # a module switch that fails its health check: the old module goes back and nginx moves to it again
        moves = []
        nginxswap.hot_upgrade = lambda wait=15: (moves.append(1), self.pid.__setitem__(0, self.pid[0] + 1))
        plan = dict(self.plan, mode='module', new_deb=None, old_deb=None, version=OLD, previous=OLD)
        self.put(self.target, b'\x7fELF running module')
        calls = iter([{'u': 200}, {'u': 502}])
        with self.assertRaises(nginxswap.SwapFail):
            nginxswap.swap(dict(plan, health_urls=['u']), lambda urls: next(calls), [])
        self.assertEqual(self.module_now(), b'\x7fELF running module')
        self.assertEqual(len(moves), 2)             # to the new module, and back to the old one


class TestFailedHotUpgrade(unittest.TestCase):
    """0.5.26: a new master that did not come up in time was left running beside the old one (CT 244 reproduced
    two masters and nginx.pid.oldbin left behind); now it is stopped: QUIT, then TERM."""

    def test_the_new_master_is_stopped(self):
        from unittest import mock
        alive = {222}
        sent = []

        def kill(pid, sig):
            sent.append((pid, sig))
            if sig == nginxswap.signal.SIGTERM:
                alive.discard(pid)
        with mock.patch.object(nginxswap, '_new_masters', lambda old: sorted(alive)), \
                mock.patch.object(nginxswap.os, 'kill', kill), mock.patch.object(nginxswap.time, 'sleep', lambda s: None):
            nginxswap._stop_new_masters(111, wait=0.05)
        self.assertEqual(sent[0], (222, nginxswap.signal.SIGQUIT))
        self.assertIn((222, nginxswap.signal.SIGTERM), sent)
        self.assertEqual(alive, set())
