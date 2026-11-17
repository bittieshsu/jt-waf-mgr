"""Whether nginx loads its ModSecurity module, now and after the next system update (nginxmod.py). The package
manager's answers are simulated; no package is looked up or changed."""
import os
import shutil
import unittest

from jtwafmgr import nginxmod

MOD = '/usr/lib/nginx/modules/ngx_http_modsecurity_module.so'


class FakeApt:
    """dpkg-query / apt-cache / apt-mark answers for one scenario."""

    def __init__(self, owners, policy, show, held=()):
        self.owners, self.policy, self.show, self.held = owners, policy, show, held

    def __call__(self, cmd, timeout=20):
        if cmd[0] == 'dpkg-query':
            o = self.owners.get(cmd[2])
            return (0, '%s: %s\n' % (o, cmd[2])) if o else (1, 'dpkg-query: no path found')
        if cmd[:2] == ['apt-cache', 'policy']:
            inst, cand = self.policy.get(cmd[2], (None, None))
            return 0, '%s:\n  Installed: %s\n  Candidate: %s\n' % (cmd[2], inst or '(none)', cand or '(none)')
        if cmd[:2] == ['apt-cache', 'show']:
            return 0, self.show.get(cmd[2], '')
        if cmd[:2] == ['apt-mark', 'showhold']:
            return 0, '\n'.join(self.held)
        return 1, ''


class TestUpdateRisk(unittest.TestCase):
    def setUp(self):
        self._run, self._which = nginxmod._run, nginxmod.shutil.which
        nginxmod.shutil.which = lambda name: '/usr/bin/' + name
        self.addCleanup(setattr, nginxmod, '_run', self._run)
        self.addCleanup(setattr, nginxmod.shutil, 'which', self._which)

    def risk(self, apt):
        nginxmod._run = apt
        return nginxmod.update_risk('/usr/sbin/nginx', [MOD])

    def test_packaged_module_that_follows(self):
        r = self.risk(FakeApt({'/usr/sbin/nginx': 'nginx', MOD: 'libnginx-mod-http-modsecurity'},
                              {'nginx': ('1.28.3-1', '1.28.4-1'), 'libnginx-mod-http-modsecurity': ('1.0.3-1', '1.0.3-2')},
                              {'nginx=1.28.4-1': 'Provides: httpd, nginx-abi-1.28.4-1\n',
                               'libnginx-mod-http-modsecurity=1.0.3-2': 'Depends: libc6, nginx-abi-1.28.4-1\n'}))
        self.assertEqual((r['update'], r['risk'], r['hand_built']), (True, False, []))

    def test_packaged_module_left_behind(self):
        r = self.risk(FakeApt({'/usr/sbin/nginx': 'nginx', MOD: 'libnginx-mod-http-modsecurity'},
                              {'nginx': ('1.28.3-1', '1.28.4-1'), 'libnginx-mod-http-modsecurity': ('1.0.3-1', '1.0.3-1')},
                              {'nginx=1.28.4-1': 'Provides: nginx-abi-1.28.4-1\n',
                               'libnginx-mod-http-modsecurity=1.0.3-1': 'Depends: nginx-abi-1.28.3-1\n'}))
        self.assertTrue(r['risk'])
        self.assertEqual(nginxmod.level({'load': {'ok': True}, 'modsecurity_module': True, 'update': r}),
                         ('warning', 'update_would_break'))

    def test_hand_built_module_held_or_not(self):
        apt = FakeApt({'/usr/sbin/nginx': 'nginx'}, {'nginx': ('1.30.6-1~bookworm', '1.30.7-1~bookworm')}, {}, held=('nginx',))
        r = self.risk(apt)
        self.assertEqual((r['update'], r['held'], r['risk'], r['hand_built']), (True, True, False, [MOD]))    # held: safe
        apt.held = ()
        r = self.risk(apt)
        self.assertTrue(r['risk'])                                                    # an update would leave it behind
        apt.policy['nginx'] = ('1.30.6-1~bookworm', '1.30.6-1~bookworm')
        r = self.risk(apt)
        self.assertFalse(r['risk'])
        self.assertEqual(nginxmod.level({'load': {'ok': True}, 'modsecurity_module': True, 'update': r}), ('warning', 'not_held'))

    def test_not_debian(self):
        nginxmod.shutil.which = lambda name: None
        self.assertEqual(nginxmod.update_risk('/usr/sbin/nginx', [MOD]), {'supported': False})


@unittest.skipUnless(shutil.which('nginx') or os.path.exists('/usr/sbin/nginx'), 'needs an nginx program')
class TestLoad(unittest.TestCase):
    def test_load_test_with_the_real_nginx(self):
        nginx = shutil.which('nginx') or '/usr/sbin/nginx'
        self.assertTrue(nginxmod.load_test(nginx, [])['ok'])
        bad = nginxmod.load_test(nginx, ['/etc/hostname'])                          # not a module at all
        self.assertIs(bad['ok'], False)
        self.assertIn('/etc/hostname', bad['incompatible'])
        self.assertEqual(nginxmod.level({'load': bad, 'modsecurity_module': True, 'update': {}}), ('critical', 'module_does_not_load'))


if __name__ == '__main__':
    unittest.main()
