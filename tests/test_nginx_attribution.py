"""0.5.9: files an approved nginx change put there (a ModSecurity module root trusts, the nginx package's own files) are
jt-waf-mgr's own change, not an outside edit (change #96's module switch raised a critical "changed outside")."""
import hashlib
import json
import os
import tempfile
import time
import unittest
from unittest import mock

from jtwafmgr import nginxswap
from jtwafmgr.app import App
from tests.helpers import TempEnv


class TestNginxAttribution(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        self.d = tempfile.mkdtemp(prefix='jtwaf-attr-')
        self.mod = os.path.join(self.d, 'modules', nginxswap.MODULE_NAME)
        os.makedirs(os.path.dirname(self.mod))
        with open(self.mod, 'wb') as fh:
            fh.write(b'\x7fELF module built for this test')
        self.sha = hashlib.sha256(open(self.mod, 'rb').read()).hexdigest()
        self.info = os.path.join(self.d, 'info')
        os.makedirs(self.info)
        self.binary = os.path.join(self.d, 'sbin-nginx')
        with open(os.path.join(self.info, 'nginx.list'), 'w') as fh:
            fh.write('/.\n%s\n' % self.binary)
        self.now = time.time()

    def tearDown(self):
        import shutil
        self.app.db.release()
        self.env.cleanup()
        shutil.rmtree(self.d, ignore_errors=True)

    def change(self, mode, ago=60):
        self.app.db.x("INSERT INTO changes(op, kind, spec, direction, state, proposed_by, created_at, updated_at) "
                      "VALUES ('nginx', 'system', ?, 'neutral', 'applied', 'boss', ?, ?)",
                      (json.dumps({'mode': mode, 'package': 'nginx', 'module_sha256': self.sha}), self.now - ago, self.now - ago))

    def ours(self, touched, trusted):
        with mock.patch.object(nginxswap, 'trusted_modules', return_value=set(trusted)):
            return self.app.monitor._nginx_files({'ts': self.now - 600}, touched, dpkg_info=self.info)

    def test_module_switch(self):
        self.assertFalse(self.ours([self.mod], {self.sha}))           # no nginx change applied: not proven ours
        self.change('module')
        self.assertTrue(self.ours([self.mod], {self.sha}))
        self.assertFalse(self.ours([self.mod], {'0' * 64}))           # a module root does not trust: outside
        self.assertFalse(self.ours([self.mod, self.binary], {self.sha}))   # a module switch installs no package

    def test_package_update(self):
        self.change('update')
        self.assertTrue(self.ours([self.binary, self.mod], {self.sha}))
        self.assertFalse(self.ours([os.path.join(self.d, 'not-the-package')], {self.sha}))

    def test_old_change_does_not_count(self):
        self.change('module', ago=7200)
        self.assertFalse(self.ours([self.mod], {self.sha}))


if __name__ == '__main__':
    unittest.main()
