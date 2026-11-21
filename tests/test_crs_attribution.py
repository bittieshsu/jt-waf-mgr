"""0.5.34: the files an approved OWASP CRS change writes (its rules, crs-setup.conf, and at the first installation the
two Include lines in the ModSecurity main file) are jt-waf-mgr's own change: a first installation was reported as a
critical "changed outside"."""
import json
import time
import unittest

from jtwafmgr.app import App
from tests.helpers import TempEnv

M = '/etc/nginx/modsec'


class TestCrsAttribution(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.app = App(self.env.cfg)
        self.addCleanup(self.app.db.release)
        self.now = time.time()

    def change(self, mode, ago=60, state='applied'):
        spec = {'mode': mode, 'to': '4.30.0', 'crs_path': M + '/crs'}
        if mode == 'first_install':
            spec.update(main_conf=M + '/main.conf', anchor=M + '/modsecurity.conf')
        self.app.db.x("INSERT INTO changes(op, kind, spec, direction, state, proposed_by, created_at, updated_at) "
                      "VALUES ('crs', 'system', ?, 'loosen', ?, 'boss', ?, ?)", (json.dumps(spec), state, self.now - ago,
                                                                                  self.now - ago))

    def ours(self, touched):
        return self.app.monitor._crs_files({'ts': self.now - 600}, touched)

    def test_first_installation(self):
        files = [M + '/main.conf', M + '/crs-setup.conf', M + '/crs/rules/REQUEST-901-INITIALIZATION.conf',
                 M + '/crs-4.30.0/rules/RESPONSE-980-CORRELATION.conf']
        self.assertFalse(self.ours(files))                              # no change: outside
        self.change('first_install')
        self.assertTrue(self.ours(files))
        self.assertFalse(self.ours(files + [M + '/modsecurity.conf']))  # another file as well: outside
        self.assertFalse(self.ours(['/etc/nginx/sites-enabled/x.conf']))

    def test_switch_does_not_cover_main_file(self):
        self.change('switch')
        self.assertTrue(self.ours([M + '/crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf', M + '/crs-4.31.0/crs-setup.conf']))
        self.assertFalse(self.ours([M + '/main.conf']))                 # a switch never touches it
        self.assertFalse(self.ours([M + '/crs-evil/x.conf']))           # not a crs-<version> directory

    def test_old_or_unapplied_change_does_not_count(self):
        self.change('first_install', ago=3 * 3600)
        self.assertFalse(self.ours([M + '/main.conf']))
        self.change('first_install', state='pending_approval')
        self.assertFalse(self.ours([M + '/main.conf']))


if __name__ == '__main__':
    unittest.main()
