"""Getting ready for the next nginx update (nginxup.py, api_nginxup.py). The package manager and the new nginx are
simulated; nothing is downloaded and no nginx is changed. A real nginx with a ModSecurity module, when this host has
one, is tried in try_module."""
import base64
import hashlib
import json
import os
import shutil
import unittest

from jtwafmgr import nginxmod, nginxup
from jtwafmgr.app import App
from tests.helpers import TempEnv

MOD = '/usr/lib/nginx/modules/ngx_http_modsecurity_module.so'


class Req:
    def __init__(self, body=None, params=None):
        self.user, self.client_ip = {'username': 'boss', 'role': 'admin'}, '127.0.0.1'
        self._b, self.params, self.query = body or {}, params or {}, {}

    def body(self):
        return self._b


class Base(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.app = App(self.env.cfg)
        self.addCleanup(self.app.stop)
        saved = (nginxmod.modules, nginxmod.update_risk, nginxup._download, nginxup.try_module, nginxmod.load_test)
        self.addCleanup(lambda: (setattr(nginxmod, 'modules', saved[0]), setattr(nginxmod, 'update_risk', saved[1]),
                                 setattr(nginxup, '_download', saved[2]), setattr(nginxup, 'try_module', saved[3]),
                                 setattr(nginxmod, 'load_test', saved[4])))
        nginxmod.modules = lambda app: ([MOD], False)
        self.loads = True
        nginxmod.load_test = lambda nginx_bin, mods: {'ok': self.loads}
        from jtwafmgr import nginxswap
        saved2 = (nginxswap.trusted_modules, nginxup._single_package)
        self.addCleanup(lambda: (setattr(nginxswap, 'trusted_modules', saved2[0]), setattr(nginxup, '_single_package', saved2[1])))
        self.trusted = {hashlib.sha256(b'\x7fELF module').hexdigest()}
        nginxswap.trusted_modules = lambda path=None: self.trusted
        nginxup._single_package = lambda pkg, version: True
        self.tried = []

    def risk(self, **kw):
        r = {'supported': True, 'nginx_package': 'nginx', 'installed': '1.30.6-1~bookworm', 'candidate': '1.30.7-1~bookworm',
             'held': True, 'update': True, 'modules': [{'path': MOD, 'package': None, 'follows': False}], 'hand_built': [MOD],
             'risk': False}
        r.update(kw)
        nginxmod.update_risk = lambda nginx_bin, mods: r

    def fake_package(self, ok=True):
        self.downloads = []

        def download(pkg, version, work, root=None):
            self.downloads.append((pkg, version))
            deb = os.path.join(work, '%s_%s_amd64.deb' % (pkg, version))
            with open(deb, 'w') as fh:
                fh.write('deb %s %s' % (pkg, version))
            if root:
                os.makedirs(os.path.join(root, 'usr', 'sbin'), exist_ok=True)
                if pkg == 'nginx':
                    with open(os.path.join(root, 'usr', 'sbin', 'nginx'), 'w') as fh:
                        fh.write('fake %s %s' % (pkg, version))
            return deb, 'f' * 64, None

        def try_module(nginx_bin, module, others=()):
            text = nginx_bin
            if os.path.isfile(nginx_bin):
                with open(nginx_bin) as fh:
                    text = fh.read()
            self.tried.append((text, nginxup.sha256_file(module), list(others)))
            return (True, 'loaded; refused the test request (403), passed an ordinary one (200)') if ok else \
                (False, 'nginx -t: module "..." version 1030006 instead of 1030007')
        nginxup._download, nginxup.try_module = download, try_module

    def put_module(self, version='1.30.7-1~bookworm', data=b'\x7fELF module', meta=None):
        d = nginxup.module_dir(self.env.cfg, version)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, nginxup.MODULE_NAME), 'wb') as fh:
            fh.write(data)
        if meta is not None:
            with open(os.path.join(d, 'module.json'), 'w') as fh:
                json.dump(meta, fh)
        return hashlib.sha256(data).hexdigest()


class TestRun(Base):
    def test_states(self):
        self.risk(update=False, candidate='1.30.6-1~bookworm')
        self.assertEqual(nginxup.run(self.app, log=lambda m: None)['state'], 'current')
        self.risk(hand_built=[], modules=[{'path': MOD, 'package': 'libnginx-mod-http-modsecurity', 'follows': True}])
        self.assertEqual(nginxup.run(self.app, log=lambda m: None)['state'], 'packaged')
        self.risk()
        st = nginxup.run(self.app, log=lambda m: None)
        self.assertEqual(st['state'], 'no_module')                       # nothing waiting for 1.30.7 yet
        self.risk(hand_built=[MOD, '/usr/lib/nginx/modules/ngx_http_other.so'])
        self.assertEqual(nginxup.run(self.app, log=lambda m: None)['state'], 'other_hand_built')
        self.risk(supported=False)
        self.assertEqual(nginxup.run(self.app, log=lambda m: None)['state'], 'unsupported')
        self.assertEqual(nginxup.read_status(self.env.cfg)['state'], 'unsupported')

    def test_ready_only_with_the_new_nginx(self):
        self.risk()
        self.fake_package()
        sha = self.put_module()
        st = nginxup.run(self.app, log=lambda m: None)
        self.assertEqual((st['state'], st['module_sha256'], st['candidate']), ('ready', sha, '1.30.7-1~bookworm'))
        self.assertEqual(self.tried[0][0], 'fake nginx 1.30.7-1~bookworm')    # the new package's nginx, not the running one
        self.assertEqual((st['mode'], st['target']), ('update', '1.30.7-1~bookworm'))
        self.assertEqual(sorted(os.listdir(os.path.join(nginxup.base(self.env.cfg), 'debs'))),     # new and the way back
                         ['nginx_1.30.6-1~bookworm_amd64.deb', 'nginx_1.30.7-1~bookworm_amd64.deb'])
        self.assertFalse(os.path.exists(os.path.join(nginxup.base(self.env.cfg), nginxup.REQUEST)))

    def test_failed_and_mismatched(self):
        self.risk()
        self.fake_package(ok=False)
        self.put_module()
        st = nginxup.run(self.app, log=lambda m: None)
        self.assertEqual(st['state'], 'failed')
        self.assertIn('version', st['error'])
        self.put_module(meta={'sha256': 'a' * 64})                        # the description names another file
        self.fake_package()
        st = nginxup.run(self.app, log=lambda m: None)
        self.assertEqual(st['state'], 'failed')
        self.assertIn('SHA-256', st['error'])

    def test_unsupported_packaging_and_trust(self):
        other = '/usr/lib/nginx/modules/ngx_http_geoip_module.so'
        self.risk(modules=[{'path': MOD, 'package': None, 'follows': False},
                           {'path': other, 'package': 'nginx-module-geoip', 'installed': '1.30.6-1', 'candidate': '1.30.7-1'}])
        self.fake_package()
        self.put_module()
        self.assertEqual(nginxup.run(self.app, log=lambda m: None)['state'], 'unsupported_packaging')
        self.risk()
        nginxup._single_package = lambda pkg, version: False                 # Debian's nginx + nginx-common
        self.assertEqual(nginxup.run(self.app, log=lambda m: None)['state'], 'unsupported_packaging')
        nginxup._single_package = lambda pkg, version: True
        self.trusted.clear()
        st = nginxup.run(self.app, log=lambda m: None)
        self.assertEqual(st['state'], 'untrusted')                            # nothing downloaded or tried
        self.assertEqual((self.downloads, self.tried), ([], []))

    def test_finish_an_update_already_installed(self):
        # nginx was updated, the module left behind: nginx -t fails; the module for the installed nginx finishes it
        self.risk(update=False, installed='1.30.7-1~bookworm', candidate='1.30.7-1~bookworm')
        self.loads = False
        self.fake_package()
        self.assertEqual(nginxup.run(self.app, log=lambda m: None)['state'], 'no_module')
        self.put_module()
        st = nginxup.run(self.app, log=lambda m: None)
        self.assertEqual((st['state'], st['mode'], st['target']), ('ready', 'finish', '1.30.7-1~bookworm'))
        self.assertEqual(self.downloads, [])                              # the installed nginx itself is tried
        self.assertEqual(self.tried[-1][0], self.env.cfg['paths']['nginx_bin'])

    def test_module_dir_names(self):
        for bad in ('', '../x', '1.0/../../etc', 'a b', 'x' * 80):
            with self.assertRaises(ValueError):
                nginxup.module_dir(self.env.cfg, bad)
        self.assertTrue(nginxup.module_dir(self.env.cfg, '1:1.30.7-1~bookworm').endswith('/modules/1_1.30.7-1~bookworm'))


class TestApi(Base):
    def upload(self, data, finish, name=nginxup.MODULE_NAME):
        from jtwafmgr.web import api_hub
        s = json.loads(api_hub.upload_start(self.app, Req({'kind': 'nginxmod', 'name': name, 'size': len(data),
                                                           'sha256': hashlib.sha256(data).hexdigest()})).body)
        api_hub.upload_chunk(self.app, Req({'index': 0, 'data': base64.b64encode(data).decode()}, {'id': s['id']}))
        return api_hub.upload_finish(self.app, Req(finish, {'id': s['id']}))

    def test_upload_and_status(self):
        from jtwafmgr import uploads
        from jtwafmgr.web import api_nginxup
        from jtwafmgr.web.server import ApiError
        self.risk()
        with self.assertRaises(uploads.UploadError):
            uploads.start(self.env.cfg, 'nginxmod', 'evil.so', 10, 'a' * 64, 'boss')
        with self.assertRaises(ApiError) as cm:
            self.upload(b'#!/bin/sh\n', {'nginx_package': '1.30.7-1~bookworm'})
        self.assertEqual(cm.exception.code, 'not_a_module')
        data = b'\x7fELF' + os.urandom(100)
        with self.assertRaises(ApiError) as cm:
            self.upload(data, {'description': {'sha256': 'b' * 64, 'nginx_package': '1.30.7-1~bookworm'}})
        self.assertEqual(cm.exception.code, 'description_mismatch')
        out = json.loads(self.upload(data, {'description': json.dumps({'sha256': hashlib.sha256(data).hexdigest(),
                                                                       'nginx_package': '1.30.7-1~bookworm', 'os': 'debian-12',
                                                                       'extra': 'dropped'})}).body)
        self.assertEqual(out['nginx_package'], '1.30.7-1~bookworm')
        d = nginxup.module_dir(self.env.cfg, '1.30.7-1~bookworm')
        with open(os.path.join(d, 'module.json')) as fh:
            meta = json.load(fh)
        self.assertEqual((meta['uploaded_by'], meta['os'], 'extra' in meta), ('boss', 'debian-12', False))
        self.assertTrue(os.path.exists(os.path.join(nginxup.base(self.env.cfg), nginxup.REQUEST)))
        self.fake_package()
        st = nginxup.run(self.app, log=lambda m: None)
        self.assertEqual(st['state'], 'untrusted')                     # uploaded through the web: root has not trusted it
        # 0.5.1: an advisory in use: the update is proposed in the same run that found it ready (the job once proposed
        # it with the state of the run before, "no module", and was refused as not ready)
        from jtwafmgr import nginxsec
        page = ('<ul><li><p>Infinite loop in request processing<br>Severity: major<br><a href="https://www.cve.org/'
                'CVERecord?id=CVE-2099-0101">CVE-2099-0101</a><br>Not vulnerable: 1.30.7+<br>Vulnerable: 1.0.0-1.30.6</p></li></ul>')
        saved = nginxsec.fetch
        nginxsec.fetch = lambda get=None, timeout=30: page
        self.addCleanup(setattr, nginxsec, 'fetch', saved)
        self.trusted.add(hashlib.sha256(data).hexdigest())
        st = nginxup.run(self.app, log=lambda m: None)              # the first run that finds it ready
        self.assertEqual(st['state'], 'ready')
        self.assertTrue(st.get('proposed_change'))
        r = self.app.workflow.get(st['proposed_change'])
        self.assertEqual((r['op'], r['proposed_by'], json.loads(r['spec'])['auto']), ('nginx', 'nginxup', True))
        st = json.loads(api_nginxup.update_status(self.app, Req()).body)
        self.assertTrue(st['waiting'][0]['trusted'])
        self.assertEqual(st['check']['state'], 'ready')
        self.assertEqual(st['waiting'][0]['for'], '1.30.7-1~bookworm')
        api_nginxup.update_check(self.app, Req())
        acts = [r[0] for r in self.app.db.q("SELECT action FROM audit WHERE action LIKE 'upload.finished' OR action LIKE 'nginx.%'")]
        self.assertEqual(acts, ['upload.finished', 'nginx.update_check_requested'])


@unittest.skipUnless(os.path.exists('/usr/sbin/nginx') and os.path.exists(MOD), 'no nginx with a ModSecurity module here')
class TestRealNginx(unittest.TestCase):
    def test_try_module(self):
        ok, detail = nginxup.try_module('/usr/sbin/nginx', MOD)
        self.assertTrue(ok, detail)


if __name__ == '__main__':
    unittest.main()
