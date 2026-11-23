"""0.5.36: a site with ModSecurity on that accepts uploads near the host's memory (nginx's ModSecurity module reads a
whole body into memory first) is a warning in the system check."""
import unittest

from jtwafmgr import compliance


class _N:
    def __init__(self, servers):
        self._s = servers

    def servers(self):
        return self._s


class _M:
    def __init__(self, settings):
        self._s = settings

    def setting(self, name, default=None):
        return self._s.get(name, default)


class _App:
    def __init__(self, servers, settings=None):
        n = _N(servers)
        modsec = _M(settings or {})

        class Site:
            def load(self, fresh=False):
                return n, modsec
        self.site = Site()


GB = 1 << 30


class TestUploadMemory(unittest.TestCase):
    def test_sizes(self):
        self.assertEqual(compliance._size_bytes('0'), 0)
        self.assertEqual(compliance._size_bytes('512k'), 512 << 10)
        self.assertEqual(compliance._size_bytes('10M'), 10 << 20)
        self.assertEqual(compliance._size_bytes('2g'), 2 * GB)
        self.assertIsNone(compliance._size_bytes('lots'))

    def test_sites(self):
        app = _App([
            {'server_names': ['nas.example.com'], 'waf': 'on', 'body_limit': '0'},
            {'server_names': ['files.example.com'], 'waf': 'block', 'body_limit': '2g',
             'bypass': [{'location': '^~ /remote.php/dav/', 'file': 'x', 'line': 1}]},
            {'server_names': ['app.example.com'], 'waf': 'on', 'body_limit': '100m'},
            {'server_names': ['www.example.com'], 'waf': 'on', 'body_limit': None},      # nginx's 1m
            {'server_names': ['share.example.com'], 'waf': 'off', 'body_limit': '0'},    # no ModSecurity: streamed
        ])
        it = compliance._check_upload_memory(app, mem=4 * GB)
        self.assertEqual(it['status'], 'warn')
        self.assertEqual(it['details']['sites'], ['nas.example.com: 0',
                                                   'files.example.com: 2g (ModSecurity off: ^~ /remote.php/dav/)'])
        self.assertEqual(it['details']['threshold_mb'], 2048)
        # 0.5.42: the inspected part costs about 7 times its size on top: 500 MB fully inspected is about 4 GB
        whole = compliance._check_upload_memory(_App([{'server_names': ['nas.example.com'], 'waf': 'on', 'body_limit': '500m'}],
                                                     {'SecRequestBodyLimit': str(500 << 20)}), mem=4 * GB)
        self.assertEqual(whole['status'], 'warn')
        part = compliance._check_upload_memory(_App([{'server_names': ['nas.example.com'], 'waf': 'on', 'body_limit': '500m'}]),
                                               mem=4 * GB)
        self.assertEqual(part['status'], 'ok')
        ok = compliance._check_upload_memory(_App([{'server_names': ['a.example.com'], 'waf': 'on', 'body_limit': '50m'}]),
                                             mem=4 * GB)
        self.assertEqual(ok['status'], 'ok')

    def test_body_inspection(self):
        servers = [{'server_names': ['nas.example.com'], 'waf': 'on', 'body_limit': '1g'},
                   {'server_names': ['www.example.com'], 'waf': 'on', 'body_limit': '100k'},   # under 128 KB: nothing to miss
                   {'server_names': ['app.example.com'], 'waf': 'on', 'body_limit': None},
                   {'server_names': ['off.example.com'], 'waf': 'off', 'body_limit': '0'}]
        app = _App(servers, {'SecRequestBodyAccess': 'On', 'SecRuleEngine': 'DetectionOnly'})

        class W:
            class managed:
                rows = []

                @classmethod
                def items(cls):
                    return cls.rows
        app.workflow = W
        it = compliance._check_body_inspection(app)
        self.assertEqual(it['status'], 'warn')
        self.assertEqual(it['details']['sites'], ['nas.example.com: 1g', 'app.example.com: 1m'])
        import json
        W.managed.rows = [{'kind': 'confident_block', 'enabled': 1, 'spec': json.dumps(
            {'target': 'body_unchecked', 'host': {'mode': 'exact', 'value': 'nas.example.com'}, 'exceptions': ['^/up/']})}]
        it = compliance._check_body_inspection(app)
        self.assertEqual(it['details']['sites'], ['app.example.com: 1m'])
        self.assertEqual(it['details']['covered'], ['nas.example.com (except ^/up/)'])
        W.managed.rows[0]['spec'] = json.dumps({'target': 'body_unchecked', 'host': {'mode': 'any'}})
        self.assertEqual(compliance._check_body_inspection(app)['status'], 'ok')
        # the engine On with Reject: ModSecurity refuses such a body itself
        app2 = _App(servers, {'SecRequestBodyAccess': 'On', 'SecRuleEngine': 'On', 'SecRequestBodyLimitAction': 'Reject'})
        W.managed.rows = []
        app2.workflow = W
        self.assertEqual(compliance._check_body_inspection(app2)['status'], 'ok')


if __name__ == '__main__':
    unittest.main()
