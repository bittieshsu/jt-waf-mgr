"""0.5.36: a site with ModSecurity on that accepts uploads near the host's memory (nginx's ModSecurity module reads a
whole body into memory first) is a warning in the system check."""
import unittest

from jtwafmgr import compliance


class _N:
    def __init__(self, servers):
        self._s = servers

    def servers(self):
        return self._s


class _App:
    def __init__(self, servers):
        n = _N(servers)

        class Site:
            def load(self, fresh=False):
                return n, None
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
        self.assertEqual(it['details']['threshold_mb'], 1024)
        ok = compliance._check_upload_memory(_App([{'server_names': ['a.example.com'], 'waf': 'on', 'body_limit': '50m'}]),
                                             mem=4 * GB)
        self.assertEqual(ok['status'], 'ok')


if __name__ == '__main__':
    unittest.main()
