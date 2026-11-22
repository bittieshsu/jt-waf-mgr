"""0.5.39: a site's server block read as nginx has it (masked, only blocks nginx loads) and an example block for a new
site (validated answers; nothing written). Synthetic data only."""
import unittest

from jtwafmgr import vhostconf
from jtwafmgr.app import App
from tests.helpers import TempEnv

CONF = '''# a comment with a brace {
server {
    listen 443 ssl;
    server_name app.example.com;
    set $x "a } brace in quotes";
    proxy_set_header Authorization "Bearer abcdefabcdefabcdefabcdefabcdefabcdefabcdef";
    location / { proxy_pass http://192.0.2.10; }   # } in a comment
}
server { listen 80; }
'''


class TestBlock(unittest.TestCase):
    def test_block_text(self):
        b = vhostconf.block_text(CONF, 2)
        self.assertTrue(b.startswith('server {') and b.rstrip().endswith('}'))
        self.assertIn('location / { proxy_pass', b)
        self.assertNotIn('listen 80', b)
        self.assertEqual(vhostconf.block_text(CONF, 9), 'server { listen 80; }')
        self.assertIsNone(vhostconf.block_text(CONF, 3))            # not where a block starts
        self.assertIsNone(vhostconf.block_text(CONF, 99))
        self.assertIsNone(vhostconf.block_text('server {\n  listen 1;\n', 1))   # never closed

    def test_site_block_only_loaded_sites(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        app = App(env.cfg)
        self.addCleanup(app.db.release)
        n, _ = app.site.load()
        s = n.servers()[0]
        got = vhostconf.site_block(app, s['file'], s['line'])
        self.assertTrue(got['text'].lstrip().startswith('server'))
        for path, line in (('/etc/passwd', 1), (s['file'], s['line'] + 1)):
            with self.assertRaises(vhostconf.VhostError):
                vhostconf.site_block(app, path, line)


class TestExample(unittest.TestCase):
    OK = {'host': 'nas.example.com', 'backend': 'https://192.0.2.18:5001', 'cert': '/etc/ssl/example/fullchain.pem',
          'key': '/etc/ssl/example/key.pem'}

    def test_synology(self):
        o = vhostconf.example(dict(self.OK, preset='synology'), ['192.168.0.0/16'], mem_bytes=4 << 30)
        t = o['text']
        self.assertIn('listen 5001 ssl;', t)
        self.assertIn('ssl_reject_handshake on;', t)                 # a port of its own: guessed names refused
        self.assertIn('X-Forwarded-For $remote_addr', t)
        self.assertIn('proxy_request_buffering off;', t)
        self.assertIn('client_max_body_size 1g;', t)
        self.assertIn('allow 192.168.0.0/16;', t)
        self.assertNotIn('modsecurity', t.lower().replace('# modsecurity', ''))   # switched on from the sites page
        self.assertNotIn('listen 80', t)                               # no port 80 redirect off port 443
        self.assertFalse(o['big_upload'])
        self.assertEqual(o['path'], '/etc/nginx/sites-available/nas.example.com.conf')

    def test_generic_and_limits(self):
        o = vhostconf.example(dict(self.OK, backend='http://192.0.2.20:8080', upload='0', internal_only=False), [],
                              mem_bytes=4 << 30)
        self.assertIn('listen 443 ssl;', o['text'])
        self.assertIn('return 301 https://$host$request_uri;', o['text'])
        self.assertNotIn('deny all', o['text'])
        self.assertNotIn('ssl_reject_handshake', o['text'])
        self.assertTrue(o['big_upload'])
        self.assertIn('NOTE: with ModSecurity on', o['text'])

    def test_refused(self):
        for bad, field in (({'host': 'bad host'}, 'host'), ({'host': 'x'}, 'host'), ({'port': '80'}, 'port'),
                           ({'port': '70000'}, 'port'), ({'backend': 'ftp://192.0.2.1'}, 'backend'),
                           ({'backend': 'http://u:p@192.0.2.1'}, 'backend'), ({'backend': 'http://192.0.2.1/x'}, 'backend'),
                           ({'upload': '5t'}, 'upload'), ({'cert': 'relative.pem'}, 'cert'),
                           ({'key': '/etc/ssl/k;evil'}, 'cert'), ({'preset': 'other'}, 'preset'),
                           ({'host': 'a.example.com;\n}'}, 'host')):
            with self.assertRaises(vhostconf.VhostError) as e:
                vhostconf.example(dict(self.OK, **bad))
            self.assertEqual(e.exception.field, field, bad)


if __name__ == '__main__':
    unittest.main()
