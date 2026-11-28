"""0.5.49: the reverse proxy examples on the project page (docs/proxy.html) are what the sites page's generator writes
now (tools/make_proxy_examples.py --check), and use example names and addresses only."""
import importlib.util
import os
import re
import unittest

TOP = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAGE = os.path.join(TOP, 'docs', 'proxy.html')
TOOL = os.path.join(TOP, 'tools', 'make_proxy_examples.py')


@unittest.skipUnless(os.path.exists(PAGE) and os.path.exists(TOOL), 'the project page is not in this tree')
class TestProxyExamples(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('make_proxy_examples', TOOL)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        with open(PAGE, encoding='utf-8') as fh:
            self.page = fh.read()

    def test_page_matches_generator(self):
        self.assertEqual(self.m.render(self.page), self.page,
                         'docs/proxy.html differs from the generator: run tools/make_proxy_examples.py')

    def test_every_example_and_synthetic_values(self):
        ex = self.m.examples()
        self.assertEqual([e[0] for e in ex], ['ex-generic', 'ex-websocket', 'ex-synology', 'ex-qnap'])
        for eid, path, text in ex:
            self.assertIn('id="%s"' % eid, self.page)
            self.assertTrue(path.startswith('/etc/nginx/sites-available/') and path.endswith('.example.com.conf'), path)
            for host in re.findall(r'^\s*server_name (\S+);', text, re.M):
                self.assertTrue(host.endswith('.example.com'), host)
            for addr in re.findall(r'proxy_pass https?://([0-9.]+):', text):
                self.assertTrue(addr.startswith(('192.0.2.', '198.51.100.', '127.0.0.1')), addr)
        syno = dict((e[0], e[2]) for e in ex)['ex-synology']
        self.assertIn('proxy_set_header Host $host:$server_port;', syno)   # off port 443 the port is kept
        self.assertIn('ssl_reject_handshake on;', syno)


if __name__ == '__main__':
    unittest.main()
