"""Reading versions and guessing applications from the sites themselves (synthetic answers, no network): versions in
parts, in a header of any answer, Roundcube's number; a 403 at 127.0.0.1 asked again at the local address; the home
page signatures in the guess (tests/fixtures/site: app.example.com, intranet.example.com, intra.example.com on 443)."""
import json
import unittest

from jtwafmgr import software
from jtwafmgr.app import App
from tests.helpers import TempEnv


class TestVersionForms(unittest.TestCase):
    def test_parts_any_status_and_roundcube(self):
        ev = software.extract_version
        self.assertEqual(ev({'json_parts': ['major', 'minor', 'patch']}, 200, {}, b'{"major":1,"minor":118,"patch":2}'), '1.118.2')
        self.assertIsNone(ev({'json_parts': ['major', 'minor', 'patch']}, 200, {}, b'{"major":1,"minor":118}'))
        self.assertIsNone(ev({'json_parts': ['a', 'b']}, 200, {}, b'{"a":true,"b":1}'))
        self.assertEqual(ev({'json_parts': ['version.major', 'version.minor', 'version.revision']}, 200, {},
                            b'{"version":{"major":2,"minor":12,"revision":1}}'), '2.12.1')
        # a header every answer carries: read whatever the status, only when asked to
        self.assertEqual(ev({'header': 'X-Version', 'any_status': True}, 401, {'x-version': '2.13.5'}, b''), '2.13.5')
        self.assertIsNone(ev({'header': 'X-Version'}, 401, {'x-version': '2.13.5'}, b''))
        self.assertEqual(ev({'header': 'X-Influxdb-Version', 'regex': r'v?([0-9]+(?:\.[0-9]+)*)', 'any_status': True}, 204,
                            {'x-influxdb-version': 'v2.7.10'}, b''), '2.7.10')
        rc = {'regex': r'"rcversion":\s*([0-9]+)', 'convert': 'roundcube'}
        self.assertEqual(ev(rc, 200, {}, b'rcmail.set_env({"rcversion":10605,"x":1})'), '1.6.5')
        self.assertIsNone(ev(rc, 200, {}, b'"rcversion":7'))
        self.assertEqual(ev({'regex': r'MediaWiki ([0-9]+(?:\.[0-9]+)*)', 'json': 'query.general.generator'}, 200, {},
                            b'{"query":{"general":{"generator":"MediaWiki 1.42.3"}}}'), '1.42.3')

    def test_every_source_is_well_formed(self):
        src = software.version_sources()
        self.assertGreaterEqual(len(src['auto']), 60)
        names = {n for n, _rx in software.SIGNATURES}
        seen = set()
        for p in src['auto']:
            self.assertIn(p['name'], names)
            self.assertNotIn(p['name'], seen)
            seen.add(p['name'])
            self.assertTrue(p['path'].startswith('/'), p)
            self.assertTrue(any(k in p for k in ('json', 'json_parts', 'header', 'regex')), p)
            if 'regex' in p:
                import re
                self.assertEqual(re.compile(p['regex']).groups >= 1, True, p)


class TestLanRetry(unittest.TestCase):
    def test_403_is_asked_again_at_the_local_address(self):
        calls = []
        real = software._fetch_at

        def fake(addr, host, probe, timeout, token):
            calls.append(addr)
            return (403, {}, b'') if addr == '127.0.0.1' else (200, {}, b'{"zulip_version":"10.4"}')
        software._fetch_at = fake
        try:
            got = software.fetch_local('chat.example.com', {'path': '/api/v1/server_settings'}, lan='198.51.100.10')
            self.assertEqual((got[0], calls), (200, ['127.0.0.1', '198.51.100.10']))
            calls.clear()
            self.assertEqual(software.fetch_local('chat.example.com', {'path': '/x'}, lan='')[0], 403)   # no local address
            self.assertEqual(calls, ['127.0.0.1'])
        finally:
            software._fetch_at = real
        a = software.lan_address()
        self.assertTrue(a is None or not a.startswith('127.'))


class TestHomepageGuess(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def test_sites_and_pages(self):
        sites = software.homepage_sites(self.app)
        self.assertIn('app.example.com', sites)
        self.assertNotIn('static.example.com', sites)            # port 80 only
        pages = {
            ('app.example.com', '/'): (302, {'location': '/login?next=%2F'}, b''),
            ('app.example.com', '/login?next=%2F'): (200, {}, b'<html><head><title>Grafana</title></head></html>'),
            ('intranet.example.com', '/'): (301, {'location': 'https://elsewhere.example.net/'}, b''),
            ('intra.example.com', '/'): (200, {'x-jenkins': '2.479.1'}, b'<title>Dashboard [Jenkins]</title>'),
        }

        def fetch(host, probe, timeout=6, token=None):
            return pages.get((host, probe['path']))
        found = software.guess_homepages(self.app, sites, fetch=fetch)
        self.assertEqual(found, {'Grafana': ['app.example.com'], 'Jenkins': ['intra.example.com']})
        out = software.refresh(self.app, 'alice', fetch=fetch)
        self.assertGreaterEqual(out['added'], 2)
        rows = {r['name']: r for r in software.listing(self.app.db)}
        self.assertEqual(rows['Grafana']['hosts'], ['app.example.com'])
        self.assertEqual(rows['Grafana']['evidence'], 'homepage: app.example.com')
        self.assertFalse(rows['Grafana']['confirmed'])                    # a guess: a person confirms
        self.assertEqual(json.loads(json.dumps(rows['Jenkins']['hosts'])), ['intra.example.com'])


if __name__ == '__main__':
    unittest.main()
