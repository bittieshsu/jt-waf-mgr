"""Synology DSM sites (0.5.33): the packages a DSM site serves, from its API list (SYNO.API.Info answers without a
login) and from the api= of its requests; the TLS port of a site that is not on 443 (DSM on 5001). Synthetic answers,
no network."""
import json
import unittest

from jtwafmgr import software
from jtwafmgr.app import App
from tests.helpers import TempEnv

INFO = {'success': True, 'data': {
    'SYNO.API.Info': {}, 'SYNO.API.Auth': {}, 'SYNO.Core.User': {}, 'SYNO.FileStation.List': {},
    'SYNO.Foto.Browse.Item': {}, 'SYNO.FotoTeam.Browse.Item': {}, 'SYNO.SurveillanceStation.Camera': {},
    'SYNO.SynologyDrive.Files': {}, 'SYNO.DownloadStation2.Task': {}, 'SYNO.NoteStation.Note': {}}}


class _Site:
    def __init__(self, servers):
        self._servers = servers

    def load(self, fresh=False):
        site = self

        class N:
            def servers(self):
                return site._servers
        return N(), None


class _App:
    def __init__(self, servers):
        self.site = _Site(servers)


class TestSynologyPackages(unittest.TestCase):
    def test_api_names(self):
        self.assertEqual(software.synology_package('SYNO.Foto.Browse.Item'), 'Synology Photos')
        self.assertEqual(software.synology_package('SYNO.FotoTeam.Browse.Item'), 'Synology Photos')
        self.assertEqual(software.synology_package('SYNO.DownloadStation2.Task'), 'Synology Download Station')
        self.assertIsNone(software.synology_package('SYNO.Core.User'))          # DSM itself
        self.assertIsNone(software.synology_package('SYNO.Fotos'))              # a prefix is a whole name part

    def test_info_answer(self):
        seen = []

        def fetch(host, probe, timeout=6, token=None):
            seen.append((host, probe['path'], probe.get('port')))
            return 200, {}, json.dumps(INFO).encode()
        got = software.synology_packages('nas.example.com', fetch, 5001)
        self.assertEqual(seen, [('nas.example.com', software.SYNOLOGY_INFO, 5001)])
        self.assertEqual(sorted(got), ['Synology Download Station', 'Synology Drive Server', 'Synology Note Station',
                                       'Synology Photos', 'Synology Surveillance Station'])
        self.assertEqual(sorted(got['Synology Photos']), ['SYNO.Foto.Browse.Item', 'SYNO.FotoTeam.Browse.Item'])
        for bad in (None, (403, {}, b''), (200, {}, b'<html>'), (200, {}, b'{"data": []}')):
            self.assertEqual(software.synology_packages('nas.example.com', lambda *a, **k: bad), {})

    def test_ports(self):
        app = _App([
            {'listen': ['5001 ssl', '[::]:5001 ssl'], 'server_names': ['nas.example.com']},
            {'listen': ['443 ssl'], 'server_names': ['app.example.com']},
            {'listen': ['12443 ssl', '443 ssl'], 'server_names': ['both.example.com']},
            {'listen': ['80'], 'server_names': ['plain.example.com']},
            {'listen': ['192.0.2.10:8443 ssl'], 'server_names': ['other.example.com']},
        ])
        self.assertEqual(software.site_ports(app), {'nas.example.com': 5001, 'other.example.com': 8443})

    def test_fetch_uses_the_port(self):
        import socket
        calls = []
        real = socket.create_connection

        def fake(addr, timeout=None):
            calls.append(addr)
            raise OSError('no')
        socket.create_connection = fake
        was = software.OFFLINE
        software.OFFLINE = False
        try:
            self.assertIsNone(software._fetch_at('127.0.0.1', 'nas.example.com', {'path': '/', 'port': 5001}, 1, None))
            self.assertIsNone(software._fetch_at('127.0.0.1', 'app.example.com', {'path': '/'}, 1, None))
        finally:
            socket.create_connection = real
            software.OFFLINE = was
        self.assertEqual(calls, [('127.0.0.1', 5001), ('127.0.0.1', 443)])


class TestSynologyGuess(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def test_dsm_site_lists_its_packages(self):
        real = (software.homepage_sites, software.site_ports, software.scan_logs)
        software.homepage_sites = lambda app: ['nas.example.com']
        software.site_ports = lambda app: {'nas.example.com': 5001}
        software.scan_logs = lambda cfg, exclude=(): {'Synology Audio Station': {'nas.example.com': 4}}
        pages = {'/': (200, {}, b'<title>nas&nbsp;-&nbsp;Synology&nbsp;DiskStation</title>'),
                 software.SYNOLOGY_INFO: (200, {}, json.dumps(INFO).encode())}
        asked = []

        def fetch(host, probe, timeout=6, token=None):
            asked.append(probe.get('port'))
            return pages.get(probe['path']) if host == 'nas.example.com' else None
        try:
            out = {r['name']: r for r in software.guess(self.app, fetch=fetch) if r['kind'] == 'site'}
        finally:
            software.homepage_sites, software.site_ports, software.scan_logs = real
        self.assertEqual(set(asked), {5001})
        self.assertEqual(out['Synology DSM']['hosts'], ['nas.example.com'])
        self.assertEqual(out['Synology Photos']['hosts'], ['nas.example.com'])
        self.assertEqual(out['Synology Photos']['evidence'], 'SYNO.API.Info: nas.example.com')
        self.assertEqual(out['Synology Audio Station']['evidence'], 'nas.example.com 4')   # from its requests
        self.assertNotIn('Synology Calendar', out)


class TestSynologyLogs(unittest.TestCase):
    def test_api_requests_count_for_the_package(self):
        line = '192.0.2.5 - - [22/Nov/2026:01:00:00 +0800] "GET /webapi/entry.cgi?api=SYNO.Foto.Browse.Item&method=list HTTP/1.1" 200 12 "-" "-"'
        m = software._API_RE.search(software._path_of(line)[1])
        self.assertEqual(software.synology_package(m.group(1)), 'Synology Photos')


if __name__ == '__main__':
    unittest.main()


class TestArgTarget(unittest.TestCase):
    """0.5.33: a confident block on the value of one named parameter (DSM's api=), phase 2, like arg_name."""
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def test_rule_text(self):
        from jtwafmgr import rulegen
        norm, text, placement = rulegen.build('confident_block', {
            'target': 'arg', 'arg': 'api', 'regex': r'^syno\.core\.', 'msg': 'DSM admin API from outside',
            'host': {'mode': 'exact', 'value': 'nas.example.com'}}, 10280, self.app.cfg)
        self.assertEqual(norm['arg'], 'api')
        self.assertTrue(text.startswith('SecRule ARGS:api "@rx ^syno\\.core\\."'))
        self.assertIn('phase:2', text)
        self.assertIn('t:none,t:lowercase', text)
        self.assertIn('arg', rulegen.BODY_TARGETS)
        for bad in ('', 'a b', 'x' * 70, None, 5, 'api|', '|api', '-x', '|'.join('abcdefghijklm'), 'api:x', '/^a/'):
            with self.assertRaises(rulegen.SpecError):
                rulegen.build('confident_block', {'target': 'arg', 'arg': bad, 'regex': '^x', 'msg': 'x'}, 10280, self.app.cfg)
        n2, _, _ = rulegen.build('confident_block', {'target': 'arg', 'arg': 'json.api', 'regex': '^x', 'msg': 'x'}, 10280,
                                 self.app.cfg)
        self.assertEqual(n2['arg'], 'json.api')
        _, t4, _ = rulegen.build('confident_block', {'target': 'arg', 'arg': 'api|compound', 'regex': 'x', 'msg': 'x'}, 10280,
                                 self.app.cfg)
        self.assertTrue(t4.startswith('SecRule ARGS:api|ARGS:compound "@rx x"'))
        n3, _, _ = rulegen.build('confident_block', {'target': 'path', 'regex': '^/x', 'msg': 'x', 'arg': 'api'}, 10280,
                                 self.app.cfg)
        self.assertNotIn('arg', n3)                  # only the arg target keeps it

    def test_evidence_skips_it(self):
        from jtwafmgr.evidence import Evidence
        self.assertIsNone(Evidence.rule_view({'target': 'arg', 'arg': 'api', 'regex': '^x'}))


class TestDsmVersion(unittest.TestCase):
    def test_info_cgi(self):
        p = [x for x in software.version_sources()['auto'] if x['name'] == 'Synology DSM'][0]
        body = (b"<html> <script type='text/javascript'>parent.location = 'http://find.synology.com#major=7&minor=4&"
                b"build=90080&junior=0&unique=synology_x&sn=EXAMPLE'</script> </html>")
        self.assertEqual(software.extract_version(p, 200, {}, body), '7.4-90080')
        self.assertIsNone(software.extract_version(p, 200, {}, b'<html>no version</html>'))
        self.assertIsNone(software.extract_version(dict(p, regex_format='{0}.{5}'), 200, {}, body))   # no such group
