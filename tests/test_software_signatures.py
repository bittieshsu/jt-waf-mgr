"""The software guess data (jtwafmgr/data/software-signatures.json): every signature is valid, its sample paths
are guessed as it (the first match wins, so a too-wide signature above another shows up here), and common paths
that any site answers are guessed as nothing."""
import collections
import json
import re
import unittest

from jtwafmgr import software

# paths many unrelated sites answer with 200: none of them may name an application
COMMON = [
    '/', '/index.html', '/favicon.ico', '/robots.txt', '/sitemap.xml', '/manifest.json', '/service-worker.js',
    '/login', '/logout', '/admin', '/admin/', '/admin/home', '/dashboard', '/dashboard/', '/Dashboard', '/management',
    '/user/login', '/login/index.php', '/php/login.php', '/search?q=a', '/graphql', '/websocket', '/client', '/messages',
    '/health', '/healthz', '/.well-known/acme-challenge/x', '/.env', '/config.json', '/bootstrap.js', '/script.js',
    '/js/app.js', '/js/script.js', '/css/site.css', '/images/a.png', '/static/js/main.js', '/assets/app.css',
    '/assets/index.js', '/assets/index-abc123.js', '/web/index.html', '/app/home', '/browser/', '/coolapp', '/jobs/',
    '/overview.html', '/xterm/', '/flows', '/hardware', '/bookmarks', '/repository/x/', '/en/', '/zh-TW/', '/news/2026/11/a',
    '/socket.io/?EIO=4&transport=polling', '/rest/api',
    '/api/', '/api/health', '/api/login', '/api/users', '/api/config', '/api/status', '/api/status-check', '/api/stats',
    '/api/tags', '/api/version', '/api/sessions', '/api/items', '/api/system/info', '/api/tokens', '/api/self', '/api/auth',
    '/api/queries', '/api/chat', '/api/events', '/api/resources', '/api/swagger', '/api/v2/users', '/v1/users', '/v1/alerts',
    '/api/v1/', '/api/v1/users', '/api/v1/status', '/api/v1/settings', '/api/v1/models', '/api/v1/accounts',
    '/api/v1/session', '/api/v1/version', '/api/v1/info', '/api/v1/data', '/api/v1/media', '/api/v1/notifications',
    '/api/v1/rules', '/api/v1/series', '/api/v1/login/x',
    '/api/v1/messages', '/api/v1/messages/flags', '/api/v1/messages?anchor=1',      # Zulip's API, not Rocket.Chat
    '/Microsoft-Server-ActiveSync?Cmd=Sync',   # Exchange, Z-Push, Zimbra, Kerio ... all answer ActiveSync
    '/Autodiscover/Autodiscover.xml',
]
GENERIC = {'PHP', 'Microsoft IIS / ASP.NET', 'Java Servlet / JSP', 'Adobe ColdFusion'}


def first(path):
    for name, rx in software._SIGS:
        if rx.search(path):
            return name
    return None


class TestSignatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(software.SIGNATURE_FILE, encoding='utf-8') as fh:
            cls.data = json.load(fh)

    def test_loaded(self):
        self.assertEqual(len(software.SIGNATURES), len(self.data['signatures']))
        self.assertGreaterEqual(len(software.SIGNATURES), 300)
        self.assertGreaterEqual(len(set(software.PACKAGES.values())), 40)
        self.assertNotIn('libc6', software.PACKAGES)                        # web-related software only

    def test_names(self):
        names = [n for n, _rx, _s in self.data['signatures']]
        self.assertEqual([n for n, c in collections.Counter(names).items() if c > 1], [])
        for n in names + list(self.data['packages'].values()) + [n for _rx, n in self.data['package_patterns']]:
            self.assertRegex(n, software.NAME_RE)     # a person could save the same name by hand

    def test_samples_are_guessed_as_their_application(self):
        wrong = []
        for name, rx, samples in self.data['signatures']:
            re.compile(rx)
            self.assertTrue(samples, name)
            wrong += [(p, name, first(p)) for p in samples if first(p) != name]
        self.assertEqual(wrong, [])

    def test_common_paths_name_nothing(self):
        wrong = [(p, first(p)) for p in COMMON if first(p) and not (first(p) == 'PHP' and p.split('?')[0].endswith('.php'))]
        self.assertEqual(wrong, [])

    def test_generic_technologies_come_last(self):
        names = [n for n, _rx in software.SIGNATURES]
        self.assertEqual(set(names[-len(GENERIC):]), GENERIC)
        self.assertEqual(first('/wp-content/a.css'), 'WordPress')       # not PHP
        self.assertEqual(first('/owa/auth/logon.aspx'), 'Exchange (OWA)')   # not ASP.NET

    def test_packages(self):
        self.assertEqual(software.product_of('nginx-core'), 'nginx')
        self.assertEqual(software.product_of('php8.2-fpm'), 'PHP')
        self.assertIsNone(software.product_of('postgresql-15'))               # not web-facing
        self.assertEqual(software.product_of('openjdk-17-jre-headless'), 'OpenJDK')
        self.assertIsNone(software.product_of('php8.2-fpm-extra'))
        self.assertIsNone(software.product_of('fonts-dejavu'))


if __name__ == '__main__':
    unittest.main()
