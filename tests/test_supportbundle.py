"""0.5.48: the support bundle (supportbundle.py) -- what goes in, pseudonyms, limits, nothing secret. Synthetic data."""
import io
import json
import unittest
import zipfile

from jtwafmgr import supportbundle, util
from jtwafmgr.app import App
from tests.helpers import TempEnv


class TestBundle(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.app = App(self.env.cfg)
        self.addCleanup(self.app.stop)
        self.n = 0

    def event(self, ip, host='app.example.com', outcome='blocked', rules=',942100,949110,', ago=60):
        self.n += 1
        matches = [{'rule_id': 942100, 'message': 'SQL Injection Attack Detected via libinjection',
                    'data': 'Matched Data: s&sos found within ARGS:id: 1 union select', 'match': 'from %s' % ip}]
        self.app.db.x('INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, status, outcome, '
                      'rule_ids, local_rule_ids, families, message, matches) VALUES '
                      "('n1', ?, ?, ?, 'GET', '/search', 'id=1', ?, ?, 403, ?, ?, ',,', ',sqli,', 'SQL Injection', ?)",
                      ('%s-%d' % (host, self.n), util.now() - ago, host, ip,
                       'internal' if ip.startswith('192.168.') else 'external', outcome, rules, json.dumps(matches)))

    def files(self, data):
        z = zipfile.ZipFile(io.BytesIO(data))
        return {n.split('/', 1)[1]: z.read(n).decode('utf-8') for n in z.namelist()}

    def test_contents_and_pseudonyms(self):
        self.event('203.0.113.7')
        self.event('203.0.113.70')
        self.event('192.168.77.3', outcome='logged')
        data, info = supportbundle.build(self.app, None, None, 'alice')
        f = self.files(data)
        for name in ('README.txt', 'manifest.json', 'events.ndjson', 'rules.json', 'modsecurity.json',
                     'system-check.json', 'changes.json', 'software.json'):
            self.assertIn(name, f)
        self.assertEqual(info['events'], 3)
        events = [json.loads(x) for x in f['events.ndjson'].splitlines()]
        self.assertEqual(len(events), 3)
        ips = {e['src_ip'] for e in events}
        self.assertTrue(all(i.startswith('ip-') for i in ips), ips)
        self.assertEqual(len(ips), 3)                                       # each address its own name
        self.assertTrue(any(i.endswith('-internal') for i in ips))
        whole = ''.join(f.values())
        for raw in ('203.0.113.7', '203.0.113.70', '192.168.77.3'):
            self.assertNotIn(raw, whole)                                    # also inside the match data
        self.assertIn('app.example.com', whole)                             # site names kept by default
        rules = json.loads(f['rules.json'])
        self.assertIn(942100, [r['id'] for r in rules])
        m = json.loads(f['manifest.json'])
        self.assertEqual(m['pseudonymised'], {'source_addresses': True, 'site_names': False})
        self.assertEqual(set(m['files']), set(f) - {'manifest.json', 'README.txt'})
        self.assertTrue(info['name'].endswith('.zip'))
        for secret in ('api_key', 'license_key', 'password_hash', 'totp_secret'):
            self.assertNotIn('"%s"' % secret, whole)

    def test_hide_hosts_and_filters(self):
        self.event('203.0.113.7')
        self.event('203.0.113.8', host='other.example.com')
        self.event('203.0.113.9', outcome='logged')
        data, info = supportbundle.build(self.app, None, None, 'alice', outcome='blocked', anon_hosts=True,
                                         host='app.example.com')
        f = self.files(data)
        self.assertEqual(info['events'], 1)
        self.assertNotIn('app.example.com', ''.join(f.values()))
        e = json.loads(f['events.ndjson'].splitlines()[0])
        self.assertEqual(e['host'], 'site-1.invalid')
        data, info = supportbundle.build(self.app, None, None, 'alice', anon_ips=False, src_ip='203.0.113.0/30')
        self.assertEqual(info['events'], 0)
        data, info = supportbundle.build(self.app, None, None, 'alice', anon_ips=False, src_ip='203.0.113.8/32')
        self.assertIn('203.0.113.8', self.files(data)['events.ndjson'])

    def test_limits(self):
        now = util.now()
        with self.assertRaises(supportbundle.BundleError) as e:
            supportbundle.build(self.app, now - 40 * 86400, now, 'alice')
        self.assertEqual(e.exception.code, 'range_too_long')
        with self.assertRaises(supportbundle.BundleError):
            supportbundle.build(self.app, now, now - 10, 'alice')
        with self.assertRaises(supportbundle.BundleError):
            supportbundle.build(self.app, None, None, 'alice', src_ip='not-an-address')
        self.event('203.0.113.7', ago=3 * 86400)                            # outside the default 24 hours
        self.assertEqual(supportbundle.build(self.app, None, None, 'alice')[1]['events'], 0)


if __name__ == '__main__':
    unittest.main()
