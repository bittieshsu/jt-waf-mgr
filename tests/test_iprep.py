"""0.4.94: IP reputation -- public lists matched on this host, Shodan InternetDB and the organisation's MISP asked by
their own job, a verdict with its reasons on the IP lookup. Synthetic addresses and answers only; nothing connects out."""
import json
import os
import time
import unittest
import urllib.error

from jtwafmgr import iprep
from jtwafmgr.app import App
from tests.helpers import TempEnv, jload

LIST_A = b'# comment\n198.51.100.0/24 ; a network\n203.0.113.7\nnot an address\n'
SPAMHAUS = b'{"cidr":"192.0.2.0/25","sblid":"SBL1","rir":"apnic"}\n{"type":"metadata","timestamp":1}\n'


def fake_get(table):
    seen = []

    def get(url, timeout=60, limit=None, headers=None, data=None, ctx=None):
        seen.append(url)
        v = table.get(url)
        if isinstance(v, Exception):
            raise v
        if v is None:
            raise urllib.error.URLError('no route (test)')
        return 200, v
    get.seen = seen
    return get


class TestLists(unittest.TestCase):
    def test_parse_and_match(self):
        self.assertEqual(iprep.parse_list(LIST_A, 'lines'), ['198.51.100.0/24', '203.0.113.7/32'])
        self.assertEqual(iprep.parse_list(SPAMHAUS, 'spamhaus'), ['192.0.2.0/25'])
        r = iprep._Ranges(['198.51.100.0/24', '198.51.100.9', '2001:db8::/48'])
        self.assertEqual((r.find('198.51.100.9'), r.find('198.51.100.255'), r.find('198.51.101.1'), r.find('2001:db8::5')),
                         ('198.51.100.0/24', '198.51.100.0/24', None, '2001:db8::/48'))

    def test_update_keeps_the_last_copy_and_drops_lists_switched_off(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        d = os.path.join(env.dir, 'iprep')
        get = fake_get({iprep.LISTS['cins'][1]: LIST_A, iprep.LISTS['spamhaus_drop'][1]: SPAMHAUS})
        iprep.update_lists(d, ['cins', 'spamhaus_drop', 'tor_exit'], now=1000, log=lambda m: None, get=get)
        man = jload(os.path.join(d, iprep.MANIFEST))
        self.assertEqual((man['cins']['count'], man['spamhaus_drop']['count']), (2, 1))
        self.assertTrue(man['tor_exit']['error'])
        # not due yet: nothing downloaded; due: a failure keeps the copy
        get2 = fake_get({})
        iprep.update_lists(d, ['cins', 'spamhaus_drop'], now=2000, log=lambda m: None, get=get2)
        self.assertEqual(get2.seen, [])
        iprep.update_lists(d, ['cins'], now=1000 + 25 * 3600, log=lambda m: None, get=get2)
        man = jload(os.path.join(d, iprep.MANIFEST))
        self.assertTrue(man['cins']['error'] and man['cins']['count'] == 2)
        self.assertTrue(os.path.exists(os.path.join(d, 'lists', 'cins.txt')))
        self.assertNotIn('spamhaus_drop', man)
        self.assertFalse(os.path.exists(os.path.join(d, 'lists', 'spamhaus_drop.txt')))

    def test_a_list_too_large_is_refused(self):
        with self.assertRaises(iprep.IprepError):
            old = iprep.MAX_ENTRIES
            iprep.MAX_ENTRIES = 1
            try:
                iprep.parse_list(LIST_A, 'lines')
            finally:
                iprep.MAX_ENTRIES = old


class TestOnline(unittest.TestCase):
    def test_internetdb(self):
        body = json.dumps({'ip': '203.0.113.9', 'ports': [22, 80, 'x'], 'tags': ['scanner', 'compromised'],
                           'vulns': ['CVE-2099-0001'], 'hostnames': ['h.example.com'], 'cpes': []}).encode()
        r = iprep.internetdb('203.0.113.9', get=fake_get({'https://internetdb.shodan.io/203.0.113.9': body}))
        self.assertEqual((r['ports'], r['tags'], r['vulns_total']), ([22, 80], ['scanner', 'compromised'], 1))
        nf = urllib.error.HTTPError('https://internetdb.shodan.io/203.0.113.8', 404, 'nf', {}, None)
        self.assertEqual(iprep.internetdb('203.0.113.8', get=fake_get({'https://internetdb.shodan.io/203.0.113.8': nf})),
                         {'none': True})

    def test_misp_feeds_weigh_and_the_key_is_sent(self):
        seen = {}

        def post(url, path, key, body, timeout, ca_file=None, verify=True, pin=None):
            seen.update(url=url, path=path, key=key, body=json.loads(body), pin=pin)
            return json.dumps({'response': {'Attribute': [
                {'event_id': '7', 'to_ids': True, 'timestamp': '1700000000', 'Event': {'id': '7', 'info': 'IPsum level 1'},
                 'Tag': [{'name': 'tlp:white'}]},
                {'event_id': '9', 'to_ids': True, 'timestamp': '1700100000', 'Event': {'id': '9', 'info': 'firehol_level1'}},
                {'event_id': '9', 'to_ids': False, 'timestamp': '1700100001', 'Event': {'id': '9', 'info': 'firehol_level1'}},
            ]}}).encode()
        r = iprep.misp('203.0.113.9', 'https://misp.example.com', 'K' * 40, pin='ab' * 32, post=post)
        self.assertEqual((seen['path'], seen['key'], seen['body']['value'], seen['pin']),
                         ('/attributes/restSearch', 'K' * 40, '203.0.113.9', 'ab' * 32))
        self.assertNotIn('includeContext', seen['body'])
        self.assertEqual((r['count'], r['to_ids'], r['weight'], [e['weight'] for e in r['events']]),
                         (3, 2, 'high', ['high', 'info']))
        self.assertEqual(iprep.misp_weight('IPsum level 3'), 'high')
        self.assertEqual(iprep.misp_weight('Tor exit nodes'), 'info')
        self.assertEqual(iprep.misp_weight('blocklist.de all'), 'medium')
        self.assertEqual(iprep.misp_weight('A hand-made event'), 'medium')

    def test_verdict(self):
        v = iprep.verdict({}, [], {})
        self.assertEqual((v['verdict'], v['reasons']), ('no_record', []))
        self.assertEqual(iprep.verdict({}, [{'list': 'tor_exit', 'name': 'Tor', 'category': 'anonymizer',
                                             'entry': 'x', 'weight': 'info'}], {})['verdict'], 'no_record')
        self.assertEqual(iprep.verdict({'blocked': 3}, [], {})['verdict'], 'suspicious')
        self.assertEqual(iprep.verdict({'blocked': 3, 'recon_block': True}, [], {})['verdict'], 'malicious')
        self.assertEqual(iprep.verdict({}, [], {'internetdb': {'tags': ['compromised']}})['verdict'], 'malicious')
        self.assertEqual(iprep.verdict({}, [], {'misp': {'count': 1, 'events': [
            {'id': '1', 'info': 'IPsum level 1', 'weight': 'info'}]}})['verdict'], 'no_record')


class TestReviewFixes(unittest.TestCase):
    """0.4.94 independent review: odd answers, a key never sent unchecked, bounded runs, overlapping sources."""

    def test_odd_answers_are_the_sources_error_not_the_runs(self):
        for body in (b'{"ports": 5}', b'{"ports": {"a": 1}, "tags": [1, {"x": 2}]}', b'[' * 5000 + b']' * 5000, b'"x"'):
            r = iprep.lookup_online('203.0.113.9', {'internetdb': True},
                                    get=fake_get({'https://internetdb.shodan.io/203.0.113.9': body}))
            self.assertTrue('error' in r['internetdb'] or isinstance(r['internetdb'].get('ports'), list), body[:20])
        for body in ({'response': []}, {'response': {'Attribute': [{'Tag': 5, 'timestamp': 1e20, 'Event': [1]}]}}, 5):
            def post(url, path, key, b, timeout, ca_file=None, verify=True, pin=None, body=body):
                return json.dumps(body).encode()
            r = iprep.lookup_online('203.0.113.9', {'misp_url': 'https://misp.example.com', 'misp_api_key': 'K'}, misp_post=post)
            self.assertIn('misp', r)

    def test_no_certificate_check_without_a_pin_sends_no_key(self):
        sent = []

        def post(*a, **k):
            sent.append(a)
            return b'{}'
        with self.assertRaises(iprep.IprepError):
            iprep.misp('203.0.113.9', 'https://misp.example.com', 'K', verify=False, post=iprep._misp_post)
        r = iprep.lookup_online('203.0.113.9', {'misp_url': 'https://misp.example.com', 'misp_api_key': 'K',
                                                'misp_verify_tls': False})
        self.assertIn('pinned', r['misp']['error'])

    def test_lists_refuse_the_whole_internet_and_keep_adjacent_entries_apart(self):
        self.assertEqual(iprep.parse_list(b'0.0.0.0/0\n::/0\n10.0.0.0/7\n203.0.113.0/24\n', 'lines'), ['203.0.113.0/24'])
        r = iprep._Ranges(['198.51.100.0/25', '198.51.100.128/25'])
        self.assertEqual(r.find('198.51.100.200'), '198.51.100.128/25')

    def test_overlapping_sources_count_once(self):
        cins = {'list': 'cins', 'name': 'CINS', 'category': 'attacker', 'entry': 'x', 'weight': 'medium'}
        bde = dict(cins, list='blocklist_de', name='blocklist.de')
        misp_bde = {'misp': {'count': 1, 'events': [{'id': '1', 'info': 'blocklist.de all', 'weight': 'medium'}]}}
        self.assertEqual(iprep.verdict({}, [cins, bde], misp_bde)['verdict'], 'suspicious')
        self.assertEqual(iprep.verdict({'blocked': 2}, [cins], {})['verdict'], 'malicious')


class TestJobAndApi(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(iprep={'enabled': True, 'lists': ['cins', 'tor_exit'], 'internetdb': True,
                                  'misp_url': 'https://misp.example.com', 'misp_api_key': 'K' * 40})
        self.addCleanup(self.env.cleanup)
        self.app = App(self.env.cfg, start_collector=False)

    def test_lookup_asks_the_job_which_answers(self):
        ip = '203.0.113.7'
        r = self.app.iprep.reputation(ip, {})
        self.assertEqual((r['verdict'], r['pending'], r['lists']), ('no_record', True, []))
        d = self.app.iprep.dir
        self.assertEqual(jload(os.path.join(d, iprep.WANTED)), [ip])
        self.assertTrue(os.path.exists(os.path.join(d, iprep.REQUEST)))
        # an internal or reserved address is never asked about
        self.assertFalse(self.app.iprep.reputation('192.168.77.20', {})['outside'])
        get = fake_get({iprep.LISTS['cins'][1]: LIST_A, iprep.LISTS['tor_exit'][1]: b'198.51.100.200\n',
                        'https://internetdb.shodan.io/' + ip: json.dumps({'tags': ['scanner'], 'ports': [443]}).encode()})

        def post(url, path, key, body, timeout, ca_file=None, verify=True, pin=None):
            return json.dumps({'response': {'Attribute': []}}).encode()
        st = iprep.run(self.app, log=lambda m: None, get=get, misp_post=post)
        self.assertEqual((st['lists'], st['online']), (2, 1))
        self.assertFalse(os.path.exists(os.path.join(d, iprep.REQUEST)))
        r = self.app.iprep.reputation(ip, {'blocked': 2})
        self.assertEqual([h['list'] for h in r['lists']], ['cins'])
        self.assertEqual((r['online']['internetdb']['tags'], r['online']['misp']['count'], r['verdict']),
                         (['scanner'], 0, 'malicious'))           # CINS (medium) + the site's own blocks (medium)
        self.assertEqual([x['source'] for x in r['reasons']], ['site', 'list', 'internetdb'])
        st = self.app.iprep.status()
        self.assertEqual([(x['id'], x['count']) for x in st['lists'] if x['on']], [('cins', 2), ('tor_exit', 1)])

    def test_a_run_is_bounded_and_forgets_what_it_asked(self):
        d = self.app.iprep.dir
        os.makedirs(d, exist_ok=True)
        ips = ['203.0.113.%d' % i for i in range(1, 9)] + ['192.168.77.21', '192.168.77.10']
        with open(os.path.join(d, iprep.WANTED), 'w') as fh:
            json.dump(ips, fh)
        open(os.path.join(d, iprep.REQUEST), 'w').close()
        calls = []

        def get(url, **k):
            calls.append(url)
            raise OSError('timed out')

        def post(*a, **k):
            raise OSError('timed out')
        st = iprep.run(self.app, log=lambda m: None, get=get, misp_post=post)
        # internal addresses are never sent; a source failing three times in a row is left alone for the run
        self.assertEqual(sum(1 for u in calls if 'internetdb' in u), iprep.SOURCE_FAILS)
        self.assertTrue(all('192.168.77.21' not in u and '192.168.77.10' not in u for u in calls))
        self.assertEqual(st['online'], 8)
        self.assertFalse(os.path.exists(os.path.join(d, iprep.REQUEST)))
        self.assertEqual(jload(os.path.join(d, iprep.WANTED)), ['192.168.77.21', '192.168.77.10'])
        # an error is asked again after an hour, not a day
        self.assertTrue(iprep._due(jload(os.path.join(d, iprep.ONLINE))['203.0.113.1'], time.time() + 3700))
        # the time limit
        with open(os.path.join(d, iprep.WANTED), 'w') as fh:
            json.dump(['198.51.100.%d' % i for i in range(1, 6)], fh)
        t = iter(range(0, 10000, 300))
        st = iprep.run(self.app, log=lambda m: None, get=fake_get({}), misp_post=post, clock=lambda: next(t))
        self.assertEqual((st['stopped'], st['online']), ('time', 1))   # 300 s in: one; 600 s: past the limit

    def test_a_token_reads_but_never_queues(self):
        r = self.app.iprep.reputation('203.0.113.7', {}, ask=False)
        self.assertEqual(r['pending'], False)
        self.assertFalse(os.path.exists(os.path.join(self.app.iprep.dir, iprep.WANTED)))

    def test_switched_off_does_nothing(self):
        self.app.cfg['iprep']['enabled'] = False
        r = self.app.iprep.reputation('203.0.113.7', {})
        self.assertEqual((r['enabled'], r['lists'], r['pending']), (False, [], False))
        self.assertFalse(os.path.exists(os.path.join(self.app.iprep.dir, iprep.WANTED)))
        st = iprep.run(self.app, log=lambda m: None, get=fake_get({}))
        self.assertNotIn('lists', st)

    def test_api(self):
        from jtwafmgr import auth
        from jtwafmgr.web.server import start_background
        from tests.test_api import Client
        self.app.auth.create_user('v1', 'viewer', password='a long test password')
        self.app.auth.create_user('a1', 'admin', password='a long test password')
        secret, _ = self.app.auth.totp_setup('a1')
        self.app.auth.totp_enable('a1', auth.totp_code(secret, int(time.time() // 30)))
        srv, _ = start_background(self.app)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = Client(srv.server_address[1])
        self.assertEqual(c.login('v1', 'a long test password')[0], 200)
        st, body, _ = c.req('GET', '/api/v1/lookups/ip/203.0.113.7')
        self.assertEqual((st, body['reputation']['verdict'], body['reputation']['pending']), (200, 'no_record', True))
        st, body, _ = c.req('GET', '/api/v1/lookups/ip/203.0.113.7/card')
        self.assertEqual((st, body['reputation']['verdict']), (200, 'no_record'))
        st, body, _ = c.req('GET', '/api/v1/iprep/status')
        self.assertEqual((st, body['enabled'], len(body['lists'])), (200, True, len(iprep.LISTS)))
        self.assertEqual(c.req('POST', '/api/v1/iprep/update', {})[0], 403)
        self.app.db.x('UPDATE users SET totp_last_step=0')
        c2 = Client(srv.server_address[1])
        self.assertEqual(c2.login('a1', 'a long test password', totp=auth.totp_code(secret, int(time.time() // 30)))[0], 200)
        st, body, _ = c2.req('POST', '/api/v1/iprep/update', {})
        self.assertEqual((st, body['requested']), (202, True))
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='iprep.update_requested'"))


if __name__ == '__main__':
    unittest.main()
