"""The war room API (api_warroom.py): what a wall may show, and nothing else."""
import json
import time
import unittest

from jtwafmgr.app import App
from jtwafmgr.collector.auditlog import Tailer
from jtwafmgr.web import api_warroom
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv, record
from tests.test_api import PW, Client


class TestWarRoom(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = TempEnv()
        cls.app = App(cls.env.cfg)
        cls.app.auth.create_user('viewer1', 'viewer', password=PW)
        now = time.time()
        cls.env.write_log([
            record(host='app.example.com', uri='/.env?token=secret1', ip='203.0.113.7', status=403, engine='Enabled',
                   rules=[10205], ts=now - 120),
            record(host='intranet.example.com', uri='/admin/x', ip='198.51.100.9', status=200, ts=now - 60),
            record(host='app.example.com', uri='/search?q=1', ip='192.168.77.50', status=200, ts=now - 30),
            record(host='app.example.com', uri='/old', ip='203.0.113.8', status=403, engine='Enabled', rules=[10205],
                   ts=now - 3 * 3600),
            record(host='made-up-by-an-outsider.example.org', uri='/x', ip='203.0.113.9', status=200, ts=now - 20),
        ])
        cls.app.tailer = Tailer(cls.env.cfg, cls.app.db)
        cls.app.tailer.poll()
        cls.srv, _ = start_background(cls.app)
        cls.port = cls.srv.server_address[1]
        api_warroom.CACHE_SECONDS = 0
        api_warroom._alias.update(at=0.0, map=None)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.app.stop()
        cls.env.cleanup()

    def viewer(self):
        c = Client(self.port)
        st, obj = c.login('viewer1')
        self.assertEqual(st, 200, obj)
        return c

    def test_needs_a_session(self):
        self.assertEqual(Client(self.port).req('GET', '/api/v1/warroom/snapshot')[0], 401)

    def test_snapshot_window_and_what_is_left_out(self):
        st, s, _ = self.viewer().req('GET', '/api/v1/warroom/snapshot')
        self.assertEqual(st, 200)
        self.assertEqual(s['totals']['events'], 4)                 # the event 3 hours ago is outside the 30 minutes
        self.assertEqual((s['totals']['blocked'], s['totals']['internal']), (1, 1))
        self.assertEqual(len(s['minutes']), 31)
        self.assertEqual(sum(m['blocked'] + m['logged'] for m in s['minutes']), 4)
        text = json.dumps(s)
        for private in ('203.0.113.7', '192.168.77.50', '/.env', 'secret1', '/search', 'intranet.example.com', 'made-up-by'):
            self.assertNotIn(private, text)                          # no address, path, query or internal site name
        hosts = {e['host'] for e in s['latest']}
        self.assertIn('app.example.com', hosts)
        self.assertTrue(any(h.startswith('internal-') for h in hosts))
        self.assertIsNone(s['destination'])                          # not set: the maps draw no destination
        # the decision flow counts each event once; the sites by alias, in 2-minute cells
        self.assertEqual(sum(sum(d.values()) for d in s['flow'].values()), 4)
        self.assertIn('other', {x['host'] for x in s['sites']})        # a Host no site serves is "other"
        self.assertEqual(s['flow']['external'].get('confident'), 1)
        app_site = next(x for x in s['sites'] if x['host'] == 'app.example.com')
        self.assertEqual((app_site['events'], len(app_site['buckets']), sum(app_site['buckets'])), (2, 15, 2))
        self.assertEqual(s['score_only'], [])
        self.assertIn('stopped', s['collector'])

    def test_a_longer_range(self):
        c = self.viewer()
        st, s, _ = c.req('GET', '/api/v1/warroom/snapshot?range=6h')
        self.assertEqual(st, 200)
        self.assertEqual((s['range'], s['window_seconds'], s['step_seconds'], s['cell_seconds']), ('6h', 21600, 720, 1440))
        self.assertEqual(s['totals']['events'], 5)                 # the event 3 hours ago is inside 6 hours
        self.assertEqual(len(s['minutes']), 31)
        self.assertEqual(sum(m['blocked'] + m['logged'] for m in s['minutes']), 5)
        self.assertEqual(sum(sum(x['buckets']) for x in s['sites']), 5)
        self.assertNotIn('203.0.113.7', json.dumps(s))
        st, live, _ = c.req('GET', '/api/v1/warroom/snapshot')
        self.assertEqual((live['range'], live['totals']['events']), ('live', 4))   # cached apart from the 6 hours
        self.assertEqual(c.req('GET', '/api/v1/warroom/snapshot?range=99d')[0], 400)
        st, b, _ = c.req('GET', '/api/v1/warroom/snapshot?only=blocked')
        self.assertEqual((st, b['only'], b['totals']['events'], b['totals']['logged']), (200, 'blocked', 1, 0))
        self.assertTrue(all(e['outcome'] == 'blocked' for e in b['latest']))
        self.assertEqual(c.req('GET', '/api/v1/warroom/snapshot?only=logged')[0], 400)

    def test_events_after_an_id(self):
        c = self.viewer()
        st, s, _ = c.req('GET', '/api/v1/warroom/snapshot')
        hw = s['high_water_id']
        st, r, _ = c.req('GET', '/api/v1/warroom/events?after=%d' % hw)
        self.assertEqual((st, r['events'], r['high_water_id'], r['more']), (200, [], hw, False))   # a heartbeat
        st, r, _ = c.req('GET', '/api/v1/warroom/events?after=0')
        self.assertEqual([e['id'] for e in r['events']], sorted(e['id'] for e in r['events']))
        self.assertNotIn('203.0.113.7', json.dumps(r))
        self.assertEqual(c.req('GET', '/api/v1/warroom/events?after=x')[0], 400)

    def test_ops_ids_kinds_and_states_only(self):
        from jtwafmgr import alerts
        alerts.raise_alert(self.app.db, self.app.audit, 'test', 'attack_in_progress', 'warning', 'wr-ops',
                           {'reason': 'probe of /secret-path.env', 'paths': ['/secret-path.env']}, notify=False)
        st, o, _ = self.viewer().req('GET', '/api/v1/warroom/ops')
        self.assertEqual(st, 200)
        self.assertEqual(o['alerts'][0]['kind'], 'attack_in_progress')
        self.assertNotIn('secret-path', json.dumps(o))               # what an outsider sent stays off the wall
        self.assertEqual(set(o['changes']), {'checking', 'pending', 'applied'})
        self.assertIn('open', o['intel'])
        self.assertIsNone(o['analysis']['latest'])

    def test_destination(self):
        self.app.cfg.data['warroom'].update(dest_label='TW / EDGE', dest_lat='25.03', dest_lon='121.56')
        try:
            self.assertEqual(api_warroom.destination(self.app.cfg), {'label': 'TW / EDGE', 'lat': 25.03, 'lon': 121.56})
            self.app.cfg.data['warroom']['dest_label'] = ''                 # the name is optional: the maps say "Us"
            self.assertEqual(api_warroom.destination(self.app.cfg), {'label': '', 'lat': 25.03, 'lon': 121.56})
            self.app.cfg.data['warroom']['dest_lat'] = '95'
            self.assertIsNone(api_warroom.destination(self.app.cfg))
        finally:
            self.app.cfg.data['warroom'].update(dest_label='', dest_lat='', dest_lon='')


if __name__ == '__main__':
    unittest.main()
