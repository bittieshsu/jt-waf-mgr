"""AI analysis of one event (eventai.py): queueing, the context the model sees, the checks on its answer, the API."""
import json
import os
import time
import unittest

from jtwafmgr import auth, eventai
from jtwafmgr.app import App
from jtwafmgr.web.server import start_background
from tests.helpers import TempEnv
from tests.test_api import PW, Client
from tests.test_intel import Base as FakeServer, Fake, openai_reply


def ev(app, i, ts, path, ip, origin='external', outcome='blocked', host='app.example.com', query='', status=403):
    app.db.x("INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, status, outcome, decided_by, "
             "rule_ids, local_rule_ids, families, message, matches) VALUES ('waf1', ?, ?, ?, 'GET', ?, ?, ?, ?, ?, ?, 'score', "
             "',930120,949110,', ',', ',lfi,', 'OS file access', ?)",
             ('e%d' % i, ts, host, path, query, ip, origin, status, outcome,
              json.dumps([{'rule_id': 930120, 'message': 'OS File Access Attempt', 'data': 'Matched Data: etc/passwd'}])))
    return app.db.one('SELECT id FROM events WHERE unique_id=?', ('e%d' % i,))['id']


class TestEventAi(FakeServer):
    def setUp(self):
        super().setUp()
        self.app.cfg.data['llm'].update(enabled=True, url=self.url + '/v1', model='local', api_key='k')
        now = time.time()
        self.eid = ev(self.app, 1, now - 60, '/../../etc/passwd', '203.0.113.9')
        for i in range(4):
            ev(self.app, 10 + i, now - 120 - i, '/.env%d' % i, '203.0.113.9')
        ev(self.app, 20, now - 3000, '/../../etc/passwd', '192.168.77.5', origin='internal', outcome='logged', status=404)

    def answer(self, **k):
        a = dict({'verdict': 'attack', 'confidence': 0.9, 'summary': 'A path traversal probe from a scanner.',
                  'evidence': ['5 probes in 2 minutes'], 'action': 'block_ip', 'action_reason': 'it keeps probing'}, **k)
        return openai_reply(content=json.dumps(a))

    def test_context(self):
        e = self.app.db.one('SELECT * FROM events WHERE id=?', (self.eid,))
        c = eventai.context(self.app, e)
        self.assertEqual(c['event']['rules'][0]['id'], 930120)
        self.assertEqual(c['same_source_hour']['events'], 5)
        self.assertEqual(c['same_site_path_7_days']['internal_users'], 1)
        self.assertFalse(c['source_blocked_now'])

    def test_queue_and_answer(self):
        row = eventai.request(self.app, self.eid, 'alice', 'zh-TW')
        self.assertEqual(row['state'], 'queued')
        self.assertTrue(os.path.exists(eventai.request_file(self.app.cfg)))
        eventai.request(self.app, self.eid, 'alice', 'zh-TW')                  # one pending per event
        self.assertEqual(self.app.db.one('SELECT COUNT(*) FROM event_analyses')[0], 1)
        Fake.script = [self.answer()]
        self.assertEqual(eventai.run_pending(self.app, log=lambda m: None), 1)
        a = eventai.latest(self.app.db, self.eid)
        self.assertEqual((a['state'], a['verdict'], a['action']), ('done', 'attack', 'block_ip'))
        sent = [b for p, h, b in Fake.seen if p == '/v1/chat/completions'][0]
        self.assertIn('Traditional Chinese', sent['messages'][0]['content'])
        self.assertIn('etc/passwd', sent['messages'][1]['content'])
        self.assertIsNone(eventai.run_pending(self.app, log=lambda m: None))    # nothing waits

    def test_answer_checks(self):
        e = self.app.db.one('SELECT * FROM events WHERE id=?', (self.eid,))
        self.assertEqual(eventai.clean({'verdict': 'false_positive', 'action': 'block_ip', 'confidence': 3}, e)['action'], 'watch')
        self.assertEqual(eventai.clean({'verdict': 'attack', 'action': 'exclude'}, e)['action'], 'watch')
        self.assertEqual(eventai.clean({'verdict': 'attack', 'action': 'block_ip', 'confidence': 3}, e)['confidence'], 1.0)
        internal = dict(e)
        internal['origin'] = 'internal'
        self.assertEqual(eventai.clean({'verdict': 'attack', 'action': 'block_ip'}, internal)['action'], 'watch')
        with self.assertRaises(Exception):
            eventai.clean({'verdict': 'maybe'}, e)

    def test_llm_off(self):
        self.app.cfg.data['llm']['enabled'] = False
        eventai.request(self.app, self.eid, 'alice', 'en')
        eventai.run_pending(self.app, log=lambda m: None)
        self.assertEqual(eventai.latest(self.app.db, self.eid)['error'], 'llm_disabled')


class TestEventAiApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = TempEnv()
        cls.app = App(cls.env.cfg)
        cls.app.auth.create_user('viewer1', 'viewer', password=PW)
        cls.app.auth.create_user('op1', 'operator', password=PW)
        cls.eid = ev(cls.app, 1, time.time(), '/x', '203.0.113.9')
        cls.srv, _ = start_background(cls.app)
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.env.cleanup()

    def test_api(self):
        v = Client(self.port)
        self.assertEqual(v.login('viewer1')[0], 200)
        st, obj, _ = v.req('GET', '/api/v1/events/%d/analysis' % self.eid)
        self.assertEqual((st, obj['analysis'], obj['llm_ready']), (200, None, False))
        self.assertEqual(v.req('POST', '/api/v1/events/%d/analysis' % self.eid, {})[0], 403)
        o = Client(self.port)
        self.assertEqual(o.login('op1')[0], 200)
        self.assertEqual(o.req('POST', '/api/v1/events/%d/analysis' % self.eid, {})[0], 409)     # no LLM
        self.app.cfg.data['llm'].update(enabled=True, url='http://192.0.2.1/v1', model='m')
        st, obj, _ = o.req('POST', '/api/v1/events/%d/analysis' % self.eid, {})
        self.assertEqual((st, obj['analysis']['state']), (202, 'queued'))
        self.assertEqual(o.req('POST', '/api/v1/events/999999/analysis', {})[0], 404)
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='event.analysis_requested'"))
        self.app.cfg.data['llm']['enabled'] = False


if __name__ == '__main__':
    unittest.main()
