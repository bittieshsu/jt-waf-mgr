"""Hourly event counts (rollup.py): kept by triggers whoever writes the events, counted in for events stored before,
and the dashboard read from them gives exactly what a scan of the events gives."""
import json
import random
import time
import unittest

from jtwafmgr import rollup, util
from jtwafmgr.app import App
from jtwafmgr.collector.auditlog import Store
from jtwafmgr.web import api
from tests.helpers import TempEnv

HOSTS = ['a.example.com', 'b.example.com', 'c.example.com', 'd.example.com']
FAMS = ['', ',xss,', ',sqli,xss,', ',lfi,', ',scanner,']
RULES = ['', ',930110,', ',941100,949110,', ',10205,', ',942100,980170,']


class Req:
    def __init__(self, app, **q):
        self.app, self.query = app, q


def insert(app, n, seed, now):
    rnd = random.Random(seed)
    for i in range(n):
        ip = '203.0.113.%d' % rnd.randrange(12) if rnd.random() < .8 else '10.0.0.%d' % rnd.randrange(3)
        app.db.x("INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, status, outcome, "
                 "decided_by, anomaly_score, rule_ids, local_rule_ids, families, message, matches) "
                 "VALUES ('waf1', ?, ?, ?, 'GET', '/x', '', ?, ?, 403, ?, ?, 5, ?, '', ?, '', '[]')",
                 ('s%d-%d' % (seed, i), now - rnd.random() * 40 * 86400, rnd.choice(HOSTS),
                  ip, 'internal' if ip.startswith('10.') else 'external', rnd.choice(['blocked', 'logged']),
                  rnd.choice(['confident', 'score', 'fallback', 'other', None]), rnd.choice(RULES), rnd.choice(FAMS)))
    # what the collector also writes for every event (Store.insert): one row per matched rule
    app.db.x("DELETE FROM event_rules")
    app.db.x("INSERT INTO event_rules(event_id, rule_id, ts, outcome) SELECT e.id, CAST(j.value AS INTEGER), e.ts, e.outcome "
             "FROM events e, json_each('[' || trim(e.rule_ids, ',') || ']') j")


def norm(d):
    """Lists whose order among equal counts is not defined: compare as sorted lists."""
    d = json.loads(json.dumps(d))
    for k in ('by_host', 'by_family', 'by_src', 'by_rule', 'by_country', 'by_asn'):
        d[k] = sorted(d[k], key=lambda x: json.dumps(x, sort_keys=True))
    return d


class TestRollup(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)
        self.now = util.now()
        insert(self.app, 1500, 1, self.now)

    def tearDown(self):
        api.OVERVIEW_ROLLUP = True
        self.env.cleanup()

    def scan(self, table):
        """The table's counts from the events directly."""
        out = {}
        dim = rollup.TABLES[table][0]
        for k, n in rollup._raw(self.app.db, table, 0, self.now + 86400, '', [], ('host', 'origin', 'outcome', dim), False).items():
            out[k] = out.get(k, 0) + n
        return out

    def stored(self, table):
        dim = rollup.TABLES[table][0]
        out = {}
        for r in self.app.db.q('SELECT host, origin, outcome, %s d, SUM(n) n FROM %s GROUP BY 1, 2, 3, 4 HAVING SUM(n) > 0' % (dim, table)):
            out[(r['host'], r['origin'], r['outcome'], r['d'])] = r['n']
        return out

    def assert_tables(self):
        for t in rollup.TABLES:
            self.assertEqual(self.stored(t), self.scan(t), t)

    def both(self, **q):
        # one clock for both answers: a window that ends a second later is not the same window (an occasional failure
        # when the two calls straddled a second)
        real, t = util.now, util.now()
        util.now = lambda: t
        try:
            api.OVERVIEW_ROLLUP = False
            raw = api._overview(self.app, Req(self.app, **q))
            api.OVERVIEW_ROLLUP = True
            fast = api._overview(self.app, Req(self.app, **q))
        finally:
            util.now = real
        return norm(raw), norm(fast)

    def test_triggers_follow_inserts_updates_and_deletes(self):
        self.assert_tables()
        self.app.db.x("UPDATE events SET decided_by='confident', families=',rce,' WHERE id % 7 = 0")
        self.app.db.x("UPDATE events SET host='e.example.com', rule_ids=',913100,' WHERE id % 11 = 0")
        self.app.db.x('DELETE FROM events WHERE id % 13 = 0')
        self.assert_tables()
        Store(self.app.db).purge(20, 365)               # the retention purge: the old hours go, the rest stays exact
        self.assertIsNone(self.app.db.one('SELECT 1 FROM ev_hour WHERE hour < ?', (int((self.now - 20 * 86400) // 3600),)))
        self.assert_tables()

    def test_events_stored_before_are_counted_in(self):
        db = self.app.db
        c = db.conn()
        for t in rollup.TABLES:
            c.execute('DROP TABLE %s' % t)
        for tr in ('events_rollup_ins', 'events_rollup_del', 'events_rollup_upd'):
            c.execute('DROP TRIGGER %s' % tr)
        db.x("UPDATE meta SET value='14' WHERE key='schema_version'")
        db.migrate()                                    # what an upgrade from 0.4.53 does
        self.assert_tables()

    def test_dashboard_same_as_a_scan(self):
        span = self.now - 25 * 86400
        for q in ({'range': '24h'}, {'range': '7d'}, {'range': 'custom', 'since': util.iso(span), 'until': util.iso(self.now - 3 * 86400 + 1234)},
                  {'range': '7d', 'host': 'b.example.com'}, {'range': '7d', 'origin': 'internal', 'outcome': 'blocked'},
                  {'range': '24h', 'not_host': 'a.example.com', 'not_outcome': 'logged'}):
            raw, fast = self.both(**q)
            self.assertEqual(fast, raw, q)

    def test_other_filters_scan(self):
        self.assertIsNone(api._rollup_filter(Req(self.app, range='24h', rule_id='930110')))
        self.assertIsNone(api._rollup_filter(Req(self.app, outcome='redirected')))
        self.assertEqual(api._rollup_filter(Req(self.app, host='B.example.com', not_origin='internal')),
                         {'host': 'b.example.com', 'not_origin': 'internal'})

    def test_one_answer_for_every_screen(self):
        api.OVERVIEW_CACHE_SECONDS = 15
        api._ov_cache.clear()
        try:
            r1 = json.loads(api.overview(self.app, Req(self.app, range='24h')).body)
            insert(self.app, 50, 2, self.now)
            r2 = json.loads(api.overview(self.app, Req(self.app, range='24h')).body)
            self.assertEqual(r1, r2)                    # within the shared time: the same answer
            api._ov_cache[(('range', '24h'),)] = (time.time() - 30,) + api._ov_cache[(('range', '24h'),)][1:]
            r3 = json.loads(api.overview(self.app, Req(self.app, range='24h')).body)
            self.assertGreaterEqual(r3['totals']['events'], r1['totals']['events'])   # older, with new events: again
        finally:
            api.OVERVIEW_CACHE_SECONDS = 0
            api._ov_cache.clear()


if __name__ == '__main__':
    unittest.main()
