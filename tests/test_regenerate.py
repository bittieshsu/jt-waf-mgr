"""0.4.93: rules an older rule generator wrote are found and written again from their own settings, as changes a person
approves (path rules and an encoded "?"); the threat intelligence's page reader survives a link with a space in it."""
import http.client
import json
import unittest

from jtwafmgr import intel, rulegen
from jtwafmgr.changes import ChangeError
from jtwafmgr.evidence import Evidence
from tests import test_hub_changes as _hc   # (not the class itself: it would run here again)


class TestRegenerate(unittest.TestCase):
    setUp = _hc.TestWorkflow.setUp
    write_index = _hc.TestWorkflow.write_index
    fake_apply = _hc.TestWorkflow.fake_apply
    approve = _hc.TestWorkflow.approve
    adopt = _hc.TestWorkflow.adopt

    def applied(self, cid):
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval', self.wf.get(cid)['checks'])
        self.approve(cid, 'checked')
        self.fake_apply()
        self.assertEqual(self.wf.get(cid)['state'], 'applied')

    def test_outdated_rules_are_written_again_as_a_change(self):
        block = self.wf.propose('add', 'confident_block', {'target': 'path', 'regex': r'^/\.env$', 'msg': 'secret file',
                                                           'exceptions': [r'^/static/']}, 'secret file probes', 'op',
                                tests=[{'host': 'app.example.com', 'path': '/.env', 'expect': 403, 'source': 'external'}])
        self.applied(block)
        excl = self.wf.propose('add', 'exclusion', {
            'host': {'mode': 'exact', 'value': 'chat.example.com'}, 'path': {'mode': 'exact', 'value': '/json/messages'},
            'method': 'POST', 'action': 'remove_target_by_id', 'rule_ids': [930120], 'targets': ['ARGS:url']},
            'a link in a message', 'op',
            tests=[{'host': 'chat.example.com', 'path': '/json/messages', 'expect': 200, 'source': 'external'}])
        self.applied(excl)
        self.assertEqual(self.wf.outdated(), [])

        # as an older version wrote them: no raw path, no normalised exclusion path, no guard for an encoded "?"
        items = {it['kind']: it for it in self.wf.managed.items() if it['kind'] in ('confident_block', 'exclusion')}
        old_block = items['confident_block']['text'].split('\n', 2)[2].replace('REQUEST_FILENAME|TX:1', 'REQUEST_FILENAME')
        self.app.db.x('UPDATE managed_rules SET text=? WHERE id=?', ('SecRule REQUEST_FILENAME "@rx ^/\\.env$" \\\n' + old_block,
                                                                     items['confident_block']['id']))
        self.app.db.x('UPDATE managed_rules SET text=? WHERE id=?',
                      (items['exclusion']['text'].replace('t:none,t:normalizePath', 't:none'), items['exclusion']['id']))
        rows = self.wf.outdated()
        self.assertEqual(sorted((r['kind'], r['ok']) for r in rows), [('confident_block', True), ('exclusion', True)])

        out = self.wf.propose_regenerate('op')
        self.assertEqual((len(out['changes']), out['without_tests']), (1, []))
        r = self.wf.get(out['changes'][0])
        self.assertEqual((r['op'], r['proposed_by'], r['proposed_via'], r['direction']), ('bundle', 'rulegen', 'api', 'loosen'))
        # the person who asked counts as the proposer (no approving it alone)
        self.assertEqual(r['proposed_owner'], 'op')
        ops = json.loads(r['spec'])['ops']
        self.assertEqual(sorted(o['op'] + ' ' + o['kind'] for o in ops), ['modify confident_block', 'modify exclusion'])
        self.assertIn('asked by op', r['reason'])
        # the tests the rules came with
        self.assertEqual(sorted((t['path'], t['expect']) for t in json.loads(r['tests'])),
                         [('/.env', 403), ('/json/messages', 200)])
        # while it is open, the rules are not proposed again
        self.assertTrue(all(x.get('open_change') == r['id'] for x in self.wf.outdated()))
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose_regenerate('op')
        self.assertEqual(cm.exception.code, 'nothing_to_regenerate')
        # someone else approves it
        self.wf.set_setting('approval.single_admin_mode', False, 'boss')
        self.applied(r['id'])
        self.assertEqual(self.wf.outdated(), [])
        text = {it['kind']: it['text'] for it in self.wf.managed.items()}
        self.assertIn('SecRule REQUEST_URI_RAW "@rx ^(?:', text['confident_block'])
        self.assertIn('%3[fF]', text['exclusion'])

    def test_api_and_audit(self):
        from jtwafmgr.web.server import start_background
        from tests.test_api import Client
        srv, _ = start_background(self.app)
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        c = Client(srv.server_address[1])
        self.assertEqual(c.login('op', 'a long test password')[0], 200)
        st, body, _ = c.req('GET', '/api/v1/managed/outdated')
        self.assertEqual((st, body['count']), (200, 0))
        st, body, _ = c.req('POST', '/api/v1/managed/regenerate', {})
        self.assertEqual((st, body['error']['code']), (409, 'nothing_to_regenerate'))
        st, body, _ = c.req('POST', '/api/v1/managed/regenerate', {'item_ids': 'all'})
        self.assertEqual(st, 422)
        st, body, _ = c.req('GET', '/api/v1/managed/outdated')
        self.assertEqual((type(body['raw_path_rules']), body['guard_regex']), (list, rulegen.PATH_GUARD_REGEX))
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='managed.regenerate_requested' AND actor='op'"))


    def test_rules_entered_as_text_and_the_guard(self):
        raw = ('SecRule REQUEST_FILENAME "@rx /\\.env$" "id:10050,phase:1,deny,status:403,log,msg:\'old\'"')
        cid = self.wf.propose('add', 'raw', {'text': raw, 'placement': 'before'}, 'an old-style rule', 'boss', role='admin')
        self.applied(cid)
        self.assertIn(10050, self.wf.raw_path_rules())
        # the guard: a confident block on the raw request target
        spec = {'target': 'raw_uri', 'regex': rulegen.PATH_GUARD_REGEX, 'msg': 'encoded question mark before dot-dot'}
        _, text, _ = rulegen.build('confident_block', spec, 10230, self.app.cfg)
        self.assertIn('SecRule REQUEST_URI_RAW "@rx ^[^?#]*%3f', text)
        view = Evidence.rule_view(spec)
        import re as _re
        rx = _re.compile(rulegen.PATH_GUARD_REGEX.encode())
        hit = lambda u: any(rx.search(v) for v in view({'uri': u, 'esc': False}))
        self.assertTrue(hit('/x%3F/../.env') and hit('/a%3f/%2E%2E/b') and hit('/a%3F/..%2Fadmin'))
        self.assertFalse(hit('/a%3F/b') or hit('/a/../b') or hit('/a?q=%3F/../x') or hit('/x%3Fa..b/c'))

    def test_a_rule_switched_on_again_is_written_by_this_version(self):
        block = self.wf.propose('add', 'confident_block', {'target': 'path', 'regex': r'^/\.git/', 'msg': 'git'}, 'git', 'op',
                                tests=[{'host': 'app.example.com', 'path': '/.git/config', 'expect': 403, 'source': 'external'}])
        self.applied(block)
        it = next(x for x in self.wf.managed.items() if x['kind'] == 'confident_block')
        off = self.wf.propose('disable', None, {}, 'off for now', 'op', item_id=it['id'])
        self.applied(off)
        self.app.db.x('UPDATE managed_rules SET text=? WHERE id=?', (it['text'].replace('REQUEST_FILENAME|TX:1', 'REQUEST_FILENAME'),
                                                                     it['id']))
        on = self.wf.propose('enable', None, {}, 'on again', 'op', item_id=it['id'])
        self.assertIn('REQUEST_FILENAME|TX:1', self.wf.get(on)['rule_text'])
        self.applied(on)
        self.assertIn('REQUEST_FILENAME|TX:1', self.wf.managed.item(it['id'])['text'])


class TestEncodedQuestionMark(unittest.TestCase):
    def test_path_rule_sees_the_raw_path_and_exclusions_skip_it(self):
        view = Evidence.rule_view({'target': 'path'})
        self.assertEqual(view({'uri': '/x%3F/../.env', 'esc': False}), [b'/x', b'/.env'])
        self.assertEqual(view({'uri': 'http://a.example/b%3f/../c?q', 'esc': False})[-1], b'/c')

    def test_exclusion_impact_models_the_guard(self):
        from jtwafmgr.app import App
        from tests.helpers import TempEnv
        env = TempEnv()
        self.addCleanup(env.cleanup)
        app = App(env.cfg, start_collector=False)
        for i, p in enumerate(('/json/messages', '/json/messages%3F/../../admin', '/x/../json/messages', '/json/../admin')):
            app.db.x("INSERT INTO events(node_id, unique_id, ts, host, method, path, query, src_ip, origin, outcome, rule_ids, "
                     "local_rule_ids, families, message, matches) VALUES ('n1', ?, strftime('%s','now'), 'chat.example.com', "
                     "'POST', ?, '', '203.0.113.5', 'external', 'blocked', ',930120,', '', ',lfi,', '', '[]')", ('u%d' % i, p))
        r = Evidence(env.cfg, app.db).exclusion_impact({'host': {'mode': 'exact', 'value': 'chat.example.com'},
                                                        'path': {'mode': 'exact', 'value': '/json/messages'},
                                                        'rule_ids': [930120]})
        self.assertEqual(r['affected_events'], 1)      # as sent and normalised: /json/messages only


class TestFetchUrl(unittest.TestCase):
    def test_a_space_in_a_link_is_escaped_and_a_bad_target_is_an_error(self):
        seen = []

        def get(url, ip, timeout):
            seen.append(url)
            return 200, {'content-type': 'text/plain'}, b'ok'
        out = intel.fetch_url('https://www.cisa.gov/a b\n', ['cisa.gov'], resolve=lambda h, p: '192.0.2.1', get=get)
        self.assertEqual((out, seen), ('ok', ['https://www.cisa.gov/a%20b']))

        def bad(url, ip, timeout):
            raise http.client.InvalidURL('control characters')
        out = intel.fetch_url('https://www.cisa.gov/x', ['cisa.gov'], resolve=lambda h, p: '192.0.2.1', get=bad)
        self.assertTrue(out.startswith('error:'))

    def test_a_failing_page_reader_does_not_end_the_run(self):
        from tests.helpers import TempEnv
        env = TempEnv()
        self.addCleanup(env.cleanup)

        def boom(url, domains):
            raise RuntimeError('x')
        s = intel.Session(env.cfg, mcp=object(), fetch=boom)
        self.assertEqual(s.run_tool('fetch_url', {'url': 'https://www.cisa.gov/x'}), 'error: RuntimeError')


if __name__ == '__main__':
    unittest.main()
