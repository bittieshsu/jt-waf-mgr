"""Pausing the WAF to troubleshoot (pause.py): the two pause rules, applied at once, resumed by hand or when the time
is up, and left out of the sandbox runs of other changes. Synthetic data only."""
import os
import unittest

from jtwafmgr import pause, util
from jtwafmgr.changes import ChangeError
from tests.test_analyst import AnalystBase


class TestPause(AnalystBase):
    def apply_pause(self, cid):
        r = self.wf.get(cid)
        self.assertEqual(r['kind'], 'pause')
        self.wf.run_checks(cid)                       # static only, then straight to the apply program
        self.assertIn(self.wf.get(cid)['state'], ('approved', 'applying'))
        self.fake_apply()
        self.assertEqual(self.wf.get(cid)['state'], 'applied', self.wf.get(cid)['error'])

    def before_file(self):
        with open(os.path.join(self.mdir, 'before-crs.conf')) as fh:
            return fh.read()

    def test_pause_a_site_then_everything_then_resume(self):
        self.adopt()
        with self.assertRaises(ChangeError) as cm:
            pause.start(self.app, 'site', 'app.example.com', 2, 'checking uploads', 'boss')
        self.assertEqual(cm.exception.code, 'invalid_duration')
        with self.assertRaises(ChangeError):
            pause.start(self.app, 'site', 'app.example.com', 1, 'x', 'boss')        # a reason is required
        cid = pause.start(self.app, 'site', 'App.Example.com.', 1, 'checking uploads', 'boss')
        self.assertIsNone(self.app.db.one("SELECT 1 FROM audit WHERE action='waf.paused'"))   # told once it is in force
        with self.assertRaises(ChangeError) as cm:          # one at a time
            pause.start(self.app, 'all', None, 1, 'checking uploads', 'boss')
        self.assertEqual(cm.exception.code, 'pause_busy')
        self.apply_pause(cid)
        text = self.before_file()
        first = [ln for ln in text.splitlines() if ln.startswith('Sec')][0]
        self.assertIn('id:10091', text.split('SecRule', 1)[1][:400])
        # above every other rule; the site as nginx chose it (the fixture's transaction id is "$host-$request_id")
        self.assertTrue(first.startswith('SecRule UNIQUE_ID'), first)
        self.assertIn('app\\.example\\.com', text)
        self.assertIn('ctl:ruleEngine=DetectionOnly,ctl:ruleRemoveById=10000-10089,ctl:ruleRemoveById=10092-10099,'
                      'ctl:ruleRemoveById=10200-19999', text)                              # the blocks that turn the engine on
        st = pause.state(self.wf)
        self.assertEqual([x['host'] for x in st['sites']], ['app.example.com'])
        self.assertIsNone(st['all'])
        self.assertTrue(0 < st['sites'][0]['left_seconds'] <= 3600)

        cid = pause.start(self.app, 'all', None, 0, 'everything is slow', 'boss')         # until resumed
        self.apply_pause(cid)
        st = pause.state(self.wf)
        self.assertIsNone(st['all']['until'])
        self.assertIn('id:10090,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly', self.before_file())

        cid = pause.resume(self.app, 'appr', all_=True)                                     # one click back
        self.assertEqual(self.wf.get(cid)['direction'], 'tighten')
        self.apply_pause(cid)
        text = self.before_file()
        self.assertNotIn('DetectionOnly', text)
        self.assertIn('SecAction "id:10090,phase:1,pass,nolog"', text)                     # the slots stay, as no-ops
        self.assertFalse(pause.state(self.wf)['active'])
        self.assertIsNone(pause.resume(self.app, 'appr', all_=True))                        # nothing left to resume
        acts = [r[0] for r in self.app.db.q("SELECT action FROM audit WHERE action LIKE 'waf.%' ORDER BY id")]
        self.assertEqual(acts, ['waf.paused', 'waf.paused', 'waf.resumed'])

    def test_only_the_pause_page_touches_the_pause_rules(self):
        self.adopt()
        with self.assertRaises(ChangeError) as cm:          # an API token or a person through the ordinary requests
            self.wf.propose('add', 'pause', {'scope': 'all', 'active': True}, 'quietly off', 'appr', via='api')
        self.assertEqual(cm.exception.code, 'pause_reserved')
        with self.assertRaises(ChangeError):
            self.wf.propose_bundle([{'op': 'add', 'kind': 'pause', 'spec': {'scope': 'all', 'active': True}}], 'quietly off', 'appr')
        self.apply_pause(pause.start(self.app, 'all', None, 1, 'everything is slow', 'boss'))
        item = next(it for it in self.wf.managed.items() if it['rule_id'] == 10090)
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose('modify', None, {'scope': 'all', 'active': True}, 'forever, no reminder', 'appr', item_id=item['id'])
        self.assertEqual(cm.exception.code, 'pause_reserved')
        from jtwafmgr import rulegen
        with self.assertRaises(rulegen.SpecError):            # detection only, from any other rule id: refused
            rulegen.check_raw_text('SecAction "id:10050,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"', cfg=self.app.cfg)

    def test_round_two_review(self):
        self.adopt()
        from jtwafmgr import rulegen
        # a raw rule cannot take a pause id (an unseen pause that would also block the switch)
        with self.assertRaises(ChangeError) as cm:
            self.wf.set_setting('approval.single_admin_mode', True, 'boss')
            self.wf.propose('add', 'raw', {'text': 'SecAction "id:10090,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"'},
                            'quietly off', 'boss', role='admin')
        self.assertEqual(cm.exception.details.get('reason'), 'pause_reserved')
        # a removal range that covers the system rules is refused (the pause's own rules aside)
        with self.assertRaises(rulegen.SpecError):
            rulegen.check_raw_text('SecRule ARGS "@rx x" "id:10150,phase:1,pass,nolog,ctl:ruleRemoveById=10297-10299"', cfg=self.app.cfg)
        # nothing goes above the pause rules
        with self.assertRaises(ChangeError) as cm:
            self.wf.propose('add', 'raw', {'text': 'SecRule REQUEST_FILENAME "@streq /x" "id:10500,phase:1,deny,status:403"',
                                           'before_rule_id': 10090}, 'above the pause', 'boss', role='admin')
        self.assertEqual(cm.exception.details.get('reason'), 'pause_reserved')
        # a refusing rule in the kept exclusion range is taken out by name
        orig = pause.also_remove
        self.addCleanup(setattr, pause, 'also_remove', orig)
        pause.also_remove = lambda app: [10150]
        self.apply_pause(pause.start(self.app, 'all', None, 1, 'everything is slow', 'boss'))
        self.assertIn('ctl:ruleRemoveById=10150"', self.before_file())

    def test_one_site_by_host_header_where_nginx_gives_no_site_name(self):
        self.adopt()
        orig = pause.match_mode
        self.addCleanup(setattr, pause, 'match_mode', orig)
        pause.match_mode = lambda app: 'host'
        self.apply_pause(pause.start(self.app, 'site', 'app.example.com', 1, 'checking uploads', 'boss'))
        self.assertIn('SecRule REQUEST_HEADERS:Host', self.before_file())

    def test_a_rollback_keeps_the_pause_as_it_is(self):
        self.adopt()
        before = self.wf.managed.current_version()['version']
        self.apply_pause(pause.start(self.app, 'all', None, 0, 'everything is slow', 'boss'))
        self.apply_pause(pause.resume(self.app, 'appr', all_=True))
        cid = self.wf.rollback(before, self.user('appr'), 'back to the adoption')       # before the pause rules existed
        self.fake_apply()
        self.assertEqual(self.wf.get(cid)['state'], 'applied')
        self.assertFalse(pause.state(self.wf)['active'])
        self.apply_pause(pause.start(self.app, 'all', None, 1, 'everything is slow', 'boss'))   # pausing still works
        self.assertTrue(pause.state(self.wf)['all'])
        mid = self.wf.managed.current_version()['version']
        self.apply_pause(pause.resume(self.app, 'appr', all_=True))
        self.wf.rollback(mid, self.user('appr'), 'back to while it was paused')        # does not bring the pause back
        self.fake_apply()
        self.assertFalse(pause.state(self.wf)['active'])
        self.assertNotIn('DetectionOnly', self.before_file())

    def test_a_failed_apply_is_told_and_not_retried_every_20_seconds(self):
        self.adopt()
        self.apply_pause(pause.start(self.app, 'site', 'app.example.com', 1, 'checking uploads', 'boss'))
        cid = pause.expire(self.app, now=util.now() + 2 * 3600)
        self.wf.run_checks(cid)
        import json as _json
        for n in sorted(os.listdir(self.spool)):              # the apply program refuses it (a health check changed)
            if n.endswith('.req'):
                with open(os.path.join(self.spool, n)) as fh:
                    req = _json.load(fh)
                with open(os.path.join(self.spool, n[:-4] + '.result'), 'w') as fh:
                    _json.dump({'request_id': n[:-4], 'version': req['version'], 'change_id': req['change_id'], 'result': 'failed',
                                'step': 'health', 'summary': 'health check changed'}, fh)
        self.wf.collect_results()
        self.assertEqual(self.wf.get(cid)['state'], 'apply_failed')
        self.assertTrue(self.app.db.one("SELECT 1 FROM audit WHERE action='waf.pause_apply_failed'"))
        self.assertIsNone(self.app.db.one("SELECT 1 FROM audit WHERE action='waf.resumed'"))
        self.assertIsNone(pause.expire(self.app, now=util.now() + 2 * 3600))           # waits before trying again
        self.assertTrue(pause.state(self.wf)['last_failed'])

    def test_runs_out_by_itself(self):
        self.adopt()
        self.apply_pause(pause.start(self.app, 'site', 'app.example.com', 1, 'checking uploads', 'boss'))
        self.apply_pause(pause.start(self.app, 'site', 'api.example.com', 3, 'checking the API', 'boss'))
        self.assertIsNone(pause.expire(self.app))                                           # nothing has run out
        cid = pause.expire(self.app, now=util.now() + 2 * 3600)
        self.assertEqual(self.wf.get(cid)['proposed_by'], 'system')
        self.apply_pause(cid)
        self.assertEqual([x['host'] for x in pause.state(self.wf)['sites']], ['api.example.com'])

    def test_sandbox_of_other_changes_tests_the_rules_unpaused(self):
        self.adopt()
        self.apply_pause(pause.start(self.app, 'all', None, 1, 'everything is slow', 'boss'))
        seen = {}

        class Box:
            def available(self):
                return True

            def run_change(self, r, files, tests, managed, samples, items):
                seen['files'], seen['kinds'] = files, {it.get('kind') for it in items}
                return {'ok': True}
        self.wf.sandbox = Box()
        cid = self.wf.propose('add', 'confident_block', {'target': 'path', 'regex': r'^/backup\.zip$', 'msg': 'backup probe'},
                              'block backup probes', 'appr')
        self.wf.run_checks(cid)
        self.assertNotIn('DetectionOnly', ''.join(seen['files'].values()))
        self.assertNotIn('pause', seen['kinds'])

    def test_reminder_once_a_day_for_a_pause_with_no_end(self):
        self.adopt()
        self.apply_pause(pause.start(self.app, 'all', None, 0, 'everything is slow', 'boss'))
        pause.expire(self.app)
        self.assertIsNone(self.app.db.one("SELECT 1 FROM audit WHERE action='waf.still_paused'"))
        later = util.now() + 86400 + 60
        pause.expire(self.app, now=later)
        pause.expire(self.app, now=later + 60)
        self.assertEqual(self.app.db.one("SELECT COUNT(*) FROM audit WHERE action='waf.still_paused'")[0], 1)


if __name__ == '__main__':
    unittest.main()
