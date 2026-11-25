"""Application protection sets (0.5.33): the data (every rule builds; each attack test matches its rule as ModSecurity
would see it and each ordinary test does not), the state per site, and proposing a set as one bundle."""
import json
import re
import unittest
import urllib.parse

from jtwafmgr import protsets, rulegen, software
from jtwafmgr.app import App
from tests.helpers import TempEnv


def _values(rule, test):
    """What the rule's first condition sees for a test request (lower case, as t:lowercase)."""
    spec = rule['spec']
    path = test['path']
    target = spec.get('target', 'path')
    if target == 'arg':
        names = spec['arg'].split('|')
        args = urllib.parse.parse_qsl(urllib.parse.urlsplit(path).query, keep_blank_values=True)
        if test.get('body') and 'urlencoded' in (test.get('headers') or {}).get('Content-Type', ''):
            args += urllib.parse.parse_qsl(test['body'], keep_blank_values=True)
        if test.get('body') and 'json' in (test.get('headers') or {}).get('Content-Type', ''):
            # libmodsecurity names a JSON body's top-level keys json.<key> (ARGS:json.sid)
            doc = json.loads(test['body'])
            args += [('json.' + k, str(v)) for k, v in doc.items() if isinstance(v, (str, int))]
        return [v.lower() for k, v in args if k.lower() in names]
    if target == 'arg_name':
        args = urllib.parse.parse_qsl(urllib.parse.urlsplit(path).query, keep_blank_values=True)
        if test.get('body') and 'urlencoded' in (test.get('headers') or {}).get('Content-Type', ''):
            args += urllib.parse.parse_qsl(test['body'], keep_blank_values=True)
        return [k.lower() for k, _ in args]
    if target == 'path':
        return [urllib.parse.unquote(urllib.parse.urlsplit(path).path).lower()]
    if target == 'uri':
        return [urllib.parse.unquote(path).lower()]
    if target == 'raw_uri':
        return [path.lower()]
    if target == 'header':
        return [v.lower() for k, v in (test.get('headers') or {}).items() if k.lower() == spec['header'].lower()]
    if target == 'body_unchecked':
        # REQBODY_ERROR / INBOUND_DATA_ERROR as libmodsecurity sets them: a multipart body without its final boundary,
        # or a form over SecRequestBodyNoFilesLimit (128 KB)
        ctype = (test.get('headers') or {}).get('Content-Type', '')
        body = test.get('body') or ''
        m = re.search(r'boundary=([^;\s]+)', ctype)
        bad = (ctype.startswith('multipart/') and (not m or ('--%s--' % m.group(1)) not in body)) or len(body) > 131072
        return ['1'] if bad else ['0']
    raise AssertionError('no view for target %s' % target)


class TestData(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.app = App(self.env.cfg)

    def tearDown(self):
        self.app.db.release()
        self.env.cleanup()

    def test_every_rule(self):
        sets = protsets.load()
        self.assertTrue(sets)
        with open(protsets.DATA_FILE, encoding='utf-8') as fh:
            raw = json.load(fh)
        self.assertEqual(sum(len(s['rules']) for s in raw['sets']), sum(len(s['rules']) for s in sets))   # none dropped
        for s in sets:
            # a change carries at most 50 tests: the whole set proposed at once must fit
            self.assertLessEqual(sum(len(r['tests']) for r in s['rules']), 50, s['id'])
            ids = [r['id'] for r in s['rules']]
            self.assertEqual(len(ids), len(set(ids)), s['id'])
            for r in s['rules']:
                spec = dict(r['spec'], host={'mode': 'exact', 'value': 'nas.example.com'}, protset='%s/%s' % (s['id'], r['id']))
                norm, text, _ = rulegen.build('confident_block', spec, 10250, self.app.cfg)
                self.assertEqual(norm['protset'], '%s/%s' % (s['id'], r['id']))
                attacks = [t for t in r['tests'] if t['expect'] == 403]
                self.assertTrue(attacks, r['id'])
                self.assertTrue(any(t['expect'] == 200 for t in r['tests']), r['id'])
                for t in r['tests']:
                    self.assertIn(t.get('source', 'external'), ('external', 'internal'))
                    seen = _values(r, t)
                    hit = _hits(r, t)        # its pattern, unless the path is one of its exceptions
                    if t['expect'] == 403:
                        self.assertTrue(hit, (r['id'], t['path'], seen))
                    elif t.get('source', 'external') == 'external':
                        self.assertFalse(hit, (r['id'], t['path'], seen))
                # the tests pass the change flow's own check
                from jtwafmgr.changes import _check_tests
                _check_tests([dict(t, host='nas.example.com', source=t.get('source', 'external')) for t in r['tests']])
                for u in r['refs'] + ([r['spec']['reference']] if r['spec'].get('reference') else []):
                    self.assertTrue(u.startswith('https://'), u)
                for c in r['cves']:
                    self.assertRegex(c, r'^CVE-\d{4}-\d{4,}$')


def _hits(rule, test):
    """Whether the rule matches the test request: its pattern on what it sees, unless the path is in its exceptions."""
    spec = rule['spec']
    rx = re.compile('^1$' if spec.get('target') in rulegen.FLAG_TARGETS else spec['regex'])
    if not any(rx.search(v) for v in _values(rule, test)):
        return False
    p = urllib.parse.unquote(urllib.parse.urlsplit(test['path']).path).lower()
    return not any(re.search(e, p) for e in spec.get('exceptions') or [])


class TestSetAsAWhole(unittest.TestCase):
    def test_ordinary_requests_pass_every_rule_of_the_set(self):
        # a set is proposed as one change: each ordinary request goes through all of its rules in the sandbox (0.5.45:
        # Nextcloud's app management test was an administration page another rule of the set refuses)
        for s in protsets.load():
            for r in s['rules']:
                for t in r['tests']:
                    if t['expect'] != 200 or t.get('source', 'external') != 'external':
                        continue
                    for other in s['rules']:
                        self.assertFalse(_hits(other, t), (s['id'], r['id'], t['path'], 'refused by', other['id']))


class TestFlow(unittest.TestCase):
    def setUp(self):
        import os
        import time
        from jtwafmgr import auth, config
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.mdir = os.path.join(self.env.dir, 'managed')
        self.spool = os.path.join(self.env.dir, 'spool')
        self.env.cfg = config.load(None, {
            'paths': dict(self.env.cfg['paths']), 'server': {'secure_cookies': False}, 'syslog': {'enabled': False},
            'collector': {'backfill_rotated': False}, 'waf': {'focus_sites': []},
            'managed': {'dir': self.mdir, 'spool': self.spool, 'sandbox_dir': os.path.join(self.env.dir, 'sbx')},
            'evidence': {'access_logs': [os.path.join(self.env.dir, '*access.log')]}})
        self.app = App(self.env.cfg)
        self.addCleanup(self.app.db.release)
        self.wf = self.app.workflow
        self.wf.set_setting('sandbox.required', False, 'test')
        a = self.app.auth
        a.create_user('boss', 'admin', password='a long test password')
        self.secret, _ = a.totp_setup('boss')
        a.totp_enable('boss', auth.totp_code(self.secret, int(time.time() // 30)))
        self.wf.set_setting('approval.single_admin_mode', True, 'boss')
        cid = self.wf.propose_adoption('boss')
        self.wf.run_checks(cid)
        self.approve(cid)
        self.fake_apply()

    def approve(self, cid, note='checked the rules of the set'):
        import time
        from jtwafmgr import auth
        self.app.db.x('UPDATE users SET totp_last_step=0 WHERE username=?', ('boss',))
        self.wf.approve(cid, self.app.auth.user_row('boss'), auth.totp_code(self.secret, int(time.time() // 30)), note)

    def fake_apply(self):
        from tests.test_hub_changes import TestWorkflow
        TestWorkflow.fake_apply(self)

    def syno(self):
        return [x for x in protsets.status(self.app) if x['id'] == 'synology-dsm'][0]

    def test_status_and_propose(self):
        self.assertTrue(all(x['sites'] == [] for x in protsets.status(self.app)))        # no DSM in the list yet
        software.save(self.app.db, 'alice', 'Synology DSM', '', hosts=['nas.example.com'])
        st = self.syno()
        self.assertEqual([x['host'] for x in st['sites']], ['nas.example.com'])
        rules = st['sites'][0]['rules']
        self.assertTrue(all(r['state'] == 'available' for r in rules))
        with self.assertRaises(protsets.ProtsetError):
            protsets.propose(self.app, 'synology-dsm', 'other.example.com', ['admin-api'], 'alice', role='admin')
        with self.assertRaises(protsets.ProtsetError):
            protsets.propose(self.app, 'synology-dsm', 'nas.example.com', ['nope'], 'alice', role='admin')
        with self.assertRaises(protsets.ProtsetError):
            protsets.propose(self.app, 'nope', 'nas.example.com', ['admin-api'], 'alice', role='admin')
        ids = [r['id'] for r in rules]
        cid = protsets.propose(self.app, 'synology-dsm', 'nas.example.com', ids, 'alice', role='admin')
        ch = self.app.workflow.get(cid)
        self.assertEqual(ch['op'], 'bundle')
        self.assertEqual(ch['direction'], 'tighten')
        spec = json.loads(ch['spec'])
        self.assertEqual(len(spec['ops']), len(ids))
        self.assertEqual({o['spec']['protset'] for o in spec['ops']}, {'synology-dsm/' + i for i in ids})
        self.assertTrue(all(o['spec']['host'] == {'mode': 'exact', 'value': 'nas.example.com'} for o in spec['ops']))
        tests = json.loads(ch['tests'])
        self.assertTrue(tests and all(t['host'] == 'nas.example.com' for t in tests))
        st = self.syno()['sites'][0]['rules']
        self.assertTrue(all(r['state'] == 'pending' and r['change_id'] == cid for r in st))
        with self.assertRaises(protsets.ProtsetError) as e:            # all waiting already
            protsets.propose(self.app, 'synology-dsm', 'nas.example.com', ids, 'alice', role='admin')
        self.assertEqual(e.exception.code, 'nothing_to_do')
        self.assertTrue(self.app.db.one("SELECT id FROM audit WHERE action='protset.proposed'"))
        # checked, approved, applied: applied; a later version writing a rule differently: update, modified in place
        from tests.test_hub_changes import FakeSandbox
        self.wf.sandbox = FakeSandbox()
        self.wf.run_checks(cid)
        self.assertEqual(self.wf.get(cid)['state'], 'pending_approval', json.loads(self.wf.get(cid)['checks'] or '{}'))
        self.approve(cid)
        self.fake_apply()
        self.assertEqual(self.wf.get(cid)['state'], 'applied')
        st = self.syno()['sites'][0]['rules']
        self.assertTrue(all(r['state'] == 'applied' and r['rule_id'] for r in st), st)
        import os
        import tempfile
        with open(protsets.DATA_FILE, encoding='utf-8') as fh:
            d = json.load(fh)
        d['sets'][0]['rules'][0]['spec']['regex'] += '|syno\\.core\\.newadminapi'
        d['sets'][0]['rules'][0]['tests'].append({'path': '/webapi/entry.cgi?api=SYNO.Core.NewAdminApi', 'method': 'GET',
                                                  'expect': 403})
        fd, path = tempfile.mkstemp(suffix='.json', dir=self.env.dir)
        with os.fdopen(fd, 'w') as fh:
            json.dump(d, fh)
        st = {r['id']: r for r in protsets.status(self.app, path)[0]['sites'][0]['rules']}
        first = d['sets'][0]['rules'][0]['id']
        self.assertEqual(st[first]['state'], 'update')
        self.assertTrue(all(r['state'] == 'applied' for k, r in st.items() if k != first))
        cid2 = protsets.propose(self.app, 'synology-dsm', 'nas.example.com', list(st), 'boss', role='admin', path=path)
        ops = json.loads(self.wf.get(cid2)['spec'])['ops']
        self.assertEqual([(o['op'], o['spec']['protset']) for o in ops], [('modify', 'synology-dsm/' + first)])


if __name__ == '__main__':
    unittest.main()
