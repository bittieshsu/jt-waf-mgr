"""CrowdSec virtual patching rules (hub.py, miniyaml.py) and uploads in parts (uploads.py). The rule files here are
written for these tests (synthetic), in the hub's format."""
import base64
import hashlib
import io
import json
import os
import tarfile
import unittest
import zipfile

from jtwafmgr import hub, miniyaml, uploads
from jtwafmgr.app import App
from tests.helpers import TempEnv

ZIMBRA = b"""name: example/vpatch-zimbra-xss
description: "Zimbra webmail XSS (synthetic test rule)"
rules:
  - and:
    - zones:
      - URI
      transform:
      - lowercase
      match:
        type: endsWith
        value: /public/error.jsp
    - zones:
      - ARGS
      variables:
      - errCode
      transform:
      - lowercase
      match:
        type: libinjectionXSS
labels:
  type: exploit
  label: "Zimbra Collaboration - XSS"
  classification:
   - cve.CVE-2099-0001
   - cwe.CWE-79
"""


class TestMiniYaml(unittest.TestCase):
    def test_subset(self):
        d = miniyaml.loads(b"""# comment
name: 'it''s'
list: [a, 'b c', 3]
map: {type: contains, value: 'x # not a comment'}
items:
  - one
  - key: v
    other: "tab\\tthere"
nested:
  deep:
    - x
block: |
  line 1
  line 2
flag: true
empty:
""")
        self.assertEqual(d['name'], "it's")
        self.assertEqual(d['list'], ['a', 'b c', 3])
        self.assertEqual(d['map'], {'type': 'contains', 'value': 'x # not a comment'})
        self.assertEqual(d['items'], ['one', {'key': 'v', 'other': 'tab\tthere'}])
        self.assertEqual(d['nested'], {'deep': ['x']})
        self.assertEqual(d['block'], 'line 1\nline 2\n')
        self.assertIs(d['flag'], True)
        self.assertIsNone(d['empty'])
        self.assertEqual(miniyaml.loads(b'v: off\n'), {'v': 'off'})          # YAML 1.2: a string, as CrowdSec reads it

    def test_refuses_what_it_cannot_read_for_sure(self):
        for bad in (b'a: &x 1\nb: *x\n', b'a: !tag x\n', b'a: 1\n---\nb: 2\n', b'a:\n\t- x\n', b'a: [b, [c]]\n',
                    b'a: 1\na: 2\n', b'a: "open\n', b'a:\n  - x\n    y: 1\n', b'a:\n  - - x\n'):
            with self.assertRaises(miniyaml.YamlError, msg=bad):
                miniyaml.loads(bad)


class TestConvert(unittest.TestCase):
    def test_zimbra_path_and_parameter(self):
        c = hub.convert(miniyaml.loads(ZIMBRA), 10400)
        self.assertTrue(c['ok'], c)
        self.assertEqual(c['rules'], 1)
        t = c['text']
        self.assertIn('SecRule REQUEST_FILENAME "@endsWith /public/error.jsp"', t)
        self.assertIn('id:10400,phase:2,pass,log', t)
        self.assertIn(',chain"', t)                                                   # the two conditions together
        self.assertIn('SecRule ARGS_GET:errCode "@detectXSS"', t)
        self.assertIn('setvar:tx.jt_block=1,ctl:ruleEngine=On', t.split('ARGS_GET:errCode')[1])   # only after both
        self.assertEqual(hub.describe(miniyaml.loads(ZIMBRA))['cves'], ['CVE-2099-0001'])

    def test_a_rule_is_converted_whole_or_not_at_all(self):
        # the path condition converts, the second one does not: no rule at all (never "path only")
        doc = miniyaml.loads(ZIMBRA.replace(b'      - ARGS\n', b'      - SOMETHING_NEW\n'))
        c = hub.convert(doc, 10400)
        self.assertEqual((c['ok'], c['text'], c['reason']), (False, '', 'zone_not_supported'))
        for patch, why in ((b'type: libinjectionXSS', b'type: fuzzy'), (b'- lowercase\n      match:\n        type: libinjectionXSS',
                                                                         b'- rot13\n      match:\n        type: libinjectionXSS')):
            self.assertFalse(hub.convert(miniyaml.loads(ZIMBRA.replace(patch, why)), 10400)['ok'])
        self.assertEqual(hub.convert({'name': 'x/y', 'seclang_rules': ['SecRule ...']}, 1)['reason'], 'seclang_or_data_files')

    def test_or_count_not_and_quotes(self):
        doc = {'name': 'x/y', 'rules': [{'and': [
            {'zones': ['METHOD'], 'match': {'type': 'equals', 'value': 'POST'}},
            {'or': [{'zones': ['BODY_ARGS'], 'variables': ['/.+file$/'], 'match': {'type': 'contains', 'value': '../'}},
                    {'zones': ['HEADERS'], 'variables': ['x-a'], 'transform': ['count'], 'match': {'type': 'gt', 'value': 1}},
                    {'zones': ['URI_FULL'], 'match': {'type': 'regex', 'value': 'a"b\\s', 'not': True}}]}]}]}
        c = hub.convert(doc, 10500)
        self.assertEqual(c['rules'], 3)                                               # one rule per "or" branch
        self.assertIn('id:10500', c['text'])
        self.assertIn('id:10502', c['text'])
        self.assertIn('SecRule ARGS_POST:/.+file$/ "@contains ../"', c['text'])
        self.assertIn('SecRule &REQUEST_HEADERS:x-a "@gt 1"', c['text'])
        self.assertIn('"!@rx a\\"b\\s"', c['text'])                                   # a quote escaped, the backslash kept
        doc['rules'][0]['and'][0]['match']['value'] = 'a\\"'
        self.assertFalse(hub.convert(doc, 1)['ok'])                                    # a backslash before a quote: refused

    def test_review_findings(self):
        # a name with quotes, newlines and actions never reaches the rule text as such
        doc = {'name': "x',ctl:ruleEngine=Off,tag:'a\"\nSecRuleEngine Off\n#", 'rules': [{'zones': ['URI'], 'match': {'type': 'contains', 'value': '/x'}}]}
        c = hub.convert(doc, 10400)
        self.assertTrue(c['ok'])
        self.assertNotIn("ctl:ruleEngine=Off", c['text'])
        self.assertEqual(len(c['text'].split('\n')), 2)
        self.assertTrue(all(hub.LINE_SHAPE.match(ln) for ln in c['text'].split('\n')))
        # a chain of thousands of conditions, odd types, macros: refused, never a crash
        long = {'name': 'x/y', 'rules': [{'and': [{'zones': ['URI'], 'match': {'type': 'contains', 'value': 'a'}}] * 9}]}
        self.assertEqual(hub.convert(long, 1)['reason'], 'too_many_conditions')
        self.assertEqual(hub.convert({'name': 'x/y', 'rules': [{'zones': ['URI'], 'match': {'type': ['x']}}]}, 1)['reason'], 'match_not_supported')
        self.assertEqual(hub.describe({'labels': {'label': 5, 'classification': 5}})['cves'], [])
        for v in ('%{REQUEST_HEADERS.host}', ' padded'):
            self.assertFalse(hub.convert({'name': 'x/y', 'rules': [{'zones': ['URI'], 'match': {'type': 'contains', 'value': v}}]}, 1)['ok'])
        # two files with one name: neither is offered
        idx = hub.build_index({'appsec-rules/a.yaml': ZIMBRA, 'appsec-rules/b.yaml': ZIMBRA}, 'c', 'test', 10400)
        self.assertEqual([r['reason'] for r in idx['rules']], ['duplicate_name', 'duplicate_name'])

    def test_converted_rules_pass_the_expert_mode_checks(self):
        from jtwafmgr import config, rulegen
        cfg = config.load(None, {})
        text = hub.convert(miniyaml.loads(ZIMBRA), 10400)['text']
        self.assertEqual(rulegen.check_raw_text(text, cfg=cfg), [10400])


def _zip(entries, top='hub-0123456789abcdef0123456789abcdef01234567'):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        for name, data in entries.items():
            z.writestr(name if name.startswith('/') or name.startswith('..') else top + '/' + name, data)
    return b.getvalue()


class TestArchive(unittest.TestCase):
    def test_zip_and_tar(self):
        data = _zip({'appsec-rules/example/vpatch-zimbra-xss.yaml': ZIMBRA, 'LICENSE': b'MIT License\n',
                     'scenarios/other.yaml': b'x: 1', 'appsec-rules/../../escape.yaml': b'x: 1'})
        files, sha, src = hub.from_archive(data, 'hub.zip')
        self.assertEqual(sorted(files), ['LICENSE', 'appsec-rules/example/vpatch-zimbra-xss.yaml'])
        self.assertEqual(sha, '0123456789abcdef0123456789abcdef01234567')
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode='w:gz') as t:
            for name, payload in (('hub-main/appsec-rules/a.yaml', ZIMBRA), ('hub-main/LICENSE', b'MIT')):
                ti = tarfile.TarInfo(name)
                ti.size = len(payload)
                t.addfile(ti, io.BytesIO(payload))
            ln = tarfile.TarInfo('hub-main/appsec-rules/link.yaml')
            ln.type, ln.linkname = tarfile.SYMTYPE, '/etc/passwd'
            t.addfile(ln)
        files, sha, _ = hub.from_archive(b.getvalue())
        self.assertEqual(sorted(files), ['LICENSE', 'appsec-rules/a.yaml'])
        with self.assertRaises(ValueError):
            hub.from_archive(_zip({'README.md': b'x'}))                               # not the hub

    def test_round_two_review(self):
        # a zip announcing more entries than allowed is refused before its directory is read
        data = bytearray(_zip({'appsec-rules/a.yaml': ZIMBRA}))
        e = data.rfind(b'PK\x05\x06')
        data[e + 10:e + 12] = (hub.MAX_MEMBERS + 1).to_bytes(2, 'little') if hub.MAX_MEMBERS + 1 < 0xFFFF else b'\xff\xff'
        with self.assertRaises(ValueError):
            hub.from_archive(bytes(data))
        for bad in (b'v: - x\n', b'v: -\n'):
            with self.assertRaises(miniyaml.YamlError):
                miniyaml.loads(bad)
        # an upload's request never downloads, even with the sync off
        env = TempEnv()
        self.addCleanup(env.cleanup)
        hub.request_sync(env.cfg, 'upload')
        calls = []
        st = hub.run(env.cfg, log=lambda m: None, fetch=lambda *a, **k: calls.append(a) or b'{}')
        self.assertEqual((st['state'], calls), ('off', []))

    def test_run_with_an_upload_and_the_index(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        cfg = env.cfg
        up = os.path.join(hub.hub_dir(cfg), hub.UPLOAD_DIR)
        os.makedirs(up)
        with open(os.path.join(up, 'hub.zip'), 'wb') as fh:
            fh.write(_zip({'appsec-rules/example/vpatch-zimbra-xss.yaml': ZIMBRA, 'LICENSE': b'MIT License\n',
                           'appsec-rules/example/broken.yaml': b'a: &x 1\n'}))
        st = hub.run(cfg, log=lambda m: None)
        self.assertEqual((st['state'], st['counts']), ('ok', {'total': 2, 'convertible': 1, 'unsupported': 1}))
        idx = hub.read_index(cfg)
        z = next(r for r in idx['rules'] if r['name'] == 'example/vpatch-zimbra-xss')
        self.assertEqual((z['change'], z['product']), ('new', 'Zimbra Collaboration'))
        self.assertEqual(idx['license'], 'MIT License\n')
        self.assertFalse(os.listdir(up))                                              # the upload is consumed
        st = hub.run(cfg, log=lambda m: None)                                          # off and nothing uploaded
        self.assertEqual(st['state'], 'off')


class TestUploads(unittest.TestCase):
    def test_parts_size_and_checksum(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        cfg = env.cfg
        data = os.urandom(uploads.CHUNK + 1000)
        s = uploads.start(cfg, 'hub', 'hub.zip', len(data), hashlib.sha256(data).hexdigest(), 'boss')
        self.assertEqual(s['chunks'], 2)
        with self.assertRaises(uploads.UploadError):                                 # out of order
            uploads.chunk(cfg, s['id'], 1, base64.b64encode(data[:10]).decode(), 'boss')
        with self.assertRaises(uploads.UploadError):                                 # someone else's upload
            uploads.chunk(cfg, s['id'], 0, base64.b64encode(data[:10]).decode(), 'eve')
        uploads.chunk(cfg, s['id'], 0, base64.b64encode(data[:uploads.CHUNK]).decode(), 'boss')
        uploads.chunk(cfg, s['id'], 1, base64.b64encode(data[uploads.CHUNK:]).decode(), 'boss')
        path, meta = uploads.finish(cfg, s['id'], 'boss')
        with open(path, 'rb') as fh:
            self.assertEqual(fh.read(), data)
        s2 = uploads.start(cfg, 'crs', 'coreruleset-4.99.0-minimal.tar.gz', 3, 'a' * 64, 'boss')
        uploads.chunk(cfg, s2['id'], 0, base64.b64encode(b'abc').decode(), 'boss')
        with self.assertRaises(uploads.UploadError) as cm:
            uploads.finish(cfg, s2['id'], 'boss')
        self.assertEqual(cm.exception.code, 'checksum_mismatch')
        for bad in (('hub', '../x.zip', 3), ('hub', '..', 3), ('hub', 'x.zip', uploads.LIMITS['hub'] + 1), ('nope', 'x.zip', 3),
                    ('crs', 'not-a-release.zip', 3)):
            with self.assertRaises(uploads.UploadError):
                uploads.start(cfg, bad[0], bad[1], bad[2], 'a' * 64, 'boss')
        uploads.start(cfg, 'hub', 'a.zip', 3, 'a' * 64, 'boss')                         # s2 above is still open: 2 now
        with self.assertRaises(uploads.UploadError) as cm:
            uploads.start(cfg, 'hub', 'b.zip', 3, 'a' * 64, 'boss')
        self.assertEqual(cm.exception.code, 'too_many_uploads')

    def test_api_routes(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        app = App(env.cfg)
        self.addCleanup(app.stop)
        from jtwafmgr.web import api_hub

        class Req:
            def __init__(self, body=None, params=None, query=None):
                self.user, self.client_ip = {'username': 'boss', 'role': 'admin'}, '127.0.0.1'
                self._b, self.params, self.query = body or {}, params or {}, query or {}

            def body(self):
                return self._b
        out = json.loads(api_hub.hub_status(app, Req()).body)
        self.assertEqual((out['enabled'], out['rules']), (False, []))
        data = _zip({'appsec-rules/example/vpatch-zimbra-xss.yaml': ZIMBRA, 'LICENSE': b'MIT'})
        s = json.loads(api_hub.upload_start(app, Req({'kind': 'hub', 'name': 'hub.zip', 'size': len(data),
                                                       'sha256': hashlib.sha256(data).hexdigest()})).body)
        api_hub.upload_chunk(app, Req({'index': 0, 'data': base64.b64encode(data).decode()}, {'id': s['id']}))
        api_hub.upload_finish(app, Req({}, {'id': s['id']}))
        self.assertTrue(os.path.exists(os.path.join(hub.hub_dir(env.cfg), hub.REQUEST)))
        hub.run(env.cfg, log=lambda m: None)
        app.db.x("INSERT INTO software(name, version, kind, source, confirmed, hosts, updated_at) "
                 "VALUES ('Zimbra', '10.1', 'web', 'person', 1, '[\"mail.example.com\"]', 0)")
        out = json.loads(api_hub.hub_status(app, Req()).body)
        self.assertEqual(out['rules'][0]['related'], [{'name': 'Zimbra', 'sites': ['mail.example.com']}])
        one = json.loads(api_hub.hub_rule(app, Req(query={'name': 'example/vpatch-zimbra-xss'})).body)
        self.assertIn('SecRule ARGS_GET:errCode', one['text'])
        self.assertFalse(out['outdated_index'])
        # an index written by an older version (no upstream tests yet): the page says to sync first
        ip = os.path.join(hub.hub_dir(env.cfg), hub.INDEX)
        with open(ip) as fh:
            old = json.load(fh)
        old.pop('format', None)
        with open(ip, 'w') as fh:
            json.dump(old, fh)
        self.assertTrue(json.loads(api_hub.hub_status(app, Req()).body)['outdated_index'])
        acts = [r[0] for r in app.db.q("SELECT action FROM audit WHERE action LIKE 'upload.%' ORDER BY id")]
        self.assertEqual(acts, ['upload.started', 'upload.finished'])


if __name__ == '__main__':
    unittest.main()
