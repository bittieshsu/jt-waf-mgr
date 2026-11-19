"""The system's own change reasons, shown in the reader's language (0.5.4): every template is found again in what it
wrote, reasons stored by earlier versions are found too, and the dictionaries carry every sentence and value."""
import json
import os
import re
import unittest

from jtwafmgr import reasons

HERE = os.path.dirname(os.path.abspath(__file__))
I18N = os.path.join(HERE, '..', 'frontend', 'src', 'i18n')


def _args(key):
    return {n: ('%d.%d' % (i, i) if n == 'version' else 'v%d %s' % (i, n))
            for i, n in enumerate(re.findall(r'\{(\w+)\}', reasons.TEMPLATES[key]))}


class TestRoundTrip(unittest.TestCase):
    def test_every_template_is_found_again(self):
        for key in reasons.TEMPLATES:
            a = _args(key)
            p = reasons.parse(reasons.text(key, **a))
            self.assertEqual(p, [{'key': key, 'args': a, 'values': {}}], key)

    def test_lines_mixed_with_free_text(self):
        s = 'The model says: a scanner.\n' + reasons.text('analyst_block', **_args('analyst_block'))
        p = reasons.parse(s)
        self.assertEqual(p[0], {'text': 'The model says: a scanner.'})
        self.assertEqual(p[1]['key'], 'analyst_block')

    def test_a_persons_words_are_left_alone(self):
        self.assertIsNone(reasons.parse('Block the scanner on shop.example.com'))
        self.assertIsNone(reasons.parse(''))
        self.assertIsNone(reasons.parse(None))

    def test_exploited_variant_wins(self):
        a = dict(_args('intel_hub'), severity='critical')
        p = reasons.parse(reasons.text('intel_hub_x', **a))
        self.assertEqual(p[0]['key'], 'intel_hub_x')
        self.assertEqual(p[0]['args']['severity'], 'critical')

    def test_program_words_are_marked_by_field(self):
        p = reasons.parse(reasons.text('paused', what='all', duration='until resumed', reason='checking a site'))[0]
        self.assertEqual(p['values'], {'what': 'all_sites', 'duration': 'until_resumed'})
        p = reasons.parse(reasons.text('resumed_why', what='shop.example.com', reason='any'))[0]
        self.assertEqual(p['values'], {})        # "any" is a value only in the method field


class TestStoredBefore054(unittest.TestCase):
    """Reasons as earlier versions wrote them (the same sentences, formatted by hand)."""

    def test_regenerated_rules(self):
        s = ('Rules written again by the rule generator of jt-waf-mgr %s from their own settings, asked '
             'by %s: %s. Path rules now also see the path cut at an encoded "?" (%%3F), normalised; '
             'exclusions and redactions scoped to a path need it both as sent and normalised and never '
             'apply to a path with an encoded "?". The network lists in force now (internal networks, '
             'known scanners) are written in, as in any new rule: compare the rule text.' % ('0.4.93', 'cli', '10400, 10228'))
        self.assertEqual(reasons.parse(s), [{'key': 'regen', 'args': {'version': '0.4.93', 'owner': 'cli', 'rules': '10400, 10228'},
                                             'values': {}}])

    def test_analyst_false_positive(self):
        only_ext = 'ALL FROM EXTERNAL SOURCES: no internal user was blocked; check that this is really normal use.\n'
        s = (only_ext + '[jt analyst] false positive, model %s, confidence %.2f. Scope: host %s, %s path %s, '
             'method %s, rules %s, %s. Last %dh: %d blocked requests from %d sources (%d internal).\n%s' % (
                 'local-model', 0.9, 'shop.example.com', 'prefix', '/api/', 'any', '942100, 942200',
                 'targets ARGS:q', 168, 12, 2, 0, 'A search box.'))
        p = reasons.parse(s)
        self.assertEqual([x.get('key') for x in p], ['analyst_all_external', 'analyst_fp', None])
        self.assertEqual(p[1]['args']['targets'], 'ARGS:q')
        self.assertEqual(p[1]['values'], {'mode': 'prefix', 'method': 'any'})

    def test_threat_intelligence(self):
        s = ('Virtual patch for %s in %s %s (%s%s): the CrowdSec Hub rule %s (%s), until the software is updated. '
             '%s References: %s' % ('CVE-2026-90001', 'Keycloak', '(version not known)', 'critical', ', exploited in the wild',
                                    'crowdsecurity/vpatch-CVE-2026-90001', 'Keycloak - RCE', 'An example.', 'https://example.com/a'))
        p = reasons.parse(s)[0]
        self.assertEqual(p['key'], 'intel_hub_x')
        self.assertEqual(p['values'], {'version': 'version_unknown'})

    def test_a_product_name_with_spaces(self):
        a = dict(_args('intel_hub'), product='OWASP CRS', version='(version not known)')
        p = reasons.parse(reasons.text('intel_hub', **a))[0]
        self.assertEqual((p['args']['product'], p['values']), ('OWASP CRS', {'version': 'version_unknown'}))

    def test_http2_off(self):
        s = ('nginx %s: nginx.org security advisory in %s (%s), which this configuration uses; rules cannot refuse it. '
             '%s off until nginx is updated (browsers fall back to an older protocol).' % ('1.30.6', 'HTTP/2', 'CVE-2026-1', 'HTTP/2'))
        self.assertEqual(reasons.parse(s)[0]['key'], 'proto_off')


@unittest.skipUnless(os.path.isdir(I18N), 'the dictionaries are in the source tree, not in a release')
class TestDictionaries(unittest.TestCase):
    def test_every_sentence_and_value_in_three_languages(self):
        values = {v for m in reasons.VALUES.values() for v in m.values()}
        for lang in ('en', 'zh-TW', 'ja'):
            d = json.load(open(os.path.join(I18N, lang + '.json'), encoding='utf-8'))
            for key, tpl in reasons.TEMPLATES.items():
                self.assertIn('creason.' + key, d, (lang, key))
                self.assertEqual(sorted(set(re.findall(r'\{(\w+)\}', tpl))),
                                 sorted(set(re.findall(r'\{(\w+)\}', d['creason.' + key]))), (lang, key))
                self.assertNotIn('jt-waf-mgr', d['creason.' + key])
            for v in values:
                self.assertIn('creason.v.' + v, d, (lang, v))


class TestShownWithTheChange(unittest.TestCase):
    def test_public_carries_the_parts(self):
        from jtwafmgr.changes import Workflow

        class _Wf:
            def _proposed_ip(self, cid):
                return None
        row = {'id': 1, 'op': 'add', 'kind': 'raw', 'item_id': None, 'rule_id': None, 'direction': 'tighten',
               'state': 'pending_approval', 'reason': reasons.text('resumed', what='everything'), 'proposed_by': 'x',
               'proposed_via': 'user', 'created_at': 0, 'updated_at': 0, 'spec': '{"text": "x", "placement": "after"}',
               'error': None, 'applied_version': None, 'proposed_owner': None}
        out = Workflow.public(_Wf(), row)
        self.assertEqual(out['reason_parts'][0]['key'], 'resumed')
        self.assertEqual(out['reason'], 'WAF resumed (everything)')      # the stored reason stays as it was


if __name__ == '__main__':
    unittest.main()
