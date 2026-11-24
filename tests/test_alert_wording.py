"""System alerts worded in the reader's language (0.5.43): CRS update, IP block list full or not written, country
lists not written, traffic spike, many 5xx. They carry a message key and its values; older alerts without the key
are worded from their values by kind, and fall back to the stored reason when those values are missing."""
import json
import os
import re
import unittest

from jtwafmgr import notify

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
I18N = os.path.join(ROOT, 'frontend', 'src', 'i18n')

CASES = [
    ({'kind': 'crs_update', 'msg': 'crs_update', 'version': '4.31.0', 'installed': '4.30.0'},
     ('4.31.0 已下載並驗證', '4.30.0')),
    ({'kind': 'other', 'msg': 'blocks_full', 'max': 500}, ('IP 封鎖清單已滿 (500 筆)',)),
    ({'kind': 'apply_failed', 'msg': 'blocks_apply_failed', 'summary': 'nginx -t failed'}, ('IP 封鎖清單寫入失敗：nginx -t failed',)),
    ({'kind': 'apply_failed', 'msg': 'countries_apply_failed', 'summary': 'TW.data: bad line'}, ('國家清單寫入失敗：TW.data: bad line',)),
    ({'kind': 'traffic_spike', 'msg': 'traffic_spike', 'hour': '2026-11-24T21:00:00+08:00', 'requests': 9000, 'usual': 812.4,
      'factor': 11.1}, ('21:00 起的一小時有 9000 個請求', '812 個的 11.1 倍')),
    ({'kind': 'traffic_errors', 'msg': 'traffic_errors', 'hour': '2026-11-24T21:00:00+08:00', 'requests': 400, 's5xx': 120,
      'percent': 30.0}, ('400 個請求中有 120 個回 5xx (30.0%)',)),
]


class TestAlertWording(unittest.TestCase):
    def test_each_language(self):
        for d, want in CASES:
            zh = notify.alert_text('zh-TW', dict(d, reason='english reason'))
            for w in want:
                self.assertIn(w, zh, d['msg'])
            for lang in ('en', 'ja'):
                s = notify.alert_text(lang, dict(d, reason='english reason'))
                self.assertNotIn('{', s, (lang, d['msg']))
                self.assertNotIn('english reason', s, (lang, d['msg']))

    def test_older_alerts(self):
        # raised before 0.5.43: no msg; the values are there -> worded by kind
        d = {'kind': 'crs_update', 'version': '4.31.0', 'installed': None, 'reason': 'OWASP CRS 4.31.0 is downloaded'}
        self.assertIn('4.31.0 已下載並驗證 (目前安裝 -)', notify.alert_text('zh-TW', d))
        # values missing -> the stored reason, never a sentence with blanks
        self.assertEqual(notify.alert_text('zh-TW', {'kind': 'crs_update', 'reason': 'old text'}), 'old text')
        self.assertEqual(notify.alert_text('zh-TW', {'kind': 'other', 'reason': 'the IP block list is full'}),
                         'the IP block list is full')

    @unittest.skipUnless(os.path.isdir(I18N), 'the dictionaries are in the source tree, not in a release')
    def test_interface_strings_match(self):
        # the web page words them with the same sentences as the notifications
        for lang in ('en', 'zh-TW', 'ja'):
            with open(os.path.join(I18N, lang + '.json'), encoding='utf-8') as fh:
                ui = json.load(fh)
            for m in notify.SYSTEM_MSGS:
                self.assertEqual(sorted(re.findall(r'\{(\w+)\}', ui['alerts.' + m])),
                                 sorted(re.findall(r'\{(\w+)\}', notify.TEXT[lang]['r.' + m])), (lang, m))

    def test_raisers_carry_the_key(self):
        # every place raising one of these alerts stores the message key
        for f, msgs in (('crsupdate.py', ['crs_update']), ('blocks.py', ['blocks_full', 'blocks_apply_failed']),
                        ('countries.py', ['countries_apply_failed']), ('traffic.py', ['traffic_spike', 'traffic_errors'])):
            with open(os.path.join(ROOT, 'jtwafmgr', f), encoding='utf-8') as fh:
                src = fh.read()
            for m in msgs:
                self.assertIn("'msg': '%s'" % m, src, (f, m))


if __name__ == '__main__':
    unittest.main()
