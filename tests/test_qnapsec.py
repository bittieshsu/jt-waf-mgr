"""QNAP's advisory feed (0.5.41): parsed with fixed patterns, downloaded only when on and a QNAP product is confirmed,
the recent advisories naming a confirmed product first, advisories seen before kept (the feed has only the newest 20).
A synthetic feed; no network."""
import os
import time
import unittest

from jtwafmgr import qnapsec
from tests.helpers import TempEnv

NOW = 1795000000
QUIET = lambda m: None      # noqa: E731 -- G10 reads the last line of the whole run


def item(n, title, when, desc='A vulnerability has been reported to affect several versions.', link=None):
    return ('<item><title>%s</title><pubDate>%s</pubDate><description><![CDATA[%s ... <a href="%s" target=\'_blank\'>'
            'More</a>]]></description><category>Press Releases</category><link>%s</link><guid isPermaLink="false">%s'
            '</guid></item>' % (title, time.strftime('%a, %d %b %Y %H:%M:%S +0800', time.gmtime(when)), desc,
                                link or 'https://www.qnap.com/en/security-advisory/QSA-99-%02d' % n,
                                link or 'https://www.qnap.com/en/security-advisory/QSA-99-%02d' % n, title))


def feed(items):
    return ('<?xml version="1.0" encoding="utf-8"?>\n<rss version="2.0"><channel><title>QNAP</title>%s</channel></rss>'
            % ''.join(items)).encode()


RECENT = [item(1, 'Multiple Vulnerabilities in QTS, QuTS hero, and QuTS cloud', NOW - 3 * 86400,
               'CVE-2099-0001: command injection &amp; more <b>bold</b>'),
          item(2, 'Vulnerabilities in PHP (PHP2Shell) Affecting Multiple QNAP Products', NOW - 2 * 86400),
          item(3, 'Multiple Vulnerabilities in File Station 5', NOW - 10 * 86400),
          item(4, 'Vulnerability in QuMagie', NOW - 20 * 86400, link='javascript:alert(1)'),
          item(5, 'Vulnerability in legacy QTS with NFS service enabled', NOW - 30 * 86400),
          item(6, 'QNAP Products Not Affected by SSHhole Vulnerability', NOW - 40 * 86400),
          item(7, 'Vulnerability in QVR Pro', NOW - 400 * 86400)]


class TestQnapFeed(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.cfg = self.env.cfg
        self.cfg['intel']['qnap'] = True
        self.products = [{'name': 'QNAP QTS', 'version': '5.1.4-20231128'}, {'name': 'QNAP File Station', 'version': ''},
                         {'name': 'Nextcloud', 'version': '30.0.2'}]

    def test_parse(self):
        d = qnapsec.parse(feed(RECENT))
        a = {x['id']: x for x in d['advisories']}
        self.assertEqual(len(a), 6)                         # item 4's link is no address: no advisory number either
        self.assertEqual(a['QSA-99-01']['products'], ['QTS', 'QuTS hero', 'QuTS cloud'])
        self.assertEqual(a['QSA-99-01']['cves'], ['CVE-2099-0001'])
        self.assertEqual(a['QSA-99-01']['summary'], 'CVE-2099-0001: command injection & more bold')   # text only
        self.assertEqual(a['QSA-99-02']['products'], [])     # "Multiple QNAP Products"
        self.assertEqual(a['QSA-99-03']['products'], ['File Station 5'])
        self.assertEqual(a['QSA-99-05']['products'], ['QTS'])
        self.assertEqual(a['QSA-99-06']['products'], [])     # not affected
        self.assertEqual(d['advisories'][0]['id'], 'QSA-99-02')               # newest first
        for bad in (b'<html>not a feed</html>', feed(RECENT[:3]), 'caf\xe9'.encode('latin-1')):
            with self.assertRaises(qnapsec.QnapError):
                qnapsec.parse(bad)

    def test_update_and_matching(self):
        got = []

        def get(url, timeout):
            got.append(url)
            return feed(RECENT)
        self.assertEqual(qnapsec.update(self.cfg, self.products[2:], get=get, now=NOW, log=QUIET), 'off')   # no QNAP product
        self.cfg['intel']['qnap'] = False
        self.assertEqual(qnapsec.update(self.cfg, self.products, get=get, now=NOW, log=QUIET), 'off')
        self.cfg['intel']['qnap'] = True
        self.assertEqual(got, [])
        self.assertEqual(qnapsec.update(self.cfg, self.products, get=get, now=NOW, log=QUIET), 'updated')
        self.assertEqual(got, [qnapsec.URL])
        self.assertEqual(oct(os.stat(qnapsec.path(self.cfg)).st_mode & 0o777), '0o600')
        self.assertEqual(qnapsec.update(self.cfg, self.products, get=get, now=time.time(), log=QUIET), 'fresh')
        m = qnapsec.matching(self.cfg, self.products, days=180, now=NOW)
        self.assertEqual([x['id'] for x in m], ['QSA-99-01', 'QSA-99-03', 'QSA-99-05', 'QSA-99-02', 'QSA-99-06'])
        self.assertEqual(m[0]['about'], ['QNAP QTS'])
        self.assertEqual(m[1]['about'], ['QNAP File Station'])     # "File Station 5"
        self.assertEqual(m[3]['about'], [])                        # about PHP: listed after them
        # the next feed has dropped the oldest ones: those seen before stay
        os.utime(qnapsec.path(self.cfg), (NOW - 30 * 3600, NOW - 30 * 3600))
        newer = [item(8, 'Vulnerability in QTS', NOW - 86400)] + RECENT[:3] + RECENT[4:6]
        self.assertEqual(qnapsec.update(self.cfg, self.products, get=lambda u, t: feed(newer), now=NOW, log=QUIET), 'updated')
        self.assertEqual(qnapsec.status(self.cfg)['advisories'], 7)
        # a failed download keeps the copy there is
        os.utime(qnapsec.path(self.cfg), (NOW - 30 * 3600, NOW - 30 * 3600))
        self.assertEqual(qnapsec.update(self.cfg, self.products, get=lambda u, t: b'<html>', now=NOW, log=QUIET),
                         'failed:not_the_feed')
        self.assertEqual(len(qnapsec.matching(self.cfg, self.products, now=NOW)), 6)


if __name__ == '__main__':
    unittest.main()
