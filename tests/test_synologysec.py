"""Synology's advisory feed (0.5.34): parsed with fixed patterns, downloaded only when on and a Synology product is
confirmed, the recent advisories naming a confirmed product first. A synthetic feed; no network."""
import os
import time
import unittest

from jtwafmgr import synologysec
from tests.helpers import TempEnv

NOW = 1795000000
QUIET = lambda m: None      # noqa: E731 -- G10 reads the last line of the whole run


def item(n, title, when, desc='Synology has released a security update.', link=None):
    return ('<item><title>%s</title><link>%s</link><description><![CDATA[%s]]></description>'
            '<pubDate>%s</pubDate><guid isPermaLink="true">x</guid></item>'
            % (title, link or 'https://www.synology.com/en-global/support/security/Synology_SA_99_%02d' % n, desc,
               time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime(when))))


def feed(extra=()):
    items = list(extra) + [item(i, 'Synology-SA-%02d:%02d SRM' % (10 + i // 50, i % 50), NOW - 400 * 86400 - i * 3600)
                           for i in range(120)]
    items.append('<item><title>DSM 4.0-2259</title><link>https://www.synology.com/x</link><description>old</description>'
                 '<pubDate>Mon, 01 Jan 2014 00:00:00 +0000</pubDate></item>')
    return ('<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Synology</title>%s</channel></rss>'
            % ''.join(items)).encode()


RECENT = [item(1, 'Synology-SA-99:01 DSM, BeeStation OS', NOW - 3 * 86400, 'CVE-2099-0001 allows remote attackers to read files.'),
          item(2, 'Synology-SA-99:02 NGINX2Root', NOW - 2 * 86400, 'CVE-2099-0002 &amp; more <b>bold</b>'),
          item(3, 'Synology-SA-99:03 Synology Photos', NOW - 10 * 86400),
          item(4, 'Synology-SA-99:04 DSM (PWN2OWN 2099)', NOW - 20 * 86400, link='javascript:alert(1)'),
          item(5, 'Synology-SA-99:05 Calendar', NOW - 30 * 86400)]


class TestSynologyFeed(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv()
        self.addCleanup(self.env.cleanup)
        self.cfg = self.env.cfg
        self.cfg['intel']['synology'] = True
        self.products = [{'name': 'Synology DSM', 'version': '7.4-90080'}, {'name': 'Synology Calendar', 'version': ''},
                         {'name': 'Nextcloud', 'version': '30.0.2'}]

    def test_parse(self):
        d = synologysec.parse(feed(RECENT))
        a = {x['id']: x for x in d['advisories']}
        self.assertEqual(len(a), 125)                                 # the DSM 4 notice has no advisory number
        self.assertEqual(a['Synology-SA-99:01']['products'], ['DSM', 'BeeStation OS'])
        self.assertEqual(a['Synology-SA-99:01']['cves'], ['CVE-2099-0001'])
        self.assertEqual(a['Synology-SA-99:02']['summary'], 'CVE-2099-0002 & more bold')    # text only
        self.assertEqual(a['Synology-SA-99:04']['link'], '')                               # not a synology.com address
        self.assertEqual(d['advisories'][0]['id'], 'Synology-SA-99:02')                    # newest first
        for bad in (b'<html>not a feed</html>', feed()[:3000], 'caf\xe9'.encode('latin-1')):
            with self.assertRaises(synologysec.SynologyError):
                synologysec.parse(bad)

    def test_update_and_matching(self):
        got = []

        def get(url, timeout):
            got.append(url)
            return feed(RECENT)
        self.assertEqual(synologysec.update(self.cfg, self.products[2:], get=get, now=NOW, log=QUIET), 'off')   # no Synology product
        self.cfg['intel']['synology'] = False
        self.assertEqual(synologysec.update(self.cfg, self.products, get=get, now=NOW, log=QUIET), 'off')
        self.cfg['intel']['synology'] = True
        self.assertEqual(got, [])
        self.assertEqual(synologysec.update(self.cfg, self.products, get=get, now=NOW, log=QUIET), 'updated')
        self.assertEqual(got, [synologysec.URL])
        self.assertEqual(oct(os.stat(synologysec.path(self.cfg)).st_mode & 0o777), '0o600')
        self.assertEqual(synologysec.update(self.cfg, self.products, get=get, now=time.time(), log=QUIET), 'fresh')
        m = synologysec.matching(self.cfg, self.products, days=180, now=NOW)
        self.assertEqual([x['id'] for x in m], ['Synology-SA-99:01', 'Synology-SA-99:04', 'Synology-SA-99:05',
                                                'Synology-SA-99:02', 'Synology-SA-99:03'])
        self.assertEqual(m[0]['about'], ['Synology DSM'])
        self.assertEqual(m[1]['about'], ['Synology DSM'])                 # "DSM (PWN2OWN 2099)"
        self.assertEqual(m[2]['about'], ['Synology Calendar'])            # "Calendar"
        self.assertEqual(m[3]['about'], [])                                # a nickname: listed after them
        self.assertEqual(synologysec.status(self.cfg)['advisories'], 125)
        # a failed download keeps the copy there is
        os.utime(synologysec.path(self.cfg), (NOW - 30 * 3600, NOW - 30 * 3600))
        self.assertEqual(synologysec.update(self.cfg, self.products, get=lambda u, t: b'<html>', now=NOW, log=QUIET), 'failed:not_the_feed')
        self.assertEqual(len(synologysec.matching(self.cfg, self.products, now=NOW)), 5)


if __name__ == '__main__':
    unittest.main()
