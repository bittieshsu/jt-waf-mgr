"""The Debian security tracker on installed Debian packages (debtracker.py, 0.5.5): Debian's fixed version for the
release decides; a CVE Debian lists for other packages only is not this package's; packages from elsewhere are never
compared. Synthetic pages and packages only."""
import gzip
import json
import os
import subprocess
import time
import unittest

from jtwafmgr import debtracker, distropkg
from tests.helpers import TempEnv


def page(sources, fixed):
    """A tracker page as security-tracker.debian.org writes it: the per-release table and the fixed-version table."""
    rows = ''.join('<tr><td><a href="/tracker/source-package/%s">%s</a> (<a href="#">PTS</a>)</td><td>%s</td><td>%s</td><td>%s</td></tr>'
                   % (s if i == 0 else '', s if i == 0 else '', rel, ver, st)
                   for s, lines in sources for i, (rel, ver, st) in enumerate(lines))
    rows2 = ''.join('<tr><td>%s</td><td>source</td><td>%s</td><td>%s</td><td></td><td></td><td></td></tr>' % x for x in fixed)
    return ('<html><body><table><tr><td><b>Name</b></td><td>CVE-2099-11111</td></tr></table>'
            '<table><tr><th>Source Package</th><th>Release</th><th>Version</th><th>Status</th></tr>%s</table>'
            '<table><tr><th>Package</th><th>Type</th><th>Release</th><th>Fixed Version</th><th>Urgency</th><th>Origin</th>'
            '<th>Debian Bugs</th></tr>%s</table></body></html>' % (rows, rows2))


BROTLI = page([('brotli', [('bookworm', '1.0.9-2', 'vulnerable'), ('bookworm (security)', '1.0.9-2+deb12u1', 'fixed'),
                           ('trixie', '1.1.0-2', 'vulnerable'), ('forky, sid', '1.2.0-4.1', 'fixed')]),
               ('nodejs', [('bookworm', '18.20.4+dfsg-1~deb12u2', 'vulnerable')])],
              [('brotli', 'bookworm', '1.0.9-2+deb12u1'), ('brotli', '(unstable)', '1.2.0-4.1'),
               ('nodejs', '(unstable)', '24.22.1+dfsg-1')])
BROTLI_U2 = page([('brotli', [('bookworm', '1.0.9-2', 'vulnerable'), ('bookworm (security)', '1.0.9-2+deb12u2', 'fixed')])],
                 [('brotli', 'bookworm', '1.0.9-2+deb12u2')])
OTHER = page([('chromium', [('bookworm', '150.0.1-1~deb12u1', 'vulnerable')])], [('chromium', '(unstable)', '(unfixed)')])
NOTAFF = page([('example', [('bookworm', '2.4.1-3', 'not affected')])], [('example', 'bookworm', '(not affected)')])


class TestVersions(unittest.TestCase):
    PAIRS = [('1.0.9-2', '1.0.9-2+deb12u1'), ('2.9.14+dfsg-1.3~deb12u6', '2.9.14+dfsg-1.3~deb12u5'), ('1.0~rc1-1', '1.0-1'),
             ('1:0.1-1', '2.0-1'), ('3.0.9-1+deb12u2', '3.0.9-1+deb12u10'), ('1.2.0-4.1', '1.2.0-4'), ('1.0a-1', '1.0-1'),
             ('1.30.7-1~bookworm', '1.30.7-1'), ('10', '9'), ('1.01-1', '1.1-1'), ('1.0+b1', '1.0'), ('1.0', '1.0')]

    def test_order_as_dpkg(self):
        want = {('1.0.9-2', '1.0.9-2+deb12u1'): -1, ('2.9.14+dfsg-1.3~deb12u6', '2.9.14+dfsg-1.3~deb12u5'): 1,
                ('1.0~rc1-1', '1.0-1'): -1, ('1:0.1-1', '2.0-1'): 1, ('3.0.9-1+deb12u2', '3.0.9-1+deb12u10'): -1,
                ('1.2.0-4.1', '1.2.0-4'): 1, ('1.0a-1', '1.0-1'): 1, ('1.30.7-1~bookworm', '1.30.7-1'): -1,
                ('10', '9'): 1, ('1.01-1', '1.1-1'): 0, ('1.0+b1', '1.0'): 1, ('1.0', '1.0'): 0}
        for (a, b), w in want.items():
            self.assertEqual(debtracker.vercmp(a, b), w, (a, b))
            self.assertEqual(debtracker.vercmp(b, a), -w, (b, a))

    @unittest.skipUnless(os.path.exists('/usr/bin/dpkg'), 'dpkg is not installed')
    def test_same_as_dpkg_itself(self):
        for a, b in self.PAIRS:
            got = debtracker.vercmp(a, b)
            op = {-1: 'lt', 0: 'eq', 1: 'gt'}[got]
            self.assertEqual(subprocess.run(['dpkg', '--compare-versions', a, op, b]).returncode, 0, (a, op, b))


class TestPage(unittest.TestCase):
    def test_parse(self):
        p = debtracker.parse(BROTLI)
        self.assertEqual(sorted(p['sources']), ['brotli', 'nodejs'])
        self.assertIn(('bookworm', '1.0.9-2+deb12u1', 'fixed'), p['sources']['brotli'])
        self.assertIn(('forky', '1.2.0-4.1', 'fixed'), p['sources']['brotli'])      # "forky, sid": both
        self.assertIn(('sid', '1.2.0-4.1', 'fixed'), p['sources']['brotli'])
        self.assertEqual(p['fixed']['brotli']['bookworm'], '1.0.9-2+deb12u1')
        self.assertIsNone(debtracker.parse(''))            # a 404: the CVE not known yet
        self.assertIsNone(debtracker.parse('<html><table><tr><td>x</td></tr></table></html>'))
        self.assertIsNone(debtracker.parse(None))

    def test_decide(self):
        p = debtracker.parse(BROTLI)
        d = debtracker.decide
        self.assertEqual(d(p, 'brotli', 'bookworm', '1.0.9-2+deb12u1')['result'], 'fixed')
        self.assertEqual(d(p, 'brotli', 'bookworm', '1.0.9-2+deb12u2')['result'], 'fixed')
        u = d(p, 'brotli', 'bookworm', '1.0.9-2')
        self.assertEqual((u['result'], u['fixed_version']), ('update', '1.0.9-2+deb12u1'))
        self.assertEqual(d(p, 'brotli', 'trixie', '1.1.0-2')['result'], 'open')
        self.assertEqual(d(p, 'nodejs', 'bookworm', '18.20.4+dfsg-1~deb12u2')['result'], 'open')
        self.assertEqual(d(p, 'brotli', 'bullseye', '1.0.9-1')['result'], 'unknown')       # a release not listed
        self.assertEqual(d(debtracker.parse(OTHER), 'libxml2', 'bookworm', '2.9.14+dfsg-1.3~deb12u6')['result'], 'not_tracked')
        self.assertEqual(d(debtracker.parse(NOTAFF), 'example', 'bookworm', '2.4.1-3')['result'], 'not_affected')
        self.assertEqual(d(None, 'brotli', 'bookworm', '1.0.9-2')['result'], 'unknown')

    def test_release(self):
        env = TempEnv()
        self.addCleanup(env.cleanup)
        osr = os.path.join(env.dir, 'os-release')
        with open(osr, 'w') as fh:
            fh.write('PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
        self.assertEqual(debtracker.release_of('2.4.1-3', osr), 'bookworm')
        self.assertEqual(debtracker.release_of('1.1.0-2+deb13u1', osr), 'trixie')     # the package's own tag first
        with open(osr, 'w') as fh:
            fh.write('ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n')
        self.assertIsNone(debtracker.release_of('2.4.1-3', osr))                      # Ubuntu: Debian's tracker is not its
        self.assertIsNone(debtracker.release_of('2.4.1-3', os.path.join(env.dir, 'none')))


STATUS = '''Package: libbrotli1
Status: install ok installed
Source: brotli
Version: 1.0.9-2+deb12u1

Package: libxml2
Status: install ok installed
Version: 2.9.14+dfsg-1.3~deb12u6

Package: nginx
Status: install ok installed
Version: 1.30.7-1~bookworm
Maintainer: NGINX Packaging <packaging@example.com>

Package: libexample0
Status: install ok installed
Source: example
Version: 2.4.1-3+deb12u1
'''


class TestThreats(unittest.TestCase):
    def setUp(self):
        self.env = TempEnv(intel={'debian': True})
        self.addCleanup(self.env.cleanup)
        d = self.env.dir
        status = os.path.join(d, 'status')
        with open(status, 'w') as fh:
            fh.write(STATUS)
        doc = os.path.join(d, 'doc')
        for pkg in ('libbrotli1', 'libxml2', 'nginx', 'libexample0'):
            os.makedirs(os.path.join(doc, pkg))
            with gzip.open(os.path.join(doc, pkg, 'changelog.Debian.gz'), 'wt') as fh:
                fh.write('%s (1.0-1) unstable\n  * Nothing about it.\n' % pkg)
        self.osr = os.path.join(d, 'os-release')
        with open(self.osr, 'w') as fh:
            fh.write('ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n')
        orig = (distropkg.DPKG_STATUS, distropkg.DOC_DIR, debtracker.OS_RELEASE)
        distropkg.DPKG_STATUS, distropkg.DOC_DIR, debtracker.OS_RELEASE = status, doc, self.osr
        self.addCleanup(lambda: (setattr(distropkg, 'DPKG_STATUS', orig[0]), setattr(distropkg, 'DOC_DIR', orig[1]),
                                 setattr(debtracker, 'OS_RELEASE', orig[2])))
        self.asked = []

    def lookup(self, pages):
        def get(url, timeout):
            self.asked.append(url)
            return pages.get(url.rsplit('/', 1)[1], '')
        return debtracker.Lookup(self.env.cfg, get=get, sleep=lambda s: None, log=lambda m: None)

    def threat(self, cve, product, version):
        t = {'id': cve, 'product': product, 'our_version': version, 'affected': 'yes', 'exploited': True}
        distropkg.apply(t)
        return t

    def test_apply(self):
        from jtwafmgr import intel
        lk = self.lookup({'CVE-2099-11111': BROTLI_U2, 'CVE-2099-22222': OTHER})
        t = self.threat('CVE-2099-11111', 'Brotli', '1.0.9-2+deb12u1')
        self.assertEqual(t['distro_check']['result'], 'not_listed')
        self.assertEqual(debtracker.apply(t, lk)['result'], 'update')
        self.assertEqual((t['affected'], t['debian_check']['fixed_version']), ('yes', '1.0.9-2+deb12u2'))
        self.assertTrue(intel.is_urgent(t))           # Debian says this release is still affected
        t = self.threat('CVE-2099-22222', 'libxml2', '2.9.14+dfsg-1.3~deb12u6')
        self.assertEqual(debtracker.apply(t, lk)['result'], 'not_tracked')
        self.assertEqual((t['affected'], t['affected_model']), ('no', 'yes'))
        self.assertFalse(intel.is_urgent(t))
        # nginx.org's package: never compared with Debian's nginx
        t = self.threat('CVE-2099-11111', 'nginx', '1.30.7-1~bookworm')
        self.assertFalse(t['distro_check']['debian'])
        self.assertIsNone(debtracker.apply(t, lk))
        # asked once each, then from the cache (a second lookup reads the saved file)
        self.assertEqual(len(self.asked), 2)
        lk.save()
        lk2 = self.lookup({})
        t = self.threat('CVE-2099-22222', 'libxml2', '2.9.14+dfsg-1.3~deb12u6')
        self.assertEqual(debtracker.apply(t, lk2)['result'], 'not_tracked')
        self.assertEqual(len(self.asked), 2)

    def test_debian_or_not(self):
        self.assertTrue(distropkg.is_debian('libx1', '1.0-1', 'Example Team <team@lists.debian.org>'))  # preflight:allow
        self.assertTrue(distropkg.is_debian('libx1', '1.0-1+deb12u3', ''))
        self.assertFalse(distropkg.is_debian('nginx', '1.30.7-1~bookworm', 'NGINX Packaging <packaging@example.com>'))
        self.assertFalse(distropkg.is_debian('libx1', '1.0-1', ''))

    def test_limits(self):
        lk = self.lookup({})
        for i in range(debtracker.MAX_PER_RUN + 5):
            lk.page('CVE-2099-%05d' % (10000 + i))
        self.assertEqual(len(self.asked), debtracker.MAX_PER_RUN)
        self.assertTrue(all(u.startswith(debtracker.URL + 'CVE-2099-') for u in self.asked))   # only the id is sent

    def test_off_asks_nothing(self):
        from jtwafmgr import intel
        from jtwafmgr.app import App
        self.env.cfg.data['intel']['debian'] = False
        app = App(self.env.cfg, start_collector=False)
        orig = debtracker._get
        debtracker._get = lambda url, timeout: self.fail('asked while off')
        self.addCleanup(setattr, debtracker, '_get', orig)
        now = time.time()
        t = {'id': 'CVE-2099-22222', 'product': 'libxml2', 'our_version': '2.9.14+dfsg-1.3~deb12u6', 'affected': 'yes'}
        app.db.x('INSERT INTO intel_threats(cve, product, first_seen, last_seen, affected, exploited, severity, details) '
                 'VALUES (?,?,?,?,?,?,?,?)', ('CVE-2099-22222', 'libxml2', now, now, 'yes', 1, 'critical', json.dumps(t)))
        self.assertEqual(intel.retire_by_distro(app, log=lambda m: None), [])

    def test_set_aside_and_alert_handled(self):
        from jtwafmgr import alerts, intel
        from jtwafmgr.app import App
        app = App(self.env.cfg, start_collector=False)
        orig = debtracker._get
        pages = {'CVE-2099-22222': OTHER, 'CVE-2099-11111': BROTLI_U2, 'CVE-2099-33333': NOTAFF}
        debtracker._get = lambda url, timeout: pages.get(url.rsplit('/', 1)[1], '')
        self.addCleanup(setattr, debtracker, '_get', orig)
        orig_sleep = debtracker.SPACING
        debtracker.SPACING = 0
        self.addCleanup(setattr, debtracker, 'SPACING', orig_sleep)
        now = time.time()
        ids = {}
        for cve, product, ver in (('CVE-2099-22222', 'libxml2', '2.9.14+dfsg-1.3~deb12u6'), ('CVE-2099-11111', 'Brotli', '1.0.9-2+deb12u1'),
                                  ('CVE-2099-33333', 'Example', '2.4.1-3+deb12u1')):
            t = {'id': cve, 'product': product, 'our_version': ver, 'affected': 'yes', 'exploited': True}
            ids[cve] = app.db.x('INSERT INTO intel_threats(cve, product, first_seen, last_seen, affected, exploited, severity, details) '
                                'VALUES (?,?,?,?,?,?,?,?)', (cve, product, now, now, 'yes', 1, 'critical', json.dumps(t))).lastrowid
            alerts.raise_alert(app.db, app.audit, 'intel', 'exploited_vulnerability', 'warning', 'intel-check:%s:%s' % (cve, product),
                               {'reason': 'test'}, link='/intel')
        done = intel.retire_by_distro(app, log=lambda m: None)
        self.assertEqual(sorted(done), sorted([ids['CVE-2099-22222'], ids['CVE-2099-33333']]))
        a = app.db.one("SELECT state, note FROM alerts WHERE dedup='intel-check:CVE-2099-22222:libxml2'")
        self.assertEqual(a['state'], 'handled')
        self.assertIn('lists other packages only', a['note'])
        r = app.db.one('SELECT status, details FROM intel_threats WHERE id=?', (ids['CVE-2099-11111'],))
        d = json.loads(r['details'])
        self.assertEqual((r['status'], d['debian_check']['result']), ('open', 'update'))     # update the package
        self.assertEqual(app.db.one("SELECT state FROM alerts WHERE dedup='intel-check:CVE-2099-11111:Brotli'")['state'], 'open')
        audit = [json.loads(x['details'] or '{}') for x in app.db.q("SELECT details FROM audit WHERE action='intel.threat_status'")]
        self.assertTrue(audit and all(x.get('reason') == 'debian_tracker' for x in audit))


if __name__ == '__main__':
    unittest.main()
