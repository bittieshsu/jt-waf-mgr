"""The Debian security tracker (security-tracker.debian.org): whether Debian has fixed a CVE in the installed package
(0.5.5).

The installed package's change log (distropkg.py) says "fixed" only when the fix is already installed. When it does not
name the CVE, the tracker says the rest: Debian fixed it in a newer package of this release (update the package), has
not fixed it yet, marks this release not affected -- or does not list the package for this CVE at all (the CVE belongs
to another program: "Use after free in XML in Google Chrome" is Chromium's, not libxml2's).

Off by default (intel.debian). When on, the threat-intelligence unit asks
https://security-tracker.debian.org/tracker/<CVE id> (only the id is sent) for threats on a package installed here from
Debian, at most MAX_PER_RUN a run, one request every SPACING seconds; answers are kept TTL
(<data dir>/intel/debian-cache.json). Packages from elsewhere (nginx.org's nginx, "1.30.7-1~bookworm") are never
compared with Debian's versions.

    fixed         the installed version is at or after Debian's fixed version for this release -> does not affect us
    not_affected  Debian marks this release not affected                                         -> does not affect us
    not_tracked   the tracker knows the CVE but lists other packages only                        -> does not affect us
    update        Debian fixed it in a newer package of this release: update the package (it still affects us)
    open          Debian has not fixed it in this release yet (it still affects us)
    unknown       no answer, the CVE not known yet, or a release the tracker does not list: nothing changes
"""
import html
import json
import os
import re
import socket
import time
import urllib.parse

from . import __version__, util

URL = 'https://security-tracker.debian.org/tracker/'
MAX_BYTES = 1024 * 1024
MAX_PER_RUN = 20
SPACING = 2.0
TTL = 86400
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
SRC_RE = re.compile(r'^[a-z0-9][a-z0-9+.-]{0,99}$')
CODENAMES = {'10': 'buster', '11': 'bullseye', '12': 'bookworm', '13': 'trixie', '14': 'forky', '15': 'duke'}
RELEASE_RE = re.compile(r'^[a-z]{3,20}$')
NOT_AFFECTING = ('fixed', 'not_affected', 'not_tracked')
OS_RELEASE = '/etc/os-release'


class TrackerError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


# ----- versions (dpkg's order: deb-version(7)) -----

def _order(c):
    if c == '~':
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_part(a, b):
    """dpkg's verrevcmp: runs of non-digits by _order (the end of a string counts 0), runs of digits as numbers."""
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i, j = i + 1, j + 1
        while i < len(a) and a[i] == '0':
            i += 1
        while j < len(b) and b[j] == '0':
            j += 1
        first = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first:
                first = (a[i] > b[j]) - (a[i] < b[j])
            i, j = i + 1, j + 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first:
            return first
    return 0


def _split(v):
    v = v.strip()
    epoch, _, rest = v.partition(':') if ':' in v else ('0', '', v)
    up, _, rev = rest.rpartition('-') if '-' in rest else (rest, '', '0')
    return int(epoch) if epoch.isdigit() else 0, up, rev


def vercmp(a, b):
    """-1, 0 or 1, as `dpkg --compare-versions a lt|eq|gt b`."""
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _cmp_part(ua, ub) or _cmp_part(ra, rb)


# ----- the release -----

def release_of(version, os_release=None):
    """The Debian release a package version belongs to: its +debNNuN tag ("2.9.14+dfsg-1.3~deb12u6" -> bookworm), else
    this host's own Debian release. None on another distribution."""
    m = re.search(r'[+~]deb(\d+)u\d', version or '')
    if m:
        return CODENAMES.get(m.group(1))
    try:
        with open(os_release or OS_RELEASE, encoding='utf-8') as fh:
            f = dict(re.findall(r'^([A-Z_]+)="?([^"\n]*)"?$', fh.read(), re.M))
    except OSError:
        return None
    if f.get('ID') != 'debian':
        return None
    name = f.get('VERSION_CODENAME') or CODENAMES.get(f.get('VERSION_ID', '').split('.')[0])
    return name if name and RELEASE_RE.match(name) else None


# ----- the tracker's page -----

def _cells(tr):
    return [html.unescape(re.sub(r'<[^>]+>', '', c)).strip() for c in re.findall(r'<t[hd][^>]*>(.*?)</t[hd]>', tr, re.S)]


def parse(text):
    """The page of one CVE: {'sources': {source: [(release, version, status)]}, 'fixed': {source: {release: version}}},
    or None (not a CVE page: unknown id, an error page)."""
    if not isinstance(text, str) or '<table' not in text:
        return None
    sources, fixed, seen = {}, {}, False
    for table in re.findall(r'<table[^>]*>(.*?)</table>', text, re.S):
        rows = [_cells(tr) for tr in re.findall(r'<tr[^>]*>(.*?)</tr>', table, re.S)]
        if not rows:
            continue
        head = [c.lower() for c in rows[0]]
        if head[:4] == ['source package', 'release', 'version', 'status']:
            seen = True
            cur = None
            for r in rows[1:]:
                if len(r) < 4:
                    continue
                name = re.sub(r'\s*\(PTS\)$', '', r[0]).strip()
                if name:
                    cur = name if SRC_RE.match(name) else None
                if not cur:
                    continue
                for rel in r[1].split(','):
                    rel = re.sub(r'\s*\(.*\)$', '', rel).strip()
                    if RELEASE_RE.match(rel):
                        sources.setdefault(cur, []).append((rel, r[2], r[3].lower()))
        elif head[:4] == ['package', 'type', 'release', 'fixed version']:
            seen = True
            for r in rows[1:]:
                if len(r) < 4 or not SRC_RE.match(r[0]):
                    continue
                rel = r[2].strip() or '(unstable)'
                fixed.setdefault(r[0], {})[rel] = r[3]
    return {'sources': sources, 'fixed': fixed} if seen else None


def decide(page, source, release, installed):
    """What the tracker's page says about the installed version of a source package in a release (see the module)."""
    if not page or not source or not release or not installed:
        return {'result': 'unknown'}
    rows = page['sources'].get(source)
    if rows is None and source not in page['fixed']:
        return {'result': 'not_tracked', 'listed': sorted(page['sources'])[:8]}
    if str((page['fixed'].get(source) or {}).get(release, '')).strip().lower() == '(not affected)':
        return {'result': 'not_affected', 'release': release}
    mine = [(v, s) for rel, v, s in rows or [] if rel == release]
    if not mine:
        return {'result': 'unknown', 'release': release}
    if all(s.startswith('not affected') for _v, s in mine):
        return {'result': 'not_affected', 'release': release}
    fixes = sorted((v for v, s in mine if s == 'fixed'), key=_Key)
    for v in fixes:
        if vercmp(installed, v) >= 0:
            return {'result': 'fixed', 'release': release, 'fixed_version': v}
    if fixes:
        return {'result': 'update', 'release': release, 'fixed_version': fixes[0]}
    return {'result': 'open', 'release': release}


class _Key:
    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        return vercmp(self.v, other.v) < 0


def _get(url, timeout):
    from .intel import _public
    import http.client
    u = urllib.parse.urlsplit(url)
    ip = _public(u.hostname, 443)
    if not ip:
        raise TrackerError('not_public')

    class Pinned(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection((ip, 443), timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=u.hostname)

    conn = Pinned(u.hostname, 443, timeout=timeout, context=util.tls_context())
    try:
        conn.request('GET', u.path, headers={'Host': u.hostname, 'Accept': 'text/html',
                                             'User-Agent': 'jt-waf-mgr/' + __version__ + ' (threat intelligence)'})
        r = conn.getresponse()
        if r.status == 404:
            return ''
        if r.status != 200:
            raise TrackerError('http_%d' % r.status)
        raw = r.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise TrackerError('too_large')
        return raw.decode('utf-8', 'replace')
    finally:
        conn.close()


def cache_path(cfg):
    return os.path.join(os.path.dirname(os.path.abspath(cfg['paths']['db'])), 'intel', 'debian-cache.json')


class Lookup:
    """The tracker's pages of one run: cached TTL, at most MAX_PER_RUN asked."""

    def __init__(self, cfg, get=None, now=None, sleep=time.sleep, log=print):
        self.cfg, self.get, self.sleep, self.log = cfg, get or _get, sleep, log
        self.now = now or time.time()
        self.asked = 0
        try:
            with open(cache_path(cfg), encoding='utf-8') as fh:
                self.cache = json.load(fh)
        except (OSError, ValueError):
            self.cache = {}
        if not isinstance(self.cache, dict):
            self.cache = {}

    def page(self, cve):
        hit = self.cache.get(cve)
        if isinstance(hit, dict) and self.now - hit.get('at', 0) < TTL:
            return hit.get('page')
        if self.asked >= MAX_PER_RUN:
            return None
        if self.asked:
            self.sleep(SPACING)
        self.asked += 1
        try:
            page = parse(self.get(URL + cve, 30))
        except Exception as e:      # noqa: BLE001 -- one CVE's question failed; the others go on
            self.log('debian: %s: %s' % (cve, getattr(e, 'code', type(e).__name__)))
            return None
        self.cache[cve] = {'at': self.now, 'page': page}
        return page

    def save(self):
        if not self.asked:
            return
        p = cache_path(self.cfg)
        os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
        tmp = p + '.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump({k: v for k, v in self.cache.items() if isinstance(v, dict) and self.now - v.get('at', 0) < TTL * 2}, fh)
        os.replace(tmp, p)
        self.log('debian: asked the security tracker about %d CVEs' % self.asked)


def apply(t, lookup, os_release=None):
    """The tracker's answer on one threat whose installed Debian package's change log does not name the CVE:
    t['debian_check']; not affecting -> t['affected'] = 'no' (the model's kept as t['affected_model']). Returns it or
    None (not asked: not a Debian package, nothing to ask)."""
    dc = t.get('distro_check') or {}
    cve = t.get('id') or ''
    if dc.get('result') not in ('not_listed', 'unknown') or not dc.get('debian') or not dc.get('source') \
            or not CVE_RE.match(cve):
        return None
    from .intel import known_version
    installed = known_version(t.get('our_version'))
    release = release_of(installed, os_release)
    if not release:
        return None
    page = lookup.page(cve)
    if page is None:
        return None
    res = dict(decide(page, dc['source'], release, installed), source=dc['source'], package=dc.get('package') or '')
    t['debian_check'] = res
    if res['result'] in NOT_AFFECTING and t.get('affected') != 'no':
        t['affected_model'], t['affected'] = t.get('affected'), 'no'
    return res
