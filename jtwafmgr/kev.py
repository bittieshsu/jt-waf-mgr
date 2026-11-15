"""CISA Known Exploited Vulnerabilities (KEV) catalog: the structured source of "exploited in the wild".

Off by default (intel.kev). When on, the threat-intelligence unit (jt-waf-mgr-intel.service; the web service never
connects out) downloads the catalog at most once a day from CISA over https, to a public address only, checks that it
is the catalog (its JSON layout and a plausible number of entries), and replaces the local copy atomically
(<data dir>/intel/kev.json, 0600). A failed or odd download keeps the copy there is.

Use: ids(cfg) -- the CVE ids in the catalog; matching(cfg, products) -- the entries for the confirmed software, as a
hint for the model; a threat whose id is in the catalog counts as exploited (the source is noted).
"""
import json
import os
import re
import socket
import time
import urllib.parse

from . import __version__, util

URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
MAX_BYTES = 16 * 1024 * 1024
MIN_ENTRIES = 500                   # the catalog has well over a thousand; fewer means something else was served
REFRESH = 20 * 3600
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
_cache = {'mtime': None, 'data': None}


class KevError(Exception):
    def __init__(self, code, detail=''):
        super().__init__(code)
        self.code, self.detail = code, util.clip(str(detail), 200)


def path(cfg):
    return os.path.join(os.path.dirname(os.path.abspath(cfg['paths']['db'])), 'intel', 'kev.json')


def _download(url, timeout):
    """The catalog's bytes: https, port 443, a public address only (the same rule as the other fetches)."""
    from .intel import _public          # one place decides what a public address is
    import http.client
    u = urllib.parse.urlsplit(url)
    if u.scheme != 'https' or not u.hostname:
        raise KevError('bad_url')
    ip = _public(u.hostname, 443)
    if not ip:
        raise KevError('not_public', u.hostname)

    class Pinned(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection((ip, 443), timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=u.hostname)

    conn = Pinned(u.hostname, 443, timeout=timeout, context=util.tls_context())
    try:
        conn.request('GET', u.path, headers={'Host': u.hostname, 'Accept': 'application/json',
                                             'User-Agent': 'jt-waf-mgr/' + __version__ + ' (threat intelligence)'})
        r = conn.getresponse()
        if r.status != 200:
            raise KevError('http_%d' % r.status)
        body = r.read(MAX_BYTES + 1)
        if len(body) > MAX_BYTES:
            raise KevError('too_large')
        return body
    finally:
        conn.close()


def parse(raw):
    """{cve: {vendor, product, name, added, ransomware}} from the catalog's JSON, or KevError."""
    try:
        d = json.loads(raw)
    except ValueError:
        raise KevError('not_json')
    vulns = d.get('vulnerabilities') if isinstance(d, dict) else None
    if not isinstance(vulns, list) or len(vulns) < MIN_ENTRIES:
        raise KevError('not_the_catalog', 'entries: %s' % (len(vulns) if isinstance(vulns, list) else 'none'))
    out = {}
    for v in vulns:
        cid = str((v or {}).get('cveID') or '').strip().upper()
        if not CVE_RE.match(cid):
            continue
        out[cid] = {'vendor': util.clip(str(v.get('vendorProject') or ''), 80), 'product': util.clip(str(v.get('product') or ''), 80),
                    'name': util.clip(str(v.get('vulnerabilityName') or ''), 200), 'added': util.clip(str(v.get('dateAdded') or ''), 10),
                    'ransomware': str(v.get('knownRansomwareCampaignUse') or '').lower() == 'known'}
    if len(out) < MIN_ENTRIES:
        raise KevError('not_the_catalog', 'valid entries: %d' % len(out))
    return {'catalog_version': util.clip(str(d.get('catalogVersion') or ''), 40), 'entries': out}


def update(cfg, get=None, now=None, log=print):
    """Download when on and the copy is older than REFRESH. Returns 'off', 'fresh', 'updated' or 'failed:<code>'."""
    if not cfg['intel'].get('kev'):
        return 'off'
    p = path(cfg)
    now = now or time.time()
    try:
        if now - os.path.getmtime(p) < REFRESH:
            return 'fresh'
    except OSError:
        pass
    try:
        raw = (get or _download)(URL, 60)
        d = parse(raw)
    except KevError as e:
        log('kev: download failed: %s %s' % (e.code, e.detail))
        return 'failed:' + e.code
    except OSError as e:
        log('kev: download failed: %s' % type(e).__name__)
        return 'failed:network'
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    tmp = p + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(dict(d, fetched_at=util.iso(now)), fh)
    os.replace(tmp, p)
    log('kev: %d entries (catalog %s)' % (len(d['entries']), d['catalog_version']))
    return 'updated'


def load(cfg):
    """The local copy ({catalog_version, fetched_at, entries}) or None; read again only when the file changes."""
    p = path(cfg)
    try:
        m = os.path.getmtime(p)
    except OSError:
        return None
    if _cache['mtime'] != (p, m):
        try:
            with open(p, encoding='utf-8') as fh:
                _cache['data'] = json.load(fh)
        except (OSError, ValueError):
            _cache['data'] = None
        _cache['mtime'] = (p, m)
    return _cache['data']


def ids(cfg):
    d = load(cfg) if cfg['intel'].get('kev') else None
    return set((d or {}).get('entries', {}))


def _norm(s):
    return re.sub(r'[^a-z0-9]+', ' ', str(s or '').lower()).strip()


def _same_product(name, prod, vend):
    """Loose on purpose (it is only a hint): "OpenSSH" = OpenSSH; "Apache HTTP Server" = Apache + HTTP Server;
    "Zimbra" in "Zimbra Collaboration Suite"; "Exchange (OWA)" in "Exchange Server" (the first word, 4+ letters)."""
    if not prod:
        return False
    if name in (prod, vend + ' ' + prod):
        return True
    first = name.split(' ')[0]
    return len(first) >= 4 and first in prod.split(' ')


def matching(cfg, products, limit=40):
    """The catalog's entries whose product (or vendor) names one of the confirmed products: [{cve, vendor, product,
    name, added}], newest first. A hint for the model; whether our version is affected is still its question."""
    d = load(cfg) if cfg['intel'].get('kev') else None
    if not d:
        return []
    names = [n for n in (_norm(p['name']) for p in products) if len(n) >= 3]
    out = []
    for cid, e in d.get('entries', {}).items():
        prod, vend = _norm(e['product']), _norm(e['vendor'])
        if any(_same_product(n, prod, vend) for n in names):
            out.append(dict(e, cve=cid))
    out.sort(key=lambda x: x['added'], reverse=True)
    return out[:limit]


def status(cfg):
    d = load(cfg) if cfg['intel'].get('kev') else None
    return {'enabled': bool(cfg['intel'].get('kev')), 'fetched_at': (d or {}).get('fetched_at'),
            'catalog_version': (d or {}).get('catalog_version'), 'entries': len((d or {}).get('entries', {}))}
