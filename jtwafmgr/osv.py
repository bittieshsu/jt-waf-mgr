"""OSV (osv.dev) query API: the known vulnerabilities of the exact distribution package versions installed here.

Off by default (intel.osv). When on, the threat-intelligence unit asks https://api.osv.dev/v1/query once a day per
confirmed product that is a Debian / Ubuntu package (the guess recorded "dpkg: <package> <version>"): the source
package, its installed version and the distribution release are sent -- nothing about the sites. No bulk download.
Answers are kept a day (<data dir>/intel/osv-cache.json) and given to the model as a structured hint; whether a
vulnerability matters here (preconditions, the attack over HTTP) is still the model's and the checks' question.
"""
import json
import os
import re
import socket
import time
import urllib.parse

from . import __version__, util

URL = 'https://api.osv.dev/v1/query'
MAX_BYTES = 4 * 1024 * 1024
MAX_QUERIES = 60
TTL = 20 * 3600
DPKG_STATUS = '/var/lib/dpkg/status'


class OsvError(Exception):
    def __init__(self, code, detail=''):
        super().__init__(code)
        self.code, self.detail = code, util.clip(str(detail), 200)


def cache_path(cfg):
    return os.path.join(os.path.dirname(os.path.abspath(cfg['paths']['db'])), 'intel', 'osv-cache.json')


def ecosystem(os_release='/etc/os-release'):
    """'Debian:12', 'Ubuntu:24.04:LTS' ... for this host, or None (another distribution: nothing is asked)."""
    try:
        with open(os_release, encoding='utf-8') as fh:
            d = dict(line.rstrip('\n').split('=', 1) for line in fh if '=' in line)
    except OSError:
        return None
    did, ver = d.get('ID', '').strip('"'), d.get('VERSION_ID', '').strip('"')
    if did == 'debian' and re.fullmatch(r'\d+', ver):
        return 'Debian:' + ver
    if did == 'ubuntu' and re.fullmatch(r'\d+\.\d+', ver):
        return 'Ubuntu:' + ver + (':LTS' if 'LTS' in d.get('VERSION', '') else '')
    return None


def source_packages(path=DPKG_STATUS):
    """{binary package: source package} (OSV's Debian records name the source package)."""
    out = {}
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError:
        return out
    for block in text.split('\n\n'):
        f = dict(re.findall(r'^([A-Za-z-]+): (.*)$', block, re.M))
        if f.get('Package'):
            out[f['Package']] = (f.get('Source') or f['Package']).split(' ')[0]
    return out


def _post(url, body, timeout):
    from .intel import _public
    import http.client
    u = urllib.parse.urlsplit(url)
    ip = _public(u.hostname, 443)
    if not ip:
        raise OsvError('not_public', u.hostname)

    class Pinned(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection((ip, 443), timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=u.hostname)

    conn = Pinned(u.hostname, 443, timeout=timeout, context=util.tls_context())
    try:
        data = json.dumps(body).encode()
        conn.request('POST', u.path, body=data, headers={'Host': u.hostname, 'Content-Type': 'application/json',
                                                         'User-Agent': 'jt-waf-mgr/' + __version__ + ' (threat intelligence)'})
        r = conn.getresponse()
        if r.status != 200:
            raise OsvError('http_%d' % r.status)
        raw = r.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise OsvError('too_large')
        return json.loads(raw)
    except ValueError:
        raise OsvError('not_json')
    finally:
        conn.close()


def _queries(db, eco, sources):
    """(product, source package, version) for the confirmed products the guess saw as packages."""
    out = []
    for r in db.q("SELECT name, evidence FROM software WHERE confirmed=1 AND evidence LIKE 'dpkg: %' ORDER BY name"):
        parts = r['evidence'].split()
        if len(parts) >= 3:
            out.append((r['name'], sources.get(parts[1], parts[1]), parts[2]))
    return out[:MAX_QUERIES]


def _summary(v):
    aliases = [a for a in (v.get('aliases') or []) if re.match(r'^CVE-\d{4}-\d{4,7}$', str(a))]
    return {'id': util.clip(str(v.get('id') or ''), 60), 'cves': aliases[:5], 'summary': util.clip(str(v.get('summary') or ''), 200),
            'modified': util.clip(str(v.get('modified') or ''), 25)}


def lookup(cfg, db, post=None, now=None, log=print, os_release='/etc/os-release', dpkg_status=DPKG_STATUS):
    """{product: {package, version, ecosystem, vulns: [{id, cves, summary, modified}]}} for the confirmed packages,
    from the cache when it is under TTL old; {} when off or not a Debian / Ubuntu host."""
    if not cfg['intel'].get('osv'):
        return {}
    eco = ecosystem(os_release)
    if not eco:
        return {}
    now = now or time.time()
    p = cache_path(cfg)
    try:
        with open(p, encoding='utf-8') as fh:
            cache = json.load(fh)
    except (OSError, ValueError):
        cache = {}
    out, asked = {}, 0
    for name, pkg, ver in _queries(db, eco, source_packages(dpkg_status)):
        key = '%s|%s|%s' % (eco, pkg, ver)
        hit = cache.get(key)
        if not hit or now - hit.get('at', 0) > TTL:
            try:
                d = (post or _post)(URL, {'package': {'name': pkg, 'ecosystem': eco}, 'version': ver}, 30)
            except Exception as e:      # noqa: BLE001 -- one package's question failed; the others go on
                log('osv: %s %s: %s' % (pkg, ver, getattr(e, 'code', type(e).__name__)))
                continue
            if not isinstance(d, dict):
                d = {}
            asked += 1
            hit = {'at': now, 'vulns': [_summary(v) for v in (d.get('vulns') or [])[:50] if isinstance(v, dict)]}
            cache[key] = hit
        out[name] = {'package': pkg, 'version': ver, 'ecosystem': eco, 'vulns': hit['vulns']}
    if asked:
        os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
        tmp = p + '.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump({k: v for k, v in cache.items() if now - v.get('at', 0) < 7 * 86400}, fh)
        os.replace(tmp, p)
        log('osv: asked about %d package versions' % asked)
    return out
