"""NVD (nvd.nist.gov) CVE API: the official score and weakness of the CVEs a search found.

Off by default (intel.nvd). When on, after each search the threat-intelligence unit asks
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id> for every new CVE id (only the id is sent), at most
one request every 6 seconds (NVD's limit without an API key) and at most MAX_PER_RUN a run; answers are kept 7 days
(<data dir>/intel/nvd-cache.json). The CVSS severity then replaces the model's guess (both are kept).

0.4.96: the affected versions too (the CPE ranges of NVD's configurations). When NVD names the product and our known
version lies outside every range it lists, the threat does not affect us -- whatever the model guessed; a version match
alone never makes a threat urgent (preconditions may still apply), it only says so.
"""
import json
import os
import re
import socket
import time
import urllib.parse

from . import __version__, util

URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
MAX_BYTES = 2 * 1024 * 1024
MAX_PER_RUN = 20
SPACING = 6.5
TTL = 7 * 86400
CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,7}$')
MAX_CPES = 400
CACHE_FORMAT = 2               # 2: with the CPE ranges (an older entry is asked again once)
# words of a product name that say nothing about which product it is
GENERIC = {'server', 'suite', 'web', 'collaboration', 'community', 'edition', 'enterprise', 'open', 'source', 'http',
           'project', 'platform', 'application', 'manager', 'management', 'framework', 'system', 'the'}
_VER = re.compile(r'^\d+(?:\.\d+)*')


class NvdError(Exception):
    def __init__(self, code, detail=''):
        super().__init__(code)
        self.code, self.detail = code, util.clip(str(detail), 200)


def cache_path(cfg):
    return os.path.join(os.path.dirname(os.path.abspath(cfg['paths']['db'])), 'intel', 'nvd-cache.json')


def _get(url, timeout):
    from .intel import _public
    import http.client
    u = urllib.parse.urlsplit(url)
    ip = _public(u.hostname, 443)
    if not ip:
        raise NvdError('not_public', u.hostname)

    class Pinned(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection((ip, 443), timeout)
            self.sock = self._context.wrap_socket(sock, server_hostname=u.hostname)

    conn = Pinned(u.hostname, 443, timeout=timeout, context=util.tls_context())
    try:
        conn.request('GET', u.path + '?' + u.query, headers={'Host': u.hostname, 'Accept': 'application/json',
                                                             'User-Agent': 'jt-waf-mgr/' + __version__ + ' (threat intelligence)'})
        r = conn.getresponse()
        if r.status != 200:
            raise NvdError('http_%d' % r.status)
        raw = r.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise NvdError('too_large')
        return json.loads(raw)
    except ValueError:
        raise NvdError('not_json')
    finally:
        conn.close()


def summary(d):
    """{score, severity, vector, cwe, published} of one CVE from the API's answer, or None."""
    vulns = d.get('vulnerabilities') if isinstance(d, dict) else None
    if not vulns or not isinstance(vulns, list) or not isinstance(vulns[0], dict) or not isinstance(vulns[0].get('cve'), dict):
        return None
    c = vulns[0]['cve']
    m = c.get('metrics') or {}
    best = None
    for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30'):
        for x in (m.get(key) or []) if isinstance(m, dict) else []:
            data = (x.get('cvssData') if isinstance(x, dict) else None) or {}
            if not isinstance(data, dict) or not isinstance(data.get('baseScore'), (int, float)):
                continue
            best = best or {'score': float(data['baseScore']), 'severity': str(data.get('baseSeverity') or '').lower(),
                            'vector': util.clip(str(data.get('vectorString') or ''), 120), 'version': key[10:]}
    cwes = sorted({str(dd.get('value')) for w in (c.get('weaknesses') or []) if isinstance(w, dict)
                   for dd in (w.get('description') or []) if isinstance(dd, dict) and re.match(r'^CWE-\d+$', str(dd.get('value')))})
    out = {'cwe': cwes[:4], 'published': util.clip(str(c.get('published') or ''), 25),
           'status': util.clip(str(c.get('vulnStatus') or ''), 40), 'cpes': cpes(c)}
    if best:
        out.update(best)
    return out


def cpes(c):
    """The vulnerable CPE matches of a CVE: [{'vendor', 'product', 'version', 'update', 'si', 'se', 'ei', 'ee'}] (the
    version range bounds: start including / excluding, end including / excluding; '' when absent)."""
    out = []

    def walk(nodes, depth=0):
        for n in nodes if isinstance(nodes, list) else []:
            if not isinstance(n, dict) or depth > 4:
                continue
            for m in n.get('cpeMatch') or []:
                if not isinstance(m, dict) or not m.get('vulnerable') or len(out) >= MAX_CPES:
                    continue
                parts = str(m.get('criteria') or '').split(':')
                if len(parts) < 7 or parts[2] not in ('a', 'o', 'h'):
                    continue
                out.append({'vendor': util.clip(parts[3], 60), 'product': util.clip(parts[4], 80),
                            'version': util.clip(parts[5], 40), 'update': util.clip(parts[6], 40),
                            'si': util.clip(str(m.get('versionStartIncluding') or ''), 40),
                            'se': util.clip(str(m.get('versionStartExcluding') or ''), 40),
                            'ei': util.clip(str(m.get('versionEndIncluding') or ''), 40),
                            'ee': util.clip(str(m.get('versionEndExcluding') or ''), 40)})
            walk(n.get('children'), depth + 1)
    for conf in c.get('configurations') or []:
        if isinstance(conf, dict):
            walk(conf.get('nodes'))
    return out


def _v(s):
    """'10.1.20' -> (10, 1, 20); a version that is not plain numbers (a build tag, a letter) -> None."""
    s = str(s or '').strip().lower().lstrip('v')
    m = _VER.match(s)
    if not m or m.end() != len(s):
        return None
    return tuple(int(x) for x in m.group(0).split('.'))


def _cmp(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def _words(name):
    return {w for w in re.findall(r'[a-z0-9]+', (name or '').lower()) if len(w) >= 4 and w not in GENERIC}


def version_check(product, version, entries):
    """Whether our version of a product is among NVD's affected ones: {'result': 'yes' | 'no', 'ranges': [...]} or None
    (NVD names no such product, our version is not plain numbers, or an entry cannot be compared -- unknown)."""
    ours = _v(version)
    words = _words(product)
    if ours is None or not words or not entries:
        return None
    mine = [e for e in entries if words & (_words(e['product'].replace('_', ' ')) | _words(e['vendor'].replace('_', ' ')))]
    if not mine:
        return None
    ranges, hit, unsure = [], False, False
    for e in mine:
        bounds = [(k, e[k]) for k in ('si', 'se', 'ei', 'ee') if e.get(k)]
        if bounds:
            ok = True
            for k, b in bounds:
                bv = _v(b)
                if bv is None:
                    unsure = True
                    ok = False
                    break
                c = _cmp(ours, bv)
                ok = ok and {'si': c >= 0, 'se': c > 0, 'ei': c <= 0, 'ee': c < 0}[k]
            lo = e.get('si') or (('>' + e['se']) if e.get('se') else '')
            hi = ('<=' + e['ei']) if e.get('ei') else ('<' + e['ee']) if e.get('ee') else ''
            ranges.append(('%s – %s' % (lo or '…', hi or '…')).strip())
            hit = hit or ok
            continue
        if e['version'] in ('*', '-', ''):
            unsure = True                  # "every version" or "no version": nothing to compare
            continue
        ev = _v(e['version'])
        if ev is None:
            unsure = True
            continue
        same = _cmp(ours, ev) == 0
        if same and e['update'] in ('*', '-', ''):
            hit = True
        elif same:
            unsure = True                  # the same release, a patch level we do not know
        if len(ranges) < 40:
            ranges.append(e['version'] + ('' if e['update'] in ('*', '-', '') else ' ' + e['update']))
    ranges = list(dict.fromkeys(ranges))[:12]
    if hit:
        return {'result': 'yes', 'ranges': ranges}
    if unsure:
        return None
    return {'result': 'no', 'ranges': ranges}


def enrich(cfg, threats, get=None, now=None, sleep=time.sleep, log=print):
    """Add t['nvd'] to each threat with a CVE id (cache first); the NVD severity becomes t['severity'] (the model's is
    kept as t['severity_model']). Returns how many were asked."""
    if not cfg['intel'].get('nvd') or not threats:
        return 0
    now = now or time.time()
    p = cache_path(cfg)
    try:
        with open(p, encoding='utf-8') as fh:
            cache = json.load(fh)
    except (OSError, ValueError):
        cache = {}
    asked = 0
    for t in threats:
        cid = t.get('id') or ''
        if not CVE_RE.match(cid):
            continue
        hit = cache.get(cid)
        if not hit or now - hit.get('at', 0) > TTL or (hit.get('info') and 'cpes' not in hit['info']):
            if asked >= MAX_PER_RUN:
                continue
            if asked:
                sleep(SPACING)
            try:
                info = summary((get or _get)(URL + '?' + urllib.parse.urlencode({'cveId': cid}), 30))
            except Exception as e:      # noqa: BLE001 -- one CVE's question failed; the others go on
                log('nvd: %s: %s' % (cid, getattr(e, 'code', type(e).__name__)))
                asked += 1
                continue
            asked += 1
            hit = {'at': now, 'info': info}
            cache[cid] = hit
        if hit.get('info'):
            t['nvd'] = {k: v for k, v in hit['info'].items() if k != 'cpes'}
            apply_versions(t, hit['info'].get('cpes') or [])
            sev = hit['info'].get('severity')
            if sev in ('critical', 'high', 'medium', 'low'):
                t['severity_model'], t['severity'] = t.get('severity'), sev
    if asked:
        os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
        tmp = p + '.tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            json.dump({k: v for k, v in cache.items() if now - v.get('at', 0) < TTL * 2}, fh)
        os.replace(tmp, p)
        log('nvd: asked about %d CVEs' % asked)
    return asked


def apply_versions(t, entries):
    """NVD's affected versions against our version of the threat's product: outside them -> the threat does not affect
    us (t['affected'] = 'no'; the model's answer kept as t['affected_model']); the comparison is kept in
    t['version_check']. Inside them changes nothing (a version match alone over-reports: preconditions)."""
    from .intel import known_version
    vc = version_check(t.get('product'), known_version(t.get('our_version')), entries)
    if not vc:
        return None
    t['version_check'] = vc
    if vc['result'] == 'no' and t.get('affected') != 'no':
        t['affected_model'], t['affected'] = t.get('affected'), 'no'
    return vc
