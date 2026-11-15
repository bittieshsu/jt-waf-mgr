"""NVD (nvd.nist.gov) CVE API: the official score and weakness of the CVEs a search found.

Off by default (intel.nvd). When on, after each search the threat-intelligence unit asks
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id> for every new CVE id (only the id is sent), at most
one request every 6 seconds (NVD's limit without an API key) and at most MAX_PER_RUN a run; answers are kept 7 days
(<data dir>/intel/nvd-cache.json). The CVSS severity then replaces the model's guess (both are kept).
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
           'status': util.clip(str(c.get('vulnStatus') or ''), 40)}
    if best:
        out.update(best)
    return out


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
        if not hit or now - hit.get('at', 0) > TTL:
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
            t['nvd'] = hit['info']
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
