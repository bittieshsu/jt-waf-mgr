"""QNAP's own security advisories (0.5.41): the RSS feed of https://www.qnap.com/en/security-advisory.

Off by default (intel.qnap). When on and the confirmed software list has a QNAP product, the threat-intelligence unit
(jt-waf-mgr-intel.service; the web service never connects out) downloads the feed at most once a day over https to a
public address only (about 16 KB: the 20 newest advisories, no severity or version fields), checks that it is the feed
(an RSS channel with QSA- advisory links) and replaces the local copy atomically (<data dir>/intel/qnap.json, 0600).
A failed or odd download keeps the copy there is; advisories seen before stay in the copy (newest 300), since the
feed itself only carries the last 20.

Use: matching(cfg, products, days) -- the recent advisories, those naming a confirmed product first, as a hint for the
model, which reads each advisory page (qnap.com is among the readable domains) for the affected and fixed versions.
The feed is data from outside: parsed with fixed patterns (no XML parser, no entities), kept as plain values, never
shown as markup.
"""
import json
import os
import re
import time
from email.utils import parsedate_to_datetime

from . import util

URL = 'https://www.qnap.com/en/security-advisory/feed'
MAX_BYTES = 1024 * 1024
MIN_ITEMS = 5                       # the feed carries 20; fewer means something else was served
KEEP = 300
REFRESH = 20 * 3600
ID_RE = re.compile(r'\b(QSA-\d{2}-\d{2,3}|NAS-\d{6}-\d{2})\b', re.I)
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}')
LINK_RE = re.compile(r'^https://www\.qnap\.com/[A-Za-z0-9_./-]{1,200}$')
_cache = {'mtime': None, 'data': None}


class QnapError(Exception):
    def __init__(self, code, detail=''):
        super().__init__(code)
        self.code, self.detail = code, util.clip(str(detail), 200)


def path(cfg):
    return os.path.join(os.path.dirname(os.path.abspath(cfg['paths']['db'])), 'intel', 'qnap.json')


def _text(s):
    s = re.sub(r'^\s*<!\[CDATA\[(.*)\]\]>\s*$', r'\1', s, flags=re.S)
    s = re.sub(r'<[^>]{0,300}>', ' ', s)
    for a, b in (('&lt;', '<'), ('&gt;', '>'), ('&quot;', '"'), ('&#39;', "'"), ('&amp;', '&')):
        s = s.replace(a, b)
    return re.sub(r'\s+', ' ', s).strip()


def _tag(item, name):
    m = re.search(r'<%s(?:\s[^>]{0,200})?>(.*?)</%s>' % (name, name), item, re.S)
    return m.group(1) if m else ''


def _products(title):
    """The products a title names: "Multiple Vulnerabilities in QTS, QuTS hero, and QuTS cloud" -> [QTS, QuTS hero,
    QuTS cloud]; "Vulnerabilities in PHP (PHP2Shell) Affecting QNE" -> [QNE]; none for "QNAP Products Not Affected"."""
    m = re.search(r'\b(?:affecting|in)\s+(.+)$', title, re.I)
    if not m or re.search(r'\bnot affected\b', title, re.I):
        return []
    rest = re.sub(r'^.*\baffecting\s+', '', m.group(1), flags=re.I)
    rest = re.sub(r'\s*\([^)]*\)', '', rest)
    out = [p.strip() for p in re.split(r',|\band\b', rest) if p.strip()]
    # "legacy QTS with NFS service enabled" -> QTS
    out = [re.sub(r'\s+with\s.*$', '', re.sub(r'^legacy\s+', '', p, flags=re.I), flags=re.I) for p in out]
    return [util.clip(p, 60) for p in out if not re.match(r'^(?:multiple\s+)?qnap\s+products?$', p, re.I)][:12]


def parse(raw):
    """{'advisories': [{id, title, products, link, published, cves, summary}]} newest first, or QnapError."""
    try:
        s = raw.decode('utf-8') if isinstance(raw, bytes) else str(raw)
    except UnicodeDecodeError:
        raise QnapError('not_utf8')
    if '<rss' not in s[:2000] or '<channel>' not in s:
        raise QnapError('not_the_feed', 'no RSS channel')
    out, seen = [], set()
    for item in re.findall(r'<item>(.*?)</item>', s, re.S)[:500]:
        title = util.clip(_text(_tag(item, 'title')), 200)
        link = _text(_tag(item, 'link'))
        desc = _text(_tag(item, 'description'))
        m = ID_RE.search(link) or ID_RE.search(desc)
        if not m:
            continue                    # a press release without an advisory number
        sid = m.group(1).upper()
        if sid in seen:
            continue
        seen.add(sid)
        try:
            published = int(parsedate_to_datetime(_text(_tag(item, 'pubDate'))).timestamp())
        except (TypeError, ValueError, OverflowError):
            published = 0
        out.append({'id': sid, 'title': title, 'products': _products(title),
                    'link': link if LINK_RE.match(link) else '', 'published': published,
                    'cves': sorted(set(CVE_RE.findall(desc + ' ' + title)))[:40],
                    'summary': util.clip(re.sub(r'\s*\.\.\.\s*More$', '', desc), 400)})
    if len(out) < MIN_ITEMS:
        raise QnapError('not_the_feed', 'advisories: %d' % len(out))
    out.sort(key=lambda a: (-a['published'], a['id']))
    return {'advisories': out}


def _wanted(cfg, products):
    return bool(cfg['intel'].get('qnap')) and any(_is_qnap(p['name']) for p in products)


def _is_qnap(name):
    return str(name).lower().startswith('qnap')


def update(cfg, products, get=None, now=None, log=print):
    """Download when on, a QNAP product is confirmed and the copy is older than REFRESH. Returns 'off', 'fresh',
    'updated' or 'failed:<code>'."""
    if not _wanted(cfg, products):
        return 'off'
    p = path(cfg)
    now = now or time.time()
    try:
        if now - os.path.getmtime(p) < REFRESH:
            return 'fresh'
    except OSError:
        pass
    try:
        if get is None:
            from .kev import _download
            raw = _download(URL, 60)
        else:
            raw = get(URL, 60)
        if len(raw) > MAX_BYTES:
            raise QnapError('too_large')
        d = parse(raw)
    except QnapError as e:
        log('qnap: download failed: %s %s' % (e.code, e.detail))
        return 'failed:' + e.code
    except Exception as e:      # noqa: BLE001 -- a cut connection, a protocol error: the copy there is stays
        log('qnap: download failed: %s' % type(e).__name__)
        return 'failed:network'
    # the feed only has the newest 20: keep the ones seen before (the copy is our own file)
    new = {a['id'] for a in d['advisories']}
    old = [a for a in (load(cfg) or {}).get('advisories') or [] if isinstance(a, dict) and a.get('id') not in new]
    allv = sorted(d['advisories'] + old, key=lambda a: (-int(a.get('published') or 0), str(a.get('id'))))[:KEEP]
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    tmp = p + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump({'advisories': allv, 'fetched_at': util.iso(now)}, fh)
    os.replace(tmp, p)
    log('qnap: %d advisories (%d in the feed)' % (len(allv), len(d['advisories'])))
    return 'updated'


def load(cfg):
    """The local copy ({advisories, fetched_at}) or None; read again only when the file changes."""
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


def _short(name):
    """"QNAP File Station" / "File Station 5" -> "file station"; "QuTS cloud" -> "quts cloud"."""
    n = re.sub(r'\s*\([^)]*\)\s*$', '', re.sub(r'^qnap\s+', '', str(name).strip(), flags=re.I)).lower()
    return re.sub(r'\s+\d+(?:\.\d+)*$', '', n)


def matching(cfg, products, days=180, now=None, limit=25):
    """The advisories published in the last `days` days when a QNAP product is confirmed: [{..., 'about': [the
    confirmed products its title names]}], those naming one first; the others follow (an advisory about PHP or the
    Linux kernel names no product but may well be about QTS)."""
    if not _wanted(cfg, products):
        return []
    d = load(cfg) or {}
    since = (now or time.time()) - days * 86400
    ours = {_short(p['name']): p['name'] for p in products if _is_qnap(p['name'])}
    out = []
    for a in d.get('advisories') or []:
        if a.get('published', 0) < since:
            continue
        about = sorted({ours[_short(x)] for x in a.get('products') or [] if _short(x) in ours})
        out.append(dict(a, about=about))
    out.sort(key=lambda a: (not a['about'], -a.get('published', 0)))
    return out[:limit]


def status(cfg):
    d = load(cfg) or {}
    return {'enabled': bool(cfg['intel'].get('qnap')), 'fetched_at': d.get('fetched_at'),
            'advisories': len(d.get('advisories') or [])}
