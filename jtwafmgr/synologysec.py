"""Synology's own security advisories (0.5.34): the RSS feed of https://www.synology.com/en-global/security/advisory.

Off by default (intel.synology). When on and the confirmed software list has a Synology product, the threat-intelligence
unit (jt-waf-mgr-intel.service; the web service never connects out) downloads the feed at most once a day over https
to a public address only (about 450 KB, every advisory since 2013 in one file), checks that it is the feed (an RSS
channel with a plausible number of Synology-SA items) and replaces the local copy atomically
(<data dir>/intel/synology.json, 0600). A failed or odd download keeps the copy there is.

Use: matching(cfg, products, days) -- the recent advisories, those naming a confirmed product first, as a hint for the
model, which reads each advisory page (synology.com is among the readable domains) for the affected and fixed versions.
The feed is data from outside: parsed with fixed patterns (no XML parser, no entities), kept as plain values, never
shown as markup.
"""
import json
import os
import re
import time
from email.utils import parsedate_to_datetime

from . import util

URL = 'https://www.synology.com/api/rssfeed/security/en-global'
MAX_BYTES = 4 * 1024 * 1024
MIN_ITEMS = 100                     # the feed has several hundred; fewer means something else was served
REFRESH = 20 * 3600
SA_RE = re.compile(r'Synology[-_]SA[-_](\d{2})[:_](\d{2,3})')
CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}')
LINK_RE = re.compile(r'^https://www\.synology\.(?:com|cn)/[A-Za-z0-9_./-]{1,200}$')
_cache = {'mtime': None, 'data': None}


class SynologyError(Exception):
    def __init__(self, code, detail=''):
        super().__init__(code)
        self.code, self.detail = code, util.clip(str(detail), 200)


def path(cfg):
    return os.path.join(os.path.dirname(os.path.abspath(cfg['paths']['db'])), 'intel', 'synology.json')


def _text(s):
    s = re.sub(r'^\s*<!\[CDATA\[(.*)\]\]>\s*$', r'\1', s, flags=re.S)
    s = re.sub(r'<[^>]{0,200}>', ' ', s)
    for a, b in (('&lt;', '<'), ('&gt;', '>'), ('&quot;', '"'), ('&#39;', "'"), ('&amp;', '&')):
        s = s.replace(a, b)
    return re.sub(r'\s+', ' ', s).strip()


def _tag(item, name):
    m = re.search(r'<%s(?:\s[^>]{0,200})?>(.*?)</%s>' % (name, name), item, re.S)
    return m.group(1) if m else ''


def parse(raw):
    """{'advisories': [{id, title, products, link, published, cves, summary}]} newest first, or SynologyError."""
    try:
        s = raw.decode('utf-8') if isinstance(raw, bytes) else str(raw)
    except UnicodeDecodeError:
        raise SynologyError('not_utf8')
    if '<rss' not in s[:2000] or '<channel>' not in s:
        raise SynologyError('not_the_feed', 'no RSS channel')
    out, seen = [], set()
    for item in re.findall(r'<item>(.*?)</item>', s, re.S)[:5000]:
        title = util.clip(_text(_tag(item, 'title')), 200)
        m = SA_RE.search(title)
        if not m:
            continue                    # the old hotfix notices of DSM 4 carry no advisory number
        sid = 'Synology-SA-%s:%s' % (m.group(1), m.group(2))
        if sid in seen:
            continue
        seen.add(sid)
        link = _text(_tag(item, 'link'))
        desc = _text(_tag(item, 'description'))
        try:
            published = int(parsedate_to_datetime(_text(_tag(item, 'pubDate'))).timestamp())
        except (TypeError, ValueError, OverflowError):
            published = 0
        rest = title[m.end():].strip(' -:')
        products = [p.strip() for p in re.split(r',|\band\b', rest) if p.strip()][:12]
        out.append({'id': sid, 'title': title, 'products': [util.clip(p, 60) for p in products],
                    'link': link if LINK_RE.match(link) else '', 'published': published,
                    'cves': sorted(set(CVE_RE.findall(desc)))[:40], 'summary': util.clip(desc, 400)})
    if len(out) < MIN_ITEMS:
        raise SynologyError('not_the_feed', 'advisories: %d' % len(out))
    out.sort(key=lambda a: (-a['published'], a['id']))
    return {'advisories': out}


def _wanted(cfg, products):
    return bool(cfg['intel'].get('synology')) and any(_is_synology(p['name']) for p in products)


def _is_synology(name):
    return str(name).lower().startswith('synology')


def update(cfg, products, get=None, now=None, log=print):
    """Download when on, a Synology product is confirmed and the copy is older than REFRESH. Returns 'off', 'fresh',
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
            raise SynologyError('too_large')
        d = parse(raw)
    except SynologyError as e:
        log('synology: download failed: %s %s' % (e.code, e.detail))
        return 'failed:' + e.code
    except Exception as e:      # noqa: BLE001 -- a cut connection, a protocol error: the copy there is stays
        log('synology: download failed: %s' % type(e).__name__)
        return 'failed:network'
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    tmp = p + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        json.dump(dict(d, fetched_at=util.iso(now)), fh)
    os.replace(tmp, p)
    log('synology: %d advisories' % len(d['advisories']))
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
    n = re.sub(r'\s*\([^)]*\)\s*$', '', re.sub(r'^synology\s+', '', str(name).strip(), flags=re.I)).lower()
    return {'dsm': 'dsm', 'drive server': 'drive', 'drive': 'drive'}.get(n, n)


def matching(cfg, products, days=180, now=None, limit=25):
    """The advisories published in the last `days` days when a Synology product is confirmed: [{..., 'about': [the
    confirmed products its title names]}], those naming one first. An advisory with a nickname for a title
    ("NGINX2Root") names no product but may well be about DSM: listed after them."""
    if not _wanted(cfg, products):
        return []
    d = load(cfg) or {}
    since = (now or time.time()) - days * 86400
    ours = {_short(p['name']): p['name'] for p in products if _is_synology(p['name'])}
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
    return {'enabled': bool(cfg['intel'].get('synology')), 'fetched_at': d.get('fetched_at'),
            'advisories': len(d.get('advisories') or [])}
