"""IP reputation: is an outside address known to be malicious? (0.4.94)

Three kinds of sources, put together on the IP lookup page with the site's own evidence:
1. Public lists downloaded once a day (Spamhaus DROP, Tor exit nodes, FireHOL level 1, Emerging Threats compromised
   hosts, abuse.ch Feodo C2, CINS Army, blocklist.de), matched on this host: looking up an address sends it nowhere.
2. Shodan InternetDB (no key): open ports, known vulnerabilities and tags of an address.
3. The organisation's own MISP (URL and API key in Settings): attributes with that address (attributes/restSearch).

Only jt-waf-mgr-iprep.service connects out (the web service never does): it downloads the lists when they are due or
asked for, and looks up the addresses someone opened in the IP lookup (only outside addresses; results kept 24 hours).
The web service writes <dir>/wanted.json and a request file, and reads <dir>/lists/*.txt and <dir>/online.json.
Downloaded and looked-up content is untrusted: parsed strictly, sizes capped, shown as text. Nothing here blocks an
address by itself; a person decides.
"""
import bisect
import hashlib
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.request

from . import __version__, util

# id -> (name, url, format, category, weight)
#   format: 'lines' (an address or network per line, # or ; comments), 'spamhaus' (Spamhaus DROP JSON lines)
#   category: what being on it means; weight: how much it says about malice (high / medium / info)
LISTS = {
    'spamhaus_drop': ('Spamhaus DROP (IPv4)', 'https://www.spamhaus.org/drop/drop_v4.json', 'spamhaus', 'hijacked', 'high'),
    'spamhaus_drop6': ('Spamhaus DROP (IPv6)', 'https://www.spamhaus.org/drop/drop_v6.json', 'spamhaus', 'hijacked', 'high'),
    'feodo': ('abuse.ch Feodo Tracker', 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', 'lines', 'botnet_c2', 'high'),
    'firehol_level1': ('FireHOL level 1', 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
                       'lines', 'malicious', 'high'),
    'et_compromised': ('Emerging Threats compromised', 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                       'lines', 'compromised', 'medium'),
    'cins': ('CINS Army', 'https://cinsscore.com/list/ci-badguys.txt', 'lines', 'attacker', 'medium'),
    'blocklist_de': ('blocklist.de', 'https://lists.blocklist.de/lists/all.txt', 'lines', 'attacker', 'medium'),
    'tor_exit': ('Tor exit nodes', 'https://check.torproject.org/torbulkexitlist', 'lines', 'anonymizer', 'info'),
}
MAX_LIST_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 500000
MAX_ONLINE_BYTES = 2 * 1024 * 1024
LIST_HOURS = 24                       # lists are downloaded again after this many hours
ONLINE_TTL = 24 * 3600                # a looked-up address is asked again after this
MAX_ONLINE_PER_RUN = 50
MAX_ONLINE_PER_DAY = 500             # addresses sent to the online sources a day, at most
ERROR_TTL = 3600                     # a failed lookup is tried again after an hour (not a day)
RUN_SECONDS = 420                    # one run stops sending before the unit's 10-minute limit
SOURCE_FAILS = 3                     # a source failing this many times in a row is not asked again in this run
MAX_WANTED = 200
WEIGHT_ORDER = {'high': 3, 'medium': 2, 'info': 1}
WANTED, ONLINE, MANIFEST, REQUEST, LISTS_REQUEST = 'wanted.json', 'online.json', 'manifest.json', 'update.request', 'lists.request'
UA = 'jt-waf-mgr/%s (IP reputation)' % __version__
_COMMENT = re.compile(r'[#;]')


class IprepError(Exception):
    pass


def iprep_dir(cfg):
    """[iprep] dir, else "iprep" next to the database (a test's temporary database takes it along)."""
    return cfg['iprep'].get('dir') or os.path.join(os.path.dirname(cfg['paths']['db']), 'iprep')


TEST_NETS = False        # tests (tests/helpers.py): the documentation networks stand for outside addresses
_DOC = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32')]


def outside(ip):
    """A public address (never an internal, reserved or documentation one: those are never sent anywhere)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if TEST_NETS and any(a.version == n.version and a in n for n in _DOC):
        return True
    return a.is_global and not a.is_multicast


def _read(path, default):
    try:
        with open(path, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _write(path, data):
    import threading
    tmp = '%s.%d.%d.tmp' % (path, os.getpid(), threading.get_ident())
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, ensure_ascii=False)
    os.replace(tmp, path)


# --- the lists ------------------------------------------------------------------------------------------------------
def parse_list(data, fmt):
    """Downloaded bytes -> sorted unique networks (strings). Lines that are not an address or a network are skipped."""
    text = data.decode('utf-8', 'replace')
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if fmt == 'spamhaus':
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            tok = obj.get('cidr') if isinstance(obj, dict) else None
            if not isinstance(tok, str):
                continue
        else:
            line = _COMMENT.split(line, 1)[0].strip()
            if not line:
                continue
            tok = line.split()[0]
        try:
            n = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            continue
        if n.prefixlen < (8 if n.version == 4 else 16):
            continue                      # "the whole Internet" is no list entry (a broken or tampered list)
        out.add(str(n))
        if len(out) > MAX_ENTRIES:
            raise IprepError('too_many_entries')
    return sorted(out)


def _get(url, timeout=60, limit=MAX_LIST_BYTES, headers=None, data=None, ctx=None):
    req = urllib.request.Request(url, data=data, headers=dict({'User-Agent': UA}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout, context=ctx or util.tls_context()) as r:
        body = r.read(limit + 1)
        if len(body) > limit:
            raise IprepError('too_large')
        return r.status, body


def update_lists(d, enabled, now=None, force=False, log=print, get=_get):
    """Download the enabled lists that are due (or all of them when forced). A list that fails keeps its last copy."""
    now = now or time.time()
    os.makedirs(os.path.join(d, 'lists'), mode=0o750, exist_ok=True)
    man = _read(os.path.join(d, MANIFEST), {})
    done = 0
    for lid in enabled:
        if lid not in LISTS:
            continue
        name, url, fmt, _, _ = LISTS[lid]
        prev = man.get(lid) or {}
        if not force and prev.get('at') and now - prev['at'] < LIST_HOURS * 3600 and not prev.get('error'):
            continue
        try:
            _, body = get(url)
            nets = parse_list(body, fmt)
            with open(os.path.join(d, 'lists', lid + '.txt.tmp'), 'w') as fh:
                fh.write('\n'.join(nets) + '\n')
            os.replace(os.path.join(d, 'lists', lid + '.txt.tmp'), os.path.join(d, 'lists', lid + '.txt'))
            man[lid] = {'at': now, 'count': len(nets), 'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body),
                        'error': None}
            log('%s: %d entries' % (lid, len(nets)))
        except (OSError, urllib.error.URLError, IprepError, ValueError) as e:
            man[lid] = dict(prev, error=util.clip(str(getattr(e, 'reason', None) or e), 200), error_at=now)
            log('%s: failed (%s)' % (lid, man[lid]['error']))
        done += 1
    for lid in list(man):            # a list switched off: its copy goes
        if lid not in enabled:
            man.pop(lid, None)
            try:
                os.unlink(os.path.join(d, 'lists', lid + '.txt'))
            except OSError:
                pass
    _write(os.path.join(d, MANIFEST), man)
    return done


class _Ranges:
    """One list as sorted, disjoint integer ranges per address family (nested and overlapping entries merged; the
    widest entry names the range): a lookup is a binary search."""

    def __init__(self, nets):
        by = {4: [], 6: []}
        for s in nets:
            try:
                n = ipaddress.ip_network(s, strict=False)
            except ValueError:
                continue
            by[n.version].append((int(n.network_address), int(n.broadcast_address), s))
        self.r = {}
        for v, rs in by.items():
            rs.sort(key=lambda x: (x[0], -x[1]))
            merged = []
            for lo, hi, s in rs:
                if merged and lo <= merged[-1][1]:          # overlapping or nested, not merely adjacent
                    if hi > merged[-1][1]:
                        merged[-1] = (merged[-1][0], hi, merged[-1][2])
                else:
                    merged.append((lo, hi, s))
            self.r[v] = ([x[0] for x in merged], merged)

    def find(self, ip):
        a = ipaddress.ip_address(ip)
        starts, rs = self.r.get(a.version, ([], []))
        i = bisect.bisect_right(starts, int(a)) - 1
        if i >= 0 and rs[i][0] <= int(a) <= rs[i][1]:
            return rs[i][2]
        return None


# --- online lookups ---------------------------------------------------------------------------------------------------
def internetdb(ip, get=_get):
    """Shodan InternetDB: {'ports', 'tags', 'vulns', 'hostnames', 'cpes'} or {'none': True} (nothing known)."""
    try:
        _, body = get('https://internetdb.shodan.io/' + ipaddress.ip_address(ip).compressed, timeout=20, limit=MAX_ONLINE_BYTES)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'none': True}
        raise
    d = json.loads(body.decode('utf-8', 'replace'))
    if not isinstance(d, dict):
        raise IprepError('unexpected answer')

    def strs(k, n, ln=80):
        v = d.get(k)
        return [util.clip(str(x), ln) for x in v[:n] if isinstance(x, (str, int))] if isinstance(v, list) else []
    ports = d.get('ports') if isinstance(d.get('ports'), list) else []
    return {'ports': [p for p in ports[:50] if isinstance(p, int) and not isinstance(p, bool) and 0 < p < 65536],
            'tags': strs('tags', 20, 40),
            'vulns': strs('vulns', 30, 30), 'vulns_total': len(d.get('vulns') or []) if isinstance(d.get('vulns'), list) else 0,
            'hostnames': strs('hostnames', 10, 120), 'cpes': strs('cpes', 15, 120)}


THREAT_LEVELS = {'1': 'high', '2': 'medium', '3': 'low', '4': 'undefined'}
# MISP's IP attributes mostly come from feeds: to_ids is nearly always set and the threat level is the feed's default,
# so what the address says is in WHICH feed (the event's info is the feed's name). First match wins; an event that names
# no known feed (a hand-made one, or a feed not listed) counts as medium.
MISP_FEEDS = [
    (r'ipsum.*level\s*[12]\b', 'info'),
    (r'ipsum.*level\s*[3-9]\b', 'high'),
    (r'firehol[_ ]level ?1|abuse\.ch.*(ssl|ipbl|feodo|c2)|threatview.*c2|honeylab|malware infra|active exploit', 'high'),
    (r'tor exit', 'info'),
    (r'ip protocol \d+|telnet login|dns recursion|smtp greet|vnc rfb|sipquery|scanner|scanning|shadowserver', 'info'),
    (r'blocklist\.de|greensnow|sshpwauth|ci-badguys|cins|bruteforce|brute force|threatview ip', 'medium'),
]
_MISP_FEEDS = [(re.compile(rx, re.I), w) for rx, w in MISP_FEEDS]


def misp_weight(info):
    for rx, w in _MISP_FEEDS:
        if rx.search(info or ''):
            return w
    return 'medium'


def _misp_post(url, path, key, body, timeout, ca_file=None, verify=True, pin=None):
    """POST to MISP over https. pin: the SHA-256 of the server certificate (a self-signed one whose name is not the
    address): checked instead of a CA and the host name."""
    import hashlib as _h
    import http.client
    import ssl
    import urllib.parse
    u = urllib.parse.urlsplit(url.rstrip('/') + path)
    if u.scheme != 'https' or not u.hostname:
        raise IprepError('misp_url must be https')
    if not verify and not pin:
        # the API key would go to whoever answers: without a CA check a pinned certificate is required
        raise IprepError('certificate check off and no pinned SHA-256: not sending the key')
    ctx = util.tls_context(ca_file or None)
    if pin or not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
    try:
        conn.connect()
        if pin:
            der = conn.sock.getpeercert(binary_form=True)
            if _h.sha256(der).hexdigest() != pin.lower().replace(':', ''):
                raise IprepError('the MISP certificate does not match the pinned SHA-256')
        conn.request('POST', u.path, body=body, headers={'Authorization': key, 'Accept': 'application/json',
                                                         'Content-Type': 'application/json', 'User-Agent': UA})
        r = conn.getresponse()
        raw = r.read(MAX_ONLINE_BYTES + 1)
        if len(raw) > MAX_ONLINE_BYTES:
            raise IprepError('too_large')
        if r.status != 200:
            raise IprepError('HTTP %d' % r.status)
        return raw
    finally:
        conn.close()


def misp(ip, url, key, timeout=20, ca_file=None, verify=True, pin=None, post=_misp_post):
    """The organisation's MISP: attributes with this address (attributes/restSearch, no context fetched: some feed
    events hold hundreds of thousands of attributes). {'count', 'to_ids', 'events': [{'id', 'info', 'weight', ...}],
    'tags', 'first', 'last', 'weight'}."""
    body = json.dumps({'returnFormat': 'json', 'value': ipaddress.ip_address(ip).compressed,
                       'type': {'OR': ['ip-src', 'ip-dst', 'ip-src|port', 'ip-dst|port', 'domain|ip']},
                       'includeEventTags': 1, 'limit': 100, 'page': 1}).encode()
    raw = post(url, '/attributes/restSearch', key, body, timeout, ca_file=ca_file, verify=verify, pin=pin)
    d = json.loads(raw.decode('utf-8', 'replace'))
    resp = d.get('response') if isinstance(d, dict) else None
    attrs = (resp.get('Attribute') if isinstance(resp, dict) else None) or []
    if not isinstance(attrs, list):
        raise IprepError('unexpected answer')
    events, tags, ts, to_ids = {}, [], [], 0
    for a in attrs[:100]:
        if not isinstance(a, dict):
            continue
        if a.get('to_ids') in (True, 1, '1'):
            to_ids += 1
        try:
            x = int(a.get('timestamp') or 0)
            if 0 < x < 4102444800:            # before 2100: anything else is no time
                ts.append(x)
        except (TypeError, ValueError, OverflowError):
            pass
        ev = a.get('Event') if isinstance(a.get('Event'), dict) else {}
        eid = str(ev.get('id') or a.get('event_id') or '')
        if eid and eid not in events and len(events) < 20:
            info = util.clip(str(ev.get('info') or ''), 160)
            events[eid] = {'id': util.clip(eid, 20), 'info': info, 'weight': misp_weight(info),
                           'threat_level': THREAT_LEVELS.get(str(ev.get('threat_level_id') or ''), 'undefined'),
                           'date': util.clip(str(ev.get('date') or ''), 10)}
        for t in (a.get('Tag') if isinstance(a.get('Tag'), list) else []):
            n = t.get('name') if isinstance(t, dict) else None
            if isinstance(n, str) and n not in tags and len(tags) < 30:
                tags.append(util.clip(n, 80))
    ts = [x for x in ts if x > 0]
    evs = sorted(events.values(), key=lambda e: -WEIGHT_ORDER[e['weight']])
    return {'count': len(attrs), 'to_ids': to_ids, 'events': evs, 'tags': tags,
            'weight': evs[0]['weight'] if evs else None,
            'first': util.iso(min(ts)) if ts else None, 'last': util.iso(max(ts)) if ts else None}


def lookup_online(ip, conf, get=_get, misp_post=None):
    """One address through every online source that is on: {'internetdb': {...} | {'error'}, 'misp': ...}."""
    out = {}
    if conf.get('internetdb'):
        try:
            out['internetdb'] = internetdb(ip, get=get)
        except Exception as e:             # noqa: BLE001 -- an odd answer is this source's error, never the run's
            out['internetdb'] = {'error': util.clip(str(getattr(e, 'reason', None) or e) or type(e).__name__, 160)}
    if conf.get('misp_url') and conf.get('misp_api_key'):
        try:
            out['misp'] = misp(ip, conf['misp_url'], conf['misp_api_key'], ca_file=conf.get('misp_ca_file'),
                               verify=conf.get('misp_verify_tls', True), pin=conf.get('misp_cert_sha256'),
                               **({'post': misp_post} if misp_post else {}))
        except Exception as e:             # noqa: BLE001 -- as above
            out['misp'] = {'error': util.clip(str(getattr(e, 'reason', None) or e) or type(e).__name__, 160)}
    return out


def _due(r, now):
    """A cached answer to ask again: older than a day, or an hour after an error."""
    if r is None:
        return True
    failed = any(isinstance(v, dict) and v.get('error') for v in r.values())
    return now - r.get('at', 0) >= (ERROR_TTL if failed else ONLINE_TTL)


def run(app, now=None, log=print, get=_get, force_lists=False, misp_post=None, clock=time.time):
    """One run of jt-waf-mgr-iprep.service: the lists when due (or asked for), then the wanted addresses. The request
    files go first (an address asked for meanwhile starts the next run); every answer is saved as it comes; a run stops
    sending after RUN_SECONDS, a source failing SOURCE_FAILS times in a row is left alone for the rest of the run, and
    at most MAX_ONLINE_PER_DAY addresses a day are sent."""
    now = now or time.time()
    c = app.cfg['iprep']
    d = iprep_dir(app.cfg)
    os.makedirs(d, mode=0o750, exist_ok=True)
    asked = os.path.exists(os.path.join(d, LISTS_REQUEST))
    for f in (REQUEST, LISTS_REQUEST):
        try:
            os.unlink(os.path.join(d, f))
        except OSError:
            pass
    st = {'ran_at': util.iso(now)}
    if not c['enabled']:
        _write(os.path.join(d, 'status.json'), dict(st, ok=True, off=True))
        return st
    st['lists'] = update_lists(d, list(c['lists']), now, force=force_lists or asked, log=log, get=get)
    internal = app.cfg.internal_networks
    wanted = []
    for ip in _read(os.path.join(d, WANTED), []):
        try:
            ip = ipaddress.ip_address(ip).compressed if isinstance(ip, str) else None
        except ValueError:
            ip = None
        if ip and outside(ip) and not util.ip_in(ip, internal) and ip not in wanted:
            wanted.append(ip)
    wanted = wanted[:MAX_WANTED]
    cache = _read(os.path.join(d, ONLINE), {})
    conf = {'internetdb': c['internetdb'], 'misp_url': c['misp_url'], 'misp_api_key': c['misp_api_key'],
            'misp_ca_file': c.get('misp_ca_file'), 'misp_verify_tls': c['misp_verify_tls'],
            'misp_cert_sha256': c.get('misp_cert_sha256') or ''}
    prev = _read(os.path.join(d, 'status.json'), {})
    day = time.strftime('%Y-%m-%d', time.localtime(now))
    sent_today = prev.get('sent', 0) if prev.get('day') == day else 0
    todo = [ip for ip in wanted if _due(cache.get(ip), now)][:MAX_ONLINE_PER_RUN] \
        if conf['internetdb'] or (conf['misp_url'] and conf['misp_api_key']) else []
    start, fails, done = clock(), {'internetdb': 0, 'misp': 0}, []
    for ip in todo:
        if sent_today >= MAX_ONLINE_PER_DAY or clock() - start > RUN_SECONDS:
            st['stopped'] = 'daily_limit' if sent_today >= MAX_ONLINE_PER_DAY else 'time'
            break
        one = dict(conf, internetdb=conf['internetdb'] and fails['internetdb'] < SOURCE_FAILS)
        if fails['misp'] >= SOURCE_FAILS:
            one['misp_url'] = ''
        r = lookup_online(ip, one, get=get, misp_post=misp_post)
        for k in fails:
            if k in r:
                fails[k] = fails[k] + 1 if r[k].get('error') else 0
        cache[ip] = dict(r, at=now)
        sent_today += 1
        done.append(ip)
        if len(cache) > 20000:
            cache = dict(sorted(cache.items(), key=lambda kv: -kv[1].get('at', 0))[:20000])
        _write(os.path.join(d, ONLINE), cache)       # every answer as it comes (a run cut short keeps them)
    if done:
        # asked: off the list (an address someone opens again is put back by the web service)
        left = [ip for ip in _read(os.path.join(d, WANTED), []) if ip not in done]
        _write(os.path.join(d, WANTED), left)
    st.update(online=len(done), day=day, sent=sent_today, ok=True)
    log('online: %d looked up' % len(done))
    _write(os.path.join(d, 'status.json'), st)
    return st


# --- the web service's side -------------------------------------------------------------------------------------------
class Iprep:
    """Matches an address against the downloaded lists, asks the job for the online sources, and puts it all together."""

    def __init__(self, app):
        global TEST_NETS
        self.app = app
        self.cfg = app.cfg
        if self.cfg['iprep'].get('documentation_nets_outside'):
            TEST_NETS = True
        self._lists = {}                 # list id -> (mtime, _Ranges)
        self._online = (None, {})
        self._asked_at = 0

    @property
    def dir(self):
        return iprep_dir(self.cfg)

    def _ranges(self, lid):
        p = os.path.join(self.dir, 'lists', lid + '.txt')
        try:
            m = os.path.getmtime(p)
        except OSError:
            return None
        c = self._lists.get(lid)
        if c and c[0] == m:
            return c[1]
        try:
            with open(p) as fh:
                r = _Ranges([x.strip() for x in fh if x.strip()])
        except OSError:
            return None
        self._lists[lid] = (m, r)
        return r

    def manifest(self):
        return _read(os.path.join(self.dir, MANIFEST), {})

    def list_hits(self, ip):
        out = []
        man = self.manifest()
        for lid in self.cfg['iprep']['lists']:
            if lid not in LISTS:
                continue
            r = self._ranges(lid)
            hit = r.find(ip) if r else None
            if hit:
                name, _, _, cat, weight = LISTS[lid]
                out.append({'list': lid, 'name': name, 'category': cat, 'weight': weight, 'entry': hit,
                            'updated': util.iso(man.get(lid, {}).get('at')) if man.get(lid, {}).get('at') else None})
        return sorted(out, key=lambda x: -WEIGHT_ORDER[x['weight']])

    def online(self, ip):
        p = os.path.join(self.dir, ONLINE)
        try:
            m = os.path.getmtime(p)
        except OSError:
            m = None
        if self._online[0] != m:
            self._online = (m, _read(p, {}) if m else {})
        return self._online[1].get(ip)

    def want(self, ip):
        """An address someone looked at: asked at the next run of the job (started at most twice a minute)."""
        ip = ipaddress.ip_address(ip).compressed
        p = os.path.join(self.dir, WANTED)
        if not os.path.isdir(os.path.dirname(self.dir.rstrip('/'))):
            return
        os.makedirs(self.dir, mode=0o750, exist_ok=True)
        cur = _read(p, [])
        if ip not in cur:
            _write(p, ([ip] + [x for x in cur if x != ip])[:MAX_WANTED])
        if time.time() - self._asked_at > 30:
            self._asked_at = time.time()
            with open(os.path.join(self.dir, REQUEST), 'w') as fh:
                fh.write(util.iso(time.time()))

    def request_lists(self):
        os.makedirs(self.dir, mode=0o750, exist_ok=True)
        for f in (LISTS_REQUEST, REQUEST):
            with open(os.path.join(self.dir, f), 'w') as fh:
                fh.write(util.iso(time.time()))

    def online_on(self):
        c = self.cfg['iprep']
        return bool(c['internetdb'] or (c['misp_url'] and c['misp_api_key']))

    def reputation(self, ip, own, ask=True):
        """Everything known about an outside address, and a verdict with its reasons. own: the site's own evidence
        ({'events', 'blocked', 'confident', 'recon_block', 'blocked_now'}). ask: queue the online sources (a person
        looking; an API token reads what is there and never makes the job send addresses out)."""
        ip = ipaddress.ip_address(ip).compressed
        c = self.cfg['iprep']
        out = {'enabled': bool(c['enabled']), 'outside': outside(ip), 'lists': [], 'online': None, 'pending': False}
        if c['enabled'] and out['outside']:
            out['lists'] = self.list_hits(ip)
            if self.online_on():
                r = self.online(ip)
                if ask and _due(r, time.time()):
                    try:
                        self.want(ip)
                    except OSError:
                        pass
                    out['pending'] = r is None
                if r is not None:
                    out['online'] = {k: v for k, v in r.items() if k != 'at'}
                    out['online_at'] = util.iso(r.get('at'))
        out.update(verdict(own, out['lists'], (out['online'] or {})))
        return out

    def status(self):
        st = _read(os.path.join(self.dir, 'status.json'), {})
        man = self.manifest()
        c = self.cfg['iprep']
        return {'enabled': bool(c['enabled']), 'ran_at': st.get('ran_at'),
                'requested': os.path.exists(os.path.join(self.dir, LISTS_REQUEST)),
                'internetdb': bool(c['internetdb']), 'misp': bool(c['misp_url'] and c['misp_api_key']),
                'lists': [{'id': lid, 'name': LISTS[lid][0], 'url': LISTS[lid][1], 'category': LISTS[lid][3],
                           'weight': LISTS[lid][4], 'on': lid in c['lists'],
                           'count': man.get(lid, {}).get('count'), 'updated': util.iso(man[lid]['at']) if man.get(lid, {}).get('at') else None,
                           'error': man.get(lid, {}).get('error')} for lid in LISTS]}


BAD_TAGS = {'malware', 'c2', 'compromised', 'botnet'}
NOTE_TAGS = {'scanner', 'tor', 'vpn', 'proxy', 'honeypot', 'self-signed', 'starttls', 'cloud', 'cdn', 'database', 'eol-os',
             'eol-product'}


def verdict(own, lists, online):
    """'malicious' | 'suspicious' | 'no_record' (never "safe": no source can vouch for an address) and the reasons, each
    {'source', 'what', 'level'}: the site's own evidence first."""
    reasons = []
    own = own or {}
    if own.get('confident'):
        reasons.append({'source': 'site', 'what': 'confident', 'n': own['confident'], 'level': 'high'})
    if own.get('recon_block'):
        reasons.append({'source': 'site', 'what': 'recon', 'level': 'high'})
    if own.get('blocked'):
        reasons.append({'source': 'site', 'what': 'blocked', 'n': own['blocked'], 'level': 'medium'})
    for h in lists:
        reasons.append({'source': 'list', 'what': h['list'], 'name': h['name'], 'category': h['category'],
                        'entry': h['entry'], 'level': h['weight']})
    idb = online.get('internetdb') or {}
    for t in idb.get('tags') or []:
        if t in BAD_TAGS:
            reasons.append({'source': 'internetdb', 'what': 'tag', 'tag': t, 'level': 'high'})
        elif t in NOTE_TAGS:
            reasons.append({'source': 'internetdb', 'what': 'tag', 'tag': t, 'level': 'info'})
    m = online.get('misp') or {}
    if m.get('count'):
        for e in (m.get('events') or [])[:5]:
            reasons.append({'source': 'misp', 'what': 'event', 'id': e['id'], 'name': e['info'], 'level': e['weight']})
    # sources that overlap count once: the site's own evidence is one source; lists of one kind are one (CINS and
    # blocklist.de both list scanners), and MISP's medium feeds are those same scanner and brute-force lists
    def group(r):
        if r['source'] == 'site':
            return 'site'
        if r['source'] == 'list':
            return 'attacker' if r.get('category') == 'attacker' else 'list:' + r['what']
        if r['source'] == 'misp' and r['level'] == 'medium':
            return 'attacker'
        return r['source']
    highs = len({group(r) for r in reasons if r['level'] == 'high'})
    mediums = len({group(r) for r in reasons if r['level'] == 'medium'} - {group(r) for r in reasons if r['level'] == 'high'})
    v = 'malicious' if highs or mediums >= 2 else 'suspicious' if mediums else 'no_record'
    return {'verdict': v, 'reasons': reasons}
