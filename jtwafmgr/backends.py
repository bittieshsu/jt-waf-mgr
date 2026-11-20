"""The servers behind the sites: what web server (and PHP) answers when nginx passes a request on.

nginx does not pass a proxied server's `Server` header on to the client (proxy_hide_header's default), so the
version of the nginx or Apache running on a back-end host cannot be read through this host's own nginx. Off by
default (intel.backend_versions). When on, the threat-intelligence unit, before each search:

- reads the `proxy_pass` targets of the sites nginx serves over TLS (an `upstream` group's servers too): literal
  addresses or names that resolve to a private address only, never one with a variable, never this program's own;
- asks each target once: `GET /` with the site's name as Host, the answer's headers only (the body is not read;
  nothing but the Host and a User-Agent is sent; a back-end certificate is not checked, as nothing secret is sent
  and back-end hosts on a local network often have their own certificates);
- reads the product and version from `Server` ("nginx/1.22.1", "Apache/2.4.57 (Debian)") and `X-Powered-By`
  ("PHP/8.2.29") and lists them in the software list as "back-end host" entries, with the sites they serve.

A version read this way is the program's own words, not a package version: a distribution's package may carry
backported fixes. Only the product and version go to the second-tier LLM (as every software entry); the addresses
stay here.
"""
import ipaddress
import json
import re
import socket
import urllib.parse

from . import traffic, util

ACTOR = 'backend-probe'
TIMEOUT = 4
MAX_TARGETS = 60
MAX_ASKS = 120
WORKERS = 8
DISMISSED_KEY = 'software.backend_dismissed'

# product names as the rest of the software list writes them (data/software-signatures.json "packages")
SERVER_HEADERS = (
    ('nginx', re.compile(r'^nginx/(\d+\.\d+\.\d+)\b', re.I)),
    ('Apache HTTP Server', re.compile(r'^Apache/(\d+\.\d+\.\d+)\b')),
    ('OpenResty', re.compile(r'^openresty/(\d+\.\d+\.\d+(?:\.\d+)?)\b', re.I)),
    ('lighttpd', re.compile(r'^lighttpd/(\d+\.\d+\.\d+)\b', re.I)),
    ('Microsoft IIS', re.compile(r'^Microsoft-IIS/(\d+\.\d+)\b')),
    ('Eclipse Jetty', re.compile(r'^Jetty\((\d+\.\d+\.\d+)', re.I)),
    ('LiteSpeed', re.compile(r'^LiteSpeed/(\d+\.\d+(?:\.\d+)?)\b', re.I)),
)
POWERED_BY = (
    # a distribution's PHP says its own version ("PHP/8.1.2-1ubuntu2.14"): kept whole, the fixes may be backported
    ('PHP', re.compile(r'^PHP/(\d+\.\d+\.\d+(?:-[\w.+~]+)?)')),
)
VERSION_OK = re.compile(r'[\w.+~:-]{1,60}')


def read_headers(headers):
    """[(product, version)] from an answer's headers ({lower-case name: value})."""
    out = []
    for header, table in (('server', SERVER_HEADERS), ('x-powered-by', POWERED_BY)):
        v = str(headers.get(header) or '').strip()
        for name, rx in table:
            m = rx.match(v)
            if m and VERSION_OK.fullmatch(m.group(1)):
                out.append((name, m.group(1)))
                break
    return out


def _resolve(host):
    """The private address a back-end name or literal stands for, or None (public, unresolvable)."""
    h = host.strip('[]')
    try:
        addrs = [ipaddress.ip_address(h)]
    except ValueError:
        try:
            addrs = [ipaddress.ip_address(x[4][0]) for x in socket.getaddrinfo(h, None, proto=socket.IPPROTO_TCP)]
        except (OSError, UnicodeError, ValueError):
            return None
    for a in addrs:
        # an IPv4 address written as IPv6 (::ffff:8.8.8.8, 6to4) is judged as that IPv4 address (Python 3.11 calls
        # ::ffff:8.8.8.8 private; ::ffff:127.0.0.1 is not "loopback" there)
        if a.version == 6 and (a.ipv4_mapped or a.sixtofour):
            a = a.ipv4_mapped or a.sixtofour
        if a.is_private and not a.is_link_local and not a.is_multicast and not a.is_unspecified:
            return str(a)
    return None


def _split(url):
    """(scheme, host, port) of a proxy_pass target "http://name:port/path", or None."""
    if '$' in url or not re.match(r'(?i)https?://', url):
        return None
    try:
        u = urllib.parse.urlsplit(url)
        port = u.port
    except ValueError:
        return None
    if not u.hostname:
        return None
    scheme = u.scheme.lower()
    return scheme, u.hostname, port or (443 if scheme == 'https' else 80)


def targets(app, resolve=_resolve):
    """[{'scheme', 'address', 'port', 'sites': [...]}] the back-end servers of the sites nginx serves on 443."""
    from .software import homepage_sites, own_hosts
    try:
        n, _ = app.site.load()
        servers = n.servers()
        groups = n.upstream_groups()
    except Exception:          # noqa: BLE001 -- no nginx configuration here
        return []
    own_port = str(app.cfg['server'].get('listen') or '').rpartition(':')[2]
    wanted = set(homepage_sites(app))
    own = own_hosts(app)
    found = {}
    for sv in servers:
        names = [h.lower() for h in sv.get('server_names') or [] if h.lower() in wanted and h.lower() not in own]
        if not names:
            continue
        for up in sv.get('upstreams') or []:
            t = _split(up)
            if not t:
                continue
            scheme, host, port = t
            members = []
            if host in groups:
                for m in groups[host]:
                    if m.startswith('unix:'):
                        continue
                    a, _, p = m.rpartition(':') if re.search(r':\d+$', m) else (m, '', '')
                    members.append((a, int(p) if p else (443 if scheme == 'https' else 80)))
            else:
                members.append((host, port))
            for a, p in members:
                addr = resolve(a)
                if not addr:
                    continue
                if ipaddress.ip_address(addr).is_loopback and str(p) == own_port:
                    continue            # this program's own web service
                key = (scheme, addr, p)
                found.setdefault(key, [])
                for h in names:
                    if h not in found[key]:
                        found[key].append(h)
    out = [{'scheme': k[0], 'address': k[1], 'port': k[2], 'sites': sorted(v)} for k, v in sorted(found.items())]
    return out[:MAX_TARGETS]


OFFLINE = False          # tests: never ask a real host


def probe(scheme, address, port, host, timeout=TIMEOUT):
    """The headers ({lower-case name: value}) of `GET /` at a back-end server, or None. Only the status line and
    headers are read."""
    if OFFLINE:
        return None
    import http.client
    import ssl
    try:
        if scheme == 'https':
            ctx = util.tls_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE     # a header is read, nothing secret is sent (see the module text)
            conn = http.client.HTTPSConnection(address, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(address, port, timeout=timeout)
    except (OSError, ValueError):
        return None
    try:
        conn.putrequest('GET', '/', skip_host=True, skip_accept_encoding=True)
        conn.putheader('Host', host)
        conn.putheader('User-Agent', 'jt-waf-mgr version check')
        conn.putheader('Accept', '*/*')
        conn.putheader('Connection', 'close')
        conn.endheaders()
        r = conn.getresponse()
        return {k.lower(): v for k, v in r.getheaders()}
    except (OSError, ValueError, http.client.HTTPException, ssl.SSLError):
        return None
    finally:
        conn.close()


def clear(app, log=print):
    """The setting switched off: the back-end hosts' entries the probe made go (a person's stay), and their alerts are
    handled -- versions no longer read must not keep deciding threats. Returns how many entries went."""
    db = app.db
    n = db.x("DELETE FROM software WHERE kind='backend' AND source='probe'").rowcount
    note = 'reading the back-end hosts\' versions was switched off'
    for a in db.q("SELECT id FROM alerts WHERE state='open' AND kind='backend_security'"):
        if db.x("UPDATE alerts SET state='handled', handled_by='intel', handled_at=?, note=? WHERE id=? AND state='open'",
                (util.now(), note, a['id'])).rowcount == 1:
            app.audit.log('alert.handled', 'intel', 'system', None, 'ok', alert_id=a['id'], kind='backend_security', note=note)
    if n:
        log('software: %d back-end entries removed (reading them is off)' % n)
    return n


def dismissed(db):
    try:
        v = json.loads(db.get_meta(DISMISSED_KEY, '[]') or '[]')
    except ValueError:
        return []
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def dismiss(db, entries):
    """A person deleted a back-end entry: its "product@site" pairs are not listed again."""
    db.set_meta(DISMISSED_KEY, json.dumps(sorted(set(dismissed(db)) | set(entries))[:2000]))


def detect(app, ask=probe, log=print, resolve=_resolve):
    """Ask the back-end servers and keep the software list's "back-end host" entries current. A site whose server
    did not answer keeps what it had; a person's entry (and a product a person listed for that site) is never
    changed. Returns {'asked', 'answered', 'added', 'updated', 'removed'}."""
    from concurrent.futures import ThreadPoolExecutor
    db = app.db
    ts = targets(app, resolve=resolve)
    stats = {'asked': 0, 'answered': 0, 'added': 0, 'updated': 0, 'removed': 0}
    if not ts:
        return stats            # no configuration read (or nothing behind it): the list stays as it was

    # each site asked with its own name (0.5.22): one address may serve several sites, each on its own PHP
    asks = [(t, site) for t in ts for site in t['sites']][:MAX_ASKS]
    stats['asked'] = len(asks)

    def one(ts_):
        t, site = ts_
        try:
            return t, site, ask(t['scheme'], t['address'], t['port'], site)
        except Exception:      # noqa: BLE001 -- one host's odd answer never stops the rest
            return t, site, None
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        answers = list(ex.map(one, asks))
    seen_sites = set()                  # sites whose back-end answered: their entries are replaced by what it said
    groups = {}                         # (product, version) -> {'sites': set, 'evidence': [...]}
    for t, site, headers in answers:
        if headers is None:
            continue
        stats['answered'] += 1
        seen_sites.add(site)
        for name, ver in read_headers(headers):
            g = groups.setdefault((name, ver), {'sites': set(), 'evidence': []})
            g['sites'].add(site)
            ev = '%s://%s:%d' % (t['scheme'], t['address'], t['port'])
            if ev not in g['evidence']:
                g['evidence'].append(ev)
    gone = set(dismissed(db))
    # what people listed: a product they keep for a site is theirs there
    theirs = {}
    for r in db.q("SELECT name, hosts FROM software WHERE source='person'"):
        theirs.setdefault(r['name'], set()).update(json.loads(r['hosts'] or '[]'))
    now = util.now()
    rows = [dict(r) for r in db.q("SELECT * FROM software WHERE kind='backend' AND source='probe' ORDER BY id")]
    # the sites that answered leave their old entries (they get what they said now); a site no longer passed to a
    # private back-end (gone from nginx, now a public address or a socket) leaves them too (0.5.22: they stayed)
    current = {s for t in ts for s in t['sites']}
    for r in rows:
        hosts = json.loads(r['hosts'] or '[]')
        keep = [h for h in hosts if h not in seen_sites and h in current]
        r['_hosts'] = keep
    for (name, ver), g in sorted(groups.items()):
        sites = sorted(h for h in g['sites'] if '%s@%s' % (name, h) not in gone and h not in theirs.get(name, set()))
        sites = [h for h in sites if traffic.HOST_RE.fullmatch(h)]
        if not sites:
            continue
        evidence = util.clip('back-end ' + ', '.join(g['evidence'][:6]), 200)
        # the entry of this product that served these sites before (its confirmation stays: the version is a fact)
        prev = next((r for r in rows if r['name'] == name and r['version'] == ver), None) or \
            next((r for r in rows if r['name'] == name and set(json.loads(r['hosts'] or '[]')) & set(sites)), None)
        if prev and not prev.get('_taken'):
            prev['_taken'] = True
            prev['_hosts'] = sorted(set(prev['_hosts']) | set(sites))
            if prev['version'] != ver:
                app.audit.log('software.version_detected', ACTOR, 'system', None, 'ok', name=name,
                              old=prev['version'] or None, new=ver, backend=True)
                log('software: back-end %s %s -> %s (%s)' % (name, prev['version'] or '-', ver, ', '.join(sites[:3])))
            prev['_version'], prev['_evidence'] = ver, evidence
            continue
        # sites another back-end entry of this product still names (they did not answer this time) stay there
        for r in rows:
            if r['name'] == name:
                r['_hosts'] = [h for h in r['_hosts'] if h not in sites]
        db.x('INSERT INTO software(name, version, hosts, kind, source, confirmed, evidence, notes, updated_at, updated_by) '
             "VALUES (?,?,?, 'backend', 'probe', 0, ?, '', ?, ?)", (name, ver, json.dumps(sites), evidence, now, ACTOR))
        stats['added'] += 1
        log('software: back-end %s %s (%s)' % (name, ver, ', '.join(sites[:3])))
    for r in rows:
        new_hosts = sorted(r['_hosts'])
        if not new_hosts:
            db.x('DELETE FROM software WHERE id=?', (r['id'],))
            stats['removed'] += 1
            continue
        ver, ev = r.get('_version', r['version']), r.get('_evidence', r['evidence'])
        if (json.dumps(new_hosts), ver, ev) != (r['hosts'], r['version'], r['evidence']):
            db.x('UPDATE software SET hosts=?, version=?, evidence=?, updated_at=?, updated_by=? WHERE id=?',
                 (json.dumps(new_hosts), ver, ev, now, ACTOR, r['id']))
            stats['updated'] += 1
    return stats
