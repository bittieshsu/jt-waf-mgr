"""The software this host and its sites run: what the threat intelligence (intel.py) looks for vulnerabilities in.

The program guesses, a person confirms (only confirmed entries are ever sent to the second-tier LLM):
- this host's own packages, with exact versions, from the Debian / Ubuntu package database (nginx, the ModSecurity
  module and library, OpenSSL, other web servers, PHP / Node.js / Java, web applications installed as packages:
  web-facing software only) and the CRS version the ModSecurity configuration loads;
- the applications behind the sites, from the paths they answer with 2xx in the access logs (the last few MB of
  each log): /realms/ answered by sso.example.com is Keycloak, /remote.php/dav is Nextcloud, ... -- names only:
  a version cannot be seen from outside, a person fills it in.
The packages and path signatures are data: data/software-signatures.json (each signature carries sample paths that
tests/test_software_signatures.py checks are guessed as it, and that no common path is).

Sent to the LLM: product names and versions (and the host facts of intel.host_facts) -- never site names, addresses
or request data.
"""
import collections
import json
import os
import re

from . import traffic, util

DPKG_STATUS = '/var/lib/dpkg/status'
SIGNATURE_FILE = os.path.join(os.path.dirname(__file__), 'data', 'software-signatures.json')


def _load(path=SIGNATURE_FILE):
    """The guess data: Debian package -> product, package patterns, and application -> paths only it answers."""
    try:
        with open(path, encoding='utf-8') as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return {}, [], [], [], []
    return (dict(d.get('packages') or {}), [(re.compile(rx), name) for rx, name in d.get('package_patterns') or []],
            [(name, rx) for name, rx, _samples in d.get('signatures') or []],
            [(name, re.compile(rx)) for name, rx, _samples in d.get('homepages') or []],
            [(str(pre), str(name)) for pre, name in d.get('synology_apis') or []])


def _load4(path=SIGNATURE_FILE):
    try:
        return _load(path)
    except (TypeError, ValueError):
        return {}, [], [], [], []


PACKAGES, PACKAGE_PATTERNS, SIGNATURES, HOMEPAGES, SYNOLOGY_APIS = _load4()
SYNOLOGY = 'Synology DSM'
_API_RE = re.compile(r'[?&]api=(SYNO\.[A-Za-z0-9_.]{1,80})')


def synology_package(api):
    """The DSM package an API name belongs to (SYNO.Foto.Browse.Item -> Synology Photos), or None (DSM's own)."""
    for pre, name in SYNOLOGY_APIS:
        if api == pre or api.startswith(pre + '.'):
            return name
    return None


SYNOLOGY_INFO = '/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=all'


def synology_packages(host, fetch, port=443):
    """{package: [API names]} that a DSM site's SYNO.API.Info answer lists (DSM answers this without a login: the
    API names it serves, so the packages installed on it). {} when it does not answer so."""
    got = fetch(host, {'path': SYNOLOGY_INFO, 'max_bytes': 1000000, 'port': port}, timeout=8)
    if not got or got[0] != 200:
        return {}
    try:
        data = json.loads(got[2].decode('utf-8', 'replace')).get('data')
    except (ValueError, AttributeError):
        return {}
    out = collections.defaultdict(list)
    for api in data if isinstance(data, dict) else ():
        name = synology_package(str(api)) if isinstance(api, str) and api.startswith('SYNO.') else None
        if name:
            out[name].append(api)
    return dict(out)
VERSION_FILE = os.path.join(os.path.dirname(__file__), 'data', 'software-versions.json')


def version_sources(path=VERSION_FILE):
    """{'auto': [...], 'manual': [...]}: where an application's version can be read (data/software-versions.json)."""
    try:
        with open(path, encoding='utf-8') as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return {'auto': [], 'manual': []}
    return {'auto': list(d.get('auto') or []), 'manual': list(d.get('manual') or [])}
# The products of this host the threat intelligence follows: web-facing ones only (the web servers, the WAF and the
# libraries it parses requests with, TLS, the CRS, web applications installed as packages). Anything else on the host
# (an SSH server, the system's Python, the kernel) is not reached through the sites, so a WAF cannot shield it: it is
# never guessed, and an entry an older version guessed is dropped. The applications behind the sites are web by
# definition; an entry a person added stays theirs.
WEB_PRODUCTS = frozenset(PACKAGES.values()) | {name for _rx, name in PACKAGE_PATTERNS} | {'nginx', 'OWASP CRS'}


def web_related(name, kind, source):
    return kind != 'host' or source == 'person' or name in WEB_PRODUCTS
_SIGS = [(name, re.compile(rx)) for name, rx in SIGNATURES]
TAIL = 8 * 1024 * 1024          # read this much of the end of each access log
MIN_HITS = 3                    # an application needs this many 2xx answers on its paths
NAME_RE = re.compile(r'[\w .+()/:-]{1,120}')
VERSION_RE = re.compile(r'[\w.+~:-]{0,60}')


def product_of(pkg):
    """The product name of a Debian package, or None when the guess does not follow it."""
    if pkg in PACKAGES:
        return PACKAGES[pkg]
    for rx, name in PACKAGE_PATTERNS:
        if rx.fullmatch(pkg):
            return name
    return None


def dpkg_packages(path=DPKG_STATUS):
    """{package: version} of the installed packages the guess follows (PACKAGES, PACKAGE_PATTERNS)."""
    out = {}
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError:
        return out
    for block in text.split('\n\n'):
        f = dict(re.findall(r'^([A-Za-z-]+): (.*)$', block, re.M))
        pkg = f.get('Package')
        if pkg and product_of(pkg) and 'installed' in (f.get('Status') or '') and f.get('Version'):
            out[pkg] = f['Version']
    return out


def _path_of(line):
    """(host or None, path, status) of one access log line, or None."""
    if line.startswith('{'):
        try:
            d = json.loads(line)
        except ValueError:
            return None
        if not isinstance(d, dict):
            return None
        p = d.get('path') or d.get('uri') or d.get('request_uri')
        if not p and d.get('request'):
            parts = str(d['request']).split(' ')
            p = parts[1] if len(parts) > 1 else ''
        try:
            st = int(d.get('http_status') or d.get('status') or 0)
        except (TypeError, ValueError):
            return None
        host = str(d.get('vhost') or d.get('host') or d.get('server_name') or '').lower() or None
        return host, str(p or ''), st
    m = re.match(r'^\S+ \S+ \S+ \[[^\]]+\] "(?:[A-Z]+) (\S+)[^"]*" (\d{3}) ', line)
    if not m:
        return None
    return None, m.group(1), int(m.group(2))


def scan_logs(cfg, tail=TAIL, exclude=()):
    """{application: {host: hits}} from the 2xx answers in the access logs. A redirect (a site that sends everything
    to https or elsewhere) is no sign the application is there; `exclude`: hosts never counted (jt-waf-mgr's own,
    whose web page answers 200 for any path)."""
    hits = collections.defaultdict(collections.Counter)
    for f in traffic.files(cfg):
        site = traffic.site_of(f)
        try:
            with open(f, 'rb') as fh:
                size = os.fstat(fh.fileno()).st_size
                fh.seek(max(0, size - tail))
                data = fh.read(tail)
        except OSError:
            continue
        lines = data.decode('utf-8', 'replace').splitlines()
        if size > tail:
            lines = lines[1:]               # the first one is cut
        for line in lines:
            r = _path_of(line)
            if not r or not 200 <= r[2] < 300:
                continue
            host = site or r[0] or '(default)'
            if host.lower() in exclude:
                continue
            if not traffic.HOST_RE.fullmatch(host) or len(host) > 253:
                continue                    # a Host header a client made up is not a site
            for name, rx in _SIGS:
                if rx.search(r[1]):
                    hits[name][host] += 1
                    break
            m = _API_RE.search(r[1]) if 'api=SYNO.' in r[1] else None
            pkg = synology_package(m.group(1)) if m else None
            if pkg:
                hits[pkg][host] += 1
    return {name: dict(c) for name, c in hits.items()}


def own_hosts(app):
    """The site names nginx sends to this program's own web service (its listen address): not an application."""
    port = str(app.cfg['server'].get('listen') or '').rpartition(':')[2]
    out = set()
    if not port.isdigit():
        return out
    try:
        n, _ = app.site.load()
        for s in n.servers():
            if any(re.search(r'(?:127\.0\.0\.1|localhost|\[::1\]):%s(?:\D|$)' % port, u) for u in s.get('upstreams') or []):
                out.update(x.lower() for x in s.get('server_names') or [])
    except Exception:          # noqa: BLE001 -- no nginx configuration here
        pass
    return out


ACTIVESYNC_SERVERS = ('Exchange (OWA)', 'Zimbra', 'SOGo', 'Kerio Connect')


HOME_BYTES = 200000                 # the start of a home page is enough for its title and meta tags
HOME_WORKERS = 8


def homepage_text(got):
    """The headers ("name: value" lines, names in lower case) and the start of the body of an answer: what the home
    page signatures (HOMEPAGES) are matched against."""
    status, headers, body = got
    return ''.join('%s: %s\n' % (k, v) for k, v in sorted(headers.items())) + '\n' + body[:HOME_BYTES].decode('utf-8', 'replace')


def match_homepage(text):
    """The application a home page names (its title, a generator tag, a header only it sends), or None."""
    for name, rx in HOMEPAGES:
        if rx.search(text):
            return name
    return None


def _home(host, fetch, port=443):
    """The home page of a site, following up to two redirects that stay on the site."""
    import urllib.parse
    path = '/'
    for _ in range(3):
        got = fetch(host, {'path': path, 'max_bytes': HOME_BYTES, 'port': port}, timeout=5)
        if not got:
            return None
        status, headers, _body = got
        loc = headers.get('location') or ''
        if status in (301, 302, 303, 307, 308) and loc:
            u = urllib.parse.urlsplit(loc)
            if u.netloc and u.netloc.lower().split(':')[0] != host:
                return None                     # it sends elsewhere: not this site's page
            path = (u.path or '/') + ('?' + u.query if u.query else '')
            if not path.startswith('/'):
                return None
            continue
        return got if status == 200 else None
    return None


def _tls_listen(listen):
    """A listen directive that serves TLS: port 443, or any port marked ssl (0.5.19: a host whose stream block on 443
    passes each name to its own port by SNI -- "listen 12443 ssl" -- is reached at 443 all the same; a name not passed
    on that way meets another certificate there, and the check of it refuses the answer)."""
    return bool(re.search(r'(?:^|:)443\b', listen) or re.search(r'\bssl\b', listen))


def _listen_port(listen):
    m = re.match(r'\s*(?:\[[^\]]*\]:|[^\s:]+:)?(\d{1,5})\b', listen)
    return int(m.group(1)) if m else None


def site_ports(app):
    """{site name: the port its TLS server answers on}: 443 when it listens there, else its own ssl port (0.5.33: a
    Synology DSM published on 5001; asking it at 443 meets another site there). Names on 443 are left out."""
    out = {}
    try:
        n, _ = app.site.load()
        servers = n.servers()
    except Exception:          # noqa: BLE001 -- no nginx configuration here
        return out
    for sv in servers:
        tls = [x for x in sv.get('listen') or [] if _tls_listen(x)]
        if not tls or any(re.search(r'(?:^|:)443\b', x) for x in tls):
            continue
        port = _listen_port(tls[0])
        for h in sv.get('server_names') or []:
            if port and 0 < port < 65536:
                out.setdefault(h.lower(), port)
    return out


def homepage_sites(app):
    """The sites worth asking for their home page: a name nginx serves over TLS, not a wildcard or a pattern, not this
    program's own, not a block that only redirects."""
    out = []
    own = own_hosts(app)
    try:
        n, _ = app.site.load()
        servers = n.servers()
    except Exception:          # noqa: BLE001 -- no nginx configuration here
        return out
    for sv in servers:
        if sv.get('redirect_only') or not any(_tls_listen(x) for x in sv.get('listen') or []):
            continue
        for h in sv.get('server_names') or []:
            h = h.lower()
            if h not in own and h not in out and traffic.HOST_RE.fullmatch(h) and '.' in h:
                out.append(h)
    return out[:200]


def guess_homepages(app, hosts, fetch=None, ports=None):
    """{application: [hosts]} from the sites' own home pages (read through this host's nginx, a few at a time)."""
    from concurrent.futures import ThreadPoolExecutor
    fetch = fetch or fetch_local
    ports = ports or {}

    def one(h):
        try:
            got = _home(h, fetch, ports.get(h, 443))
            return h, (match_homepage(homepage_text(got)) if got else None)
        except Exception:      # noqa: BLE001 -- one site's odd answer never stops the guess
            return h, None
    found = collections.defaultdict(list)
    with ThreadPoolExecutor(max_workers=HOME_WORKERS) as ex:
        for h, name in ex.map(one, hosts):
            if name:
                found[name].append(h)
    return dict(found)


def host_products(path=None):
    """{product: (package, version)} of this host's packages. When several packages give one product, the newest
    version stands for it (0.5.28: a host upgraded from Debian 11 keeps libssl1.1 1.1.1w next to libssl3 3.0.22;
    taken in name order the leftover won, and OpenSSL threats were judged against the library nginx does not load)."""
    from .debtracker import vercmp
    out = {}
    for pkg, ver in sorted(dpkg_packages(path or DPKG_STATUS).items()):
        name = product_of(pkg)
        if name and (name not in out or vercmp(ver, out[name][1]) > 0):
            out[name] = (pkg, ver)
    return out


def guess(app, fetch=None):
    """What the program can tell: [{name, version, hosts, evidence, kind}]."""
    out = []
    seen = {}
    for name, (pkg, ver) in sorted(host_products().items()):
        seen[name] = True
        out.append({'name': name, 'version': ver, 'hosts': [], 'kind': 'host', 'evidence': 'dpkg: %s %s' % (pkg, ver)})
    if 'nginx' not in seen:
        try:
            v = app.site.nginx_version() or ''
        except Exception:      # noqa: BLE001 -- no nginx binary here
            v = ''
        m = re.search(r'nginx/([\d.]+)', v)
        if m:
            out.append({'name': 'nginx', 'version': m.group(1), 'hosts': [], 'kind': 'host', 'evidence': v[:80]})
    try:
        _, m = app.site.load()
        crs = m.crs_status().get('version')
    except Exception:          # noqa: BLE001
        crs = None
    if crs:
        out.append({'name': 'OWASP CRS', 'version': crs, 'hosts': [], 'kind': 'host', 'evidence': 'ModSecurity configuration'})
    found = scan_logs(app.cfg, exclude=own_hosts(app))
    # ActiveSync alone means Z-Push; on a host that also shows a mail server with its own ActiveSync it is that one
    with_own = set()
    for n in ACTIVESYNC_SERVERS:
        with_own.update(found.get(n, {}))
    if 'Z-Push' in found:
        found['Z-Push'] = {h: c for h, c in found['Z-Push'].items() if h not in with_own}
    # the home pages: an application whose paths the logs do not show (or show too seldom) but whose page names it
    ports = site_ports(app)
    try:
        home = guess_homepages(app, homepage_sites(app), fetch=fetch, ports=ports)
    except Exception:          # noqa: BLE001 -- the guess stands on the logs alone
        home = {}
    # a Synology DSM site: the packages its API list names (0.5.33)
    dsm = sorted(set(h for h, n in found.get(SYNOLOGY, {}).items() if n >= MIN_HITS) | set(home.get(SYNOLOGY, [])))
    listed = collections.defaultdict(dict)
    for h in dsm[:10]:
        try:
            for name, apis in synology_packages(h, fetch or fetch_local, ports.get(h, 443)).items():
                listed[name][h] = apis
        except Exception:      # noqa: BLE001 -- one site's odd answer never stops the guess
            continue
    for name in sorted(set(found) | set(home) | set(listed)):
        by_host = found.get(name, {})
        hosts = sorted(h for h, n in by_host.items() if n >= MIN_HITS)
        pages = sorted(h for h in home.get(name, []) if h not in hosts)
        apis = sorted(h for h in listed.get(name, {}) if h not in hosts and h not in pages)
        pages += apis
        if hosts or pages:
            ev = ', '.join('%s %d' % (h, by_host[h]) for h in hosts[:8])
            if pages and len(pages) > len(apis):
                ev = (ev + '; ' if ev else '') + 'homepage: ' + ', '.join([h for h in pages if h not in apis][:8])
            if apis:
                ev = (ev + '; ' if ev else '') + 'SYNO.API.Info: ' + ', '.join(apis[:8])
            out.append({'name': name, 'version': '', 'hosts': sorted(hosts + pages), 'kind': 'site', 'evidence': ev})
    return out


# --- the stored list -------------------------------------------------------------------------------------------

def _row(r):
    return {'id': r['id'], 'name': r['name'], 'version': r['version'], 'hosts': json.loads(r['hosts'] or '[]'),
            'kind': r['kind'], 'source': r['source'], 'confirmed': bool(r['confirmed']), 'evidence': r['evidence'],
            'notes': r['notes'], 'updated_at': util.iso(r['updated_at']), 'updated_by': r['updated_by']}


def listing(db):
    return [_row(r) for r in db.q('SELECT * FROM software ORDER BY kind, name')]


def confirmed(db):
    """What the LLM may see: product and version, nothing about the sites; web-facing software only. A product
    listed more than once (two servers on different versions) is one line with every version."""
    out = {}
    for r in db.q('SELECT name, version, kind, source FROM software WHERE confirmed=1 ORDER BY name, id'):
        if web_related(r['name'], r['kind'], r['source']):
            out.setdefault(r['name'], []).append(r['version'] or 'unknown')
    return [{'name': n, 'version': join_versions(v)} for n, v in out.items()]


def join_versions(versions):
    """Several versions of one product, oldest-looking first, each once: "10.1.20, 10.1.21"."""
    seen = []
    for v in versions:
        if v not in seen:
            seen.append(v)
    known = sorted((v for v in seen if v != 'unknown'), key=_vkey)
    return ', '.join(known + (['unknown'] if 'unknown' in seen else [])) or 'unknown'


def _vkey(v):
    return [(0, int(x), '') if x.isdigit() else (1, 0, x) for x in re.split(r'[.+~:-]', v)]


def versions_of(db, name):
    """The confirmed version line of one product, as confirmed() gives it ('' when it is not listed)."""
    vs = [r['version'] or 'unknown' for r in db.q('SELECT version FROM software WHERE name=? AND confirmed=1 ORDER BY id',
                                                     (name,))]
    return join_versions(vs) if vs else ''


def hosts_of(db, name):
    """Every site a product is listed for (all its entries). A product this host runs itself (nginx here, in front of
    every site) is not narrowed to the sites of the same product on back-end hosts (0.5.17)."""
    out = []
    rows = db.q('SELECT hosts, kind FROM software WHERE name=? ORDER BY id', (name,))
    here = any(r['kind'] == 'host' for r in rows)
    for r in rows:
        if here and r['kind'] == 'backend':
            continue
        for h in json.loads(r['hosts'] or '[]'):
            if h not in out:
                out.append(h)
    return out


def tech_versions(db):
    """(product, tech) -> {site: [versions]} of a language (PHP) under a product on every one of the product's sites, as
    their back-end hosts said it (backends.py), or None when a site's is not known. A site behind two back-ends (an
    upstream group) may have two versions: both are kept (0.5.22: the last one read stood for the site)."""
    def f(product, tech):
        sites = hosts_of(db, product)
        if not sites:
            return None
        known = {}
        for r in db.q("SELECT version, hosts FROM software WHERE name=? AND kind='backend' AND version<>'' ORDER BY id",
                      (tech,)):
            for h in json.loads(r['hosts'] or '[]'):
                if r['version'] not in known.setdefault(h, []):
                    known[h].append(r['version'])
        if any(h not in known for h in sites):
            return None
        return {h: known[h] for h in sites}
    return f


def followed(db, name):
    """Whether a product is one the threat intelligence follows (web-facing), whatever its confirmation."""
    if name in WEB_PRODUCTS:
        return True
    return any(web_related(name, r['kind'], r['source']) for r in db.q('SELECT kind, source FROM software WHERE name=?', (name,)))


def prune_unrelated(db):
    """Drop what an older version guessed on the host that is not web-facing (confirmed or not). Returns the names."""
    gone = [r['name'] for r in db.q("SELECT name, kind, source FROM software WHERE source='guess'")
            if not web_related(r['name'], r['kind'], r['source'])]
    for n in gone:
        db.x("DELETE FROM software WHERE name=? AND source='guess'", (n,))
    return gone


# --- versions read from the applications themselves -----------------------------------------------------------

PROBE_ACTOR = 'version-probe'


def lan_address():
    """This host's own address on its local network (the one its default route leaves from), or None: a site that
    only lets the local network in (an nginx allow list, a geo map) answers 403 to 127.0.0.1 but not to this one.
    Found without sending anything (a UDP socket's connect only picks the route); a private address only."""
    import ipaddress
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('192.0.2.1', 9))             # documentation address: nothing is sent
            ip = s.getsockname()[0]
        a = ipaddress.ip_address(ip)
    except (OSError, ValueError):
        return None
    return ip if a.is_private and not a.is_loopback and not a.is_link_local else None


OFFLINE = False          # tests: never ask a real nginx (the unit tests also run on a production host)


def _fetch_at(addr, host, probe, timeout, token):
    if OFFLINE:
        return None
    import http.client
    import socket
    import ssl
    from . import util
    body = probe.get('body')
    data = json.dumps(body).encode() if isinstance(body, (dict, list)) else None
    ctx = util.tls_context()            # the system's verification, TLS 1.2 or newer (as every TLS client here)
    port = int(probe.get('port') or 443)
    try:
        raw = socket.create_connection((addr, port), timeout=timeout)
        sock = ctx.wrap_socket(raw, server_hostname=host)
    except (OSError, ssl.SSLError):
        return None
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    conn.sock = sock
    try:
        conn.request(probe.get('method') or 'GET', probe['path'], body=data,
                     headers={'Host': host, 'User-Agent': 'jt-waf-mgr version check', 'Accept': '*/*',
                              **({'Content-Type': 'application/json'} if data else {}),
                              **({probe['token_header']: token} if token and probe.get('token_header') else {})})
        r = conn.getresponse()
        out = r.read(int(probe.get('max_bytes') or 300000))
        return r.status, {k.lower(): v for k, v in r.getheaders()}, out
    except (OSError, http.client.HTTPException):
        return None
    finally:
        conn.close()


def fetch_local(host, probe, timeout=6, token=None, lan=None):
    """One request to a site through this host's own nginx: 127.0.0.1:443 with the site's name for TLS (SNI, the
    certificate checked against it) and Host. Returns (status, headers {lower: value}, body bytes) or None.
    A 403 there (a site open to the local network only) is asked once more at this host's local address."""
    got = _fetch_at('127.0.0.1', host, probe, timeout, token)
    if got and got[0] == 403:
        addr = lan if lan is not None else lan_address()
        if addr:
            again = _fetch_at(addr, host, probe, timeout, token)
            if again:
                return again
    return got


def extract_version(probe, status, headers, body):
    """The version an answer carries, or None (anything that is not a plain version string is refused)."""
    if status != 200 and not (probe.get('any_status') and status):
        return None                 # any_status: the version is in a header of every answer (a 204, a 401, a 429)
    v = None
    if probe.get('json_parts'):
        # a version in parts ({"major":1,"minor":2,"patch":3}): each a dotted path, joined with dots
        try:
            doc = json.loads(body.decode('utf-8', 'replace'))
        except ValueError:
            doc = None
        parts = [_json_at(doc, p) for p in probe['json_parts']]
        v = '.'.join(str(x) for x in parts) if all(isinstance(x, (int, str)) and not isinstance(x, bool)
                                                   and str(x) != '' for x in parts) else None
    elif probe.get('header'):
        v = headers.get(probe['header'].lower())
    elif probe.get('json'):
        try:
            v = _json_at(json.loads(body.decode('utf-8', 'replace')), probe['json'])
        except ValueError:
            v = None
    elif probe.get('regex'):
        m = re.search(probe['regex'], body.decode('utf-8', 'replace'))
        if m and probe.get('regex_format'):
            # 0.5.33: a version in several groups (Synology DSM: major=7&minor=4&build=90080 -> 7.4-90080)
            try:
                v = probe['regex_format'].format(*m.groups())
            except (IndexError, KeyError, ValueError):
                v = None
        else:
            v = m.group(1) if m else None
    if v is not None and probe.get('regex') and (probe.get('header') or probe.get('json')):
        m = re.search(probe['regex'], str(v))
        v = m.group(1) if m else None
    if v is not None and probe.get('convert') == 'roundcube':
        # Roundcube's "rcversion" 10605 is 1.6.5 (major * 10000 + minor * 100 + patch)
        try:
            n = int(v)
            v = '%d.%d.%d' % (n // 10000, n // 100 % 100, n % 100) if 10000 <= n < 1000000 else None
        except (TypeError, ValueError):
            v = None
    v = str(v).strip() if v is not None else ''
    return v if v and len(v) <= 60 and VERSION_RE.fullmatch(v) and re.search(r'\d', v) else None


def _json_at(v, path):
    """The value at a dotted path ("result.server_version"; a number indexes a list), or None."""
    for part in str(path).split('.'):
        if isinstance(v, list) and part.isdigit():
            v = v[int(part)] if int(part) < len(v) else None
        else:
            v = v.get(part) if isinstance(v, dict) else None
    return v


def sync_host_versions(app, log=print, path=DPKG_STATUS):
    """This host's own packages: the installed version is a fact, not a guess, so a guessed entry follows it and keeps
    its confirmation (0.5.8: nginx 1.30.7, installed by an approved update, was still searched for as 1.30.6 until
    someone pressed "guess again"). A person's entry is never changed. Returns the names updated."""
    db = app.db
    found = host_products(path)
    changed = []
    for r in db.q("SELECT id, name, version FROM software WHERE source='guess' AND kind='host'"):
        f = found.get(r['name'])
        if f and f[1] and f[1] != r['version']:
            db.x('UPDATE software SET version=?, evidence=?, updated_at=?, updated_by=? WHERE id=?',
                 (f[1], 'dpkg: %s %s' % f, util.now(), PROBE_ACTOR, r['id']))
            app.audit.log('software.version_detected', PROBE_ACTOR, 'system', None, 'ok', name=r['name'],
                          old=r['version'] or None, new=f[1], package=f[0])
            log('software: %s %s -> %s (installed package)' % (r['name'], r['version'], f[1]))
            changed.append(r['name'])
    return changed


def detect_versions(app, fetch=fetch_local, log=print):
    """For each application in the list that tells its version (version_sources()['auto']) and has a site: read it
    and fill it in. A version a person typed is never replaced; one read before is kept current. Returns
    [{name, old, new, host}] of what changed (audited)."""
    db = app.db
    probes = {p['name']: p for p in version_sources()['auto']}

    def token_of(p):
        sec, _, key = (p.get('token_setting') or '').partition('.')
        return str((app.cfg.data.get(sec) or {}).get(key) or '') if key else ''

    changed = []
    ports = site_ports(app)
    for r in db.q("SELECT * FROM software WHERE kind='site'"):
        p = probes.get(r['name'])
        if not p:
            continue
        token = token_of(p)
        if p.get('token_setting') and not token:
            continue                    # it tells its version only with a token: not set, not asked
        if r['version'] and r['updated_by'] != PROBE_ACTOR:
            continue                    # a person's version (or one they confirmed by hand) stays
        hosts = json.loads(r['hosts'] or '[]')
        for host in hosts[:5]:
            hp = dict(p, port=ports[host]) if host in ports else p
            got = fetch(host, hp, token=token) if token else fetch(host, hp)
            v = extract_version(p, *got) if got else None
            if not v:
                continue
            if v != r['version']:
                db.x('UPDATE software SET version=?, evidence=?, updated_at=?, updated_by=? WHERE id=?',
                     (v, util.clip('%s told its version (%s %s)' % (host, p.get('method') or 'GET', p['path']), 200),
                      util.now(), PROBE_ACTOR, r['id']))
                app.audit.log('software.version_detected', PROBE_ACTOR, 'system', None, 'ok', name=r['name'],
                              old=r['version'] or None, new=v, host=host)
                changed.append({'name': r['name'], 'old': r['version'], 'new': v, 'host': host})
                log('software: %s %s -> %s (%s)' % (r['name'], r['version'] or '-', v, host))
            break
    return changed


def refresh(app, actor, fetch=fetch_local):
    """Store the guesses: new names are added unconfirmed; a guessed version that changed updates an unconfirmed
    entry (a person's version is never overwritten); hosts and evidence are refreshed. Returns {added, updated}."""
    db = app.db
    added = updated = removed = 0
    now = util.now()
    found = guess(app, fetch=fetch)
    # a guess the program no longer makes (and nobody confirmed or edited) goes away
    dismissed = set(dismissed_names(db))
    found = [g for g in found if g['name'] not in dismissed]     # a person removed it: not guessed again
    names = {g['name'] for g in found}
    for r in db.q("SELECT id, name FROM software WHERE source='guess' AND confirmed=0"):
        if r['name'] not in names:
            db.x('DELETE FROM software WHERE id=?', (r['id'],))
            removed += 1
    removed += len(prune_unrelated(db))
    for g in found:
        # the back-end hosts' entries (backends.py) are kept by their own probe, not by the guess
        rows = db.q("SELECT * FROM software WHERE name=? AND kind<>'backend' ORDER BY id", (g['name'],))
        if any(x['source'] == 'person' for x in rows):
            continue                # a person keeps this product's entries (one or several): the guess leaves them
        r = rows[0] if rows else None
        if not r:
            db.x('INSERT INTO software(name, version, hosts, kind, source, confirmed, evidence, notes, updated_at, updated_by) '
                 "VALUES (?,?,?,?, 'guess', 0, ?, '', ?, ?)",
                 (g['name'], g['version'], json.dumps(g['hosts']), g['kind'], g['evidence'], now, actor))
            added += 1
            continue
        version = r['version']
        confirmed_flag = r['confirmed']
        hosts = r['hosts'] if r['source'] == 'person' else json.dumps(g['hosts'])   # a person's site list stays
        if r['source'] == 'guess' and g['version'] and g['version'] != r['version']:
            version, confirmed_flag = g['version'], 0          # a new version needs a new look
        if (version, hosts, g['evidence']) != (r['version'], r['hosts'], r['evidence']):
            db.x('UPDATE software SET version=?, hosts=?, evidence=?, confirmed=?, updated_at=? WHERE id=?',
                 (version, hosts, g['evidence'], confirmed_flag, now, r['id']))
            updated += 1
    try:
        versions = len(detect_versions(app, fetch=fetch, log=lambda *a: None))
    except Exception:          # noqa: BLE001 -- the guess stands without the versions
        versions = 0
    return {'added': added, 'updated': updated, 'removed': removed, 'versions': versions}


def confirm_all(db, actor):
    """Confirm every entry still waiting (a version is not needed: without one the search goes by the name)."""
    return db.x('UPDATE software SET confirmed=1, updated_at=?, updated_by=? WHERE confirmed=0', (util.now(), actor)).rowcount


class SoftwareError(Exception):
    def __init__(self, code, message=''):
        super().__init__(code)
        self.code, self.message = code, message


def save(db, actor, name, version, hosts=None, notes='', confirmed_flag=True, sid=None):
    """Add or edit one entry (a person's entry is confirmed by default)."""
    name = (name or '').strip()
    version = (version or '').strip()
    if not NAME_RE.fullmatch(name):
        raise SoftwareError('bad_name', 'letters, digits, spaces and . + ( ) / : - only, up to 120')
    if not VERSION_RE.fullmatch(version):
        raise SoftwareError('bad_version', 'up to 60 characters: letters, digits and . + ~ : -')
    hosts = [h for h in (hosts or []) if isinstance(h, str) and traffic.HOST_RE.fullmatch(h.lower())][:50]
    notes = util.clip(str(notes or ''), 300)
    now = util.now()
    if sid is None:
        _same(db, name, hosts, None, 'site')
        cur = db.x('INSERT INTO software(name, version, hosts, kind, source, confirmed, evidence, notes, updated_at, updated_by) '
                   "VALUES (?,?,?, 'site', 'person', ?, '', ?, ?, ?)",
                   (name, version, json.dumps(hosts), 1 if confirmed_flag else 0, notes, now, actor))
        if name in dismissed_names(db):
            _set_dismissed(db, [x for x in dismissed_names(db) if x != name])
        return cur.lastrowid
    r = db.one('SELECT * FROM software WHERE id=?', (int(sid),))
    if not r:
        raise SoftwareError('not_found')
    _same(db, name, hosts or json.loads(r['hosts'] or '[]'), r['id'], r['kind'])
    if r['source'] == 'guess' and r['name'] != name:
        # a person renamed a guess (Exchange -> Z-Push): the old name is not guessed again
        _set_dismissed(db, dismissed_names(db) + [r['name']])
    db.x("UPDATE software SET name=?, version=?, hosts=?, notes=?, confirmed=?, source='person', updated_at=?, updated_by=? "
         'WHERE id=?', (name, version, json.dumps(hosts or json.loads(r['hosts'] or '[]')), notes,
                        1 if confirmed_flag else 0, now, actor, r['id']))
    return r['id']


def _same(db, name, hosts, sid, kind='site'):
    """One product may be listed again for other sites (two servers on different versions): every entry of the
    same name then names its sites, and no site is in two of them. This host's own package and a back-end host's
    server of the same name (nginx here, nginx behind it) are different programs: both may be listed."""
    for r in db.q('SELECT id, hosts, kind FROM software WHERE name=? AND id IS NOT ?', (name, sid)):
        theirs = set(json.loads(r['hosts'] or '[]'))
        if {r['kind'], kind} == {'host', 'backend'}:
            continue
        if r['kind'] == 'host' or not theirs or not hosts:
            raise SoftwareError('exists', 'already in the list: to list it again, give every entry of it its own sites')
        if theirs & set(hosts):
            raise SoftwareError('exists', 'already in the list for %s: each entry of the same product has its own sites'
                                % ', '.join(sorted(theirs & set(hosts))[:3]))


DISMISSED_KEY = 'software.dismissed'


def dismissed_names(db):
    """Guesses a person removed: "重新推測" leaves them out (adding the name by hand takes it off this list)."""
    try:
        v = json.loads(db.get_meta(DISMISSED_KEY, '[]') or '[]')
    except ValueError:
        return []
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _set_dismissed(db, names):
    db.set_meta(DISMISSED_KEY, json.dumps(sorted(set(names))[:500]))


def delete(db, sid):
    r = db.one('SELECT name, source, hosts FROM software WHERE id=?', (int(sid),))
    n = db.x('DELETE FROM software WHERE id=?', (int(sid),)).rowcount
    if n and r['source'] == 'guess':
        _set_dismissed(db, dismissed_names(db) + [r['name']])
    elif n and r['source'] == 'probe':
        from . import backends          # a back-end host's entry: not listed again for these sites
        backends.dismiss(db, ['%s@%s' % (r['name'], h) for h in json.loads(r['hosts'] or '[]')])
    return n
