"""The software this host and its sites run: what the threat intelligence (intel.py) looks for vulnerabilities in.

The program guesses, a person confirms (only confirmed entries are ever sent to the second-tier LLM):
- this host's own packages, with exact versions, from the Debian / Ubuntu package database (nginx, the ModSecurity
  module and library, OpenSSL, OpenSSH, glibc, web and database servers, ...) and the CRS version the ModSecurity
  configuration loads;
- the applications behind the sites, from the paths they answer with 2xx in the access logs (the last few MB of
  each log): /realms/ answered by sso.example.com is Keycloak, /remote.php/dav is Nextcloud, ... -- names only:
  a version cannot be seen from outside, a person fills it in.
The packages and path signatures are data: data/software-signatures.json (each signature carries sample paths that
tests/test_software_signatures.py checks are guessed as it, and that no common path is).

Sent to the LLM: product names and versions only -- never site names, addresses or request data.
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
        return {}, [], []
    return (dict(d.get('packages') or {}), [(re.compile(rx), name) for rx, name in d.get('package_patterns') or []],
            [(name, rx) for name, rx, _samples in d.get('signatures') or []])


PACKAGES, PACKAGE_PATTERNS, SIGNATURES = _load()
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


def guess(app):
    """What the program can tell: [{name, version, hosts, evidence, kind}]."""
    out = []
    pk = dpkg_packages()
    seen = {}
    for pkg, ver in sorted(pk.items()):
        name = product_of(pkg)
        if name in seen:
            continue
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
    for name, by_host in sorted(scan_logs(app.cfg, exclude=own_hosts(app)).items()):
        hosts = sorted(h for h, n in by_host.items() if n >= MIN_HITS)
        if hosts:
            out.append({'name': name, 'version': '', 'hosts': hosts, 'kind': 'site',
                        'evidence': ', '.join('%s %d' % (h, by_host[h]) for h in hosts[:8])})
    return out


# --- the stored list -------------------------------------------------------------------------------------------

def _row(r):
    return {'id': r['id'], 'name': r['name'], 'version': r['version'], 'hosts': json.loads(r['hosts'] or '[]'),
            'kind': r['kind'], 'source': r['source'], 'confirmed': bool(r['confirmed']), 'evidence': r['evidence'],
            'notes': r['notes'], 'updated_at': util.iso(r['updated_at']), 'updated_by': r['updated_by']}


def listing(db):
    return [_row(r) for r in db.q('SELECT * FROM software ORDER BY kind, name')]


def confirmed(db):
    """What the LLM may see: product and version, nothing about the sites."""
    return [{'name': r['name'], 'version': r['version'] or 'unknown'}
            for r in db.q('SELECT name, version FROM software WHERE confirmed=1 ORDER BY name')]


def refresh(app, actor):
    """Store the guesses: new names are added unconfirmed; a guessed version that changed updates an unconfirmed
    entry (a person's version is never overwritten); hosts and evidence are refreshed. Returns {added, updated}."""
    db = app.db
    added = updated = removed = 0
    now = util.now()
    found = guess(app)
    # a guess the program no longer makes (and nobody confirmed or edited) goes away
    dismissed = set(dismissed_names(db))
    found = [g for g in found if g['name'] not in dismissed]     # a person removed it: not guessed again
    names = {g['name'] for g in found}
    for r in db.q("SELECT id, name FROM software WHERE source='guess' AND confirmed=0"):
        if r['name'] not in names:
            db.x('DELETE FROM software WHERE id=?', (r['id'],))
            removed += 1
    for g in found:
        r = db.one('SELECT * FROM software WHERE name=?', (g['name'],))
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
    return {'added': added, 'updated': updated, 'removed': removed}


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
        if db.one('SELECT 1 FROM software WHERE name=?', (name,)):
            raise SoftwareError('exists', 'already in the list')
        cur = db.x('INSERT INTO software(name, version, hosts, kind, source, confirmed, evidence, notes, updated_at, updated_by) '
                   "VALUES (?,?,?, 'site', 'person', ?, '', ?, ?, ?)",
                   (name, version, json.dumps(hosts), 1 if confirmed_flag else 0, notes, now, actor))
        if name in dismissed_names(db):
            _set_dismissed(db, [x for x in dismissed_names(db) if x != name])
        return cur.lastrowid
    r = db.one('SELECT * FROM software WHERE id=?', (int(sid),))
    if not r:
        raise SoftwareError('not_found')
    if r['source'] == 'guess' and r['name'] != name:
        # a person renamed a guess (Exchange -> Z-Push): the old name is not guessed again
        _set_dismissed(db, dismissed_names(db) + [r['name']])
    db.x("UPDATE software SET name=?, version=?, hosts=?, notes=?, confirmed=?, source='person', updated_at=?, updated_by=? "
         'WHERE id=?', (name, version, json.dumps(hosts or json.loads(r['hosts'] or '[]')), notes,
                        1 if confirmed_flag else 0, now, actor, r['id']))
    return r['id']


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
    r = db.one('SELECT name, source FROM software WHERE id=?', (int(sid),))
    n = db.x('DELETE FROM software WHERE id=?', (int(sid),)).rowcount
    if n and r['source'] == 'guess':
        _set_dismissed(db, dismissed_names(db) + [r['name']])
    return n
