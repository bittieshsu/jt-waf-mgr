"""The software this host and its sites run: what the threat intelligence (intel.py) looks for vulnerabilities in.

The program guesses, a person confirms (only confirmed entries are ever sent to the second-tier LLM):
- this host's own packages, with exact versions, from the Debian / Ubuntu package database (nginx, the ModSecurity
  module and library, OpenSSL, Python) and the CRS version the ModSecurity configuration loads;
- the applications behind the sites, from the paths they answer with 2xx / 3xx in the access logs (the last few
  MB of each log): /realms/ answered by sso.example.com is Keycloak, /remote.php/dav is Nextcloud, ... -- names only:
  a version cannot be seen from outside, a person fills it in.

Sent to the LLM: product names and versions only -- never site names, addresses or request data.
"""
import collections
import json
import os
import re

from . import traffic, util

DPKG_STATUS = '/var/lib/dpkg/status'
# package -> product name the vulnerability databases use
PACKAGES = {
    'nginx': 'nginx', 'nginx-core': 'nginx', 'nginx-full': 'nginx', 'nginx-extras': 'nginx', 'nginx-light': 'nginx',
    'libnginx-mod-http-modsecurity': 'ModSecurity-nginx connector',
    'libmodsecurity3': 'libmodsecurity (ModSecurity v3)', 'libmodsecurity3t64': 'libmodsecurity (ModSecurity v3)',
    'openssl': 'OpenSSL', 'libssl3': 'OpenSSL', 'libssl3t64': 'OpenSSL',
    'python3': 'Python', 'libpcre2-8-0': 'PCRE2', 'libxml2': 'libxml2', 'libxml2-16': 'libxml2', 'libyajl2': 'YAJL',
    'liblua5.3-0': 'Lua', 'libmaxminddb0': 'libmaxminddb', 'openssh-server': 'OpenSSH',
}
# application -> paths only it answers (a hit counts only with a 2xx / 3xx answer: probes get 404)
SIGNATURES = [
    ('Keycloak', r'^/(?:auth/)?realms/[^/]+/(?:protocol/openid-connect|login-actions|account)'),
    ('Nextcloud', r'^/(?:remote\.php/(?:web)?dav|ocs/v[12]\.php|index\.php/apps/|apps/files/)'),
    ('WordPress', r'^/wp-(?:admin/admin-ajax\.php|includes/|content/|json/)'),
    ('Zimbra', r'^/(?:service/(?:soap|home|upload)|zimbraAdmin/|public/(?:login|Preferences)\.jsp)'),
    ('Odoo', r'^/(?:web/(?:dataset/call_kw|webclient/|login)|xmlrpc/2/)'),
    ('Proxmox VE', r'^/(?:api2/(?:json|extjs)/|pve2/)'),
    ('Proxmox Backup Server', r'^/api2/json/admin/datastore'),
    ('Grafana', r'^/(?:api/(?:dashboards|datasources|frontend/settings)|public/build/)'),
    ('GitLab', r'^/(?:api/v4/projects|-/manifest\.json|assets/webpack/)'),
    ('Gitea', r'^/(?:api/v1/repos/|user/login\?redirect_to|assets/js/index\.js)'),
    ('Zabbix', r'^/(?:zabbix/)?(?:zabbix\.php|jsrpc\.php)'),
    ('Jitsi Meet', r'^/(?:http-bind|xmpp-websocket|colibri-ws/)'),
    ('Zulip', r'^/(?:json/(?:events|messages)|static/webpack-bundles/)'),
    ('Mattermost', r'^/api/v4/(?:users/me|websocket)'),
    ('Rocket.Chat', r'^/(?:sockjs/|api/v1/(?:me|login))'),
    ('Collabora Online', r'^/(?:cool|browser|loleaflet|hosting/discovery)'),
    ('ONLYOFFICE Docs', r'^/(?:web-apps/apps/|coauthoring/|cache/files/)'),
    ('draw.io', r'^/(?:js/app\.min\.js|drawio/|export3\.html)'),
    ('Apache Guacamole', r'^/(?:guacamole/)?api/(?:tokens|session/)'),
    ('MeshCentral', r'^/(?:meshrelay\.ashx|control\.ashx|agent\.ashx)'),
    ('Wazuh dashboard', r'^/app/(?:wazuh|wz-home|endpoints-summary)'),
    ('OpenSearch Dashboards', r'^/(?:api/saved_objects|ui/default_branding)'),
    ('Graylog', r'^/api/(?:system/|search/universal|views/search)'),
    ('NetBox', r'^/api/(?:dcim|ipam)/'),
    ('Synology DSM', r'^/webapi/(?:entry\.cgi|auth\.cgi)'),
    ('Home Assistant', r'^/(?:api/websocket|auth/authorize|frontend_latest/)'),
    ('Jenkins', r'^/(?:jenkins/)?(?:ajaxBuildQueue|ajaxExecutors|static/[0-9a-f]{8}/)'),
    ('Portainer', r'^/api/(?:endpoints|motd)'),
    ('MinIO', r'^/(?:minio/|api/v1/buckets)'),
    ('Vaultwarden', r'^/(?:identity/connect/token|api/ciphers|notifications/hub)'),
    ('Roundcube', r'^/(?:roundcube/)?\?_task='),
    ('phpMyAdmin', r'^/(?:phpmyadmin/)?(?:index\.php\?route=|js/dist/)'),
    ('Uptime Kuma', r'^/(?:api/status-page/|upload/|assets/index-[\w-]+\.js)'),
    ('Kibana', r'^/(?:internal/security/|api/status)'),
    ('Nginx Proxy Manager', r'^/api/nginx/proxy-hosts'),
    ('Moodle', r'^/(?:lib/ajax/service\.php|theme/yui_combo\.php)'),
    ('Joomla', r'^/(?:administrator/index\.php|media/system/js/)'),
    ('Drupal', r'^/(?:core/misc/drupal\.js|sites/default/files/)'),
    ('Magento', r'^/(?:static/version\d+/|customer/section/load)'),
    ('Exchange (OWA)', r'^/(?:owa/|ecp/|EWS/Exchange\.asmx|Microsoft-Server-ActiveSync)'),
    ('Citrix NetScaler Gateway', r'^/(?:vpn/index\.html|logon/LogonPoint/)'),
    ('Fortinet FortiGate SSL VPN', r'^/remote/(?:login|logincheck)'),
    ('Ivanti Connect Secure', r'^/dana-na/'),
]
_SIGS = [(name, re.compile(rx)) for name, rx in SIGNATURES]
TAIL = 8 * 1024 * 1024          # read this much of the end of each access log
MIN_HITS = 3                    # an application needs this many 2xx / 3xx answers on its paths
NAME_RE = re.compile(r'[\w .+()/:-]{1,120}')
VERSION_RE = re.compile(r'[\w.+~:-]{0,60}')


def dpkg_packages(path=DPKG_STATUS):
    """{package: version} of the installed packages in PACKAGES."""
    out = {}
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError:
        return out
    for block in text.split('\n\n'):
        f = dict(re.findall(r'^([A-Za-z-]+): (.*)$', block, re.M))
        pkg = f.get('Package')
        if pkg in PACKAGES and 'installed' in (f.get('Status') or '') and f.get('Version'):
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
        name = PACKAGES[pkg]
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
        return cur.lastrowid
    r = db.one('SELECT * FROM software WHERE id=?', (int(sid),))
    if not r:
        raise SoftwareError('not_found')
    db.x("UPDATE software SET name=?, version=?, hosts=?, notes=?, confirmed=?, source='person', updated_at=?, updated_by=? "
         'WHERE id=?', (name, version, json.dumps(hosts or json.loads(r['hosts'] or '[]')), notes,
                        1 if confirmed_flag else 0, now, actor, r['id']))
    return r['id']


def delete(db, sid):
    return db.x('DELETE FROM software WHERE id=?', (int(sid),)).rowcount
