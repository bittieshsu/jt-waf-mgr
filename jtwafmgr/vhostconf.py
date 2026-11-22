"""Site configuration, read and suggested (0.5.39): jt-waf-mgr never writes a server block. It shows a site's block as
nginx has it (secret-looking values masked) and writes an example block for a new site from a few answers, for an
administrator to save and load by hand (nginx -t, reload). ModSecurity is then switched on for the site from the sites
page (a marked include line, an approved change), not in the example.

Presets: "generic" (a reverse proxy to one back end) and "synology" (Synology DSM: its own HTTPS port, WebSocket,
large uploads streamed, X-Forwarded-For replaced, never appended, for DSM's auto block)."""
import ipaddress
import re
import urllib.parse

HOST_RE = re.compile(r'^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+$')
SIZE_RE = re.compile(r'^(?:0|[1-9][0-9]{0,5}[kmg]?)$')
PATH_RE = re.compile(r'^/[A-Za-z0-9_./@+-]{1,250}$')
PRESETS = ('generic', 'synology')
MAX_LINES = 2000


class VhostError(Exception):
    def __init__(self, code, field=None):
        super().__init__(code)
        self.code, self.field = code, field


# --- a site's own block -------------------------------------------------------------------------------------------

def block_text(text, line):
    """The text of the server block that starts at `line` (1-based; the line of its `server` word), to its closing
    brace: braces inside quotes and comments do not count. None when no block starts there."""
    lines = text.split('\n')
    if not 0 < line <= len(lines):
        return None
    start = line - 1
    rest = '\n'.join(lines[start:])
    m = re.match(r'\s*server\s*\{', rest)
    if not m:
        return None
    depth, i, quote = 0, 0, None
    while i < len(rest):
        c = rest[i]
        if quote:
            if c == '\\':
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in '"\'':
            quote = c
        elif c == '#':
            j = rest.find('\n', i)
            i = len(rest) if j < 0 else j
            continue
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                out = rest[:i + 1].split('\n')
                return '\n'.join(out[:MAX_LINES]) + ('\n# ...' if len(out) > MAX_LINES else '')
        i += 1
    return None


def site_block(app, path, line):
    """{file, line, text (masked)} of a server block nginx loads, or VhostError: only a block the parsed configuration
    names (never any file a caller asks for)."""
    from .compliance import Monitor
    n, _ = app.site.load()
    if not any(s['file'] == path and s['line'] == line for s in n.servers()):
        raise VhostError('not_a_site', 'file')
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            text = fh.read(4 * 1024 * 1024)
    except OSError:
        raise VhostError('unreadable', 'file')
    block = block_text(text, line)
    if block is None:
        raise VhostError('no_block', 'line')
    return {'file': path, 'line': line, 'text': Monitor.mask_config(block)}


# --- an example for a new site ------------------------------------------------------------------------------------

def certificates(app):
    """[{cert, key, names}] the TLS server blocks use now (the most used first): an example picks from these."""
    from .nginxconf import _value
    n, _ = app.site.load()
    h = n.http()
    seen = {}
    for s in (h.children if h else []):
        if s.name != 'server' or s.children is None:
            continue
        cert, key = _value(s.children, 'ssl_certificate'), _value(s.children, 'ssl_certificate_key')
        if cert and key and PATH_RE.match(cert) and PATH_RE.match(key):
            e = seen.setdefault((cert, key), {'cert': cert, 'key': key, 'names': 0})
            e['names'] += 1
    return sorted(seen.values(), key=lambda e: -e['names'])[:20]


def _backend(url):
    u = urllib.parse.urlsplit(url or '')
    if u.scheme not in ('http', 'https') or not u.hostname or u.path not in ('', '/') or u.query or u.fragment or \
            u.username or u.password:
        raise VhostError('invalid_backend', 'backend')
    host = u.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.match(host):
            raise VhostError('invalid_backend', 'backend')
    try:
        port = u.port
    except ValueError:
        raise VhostError('invalid_backend', 'backend')
    return u.scheme, ('[%s]' % host if ':' in host else host) + (':%d' % port if port else '')


def example(opts, internal_networks=(), mem_bytes=None):
    """The text of a server block for a new site from the answers (validated; nothing is written)."""
    preset = opts.get('preset') or 'generic'
    if preset not in PRESETS:
        raise VhostError('invalid_preset', 'preset')
    host = str(opts.get('host') or '').strip().lower()
    if not HOST_RE.match(host):
        raise VhostError('invalid_host', 'host')
    try:
        port = int(opts.get('port') or (5001 if preset == 'synology' else 443))
    except (TypeError, ValueError):
        raise VhostError('invalid_port', 'port')
    if not 1 <= port <= 65535 or port == 80:
        raise VhostError('invalid_port', 'port')
    scheme, backend = _backend(opts.get('backend'))
    body = str(opts.get('upload') or ('1g' if preset == 'synology' else '10m')).strip().lower()
    if not SIZE_RE.match(body):
        raise VhostError('invalid_upload', 'upload')
    cert, key = str(opts.get('cert') or ''), str(opts.get('key') or '')
    if not (PATH_RE.match(cert) and PATH_RE.match(key)):
        raise VhostError('invalid_cert', 'cert')
    internal = bool(opts.get('internal_only', True))
    websocket = bool(opts.get('websocket', preset == 'synology'))
    stream = preset == 'synology' or bool(opts.get('stream_uploads'))
    v6 = bool(opts.get('ipv6', True))
    nets = [str(x) for x in internal_networks] or ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1']
    var = re.sub(r'[^a-z0-9]', '_', host.split('.')[0]) + '_connection_upgrade'
    L = []
    L.append('# %s -> %s://%s (example written by jt-waf-mgr; check it, save it as' % (host, scheme, backend))
    L.append('# /etc/nginx/sites-available/%s.conf, link it into sites-enabled, then nginx -t and reload).' % host)
    L.append('# ModSecurity: switch it on for this site on the jt-waf-mgr sites page afterwards (an approved change).')
    if preset == 'synology':
        L.append('# Synology DSM: add this proxy under DSM Control Panel > Security > Trusted proxies, or DSM\'s')
        L.append('# auto block sees every client as the proxy.')
    big = body == '0' or (mem_bytes and _bytes(body) > mem_bytes // 4)
    if big:
        L.append('# NOTE: with ModSecurity on, nginx reads a whole upload into memory first; keep client_max_body_size')
        L.append('# well below this host\'s memory (the system check warns), or leave ModSecurity off for this site.')
    if websocket:
        L += ['map $http_upgrade $%s {' % var, '    default upgrade;', "    ''      close;", '}', '']
    if port != 443:
        L += ['# only the names served on port %d get a TLS handshake: a scan of the address, or a guessed' % port,
              '# name, is refused (keep one such block per port; leave it out if the port has one already)',
              'server {', '    listen %d ssl default_server;' % port] + \
             (['    listen [::]:%d ssl default_server;' % port] if v6 else []) + ['    ssl_reject_handshake on;', '}', '']
    L += ['server {', '    listen %d ssl;' % port] + (['    listen [::]:%d ssl;' % port] if v6 else [])
    L += ['    http2 on;', '    server_name %s;' % host, '',
          '    ssl_certificate     %s;' % cert, '    ssl_certificate_key %s;' % key,
          '    ssl_protocols TLSv1.2 TLSv1.3;', '    ssl_prefer_server_ciphers off;', '    server_tokens off;', '']
    if internal:
        L.append('    # the local network only (delete these lines to publish the site)')
        L += ['    allow %s;' % n for n in nets] + ['    deny all;', '']
    L += ['    add_header Strict-Transport-Security "max-age=15768000" always;',
          '    client_max_body_size %s;' % body, '',
          '    location / {', '        proxy_pass %s://%s;' % (scheme, backend), '        proxy_http_version 1.1;']
    if scheme == 'https':
        L.append('        proxy_ssl_verify off;          # a private back end with its own certificate')
        L.append('        proxy_ssl_server_name on;')
    L += ['        proxy_set_header Host $host;', '        proxy_set_header X-Real-IP $remote_addr;',
          '        proxy_set_header X-Forwarded-For $remote_addr;   # replaced, never appended (a client cannot forge it)',
          '        proxy_set_header X-Forwarded-Proto $scheme;']
    if websocket:
        L += ['        proxy_set_header Upgrade $http_upgrade;', '        proxy_set_header Connection $%s;' % var]
    if stream:
        L += ['        proxy_request_buffering off;', '        proxy_buffering off;',
              '        proxy_read_timeout 3600s;', '        proxy_send_timeout 3600s;']
    else:
        L.append('        proxy_read_timeout 120s;')
    L += ['    }', '', '    access_log /var/log/nginx/%s.access.log;' % host,
          '    error_log  /var/log/nginx/%s.error.log;' % host, '}']
    if port == 443 and opts.get('redirect_80', True):
        L += ['', 'server {', '    listen 80;'] + (['    listen [::]:80;'] if v6 else []) + \
             ['    server_name %s;' % host] + (['    allow %s;' % n for n in nets] + ['    deny all;'] if internal else []) + \
             ['    return 301 https://$host$request_uri;', '}']
    return {'text': '\n'.join(L) + '\n', 'path': '/etc/nginx/sites-available/%s.conf' % host, 'big_upload': bool(big),
            'steps': ['sudoedit /etc/nginx/sites-available/%s.conf' % host,
                      'sudo ln -s ../sites-available/%s.conf /etc/nginx/sites-enabled/%s.conf' % (host, host),
                      'sudo nginx -t && sudo systemctl reload nginx']}


def _bytes(v):
    m = re.match(r'^(\d+)([kmg]?)$', v)
    return int(m.group(1)) * {'': 1, 'k': 1 << 10, 'm': 1 << 20, 'g': 1 << 30}[m.group(2)] if m else 0
