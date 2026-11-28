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
PRESETS = ('generic', 'synology', 'qnap')
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
    nas = preset in ('synology', 'qnap')
    body = str(opts.get('upload') or ('1g' if nas else '10m')).strip().lower()
    if not SIZE_RE.match(body):
        raise VhostError('invalid_upload', 'upload')
    cert, key = str(opts.get('cert') or ''), str(opts.get('key') or '')
    if not (PATH_RE.match(cert) and PATH_RE.match(key)):
        raise VhostError('invalid_cert', 'cert')
    internal = bool(opts.get('internal_only', True))
    websocket = bool(opts.get('websocket', nas))
    stream = nas or bool(opts.get('stream_uploads'))
    v6 = bool(opts.get('ipv6', True))
    # 0.5.48: Synology Photos for iOS uploads with "multipart/form-data; charset=utf-8; boundary=...", which
    # ModSecurity (3.0.9 to 3.0.17) does not parse: the body goes uninspected, and the protection set's
    # body-unchecked rule refuses it from outside. Exactly that shape is passed, with the Content-Type in standard
    # form, to a loopback server that inspects it in full (measured on a DSM 7.4 site, 2026-11-26)
    photos_fix = preset == 'synology' and bool(opts.get('photos_ios', True))
    nets = [str(x) for x in internal_networks] or ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1']
    var = re.sub(r'[^a-z0-9]', '_', host.split('.')[0]) + '_connection_upgrade'
    L = []
    L.append('# %s -> %s://%s (example written by jt-waf-mgr; check it, save it as' % (host, scheme, backend))
    L.append('# /etc/nginx/sites-available/%s.conf, link it into sites-enabled, then nginx -t and reload).' % host)
    L.append('# ModSecurity: switch it on for this site on the jt-waf-mgr sites page afterwards (an approved change).')
    if preset == 'synology':
        L.append('# Synology DSM: add this proxy under DSM Control Panel > Security > Trusted proxies, or DSM\'s')
        L.append('# auto block sees every client as the proxy.')
    if preset == 'qnap':
        # 0.5.49: no QNAP at hand -- only what is public: the web interface and the apps (Qfile, QuMagie, Qsync) use the
        # same port; QTS's Network Access Protection blocks the address it sees after failed logins
        L.append('# QNAP QTS: the web interface and the apps (Qfile, QuMagie, Qsync) use this one port. QTS blocks the')
        L.append('# address it sees after failed logins (Network Access Protection): behind a proxy check what your QTS')
        L.append('# version does with X-Forwarded-For, or one person\'s wrong password can lock everyone out.')
    big = body == '0' or (mem_bytes and _bytes(body) > mem_bytes // 4)
    if big:
        L.append('# NOTE: with ModSecurity on, nginx reads a whole upload into memory first; keep client_max_body_size')
        L.append('# well below this host\'s memory (the system check warns), or leave ModSecurity off for this site.')
    if websocket:
        L += ['map $http_upgrade $%s {' % var, '    default upgrade;', "    ''      close;", '}', '']
    # 0.5.49: on another port than 443 the back end must see the port too: DSM (and many apps) build their redirects
    # from Host, and without it the browser is sent to port 443 (Surveillance Station opened another site there)
    host_hdr = '$host' if port == 443 else '$host:$server_port'
    label = re.sub(r'[^a-z0-9]', '_', host.split('.')[0])
    mp_var, mp_loc = label + '_mp_ct', '@' + label + '_mp_fix'
    loop_port = port + 10000 if port + 10000 <= 65535 else port - 10000
    if photos_fix:
        L += ['# Synology Photos for iOS sends "multipart/form-data; charset=utf-8; boundary=...". ModSecurity accepts',
              '# only one ";" before the boundary and would not inspect such a body at all (from outside the',
              '# protection set refuses it). Exactly this shape goes, with the Content-Type in standard form, to the',
              '# loopback server at the end, which inspects it in full like any other request.',
              'map $content_type $%s {' % mp_var,
              '    "~*^multipart/form-data;[ \\t]*charset=[A-Za-z0-9_-]{1,20};[ \\t]*(boundary=[A-Za-z0-9\'()+_,./:=?-]{1,70})$"'
              ' "multipart/form-data; $1";',
              '    default "";', '}', '']
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
          '    client_max_body_size %s;' % body, '']
    if photos_fix:
        L += ['    error_page 419 = %s;   # see the map $%s above' % (mp_loc, mp_var),
              '    if ($%s) { return 419; }' % mp_var, '',
              '    location %s {' % mp_loc,
              '        modsecurity off;               # inspected by the loopback server below',
              '        proxy_pass http://127.0.0.1:%d;' % loop_port,
              '        proxy_set_header Host %s;' % host_hdr,
              '        proxy_set_header Content-Type $%s;' % mp_var,
              '        proxy_set_header X-Jt-Client $remote_addr;    # the only source address the loopback server trusts',
              '        proxy_set_header X-Forwarded-For "";', '        proxy_set_header X-Real-IP "";',
              '        proxy_http_version 1.1;', '        proxy_request_buffering off;', '        proxy_buffering off;',
              '        proxy_read_timeout 3600s;', '        proxy_send_timeout 3600s;', '    }', '']
    L += [
          '    location / {', '        proxy_pass %s://%s;' % (scheme, backend), '        proxy_http_version 1.1;']
    if scheme == 'https':
        L.append('        proxy_ssl_verify off;          # a private back end with its own certificate')
        L.append('        proxy_ssl_server_name on;')
    if port != 443:
        L.append('        # the port browsers use: if a port forward or a stream in front changes it, write that port here')
    L += ['        proxy_set_header Host %s;' % host_hdr, '        proxy_set_header X-Real-IP $remote_addr;',
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
    if photos_fix:
        L += ['', '# loopback only: the Synology Photos iOS uploads from the server above, inspected by ModSecurity',
              '# (no allow/deny: after real_ip the address is the client\'s; listening on 127.0.0.1 is the limit)',
              'server {', '    listen 127.0.0.1:%d;' % loop_port, '    server_name %s;' % host,
              '    modsecurity on;', '    set_real_ip_from 127.0.0.1;', '    real_ip_header X-Jt-Client;',
              '    client_max_body_size %s;' % body, '    server_tokens off;', '',
              '    location / {', '        proxy_pass %s://%s;' % (scheme, backend)] + \
             (['        proxy_ssl_verify off;', '        proxy_ssl_server_name on;'] if scheme == 'https' else []) + \
             ['        proxy_set_header Host %s;' % ('$host' if port == 443 else '$host:%d' % port),
              '        proxy_set_header X-Real-IP $remote_addr;',
              '        proxy_set_header X-Forwarded-For $remote_addr;', '        proxy_set_header X-Forwarded-Proto https;',
              '        proxy_http_version 1.1;', '        proxy_request_buffering off;', '        proxy_buffering off;',
              '        proxy_read_timeout 3600s;', '        proxy_send_timeout 3600s;', '    }', '',
              '    access_log off;                    # logged by the public server',
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
