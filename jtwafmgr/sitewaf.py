"""Switching ModSecurity on or off for one site from the web interface (a change: checked, approved, applied by the
root program). The only edit ever made to a server block is one marked line right after its `server {` line:

    include /etc/nginx/snippets/modsec-on.conf;  # jt-waf-mgr: WAF on (change #12)

"Off" removes exactly that line again -- a WAF that was switched on any other way is left alone (edit it by hand).
The snippet is the one the other sites already include to switch ModSecurity on; when there is none, a managed one
(modsecurity on, plus the rules file when the http block does not load one) next to the managed rule files.

The page blocked visitors see (kind "page") works the same way, for one site or all of them at once:

    include /etc/nginx/modsec/jt-waf-mgr/blocked-page.conf;  # jt-waf-mgr: blocked page (change #13)

The snippet (error_page 403 plus an internal location with server-side includes for the request id) and the page
itself are managed files next to the rule files, written by the root program from this package.

The same plan is computed twice: by the web service when the change is proposed, and again by the root program
before it writes, which applies only when both agree and the files still have the checked contents.
"""
import collections
import hashlib
import os
import re

from .nginxconf import NginxConfig

MARK = '# jt-waf-mgr: WAF on'
MANAGED_SNIPPET = 'site-on.conf'
MODES = ('enable', 'disable')
SERVER_LINE = re.compile(r'^(\s*)server\s*\{\s*(?:#.*)?$')
HOST_RE = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)*$')
SNIPPET_LINE = re.compile(r'^\s*(?:#.*|modsecurity\s+on\s*;|modsecurity_rules_file\s+\S+\s*;)?\s*$')
MAX_BLOCKS = 10
SNIPPET_PATH = re.compile(r'^/[A-Za-z0-9._/-]{1,300}$')
MARK_LINE = re.compile(r'^\s*include\s+(/[A-Za-z0-9._/-]{1,300});\s+' + re.escape(MARK) + r' \(change #\d+\)\s*$')

KINDS = ('waf', 'page')
ALL = '*'                                   # every site (the blocked page only)
PAGE_MARK = '# jt-waf-mgr: blocked page'
PAGE_MARK_LINE = re.compile(r'^\s*include\s+(/[A-Za-z0-9._/-]{1,300});\s+' + re.escape(PAGE_MARK) + r' \(change #\d+\)\s*$')
PAGE_SNIPPET = 'blocked-page.conf'
PAGE_DIR = 'blocked-page'
PAGE_FILE = 'jt-blocked.html'
PAGE_URI = '/' + PAGE_FILE
MAX_PAGE_BLOCKS = 300
MARKS = {'waf': MARK, 'page': PAGE_MARK}
MARK_LINES = {'waf': MARK_LINE, 'page': PAGE_MARK_LINE}


class PlanError(Exception):
    def __init__(self, code, **details):
        super().__init__(code)
        self.code, self.details = code, details


def _sha(path):
    with open(path, 'rb') as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def split_lines(text):
    """Lines as nginx and our parser count them: only \\n ends a line (str.splitlines also breaks at \\x0c, \\x85,
    U+2028 ... and would point at another server block)."""
    parts = text.split('\n')
    out = [x + '\n' for x in parts[:-1]]
    if parts[-1]:
        out.append(parts[-1])
    return out


def marked_at(lines, idx, kind='waf'):
    """Index of this kind's marked line among the marked lines right after the `server {` line at idx, else None."""
    j = idx + 1
    while j < len(lines):
        line = lines[j].rstrip('\n')
        k = next((k for k, rx in MARK_LINES.items() if rx.match(line)), None)
        if k is None:
            return None
        if k == kind:
            return j
        j += 1
    return None


def _lines(path):
    with open(path, encoding='utf-8', newline='') as fh:
        text = fh.read()
    if re.search(r'\r(?!\n)', text):
        # a lone carriage return: our parser (universal newlines) and this file's lines would count differently
        raise PlanError('unusual_line_endings', file=path)
    return split_lines(text)


def _snippet_ok(path):
    """A file that only switches ModSecurity on (and may name its rules file): safe to include in a server block."""
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > 4096:
            return False
        lines = _lines(path)
    except (OSError, UnicodeDecodeError, PlanError):
        return False
    return all(SNIPPET_LINE.match(x) for x in lines) and any(re.match(r'^\s*modsecurity\s+on\s*;', x) for x in lines)


def _servers(conf):
    h = conf.http()
    return [d for d in (h.children if h else []) if d.name == 'server' and d.children is not None]


def _flag(children):
    v = None
    for d in children:
        if d.name == 'modsecurity' and d.args:
            v = d.args[0] == 'on'
    return v


def _names(s):
    return [a.lower() for d in s.children if d.name == 'server_name' for a in d.args]


def _redirect_only(children):
    """Only a redirect (return 301/302/307/308 at the server or in its one location): nothing to protect."""
    def ret(ch):
        return any(d.name == 'return' and d.args and d.args[0] in ('301', '302', '307', '308') for d in ch)
    locs = [d for d in children if d.name == 'location' and d.children is not None]
    if ret(children):
        return True
    serving = [loc for loc in locs if not (loc.args and loc.args[-1].startswith('/.well-known'))]
    return bool(serving) and all(ret(loc.children) for loc in serving)


def snippet(cfg, conf):
    """(path, text to write or None): the snippet the sites with ModSecurity already include, else the managed one."""
    seen = collections.Counter()
    for s in _servers(conf):
        if _flag(s.children):
            for d in s.children:
                if d.name == 'include' and d.args and _snippet_ok(d.args[0]):
                    seen[d.args[0]] += 1
    if seen:
        return seen.most_common(1)[0][0], None
    h = conf.http()
    rules = any(d.name == 'modsecurity_rules_file' for d in (h.children if h else []))
    text = '# Generated by jt-waf-mgr: ModSecurity for a site, included in its server block\nmodsecurity on;\n'
    if not rules:
        files = [d.args[0] for s in _servers(conf) for d in s.children if d.name == 'modsecurity_rules_file' and d.args]
        if not files:
            raise PlanError('no_rules_file')
        text += 'modsecurity_rules_file %s;\n' % collections.Counter(files).most_common(1)[0][0]
    return os.path.join(cfg['managed']['dir'], MANAGED_SNIPPET), text


def plan(cfg, host, mode, conf=None, kind='waf'):
    """{'host', 'mode', 'kind', 'blocks': [{file, line, names, nth, sha256}], 'snippet': path, 'snippet_text': text or
    None} (and for the page: 'skipped', the blocks that keep their own 403 page)."""
    host = (host or '').lower().strip()
    if mode not in MODES or kind not in KINDS or not (HOST_RE.match(host) or (kind == 'page' and host == ALL)):
        raise PlanError('invalid_request')
    conf = conf or NginxConfig(cfg['paths']['nginx_conf'])
    if conf.errors:
        raise PlanError('nginx_config_unreadable', errors=conf.errors[:3])
    if kind == 'page':
        return _page_plan(cfg, host, mode, conf)
    path, text = snippet(cfg, conf) if mode == 'enable' else (None, None)
    if path is not None and not SNIPPET_PATH.match(path):
        raise PlanError('snippet_path', path=path)
    if path is not None and text is not None and os.path.exists(path):
        try:
            with open(path, encoding='utf-8') as fh:
                if fh.read() != text:
                    raise PlanError('managed_snippet_changed', path=path)     # edited by hand: not ours to include
        except (OSError, UnicodeDecodeError):
            raise PlanError('managed_snippet_changed', path=path)
    blocks = []
    nth = collections.Counter()
    for s in _servers(conf):
        k = os.path.realpath(s.file)
        nth[k] += 1
        if host not in _names(s):
            continue
        try:
            lines = _lines(s.file)
        except (OSError, UnicodeDecodeError):
            raise PlanError('file_unreadable', file=s.file)
        idx = s.line - 1
        if not 0 <= idx < len(lines) or not SERVER_LINE.match(lines[idx].rstrip('\n')):
            raise PlanError('server_line_shape', file=s.file, line=s.line)
        j = marked_at(lines, idx, 'waf')
        mm = MARK_LINE.match(lines[j].rstrip('\n')) if j is not None else None
        marked = bool(mm)
        if marked and mode == 'disable' and not _snippet_ok(mm.group(1)):
            # whatever it includes (the managed snippet too) must only switch ModSecurity on: anything else is not ours
            raise PlanError('marked_line_not_a_waf_switch', file=s.file, line=s.line)
        if mode == 'enable':
            flag = _flag(s.children)
            if flag or _redirect_only(s.children):
                continue                          # on already, or nothing to protect
            if flag is False:
                raise PlanError('switched_off_by_hand', file=s.file, line=s.line)
        elif not marked:
            if _flag(s.children):
                raise PlanError('not_switched_on_here', file=s.file, line=s.line)
            continue
        blocks.append({'file': s.file, 'line': s.line, 'names': _names(s)[:50], 'nth': nth[k], 'sha256': _sha(s.file)})
    if not blocks:
        raise PlanError('nothing_to_do')
    if len(blocks) > MAX_BLOCKS:
        raise PlanError('too_many_blocks')
    return {'host': host, 'mode': mode, 'kind': 'waf', 'blocks': blocks, 'snippet': path, 'snippet_text': text}


# --- the page blocked visitors see -------------------------------------------------------------------------------
def page_html():
    """The page, from this package (the root program writes it from its own installed copy)."""
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'blocked-page.html'), encoding='utf-8') as fh:
        return fh.read()


def page_paths(cfg):
    """(snippet path, directory of the page, page path): managed files next to the rule files."""
    d = cfg['managed']['dir']
    return os.path.join(d, PAGE_SNIPPET), os.path.join(d, PAGE_DIR), os.path.join(d, PAGE_DIR, PAGE_FILE)


def page_snippet_text(cfg):
    _, pdir, _ = page_paths(cfg)
    # allow all: an address on the IP block list (deny in the http block) would be refused the page too and see nginx's
    # own 403; the location is internal, so it is reached only through error_page.
    return ('# Generated by jt-waf-mgr (rewritten by it): the page a visitor sees when nginx answers 403, with the request\n'
            '# id to give the administrator. Switched on and off from the Sites page.\n'
            'error_page 403 %s;\n'
            'location = %s {\n'
            '    internal;\n'
            '    allow all;\n'
            '    root %s;\n'
            '    ssi on;\n'
            '    modsecurity off;\n'
            '    add_header Cache-Control "no-store" always;\n'
            '}\n') % (PAGE_URI, PAGE_URI, pdir)


def _includes(children, path):
    return any(d.name == 'include' and d.args and os.path.realpath(d.args[0]) == os.path.realpath(path) for d in children)


def _own_403(children):
    """The server block already has a 403 page (or our location): ours would clash or change what people see."""
    return any(d.name == 'error_page' and '403' in d.args[:-1] for d in children) or \
        any(d.name == 'location' and d.args[-1:] == [PAGE_URI] for d in children)


def _page_plan(cfg, host, mode, conf):
    path, pdir, _ = page_paths(cfg)
    text = page_snippet_text(cfg) if mode == 'enable' else None
    for x in (path, pdir):
        if not SNIPPET_PATH.match(x):
            raise PlanError('snippet_path', path=x)
    # both files are jt-waf-mgr's own: a newer release brings a newer snippet or page, written by the next "enable"
    # (with nothing else to do, "every site" only refreshes them)
    refresh = mode == 'enable' and page_stale(cfg)
    blocks, skipped = [], []
    nth = collections.Counter()
    for s in _servers(conf):
        k = os.path.realpath(s.file)
        nth[k] += 1
        names = _names(s)
        if host == ALL:
            if not any(HOST_RE.match(n) for n in names):
                continue                          # the catch-all `_` and other non-site blocks
        elif host not in names:
            continue
        try:
            lines = _lines(s.file)
        except (OSError, UnicodeDecodeError):
            raise PlanError('file_unreadable', file=s.file)
        idx = s.line - 1
        if not 0 <= idx < len(lines) or not SERVER_LINE.match(lines[idx].rstrip('\n')):
            raise PlanError('server_line_shape', file=s.file, line=s.line)
        j = marked_at(lines, idx, 'page')
        b = {'file': s.file, 'line': s.line, 'names': names[:50], 'nth': nth[k], 'sha256': _sha(s.file)}
        if mode == 'enable':
            if j is not None or _includes(s.children, path) or _redirect_only(s.children):
                continue                          # has it already, or only redirects
            if _own_403(s.children):
                skipped.append(dict(b, why='own_error_page'))
                continue
            blocks.append(b)
        else:
            if j is None:
                if _includes(s.children, path) and host != ALL:
                    raise PlanError('page_included_by_hand', file=s.file, line=s.line)
                continue
            mm = PAGE_MARK_LINE.match(lines[j].rstrip('\n'))
            if os.path.realpath(mm.group(1)) != os.path.realpath(path):
                raise PlanError('marked_line_not_the_page', file=s.file, line=s.line)
            blocks.append(b)
    if not blocks and not (refresh and host == ALL and _in_use(conf, path)):
        raise PlanError('nothing_to_do', skipped=len(skipped))
    if len(blocks) > MAX_PAGE_BLOCKS:
        raise PlanError('too_many_blocks')
    return {'host': host, 'mode': mode, 'kind': 'page', 'blocks': blocks, 'skipped': skipped[:100], 'refresh': refresh,
            'snippet': path if mode == 'enable' else None, 'snippet_text': text}


def _read(path):
    try:
        with open(path, 'rb') as fh:
            return fh.read()
    except OSError:
        return None


def page_stale(cfg):
    """The snippet or the page on disk is not this release's (or is missing)."""
    snip, _, page = page_paths(cfg)
    return _read(snip) != page_snippet_text(cfg).encode('utf-8') or _read(page) != page_html().encode('utf-8')


def _in_use(conf, path):
    return any(_includes(s.children, path) for s in _servers(conf))


def edit(text, lines_1based, mode, snippet_path, change_id, kind='waf'):
    """The file's new text: the marked include right after each `server {` line (enable), or that line removed."""
    lines = split_lines(text)
    if mode == 'enable' and not SNIPPET_PATH.match(snippet_path or ''):
        raise PlanError('snippet_path')
    for ln in sorted(set(lines_1based), reverse=True):
        idx = ln - 1
        m = SERVER_LINE.match(lines[idx].rstrip('\n'))
        if not m:
            raise PlanError('server_line_shape', line=ln)
        j = marked_at(lines, idx, kind)
        if mode == 'enable':
            if j is not None:
                raise PlanError('already_marked', line=ln)
            if not lines[idx].endswith('\n'):
                lines[idx] += '\n'
            lines.insert(idx + 1, '%s  include %s;  %s (change #%d)\n' % (m.group(1), snippet_path, MARKS[kind], change_id))
        else:
            if j is None:
                raise PlanError('mark_missing', line=ln)
            del lines[j]
    return ''.join(lines)


def preview(p, change_id=0):
    """What the change does, as text for the change page."""
    out = []
    mark = MARKS[p.get('kind') or 'waf']
    for b in p['blocks']:
        if p['mode'] == 'enable':
            out.append('%s:%d (%s)\n  + include %s;  %s (change #%d)' % (b['file'], b['line'], ' '.join(b['names'][:5]),
                                                                       p['snippet'], mark, change_id))
        else:
            out.append('%s:%d (%s)\n  - include ...;  %s' % (b['file'], b['line'], ' '.join(b['names'][:5]), mark))
    for b in p.get('skipped') or []:
        out.append('%s:%d (%s)\n  = has its own 403 page: left as it is' % (b['file'], b['line'], ' '.join(b['names'][:5])))
    if p.get('snippet_text'):
        out.append('%s:\n%s' % (p['snippet'], p['snippet_text']))
    return '\n\n'.join(out)


def waf_states(cfg):
    """{(file, n-th server block in it): (names, ModSecurity on?, includes the blocked page?)} for every server block,
    to compare before and after a write (the n-th block of a file stays the n-th one when a line is added or removed)."""
    conf = NginxConfig(cfg['paths']['nginx_conf'])
    page = page_paths(cfg)[0]
    nth, out = collections.Counter(), {}
    for x in _servers(conf):
        k = os.path.realpath(x.file)
        nth[k] += 1
        out[(k, nth[k])] = (tuple(_names(x)), bool(_flag(x.children)), _includes(x.children, page))
    return out, conf.errors
