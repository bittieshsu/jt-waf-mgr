"""Switching HTTP/2 or HTTP/3 off for a while, and back on, when nginx itself has a flaw in it (0.4.98).

A flaw in nginx's HTTP/2 or HTTP/3 code happens before ModSecurity sees a request: no rule can refuse it. Until the
fixed nginx is installed, the feature can be switched off -- browsers fall back to HTTP/1.1 (or HTTP/2 for HTTP/3).
The nginx security advisories (nginxsec.py) say when; this module plans the edit and the root program makes it:

    http2 on;                    ->  # jt-waf-mgr: http2 off (change #12): http2 on;
    listen 443 ssl http2;        ->  listen 443 ssl;  # jt-waf-mgr: http2 off (change #12): listen 443 ssl http2;
    http3 on;                    ->  # jt-waf-mgr: http3 off (change #12): http3 on;
    listen 443 quic reuseport;   ->  # jt-waf-mgr: http3 off (change #12): listen 443 quic reuseport;

"On" puts exactly the marked lines back as they were (the original is on the line). Only directives on one line of
their own are edited; anything else stops the plan (edit it by hand). As for the site WAF switch (sitewaf.py), the plan
is computed by the web service and again by the root program, which writes only when both agree and every file still
has the checked contents, then checks that nothing but the planned directives changed, nginx -t, reload, health checks,
and puts everything back on any failure.
"""
import hashlib
import os
import re

from .nginxconf import NginxConfig, walk

FEATURES = ('http2', 'http3')
MODES = ('off', 'on')
MAX_LINES = 400
MARK = '# jt-waf-mgr: %s off (change #%d): '
MARK_RE = re.compile(r'^(\s*)(?:(listen\s[^;#]*;)\s+)?# jt-waf-mgr: (http2|http3) off \(change #([1-9]\d{0,9})\): (.{1,400})$')
ON_LINE = {'http2': re.compile(r'^(\s*)http2\s+on\s*;\s*(?:#.*)?$', re.I), 'http3': re.compile(r'^(\s*)http3\s+on\s*;\s*(?:#.*)?$', re.I)}
LISTEN_LINE = re.compile(r'^(\s*)listen\s+([^;#{}]+);\s*(?:#.*)?$')
# the original kept on a marked line: one of the directives this switches, on its own, maybe with its comment
SAFE_ORIGINAL = re.compile(r'^(?:http2\s+on|http3\s+on|listen\s+[^;#{}\'"]+)\s*;\s*(?:#[^\n]*)?$', re.I)


class PlanError(Exception):
    def __init__(self, code, **details):
        super().__init__(code)
        self.code = code
        self.details = details


def _sha(path):
    with open(path, 'rb') as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _lines(path):
    with open(path, encoding='utf-8') as fh:
        return fh.read().splitlines(True)


def _listen_has(args, feature):
    a = [x.lower() for x in args]
    return 'http2' in a if feature == 'http2' else 'quic' in a


def _drop_token(directive, token):
    """'listen 443 ssl http2;  # note' -> 'listen 443 ssl;' (the parameters without one of them)."""
    m = re.match(r'^\s*listen\s+([^;#{}]+);', directive)
    parts = [p for p in m.group(1).split() if p.lower() != token]
    return 'listen %s;' % ' '.join(parts)


def _on(args):
    return [a.lower() for a in args[:1]] == ['on']


def _quic_only_servers(conf):
    """Server blocks whose every listen is a QUIC one: switching HTTP/3 off would leave them without a listen (nginx
    would then listen on port 80 for them)."""
    out = []
    for d, _ in walk(conf.tree):
        if d.name != 'server' or d.children is None:
            continue
        ls = [c for c in d.children if c.name == 'listen']
        if ls and all(_listen_has([str(a) for a in c.args or []], 'http3') for c in ls):
            out.append((d.file, d.line))
    return out


def plan(cfg, feature, mode, conf=None, from_changes=None):
    """{'feature', 'mode', 'edits': [{'file', 'line', 'sha256', 'old', 'new'}]} -- lines are 1-based; 'old' is the
    line as it is (no line ending), 'new' what it becomes. A file included several times is edited once.
    "on" puts back only lines marked by the given changes (the "off" changes this system applied), when given."""
    if feature not in FEATURES or mode not in MODES:
        raise PlanError('invalid_request')
    conf = conf or NginxConfig(cfg['paths']['nginx_conf'])
    if conf.errors:
        raise PlanError('nginx_config_unreadable', errors=conf.errors[:3])
    edits = []
    cache = {}

    def line_of(path, n):
        if path not in cache:
            try:
                cache[path] = _lines(path)
            except (OSError, UnicodeDecodeError):
                raise PlanError('file_unreadable', file=path)
        ls = cache[path]
        if not 1 <= n <= len(ls):
            raise PlanError('line_shape', file=path, line=n)
        return ls[n - 1].rstrip('\r\n')

    seen = set()
    if mode == 'off':
        if feature == 'http3':
            only = _quic_only_servers(conf)
            if only:
                raise PlanError('quic_only_server', file=only[0][0], line=only[0][1])
        for d, _ in walk(conf.tree):
            args = [str(a) for a in d.args or []]
            if not (d.name == feature and _on(args) or d.name == 'listen' and _listen_has(args, feature)):
                continue
            key = (os.path.realpath(d.file), d.line)
            if key in seen:
                continue                # the same file included again (a shared snippet): one edit
            seen.add(key)
            old = line_of(d.file, d.line)
            original = old.strip()      # kept whole on the marked line (with its comment), put back as it was
            if len(original) > 400:
                raise PlanError('line_shape', file=d.file, line=d.line)
            if d.name == feature:
                m = ON_LINE[feature].match(old)
                if not m:
                    raise PlanError('line_shape', file=d.file, line=d.line)
                new = m.group(1) + (MARK % (feature, 0)) + original
            else:
                m = LISTEN_LINE.match(old)
                if not m or not _listen_has(m.group(2).split(), feature):
                    raise PlanError('line_shape', file=d.file, line=d.line)
                if feature == 'http2':
                    new = m.group(1) + _drop_token(original, 'http2') + '  ' + (MARK % (feature, 0)) + original
                else:       # a QUIC listener without "quic" would be a second TCP listener: the whole line goes
                    new = m.group(1) + (MARK % (feature, 0)) + original
            if not SAFE_ORIGINAL.match(original):
                raise PlanError('line_shape', file=d.file, line=d.line)
            edits.append({'file': d.file, 'line': d.line, 'old': old, 'new': new})
    else:
        allowed = None if from_changes is None else {int(x) for x in from_changes}
        for path in sorted(conf.files):
            if os.path.realpath(path) in seen:
                continue
            seen.add(os.path.realpath(path))
            try:
                ls = cache.setdefault(path, _lines(path))
            except (OSError, UnicodeDecodeError):
                raise PlanError('file_unreadable', file=path)
            for i, raw in enumerate(ls):
                old = raw.rstrip('\r\n')
                m = MARK_RE.match(old)
                if not m or m.group(3) != feature:
                    continue
                if allowed is not None and int(m.group(4)) not in allowed:
                    continue            # a comment someone wrote in that shape, or a change not applied: not ours
                original = m.group(5).strip()
                if not SAFE_ORIGINAL.match(original):
                    raise PlanError('marked_line_shape', file=path, line=i + 1)
                if m.group(2) and _drop_token(original, 'http2') != m.group(2).strip():
                    # the listen line was edited by hand since: put back by hand
                    raise PlanError('marked_line_changed', file=path, line=i + 1)
                edits.append({'file': path, 'line': i + 1, 'old': old, 'new': m.group(1) + original})
    if not edits:
        raise PlanError('nothing_to_do')
    if len(edits) > MAX_LINES:
        raise PlanError('too_many_lines')
    shas = {}
    for e in edits:
        if e['file'] not in shas:
            shas[e['file']] = _sha(e['file'])
        e['sha256'] = shas[e['file']]
    return {'feature': feature, 'mode': mode, 'edits': edits}


def with_change(p, change_id):
    """The plan's new lines with the change number in their mark."""
    out = []
    for e in p['edits']:
        new = e['new'].replace(MARK % (p['feature'], 0), MARK % (p['feature'], int(change_id))) if p['mode'] == 'off' else e['new']
        out.append(dict(e, new=new))
    return out


def edit(text, edits):
    """The file's new text: each planned line (1-based) replaced, only when it is still exactly the planned old line
    (its line ending kept)."""
    lines = text.splitlines(True)
    for e in edits:
        i = e['line'] - 1
        if not 0 <= i < len(lines) or lines[i].rstrip('\r\n') != e['old']:
            raise PlanError('line_changed', line=e['line'])
        body = lines[i].rstrip('\r\n')
        lines[i] = e['new'] + lines[i][len(body):]
    return ''.join(lines)


def preview(p, change_id=0):
    out = []
    for e in with_change(p, change_id):
        out.append('%s:%d\n  - %s\n  + %s' % (e['file'], e['line'], e['old'].strip(), e['new'].strip()))
    return '\n\n'.join(out)


def signature(cfg, feature):
    """Every directive of the configuration as (file, name, args), with the feature itself taken out (its "on"
    directives dropped; "http2" taken out of listen parameters, a QUIC listen dropped), and how many directives switch
    the feature on: the root program compares before and after a write -- nothing else may differ."""
    conf = NginxConfig(cfg['paths']['nginx_conf'])
    sig, lines = [], set()
    for d, ctx in walk(conf.tree):
        args = [str(a) for a in d.args or []]
        if d.name == feature and _on(args):
            lines.add((os.path.realpath(d.file), d.line))       # once per line, however often its file is included
            continue
        if d.name == 'listen' and _listen_has(args, feature):
            lines.add((os.path.realpath(d.file), d.line))
            if feature == 'http3':
                continue
            args = [a for a in args if a.lower() != 'http2']
        sig.append((os.path.realpath(d.file), ctx, d.name, tuple(args)))
    return sig, len(lines), conf.errors


def state(cfg, conf=None, from_changes=None):
    """{'http2': {'on': n lines, 'off_by_us': n marked lines, 'change_ids'}, 'http3': {...}}; marked lines count only
    for the given changes (the "off" changes this system applied), when given."""
    conf = conf or NginxConfig(cfg['paths']['nginx_conf'])
    out = {f: {'on': 0, 'off_by_us': 0, 'change_ids': []} for f in FEATURES}
    seen = {f: set() for f in FEATURES}
    for d, _ in walk(conf.tree):
        args = [str(a).lower() for a in d.args or []]
        for f in FEATURES:
            if d.name == f and _on(args) or d.name == 'listen' and _listen_has(args, f):
                seen[f].add((os.path.realpath(d.file), d.line))
    for f in FEATURES:
        out[f]['on'] = len(seen[f])
    allowed = None if from_changes is None else {int(x) for x in from_changes}
    for path in {os.path.realpath(p) for p in conf.files}:
        try:
            for raw in _lines(path):
                m = MARK_RE.match(raw.rstrip('\r\n'))
                if m and (allowed is None or int(m.group(4)) in allowed):
                    out[m.group(3)]['off_by_us'] += 1
                    if int(m.group(4)) not in out[m.group(3)]['change_ids']:
                        out[m.group(3)]['change_ids'].append(int(m.group(4)))
        except (OSError, UnicodeDecodeError):
            continue
    return out
