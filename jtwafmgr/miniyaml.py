"""A small YAML reader for the CrowdSec Hub's rule files (no third-party package on the target hosts).

It reads the subset those files use -- block mappings and sequences by indentation, "- key: value" items, plain,
single- and double-quoted scalars, flow sequences of scalars ("[a, b]"), literal and folded block scalars ("|", ">"),
comments -- and refuses everything else (anchors, aliases, tags, flow mappings, several documents, tabs), so a file
it cannot read for certain is reported, never guessed. Scalars stay strings except whole integers and true/false/null.
"""
import re


class YamlError(ValueError):
    def __init__(self, line, why):
        super().__init__('line %d: %s' % (line, why))
        self.line, self.why = line, why


MAX_BYTES = 256 * 1024
MAX_LINE = 4096                     # the hub's longest line today is about 260 characters
MAX_DEPTH = 32
_INT = re.compile(r'^-?(?:0|[1-9][0-9]{0,17})$')
# no stretch of spaces two parts of the pattern could share (linear time on any line)
_KEY = re.compile(r'^(?P<key>[A-Za-z0-9_][A-Za-z0-9_.\-]*(?: [A-Za-z0-9_.\-]+)*|"[^"]*"|\'[^\']*\') ?:(?: +(?P<rest>.*))?$')


def _strip_comment(s):
    """A '#' starts a comment outside quotes when it begins the text or follows a space."""
    out, q, i = [], None, 0
    while i < len(s):
        c = s[i]
        if q:
            out.append(c)
            if c == q:
                if q == "'" and i + 1 < len(s) and s[i + 1] == "'":
                    out.append("'")
                    i += 1
                else:
                    q = None
            elif c == '\\' and q == '"' and i + 1 < len(s):
                out.append(s[i + 1])
                i += 1
        elif c in '"\'' and (not out or out[-1] in ' \t[,:-'):
            q = c
            out.append(c)
        elif c == '#' and (not out or out[-1] in ' \t'):
            break
        else:
            out.append(c)
        i += 1
    return ''.join(out).rstrip()


def _scalar(s, line):
    s = s.strip()
    if not s:
        return None
    if s[0] in '&*!':
        raise YamlError(line, 'anchors, aliases and tags are not supported')
    if s[0] == '{':
        # a flow mapping of scalars: {type: contains, value: 'x'}
        if not s.endswith('}'):
            raise YamlError(line, 'unclosed flow mapping')
        out = {}
        for item in _split_flow(s[1:-1], line):
            if not item.strip():
                continue
            m = _KEY.match(item.strip())
            if not m:
                raise YamlError(line, 'expected "key: value" in a flow mapping')
            key = m.group('key')
            key = _scalar(key, line) if key[0] in '"\'' else key
            if key in out:
                raise YamlError(line, 'duplicate key %r' % key)
            out[key] = _scalar(m.group('rest') or '', line)
        return out
    if s[0] == '[':
        if not s.endswith(']'):
            raise YamlError(line, 'unclosed flow sequence')
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_scalar(x, line) for x in _split_flow(inner, line)]
    if s[0] == "'":
        if len(s) < 2 or not s.endswith("'"):
            raise YamlError(line, 'unclosed quote')
        body = s[1:-1]
        if re.search(r"(?<!')'(?!')", body.replace("''", '')):
            raise YamlError(line, 'stray quote')
        return body.replace("''", "'")
    if s[0] == '"':
        if len(s) < 2 or not s.endswith('"'):
            raise YamlError(line, 'unclosed quote')
        if re.search(r'(?<!\\)(?:\\\\)*"', s[1:-1]):
            raise YamlError(line, 'stray quote')
        return _unescape(s[1:-1], line)
    # a plain scalar that YAML could read differently (a ": " or " #" inside, a leading sign or indicator):
    # refused rather than guessed
    if re.search(r': | #|\t', s) or s[0] in '+%@`|>?:,' or s.endswith(':'):
        raise YamlError(line, 'ambiguous plain value; quote it')
    if _INT.match(s):
        return int(s)
    low = s.lower()
    if low in ('true', 'false'):
        return low == 'true'
    if low in ('null', '~'):
        return None
    return s


def _split_flow(inner, line):
    """The items of a flow collection, split at the commas outside quotes; no nesting."""
    items, cur, q = [], [], None
    for c in inner:
        if q:
            cur.append(c)
            if c == q:
                q = None
        elif c in '"\'':
            q = c
            cur.append(c)
        elif c in '[]{}':
            raise YamlError(line, 'nested flow collections are not supported')
        elif c == ',':
            items.append(''.join(cur))
            cur = []
        else:
            cur.append(c)
    if q:
        raise YamlError(line, 'unclosed quote')
    items.append(''.join(cur))
    return items


_ESC = {'n': '\n', 't': '\t', 'r': '\r', '0': '\0', '\\': '\\', '"': '"', '/': '/', ' ': ' ', 'a': '\a', 'b': '\b',
        'e': '\x1b', 'f': '\f', 'v': '\v'}


def _unescape(s, line):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c != '\\':
            out.append(c)
            i += 1
            continue
        if i + 1 >= len(s):
            raise YamlError(line, 'bad escape')
        e = s[i + 1]
        if e in _ESC:
            out.append(_ESC[e])
            i += 2
        elif e in 'xuU':
            n = {'x': 2, 'u': 4, 'U': 8}[e]
            h = s[i + 2:i + 2 + n]
            if len(h) != n or not re.fullmatch(r'[0-9A-Fa-f]+', h):
                raise YamlError(line, 'bad escape')
            out.append(chr(int(h, 16)))
            i += 2 + n
        else:
            raise YamlError(line, 'bad escape')
    return ''.join(out)


def loads(text):
    """The document as dicts, lists and scalars. Raises YamlError."""
    if isinstance(text, bytes):
        if len(text) > MAX_BYTES:
            raise YamlError(0, 'file too large')
        try:
            text = text.decode('utf-8')
        except UnicodeDecodeError:
            raise YamlError(0, 'not UTF-8')
    if len(text) > MAX_BYTES:
        raise YamlError(0, 'file too large')
    raw = text.split('\n')
    lines = []          # (number, indent, content) of the lines that carry something
    for n, ln in enumerate(raw, 1):
        if len(ln) > MAX_LINE:
            raise YamlError(n, 'line too long')
        if '\t' in ln[:len(ln) - len(ln.lstrip())]:
            raise YamlError(n, 'tab in indentation')
        st = ln.rstrip('\r')
        if st.strip() in ('---', '...') and not lines:
            continue
        if st.strip() in ('---', '...'):
            raise YamlError(n, 'several documents are not supported')
        lines.append((n, len(st) - len(st.lstrip(' ')), st))
    p = _Parser(lines)
    p.skip_blank()
    if p.i >= len(p.lines):
        return None
    v = p.block(p.indent(), 0)
    p.skip_blank()
    if p.i < len(p.lines):
        raise YamlError(p.lines[p.i][0], 'unexpected indentation')
    return v


class _Parser:
    def __init__(self, lines):
        self.lines, self.i = lines, 0

    def blank(self, k):
        s = self.lines[k][2].strip()
        return not s or s.startswith('#')

    def skip_blank(self):
        while self.i < len(self.lines) and self.blank(self.i):
            self.i += 1

    def indent(self):
        return self.lines[self.i][1]

    def block(self, ind, depth):
        if depth > MAX_DEPTH:
            raise YamlError(self.lines[self.i][0], 'nested too deep')
        content = self.lines[self.i][2].strip()
        if content == '-' or content.startswith('- '):
            return self.seq(ind, depth)
        return self.mapping(ind, depth)

    def seq(self, ind, depth):
        out = []
        while True:
            self.skip_blank()
            if self.i >= len(self.lines):
                return out
            n, lind, ln = self.lines[self.i]
            body = ln.strip()
            if lind < ind:
                return out
            if lind > ind:
                raise YamlError(n, 'unexpected indentation')
            if not (body == '-' or body.startswith('- ')):
                return out
            rest = _strip_comment(body[1:].lstrip(' '))
            if rest == '-' or rest.startswith('- '):
                raise YamlError(n, 'a sequence inside a sequence on one line is not supported')
            self.i += 1
            if not rest:
                self.skip_blank()
                if self.i < len(self.lines) and self.indent() > ind:
                    out.append(self.block(self.indent(), depth + 1))
                else:
                    out.append(None)
                continue
            m = _KEY.match(rest)
            if m and not rest.startswith(('"', "'", '[')) or (m and rest[0] in '"\'' and m.group('key')[0] in '"\''):
                # "- key: value": a mapping whose keys line up with "key"
                sub = ind + (len(body) - len(body[1:].lstrip(' ')))
                self.i -= 1
                self.lines[self.i] = (n, sub, ' ' * sub + rest)
                out.append(self.mapping(sub, depth + 1))
                continue
            out.append(self.value(rest, n, ind, depth))

    def mapping(self, ind, depth):
        out = {}
        while True:
            self.skip_blank()
            if self.i >= len(self.lines):
                return out
            n, lind, ln = self.lines[self.i]
            if lind < ind:
                return out
            if lind > ind:
                raise YamlError(n, 'unexpected indentation')
            body = _strip_comment(ln.strip())
            if body == '-' or body.startswith('- '):
                return out
            m = _KEY.match(body)
            if not m:
                raise YamlError(n, 'expected "key: value"')
            key = m.group('key')
            if key[0] in '"\'':
                key = _scalar(key, n)
            if key in out:
                raise YamlError(n, 'duplicate key %r' % key)
            self.i += 1
            rest = (m.group('rest') or '').strip()
            if rest:
                out[key] = self.value(rest, n, ind, depth)
                continue
            self.skip_blank()
            if self.i < len(self.lines) and (self.indent() > ind or (self.indent() == ind and self.lines[self.i][2].strip().startswith('- '))):
                out[key] = self.block(self.indent(), depth + 1)
            else:
                out[key] = None

    def value(self, rest, n, ind, depth):
        if rest[0] in '|>':
            if not re.fullmatch(r'[|>][-+]?', rest):
                raise YamlError(n, 'unsupported block scalar header')
            return self.block_scalar(rest, ind)
        return _scalar(rest, n)

    def block_scalar(self, head, ind):
        start, body = self.i, []
        while self.i < len(self.lines):
            n, lind, ln = self.lines[self.i]
            if ln.strip() and lind <= ind:
                break
            body.append(ln)
            self.i += 1
        while body and not body[-1].strip():
            body.pop()
            self.i -= 1
        if not body:
            return ''
        pad = min(len(b) - len(b.lstrip(' ')) for b in body if b.strip())
        rows = [b[pad:] if b.strip() else '' for b in body]
        text = '\n'.join(rows) if head[0] == '|' else re.sub(r'(?<!\n)\n(?!\n)', ' ', '\n'.join(rows))
        return text if head.endswith('-') else text + '\n'
