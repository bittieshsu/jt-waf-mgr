"""CrowdSec virtual patching rules (the CrowdSec Hub, github.com/crowdsecurity/hub, MIT licence), converted on this
host into ModSecurity rules.

jt-waf-mgr-hub.service (daily timer, or "sync now" / an upload on the page) takes the hub's `appsec-rules/` and the
`LICENSE` of one commit (about 0.2 MB) -- downloaded, or from an archive an administrator uploaded -- reads each rule with the small
YAML reader (miniyaml) and converts it only when every condition keeps its exact meaning; anything else is listed as
"not supported yet" with the reason (a rule that kept only part of its conditions could refuse ordinary visitors).
The web service never reaches the internet and never unpacks an upload: it reads the index this job writes.

Phase 1: sync, upload, convert, list. Phase 2 (0.4.90): the hub's own tests (.appsec-tests) become sandbox requests, and a
converted rule is proposed as a change (rulegen kind 'crowdsec', changes.Workflow._hub_spec). Phase 3: the threat
intelligence proposes the hub's rule for a CVE (intel.propose_hub_patches).
"""
import hashlib
import io
import json
import os
import re
import tarfile
import time
import urllib.parse
import urllib.request
import zipfile

from . import miniyaml, util

REPO = 'crowdsecurity/hub'
API = 'https://api.github.com/repos/%s' % REPO
RAW = 'https://raw.githubusercontent.com/%s/%%s/%%s' % REPO
INDEX = 'index.json'
INDEX_FORMAT = 4                # 2: with the hub's own tests (0.4.90); 3: requests to let through, more templates (0.4.92);
                                # 4: the path also seen whole at an encoded "?" (0.4.93)
REQUEST = 'sync.request'
UPLOAD_DIR = 'upload'
MAX_FILE = 256 * 1024
MAX_FILES = 2000
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_UNPACKED = 200 * 1024 * 1024
MAX_ALTERNATIVES = 16          # "or" branches a rule may expand to (each is one ModSecurity rule)
MAX_CONDITIONS = 8             # conditions in one chain (the hub uses up to 4)
MAX_TEXT = 32 * 1024           # converted text of one rule file
MAX_INDEX = 16 * 1024 * 1024   # the index the web service reads
MAX_MEMBERS = 20000            # entries in an uploaded archive, taken or not
SAFE_TEXT = re.compile(r"[^A-Za-z0-9 _./:()-]")
# every line of a converted rule has one of these shapes (a guard against anything slipping through)
LINE_SHAPE = re.compile(r'^(?: {4})*SecRule [^\s"]+ "(?:[^"\\\n]|\\.)*" \\$|^(?: {4})*    "[^"\n]*"$')

# the same meaning as CrowdSec's own translation of these rules into SecLang
ZONES = {'ARGS': 'ARGS_GET', 'ARGS_NAMES': 'ARGS_GET_NAMES', 'BODY_ARGS': 'ARGS_POST', 'BODY_ARGS_NAMES': 'ARGS_POST_NAMES',
         'COOKIES': 'REQUEST_COOKIES', 'COOKIES_NAMES': 'REQUEST_COOKIES_NAMES', 'FILES': 'FILES', 'FILES_NAMES': 'FILES_NAMES',
         'FILENAMES': 'FILES', 'FILES_TOTAL_SIZE': 'FILES_COMBINED_SIZE', 'HEADERS': 'REQUEST_HEADERS',
         'HEADERS_NAMES': 'REQUEST_HEADERS_NAMES', 'METHOD': 'REQUEST_METHOD', 'PROTOCOL': 'REQUEST_PROTOCOL',
         'URI': 'REQUEST_FILENAME', 'URI_FULL': 'REQUEST_URI_RAW', 'RAW_BODY': 'REQUEST_BODY'}
# libmodsecurity 3.0 (Debian 12's 3.0.9: tested) puts the arguments of a JSON body ("json.a.b", the names CrowdSec uses too)
# in ARGS and ARGS_NAMES but not in ARGS_POST: a body zone also looks at the JSON arguments there. Only names that start
# with "json." -- a query parameter would have to be named so itself to be taken as well.
JSON_TOO = {'BODY_ARGS': 'ARGS:/^json\\./', 'BODY_ARGS_NAMES': 'ARGS_NAMES:/^json\\./'}
TRANSFORMS = {'lowercase': 't:lowercase', 'uppercase': 't:uppercase', 'b64decode': 't:base64Decode', 'hexdecode': 't:hexDecode',
              'length': 't:length', 'urldecode': 't:urlDecode', 'trim': 't:trim', 'normalize_path': 't:normalizePath',
              'normalizepath': 't:normalizePath', 'htmlentitydecode': 't:htmlEntityDecode', 'html_entity_decode': 't:htmlEntityDecode'}
MATCH = {'regex': '@rx', 'equals': '@streq', 'startsWith': '@beginsWith', 'endsWith': '@endsWith', 'contains': '@contains',
         'libinjectionSQL': '@detectSQLi', 'libinjectionXSS': '@detectXSS', 'gt': '@gt', 'lt': '@lt', 'gte': '@ge',
         'lte': '@le', 'eq': '@eq'}
NUMERIC = ('gt', 'lt', 'gte', 'lte', 'eq')
NO_VALUE = ('libinjectionSQL', 'libinjectionXSS')
VAR_RE = re.compile(r'^[A-Za-z0-9_.\-\[\]]{1,128}$')
# a variable named by a regular expression ("/.+filename$/"): ModSecurity takes ARGS_POST:/.../ the same way; no space,
# quote or "|" (they would end the variable list)
VAR_RX = re.compile(r'^/[^\s"|/][^\s"|]{0,250}/$')
NAME_RE = re.compile(r'^[a-z0-9_.-]+/[A-Za-z0-9_.-]{1,120}$')


class Unsupported(Exception):
    def __init__(self, why, **details):
        super().__init__(why)
        self.why, self.details = why, details


def hub_dir(cfg):
    return cfg['hub']['dir']


# --- conversion ----------------------------------------------------------------------------------------------------

def _leaf(c):
    """One condition -> (variables, operator, transforms) of a SecRule; raises Unsupported."""
    if not isinstance(c, dict):
        raise Unsupported('condition_not_a_mapping')
    extra = set(c) - {'zones', 'variables', 'transform', 'match', 'name'}
    if extra:
        raise Unsupported('unknown_condition_keys', keys=sorted(extra))
    zones = c.get('zones')
    if not isinstance(zones, list) or not zones or not all(isinstance(z, str) for z in zones):
        raise Unsupported('zones_missing')
    bad = [z for z in zones if z not in ZONES]
    if bad:
        raise Unsupported('zone_not_supported', zones=bad)
    names = c.get('variables') or []
    if not isinstance(names, list) or not all(isinstance(v, str) and (VAR_RE.match(v) or VAR_RX.match(v)) for v in names):
        raise Unsupported('variable_not_supported')
    for v in names:
        if v.endswith('%/') or v.endswith('%'):
            raise Unsupported('variable_not_supported')
        if VAR_RX.match(v):
            try:
                re.compile(v[1:-1])
            except re.error:
                raise Unsupported('variable_not_supported')
    tf = c.get('transform') or []
    if not isinstance(tf, list) or not all(isinstance(t, str) for t in tf):
        raise Unsupported('transform_not_supported')
    count = 'count' in tf
    tf = [t for t in tf if t != 'count']
    bad = [t for t in tf if t.lower() not in TRANSFORMS]
    if bad:
        raise Unsupported('transform_not_supported', transforms=bad)
    m = c.get('match')
    if not isinstance(m, dict) or set(m) - {'type', 'value', 'not'}:
        raise Unsupported('match_not_supported')
    mt = m.get('type')
    if not isinstance(mt, str) or mt not in MATCH:
        raise Unsupported('match_not_supported', type=str(mt)[:40])
    val = m.get('value')
    if mt in NUMERIC:
        if not isinstance(val, int) or isinstance(val, bool):
            raise Unsupported('match_value_not_a_number')
        arg = str(val)
    elif mt in NO_VALUE:
        arg = ''
    else:
        if isinstance(val, bool) or val is None:
            raise Unsupported('match_value_missing')
        arg = str(val)
        # inside the rule's double quotes only a quote is escaped; a backslash right before one (or at the very end)
        # would change what the rule matches, so such a value is not taken
        if not arg or len(arg) > 4096 or re.search(r'[\x00\r\n\x0b\x0c\x1c-\x1e\x85\u2028\u2029]', arg) or \
                re.search(r'\\(?:"|$)', arg):
            raise Unsupported('match_value_not_supported')
        # ModSecurity expands %{...} in these operators and may trim the ends; CrowdSec takes the value as it is.
        # ModSecurity 3.0 cannot read a value that ends in "%" (the whole configuration fails to load: tested)
        if '%{' in arg or arg != arg.strip() or arg.endswith('%'):
            raise Unsupported('match_value_not_supported')
        if mt == 'regex':
            try:
                re.compile(arg)
            except re.error:
                pass        # PCRE may still take it (look-behinds, possessive): the static check and nginx -t decide
    if m.get('not') not in (None, False, True):
        raise Unsupported('match_not_supported')
    if count and names == [] and len(zones) > 1:
        raise Unsupported('count_over_several_zones')
    variables = []
    for z in zones:
        target = ZONES[z]
        if names:
            variables += [('&' if count else '') + target + ':' + v for v in names]
            if z in ('BODY_ARGS', 'BODY_ARGS_NAMES') and not count:
                variables += [('ARGS:' if z == 'BODY_ARGS' else 'ARGS_NAMES:') + v for v in names if v.lower().startswith('json.')]
        else:
            variables.append(('&' if count else '') + target)
            if z in JSON_TOO and not count:
                variables.append(JSON_TOO[z])
    op = ('!' if m.get('not') else '') + MATCH[mt] + (' ' + arg if arg else '')
    return '|'.join(variables), op, ','.join(['t:none'] + [TRANSFORMS[t.lower()] for t in tf])


def _dnf(node, depth=0):
    """A rule tree ("and" / "or" / a condition) as alternatives, each a list of conditions (all must match)."""
    if depth > 8:
        raise Unsupported('nested_too_deep')
    if not isinstance(node, dict):
        raise Unsupported('condition_not_a_mapping')
    if 'and' in node or 'or' in node:
        if len(node) != 1:
            raise Unsupported('unknown_condition_keys', keys=sorted(node))
        kids = node.get('and') if 'and' in node else node.get('or')
        if not isinstance(kids, list) or not kids:
            raise Unsupported('empty_group')
        parts = [_dnf(k, depth + 1) for k in kids]
        if 'or' in node:
            out = [alt for p in parts for alt in p]
        else:
            out = [[]]
            for p in parts:
                out = [a + b for a in out for b in p]
                if len(out) > MAX_ALTERNATIVES:
                    raise Unsupported('too_many_alternatives')
                if any(len(a) > MAX_CONDITIONS for a in out):
                    raise Unsupported('too_many_conditions')
        if len(out) > MAX_ALTERNATIVES:
            raise Unsupported('too_many_alternatives')
        return out
    return [[_leaf(node)]]


def _alternatives(doc):
    """A hub rule file -> (alternatives: [[(variables, operator, transforms)]], msg, tag); raises Unsupported."""
    if not isinstance(doc, dict):
        raise Unsupported('not_a_mapping')
    if doc.get('seclang_rules') or doc.get('seclang_files_rules') or doc.get('data'):
        raise Unsupported('seclang_or_data_files')
    rules = doc.get('rules')
    if not isinstance(rules, list) or not rules:
        raise Unsupported('no_rules')
    alts = []
    for r in rules:
        alts += _dnf(r)
    if len(alts) > MAX_ALTERNATIVES:
        raise Unsupported('too_many_alternatives')
    name = str(doc.get('name') or '')
    labels = doc.get('labels') if isinstance(doc.get('labels'), dict) else {}
    label = labels.get('label') if isinstance(labels.get('label'), str) else ''
    msg = SAFE_TEXT.sub('', label or name)[:80]
    tag = re.sub(r'[^A-Za-z0-9_./-]', '', name)[:120]
    return alts, msg, tag


def render(doc, first_id, head=(), tail=()):
    """A hub rule file -> (ModSecurity text, how many rules). One chain per alternative with ids first_id, first_id + 1,
    ...; head: conditions put in front of every chain (the sites), tail: after it (the sources). Each rule marks the
    request like a confident block (jt_block), which the system rules refuse. Raises Unsupported."""
    alts, msg, tag = _alternatives(doc)
    if any(len(a) + len(head) + len(tail) > MAX_CONDITIONS + 2 for a in alts):     # (+ the path capture: not counted)
        raise Unsupported('too_many_conditions')
    from .rulegen import PATH_CAPTURE, PATH_VARS
    texts = []
    for i, conds in enumerate(alts):
        rid = first_id + i
        first = ("id:%d,phase:2,pass,log,msg:'jt confident block: CrowdSec %s',tag:'jt-confident-block',tag:'crowdsec-hub',"
                 "tag:'%s'" % (rid, msg, tag))
        # the path (URI) as the backend gets it too: libmodsecurity 3.0.9 cuts REQUEST_FILENAME at an encoded "?",
        # CrowdSec does not (0.4.93: TX:1, the raw path, captured first -- rulegen.PATH_CAPTURE)
        uses_path = any('REQUEST_FILENAME' in v.split('|') for v, _, _ in conds)
        conds = [('|'.join(PATH_VARS if x == 'REQUEST_FILENAME' else x for x in v.split('|')), o, t) for v, o, t in conds]
        conds = list(head) + ([PATH_CAPTURE] if uses_path else []) + list(conds) + list(tail)   # (after the site: cheaper)
        lines = []
        for j, (var, op, tr) in enumerate(conds):
            ind = '    ' * j
            acts = ([first] if j == 0 else []) + [tr]
            if j < len(conds) - 1:
                acts.append('chain')
            else:
                acts.append('setvar:tx.jt_block=1,ctl:ruleEngine=On')
            lines.append('%sSecRule %s "%s" \\\n%s    "%s"' % (ind, var, op.replace('"', '\\"'), ind, ','.join(acts)))
        texts.append('\n'.join(lines))
    text = '\n'.join(texts)
    if len(text) > MAX_TEXT:
        raise Unsupported('too_long')
    if not all(LINE_SHAPE.match(ln) for ln in text.split('\n')) or text.splitlines() != text.split('\n'):
        raise Unsupported('unexpected_text')      # (the root side splits rules with str.splitlines())
    return text, len(alts)


def convert(doc, first_id=0):
    """A hub rule file -> {'ok', 'text', 'rules' (how many ModSecurity rules), 'reason', 'details'} (the preview the
    page shows; a proposed rule adds its sites and sources: render())."""
    try:
        text, n = render(doc, first_id)
        return {'ok': True, 'text': text, 'rules': n, 'reason': None, 'details': {}}
    except Unsupported as e:
        details = {k: (v[:20] if isinstance(v, list) else v) for k, v in list((e.details or {}).items())[:5]}
        return {'ok': False, 'text': '', 'rules': 0, 'reason': e.why, 'details': details}


def describe(doc):
    """What the page shows about a rule: label, description, CVEs, the product its label names."""
    labels = doc.get('labels') if isinstance(doc, dict) and isinstance(doc.get('labels'), dict) else {}
    cls = labels.get('classification') if isinstance(labels.get('classification'), list) else []
    cves = sorted({c[4:].upper() for c in cls if isinstance(c, str) and c.lower().startswith('cve.')})
    cwes = sorted({c[4:].upper() for c in cls if isinstance(c, str) and c.lower().startswith('cwe.')})
    label = labels.get('label') if isinstance(labels.get('label'), str) else ''
    label = label[:200]
    product = label.split(' - ')[0].strip() if ' - ' in label else ''
    desc = doc.get('description') if isinstance(doc, dict) and isinstance(doc.get('description'), str) else ''
    return {'label': label, 'description': desc[:500],
            'cves': cves, 'cwes': cwes, 'product': product[:120], 'behavior': str(labels.get('behavior') or '')[:60],
            'confidence': labels.get('confidence') if isinstance(labels.get('confidence'), int) else None}


# --- the hub's own test requests (.appsec-tests/<name>/: config.yaml + a nuclei template) ----------------------------

TEST_HOST = 'jtwaf-test-host.invalid'      # the site's name goes here when the rule is proposed for a site
TEST_PATH = re.compile(r'^\.appsec-tests/[A-Za-z0-9_.-]{1,120}/[A-Za-z0-9_.-]{1,120}\.yaml$')
MAX_TESTS = 10                              # requests taken from one template (each must be refused)
MAX_TEST_BODY = 64 * 1024
TEST_METHODS = ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')
TEMPLATE_KEYS = {'id', 'info', 'http', 'requests', 'variables'}
REQUEST_KEYS = {'raw', 'method', 'path', 'headers', 'body', 'matchers', 'matchers-condition', 'cookie-reuse', 'max-size',
                'stop-at-first-match', 'redirects', 'max-redirects', 'skip-variables-check'}
DROP_HEADERS = ('host', 'content-length', 'connection', 'transfer-encoding')
# the sandbox gave each request its client address in X-Forwarded-For until 0.5.49 (now X-JTWAF-Client); the hub's
# tests that set it stay out until they are measured again on real nginx
UNSENDABLE_HEADERS = ('x-forwarded-for',)
_PLACEHOLDER = re.compile(r'\{\{([^{}]{1,200})\}\}')


def _refused(matchers, cond):
    """What each request of a group must do: 'each' ("status: [403]": every request is an attack the rule refuses) or
    {request number from 1: 'refuse' | 'pass'} ("status_code_2 == 403" refused; "status_code_3 == 404" -- or any other
    code -- an ordinary request the rule must let through; all of them together). Anything else (words in the page,
    "or") cannot be judged here."""
    if not isinstance(matchers, list) or not matchers:
        raise Unsupported('test_matchers')
    if len(matchers) > 1 and cond not in (None, 'and'):
        raise Unsupported('test_matchers')
    each, which = False, {}
    for m in matchers:
        if not isinstance(m, dict) or set(m) - {'type', 'status', 'dsl', 'condition', 'name'}:
            raise Unsupported('test_matchers')
        if m.get('type') == 'status' and m.get('status') == [403] and m.get('condition') in (None, 'or', 'and'):
            each = True
        elif m.get('type') == 'dsl' and isinstance(m.get('dsl'), list) and m['dsl'] and \
                (len(m['dsl']) == 1 or m.get('condition') == 'and'):
            for x in m['dsl']:
                d = re.fullmatch(r'\s*status_code(?:_(\d{1,2}))?\s*==\s*([1-5][0-9][0-9])\s*', str(x))
                if not d:
                    raise Unsupported('test_matchers')
                n = int(d.group(1) or 1)
                want = 'refuse' if d.group(2) == '403' else 'pass'
                if which.get(n, want) != want:
                    raise Unsupported('test_matchers')
                which[n] = want
        else:
            raise Unsupported('test_matchers')
    if each and which:
        raise Unsupported('test_matchers')
    if not each and 'refuse' not in which.values():
        raise Unsupported('test_matchers')       # nothing the rule must refuse: no proof of the rule
    return 'each' if each else which


# nuclei's random helpers give fixed text here: the same request every time (a test that passes once passes again)
_RAND_ALNUM = 'jtwafrand7q3kx9m2p4v8w1z5c6b0nh'
_RAND_ALPHA = 'jtwafrandqkxmpvwzcbnhlgseyoiu'
_RAND_NUM = '7391582046'
OAST_HOST = 'jtwaf-oast.invalid'        # an out-of-band callback address ({{interactsh-url}}): never answers
_TOKEN = re.compile(r'\s*(?:(?P<str>"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')|(?P<int>-?\d{1,9})(?![\w-])|'
                    r'(?P<name>[A-Za-z_][A-Za-z0-9_-]{0,63})|(?P<p>[(),]))')


def _fixed(n, chars):
    n = int(n)
    if not 0 < n <= 256:
        raise Unsupported('test_placeholder', name='rand')
    return (chars * (n // len(chars) + 1))[:n]


def _call(fn, args, key):
    import base64
    import urllib.parse

    def text(i):
        if len(args) <= i or not isinstance(args[i], (str, bytes)):
            raise Unsupported('test_placeholder', name=key[:40])
        return args[i].decode('latin-1') if isinstance(args[i], bytes) else args[i]

    def num(i, default=None):
        if len(args) <= i:
            if default is None:
                raise Unsupported('test_placeholder', name=key[:40])
            return default
        v = args[i]
        if isinstance(v, str) and re.fullmatch(r'-?\d{1,9}', v):
            v = int(v)
        if not isinstance(v, int):
            raise Unsupported('test_placeholder', name=key[:40])
        return v
    try:
        if fn == 'hex_decode':
            return bytes.fromhex(text(0))
        if fn == 'base64':
            a = args[0] if args else ''
            return base64.b64encode(a if isinstance(a, bytes) else text(0).encode('utf-8')).decode('ascii')
        if fn == 'base64_decode':
            return base64.b64decode(text(0), validate=True)
        if fn == 'url_encode':
            return urllib.parse.quote(text(0), safe='')
        if fn == 'url_decode':
            return urllib.parse.unquote(text(0))
        if fn == 'to_lower':
            return text(0).lower()
        if fn == 'to_upper':
            return text(0).upper()
        if fn == 'concat':
            return ''.join(text(i) for i in range(len(args)))
        if fn in ('rand_base', 'rand_text_alphanumeric', 'rand_char'):
            if fn == 'rand_char':
                return _RAND_ALNUM[0]
            return _fixed(num(0), text(1) if len(args) > 1 and text(1) else _RAND_ALNUM)
        if fn == 'rand_text_alpha':
            return _fixed(num(0), _RAND_ALPHA)
        if fn == 'rand_text_numeric':
            return _fixed(num(0), _RAND_NUM)
        if fn == 'rand_int':
            return str(num(0, 0))
    except ValueError:
        raise Unsupported('test_placeholder', name=key[:40])
    raise Unsupported('test_placeholder', name=key[:40])


def _value(key, variables, in_path, depth):
    """One {{...}}: a name (Hostname, BaseURL, randstr, a variable of the template) or a call of nuclei's helpers,
    nested ("to_lower(rand_text_alphanumeric(8))"; arguments: quoted text, numbers, names) -> str or bytes."""
    toks, pos = [], 0
    while pos < len(key):
        m = _TOKEN.match(key, pos)
        if not m or m.end() == pos:
            if key[pos:].strip():
                raise Unsupported('test_placeholder', name=key[:40])
            break
        toks.append(m)
        pos = m.end()
    i = 0

    def expr():
        nonlocal i
        if i >= len(toks):
            raise Unsupported('test_placeholder', name=key[:40])
        t = toks[i]
        i += 1
        if t.group('str') is not None:
            q = t.group('str')
            return re.sub(r'\\(.)', r'\1', q[1:-1])
        if t.group('int') is not None:
            return int(t.group('int'))
        name = t.group('name')
        if name is None:
            raise Unsupported('test_placeholder', name=key[:40])
        if i < len(toks) and toks[i].group('p') == '(':
            i += 1
            args = []
            if i < len(toks) and toks[i].group('p') == ')':
                i += 1
            else:
                while True:
                    args.append(expr())
                    if i < len(toks) and toks[i].group('p') == ',':
                        i += 1
                        continue
                    if i < len(toks) and toks[i].group('p') == ')':
                        i += 1
                        break
                    raise Unsupported('test_placeholder', name=key[:40])
            return _call(name, args, key)
        if name in ('Hostname', 'Host'):
            return TEST_HOST
        if name in ('BaseURL', 'RootURL'):
            return '' if in_path else 'http://' + TEST_HOST
        if re.fullmatch(r'randstr(?:_\d{1,2})?', name):
            return 'jtwafrand7q3k'
        if name in ('interactsh-url', 'interactsh_url'):
            return OAST_HOST
        if name in variables:
            if depth >= 4:
                raise Unsupported('test_placeholder', name=key[:40])
            return _expand(variables[name], variables, True, in_path, depth + 1)
        raise Unsupported('test_placeholder', name=key[:40])
    v = expr()
    if i != len(toks):
        raise Unsupported('test_placeholder', name=key[:40])
    return str(v) if isinstance(v, int) else v


def _expand(text, variables, binary_ok, in_path=False, depth=0):
    """Placeholders -> text (str) or bytes (when a helper such as hex_decode makes binary data)."""
    parts, binary = [], False
    pos = 0
    for m in _PLACEHOLDER.finditer(text):
        parts.append(text[pos:m.start()])
        pos = m.end()
        val = _value(m.group(1).strip(), variables, in_path, depth)
        if isinstance(val, bytes):
            if not binary_ok:
                raise Unsupported('test_binary_outside_body')
            try:
                val = val.decode('utf-8')
            except UnicodeDecodeError:
                binary = True
        parts.append(val)
    parts.append(text[pos:])
    if binary:
        return b''.join(p if isinstance(p, bytes) else p.encode('utf-8') for p in parts)
    return ''.join(p.decode('utf-8') if isinstance(p, bytes) else p for p in parts)


def _test_case(method, target, headers, body, variables):
    method = str(method or '').upper()
    if method not in TEST_METHODS:
        raise Unsupported('test_method', method=method[:20])
    path = _expand(target, variables, False, in_path=True)
    if path == '' or path.startswith('?'):
        path = '/' + path                       # "{{BaseURL}}" alone: the site's root
    if isinstance(path, bytes) or not path.startswith('/') or len(path) > 2048 or re.search(r'[^\x21-\x7e]', path):
        raise Unsupported('test_path')
    hdr = {}
    for k, v in headers:
        v = _expand(str(v), variables, False)
        if not re.fullmatch(r'[A-Za-z0-9-]{1,64}', k) or re.search(r'[\x00-\x1f\x7f]', v) or len(v) > 4096:
            raise Unsupported('test_header')
        try:
            v.encode('latin-1')
        except UnicodeEncodeError:
            raise Unsupported('test_header')
        if k.lower() in UNSENDABLE_HEADERS:
            raise Unsupported('test_header')
        if k.lower() in DROP_HEADERS:
            continue
        if k.lower() == 'user-agent' and not v.strip():
            continue        # nuclei's (Go's) client sends no User-Agent at all for an empty one: neither does the sandbox
        hdr[k] = v
    if len(hdr) > 20:
        raise Unsupported('test_header')
    out = {'method': method, 'path': path, 'headers': hdr}
    if body not in (None, ''):
        b = _expand(str(body), variables, True)
        size = len(b) if isinstance(b, bytes) else len(b.encode('utf-8'))
        if size > MAX_TEST_BODY:
            raise Unsupported('test_body')
        if isinstance(b, bytes):
            import base64
            out['body_b64'] = base64.b64encode(b).decode('ascii')
        else:
            out['body'] = b
    return out


def _raw_case(raw, variables):
    if not isinstance(raw, str):
        raise Unsupported('test_raw')
    text = raw.lstrip('\r\n')
    # nuclei's own annotations before the request line ("@timeout: 20s"): for the scanner, not part of the request
    while re.match(r'@[a-z-]{1,30}\s*:[^\n]*\n', text):
        text = text.split('\n', 1)[1]
    m = re.search(r'\r?\n\r?\n', text)
    head, body = (text[:m.start()], text[m.end():]) if m else (text, '')
    lines = head.replace('\r\n', '\n').split('\n')       # the body is sent as written (multipart needs its CRLFs)
    m = re.fullmatch(r'([A-Za-z]{3,10}) (\S+) HTTP/1\.[01]', lines[0].strip())
    if not m:
        raise Unsupported('test_raw')
    headers = []
    for ln in lines[1:]:
        if not ln.strip():
            continue
        k, c, v = ln.partition(':')
        if not c:
            raise Unsupported('test_raw')
        headers.append((k.strip(), v.strip()))
    if body.endswith('\n') and not body.endswith('\r\n'):
        body = body[:-1]                         # the line break a YAML block ends with, not the request's own CRLF
    return _test_case(m.group(1), m.group(2), headers, body, variables)


def nuclei_tests(doc):
    """A nuclei template from the hub's tests -> [{'method', 'path', 'headers', 'body' | 'body_b64', 'expect'}]: expect
    'refuse' (an attack the rule must refuse) or 'pass' (an ordinary request it must let through); the site's name is
    TEST_HOST until the rule is proposed. Raises Unsupported: only what can be sent exactly is taken."""
    if not isinstance(doc, dict) or set(doc) - TEMPLATE_KEYS:
        raise Unsupported('test_template')
    variables = {}
    for k, v in (doc.get('variables') or {}).items() if isinstance(doc.get('variables'), dict) else ():
        if isinstance(v, (str, int)) and not isinstance(v, bool):
            variables[str(k)] = str(v)          # expanded where used (a variable may name others and helpers)
    groups = doc.get('http') if 'http' in doc else doc.get('requests')
    if not isinstance(groups, list) or not 1 <= len(groups) <= 5 or not all(isinstance(g, dict) for g in groups):
        raise Unsupported('test_template')
    out = []
    for g in groups:
        if set(g) - REQUEST_KEYS:
            raise Unsupported('test_request_keys', keys=sorted(set(g) - REQUEST_KEYS)[:5])
        mode = _refused(g.get('matchers'), g.get('matchers-condition'))
        if 'raw' in g:
            raws = g.get('raw')
            if not isinstance(raws, list) or not raws:
                raise Unsupported('test_raw')
            cases = [_raw_case(r, variables) for r in raws]
        else:
            paths = g.get('path')
            if not isinstance(paths, list) or not paths or not all(isinstance(x, str) for x in paths):
                raise Unsupported('test_template')
            hd = g.get('headers') or {}
            if not isinstance(hd, dict):
                raise Unsupported('test_header')
            cases = [_test_case(g.get('method') or 'GET', x, [(str(k), v) for k, v in hd.items()], g.get('body'), variables)
                     for x in paths]
        if mode == 'each':
            out += [dict(c, expect='refuse') for c in cases]
        else:
            if max(mode) > len(cases):
                raise Unsupported('test_matchers')
            out += [dict(c, expect=mode[i]) for i, c in enumerate(cases, 1) if i in mode]
    refuse = [c for c in out if c['expect'] == 'refuse']
    keep = refuse[:MAX_TESTS]
    keep += [c for c in out if c['expect'] == 'pass'][:max(0, MAX_TESTS - len(keep))]
    return keep


def upstream_tests(files):
    """{rule path: (tests, reason)} from the hub's .appsec-tests: a test folder names its rule in config.yaml (one rule
    besides the hub's base configuration) and its template."""
    out = {}
    dirs = sorted({p.split('/')[1] for p in files if TEST_PATH.match(p)})
    for d in dirs:
        cfgp = '.appsec-tests/%s/config.yaml' % d
        if cfgp not in files:
            continue
        try:
            cfg = miniyaml.loads(files[cfgp])
        except miniyaml.YamlError:
            continue
        if not isinstance(cfg, dict):
            continue
        rules = [r[2:] if isinstance(r, str) and r.startswith('./') else r for r in cfg.get('appsec-rules') or []]
        rules = [r for r in rules if isinstance(r, str) and r.startswith('appsec-rules/') and not r.endswith('/base-config.yaml')]
        tpl = cfg.get('nuclei_template')
        if len(rules) != 1 or not isinstance(tpl, str):
            continue
        tp = '.appsec-tests/%s/%s' % (d, tpl)
        try:
            if tp not in files:
                raise Unsupported('test_template_missing')
            try:
                doc = miniyaml.loads(files[tp])
            except miniyaml.YamlError:
                raise Unsupported('test_yaml')
            res = (nuclei_tests(doc), None)
        except Unsupported as e:
            res = ([], e.why)
        if rules[0] not in out or (res[0] and not out[rules[0]][0]):
            out[rules[0]] = res
    return out


def _zones(node):
    """Every zone named anywhere in a rule tree."""
    if isinstance(node, dict):
        z = node.get('zones') if isinstance(node.get('zones'), list) else []
        return set(x for x in z if isinstance(x, str)) | set().union(*[_zones(v) for v in node.values()] or [set()])
    if isinstance(node, list):
        return set().union(*[_zones(v) for v in node] or [set()])
    return set()


URL_HEADER_ZONES = {'URI', 'URI_FULL', 'METHOD', 'PROTOCOL', 'HEADERS'}


def url_header_only(raw):
    """Whether a hub rule looks only at the URL, the method, the protocol and named headers (what a site's recent
    requests show): the only CrowdSec rules applied without a person."""
    try:
        doc = miniyaml.loads(raw.encode('utf-8') if isinstance(raw, str) else raw)
    except miniyaml.YamlError:
        return False
    if not isinstance(doc, dict):
        return False

    def leaves(node):
        if isinstance(node, dict) and ('and' in node or 'or' in node):
            for k in node.get('and') or node.get('or') or []:
                yield from leaves(k)
        else:
            yield node
    try:
        ls = [x for r in doc.get('rules') or [] for x in leaves(r)]
    except (TypeError, AttributeError):
        return False
    return bool(ls) and all(isinstance(x, dict) and isinstance(x.get('zones'), list) and set(x['zones']) <= URL_HEADER_ZONES
                            and ('HEADERS' not in x['zones'] or x.get('variables')) for x in ls)


def fp_warning(raw):
    """The hub's file itself warns that the rule refuses ordinary requests (a disclaimer, "false positives")."""
    t = raw.decode('utf-8', 'replace').lower() if isinstance(raw, bytes) else str(raw).lower()
    return 'false positive' in t or 'disclaimer' in t


# --- sources: the GitHub repository, or an uploaded archive --------------------------------------------------------

def _fetch(url, limit, accept='application/octet-stream'):
    req = urllib.request.Request(url, headers={'User-Agent': 'jt-waf-mgr', 'Accept': accept})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError('response too large: %s' % url)
    return data


def download(log=print, fetch=_fetch, have=None):
    """The newest commit of the hub's default branch: {path: bytes} for appsec-rules/**.yaml and LICENSE, and the
    commit. Only those files are fetched (about 0.2 MB), each by the commit id. None when that commit is `have`."""
    c = json.loads(fetch(API + '/commits/master', 1024 * 1024, 'application/vnd.github+json'))
    sha = c.get('sha') or ''
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('no commit id from GitHub')
    if have and sha == have:
        log('hub: commit %s is the one already read' % sha[:12])
        return None
    tree = json.loads(fetch(API + '/git/trees/%s?recursive=1' % sha, 16 * 1024 * 1024, 'application/vnd.github+json'))
    if tree.get('truncated'):
        raise ValueError('the file list from GitHub is incomplete')
    paths = [e['path'] for e in tree.get('tree') or [] if e.get('type') == 'blob' and _wanted(e.get('path') or '')
             and not (TEST_PATH.match(e.get('path') or '') and (e.get('size') or 0) > MAX_FILE)]
    rules_first = sorted(paths, key=lambda p: p.startswith('.appsec-tests/'))
    if sum(1 for p in paths if not p.startswith('.appsec-tests/')) > MAX_FILES:
        raise ValueError('too many files')
    paths = rules_first[:MAX_FILES]               # tests beyond the limit are left out, never the rules
    import concurrent.futures
    def one(p):
        try:
            return fetch(RAW % (sha, urllib.parse.quote(p)), MAX_FILE)
        except ValueError:
            if p.startswith('.appsec-tests/'):
                return None                       # a test too large: that rule has no test, the sync goes on
            raise
    with concurrent.futures.ThreadPoolExecutor(4) as ex:       # a few at a time: about half a minute, not two
        got = list(ex.map(one, paths))
    files = {p: b for p, b in zip(paths, got) if b is not None}
    log('hub: %d files from commit %s' % (len(files), sha[:12]))
    return files, sha, 'github'


def _wanted(path):
    return path == 'LICENSE' or ('..' not in path and (
        (path.startswith('appsec-rules/') and path.endswith('.yaml')) or TEST_PATH.match(path) is not None))


def from_archive(data, name=''):
    """An uploaded hub archive (GitHub's "Download ZIP" or a .tar.gz of the repository) -> (files, commit or None).
    Only regular files under appsec-rules/ and LICENSE are taken; links, devices and anything outside are skipped."""
    if len(data) > MAX_ARCHIVE:
        raise ValueError('archive too large')
    files, total, top_seen = {}, 0, set()

    def take(path, size, read):
        nonlocal total
        parts = path.split('/')
        if len(parts) < 2 or any(p in ('', '.', '..') for p in parts):
            return
        top_seen.add(parts[0])
        rel = '/'.join(parts[1:])
        if not _wanted(rel):
            return
        if size > MAX_FILE:
            if TEST_PATH.match(rel):
                return                               # a test too large: that rule has no test
            raise ValueError('file too large: %s' % rel)
        total += size
        if total > MAX_UNPACKED:
            raise ValueError('archive unpacks too large')
        if len(files) >= MAX_FILES * 2:
            raise ValueError('too many files')
        files[rel] = read()
    if data[:4] == b'PK\x03\x04':
        # the entry count from the end record, before zipfile reads the whole directory into memory
        eocd = data.rfind(b'PK\x05\x06', max(0, len(data) - 65558))
        if eocd < 0 or len(data) < eocd + 22:
            raise ValueError('not a readable zip archive')
        entries = int.from_bytes(data[eocd + 10:eocd + 12], 'little')
        if entries == 0xFFFF or data.rfind(b'PK\x06\x06') >= 0 or entries > MAX_MEMBERS:
            raise ValueError('too many entries in the archive')
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if len(z.infolist()) > MAX_MEMBERS:
                raise ValueError('too many entries in the archive')
            for i in z.infolist():
                if i.is_dir() or i.filename.startswith('/') or '\\' in i.filename:
                    continue
                if (i.external_attr >> 16) & 0o170000 not in (0, 0o100000):      # links and the like
                    continue
                take(i.filename, i.file_size, lambda i=i: z.read(i)[:MAX_FILE + 1])
            comment = z.comment.decode('ascii', 'replace') if z.comment else ''
    elif data[:2] == b'\x1f\x8b':
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as t:
            seen = 0
            for m in t:
                seen += 1
                if seen > MAX_MEMBERS:
                    raise ValueError('too many entries in the archive')
                if not m.isreg() or m.name.startswith('/'):
                    continue
                take(m.name, m.size, lambda m=m: t.extractfile(m).read(MAX_FILE + 1))
            comment = ''
    else:
        raise ValueError('not a .zip or .tar.gz archive')
    if len(top_seen) != 1:
        raise ValueError('not an archive of one repository folder')
    sha = None
    m = re.search(r'\b([0-9a-f]{40})\b', comment) or re.search(r'-([0-9a-f]{7,40})$', next(iter(top_seen)))
    if m:
        sha = m.group(1)
    if not any(p.startswith('appsec-rules/') for p in files):
        raise ValueError('no appsec-rules/ in the archive: is it the CrowdSec Hub?')
    return files, sha, 'upload' + (':' + name[:100] if name else '')


# --- the index the page reads ----------------------------------------------------------------------------------------

def build_index(files, commit, source, preview_id, now=None):
    """Read and convert every rule. The text shown uses preview_id (the first id of waf.hub_range): the real ids are
    handed out when a rule is proposed as a change."""
    now = now or time.time()
    lic = files.get('LICENSE') or b''
    rules = []
    tests = upstream_tests(files)
    for path in sorted(p for p in files if p.startswith('appsec-rules/')):
        raw = files[path]
        t, why = tests.get(path, ([], 'no_test'))
        item = {'path': path, 'sha256': hashlib.sha256(raw).hexdigest(), 'tests': t, 'tests_reason': why,
                'fp_warning': fp_warning(raw)}
        try:
            doc = miniyaml.loads(raw)
        except miniyaml.YamlError as e:
            rules.append(dict(item, name=path.rsplit('/', 1)[-1][:-5], ok=False, reason='yaml', details={'error': str(e)[:200]},
                              yaml=raw.decode('utf-8', 'replace')[:20000]))
            continue
        name = (doc or {}).get('name') if isinstance(doc, dict) else ''
        name = name if isinstance(name, str) and NAME_RE.match(name) else path[len('appsec-rules/'):-5]
        try:
            conv = convert(doc, preview_id)
            desc = describe(doc if isinstance(doc, dict) else {})
        except Exception as e:      # noqa: BLE001 -- one odd file never stops the others
            conv = {'ok': False, 'reason': 'error', 'details': {'error': type(e).__name__}, 'text': '', 'rules': 0}
            desc = describe({})
        try:
            whole = len(raw) <= 20000 and raw.decode('utf-8') is not None
        except UnicodeDecodeError:
            whole = False
        if conv['ok'] and not whole:
            # the index keeps 20,000 characters of the file: a rule must be kept whole to be proposed
            conv = {'ok': False, 'reason': 'too_long', 'details': {}, 'text': '', 'rules': 0}
        rules.append(dict(item, name=name, yaml=raw.decode('utf-8', 'replace')[:20000],
                          ok=conv['ok'], reason=conv['reason'], details=conv['details'], text=conv['text'],
                          rule_count=conv['rules'], **desc))
    # two files with one name: neither can be told apart later (proposing one must mean exactly that file)
    seen = {}
    for r in rules:
        seen[r['name']] = seen.get(r['name'], 0) + 1
    for r in rules:
        if seen[r['name']] > 1:
            r.update(ok=False, reason='duplicate_name', text='', rule_count=0, details={})
    return {'format': INDEX_FORMAT, 'commit': commit, 'source': source, 'synced_at': util.iso(now), 'license': lic.decode('utf-8', 'replace')[:20000],
            'license_sha256': hashlib.sha256(lic).hexdigest() if lic else None, 'rules': rules,
            'counts': {'total': len(rules), 'convertible': sum(1 for r in rules if r['ok']),
                       'unsupported': sum(1 for r in rules if not r['ok'])}}


def read_index(cfg):
    p = os.path.join(hub_dir(cfg), INDEX)
    try:
        if os.path.getsize(p) > MAX_INDEX:
            return None
        with open(p, encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_json(path, data):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, ensure_ascii=False)
    os.replace(tmp, path)


ENABLED = 'enabled'


def marker(cfg):
    """The web service keeps this file while the sync is switched on in Settings (the job reads no settings)."""
    p = os.path.join(hub_dir(cfg), ENABLED)
    try:
        if cfg['hub']['enabled'] and not os.path.exists(p):
            os.makedirs(hub_dir(cfg), mode=0o750, exist_ok=True)
            with open(p, 'w') as fh:
                fh.write(util.iso(time.time()))
        elif not cfg['hub']['enabled'] and os.path.exists(p):
            os.unlink(p)
    except OSError:
        pass


def request_sync(cfg, why='sync'):
    """Called by the web service: the path unit starts the job. why: 'sync' (download now; the page asks only while
    the sync is switched on) or 'upload' (read the uploaded archive; never a reason to download)."""
    d = hub_dir(cfg)
    os.makedirs(d, mode=0o750, exist_ok=True)
    p = os.path.join(d, REQUEST)
    old = ''
    try:
        with open(p) as fh:
            old = fh.read(64)
    except OSError:
        pass
    with open(p, 'w') as fh:
        fh.write('sync' if why == 'sync' or old.startswith('sync') else 'upload')


def run(cfg, log=print, fetch=_fetch, now=None):
    """jt-waf-mgr-hub.service: an uploaded archive waiting in upload/ first, else (when enabled) the newest commit.
    Writes index.json (with the previous rules marked new / changed / same / removed) and the LICENSE. Returns the
    status."""
    d = hub_dir(cfg)
    os.makedirs(d, mode=0o750, exist_ok=True)
    try:
        with open(os.path.join(d, REQUEST)) as fh:
            asked = fh.read(64).startswith('sync')      # "sync now" (an upload's request never downloads)
    except OSError:
        asked = False
    try:
        os.unlink(os.path.join(d, REQUEST))
    except OSError:
        pass
    status = {'at': util.iso(now or time.time())}
    # the page shows that it is working (the request file is gone by now)
    _write_json(os.path.join(d, 'status.json'), dict(read_status(cfg), state='running', started_at=status['at']))
    up = os.path.join(d, UPLOAD_DIR)
    waiting = sorted(os.listdir(up)) if os.path.isdir(up) else []
    try:
        if waiting:
            waiting.sort(key=lambda n: os.path.getmtime(os.path.join(up, n)))
            name = waiting[-1]                              # the newest; the others are reported as skipped
            with open(os.path.join(up, name), 'rb') as fh:
                data = fh.read(MAX_ARCHIVE + 1)
            for n in waiting:
                os.unlink(os.path.join(up, n))
            if len(waiting) > 1:
                status['skipped_uploads'] = waiting[:-1][:10]
            files, sha, source = from_archive(data, name)
        elif asked or os.path.exists(os.path.join(d, ENABLED)):
            # the web service keeps the marker from Settings (config.toml alone does not switch the download on)
            cur = read_index(cfg) or {}
            # an index written by an older version (without the hub's tests) is read again even for the same commit
            got = download(log, fetch, have=cur.get('commit') if cur.get('format') == INDEX_FORMAT else None)
            if got is None:
                status.update(state='ok', unchanged=True, commit=(read_index(cfg) or {}).get('commit'))
                _write_json(os.path.join(d, 'status.json'), status)
                return status
            files, sha, source = got
        else:
            status.update(state='off')
            _write_json(os.path.join(d, 'status.json'), status)
            return status
        old = read_index(cfg) or {}
        idx = build_index(files, sha, source, cfg['waf']['hub_range'][0], now)
        before = {r['name']: r['sha256'] for r in old.get('rules') or []}
        for r in idx['rules']:
            r['change'] = 'new' if r['name'] not in before else ('changed' if before[r['name']] != r['sha256'] else 'same')
        gone = sorted(set(before) - {r['name'] for r in idx['rules']})
        idx['removed'] = gone
        if old.get('commit'):
            idx['previous_commit'] = old.get('commit')
        with open(os.path.join(d, 'LICENSE.tmp'), 'wb') as fh:
            fh.write(files.get('LICENSE') or b'')
        os.replace(os.path.join(d, 'LICENSE.tmp'), os.path.join(d, 'LICENSE'))
        if len(json.dumps(idx)) > MAX_INDEX:
            raise ValueError('the converted rules are too large')
        _write_json(os.path.join(d, INDEX), idx)
        status.update(state='ok', commit=sha, source=source, counts=idx['counts'],
                      new=sum(1 for r in idx['rules'] if r['change'] == 'new'),
                      changed=sum(1 for r in idx['rules'] if r['change'] == 'changed'), removed=len(gone))
        log('hub: %(total)d rules, %(convertible)d convertible, %(unsupported)d not supported' % idx['counts'])
    except Exception as e:      # noqa: BLE001 -- offline, rate limit, a bad archive: reported; the last index stays
        status.update(state='error', error=('%s: %s' % (type(e).__name__, e))[:300])
        log('hub: ' + status['error'])
    _write_json(os.path.join(d, 'status.json'), status)
    return status


def read_status(cfg):
    try:
        with open(os.path.join(hub_dir(cfg), 'status.json'), encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}
