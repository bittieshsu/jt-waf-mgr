"""CrowdSec virtual patching rules (the CrowdSec Hub, github.com/crowdsecurity/hub, MIT licence), converted on this
host into ModSecurity rules.

jt-waf-mgr-hub.service (daily timer, or "sync now" / an upload on the page) takes the hub's `appsec-rules/` and the
`LICENSE` of one commit (about 0.2 MB) -- downloaded, or from an archive an administrator uploaded -- reads each rule with the small
YAML reader (miniyaml) and converts it only when every condition keeps its exact meaning; anything else is listed as
"not supported yet" with the reason (a rule that kept only part of its conditions could refuse ordinary visitors).
The web service never reaches the internet and never unpacks an upload: it reads the index this job writes.

Phase 1 (this module): sync, upload, convert, list. Proposing a converted rule as a change comes next.
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
         'URI': 'REQUEST_FILENAME', 'URI_FULL': 'REQUEST_URI', 'RAW_BODY': 'REQUEST_BODY'}
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
        if not arg or len(arg) > 4096 or re.search(r'[\x00\r\n]', arg) or re.search(r'\\(?:"|$)', arg):
            raise Unsupported('match_value_not_supported')
        # ModSecurity expands %{...} in these operators and may trim the ends; CrowdSec takes the value as it is
        if '%{' in arg or arg != arg.strip():
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
        else:
            variables.append(('&' if count else '') + target)
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


def convert(doc, first_id=0):
    """A hub rule file -> {'ok', 'text', 'rules' (how many ModSecurity rules), 'reason', 'details'}. The rules use ids
    first_id, first_id + 1, ...; they mark the request like a confident block (jt_block), which the system rules refuse."""
    try:
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
        texts = []
        for i, conds in enumerate(alts):
            rid = first_id + i
            first = ("id:%d,phase:2,pass,log,msg:'jt confident block: CrowdSec %s',tag:'jt-confident-block',tag:'crowdsec-hub',"
                     "tag:'%s'" % (rid, msg, tag))
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
        if not all(LINE_SHAPE.match(ln) for ln in text.split('\n')):
            raise Unsupported('unexpected_text')
        return {'ok': True, 'text': text, 'rules': len(alts), 'reason': None, 'details': {}}
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
    paths = [e['path'] for e in tree.get('tree') or [] if e.get('type') == 'blob' and _wanted(e.get('path') or '')]
    if len(paths) > MAX_FILES:
        raise ValueError('too many files')
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(4) as ex:       # a few at a time: about half a minute, not two
        got = list(ex.map(lambda p: fetch(RAW % (sha, urllib.parse.quote(p)), MAX_FILE), paths))
    files = dict(zip(paths, got))
    log('hub: %d files from commit %s' % (len(files), sha[:12]))
    return files, sha, 'github'


def _wanted(path):
    return path == 'LICENSE' or (path.startswith('appsec-rules/') and path.endswith('.yaml') and '..' not in path)


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
            raise ValueError('file too large: %s' % rel)
        total += size
        if total > MAX_UNPACKED or len(files) >= MAX_FILES:
            raise ValueError('archive unpacks too large')
        files[rel] = read()
    if data[:4] == b'PK\x03\x04':
        # the entry count from the end record, before zipfile reads the whole directory into memory
        eocd = data.rfind(b'PK\x05\x06', max(0, len(data) - 65558))
        if eocd < 0 or len(data) < eocd + 22:
            raise ValueError('not a readable zip archive')
        total = int.from_bytes(data[eocd + 10:eocd + 12], 'little')
        if total == 0xFFFF or data.rfind(b'PK\x06\x06') >= 0 or total > MAX_MEMBERS:
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
    for path in sorted(p for p in files if p.startswith('appsec-rules/')):
        raw = files[path]
        item = {'path': path, 'sha256': hashlib.sha256(raw).hexdigest()}
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
    return {'commit': commit, 'source': source, 'synced_at': util.iso(now), 'license': lic.decode('utf-8', 'replace')[:20000],
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
            got = download(log, fetch, have=(read_index(cfg) or {}).get('commit'))
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
