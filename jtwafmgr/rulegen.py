"""Rule templates -> SecRule text, static checks, and change direction.

Every generated rule has a fixed shape, the same as the hand-written site rules it replaces:

  confident block   SecRule <target> "@rx ..." "id:N,phase:1,pass,log,...,msg:'jt confident block: ...',
                    tag:'jt-confident-block',chain"  ...  SecRule REMOTE_ADDR "!@ipMatch <internal>"
                    "t:none,setvar:tx.jt_block=1,ctl:ruleEngine=On"
                    (the system rules add the critical score so that CRS's 949110 decides, and refuse
                    what stays under the threshold)
  exclusion         a phase-1 chain on Host / path / method / source ending in ctl:ruleRemove...
  redaction         ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:<field> for each field (not inspected,
                    so never copied into the audit log)
  plugin toggle     setvar:'tx.<plugin>-plugin_enabled=1' for one Host
  raw               expert mode: SecRule text as written, checked against a forbidden list
  country           Host -> REMOTE_ADDR "!@ipMatchFromFile <rules_dir>/<SET>.data" (allow: only these countries) or
                    "@ipMatchFromFile ..." (deny) -> REMOTE_ADDR "!@ipMatch <never blocked>" -> jt_block, like a
                    confident block; the list file is written by the root program (countries.py)
"""
import ipaddress
import os
import re
import subprocess
import sys

from .modsecconf import logical_lines, split_actions, split_args

KINDS = ('exclusion', 'confident_block', 'redaction', 'plugin', 'raw', 'country', 'pause', 'crowdsec')
EXCLUSION_ACTIONS = ('remove_target_by_id', 'remove_target_by_tag', 'remove_rule', 'remove_tag', 'score_only',
                     'body_processor')
BLOCK_TARGETS = {
    # target -> (variable, transformations)
    'path': ('REQUEST_FILENAME', 't:none,t:urlDecodeUni,t:normalizePath,t:lowercase'),
    'uri': ('REQUEST_URI', 't:none,t:urlDecodeUni,t:lowercase'),
    # the request target as sent, not decoded (0.4.93: e.g. an encoded "?" followed by "..", which hides the path from
    # REQUEST_FILENAME on libmodsecurity 3.0.9)
    'raw_uri': ('REQUEST_URI_RAW', 't:none,t:lowercase'),
    'ua': ('REQUEST_HEADERS:User-Agent', 't:none,t:lowercase'),
    'host': ('REQUEST_HEADERS:Host', 't:none,t:lowercase'),
    'header': (None, 't:none'),
}
TARGET_RE = re.compile(r'^(?:ARGS|ARGS_GET|ARGS_POST|ARGS_NAMES|ARGS_GET_NAMES|ARGS_POST_NAMES|REQUEST_COOKIES|'
                       r'REQUEST_COOKIES_NAMES|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|XML|REQUEST_BODY|REQUEST_URI|'
                       r'REQUEST_URI_RAW|REQUEST_FILENAME|REQUEST_BASENAME|FILES|FILES_NAMES|QUERY_STRING)'
                       r'(?::[A-Za-z0-9_.\-\[\]/@$^*|()?\\]{1,128})?$')
TAG_RE = re.compile(r'^[A-Za-z0-9_./\-]{1,80}$')
HEADER_RE = re.compile(r'^[A-Za-z0-9-]{1,64}$')
PLUGIN_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,63}$')
HOST_RE = re.compile(r'^(?:\*\.)?[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)*$')
SAFE_TEXT_RE = re.compile(r'^[^\'"\\\x00-\x1f\x7f]*$')
BENIGN = ['/', '/index.html', '/api/v1/items?page=2', '/static/app.3f9a.js', '/login',
          'mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/130.0 safari/537.36',
          'app.example.com', '/images/logo.png', '/search?q=hello+world']

# Expert mode: what a raw rule may never do (SPEC 5.6), plus what the apply program refuses too.
FORBIDDEN = [
    (re.compile(r'^\s*SecRuleEngine\s+Off\b', re.I | re.M), 'SecRuleEngine Off'),
    (re.compile(r'ctl:\s*ruleEngine\s*=\s*Off', re.I), 'ctl:ruleEngine=Off'),
    (re.compile(r'\bexec\s*:', re.I), 'exec action'),
    (re.compile(r'^\s*SecAudit\w*', re.I | re.M), 'audit settings'),
    (re.compile(r'ctl:\s*auditEngine', re.I), 'ctl:auditEngine'),
    (re.compile(r'ctl:\s*auditLogParts', re.I), 'ctl:auditLogParts'),
    (re.compile(r'^\s*SecRequestBodyAccess\s+Off\b', re.I | re.M), 'SecRequestBodyAccess Off'),
    (re.compile(r'\bsetenv\s*:', re.I), 'setenv'),
    (re.compile(r'^\s*Include\b', re.I | re.M), 'Include'),
    (re.compile(r'^\s*Sec(?:DataDir|TmpDir|UploadDir|DebugLog\w*|Collection\w*|Remote\w*|ComponentSignature|'
                r'ArgumentSeparator|CookieFormat|UnicodeMapFile|PcreMatchLimit\w*|RequestBody\w*|ResponseBody\w*|'
                r'StatusEngine|ServerSignature|HttpBlKey|GeoLookupDb|GsbLookupDb|WebAppId|Default\w*)\b',
                re.I | re.M), 'engine-wide setting'),
    # @pmFromFile / @ipMatchFromFile are allowed only for a .data file in the ModSecurity configuration
    # directory (e.g. the CRS's own lists): see _data_file_ok(); every other file-reading operator is refused
    (re.compile(r'@(?!(?:pm|ipMatch)FromFile\b)\w*FromFile\b', re.I), 'operators reading files'),
    (re.compile(r'@inspectFile\b', re.I), '@inspectFile'),
]
PAUSE_ENGINE = re.compile(r'ctl:\s*ruleEngine\s*=\s*DetectionOnly', re.I)
DATA_FILE_OP = re.compile(r'@(?:pm|ipMatch)FromFile\s+([^\s"\']+)', re.I)
DATA_FILE_DIRS = ('/etc/nginx/modsec/', '/etc/modsecurity/', '/usr/share/modsecurity-crs/')


def _data_file_ok(path, cfg=None):
    """A list file the rule reads: an absolute path to a .data file below a ModSecurity configuration
    directory, no '..', no URL (@pmFromFile can fetch https:// lists — never from here)."""
    if re.fullmatch(r'[\w.-]+\.data', path) and not path.startswith('.'):
        return True          # a bare file name: next to the rule file, inside the configuration directory
    if cfg is not None:      # a country list written by the root program (countries.rules_dir, from config.toml)
        d = cfg['countries']['rules_dir'].rstrip('/') + '/'
        rest = path[len(d):] if path.startswith(d) else ''
        if re.fullmatch(r'[A-Z]{2}(?:-[A-Z]{2}){0,49}\.data', rest):
            return True
    return (path.startswith('/') and path.endswith('.data') and '..' not in path.split('/')
            and re.fullmatch(r'[\w./-]+', path) is not None and any(path.startswith(d) for d in DATA_FILE_DIRS))


ALLOWED_DIRECTIVES = ('SecRule', 'SecAction', 'SecRuleRemoveById', 'SecRuleRemoveByTag', 'SecRuleRemoveByMsg',
                      'SecRuleUpdateTargetById', 'SecRuleUpdateTargetByTag', 'SecRuleUpdateActionById', 'SecMarker')


class SpecError(ValueError):
    def __init__(self, field, code, **details):
        super().__init__('%s: %s' % (field, code))
        self.field = field
        self.code = code
        self.details = details


def _ip_list(networks):
    return ','.join(str(n) if n.prefixlen != n.max_prefixlen or n.version == 4 else str(n.network_address)
                    for n in networks)


def _regex_ok(field, rx, allow_broad=False):
    if not isinstance(rx, str) or not rx.strip():
        raise SpecError(field, 'empty')
    if len(rx) > 1000:
        raise SpecError(field, 'too_long')
    if not SAFE_TEXT_RE.match(rx.replace('\\', '').replace("'", '')) or '"' in rx or '\n' in rx:
        raise SpecError(field, 'forbidden_character')
    # where Python's re (every check here) and ModSecurity's PCRE read a pattern differently: a macro %{...} is
    # expanded at run time by ModSecurity (an empty or attacker-chosen pattern), and [[:alnum:]] is a POSIX class in
    # PCRE but a set plus a literal ] in Python -- both would make the checks here meaningless
    if '%{' in rx or re.search(r'\[[:.=][a-z]*[:.=]\]', rx):
        raise SpecError(field, 'pcre_python_mismatch')
    try:
        c = re.compile(rx)
    except re.error as e:
        raise SpecError(field, 'invalid_regex', error=str(e)[:200])
    if not allow_broad:
        if c.search('') is not None:
            raise SpecError(field, 'matches_empty')
        if sum(1 for b in BENIGN if c.search(b)) >= len(BENIGN) - 2:
            raise SpecError(field, 'too_broad')
    if redos_shape(rx):
        raise SpecError(field, 'redos_shape')
    if not redos_runtime_ok(rx):
        raise SpecError(field, 'redos_runtime')
    return rx


def redos_shape(rx):
    """Nested quantifiers and quantified alternations of quantified branches: refuse the shape."""
    s = re.sub(r'\\.', 'x', rx)                     # drop escapes
    s = re.sub(r'\[[^\]]*\]', 'x', s)               # character classes -> one char
    # a group whose body ends with a quantifier, quantified again: (a+)+ (\w*)* (x{2,})+
    if re.search(r'\([^()]*[+*}]\)\s*[+*{]', s):
        return True
    # (a|ab)* style: quantified group with alternation where a branch is itself quantified
    for m in re.finditer(r'\(([^()]*\|[^()]*)\)\s*[+*{]', s):
        if re.search(r'[+*}]', m.group(1)):
            return True
    return False


_REDOS_OK = {}     # regex -> True (passed); only passes are remembered, a failure is checked again


def redos_runtime_ok(rx, timeout=2.0):
    """Run the regex on long hostile strings in a subprocess; False if it does not finish in time."""
    if _REDOS_OK.get(rx):
        return True
    ok = _redos_run(rx, timeout)
    if ok:
        if len(_REDOS_OK) > 5000:
            _REDOS_OK.clear()
        _REDOS_OK[rx] = True
    return ok


def _redos_run(rx, timeout):
    code = ('import re,sys\nr=re.compile(sys.stdin.read())\n'
            'for s in ("a"*20000+"!", "/"*20000+"x", "%2e"*5000+"\\x00", "a/"*10000, " "*20000+"x", "0"*20000+"z"):\n'
            '    r.search(s)\n')
    try:
        p = subprocess.run([sys.executable, '-I', '-c', code], input=rx, text=True, capture_output=True, timeout=timeout)
        return p.returncode == 0
    except subprocess.TimeoutExpired:
        return False


def _text_ok(field, s, maxlen=160, required=False):
    if s is None or s == '':
        if required:
            raise SpecError(field, 'required')
        return ''
    if not isinstance(s, str) or len(s) > maxlen or not SAFE_TEXT_RE.match(s):
        raise SpecError(field, 'invalid_text', max_length=maxlen)
    return s


# the Host header as nginx accepts it for the site: "name", "name." (a trailing dot), "name:443", "name.:443". A full URL
# in the request line ("GET http://name/ HTTP/1.1") routes by that URL, but nginx gives ModSecurity the path only, so no
# ModSecurity rule can see it: a site whose country limit must hold for such requests needs the check in nginx too.
HOST_RX_FMT = r'^%s\.?(?::[0-9]*)?$'


def _host_cond(host):
    """{'mode': 'exact'|'regex'|'any', 'value': ...} -> (variable, operator, transforms) or None"""
    if not host:
        return None
    if not isinstance(host, dict):
        raise SpecError('host', 'invalid_host_format', expected={'mode': 'exact', 'value': 'www.example.com'})
    if host.get('mode', 'any') == 'any':
        return None
    mode, v = host.get('mode'), (host.get('value') or '').strip().lower()
    if mode == 'exact':
        if not HOST_RE.match(v):
            raise SpecError('host', 'invalid_host')
        pat = re.escape(v).replace('\\*', '[^.]+') if v.startswith('*.') else re.escape(v)
        # nginx serves the site for its name with a trailing dot too ("example.com."): that form must match, or a rule
        # scoped to the site (a country limit, a block) is skipped for it
        return ('REQUEST_HEADERS:Host', '@rx ' + HOST_RX_FMT % pat.replace('\\-', '-'), 't:none,t:lowercase')
    if mode == 'regex':
        _regex_ok('host', v)
        return ('REQUEST_HEADERS:Host', '@rx ' + v, 't:none,t:lowercase')
    raise SpecError('host', 'invalid_mode')


def _path_cond(path, negate=False):
    if not path:
        return None
    if not isinstance(path, dict):
        raise SpecError('path', 'invalid_path_format', expected={'mode': 'exact', 'value': '/login'})
    if path.get('mode', 'any') == 'any':
        return None
    mode, v = path.get('mode'), path.get('value') or ''
    if mode in ('exact', 'prefix'):
        if not v.startswith('/') or len(v) > 512 or re.search(r'[\s"\'\\\x00-\x1f\x7f]', v):
            raise SpecError('path', 'invalid_path')
        op = '@streq ' if mode == 'exact' else '@beginsWith '
        return ('REQUEST_FILENAME', ('!' if negate else '') + op + v, 't:none')
    if mode == 'regex':
        _regex_ok('path', v)
        return ('REQUEST_FILENAME', ('!' if negate else '') + '@rx ' + v, 't:none')
    raise SpecError('path', 'invalid_mode')


# The path a person scopes an exclusion (or a redaction) to must hold both as sent and normalised: "/a/../admin" is no
# "/a/" path (normalised it is "/admin"), and "/x/../a/b" is no "/a/" path either (as sent) -- never wider than the path
# as written.
PATH_COND_TRANSFORMS = 't:none,t:normalizePath'
# libmodsecurity 3.0.9 cuts REQUEST_FILENAME at an encoded "?" (%3F) of the path ("/json/messages%3F/../../admin" is
# "/json/messages" to it, while the backend gets "/admin"); 3.0.14 does not. An exclusion never applies to such a
# request: it is inspected in full.
PATH_CUT_GUARD = ('REQUEST_URI_RAW', '!@rx ^[^?#]*%3[fF]', 't:none')
# A path rule looks at REQUEST_FILENAME and at the path of the raw request target, captured here (TX:1, up to the
# query; an absolute-form "scheme://host" prefix left out): what was cut at an encoded "?" is seen whole, so
# "/x%3F/../.env" is "/.env" to the rule as it is to the backend.
PATH_CAPTURE = ('REQUEST_URI_RAW', '@rx ^(?:[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#]*)?([^?#]*)', 't:none,capture')
PATH_VARS = 'REQUEST_FILENAME|TX:1'
# A confident block (target raw_uri) that covers rules entered as text: an encoded "?" in the path followed later by a
# "../" segment (encoded or not) -- what hides a path from REQUEST_FILENAME on libmodsecurity 3.0.9 and still reaches it
# at the backend. Matched against the raw request target, lowercase.
PATH_GUARD_REGEX = r'^[^?#]*%3f[^?#]*(?:/|%2f|%5c)(?:\.|%2e){2}(?:/|%2f|%5c|$|\?|#)'
# The exception condition of a confident block: both views of the path must be exempted (normalised: "/share/../.env"
# is no "/share/" path)
EXCEPTION_TRANSFORMS = 't:none,t:urlDecodeUni,t:normalizePath,t:lowercase'


def _scoped_path(path_cond):
    """The conditions of an exclusion / redaction path scope: the path as sent and normalised, and no encoded "?"."""
    return [path_cond, (path_cond[0], path_cond[1], PATH_COND_TRANSFORMS), PATH_CUT_GUARD] if path_cond else []


def _source_cond(source, internal):
    if source in (None, '', 'all'):
        return None
    if source == 'internal':
        return ('REMOTE_ADDR', '@ipMatch ' + internal, 't:none')
    if source == 'external':
        return ('REMOTE_ADDR', '!@ipMatch ' + internal, 't:none')
    raise SpecError('source', 'invalid_source')


def _chain(conds, first_actions, final_actions):
    """conds: [(var, op, transforms)], at least one. Returns SecRule text (continuation lines)."""
    lines = []
    n = len(conds)
    for i, (var, op, tr) in enumerate(conds):
        ind = '    ' * i
        acts = []
        if i == 0:
            acts.append(first_actions)
        acts.append(tr)
        if i < n - 1:
            acts.append('chain')
        else:
            if final_actions:
                acts.append(final_actions)
        a = ','.join(x for x in acts if x)
        lines.append('%sSecRule %s "%s" \\\n%s    "%s"' % (ind, var, op.replace('"', '\\"'), ind, a))
    return '\n'.join(lines)


def build(kind, spec, rule_id, cfg):
    """Returns (normalized spec, rule text, placement). Raises SpecError -- also for a field of the wrong type (a string
    where an object belongs: an API caller gets 422 naming the problem, never a 500)."""
    if not isinstance(spec, dict):
        raise SpecError('spec', 'invalid_spec', expected='object')
    try:
        return _build(kind, spec, rule_id, cfg)
    except (AttributeError, TypeError, KeyError) as e:
        import traceback
        traceback.print_exc()           # (in the service's journal: a check that should name the field is missing)
        raise SpecError('spec', 'invalid_spec', error=type(e).__name__, detail=str(e)[:120])


def _build(kind, spec, rule_id, cfg):
    internal = _ip_list(cfg.internal_networks)
    if kind == 'exclusion':
        return _exclusion(spec, rule_id, cfg, internal)
    if kind == 'confident_block':
        return _confident(spec, rule_id, cfg, internal)
    if kind == 'redaction':
        return _redaction(spec, rule_id, cfg)
    if kind == 'plugin':
        return _plugin(spec, rule_id)
    if kind == 'raw':
        return _raw(spec, rule_id, cfg)
    if kind == 'country':
        return _country(spec, rule_id, cfg)
    if kind == 'pause':
        return _pause(spec, rule_id, cfg)
    if kind == 'crowdsec':
        return _crowdsec(spec, rule_id, cfg, internal)
    raise SpecError('kind', 'unknown_kind')


PAUSE_ACTION = 'ctl:ruleEngine=DetectionOnly'
PAUSE_IDS = (10090, 10091)


def pause_ids(cfg=None):
    ids = (cfg['waf'].get('pause_ids') if cfg is not None else None) or PAUSE_IDS
    return int(ids[0]), int(ids[1])


def pause_removals(cfg):
    """The rule id ranges a pause takes out of the request: the whole local range except the exclusions (they keep
    CRS's own false positives out of the log, and keep secrets out of it) and the pause rules themselves. A paused site's
    blocks switch the engine back on with ctl:ruleEngine=On (confident blocks, country limits, the CRS score refusal on
    a DetectionOnly engine), so detection only is not enough on its own."""
    lo, hi = cfg['waf']['local_range']
    keep = [tuple(cfg['waf']['exclusion_range'])] + [(i, i) for i in pause_ids(cfg)]
    out, cur = [], lo
    for a, b in sorted(keep):
        if a > cur:
            out.append((cur, min(a - 1, hi)))
        cur = max(cur, b + 1)
    if cur <= hi:
        out.append((cur, hi))
    return ','.join('ctl:ruleRemoveById=%d-%d' % (a, b) for a, b in out if a <= b)


def _pause(spec, rid, cfg):
    """The troubleshooting switch (pause.py): ModSecurity only detects -- logs, never refuses -- for every site
    (scope all) or for the listed sites. With nothing paused the rule stays as a no-op, so its id and place at the top
    of the file stay the same and resuming is one plain edit."""
    scope = spec.get('scope')
    if scope not in ('all', 'sites'):
        raise SpecError('scope', 'invalid_scope')
    if rid not in pause_ids(cfg):
        raise SpecError('rule_id', 'not_a_pause_id')
    first = {'first': True}
    elo, ehi = cfg['waf']['exclusion_range']
    extra = sorted({int(i) for i in spec.get('also_remove') or [] if isinstance(i, int) and not isinstance(i, bool)
                    and elo <= i <= ehi})[:100]
    off = PAUSE_ACTION + ',' + pause_removals(cfg) + ''.join(',ctl:ruleRemoveById=%d' % i for i in extra)
    first = dict(first, also_remove=extra) if extra else first
    if scope == 'all':
        on = bool(spec.get('active'))
        keep = {k: spec.get(k) for k in ('since', 'until', 'by', 'reason') if on and spec.get(k) is not None}
        text = 'SecAction "id:%d,phase:1,pass,nolog%s"' % (rid, ',' + off if on else '')
        return dict(first, scope='all', active=on, **keep), text, 'before'
    sites, seen = [], set()
    for s in spec.get('sites') or []:
        h = str((s or {}).get('host') or '').strip().lower().rstrip('.')
        if not HOST_RE.match(h) or h.startswith('*.') or h in seen:
            raise SpecError('host', 'invalid_host', host=h[:100])
        seen.add(h)
        sites.append(dict({k: s.get(k) for k in ('since', 'until', 'by', 'reason') if s.get(k) is not None}, host=h))
    if len(sites) > 200:
        raise SpecError('sites', 'too_many')
    match = spec.get('match') or 'host'
    if match not in ('txid', 'host'):
        raise SpecError('match', 'invalid_match')
    if not sites:
        return dict(first, scope='sites', sites=[], match=match), 'SecAction "id:%d,phase:1,pass,nolog"' % rid, 'before'
    alt = '(?:%s)' % '|'.join(re.escape(s['host']).replace('\\-', '-') for s in sites)
    if match == 'txid':
        # the transaction id is nginx's "$host-$request_id": the site nginx chose, also for a request line with a full
        # URL (whose Host header can name another site)
        cond = ('UNIQUE_ID', '@rx ^%s\\.?-[0-9a-f]{32}$' % alt, 't:none,t:lowercase')
    else:
        cond = ('REQUEST_HEADERS:Host', '@rx ' + HOST_RX_FMT % alt, 't:none,t:lowercase')
    text = _chain([cond], 'id:%d,phase:1,pass,nolog' % rid, off)
    return dict(first, scope='sites', sites=sites, match=match), text, 'before'


def never_list(cfg):
    """Addresses a country rule never refuses: the internal networks, the known scanners, the trusted proxies and
    the protected list (a CDN in front of a site: its own addresses are in no country list of the site's users)."""
    nets = list(cfg.internal_networks) + list(cfg.known_scanners) + list(cfg.trusted_proxies)
    for x in cfg['blocks'].get('protected') or []:
        try:
            nets.append(ipaddress.ip_network(str(x), strict=False))
        except ValueError:
            continue
    seen, out = set(), []
    for n in nets:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _country(spec, rid, cfg):
    """One site's country limit: mode 'allow' (only these countries) or 'deny' (not these countries).
    The list file is written by the root program from the registries' data (countries.py)."""
    from .countries import DataError, set_name
    host = spec.get('host') or {}
    if host.get('mode') != 'exact':
        raise SpecError('host', 'scope_required')        # a country limit is per site, named exactly
    h = _host_cond(host)
    mode = spec.get('mode')
    if mode not in ('allow', 'deny'):
        raise SpecError('mode', 'invalid_mode')
    try:
        name = set_name(spec.get('countries') or [])
    except DataError:
        raise SpecError('countries', 'invalid_countries', limit=50)
    note = _text_ok('note', spec.get('note'), 160)
    path = os.path.join(cfg['countries']['rules_dir'], name + '.data')
    conds = [h, ('REMOTE_ADDR', ('!' if mode == 'allow' else '') + '@ipMatchFromFile ' + path, 't:none')]
    never = never_list(cfg)
    if never:
        conds.append(('REMOTE_ADDR', '!@ipMatch ' + _ip_list(never), 't:none'))
    what = ('only ' if mode == 'allow' else 'from ') + ' '.join(name.split('-')[:12]) + (' ...' if name.count('-') >= 12 else '')
    first = "id:%d,phase:1,pass,log,msg:'jt country block: %s',tag:'jt-country-block'" % (rid, what)
    text = _chain(conds, first, 'setvar:tx.jt_block=1,ctl:ruleEngine=On')
    norm = {'host': {'mode': host.get('mode'), 'value': (host.get('value') or '').strip().lower()}, 'mode': mode,
            'countries': name.split('-'), 'note': note}
    return norm, text, 'before'


CROWDSEC_MAX_HOSTS = 20


def _license_lines(text, commit=None):
    """The hub's LICENSE as comment lines: printable, no backslash (a trailing one would join the next line). Only an MIT
    licence text is copied (the file comes from the internet: words the expert-mode checks refuse, or anything else, are
    replaced by where to read it)."""
    t = text or ''
    if not (t.lstrip().startswith('MIT License') and 'Permission is hereby granted, free of charge' in t and len(t) <= 4000) or \
            any(rx.search(t) for rx, _ in FORBIDDEN):
        return ['# licence: https://github.com/crowdsecurity/hub/blob/%s/LICENSE' % (commit or 'master')]
    out = []
    for ln in (text or '').splitlines()[:60]:
        ln = re.sub(r'[^\x20-\x7e]', '', ln).replace('\\', '/').rstrip()[:200]
        out.append(('# ' + ln) if ln else '#')
    return out


def _crowdsec(spec, rid, cfg, internal):
    """A CrowdSec Hub rule (hub.py) for the listed sites: the hub's YAML is kept in the spec and converted again here,
    so the rule text always follows from what was proposed and approved. The workflow fills yaml, sha256, commit,
    license and tests from the synced index; only name, hosts, source and note come from the person."""
    import hashlib
    from . import hub, miniyaml
    name = spec.get('name') or ''
    if not isinstance(name, str) or not hub.NAME_RE.match(name):
        raise SpecError('name', 'invalid_name')
    raw = spec.get('yaml')
    if not isinstance(raw, str) or not raw or len(raw) > hub.MAX_FILE:
        raise SpecError('yaml', 'invalid_yaml')
    sha = hashlib.sha256(raw.encode('utf-8')).hexdigest()
    if spec.get('sha256') != sha:
        raise SpecError('sha256', 'sha256_mismatch')
    commit = spec.get('commit')
    if commit is not None and not (isinstance(commit, str) and re.fullmatch(r'[0-9a-f]{7,40}', commit)):
        raise SpecError('commit', 'invalid_commit')
    all_sites = spec.get('all_sites') is True
    hosts = spec.get('hosts') or []
    if all_sites:
        if hosts:
            raise SpecError('hosts', 'all_sites_with_hosts')
    elif not isinstance(hosts, list) or not 1 <= len(hosts) <= CROWDSEC_MAX_HOSTS:
        raise SpecError('hosts', 'scope_required', limit=CROWDSEC_MAX_HOSTS)
    hosts = sorted({str(h).strip().lower() for h in hosts})
    pats = []
    for h in hosts:
        if not HOST_RE.match(h):
            raise SpecError('hosts', 'invalid_host', host=h[:80])
        pats.append((re.escape(h).replace('\\*', '[^.]+') if h.startswith('*.') else re.escape(h)).replace('\\-', '-'))
    # the site named by the Host header OR by the transaction id nginx gives ModSecurity ("$host-$request_id", the site
    # nginx chose: a full URL in the request line or HTTP/2's :authority cannot hide behind another Host header). Either
    # one applies the rule (a block: the wider the better); without that transaction id format only the Host header counts
    head = [('REQUEST_HEADERS:Host|UNIQUE_ID', '@rx ^(?:%s)\\.?(?:(?::[0-9]*)?|-[0-9a-f]{32})$' % '|'.join(pats),
             't:none,t:lowercase')] if not all_sites else []    # all sites: a framework's flaw, wherever it runs
    source = spec.get('source') or 'external'
    if source == 'external':
        tail = [('REMOTE_ADDR', '!@ipMatch ' + internal, 't:none')]
    elif source == 'all':
        tail = [('REMOTE_ADDR', '!@ipMatch ' + _ip_list(cfg.known_scanners), 't:none')] if cfg.known_scanners else []
    else:
        raise SpecError('source', 'invalid_source')
    note = _text_ok('note', spec.get('note'), 160)
    lic = spec.get('license') or ''
    if not isinstance(lic, str) or len(lic) > 8000:
        raise SpecError('license', 'invalid_license')
    try:
        doc = miniyaml.loads(raw.encode('utf-8'))
        if not isinstance(doc, dict) or doc.get('name') != name:
            raise SpecError('yaml', 'name_mismatch')
        body, n = hub.render(doc, rid, head, tail)
    except miniyaml.YamlError as e:
        raise SpecError('yaml', 'invalid_yaml', error=str(e)[:200])
    except hub.Unsupported as e:
        raise SpecError('yaml', 'not_convertible', reason=e.why)
    lo, hi = cfg['waf']['hub_range']
    if not (lo <= rid and rid + n - 1 <= hi):
        raise SpecError('rule_id', 'id_range_full')
    head_lines = ['# CrowdSec Hub appsec rule %s (github.com/crowdsecurity/hub%s, %s sha256 %s)' % (
                      name, ' commit ' + commit if commit else '', 'appsec-rules file', sha),
                  '# converted to ModSecurity by jt-waf-mgr for: %s' % ('all sites' if all_sites else ' '.join(hosts)[:300])]
    if lic:
        head_lines.append('# The CrowdSec Hub licence (MIT):')
        head_lines += _license_lines(lic, commit)
    text = '\n'.join(head_lines) + '\n' + body
    if len(text) > 64 * 1024:
        raise SpecError('yaml', 'not_convertible', reason='too_long')
    tests = spec.get('tests') or []
    if not isinstance(tests, list) or len(tests) > hub.MAX_TESTS:
        raise SpecError('tests', 'invalid_tests')
    norm = {'name': name, 'yaml': raw, 'sha256': sha, 'commit': commit, 'hosts': hosts, 'all_sites': all_sites,
            'source': source, 'note': note,
            'license': lic, 'tests': tests, 'rule_count': n, 'fp_warning': bool(spec.get('fp_warning'))}
    if spec.get('before_rule_id'):
        norm['before_rule_id'] = spec['before_rule_id']
    return norm, text, 'before'


def _exclusion(spec, rid, cfg, internal):
    action = spec.get('action', 'remove_target_by_id')
    if action not in EXCLUSION_ACTIONS:
        raise SpecError('action', 'invalid_action')
    host, path = _host_cond(spec.get('host')), _path_cond(spec.get('path'))
    if not host and not path:
        raise SpecError('host', 'scope_required')   # global exclusions only in expert mode
    method = (spec.get('method') or '').upper()
    if method and not re.fullmatch(r'[A-Z]{3,10}', method):
        raise SpecError('method', 'invalid_method')
    src = _source_cond(spec.get('source'), internal)
    ids = spec.get('rule_ids') or []
    if not isinstance(ids, list) or not all(isinstance(x, int) and 1 <= x <= 99999999 for x in ids) or len(ids) > 20:
        raise SpecError('rule_ids', 'invalid_rule_ids')
    targets = spec.get('targets') or []
    if not isinstance(targets, list) or len(targets) > 20 or not all(isinstance(t, str) and TARGET_RE.match(t) for t in targets):
        raise SpecError('targets', 'invalid_targets')
    tag = spec.get('tag') or ''
    ctl = []
    if action == 'remove_target_by_id':
        if not ids or not targets:
            raise SpecError('targets', 'rule_ids_and_targets_required')
        ctl = ['ctl:ruleRemoveTargetById=%d;%s' % (i, t) for i in ids for t in targets]
    elif action == 'remove_target_by_tag':
        if not TAG_RE.match(tag) or not targets:
            raise SpecError('tag', 'tag_and_targets_required')
        ctl = ['ctl:ruleRemoveTargetByTag=%s;%s' % (tag, t) for t in targets]
    elif action == 'remove_rule':
        if not ids:
            raise SpecError('rule_ids', 'required')
        ctl = ['ctl:ruleRemoveById=%d' % i for i in ids]
    elif action == 'remove_tag':
        if not TAG_RE.match(tag):
            raise SpecError('tag', 'invalid_tag')
        if not spec.get('confirm_tag'):
            raise SpecError('tag', 'confirmation_required')
        ctl = ['ctl:ruleRemoveByTag=%s' % tag]
    elif action == 'score_only':
        ctl = ['ctl:ruleRemoveById=%d' % i for i in cfg['waf']['threshold_rule_ids']]
        if not ctl:
            raise SpecError('action', 'no_threshold_rule')
    elif action == 'body_processor':
        bp = spec.get('body_processor')
        if bp not in ('JSON', 'XML', 'URLENCODED', 'MULTIPART'):
            raise SpecError('body_processor', 'invalid_body_processor')
        ctl = ['ctl:requestBodyProcessor=%s' % bp]
    conds = ([host] if host else []) + _scoped_path(path)
    if method:
        conds.append(('REQUEST_METHOD', '@streq ' + method, 't:none'))
    if src:
        conds.append(src)
    text = _chain(conds, 'id:%d,phase:1,pass,nolog' % rid, ','.join(ctl))
    norm = {'host': spec.get('host') or {'mode': 'any'}, 'path': spec.get('path') or {'mode': 'any'},
            'method': method, 'source': spec.get('source') or 'all', 'action': action, 'rule_ids': ids,
            'targets': targets, 'tag': tag, 'body_processor': spec.get('body_processor') or '',
            'confirm_tag': bool(spec.get('confirm_tag'))}
    return norm, text, 'before'


def _confident(spec, rid, cfg, internal):
    target = spec.get('target', 'path')
    if target not in BLOCK_TARGETS:
        raise SpecError('target', 'invalid_target')
    var, tr = BLOCK_TARGETS[target]
    if target == 'header':
        h = spec.get('header') or ''
        if not HEADER_RE.match(h):
            raise SpecError('header', 'invalid_header')
        var = 'REQUEST_HEADERS:' + h
    rx = _regex_ok('regex', spec.get('regex'))
    msg = _text_ok('msg', spec.get('msg'), 100, required=True)
    ref = _text_ok('reference', spec.get('reference'), 200)
    exc = spec.get('exceptions') or []
    if not isinstance(exc, list) or len(exc) > 10:
        raise SpecError('exceptions', 'invalid_exceptions')
    for e in exc:
        _regex_ok('exceptions', e, allow_broad=True)
    conds = [(PATH_VARS if target == 'path' else var, '@rx ' + rx, tr)]
    if exc:
        conds.append((PATH_VARS, '!@rx ' + '|'.join('(?:%s)' % e for e in exc), EXCEPTION_TRANSFORMS))
    if target == 'path' or exc:
        conds.insert(0, PATH_CAPTURE)
    h = _host_cond(spec.get('host'))
    if h:
        conds.append(h)
    # source: 'external' (default) -- internal addresses are never blocked; 'all' -- internal addresses too,
    # except the known scanners (their list is written into the rule as it is at this moment)
    source = spec.get('source') or 'external'
    if source == 'external':
        conds.append(('REMOTE_ADDR', '!@ipMatch ' + internal, 't:none'))
    elif source == 'all':
        if cfg.known_scanners:
            conds.append(('REMOTE_ADDR', '!@ipMatch ' + _ip_list(cfg.known_scanners), 't:none'))
    else:
        raise SpecError('source', 'invalid_source')
    first = "id:%d,phase:1,pass,log,msg:'jt confident block: %s',tag:'jt-confident-block'" % (rid, msg)
    text = _chain(conds, first, 'setvar:tx.jt_block=1,ctl:ruleEngine=On')
    norm = {'target': target, 'header': spec.get('header') or '', 'regex': rx, 'exceptions': exc,
            'host': spec.get('host') or {'mode': 'any'}, 'msg': msg, 'reference': ref, 'source': source}
    return norm, text, 'before'


def _redaction(spec, rid, cfg):
    fields = spec.get('fields') or []
    if not isinstance(fields, list) or not fields or len(fields) > 30 or not all(
            isinstance(f, str) and re.fullmatch(r'[A-Za-z0-9_.\-\[\]]{1,64}', f) for f in fields):
        raise SpecError('fields', 'invalid_fields')
    # the CrowdSec Hub's rules (tag crowdsec-hub) look at ARGS_GET / ARGS_POST and a JSON body's json.<name> as well:
    # those are taken out for them too (tested with libmodsecurity 3.0.9), so a redacted field is never inspected or logged
    ctl = ','.join('ctl:ruleRemoveTargetByTag=OWASP_CRS;ARGS:%s' % f for f in fields) + ',' + ','.join(
        'ctl:ruleRemoveTargetByTag=crowdsec-hub;%s' % t for f in fields
        for t in ('ARGS_GET:%s' % f, 'ARGS_POST:%s' % f, 'ARGS:json.%s' % f))
    host, path = _host_cond(spec.get('host')), _path_cond(spec.get('path'))
    conds = ([host] if host else []) + _scoped_path(path)
    if conds:
        text = _chain(conds, 'id:%d,phase:1,pass,nolog' % rid, ctl)
    else:
        text = 'SecAction "id:%d,phase:1,pass,nolog,t:none,\\\n    %s"' % (rid, ',\\\n    '.join(ctl.split(',')))
    return {'fields': fields, 'host': spec.get('host') or {'mode': 'any'}, 'path': spec.get('path') or {'mode': 'any'}}, text, 'before'


def _plugin(spec, rid):
    name = spec.get('plugin') or ''
    if not PLUGIN_RE.match(name):
        raise SpecError('plugin', 'invalid_plugin')
    host = _host_cond(spec.get('host'))
    if not host:
        raise SpecError('host', 'scope_required')
    text = _chain([host], 'id:%d,phase:1,pass,nolog' % rid, "setvar:'tx.%s-plugin_enabled=1'" % name)
    return {'plugin': name, 'host': spec.get('host')}, text, 'before'


def check_raw_text(text, allow_ids=None, cfg=None):
    """Expert / imported text: only rule directives, nothing from FORBIDDEN. Returns the rule ids."""
    if not isinstance(text, str) or not text.strip():
        raise SpecError('text', 'empty')
    if len(text) > 20000 or '\x00' in text:
        raise SpecError('text', 'too_long')
    if PAUSE_ENGINE.search(text):
        # switching the engine to detection only is the pause switch's alone (and it has its own two rule ids)
        ids = [int(x) for x in re.findall(r'\bid\s*:\s*(\d+)', text)]
        if not ids or any(i not in pause_ids(cfg) for i in ids):
            raise SpecError('text', 'forbidden', what='ctl:ruleEngine=DetectionOnly')
    for rx, what in FORBIDDEN:
        if rx.search(text):
            raise SpecError('text', 'forbidden', what=what)
    for m in DATA_FILE_OP.finditer(text):
        if not _data_file_ok(m.group(1), cfg):
            raise SpecError('text', 'forbidden', what='operators reading files outside the ModSecurity data directories')
    ids = []
    for _, s, _ in logical_lines(text):
        words = split_args(s)
        if not words:
            continue
        if words[0] not in ALLOWED_DIRECTIVES:
            raise SpecError('text', 'directive_not_allowed', directive=words[0][:40])
        if words[0] in ('SecRule', 'SecAction'):
            acts = split_actions(words[-1]) if len(words) > (3 if words[0] == 'SecRule' else 1) else []
            own, removes = [], []
            for k, v in acts:
                if k == 'id':
                    try:
                        own.append(int(v.strip("'\"")))
                    except ValueError:
                        raise SpecError('text', 'invalid_id')
                if k == 'ctl' and re.match(r'(?i)rule(?:Remove(?:ById|ByTag)|RemoveTarget\w*)=', v) and cfg is not None:
                    removes.append(v.split('=', 1)[1].split(';')[0])
            ids += own
            # the system rules (the score refusal and its fallback) are never taken out -- a range ("10200-19999")
            # counts too; only the pause switch's own rules take its ranges out, for the request they pause
            if removes and not (own and all(i in pause_ids(cfg) for i in own)):
                hit = _removed_system(removes, cfg)
                if hit is not None:
                    raise SpecError('text', 'removes_system_rule', rule_id=hit)
        if words[0] == 'SecRuleRemoveById' and cfg is not None:
            hit = _removed_system([p for w in words[1:] for p in w.split(',')], cfg)
            if hit is not None:
                raise SpecError('text', 'removes_system_rule', rule_id=hit)
    return ids


def _removed_system(targets, cfg):
    """The first system rule id a list of rule-removal targets ("10299", "10200-19999") takes out, or None."""
    sysids = set(cfg['waf']['fallback_rule_ids']) | set(cfg['waf']['score_rule_ids'])
    for tgt in targets:
        m = re.fullmatch(r'\s*(\d+)\s*(?:-\s*(\d+)\s*)?', tgt or '')
        if not m:
            continue
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        for i in sorted(sysids):
            if a <= i <= b:
                return i
    return None


def _raw(spec, rid, cfg):
    text = spec.get('text') or ''
    placement = spec.get('placement', 'before')
    if placement not in ('before', 'after'):
        raise SpecError('placement', 'invalid_placement')
    ids = check_raw_text(text, cfg=cfg)
    if any(i in pause_ids(cfg) for i in ids):
        # the pause switch's two ids: a rule of its own there would be a pause nobody sees, and would block the switch
        raise SpecError('rule_id', 'pause_reserved')
    lo, hi = cfg['waf']['local_range']
    for i in ids:
        if not lo <= i <= hi:
            raise SpecError('text', 'id_out_of_range', rule_id=i)
    if len(ids) > 1:
        raise SpecError('text', 'one_rule_per_change')
    if rid is not None and ids and ids[0] != rid:
        raise SpecError('text', 'id_mismatch', rule_id=ids[0])
    norm = {'text': text.strip('\n'), 'placement': placement}
    # where a new rule goes: at the end of its file (default), or right before another managed rule
    before = spec.get('before_rule_id')
    if before not in (None, ''):
        if not isinstance(before, int) or isinstance(before, bool) or before <= 0:
            raise SpecError('before_rule_id', 'invalid_rule_id')
        norm['before_rule_id'] = before
    return norm, text.strip('\n'), placement


def raw_direction(text):
    t = text
    loosen = re.search(r'ctl:\s*rule(?:Remove|Engine\s*=\s*(?:Off|DetectionOnly))|SecRuleRemove|SecRuleUpdateTarget|'
                       r'ctl:\s*requestBodyProcessor|plugin_enabled\s*=\s*1|\ballow\b', t, re.I)
    tighten = re.search(r'\bdeny\b|\bdrop\b|ctl:\s*ruleEngine\s*=\s*On|jt_block\s*=\s*1', t, re.I)
    return 'tighten' if tighten and not loosen else 'loosen'


def host_matches(host, h):
    """Whether a rule's host scope ({'mode': 'any'|'exact'|'regex', 'value'}) covers request host h (the
    condition _host_cond writes, in Python). A pattern Python cannot read counts as covering it."""
    host = host or {}
    mode, v = host.get('mode', 'any'), (host.get('value') or '').strip().lower()
    h = (h or '').strip().lower()
    if mode == 'any' or not mode:
        return True
    if mode == 'exact':
        pat = re.escape(v).replace('\\*', '[^.]+') if v.startswith('*.') else re.escape(v)
        return re.fullmatch(pat + r'\.?(?::[0-9]*)?', h) is not None
    try:
        return re.search(v, h) is not None
    except re.error:
        return True


def _never_in(text):
    m = re.search(r'REMOTE_ADDR "!@ipMatch ([^"]*)"', text or '')
    return set(m.group(1).split(',')) if m else set()


def country_modify_direction(old, new, old_text=None, new_text=None):
    """A changed country limit tightens only when it covers the same site the same way and refuses at least
    what it refused before: fewer allowed countries, or more blocked ones, and no address added to the ones it
    never refuses (the rule text is rebuilt with today's internal networks, scanners, proxies and protected
    list). Anything else loosens."""
    if old_text is not None and new_text is not None and not _never_in(new_text) <= _never_in(old_text):
        return 'loosen'

    def site(s):
        h = s.get('host') or {}
        return (h.get('mode') or 'any', (h.get('value') or '').strip().lower())
    if not old or not new or site(old) != site(new) or old.get('mode') != new.get('mode'):
        return 'loosen'
    a, b = set(old.get('countries') or []), set(new.get('countries') or [])
    if new.get('mode') == 'allow':
        return 'tighten' if b and b <= a else 'loosen'
    if new.get('mode') == 'deny':
        return 'tighten' if b >= a else 'loosen'
    return 'loosen'


def direction(op, kind, text=''):
    """SPEC 6.1: tightening vs loosening. Anything unclear counts as loosening."""
    tightening_kind = kind in ('confident_block', 'country', 'crowdsec') or (kind == 'raw' and raw_direction(text) == 'tighten')
    if op == 'add':
        return 'tighten' if tightening_kind else 'loosen'
    if op in ('disable', 'delete'):
        return 'loosen' if tightening_kind else 'tighten'
    if op == 'enable':
        return 'tighten' if tightening_kind else 'loosen'
    return 'loosen'   # modify
