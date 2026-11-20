"""nginx's own security advisories (nginx.org/en/security_advisories.html) against the installed nginx (0.4.98).

Flaws in nginx itself -- HTTP/2 or HTTP/3 framing, the resolver, the mail and stream modules -- happen before a request
reaches ModSecurity: no rule can refuse them; only an nginx update (or switching the feature off) helps. The nginx
update job (nginxup.py, which already reaches nginx.org for the packages) reads the advisories page each run:

- which advisories the installed nginx is vulnerable to, and whether this configuration uses the feature each one is
  about (HTTP/2, HTTP/3, resolver, mail, stream, PROXY protocol, ssl_preread, SSI, alias, TLS session ticket keys);
- an alert ("nginx security update"; critical for a major one in a feature in use), with the version that fixes them
  and whether the update is ready (the module verified); the update itself is still a change an administrator approves;
- threat intelligence threats for nginx with a CVE the page lists are decided by it: the installed version is not
  vulnerable -> set aside (the model's or NVD's guess no longer stays "affects us").

The page is data from outside: parsed with fixed patterns, kept as plain values, never shown as markup.
"""
import json
import os
import re
import time
import urllib.request

from . import util

URL = 'https://nginx.org/en/security_advisories.html'
CACHE = 'advisories.json'
MAX_PAGE = 1024 * 1024
MAX_ADVISORIES = 400
CVE_RE = re.compile(r'CVE-(?:CVE-)?(\d{4}-\d{4,7})')
_VER = re.compile(r'\d+\.\d+(?:\.\d+)?')

# advisory title -> the configuration feature it needs (None: any nginx serving HTTP)
def _word(w):
    # a word of its own, also inside a module name (ngx_http_mp4_module): letters and digits around it end it
    return r'(?<![a-z0-9])' + w + r'(?![a-z0-9])'


FEATURES = (
    (re.compile(r'http/2|' + _word('spdy'), re.I), 'http2'),
    (re.compile(r'http/3|' + _word('quic'), re.I), 'http3'),
    (re.compile(_word('resolver'), re.I), 'resolver'),
    (re.compile(_word('mail') + '|' + _word('smtp') + '|' + _word('imap') + '|' + _word('pop3'), re.I), 'mail'),
    (re.compile(r'ssl_preread', re.I), 'ssl_preread'),
    (re.compile(_word('stream'), re.I), 'stream'),
    (re.compile(r'proxy[ _]protocol', re.I), 'proxy_protocol'),
    (re.compile(_word('ssi'), re.I), 'ssi'),
    (re.compile(_word('alias'), re.I), 'alias'),
    (re.compile(r'session[ _]ticket', re.I), 'ssl_session_ticket_key'),
    (re.compile(_word('mp4'), re.I), 'mp4'),
    (re.compile(_word('dav') + '|webdav', re.I), 'dav'),
)


def base(cfg):
    from .nginxup import base as b
    return b(cfg)


def _v(s):
    m = _VER.fullmatch((s or '').strip())
    if not m:
        return None
    t = tuple(int(x) for x in m.group(0).split('.'))
    return t + (0,) * (3 - len(t))


def parse(html):
    """The advisories on the page: [{'title', 'severity', 'cves', 'not_vulnerable', 'vulnerable', 'advisory'}]."""
    out = []
    # item by item, each cut short (the page is from outside: no pattern scans the whole page from every position)
    for chunk in re.split(r'<li\b[^>]{0,100}>', html or '', flags=re.I)[1:MAX_ADVISORIES * 4]:
        chunk = chunk[:4000]
        m = re.match(r'\s*<p>(.*?)</p>', chunk, re.S | re.I)
        if not m:
            continue
        parts = [re.sub(r'<[^>]{0,500}>', '', p).strip() for p in re.split(r'<br\s*/?>', m.group(1), flags=re.I)]
        if not parts or not parts[0]:
            continue
        a = {'title': util.clip(parts[0], 200), 'severity': '', 'cves': [], 'not_vulnerable': [], 'vulnerable': [],
             'advisory': ''}
        for p in parts[1:]:
            low = p.lower()
            if low.startswith('severity:'):
                a['severity'] = util.clip(p.split(':', 1)[1].strip().lower(), 20)
            elif low.startswith('not vulnerable:'):
                a['not_vulnerable'] = [x.strip() for x in p.split(':', 1)[1].split(',') if x.strip()][:20]
            elif low.startswith('vulnerable:'):
                a['vulnerable'] = [x.strip() for x in p.split(':', 1)[1].split(',') if x.strip()][:20]
        a['cves'] = sorted({'CVE-' + c for c in CVE_RE.findall(m.group(1))})[:10]
        link = re.search(r'href="(https://[^"]{1,300})"[^>]*>\s*Advisory', m.group(1), re.I)
        if link:
            a['advisory'] = link.group(1)
        if a['vulnerable']:
            out.append(a)
        if len(out) >= MAX_ADVISORIES:
            break
    return out


def is_vulnerable(version, adv):
    """True / False for an upstream nginx version ('1.30.6'); None when the page's ranges cannot be read.
    "Vulnerable: 1.9.5-1.31.8" and "Not vulnerable: 1.31.9+, 1.30.7+" (a fix in a branch covers that branch's later
    releases; the newest branch's covers every later one)."""
    v = _v(version)
    if v is None:
        return None
    inside, readable = False, False
    for r in adv.get('vulnerable') or []:
        if r.lower() in ('all', 'all versions'):
            inside = readable = True
            continue
        lo, _, hi = r.partition('-')
        a, b = _v(lo), _v(hi or lo)
        if a is None or b is None:
            continue
        readable = True
        inside = inside or a <= v <= b
    if not readable:
        return None
    if not inside:
        return False
    fixes = [x for x in (_v(n.rstrip('+')) for n in adv.get('not_vulnerable') or [] if n.endswith('+')) if x]
    for f in fixes:
        if f[:2] == v[:2] and v >= f:
            return False
    if fixes and v >= max(fixes):
        return False
    return True


def upstream(version):
    """(upstream version, exact) of an nginx package version: nginx.org's packages ('1.30.6-1~bookworm') are the
    release itself; a distribution's ('1.22.1-9+deb12u2') may carry backported fixes ("vulnerable" is not certain)."""
    s = str(version or '').strip()
    m = re.fullmatch(r'(?:\d+:)?(\d+\.\d+\.\d+)(-\d+~[a-z]+\d*)?', s)
    if m:
        return m.group(1), True
    m = re.match(r'(?:\d+:)?(\d+\.\d+\.\d+)', s)
    return (m.group(1), False) if m else (None, False)


def features(cfg, conf=None):
    """The features of this nginx configuration the advisories are about: {name: True}."""
    from .nginxconf import NginxConfig, walk
    try:
        conf = conf or NginxConfig(cfg['paths']['nginx_conf'])
    except Exception:      # noqa: BLE001 -- no configuration to read: nothing is known to be in use
        return {}
    out = {}
    for d, ctx in walk(conf.tree):
        n, args = d.name, [a.lower() for a in (d.args or [])]
        top = ctx[0].split(' ')[0] if ctx else ''
        if n == 'http2' and args[:1] == ['on'] or n == 'listen' and 'http2' in args:
            out['http2'] = True
        if n == 'http3' and args[:1] == ['on'] or n == 'listen' and 'quic' in args:
            out['http3'] = True
        if n == 'resolver':
            out['resolver'] = True
        if n == 'mail' and d.children is not None:
            out['mail'] = True
        if n == 'stream' and d.children is not None:
            out['stream'] = True
        if n == 'listen' and 'proxy_protocol' in args:
            out['proxy_protocol'] = True
        if n == 'ssl_preread' and args[:1] == ['on']:
            out['ssl_preread'] = True
        if n == 'ssi' and args[:1] == ['on']:
            out['ssi'] = True
        if n == 'alias':
            out['alias'] = True
        if n == 'ssl_session_ticket_key':
            out['ssl_session_ticket_key'] = True
        if n == 'mp4':
            out['mp4'] = True
        if n == 'dav_methods' and args and args[0] != 'off':
            out['dav'] = True
        if top == 'stream' and n == 'ssl_verify_client':
            out['stream'] = True
    return out


def feature_of(adv):
    for rx, name in FEATURES:
        if rx.search(adv.get('title') or ''):
            return name
    return None


OFFLINE = False                 # the tests set it: nginx.org is never asked from a test (they also run on production)


def fetch(get=None, timeout=30):
    """The page (nginx.org, HTTPS, size-limited)."""
    if get:
        return get(URL)
    if OFFLINE:
        raise OSError('offline (tests)')
    req = urllib.request.Request(URL, headers={'User-Agent': 'jt-waf-mgr nginx-update-check'})
    with urllib.request.urlopen(req, timeout=timeout) as r:          # noqa: S310 -- a fixed https URL
        return r.read(MAX_PAGE + 1)[:MAX_PAGE].decode('utf-8', 'replace')


def refresh(cfg, get=None, log=print):
    """Read the page and keep the advisories (the last good list stays when the page cannot be read)."""
    p = os.path.join(base(cfg), CACHE)
    try:
        advs = parse(fetch(get))
        if not advs:
            raise ValueError('no advisories on the page')
    except Exception as e:      # noqa: BLE001 -- the last list is kept; tried again next run
        log('nginxsec: advisories not read (%s)' % type(e).__name__)
        return load(cfg)
    os.makedirs(base(cfg), mode=0o750, exist_ok=True)
    with open(p + '.tmp', 'w', encoding='utf-8') as fh:
        json.dump({'at': util.iso(time.time()), 'advisories': advs}, fh, ensure_ascii=False)
    os.replace(p + '.tmp', p)
    return advs


def load(cfg):
    try:
        with open(os.path.join(base(cfg), CACHE), encoding='utf-8') as fh:
            return json.load(fh).get('advisories') or []
    except (OSError, ValueError, AttributeError):
        return []


def assess(cfg, installed, candidate=None, advs=None, feats=None, distro=None):
    """The advisories the installed nginx is vulnerable to: {'version', 'exact', 'issues': [...], 'fixed_by_candidate',
    'major_in_use'}; each issue {'title', 'severity', 'cves', 'feature', 'in_use', 'backported', 'fixed_in', 'advisory'}.
    distro(cve): a distribution package's own word on a CVE ('fixed' ...; default: its installed change log)."""
    advs = load(cfg) if advs is None else advs
    ver, exact = upstream(installed)
    cand, _ = upstream(candidate)
    feats = features(cfg) if feats is None else feats
    if distro is None and not exact:
        from . import distropkg
        distro = lambda cve: (distropkg.check('nginx', installed, cve) or {}).get('result')   # noqa: E731
    issues = []
    for a in advs:
        if not ver or is_vulnerable(ver, a) is not True:
            continue
        if (a.get('severity') or '').strip().lower() == 'none':
            continue            # 0.4.99: nginx.org's "Severity: none" (CVE-2009-4487, every version): no flaw to fix
        f = feature_of(a)
        cves = a.get('cves') or []
        # 0.5.12: a distribution's nginx (Ubuntu's 1.28.3-2ubuntu1.12) whose installed change log lists the fix for
        # every CVE of the advisory: fixed here, whatever the upstream version says
        back = not exact and bool(cves) and distro is not None and all(distro(c) == 'fixed' for c in cves)
        issues.append({'title': a['title'], 'severity': a.get('severity') or '', 'cves': cves,
                       'feature': f, 'in_use': not back and (True if f is None else bool(feats.get(f))), 'backported': back,
                       'fixed_in': [n for n in a.get('not_vulnerable') or []][:4], 'advisory': a.get('advisory') or '',
                       'candidate_fixes': bool(cand) and is_vulnerable(cand, a) is False})
    open_ = [i for i in issues if not i['backported']]
    return {'version': ver, 'exact': exact, 'issues': issues,
            'fixed_by_candidate': bool(open_) and all(i['candidate_fixes'] for i in open_),
            'major_in_use': any(i['severity'] in ('major', 'high', 'critical') and i['in_use'] for i in issues)}


def raise_alerts(app, st, log=print, feats=None):
    """One alert for the installed version's open advisories (none while it is vulnerable to nothing in use). Returns
    the assessment."""
    from . import alerts
    a = assess(app.cfg, st.get('installed'), st.get('candidate'), feats=feats)
    used = [i for i in a['issues'] if i['in_use']]
    if not used:
        return a
    cves = sorted({c for i in used for c in i['cves']})
    dedup = 'nginx-security:%s:%s' % (a['version'], ','.join(cves)[:200])
    # 0.4.100: the list for this version changed (an advisory more, or one no longer counted): the new alert replaces
    # the open one, not a second alert beside it
    note = 'replaced by a newer alert for nginx %s (the list of advisories changed)' % a['version']
    for old in app.db.q("SELECT id FROM alerts WHERE state='open' AND kind='nginx_security' AND dedup LIKE ? AND dedup<>?",
                        ('nginx-security:%s:%%' % a['version'], dedup)):
        if app.db.x("UPDATE alerts SET state='handled', handled_by='nginxup', handled_at=?, note=? WHERE id=? AND state='open'",
                    (util.now(), note, old['id'])).rowcount == 1:
            app.audit.log('alert.handled', 'nginxup', 'system', None, 'ok', alert_id=old['id'], kind='nginx_security', note=note)
    alerts.raise_alert(app.db, app.audit, 'nginxup', 'nginx_security', 'critical' if a['major_in_use'] else 'warning',
                       dedup,
                       {'reason': 'nginx %s has %d security issue(s) in features this configuration uses (%s): rules cannot '
                                  'refuse these; update nginx%s.' % (
                                      a['version'], len(used), ', '.join(cves)[:300] or ', '.join(i['title'] for i in used)[:300],
                                      (' to %s (ready: the ModSecurity module was verified with it)' % st.get('target'))
                                      if st.get('state') == 'ready' else ''),
                        'msg': 'nginx_security', 'installed': a['version'], 'exact': a['exact'],
                        'candidate': st.get('candidate'), 'ready': st.get('state') == 'ready', 'cves': cves[:20],
                        'issues': [{k: i[k] for k in ('title', 'severity', 'feature', 'cves')} for i in used][:20],
                        'not_in_use': [i['title'] for i in a['issues'] if not i['in_use'] and not i['backported']][:20],
                        'backported': [c for i in a['issues'] if i['backported'] for c in i['cves']][:20]},
                       link='/nginx-update')
    log('nginxsec: nginx %s: %d advisories in use (%s)' % (a['version'], len(used), ', '.join(cves)[:200]))
    return a


BACKEND_NOTE = 'the back-end nginx %s is no longer listed (updated, or its sites moved)'


def backend_alerts(app, log=print, advs=None):
    """An alert for each back-end host's nginx version (backends.py) the advisories list as vulnerable: jt-waf-mgr
    does not update that host, a person does. The features its configuration uses are not known here, and the
    version comes from its Server header (a distribution's package may carry the fixes): a warning, never critical.
    An open alert whose version is no longer listed is handled. Returns the dedup keys raised."""
    from . import alerts
    advs = load(app.cfg) if advs is None else advs
    if not advs:
        return None             # the advisories cannot be read: the open alerts stay as they are (0.5.22)
    raised = []
    for r in app.db.q("SELECT version, hosts FROM software WHERE kind='backend' AND name='nginx' ORDER BY id"):
        ver, _ = upstream(r['version'])
        if not ver or not advs:
            continue
        issues = [a for a in advs if (a.get('severity') or '').strip().lower() != 'none' and is_vulnerable(ver, a) is True]
        if not issues:
            continue
        cves = sorted({c for a in issues for c in a.get('cves') or []})
        hosts = json.loads(r['hosts'] or '[]')
        dedup = 'nginx-backend:%s:%s' % (ver, ','.join(cves)[:200])
        raised.append(dedup)
        fixed = sorted({n for a in issues for n in a.get('not_vulnerable') or []}, key=lambda x: _v(x.rstrip('+')) or ())
        alerts.raise_alert(app.db, app.audit, 'intel', 'backend_security', 'warning', dedup,
                           {'reason': 'the nginx %s on the back-end host of %s has %d security advisories at nginx.org (%s): '
                                      'update nginx on that host (jt-waf-mgr does not update it; a distribution package '
                                      'may already carry the fixes).' % (ver, ', '.join(hosts[:5]), len(issues),
                                                                         ', '.join(cves)[:300] or ', '.join(a['title'] for a in issues)[:300]),
                            'msg': 'backend_security', 'installed': ver, 'sites': hosts[:20], 'cves': cves[:20],
                            'issues': [{'title': a['title'], 'severity': a.get('severity') or '', 'cves': a.get('cves') or []}
                                       for a in issues][:20], 'fixed_in': fixed[-4:]},
                           link='/intel')
        log('nginxsec: back-end nginx %s (%s): %d advisories' % (ver, ', '.join(hosts[:3]), len(issues)))
    for old in app.db.q("SELECT id, dedup FROM alerts WHERE state='open' AND kind='backend_security'"):
        if old['dedup'] in raised:
            continue
        note = BACKEND_NOTE % (old['dedup'].split(':')[1] if old['dedup'].count(':') >= 2 else '-')
        if app.db.x("UPDATE alerts SET state='handled', handled_by='intel', handled_at=?, note=? WHERE id=? AND state='open'",
                    (util.now(), note, old['id'])).rowcount == 1:
            app.audit.log('alert.handled', 'intel', 'system', None, 'ok', alert_id=old['id'], kind='backend_security', note=note)
    return raised


SET_ASIDE_NOTE = 'nginx.org security advisory: nginx %s is not vulnerable (%s; fixed in %s)'


def decide_threats(app, installed=None, log=print):
    """Open threat intelligence threats for nginx whose CVE the advisories list: not vulnerable -> set aside (with the
    advisory as the reason, its open alerts handled); vulnerable -> noted on the threat (an nginx.org package version
    is the release itself: affects us). Returns the threat ids set aside."""
    from .intel import known_version
    db = app.db
    advs = load(app.cfg)
    if not advs:
        return []
    backend = [v for v in (upstream(r['version'])[0] for r in db.q(
        "SELECT version FROM software WHERE kind='backend' AND name='nginx'")) if v]
    # this host's own nginx: the caller's (the nginx update job's installed package), else the software list's entry
    # for this host -- never the threat's "our version", which joins every listed nginx (0.5.22: "1.22.1, 1.30.7" read
    # as the back-end's 1.22.1, and this host's 1.30.7 was never compared)
    here = installed or next((x['version'] for x in db.q(
        "SELECT version FROM software WHERE kind='host' AND name='nginx' AND version<>'' ORDER BY id")), None)
    by_cve = {}
    for a in advs:
        for c in a.get('cves') or []:
            by_cve.setdefault(c, a)
    done = []
    for r in db.q("SELECT id, cve, product, affected, details FROM intel_threats WHERE status='open'"):
        if (r['product'] or '').strip().lower() not in ('nginx', 'nginx open source', 'nginx oss'):
            continue
        a = by_cve.get(r['cve'])
        if not a:
            continue
        try:
            t = json.loads(r['details'] or '{}')
        except ValueError:
            continue
        # this host's nginx (or, with no entry for it and no back-end, the threat's own version) and every back-end's:
        # set aside only when none of them is vulnerable (0.5.17); one vulnerable is enough to keep it
        ver, exact = upstream(here or (known_version(t.get('our_version')) if not backend else ''))
        every = list(dict.fromkeys(([ver] if ver else []) + backend))
        if not every:
            continue
        results = [is_vulnerable(v, a) for v in every]
        if any(x is True for x in results):
            vul = True
        elif any(x is None for x in results):
            continue
        else:
            vul = False
            ver = ', '.join(every)
        t['nginx_advisory'] = {'title': a['title'], 'vulnerable': a['vulnerable'], 'not_vulnerable': a['not_vulnerable'],
                               'result': 'yes' if vul else 'no', 'exact': exact}
        if vul:
            db.x('UPDATE intel_threats SET details=? WHERE id=?', (json.dumps(t, ensure_ascii=False), r['id']))
            continue
        note = SET_ASIDE_NOTE % (ver, a['title'], ', '.join(a['not_vulnerable']) or '-')
        db.x("UPDATE intel_threats SET affected='no', details=?, status='ignored', status_by='intel', status_at=? WHERE id=?",
             (json.dumps(t, ensure_ascii=False), util.now(), r['id']))
        app.audit.log('intel.threat_status', 'intel', 'system', None, 'ok', threat_id=r['id'], status='ignored',
                      reason='nginx_advisory', cve=r['cve'])
        done.append(r['id'])
        for pre in ('intel', 'intel-check', 'intel-patch'):
            for al in db.q("SELECT id, kind FROM alerts WHERE state='open' AND dedup=?", ('%s:%s:%s' % (pre, r['cve'], r['product']),)):
                if db.x("UPDATE alerts SET state='handled', handled_by='intel', handled_at=?, note=? WHERE id=? AND state='open'",
                        (util.now(), note, al['id'])).rowcount == 1:
                    app.audit.log('alert.handled', 'intel', 'system', None, 'ok', alert_id=al['id'], kind=al['kind'], note=note)
    if done:
        log('nginxsec: %d nginx threats set aside by the nginx.org advisories' % len(done))
    return done
