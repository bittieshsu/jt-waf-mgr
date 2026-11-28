"""The CRS score refusing outside requests (0.5.48).

jt-waf-mgr keeps the ModSecurity engine in detection only and refuses through rules that switch blocking on for the
request they match (ctl:ruleEngine=On). A host adopted from a fresh ModSecurity therefore had confident blocks that
refuse, but the OWASP CRS score only logged -- for outside sources too: the configuration names the rule that should do
it (waf.threshold_rule_ids, 10297) and nothing wrote it. This module tells whether the CRS score refuses outside
requests on this host (the decision model, the same simulation the WAF decision page shows) and proposes the rule:
outside sources at or over the CRS threshold are refused, internal ones keep being logged.

A site running an application with a protection set gets the set's exclusions for the known false positives of its
ordinary use in the same change (Synology DSM: the labels the Photos app recognised in a photo, "watch", "time",
"cat", taken for Unix commands; an API name ending in ".Profile" taken for a restricted file; settings JSON taken for
SQL injection; a browser's text/plain settings save): once the score refuses, each of these would be refused from
outside. The change is then a loosening one and needs a person's approval with a one-time code; never
applied by itself either way.

Plain data and the existing change flow; no network."""
from . import reasons, rulegen, software, util
from . import __version__

DSM_APPS = ('Synology DSM', 'Synology Photos')
PHOTOS_RULE = ('synology-dsm', 'photos-ml-labels')
TAG = 'jt-score-block'

_cache = {'m': None, 'value': None}


class ScoreBlockError(Exception):
    def __init__(self, code, status=409, **details):
        super().__init__(code)
        self.code, self.status, self.details = code, status, details


def external_blocks(app):
    """True when a request from outside at or over the CRS threshold is refused on this host (engine On, or a rule
    that switches blocking on for it); False when the CRS only logs it (or there is no CRS). Cached per loaded
    configuration (the decision model simulates every engine context)."""
    try:
        _, m = app.site.load()
    except Exception:          # noqa: BLE001 -- no configuration: nothing refuses
        return False
    if _cache['m'] is m:
        return _cache['value']
    crs = m.crs_status()
    if crs.get('engine_mode') == 'On':
        value = True
    elif not crs.get('version') or crs.get('engine_mode') == 'Off':
        value = False
    else:
        try:
            from . import decision
            s = decision.model(app)['summary']['external']
            value = s.get('over_result') == 'blocked'
        except Exception:      # noqa: BLE001 -- a model that fails to build: say it does not refuse (a hint, no harm)
            value = False
    _cache['m'], _cache['value'] = m, value
    return value


def _pending(app):
    """The id of an open change that already carries the score refusal, or None."""
    from .changes import FINAL
    for r in app.db.q('SELECT id, spec FROM changes WHERE state NOT IN (%s) ORDER BY id' % ','.join('?' * len(FINAL)),
                      FINAL):
        if TAG in (r['spec'] or ''):
            return r['id']
    return None


def rule_text(app, rid):
    """The rule: outside source and the CRS inbound score at or over its threshold -> refused. CRS 4 keeps the score
    that counts for blocking in TX:BLOCKING_INBOUND_ANOMALY_SCORE (the paranoia levels over the blocking one only
    detect); CRS 3 had one TX:ANOMALY_SCORE."""
    _, m = app.site.load()
    version = str(m.crs_status().get('version') or '')
    var = 'TX:ANOMALY_SCORE' if version.startswith('3.') else 'TX:BLOCKING_INBOUND_ANOMALY_SCORE'
    internal = rulegen._ip_list(app.cfg.internal_networks)
    return ('SecRule %s "@ge %%{tx.inbound_anomaly_score_threshold}" \\\n'
            '    "id:%d,phase:2,deny,status:403,log,t:none,msg:\'jt external block: CRS anomaly score over the threshold\','
            'tag:\'%s\',chain"\n'
            '    SecRule REMOTE_ADDR "!@ipMatch %s" \\\n'
            '        "t:none,setvar:tx.jt_block=1,ctl:ruleEngine=On"' % (var, rid, TAG, internal))


def _waf_hosts(app):
    """Server names of the sites with the WAF on (the tests need a site the requests reach the CRS on)."""
    n, _ = app.site.load()
    out = []
    for s in n.servers():
        if s.get('waf') in ('on', 'block'):
            for name in s['server_names']:
                if name and '*' not in name and not name.startswith('~') and name != '_' and name not in out:
                    out.append(name)
    return out


def dsm_hosts(app, waf_hosts=None):
    hosts = []
    for a in DSM_APPS:
        for h in software.hosts_of(app.db, a):
            if h not in hosts and (waf_hosts is None or h in waf_hosts):
                hosts.append(h)
    return hosts


def status(app):
    """{'blocks', 'rule_id', 'pending' (change id), 'dsm_hosts', 'can_propose'} for the dashboard."""
    rid = (app.cfg['waf']['threshold_rule_ids'] or [None])[0]
    blocks = external_blocks(app)
    waf = _waf_hosts(app) if not blocks else []
    return {'blocks': blocks, 'rule_id': rid, 'pending': None if blocks else _pending(app),
            'dsm_hosts': dsm_hosts(app, waf) if waf else [], 'can_propose': bool(not blocks and waf and rid)}


def propose(app, actor, via='user', role=None, owner=None):
    """One change (a bundle): the score refusal for outside sources, and for each site with the WAF on that runs
    Synology DSM the Photos false positive excluded (unless already applied or waiting)."""
    from . import protsets
    if external_blocks(app):
        raise ScoreBlockError('already_blocks')
    rid = (app.cfg['waf']['threshold_rule_ids'] or [None])[0]
    if not rid:
        raise ScoreBlockError('no_threshold_rule', 422)
    cid = _pending(app)
    if cid:
        raise ScoreBlockError('pending', change_id=cid)
    it = app.workflow.managed.item_by_rule(rid)
    if (it and not it['deleted']) or (not it and app.site.rule(rid)):
        raise ScoreBlockError('rule_id_taken', rule_id=rid)
    waf = _waf_hosts(app)
    if not waf:
        raise ScoreBlockError('no_waf_site', 422)
    ops = [{'op': 'add', 'kind': 'raw', 'spec': {'text': rule_text(app, rid), 'placement': 'after'}}]
    probe = waf[0]
    tests = [{'host': probe, 'path': '/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', 'source': 'external', 'expect': 403},
             {'host': probe, 'path': '/?id=1%20UNION%20SELECT%20password%20FROM%20users', 'source': 'external',
              'expect': 403},
             {'host': probe, 'path': '/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', 'source': 'internal', 'expect': 200}]
    # every exclusion of an application's protection set for its sites with the WAF on (the known false positives of
    # its ordinary use: once the score refuses, they would be refused from outside), unless applied or waiting
    photos = []
    applied, pending = protsets._applied(app), protsets._pending(app)
    for s in protsets.load():
        excl = [r for r in s['rules'] if r['kind'] == 'exclusion']
        if not excl:
            continue
        for h in software.hosts_of(app.db, s['app']):
            if h not in waf:
                continue
            added = False
            for rule in excl:
                tag = '%s/%s' % (s['id'], rule['id'])
                if (tag, h) in pending or ((tag, h) in applied and applied[(tag, h)]['enabled']):
                    continue
                if rule['needs'] and not all(h in software.hosts_of(app.db, n) for n in rule['needs']):
                    continue
                spec = dict(rule['spec'], host={'mode': 'exact', 'value': h}, protset=tag)
                spec.setdefault('source', 'all')
                ops.append({'op': 'add', 'kind': 'exclusion', 'spec': spec})
                tests += protsets._tests(rule, h)
                added = True
            if added and s['id'] == PHOTOS_RULE[0]:
                # the command injection rules still refuse a real command in another parameter
                tests.append({'host': h, 'path': '/webapi/entry.cgi', 'method': 'POST', 'source': 'external',
                              'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                              'body': 'api=SYNO.Foto.Search.Search&method=list&keyword=%3B+cat+%2Fetc%2Fpasswd',
                              'expect': 403})
            if added:
                photos.append(h)
    reason = reasons.text('scoreblock', version=__version__, rule=str(rid))
    if photos:
        reason += '\n' + reasons.text('scoreblock_apps', hosts=', '.join(photos))
    cid = app.workflow.propose_bundle(ops, util.clip(reason, 2000), actor, via, tests=tests[:50], role=role, owner=owner)
    app.audit.log('scoreblock.proposed', actor, 'token' if via == 'api' else 'user', None, 'ok', rule_id=rid,
                  change_id=cid, photos_hosts=photos)
    _cache['m'] = None
    return cid

