"""Reasons the system writes for its own proposals, in a form the page can show in the reader's language (0.5.4).

The stored reason stays English (the CLI, the audit trail, notifications and the comment in the rules file read it).
Each sentence comes from a template here; parse() finds the templates again in a stored reason -- also in reasons
written before 0.5.4, which used the same sentences -- and returns pieces: {'key', 'args'} for a known sentence, or
{'text'} for anything else (a person's own words, what a model wrote). The page translates the keys (creason.<key>)
and shows the rest as it is.
"""
import re

TEMPLATES = {
    'regen': 'Rules written again by the rule generator of jt-waf-mgr {version} from their own settings, asked by {owner}: '
             '{rules}. Path rules now also see the path cut at an encoded "?" (%3F), normalised; exclusions and redactions '
             'scoped to a path need it both as sent and normalised and never apply to a path with an encoded "?". The '
             'network lists in force now (internal networks, known scanners) are written in, as in any new rule: compare '
             'the rule text.',
    'proto_off': 'nginx {version}: nginx.org security advisory in {proto} ({cves}), which this configuration uses; rules '
                 'cannot refuse it. {proto2} off until nginx is updated (browsers fall back to an older protocol).',
    'proto_on': 'nginx {version} is vulnerable to no advisory in {proto} any more: the lines switched off for it go back '
                'as they were.',
    'nginx_update': 'nginx {version} -> {target}: nginx.org security advisories for features this configuration uses '
                    '({cves}). Rules cannot refuse these; the ModSecurity module was verified with the new nginx ({detail}).',
    'intel_patch_x': 'Virtual patch for {cve} in {product} {version} ({severity}, exploited in the wild), until the '
                     'software is updated. {summary} Attack: {attack}. Rule: {rule}. References: {refs}',
    'intel_patch': 'Virtual patch for {cve} in {product} {version} ({severity}), until the software is updated. {summary} '
                   'Attack: {attack}. Rule: {rule}. References: {refs}',
    'intel_hub_x': 'Virtual patch for {cve} in {product} {version} ({severity}, exploited in the wild): the CrowdSec Hub '
                   'rule {rule} ({label}), until the software is updated. {summary} References: {refs}',
    'intel_hub': 'Virtual patch for {cve} in {product} {version} ({severity}): the CrowdSec Hub rule {rule} ({label}), '
                 'until the software is updated. {summary} References: {refs}',
    'intel_hub_add': 'Add {hosts} to the CrowdSec rule {rule} for {cve} in {product}.',
    'analyst_all_external': 'ALL FROM EXTERNAL SOURCES: no internal user was blocked; check that this is really normal use.',
    'analyst_fp_whole': '[jt analyst] false positive, model {model}, confidence {confidence}. Scope: host {host}, {mode} '
                        'path {path}, method {method}, rules {rules}, WHOLE RULE removed there. Last {hours}h: {events} '
                        'blocked requests from {sources} sources ({internal} internal).',
    'analyst_fp': '[jt analyst] false positive, model {model}, confidence {confidence}. Scope: host {host}, {mode} path '
                  '{path}, method {method}, rules {rules}, targets {targets}. Last {hours}h: {events} blocked requests '
                  'from {sources} sources ({internal} internal).',
    'analyst_block': '[jt analyst] model {model}, confidence {confidence}. Last {hours}h, external sources only: {events} '
                     'events, {sources} sources; hosts: {hosts}; families: {families}; rules: {rules}; statuses: {statuses}.',
    'paused': 'WAF paused ({what}, {duration}): {reason}',
    'resumed_why': 'WAF resumed ({what}): {reason}',
    'resumed': 'WAF resumed ({what})',
}
# values the templates fill in from the program's own English words, by field: the page shows them translated
# (creason.v.<name>)
VALUES = {'version': {'(version not known)': 'version_unknown'}, 'severity': {'severity not known': 'severity_unknown'},
          'method': {'any': 'any'}, 'mode': {'prefix': 'prefix', 'exact': 'exact'},
          'duration': {'until resumed': 'until_resumed'}, 'what': {'all': 'all_sites', 'all sites': 'all_sites',
                                                                   'everything': 'everything'},
          'detail': {'ready': 'ready'}, 'model': {'?': 'unknown'}}
# a version is one word (a product name may have spaces: "OWASP CRS 4.30.0")
FIELD_RX = {'version': r'\(version not known\)|[^\s(]\S*|', 'severity': r'[^()]*?'}
_FIELD = re.compile(r'\{(\w+)\}')


def text(key, **args):
    """The English sentence (what is stored)."""
    return TEMPLATES[key].format(**args)


def _compile(tpl):
    out, pos = [], 0
    for m in _FIELD.finditer(tpl):
        out.append(re.escape(tpl[pos:m.start()]))
        out.append('(?P<%s>%s)' % (m.group(1), FIELD_RX.get(m.group(1), '.*?')))
        pos = m.end()
    out.append(re.escape(tpl[pos:]))
    return re.compile(''.join(out), re.S)


_RX = [(k, _compile(v)) for k, v in TEMPLATES.items()]


def _match(s):
    for k, rx in _RX:
        m = rx.fullmatch(s)
        if m:
            args = {n: v for n, v in m.groupdict().items()}
            return {'key': k, 'args': args, 'values': {n: VALUES[n][v] for n, v in args.items() if v in VALUES.get(n, {})}}
    return None


def parse(reason):
    """[{'key', 'args', 'values'} | {'text'}], or None when nothing in it is a known sentence (show it as it is)."""
    s = str(reason or '')
    if not s or len(s) > 4000:
        return None
    whole = _match(s)
    if whole:
        return [whole]
    parts, found = [], False
    for line in s.split('\n'):
        m = _match(line) if line else None
        found = found or bool(m)
        parts.append(m or {'text': line})
    return parts if found else None
