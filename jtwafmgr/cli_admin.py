"""Administration from the command line: what the web interface does for IP blocks, alerts, changes, settings, API
tokens, threat intelligence and the periodic review -- with the same rules. A write names the person it is done for
(--as USER, an existing account with the role the web interface asks for); the audit trail records that person with
"cli" as the source, and the rules that bind a person bind it here too (no approving one's own change unless
single-admin mode, a fresh one-time code where the web interface asks for one).

  jt-waf-mgr blocks list | add IP --reason R [--ttl 24h] | extend ID --ttl 7d|--permanent --reason R | remove ID --note N
  jt-waf-mgr alerts list [--all] | handle ID --note N
  jt-waf-mgr changes list [--state S] | show ID | approve ID [--note N] [--totp CODE] | reject ID --note N | recheck ID
                     | outdated | regenerate   (rules an older version wrote: written again, approved as any change)
  jt-waf-mgr settings show [PREFIX] | set KEY=VALUE... | export -o FILE [--secrets] | import FILE [--only LIST] [--dry-run]
  jt-waf-mgr tokens list | revoke ID
  jt-waf-mgr intel threats | status ID open|handled|ignored | versions   (compare open threats with NVD's affected versions)
  jt-waf-mgr review run
"""
import json
import re
import sys

ROLE_RANK = {'viewer': 0, 'operator': 1, 'approver': 2, 'admin': 3}
DUR_RE = re.compile(r'^(\d+)([smhd]?)$')


class CliError(Exception):
    pass


def _out(obj, as_json):
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, indent=1, default=str))
        return True
    return False


def _person(app, args, role):
    """The account a write is done for; it must exist, be enabled and have at least `role`."""
    name = (getattr(args, 'as_user', None) or '').strip().lower()
    if not name:
        raise CliError('--as USER is required: the person this is done for (it is recorded in the audit trail)')
    u = app.auth.user_row(name)
    if not u or u['disabled']:
        raise CliError('no such enabled account: %s' % name)
    if ROLE_RANK.get(u['role'], -1) < ROLE_RANK[role]:
        raise CliError('%s is %s; this needs %s' % (name, u['role'], role))
    app.audit.ctx.src_ip = 'cli'
    return {'username': u['username'], 'role': u['role'], 'display_name': u['display_name'] if 'display_name' in u.keys() else ''}


def _num(v, what='an id'):
    try:
        return int(str(v))
    except (TypeError, ValueError):
        raise CliError('%s is needed (a number): %s' % (what, v if v is not None else 'missing'))


def duration(s):
    m = DUR_RE.match(str(s or '').strip().lower())
    if not m:
        raise CliError('a duration like 3600, 90m, 24h or 7d: %r' % s)
    return int(m.group(1)) * {'': 1, 's': 1, 'm': 60, 'h': 3600, 'd': 86400}[m.group(2)]


def _table(rows, cols):
    if not rows:
        print('(none)')
        return
    w = [max(len(c), *(len(str(r.get(c, '') if r.get(c) is not None else '')) for r in rows)) for c in cols]
    w = [min(x, 60) for x in w]
    print('  '.join(c.ljust(w[i]) for i, c in enumerate(cols)))
    for r in rows:
        print('  '.join(str(r.get(c, '') if r.get(c) is not None else '')[:60].ljust(w[i]) for i, c in enumerate(cols)))


# --- IP blocks ------------------------------------------------------------------------------------------------------
def cmd_blocks(app, args):
    from .blocks import BlockError
    b = app.blocks
    try:
        if args.action == 'list':
            items = b.listing('all' if args.all else 'active')
            if not _out(items, args.json):
                _table(items, ['id', 'ip', 'state', 'source', 'created_at', 'expires_at', 'reason'])
            return 0
        if args.action == 'add':
            if not args.target:
                raise CliError('the address to block is needed')
            p = _person(app, args, 'approver')
            ttl = 'permanent' if args.permanent else duration(args.ttl or app.cfg['blocks']['default_ttl'])
            item = b.add(args.target, ttl, 'cli', args.reason, p['username'], via='user', role=p['role'], src_ip='cli')
            _out(item, True)
            return 0
        if args.action == 'extend':
            p = _person(app, args, 'approver')
            ttl = 'permanent' if args.permanent else duration(args.ttl)
            _out(b.extend(_num(args.target, 'the block id'), ttl, args.reason, p['username'], p['role'], src_ip='cli'), True)
            return 0
        if args.action == 'remove':
            p = _person(app, args, 'approver')
            n = b.remove(p['username'], via='user', block_id=_num(args.target, 'the block id'), note=args.note, src_ip='cli')
            print('removed %d' % n)
            return 0
    except BlockError as e:
        raise CliError('%s %s' % (e.code, getattr(e, 'extra', '') or ''))
    return 2


# --- alerts -----------------------------------------------------------------------------------------------------------
def cmd_alerts(app, args):
    from . import alerts
    if args.action == 'list':
        items = alerts.listing(app.db, state=None if args.all else 'open', limit=500)['items']
        if not _out(items, args.json):
            _table([dict(i, what=i.get('summary') or '') for i in items],
                   ['id', 'state', 'severity', 'kind', 'created_at', 'what'])
        return 0
    if args.action == 'handle':
        p = _person(app, args, 'approver')
        try:
            _out(alerts.handle(app.db, app.audit, _num(args.id), p['username'], args.note or '', src_ip='cli'), True)
        except alerts.AlertError as e:
            raise CliError(e.code)
        return 0
    return 2


# --- changes ----------------------------------------------------------------------------------------------------------
def cmd_changes(app, args):
    from .changes import ChangeError
    wf = app.workflow
    try:
        if args.action == 'list':
            rows = app.db.q('SELECT id, state, op, kind, direction, proposed_by, created_at, reason FROM changes '
                            + ('WHERE state=? ' if args.state else '') + 'ORDER BY id DESC LIMIT 200',
                            (args.state,) if args.state else ())
            items = [dict(r) for r in rows]
            if not _out(items, args.json):
                _table(items, ['id', 'state', 'op', 'kind', 'direction', 'proposed_by', 'reason'])
            return 0
        if args.action == 'show':
            r = wf.get(_num(args.id))
            _out({k: r[k] for k in r.keys()}, True)
            return 0
        if args.action == 'approve':
            p = _person(app, args, 'approver')
            wf.approve(_num(args.id), p, totp=args.totp, note=args.note or '')
            print('approved #%s; the apply program takes it from here' % args.id)
            return 0
        if args.action == 'reject':
            p = _person(app, args, 'approver')
            wf.reject(_num(args.id), p, args.note)
            print('rejected #%s' % args.id)
            return 0
        if args.action == 'outdated':
            rows = wf.outdated()
            if not _out(rows, args.json):
                _table(rows, ['item_id', 'rule_id', 'kind', 'ok', 'open_change', 'reason'])
                raw = wf.raw_path_rules()
                if raw:
                    print('rules entered as text that look at REQUEST_FILENAME only (not written again): %s' % raw)
            return 0
        if args.action == 'regenerate':
            p = _person(app, args, 'operator')
            app.audit.log('managed.regenerate_requested', p['username'], 'user', 'cli', 'ok')
            out = wf.propose_regenerate(p['username'])
            print('proposed %s; approve them as any change%s' % (', '.join('#%d' % i for i in out['changes']),
                  ('; without a test it refuses (propose by hand): %s' % out['without_tests']) if out['without_tests'] else ''))
            return 0
        if args.action == 'recheck':
            p = _person(app, args, 'operator')
            wf.recheck(_num(args.id), p)
            print('#%s is being checked again' % args.id)
            return 0
    except ChangeError as e:
        raise CliError('%s %s' % (e.code, e.details or ''))
    except KeyError:
        raise CliError('no such change: %s' % getattr(args, 'id', ''))
    return 2


# --- settings ---------------------------------------------------------------------------------------------------------
def _value(text, key=''):
    """KEY=VALUE as the setting's type: true/false, a number, a JSON list; anything else (a string, a secret, an id
    made of digits) stays the text as typed."""
    from . import uisettings
    kind = uisettings.EDITABLE.get(key, ('',))[0]
    if key.startswith('workflow.') or kind in ('bool', 'int', 'list'):
        try:
            return json.loads(text)
        except ValueError:
            return text
    return text


def cmd_settings(app, args):
    from . import settings_io, uisettings
    if args.action == 'show':
        pub = uisettings.public(app.cfg, app.db)
        rows = [{'key': k, 'value': ('(set)' if v.get('set') else '(not set)') if v['type'] == 'secret' else json.dumps(v.get('value'), ensure_ascii=False),
                 'from': v['source']} for k, v in sorted(pub.items()) if not args.prefix or k.startswith(args.prefix)]
        for k, v in sorted(app.workflow.settings().items()):
            if not args.prefix or ('workflow.' + k).startswith(args.prefix):
                rows.append({'key': 'workflow.' + k, 'value': json.dumps(v), 'from': 'workflow'})
        if not _out(rows, args.json):
            _table(rows, ['key', 'value', 'from'])
        return 0
    if args.action == 'set':
        p = _person(app, args, 'admin')
        ui, wfv = {}, {}
        for kv in args.items:
            if '=' not in kv:
                raise CliError('KEY=VALUE: %r' % kv)
            k, v = kv.split('=', 1)
            (wfv if k.startswith('workflow.') else ui)[k[9:] if k.startswith('workflow.') else k] = _value(v, k)
        data = {'format': settings_io.FORMAT, 'settings': ui, 'workflow': wfv}
        keys = ['settings:' + k for k in ui] + ['workflow:' + k for k in wfv]
        try:
            done = settings_io.apply(app, data, keys, p['username'], src_ip='cli')
        except settings_io.ImportError_ as e:
            raise CliError('%s %s' % (e.code, e.details))
        print('changed: %s' % (', '.join(done['settings'] + ['workflow.' + k for k in done['workflow']]) or 'nothing'))
        if done['settings']:
            print('the web service reads its settings when it starts: sudo systemctl restart jt-waf-mgr')
        return 0
    if args.action == 'export':
        # always to a new mode-600 file, never to the terminal (scrollback, a captured log)
        if not args.output:
            raise CliError('export needs -o FILE: the settings are written to a new file (mode 600)')
        if args.secrets:
            _person(app, args, 'admin')
        app.audit.log('settings.exported', getattr(args, 'as_user', None) or 'cli', src_ip='cli', secrets=args.secrets,
                      severity='warning' if args.secrets else 'info')
        if args.output:      # always (checked above)
            text = json.dumps(settings_io.export(app, secrets=bool(args.secrets)), ensure_ascii=False, indent=1)
            import os
            try:
                fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            except FileExistsError:
                raise CliError('%s exists: give a new file name (it is created with mode 600)' % args.output)
            with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                fh.write(text + '\n')
            print('written to %s%s' % (args.output, ' (keys and passwords included: keep it safe)' if args.secrets else ''))
        return 0
    if args.action == 'import':
        with open(args.file, 'rb') as fh:
            raw = fh.read()
        try:
            data = settings_io.parse(raw)
        except settings_io.ImportError_ as e:
            raise CliError(e.code)
        pv = settings_io.preview(app, data)
        only = [x.strip() for x in (args.only or '').split(',') if x.strip()]

        def wanted(i):
            # only what differs (and is accepted); --only narrows that to some groups or keys
            if not i['valid'] or i['same']:
                return False
            full = ('workflow.' if i['area'] == 'workflow' else '') + i['key']
            return not only or any(o in (i['group'], i['key'], full) for o in only)
        picked = [i for i in pv['items'] if wanted(i)]
        for i in pv['items']:
            mark = '+' if i in picked else ('=' if i['same'] else ('?' if not i['known'] else ('!' if not i['valid'] else ' ')))
            if i in picked or args.verbose:
                print('%s %-45s %s -> %s' % (mark, ('workflow.' if i['area'] == 'workflow' else '') + i['key'],
                                              json.dumps(i['current'], ensure_ascii=False)[:40], json.dumps(i['incoming'], ensure_ascii=False)[:40]))
        if args.dry_run or not picked:
            print('%d setting(s) would be written%s' % (len(picked), ' (dry run)' if args.dry_run else ''))
            return 0
        p = _person(app, args, 'admin')
        try:
            done = settings_io.apply(app, data, ['%s:%s' % (i['area'], i['key']) for i in picked], p['username'], src_ip='cli')
        except settings_io.ImportError_ as e:
            raise CliError('%s %s' % (e.code, e.details))
        print('changed %d setting(s)' % (len(done['settings']) + len(done['workflow'])))
        if done['settings']:
            print('the web service reads its settings when it starts: sudo systemctl restart jt-waf-mgr')
        return 0
    return 2


# --- tokens, intel, review ----------------------------------------------------------------------------------------------
def cmd_tokens(app, args):
    if args.action == 'list':
        from . import util
        rows = [{'id': r['id'], 'name': r['name'], 'scopes': ','.join(json.loads(r['scopes'] or '[]')),
                 'sources': ','.join(json.loads(r['allowed_cidrs'] or '[]')),
                 'expires_at': util.iso(r['expires_at']) if r['expires_at'] else '', 'revoked': bool(r['revoked']),
                 'last_used_at': util.iso(r['last_used_at']) if r['last_used_at'] else '', 'created_by': r['created_by']}
                for r in app.db.q('SELECT * FROM tokens ORDER BY name')]
        if not _out(rows, args.json):
            _table(rows, ['id', 'name', 'scopes', 'sources', 'expires_at', 'revoked', 'last_used_at'])
        return 0
    if args.action == 'revoke':
        p = _person(app, args, 'admin')
        r = app.db.one('SELECT * FROM tokens WHERE id=?', (args.id,))
        if not r:
            raise CliError('no such token: %s' % args.id)
        app.db.x('UPDATE tokens SET revoked=1 WHERE id=?', (r['id'],))
        app.audit.log('token.revoked', p['username'], src_ip='cli', token=r['name'], token_id=r['id'])
        print('revoked %s (%s)' % (r['id'], r['name']))
        return 0
    return 2


def cmd_intel(app, args):
    from . import intel
    if args.action == 'threats':
        items = intel.threats(app.db)
        if not _out(items, args.json):
            _table([{k: i.get(k) for k in ('threat_id', 'id', 'product', 'severity', 'affected', 'exploited', 'status')} for i in items],
                   ['threat_id', 'id', 'product', 'severity', 'affected', 'exploited', 'status'])
        return 0
    if args.action == 'versions':
        # 0.4.96: compare the open threats with NVD's affected versions now (normally at each search)
        p = _person(app, args, 'approver')
        done = intel.retire_by_version(app, log=lambda m: print(m))
        done += intel.retire_by_distro(app, log=lambda m: print(m))     # 0.4.99: a distribution's backported fix
        app.audit.log('intel.versions_checked', p['username'], 'user', 'cli', 'ok', set_aside=done)
        print('set aside: %s' % (done or 'none'))
        return 0
    if args.action == 'status':
        p = _person(app, args, 'approver')
        try:
            intel.set_status(app.db, app.audit, _num(args.id), args.status, p['username'], src_ip='cli')
        except intel.IntelError as e:
            raise CliError(e.code)
        print('threat %s: %s' % (args.id, args.status))
        return 0
    return 2


def cmd_review(app, args):
    from . import review
    p = _person(app, args, 'approver')
    rid, _ = review.run(app, 'manual')
    app.audit.log('review.run', p['username'], src_ip='cli', review_id=rid)
    print('review #%s' % rid)
    return 0


def register(sub):
    """Add the commands to the argparse sub-parsers; returns {command: handler}."""
    def common(p, write=True):
        p.add_argument('--json', action='store_true', help='machine-readable output')
        if write:
            p.add_argument('--as', dest='as_user', metavar='USER', help='the person this is done for (an existing account)')
        return p
    b = common(sub.add_parser('blocks', help='temporary IP blocks: list, add, extend, remove'))
    b.add_argument('action', choices=('list', 'add', 'extend', 'remove'))
    b.add_argument('target', nargs='?', help='address (add) or block id (extend, remove)')
    b.add_argument('--ttl', help='3600, 90m, 24h, 7d')
    b.add_argument('--permanent', action='store_true', help='admin only')
    b.add_argument('--reason')
    b.add_argument('--note')
    b.add_argument('--all', action='store_true', help='list: ended ones too')
    a = common(sub.add_parser('alerts', help='open alerts: list, mark handled'))
    a.add_argument('action', choices=('list', 'handle'))
    a.add_argument('id', nargs='?')
    a.add_argument('--note')
    a.add_argument('--all', action='store_true')
    c = common(sub.add_parser('changes', help='changes: list, show, approve, reject, check again, rules to write again'))
    c.add_argument('action', choices=('list', 'show', 'approve', 'reject', 'recheck', 'outdated', 'regenerate'))
    c.add_argument('id', nargs='?')
    c.add_argument('--state')
    c.add_argument('--note')
    c.add_argument('--totp', help='a fresh one-time code (where the web interface asks for one)')
    s = common(sub.add_parser('settings', help='settings: show, set, export, import'))
    s.add_argument('action', choices=('show', 'set', 'export', 'import'))
    s.add_argument('items', nargs='*', help='show: a key prefix; set: KEY=VALUE ...; import: the file')
    s.add_argument('-o', '--output', help='export: write to this file (mode 600)')
    s.add_argument('--secrets', action='store_true', help='export: keys and passwords too (needs -o FILE and --as an admin)')
    s.add_argument('--only', help='import: a comma list of groups (llm, notify, workflow...) or keys; default: all that differ')
    s.add_argument('--dry-run', action='store_true', help='import: only show what would change')
    s.add_argument('-v', '--verbose', action='store_true', help='import: list every setting of the file')
    t = common(sub.add_parser('tokens', help='API tokens: list, revoke'))
    t.add_argument('action', choices=('list', 'revoke'))
    t.add_argument('id', nargs='?')
    i = common(sub.add_parser('intel', help='threat intelligence: threats, set a status, check versions against NVD'))
    i.add_argument('action', choices=('threats', 'status', 'versions'))
    i.add_argument('id', nargs='?')
    i.add_argument('status', nargs='?', choices=('open', 'handled', 'ignored'))
    r = common(sub.add_parser('review', help='run the periodic WAF review now'))
    r.add_argument('action', choices=('run',))
    return {'blocks': cmd_blocks, 'alerts': cmd_alerts, 'changes': cmd_changes, 'settings': cmd_settings,
            'tokens': cmd_tokens, 'intel': cmd_intel, 'review': cmd_review}


def run(handler, app, args):
    if args.cmd == 'settings':
        if args.action == 'show':
            args.prefix = args.items[0] if args.items else ''
        elif args.action == 'import':
            if len(args.items) != 1:
                raise CliError('import FILE')
            args.file = args.items[0]
    try:
        return handler(app, args)
    except CliError as e:
        print('error: %s' % e, file=sys.stderr)
        return 1
