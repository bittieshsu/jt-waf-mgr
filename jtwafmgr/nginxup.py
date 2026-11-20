"""Getting ready for an nginx update before it happens, so that the WAF is never left behind (with nginxmod.py).

jt-waf-mgr-nginxup.service (a timer every 6 hours, after apt's lists for nginx are refreshed; or "check now" / a module upload on the page) -- a job that may reach the
package repositories, never the web service:

1. asks apt which nginx the next update brings (the candidate); nothing to do while it is the installed one;
2. downloads that nginx package with `apt-get download` (not installed) and unpacks it in a temporary directory;
3. takes the ModSecurity module for it: one an administrator uploaded (built with deploy/build-modsecurity-module.sh,
   on a build host or here), checked against the description that comes with it;
4. starts the *new* nginx program with that module on a local port, with one rule, and checks that a request the rule
   refuses gets 403 and an ordinary one 200;
5. writes the result (ready to update, or why not). Only a module that passed this for exactly that nginx package may
   be used for the update (the root program checks its SHA-256 again).
"""
import glob
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

from . import util

REQUEST = 'check.request'
STATUS = 'status.json'
MODULE_NAME = 'ngx_http_modsecurity_module.so'
MAX_MODULE = 8 * 1024 * 1024
REFRESH_EVERY = 15 * 60          # "check now" refreshes apt's lists at most this often



def rolled_back_from(db, target):
    """The newest applied nginx change is a rollback away from an update to this version (0.5.25: with automatic updates
    on, the job proposed and applied that version again within minutes of a person's rollback)."""
    if not target or db is None:
        return False
    r = db.one("SELECT spec FROM changes WHERE op='nginx' AND state='applied' ORDER BY updated_at DESC, id DESC LIMIT 1")
    try:
        sp = json.loads(r['spec'] or '{}') if r else {}
        if sp.get('mode') != 'rollback':
            return False
        fr = db.one('SELECT spec FROM changes WHERE id=?', (int(sp.get('from_change') or 0),))
        return bool(fr) and json.loads(fr['spec'] or '{}').get('target') == target
    except (ValueError, TypeError):
        return False

def base(cfg):
    return os.path.join(os.path.dirname(os.path.abspath(cfg['paths']['db'])), 'nginxup')


def _run(cmd, cwd=None, timeout=120):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, errors='replace',
                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': cwd or '/tmp'})
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except (OSError, subprocess.SubprocessError) as e:
        return None, type(e).__name__


def read_status(cfg):
    try:
        with open(os.path.join(base(cfg), STATUS), encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _write_status(cfg, st):
    d = base(cfg)
    os.makedirs(d, mode=0o750, exist_ok=True)
    p = os.path.join(d, STATUS)
    with open(p + '.tmp', 'w', encoding='utf-8') as fh:
        json.dump(st, fh, ensure_ascii=False)
    os.replace(p + '.tmp', p)


def request_check(cfg):
    d = base(cfg)
    os.makedirs(d, mode=0o750, exist_ok=True)
    with open(os.path.join(d, REQUEST), 'w') as fh:
        fh.write(util.iso(time.time()))


def request_refresh(cfg):
    """Check now, with apt's lists for nginx refreshed first (root, jt-waf-mgr-nginx-aptrefresh.service; it starts
    the check afterwards)."""
    d = base(cfg)
    os.makedirs(d, mode=0o750, exist_ok=True)
    stamp = os.path.join(d, 'refresh.last')
    try:
        recent = time.time() - os.stat(stamp).st_mtime < REFRESH_EVERY
    except OSError:
        recent = False
    if recent:
        # refreshed a moment ago: just check (systemd limits how often the root job may start; clicking "check now"
        # again and again must not use that up)
        return request_check(cfg)
    with open(stamp, 'w') as fh:
        fh.write(util.iso(time.time()))
    with open(os.path.join(d, 'refresh.request'), 'w') as fh:
        fh.write(util.iso(time.time()))


def module_dir(cfg, package_version):
    """Where the module for one nginx package version waits (uploaded, or a prebuilt one)."""
    if not re.fullmatch(r'[0-9][A-Za-z0-9.+~:-]{0,60}', package_version or ''):
        raise ValueError('not a package version')
    return os.path.join(base(cfg), 'modules', package_version.replace(':', '_'))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for b in iter(lambda: fh.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def _free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _get(port, path):
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d%s' % (port, path), timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:
        return None


def try_module(nginx_bin, module, other_modules=()):
    """Start nginx_bin with the module and one rule; True when a refused request gets 403 and an ordinary one 200.
    Returns (ok, detail)."""
    d = tempfile.mkdtemp(prefix='jtwaf-nginxup-')
    pid = None
    try:
        for x in ('logs', 'tmp'):
            os.makedirs(os.path.join(d, x))
        rules = os.path.join(d, 'rules.conf')
        with open(rules, 'w') as fh:
            fh.write('SecRuleEngine On\nSecRule ARGS "@streq jt-waf-mgr-update-check" "id:1,phase:1,deny,status:403,nolog"\n')
        port = _free_port()
        conf = os.path.join(d, 'nginx.conf')
        with open(conf, 'w') as fh:
            fh.write(''.join('load_module %s;\n' % m for m in list(other_modules) + [module]))
            fh.write('pid %(d)s/nginx.pid;\nerror_log %(d)s/logs/error.log warn;\nevents { worker_connections 16; }\n'
                     'http { access_log off; client_body_temp_path %(d)s/tmp/b; proxy_temp_path %(d)s/tmp/p; '
                     'fastcgi_temp_path %(d)s/tmp/f; uwsgi_temp_path %(d)s/tmp/u; scgi_temp_path %(d)s/tmp/s;\n'
                     '  server { listen 127.0.0.1:%(p)d; modsecurity on; modsecurity_rules_file %(r)s;\n'
                     '    location / { return 200 "ok\\n"; } } }\n' % {'d': d, 'p': port, 'r': rules})
        cmd = [nginx_bin, '-p', d + '/', '-c', conf, '-e', os.path.join(d, 'logs', 'error.log')]
        rc, out = _run(cmd + ['-t'], cwd=d)
        if rc != 0:
            lines = [x for x in out.strip().splitlines() if x.strip()]
            why = next((x for x in lines if '[emerg]' in x or '[alert]' in x), lines[-1] if lines else str(rc))
            return False, 'nginx -t: ' + util.clip(why.replace(d, '...'), 300)
        rc, out = _run(cmd, cwd=d)
        if rc != 0:
            return False, 'nginx did not start: ' + util.clip(out.strip(), 300)
        for _ in range(50):
            try:
                with open(os.path.join(d, 'nginx.pid')) as fh:
                    pid = int(fh.read().strip())
                break
            except (OSError, ValueError):
                time.sleep(0.1)
        refused = _get(port, '/?q=jt-waf-mgr-update-check')
        ordinary = _get(port, '/')
        if (refused, ordinary) != (403, 200):
            return False, 'the module did not refuse (got %s for the test request, %s for an ordinary one)' % (refused, ordinary)
        return True, 'loaded; refused the test request (403), passed an ordinary one (200)'
    finally:
        if not pid:
            try:                    # started late: the pid file shows up after the wait above
                time.sleep(0.5)
                with open(os.path.join(d, 'nginx.pid')) as fh:
                    pid = int(fh.read().strip())
            except (OSError, ValueError):
                pass
        if pid:
            try:
                os.kill(pid, 15)
                time.sleep(0.3)
            except OSError:
                pass
        shutil.rmtree(d, ignore_errors=True)


def run(app, log=print, now=None):
    """The job. Returns the status written to status.json."""
    from . import nginxmod
    cfg = app.cfg
    d = base(cfg)
    os.makedirs(d, mode=0o750, exist_ok=True)
    try:
        os.unlink(os.path.join(d, REQUEST))
    except OSError:
        pass
    now = now or time.time()
    st = {'at': util.iso(now)}
    _write_status(cfg, dict(read_status(cfg), state='running', started_at=st['at']))
    try:
        mods, _ = nginxmod.modules(app)
        up = nginxmod.update_risk(cfg['paths']['nginx_bin'], mods)
        loads = nginxmod.load_test(cfg['paths']['nginx_bin'], mods).get('ok')
        st.update(installed=up.get('installed'), candidate=up.get('candidate'), package=up.get('nginx_package'),
                  held=up.get('held'), supported=up.get('supported'))
        others = [m for m in up.get('hand_built') or [] if 'modsecurity' not in os.path.basename(m).lower()]
        if not up.get('supported') or not up.get('nginx_package'):
            st.update(state='unsupported')
        elif loads is False and up.get('hand_built') and not others:
            # nginx was updated and the module left behind: the running nginx is still the old program, the next
            # restart fails. Finish it with a module for the installed nginx.
            st.update(mode='finish', target=up['installed'])
            st.update(_prepare(cfg, up, 'finish', [], log))
        elif not up.get('update'):
            st.update(state='current')
        elif not up.get('hand_built'):
            # packaged modules: the package system brings them with nginx (nginxmod tells when it would not)
            st.update(state='packaged', risk=up.get('risk'))
        elif [x for x in up['modules'] if x.get('package')] or not _single_package(up['nginx_package'], up['candidate']):
            # packaged modules next to the hand-built one, or an nginx that needs sibling packages of the same version
            # (Debian's nginx + nginx-common): the update would need the whole set; not supported
            st.update(state='unsupported_packaging')
        elif others:
            # only the ModSecurity module is prepared here; another module built by hand needs the same care
            st.update(state='other_hand_built', modules_by_hand=others)
        else:
            st.update(mode='update', target=up['candidate'])
            st.update(_prepare(cfg, up, 'update', [], log))
    except Exception as e:      # noqa: BLE001 -- reported; tried again next time
        st.update(state='error', error=('%s: %s' % (type(e).__name__, e))[:300])
    # the verified state first: proposing the update reads it (0.5.1: proposing right after the module was verified
    # read the state before, "no module yet", and was refused as not ready)
    _write_status(cfg, st)
    try:
        security(app, st, log)
    except Exception as e:      # noqa: BLE001 -- the update check stands; the advisories are read again next run
        log('nginxup: security advisories: %s' % type(e).__name__)
    _write_status(cfg, st)
    log('nginxup: %s' % st.get('state'))
    return st


def security(app, st, log=print, get=None):
    """0.4.98: nginx's own security advisories against the installed nginx (nginxsec.py): kept in the status, an alert
    for the ones in features this configuration uses, nginx threats of the threat intelligence decided by them, and the
    verified update proposed (an administrator approves it with a one-time code; never applied by itself)."""
    from . import nginxsec
    cfg = app.cfg
    if not cfg['nginxup'].get('advisories') or not st.get('installed'):
        return None
    nginxsec.refresh(cfg, get=get, log=log)
    # a feature this system switched off for now still counts as used: nginx stays vulnerable until it is updated
    from . import protooff
    feats = nginxsec.features(cfg)
    wf = getattr(app, 'workflow', None)
    if wf is not None:
        for f in MITIGABLE:
            try:
                if protooff.state(cfg, from_changes=wf.proto_off_changes(f))[f]['off_by_us']:
                    feats[f] = True
            except Exception:       # noqa: BLE001 -- no configuration to read: as it is
                pass
    a = nginxsec.raise_alerts(app, st, log=log, feats=feats)
    st['security'] = {'version': a['version'], 'exact': a['exact'], 'major_in_use': a['major_in_use'],
                      'fixed_by_candidate': a['fixed_by_candidate'], 'issues': a['issues'][:40]}
    nginxsec.decide_threats(app, st.get('installed'), log=log)
    try:
        st['mitigation'] = mitigate(app, a, log)
    except Exception as e:      # noqa: BLE001 -- the alert stands; tried again next run
        log('nginxup: mitigation: %s' % type(e).__name__)
    used = [i for i in a['issues'] if i['in_use']]
    if used and st.get('state') == 'ready' and rolled_back_from(app.db, st.get('target')):
        # 0.5.25: a person rolled back away from this version: not proposed (nor applied by itself) again; a newer
        # version, or a person proposing it, starts over
        st['skipped_after_rollback'] = st.get('target')
        log('nginxup: %s not proposed again: a person rolled back from it' % st.get('target'))
    elif used and st.get('state') == 'ready' and cfg['nginxup'].get('auto_propose') and getattr(app, 'workflow', None):
        from .changes import ChangeError
        cves = sorted({c for i in used for c in i['cves']})
        try:
            from . import reasons
            cid = app.workflow.propose_nginx(
                reasons.text('nginx_update', version=a['version'], target=st.get('target'),
                             cves=', '.join(cves)[:600] or ', '.join(i['title'] for i in used)[:600],
                             detail=st.get('detail') or 'ready'), 'nginxup', role='admin', auto=True)
            st['proposed_change'] = cid
            log('nginxup: update proposed as change #%d' % cid)
        except ChangeError as e:
            if e.code != 'nginx_change_pending':
                log('nginxup: update not proposed (%s)' % e.code)
    return a


def _single_package(pkg, version):
    from .nginxswap import single_package
    return single_package(pkg, version)


def index_sha256(pkg, version):
    """The SHA-256 apt's signed index gives for one package version of this host's architecture (the root program
    checks it again itself)."""
    from .nginxswap import arch, index_sha256 as idx
    return idx(pkg, version, arch())


def _download(pkg, version, work, root=None):
    """apt-get download one package (not installed) into work; unpack it under root when given.
    Returns (path, sha256, error)."""
    d = tempfile.mkdtemp(dir=work)
    rc, out = _run(['apt-get', 'download', '%s=%s' % (pkg, version)], cwd=d, timeout=600)
    debs = glob.glob(os.path.join(d, '*.deb'))
    if rc != 0 or len(debs) != 1:
        return None, None, 'cannot download %s %s: %s' % (pkg, version, util.clip(out.strip(), 200))
    sha = sha256_file(debs[0])
    want = index_sha256(pkg, version)
    if not want or sha != want:
        return None, None, '%s %s does not match apt\'s index (SHA-256)' % (pkg, version)
    if root:
        rc, out = _run(['dpkg-deb', '-x', debs[0], root], cwd=d)
        if rc != 0:
            return None, None, 'cannot unpack %s: %s' % (os.path.basename(debs[0]), util.clip(out.strip(), 200))
    return debs[0], sha, None


def _keep_debs(cfg, paths):
    """Keep the packages the root program takes (new and previous) in debs/; nothing else."""
    d = os.path.join(base(cfg), 'debs')
    os.makedirs(d, mode=0o750, exist_ok=True)
    names = set()
    for p in paths:
        tmp = os.path.join(d, '.%s.tmp' % os.path.basename(p))
        shutil.copyfile(p, tmp)
        os.replace(tmp, os.path.join(d, os.path.basename(p)))     # never a half-written package for the root program
        names.add(os.path.basename(p))
    for n in os.listdir(d):
        if n not in names:
            try:
                os.unlink(os.path.join(d, n))
            except OSError:
                pass


def _prepare(cfg, up, mode, packaged, log):
    """Try the module waiting for the target nginx: the candidate package's nginx (update; with the candidates of the
    packaged modules that go with it), or the installed one (finish)."""
    pkg = up['nginx_package']
    target = up['candidate'] if mode == 'update' else up['installed']
    mdir = module_dir(cfg, target)
    mod = os.path.join(mdir, MODULE_NAME)
    if not os.path.isfile(mod):
        return {'state': 'no_module', 'module_dir': mdir}
    meta = {}
    try:
        with open(os.path.join(mdir, 'module.json'), encoding='utf-8') as fh:
            meta = json.load(fh)
    except (OSError, ValueError):
        pass
    sha = sha256_file(mod)
    if meta.get('sha256') and meta['sha256'] != sha:
        return {'state': 'failed', 'error': 'the module does not match its description (SHA-256)', 'module_sha256': sha}
    from .nginxswap import trusted_modules
    if sha not in trusted_modules():
        # root loads only a module root itself trusts; nothing is downloaded or tried until then
        return {'state': 'untrusted', 'module_sha256': sha}
    out = {'module_sha256': sha, 'package_sha256': None,
           'module': {k: meta.get(k) for k in ('os', 'arch', 'connector', 'libmodsecurity', 'built_at', 'source', 'nginx_package')}}
    if mode == 'finish':
        ok, detail = try_module(cfg['paths']['nginx_bin'], mod)
    else:
        work = tempfile.mkdtemp(prefix='jtwaf-nginxup-pkg-')
        try:
            root = os.path.join(work, 'root')
            new_deb, out['package_sha256'], err = _download(pkg, target, work, root)
            nginx_new = os.path.join(root, 'usr', 'sbin', 'nginx')
            if err or not os.path.isfile(nginx_new):
                return dict(out, state='error', error=err or 'no usr/sbin/nginx in the %s package' % pkg)
            old_deb, _, err = _download(pkg, up['installed'], work)
            if err:
                return dict(out, state='error', error='the way back: ' + err)
            others = []
            for x in packaged:
                if x.get('candidate') and x['candidate'] != x.get('installed'):
                    _, _, err = _download(x['package'], x['candidate'], work, root)
                    if err:
                        return dict(out, state='error', error=err)
                new = os.path.join(root, os.path.realpath(x['path']).lstrip('/'))
                others.append(new if os.path.isfile(new) else x['path'])
            ok, detail = try_module(nginx_new, mod, others)
            if ok:
                _keep_debs(cfg, [new_deb, old_deb])
        finally:
            shutil.rmtree(work, ignore_errors=True)
    log('nginxup: %s %s (%s): %s' % (pkg, target, mode, detail))
    return dict(out, state='ready' if ok else 'failed', **{'detail' if ok else 'error': detail},
                verified_at=util.iso(time.time()) if ok else None)


MITIGABLE = ('http2', 'http3')


def mitigate(app, a, log=print):
    """0.4.98: a major advisory in HTTP/2 or HTTP/3 while the installed nginx is vulnerable and the configuration has the
    feature on: propose switching it off (protooff.py). Once the installed nginx is vulnerable to no advisory about the
    feature (updated), propose putting back the lines this system switched off. Applied by themselves when
    nginxup.auto_mitigate is on -- not for a distribution's nginx package, which may carry the fixes already (backports):
    a person decides there. Returns what was proposed: {'change_id', 'feature', 'mode'}."""
    from . import protooff
    from .changes import ChangeError
    wf = getattr(app, 'workflow', None)
    if wf is None or not a.get('version'):
        return None
    # what the installed nginx is vulnerable to, whether the feature is on now or switched off already
    vulnerable = {i['feature'] for i in a['issues'] if i['feature'] in MITIGABLE}
    major = {i['feature'] for i in a['issues'] if i['feature'] in MITIGABLE and i['severity'] in ('major', 'high', 'critical')}
    ours = {f: wf.proto_off_changes(f) for f in MITIGABLE}
    todo = []
    for f in MITIGABLE:
        st = protooff.state(app.cfg, from_changes=ours[f])[f]
        if f in major and st['on']:
            todo.append((f, 'off'))
        elif f not in vulnerable and st['off_by_us']:
            todo.append((f, 'on'))
    for f, mode in todo:
        name = f.upper().replace('HTTP', 'HTTP/')
        cves = sorted({c for i in a['issues'] if i['feature'] == f for c in i['cves']})
        from . import reasons
        reason = (reasons.text('proto_off', version=a['version'], proto=name, cves=', '.join(cves)[:400], proto2=name)
                  if mode == 'off' else reasons.text('proto_on', version=a['version'], proto=name))
        try:
            cid = wf.propose_proto(f, mode, reason, 'nginxup', auto=bool(a.get('exact')))
        except ChangeError as e:
            if e.code not in ('proto_change_pending', 'nothing_to_do'):
                log('nginxup: %s %s not proposed (%s)' % (f, mode, e.code))
            continue
        log('nginxup: %s %s proposed as change #%d' % (f, mode, cid))
        return {'change_id': cid, 'feature': f, 'mode': mode}       # one at a time (one open change of this kind)
    return None
