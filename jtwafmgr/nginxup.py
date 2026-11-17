"""Getting ready for an nginx update before it happens, so that the WAF is never left behind (with nginxmod.py).

jt-waf-mgr-nginxup.service (daily timer, or "check now" / a module upload on the page) -- a job that may reach the
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
        st.update(installed=up.get('installed'), candidate=up.get('candidate'), package=up.get('nginx_package'),
                  held=up.get('held'), supported=up.get('supported'))
        if not up.get('supported') or not up.get('nginx_package'):
            st.update(state='unsupported')
        elif not up.get('update'):
            st.update(state='current')
        elif not up.get('hand_built'):
            # packaged modules: the package system brings them with nginx (nginxmod tells when it would not)
            st.update(state='packaged', risk=up.get('risk'))
        else:
            others = [m for m in up['hand_built'] if 'modsecurity' not in os.path.basename(m).lower()]
            if others:
                # only the ModSecurity module is prepared here; another module built by hand needs the same care
                st.update(state='other_hand_built', modules_by_hand=others)
            else:
                st.update(_prepare(cfg, up, [x for x in up['modules'] if x.get('package')], log))
    except Exception as e:      # noqa: BLE001 -- reported; tried again next time
        st.update(state='error', error=('%s: %s' % (type(e).__name__, e))[:300])
    _write_status(cfg, st)
    log('nginxup: %s' % st.get('state'))
    return st


def _download(pkg, version, work, root):
    """apt-get download one package (not installed) and unpack it under root. Returns (sha256, error)."""
    d = tempfile.mkdtemp(dir=work)
    rc, out = _run(['apt-get', 'download', '%s=%s' % (pkg, version)], cwd=d, timeout=600)
    debs = glob.glob(os.path.join(d, '*.deb'))
    if rc != 0 or len(debs) != 1:
        return None, 'cannot download %s %s: %s' % (pkg, version, util.clip(out.strip(), 200))
    rc, out = _run(['dpkg-deb', '-x', debs[0], root], cwd=d)
    if rc != 0:
        return None, 'cannot unpack %s: %s' % (os.path.basename(debs[0]), util.clip(out.strip(), 200))
    return sha256_file(debs[0]), None


def _prepare(cfg, up, packaged, log):
    """Download the candidate nginx package (and the candidates of the packaged modules that go with it), then try
    the module waiting for it in that new nginx."""
    pkg, cand = up['nginx_package'], up['candidate']
    mdir = module_dir(cfg, cand)
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
    work = tempfile.mkdtemp(prefix='jtwaf-nginxup-pkg-')
    try:
        root = os.path.join(work, 'root')
        deb_sha, err = _download(pkg, cand, work, root)
        nginx_new = os.path.join(root, 'usr', 'sbin', 'nginx')
        if err or not os.path.isfile(nginx_new):
            return {'state': 'error', 'error': err or 'no usr/sbin/nginx in the %s package' % pkg}
        others = []
        for x in packaged:
            if x.get('candidate') and x['candidate'] != x.get('installed'):
                _, err = _download(x['package'], x['candidate'], work, root)
                if err:
                    return {'state': 'error', 'error': err}
            new = os.path.join(root, os.path.realpath(x['path']).lstrip('/'))
            others.append(new if os.path.isfile(new) else x['path'])
        ok, detail = try_module(nginx_new, mod, others)
        log('nginxup: %s %s: %s' % (pkg, cand, detail))
        return {'state': 'ready' if ok else 'failed', 'module_sha256': sha, 'package_sha256': deb_sha,
                'module': {k: meta.get(k) for k in ('os', 'arch', 'connector', 'libmodsecurity', 'built_at', 'source', 'nginx_package')},
                'detail' if ok else 'error': detail, 'verified_at': util.iso(time.time()) if ok else None}
    finally:
        shutil.rmtree(work, ignore_errors=True)
