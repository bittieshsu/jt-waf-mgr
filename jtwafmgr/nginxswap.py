"""The root side of an nginx update. The web service and the jobs never change nginx.

An update is a change an admin approved (op 'nginx'), made only with a module that the nginxup job tried with exactly
that nginx package. Two root steps:

1. prepare() -- in the apply program (its usual sandbox: no network, /usr read only). Everything is checked again:
   the package version is still what apt offers (or, to finish an update someone already installed, the installed
   one); the module, the new package and the current package (the way back) are copied from the job's directory
   without following links into root's own directory; each package must have the SHA-256 that apt's signed index
   gives for that version (a file the service user downloaded is never trusted for itself); the new package's nginx
   is started with the module on a local port once more and must refuse the test request. Then it writes the request
   for step 2 into root's own directory and starts it.

2. main() -- jt-waf-mgr-nginxswap.service (root, no network, may write /usr: dpkg must). It reads only that request:
   module in place (rename), the verified package installed with dpkg, nginx moved to the new program without
   stopping (the nginx.org package does this itself; otherwise USR2 here); the new master must run the new program,
   `nginx -t` must pass and the health URLs must answer as before -- else the old module and the old package go
   back the same way. The hold mark is put back either way.
"""
import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

PKG_RE = re.compile(r'^[a-z0-9][a-z0-9+.-]{0,60}$')
VER_RE = re.compile(r'^[0-9][A-Za-z0-9.+~:-]{0,60}$')
SHA_RE = re.compile(r'^[0-9a-f]{64}$')
MODULE_NAME = 'ngx_http_modsecurity_module.so'
UNIT = 'jt-waf-mgr-nginxswap.service'
TRUSTED = '/etc/jt-waf-mgr/trusted-modules.sha256'
SWAP_SECONDS = 1800             # TimeoutStartSec of the swap unit
SWAP_STOP_SECONDS = 900         # its TimeoutStopSec (KillMode=mixed: time to put things back); apply waits for both
MAX_HEALTH = 10                 # health URLs checked around an nginx update (each up to 30 s, twice)
TERM = []                       # set when systemd stops the unit: the next step puts everything back
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'}


class SwapFail(Exception):
    def __init__(self, step, summary):
        super().__init__(summary)
        self.step, self.summary = step, summary


def _run(cmd, cwd=None, timeout=300):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, errors='replace', env=ENV)
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except (OSError, subprocess.SubprocessError) as e:
        return None, type(e).__name__


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for b in iter(lambda: fh.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def trusted_modules(path=TRUSTED):
    """The SHA-256s of the modules root trusts: written only by root (the build script run as root on this host, or
    `jt-waf-mgr nginx-module-trust FILE`). The web service and the jobs can read it, never write it. A module that is
    not on it is never loaded by root -- whatever the request or the job's status says."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return set()
    with os.fdopen(fd) as fh:
        st = os.fstat(fh.fileno())
        if st.st_uid != 0 or st.st_mode & 0o022 or not stat.S_ISREG(st.st_mode):
            return set()        # not root's alone: trust nothing
        d = os.stat(os.path.dirname(path))
        if d.st_uid != 0 or d.st_mode & 0o022:
            return set()
        return {ln.split()[0].lower() for ln in fh.read(1 << 20).splitlines() if ln.strip() and SHA_RE.match(ln.split()[0].lower())}


def store_dir(state):
    """Root's own copies of the trusted modules: <sha256>.so (the only module files root ever installs)."""
    return os.path.join(state, 'modules')


def trust(module_path, sha256, state, note='', path=TRUSTED):
    """Root: copy a module file into root's own store and trust it -- only when the copy has exactly the SHA-256 the
    person read from the build output (the file may sit where others can change it). Returns the SHA-256."""
    if os.geteuid() != 0:
        raise SwapFail('trust', 'only root can trust a module (run it with sudo)')
    from . import integrity
    res = integrity.verify_program()
    if res['status'] != 'ok' and not (res['status'] == 'not_installed' and res['dir'] != integrity.INSTALL_DIR):
        raise SwapFail('integrity', 'program integrity check failed (%s): nothing trusted' % (res.get('reason') or res['status']))
    sha256 = (sha256 or '').lower()
    if not SHA_RE.match(sha256):
        raise SwapFail('trust', '--sha256 must be the 64-character SHA-256 the build script printed')
    store = store_dir(state)
    os.makedirs(store, mode=0o700, exist_ok=True)
    os.chmod(store, 0o700)
    tmp = os.path.join(store, '.incoming-%d' % os.getpid())
    try:
        copy_nofollow(module_path, tmp, 16 << 20)
        with open(tmp, 'rb') as fh:
            if fh.read(4) != b'\x7fELF':
                raise SwapFail('trust', 'not a shared object (ELF) file')
        if sha256_file(tmp) != sha256:
            raise SwapFail('trust', 'the file does not have that SHA-256: compare with the build output, nothing trusted')
        os.replace(tmp, os.path.join(store, sha256 + '.so'))
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    try:            # a record outside the database root alone writes (the audit chain is the service user's)
        import syslog
        syslog.openlog('jt-waf-mgr', 0, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_NOTICE, json.dumps({'jt_waf_mgr': {'v': 1, 'kind': 'nginx_module_trusted', 'sha256': sha256,
                                                                    'by_uid': os.getuid(), 'sudo_user': os.environ.get('SUDO_USER', ''),
                                                                    'note': note[:120]}}))
    except Exception:       # noqa: BLE001 -- the list line below is the record that counts
        pass
    if sha256 not in trusted_modules(path):
        line = '%s  %s %s\n' % (sha256, time.strftime('%Y-%m-%dT%H:%M:%S'), re.sub(r'[^\w .:/@+~-]', '', note)[:120])
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
        with os.fdopen(fd, 'a') as fh:
            fh.write(line)
        try:
            import grp
            os.chown(path, 0, grp.getgrnam('jtwaf').gr_gid)       # the web service shows which modules are trusted
        except (KeyError, OSError):
            pass
    return sha256


def owner(nginx_bin):
    """The package that owns the nginx program, as root sees it (never taken from a request)."""
    for p in (os.path.realpath(nginx_bin), nginx_bin):
        rc, out = _run(['dpkg-query', '-S', p], timeout=60)
        if rc == 0 and out:
            name = out.splitlines()[0].split(':')[0].strip()
            if PKG_RE.match(name):
                return name
    return None


def single_package(pkg, version):
    """True when the package can be installed on its own: no exact-version dependency on a sibling package
    (Debian's nginx needs nginx-common of the same version), and no installed package that needs exactly the current
    version of it (nginx.org's nginx-module-*, loaded or not). Such sets are not supported here."""
    rc, out = _run(['apt-cache', 'show', '%s=%s' % (pkg, version)], timeout=60)
    if rc != 0:
        return False
    block = (out or '').split('\n\n')[0]
    if any(re.search(r'\(\s*=', d) for d in re.findall(r'^(?:Pre-)?Depends:\s*(.*)$', block, re.M)):
        return False
    return not exact_dependents(pkg)


def exact_dependents(pkg):
    """Installed packages that depend on exactly one version of pkg."""
    rc, out = _run(['dpkg-query', '-W', '-f=${db:Status-Abbrev}|${Package}|${Pre-Depends}, ${Depends}\n'], timeout=120)
    found = []
    for line in (out or '').splitlines() if rc == 0 else []:
        st, _, rest = line.partition('|')
        name, _, deps = rest.partition('|')
        if st.strip() in ('ii', 'hi') and re.search(r'(?:^|[,|]\s*)%s(?::\w+)?\s*\(\s*=' % re.escape(pkg), deps):
            found.append(name)
    return found


def work_dir(state):
    return os.path.join(state, 'nginx-update')


def check_request(req):
    """Shape of an nginx_update request from the spool (never trusted)."""
    for k, r in (('package', PKG_RE), ('version', VER_RE), ('module_sha256', SHA_RE)):
        if not isinstance(req.get(k), str) or not r.match(req[k]):
            raise SwapFail('request', 'bad %s' % k)
    if not isinstance(req.get('change_id'), int) or req.get('mode') not in ('update', 'finish'):
        raise SwapFail('request', 'bad change id or mode')
    return req


def policy(pkg):
    rc, out = _run(['apt-cache', 'policy', pkg], timeout=60)
    inst = re.search(r'Installed:\s*(\S+)', out or '')
    cand = re.search(r'Candidate:\s*(\S+)', out or '')
    norm = lambda m: None if not m or m.group(1) == '(none)' else m.group(1)   # noqa: E731
    return norm(inst), norm(cand)


def index_sha256(pkg, version, arch):
    """The SHA-256 apt's signed index gives for one package version (None when it has none)."""
    rc, out = _run(['apt-cache', 'show', '%s=%s' % (pkg, version)], timeout=60)
    if rc != 0:
        return None
    for block in (out or '').split('\n\n'):
        a = re.search(r'^Architecture:\s*(\S+)', block, re.M)
        s = re.search(r'^SHA256:\s*([0-9a-f]{64})', block, re.M)
        if s and (not a or a.group(1) in (arch, 'all')):
            return s.group(1)
    return None


def held(pkg):
    rc, out = _run(['apt-mark', 'showhold'], timeout=60)
    return rc == 0 and pkg in (out or '').split()


def copy_nofollow(src, dst, limit):
    """Copy a file the service user owns without following links; anything but a plain file is refused."""
    try:
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        raise SwapFail('files', 'cannot open %s: %s' % (os.path.basename(src), e.strerror))
    with os.fdopen(fd, 'rb') as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise SwapFail('files', '%s is not a plain file or too large' % os.path.basename(src))
        with open(dst, 'wb') as out:
            while True:
                b = fh.read(1 << 20)
                if not b:
                    break
                out.write(b)
                limit -= len(b)
                if limit < 0:
                    raise SwapFail('files', '%s grew while copied' % os.path.basename(src))
    os.chmod(dst, 0o600)


def _main_level(path, prefix, seen=None, depth=0, confdir=None):
    """load_module lines of the main context: the main file and the files its top-level include lines name (as
    Debian's modules-enabled/*.conf). Read directly: `nginx -T` prints nothing exactly when it matters (the installed
    nginx no longer loads the module)."""
    seen = seen if seen is not None else set()
    out = []
    confdir = confdir or os.path.dirname(path)
    for f in sorted(glob.glob(path if path.startswith('/') else os.path.join(confdir, path))):
        if f in seen or depth > 4:
            continue
        seen.add(f)
        try:
            with open(f, encoding='utf-8', errors='replace') as fh:
                text = fh.read()
        except OSError:
            continue
        level = 0
        for line in text.splitlines():
            code = line.split('#', 1)[0]
            if level == 0:
                m = re.match(r'\s*load_module\s+"?([^";\s]+)"?\s*;', code)
                if m:
                    out.append(m.group(1))
                m = re.match(r'\s*include\s+"?([^";\s]+)"?\s*;', code)
                if m:
                    out += _main_level(m.group(1), prefix, seen, depth + 1, confdir)
            level += code.count('{') - code.count('}')
    return out


def module_target(nginx_bin):
    """The file the configuration loads the ModSecurity module from (the one that is replaced)."""
    v = _run([nginx_bin, '-V'], timeout=30)[1] or ''
    m = re.search(r'--prefix=(\S+)', v)
    prefix = (m.group(1).rstrip('/') if m else '/etc/nginx') + '/'
    m = re.search(r'--conf-path=(\S+)', v)
    conf = m.group(1) if m else prefix + 'conf/nginx.conf'
    found = set()
    for p in _main_level(conf, prefix):
        if 'modsecurity' in os.path.basename(p).lower():
            found.add(os.path.realpath(p if p.startswith('/') else prefix + p))
    if len(found) != 1:
        raise SwapFail('module', 'expected one ModSecurity load_module line, found %d' % len(found))
    return found.pop()


def arch():
    rc, out = _run(['dpkg', '--print-architecture'], timeout=30)
    return (out or '').strip() if rc == 0 else ''


def as_nobody(try_module, nginx_bin, module, work=None):
    """try_module in a child process running as nobody: no root process loads a module before it is installed, not
    even a trusted one. The program and the module are copied where nobody can read them. Returns (ok, detail)."""
    import pwd
    nob = pwd.getpwnam('nobody')
    d = tempfile.mkdtemp(prefix='jtwaf-try-')            # the apply unit's own /tmp (PrivateTmp)
    try:
        os.chmod(d, 0o755)
        prog, mod = os.path.join(d, 'nginx'), os.path.join(d, MODULE_NAME)
        shutil.copyfile(nginx_bin, prog)
        shutil.copyfile(module, mod)
        os.chmod(prog, 0o755)
        os.chmod(mod, 0o644)
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:            # pragma: no cover -- the child
            try:
                os.close(r)
                os.closerange(3, w)
                os.closerange(w + 1, 65536)
                os.setgroups([])
                os.setgid(nob.pw_gid)
                os.setuid(nob.pw_uid)
                ok, detail = try_module(prog, mod)
                os.write(w, json.dumps([bool(ok), str(detail)[:2000]]).encode())
            except BaseException as e:      # noqa: BLE001
                os.write(w, json.dumps([False, 'test as nobody: %s: %s' % (type(e).__name__, str(e)[:200])]).encode())
            finally:
                os._exit(0)
        os.close(w)
        data = b''
        while True:
            b = os.read(r, 4096)
            if not b:
                break
            data += b
        os.close(r)
        os.waitpid(pid, 0)
        try:
            ok, detail = json.loads(data.decode())
            return bool(ok), str(detail)
        except ValueError:
            return False, 'the test as nobody gave no answer'
    finally:
        shutil.rmtree(d, ignore_errors=True)


# --- step 1: in the apply program ----------------------------------------------------------------------------------
def prepare(applier, req, job_dir, try_module, log):
    """Check everything, put the verified files into root's directory, run step 2, return its result."""
    check_request(req)
    pkg, ver = req['package'], req['version']
    if owner(applier.nginx) != pkg:
        raise SwapFail('preflight', 'nginx does not come from the package %s' % pkg)
    if req['module_sha256'] not in trusted_modules():
        raise SwapFail('trust', 'the module is not trusted by root: run `sudo jt-waf-mgr nginx-module-trust FILE --sha256 HASH` '
                                'on this host (the build script run as root here does it itself)')
    if applier.swap_busy():
        raise SwapFail('preflight', 'an nginx update is still running')
    inst, cand = policy(pkg)
    if req['mode'] == 'update' and (cand != ver or inst == ver):
        raise SwapFail('preflight', 'apt now offers %s %s (installed %s), not the verified %s' % (pkg, cand, inst, ver))
    if req['mode'] == 'finish' and inst != ver:
        raise SwapFail('preflight', 'the installed %s is %s, not %s' % (pkg, inst, ver))
    if req['mode'] == 'update' and not single_package(pkg, ver):
        raise SwapFail('preflight', '%s %s needs other packages of the same version; not supported' % (pkg, ver))
    if not applier.master_pid():
        raise SwapFail('preflight', 'nginx is not running')
    base = work_dir(applier.state)
    os.makedirs(base, mode=0o700, exist_ok=True)
    olds = sorted((x for x in os.listdir(base) if re.match(r'c\d+-', x)), key=lambda x: os.path.getmtime(os.path.join(base, x)))
    for x in olds[:-4]:             # the last few attempts stay for people to look at
        shutil.rmtree(os.path.join(base, x), ignore_errors=True)
    work = tempfile.mkdtemp(prefix='c%d-%s-' % (req['change_id'], time.strftime('%Y%m%d-%H%M%S')), dir=base)
    # the module: root's own copy made when it was trusted (never the file in the service user's directory)
    mod = os.path.join(work, MODULE_NAME)
    try:
        shutil.copyfile(os.path.join(store_dir(applier.state), req['module_sha256'] + '.so'), mod)
        os.chmod(mod, 0o600)
    except OSError:
        raise SwapFail('trust', 'root has no copy of that module: trust it again with `nginx-module-trust FILE --sha256 HASH`')
    if sha256_file(mod) != req['module_sha256']:
        raise SwapFail('module', "root's copy of the module does not have its SHA-256")
    a = arch()
    debs = {}
    for role, v in (('new', ver), ('old', inst)) if req['mode'] == 'update' else ():
        want = index_sha256(pkg, v, a)
        if not want:
            raise SwapFail('package', "apt's index has no %s %s: %s" % (pkg, v, 'no way back' if role == 'old' else 'cannot check it'))
        src = os.path.join(job_dir, 'debs', '%s_%s_%s.deb' % (pkg, v.replace(':', '%3a'), a))
        dst = os.path.join(work, '%s.deb' % role)
        copy_nofollow(src, dst, 256 << 20)
        if sha256_file(dst) != want:
            raise SwapFail('package', '%s %s does not match the SHA-256 in apt\'s index' % (pkg, v))
        debs[role] = dst
    target = module_target(applier.nginx)
    if req['mode'] == 'update':
        root = os.path.join(work, 'unpacked')
        rc, out = _run(['dpkg-deb', '-x', debs['new'], root], timeout=300)
        new_bin = os.path.join(root, 'usr', 'sbin', 'nginx')
        ok, detail = as_nobody(try_module, new_bin, mod, work) if rc == 0 and os.path.isfile(new_bin) else (False, (out or '')[-200:])
        shutil.rmtree(root, ignore_errors=True)
    else:
        ok, detail = as_nobody(try_module, applier.nginx, mod, work)
    if not ok:
        raise SwapFail('verify', 'the module did not pass with nginx %s: %s' % (ver, detail))
    log.append('verified %s %s with the module %s (again, as nobody)' % (pkg, ver, req['module_sha256'][:12]))
    # the health URLs root itself reads from the database (not the request): the list people set in Settings
    urls = applier.stored_health_urls()
    plan = {'change_id': req['change_id'], 'mode': req['mode'], 'package': pkg, 'version': ver, 'previous': inst,
            'work': work, 'module': mod, 'target': target, 'new_deb': debs.get('new'), 'old_deb': debs.get('old'),
            'health_urls': urls, 'nginx': applier.nginx}
    tmp = os.path.join(base, 'request.json.tmp')
    try:
        os.unlink(tmp)
    except OSError:
        pass
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as fh:
        json.dump(plan, fh)        # root's alone: step 2 refuses anything else
    os.replace(os.path.join(base, 'request.json.tmp'), os.path.join(base, 'request.json'))
    for f in ('result.json',):
        try:
            os.unlink(os.path.join(base, f))
        except OSError:
            pass
    rc, out = _run(['systemctl', 'start', UNIT], timeout=SWAP_SECONDS + SWAP_STOP_SECONDS + 120)
    try:
        with open(os.path.join(base, 'result.json')) as fh:
            res = json.load(fh)
    except (OSError, ValueError):
        # nobody knows how far it got: treat it as half done (critical alert, a person looks)
        e = SwapFail('install', 'the update unit gave no result (%s): %s' % (rc, (out or '').strip()[-300:]))
        e.half, e.not_held = True, False
        raise e
    finally:
        try:
            os.unlink(os.path.join(base, 'request.json'))
        except OSError:
            pass
    log.extend(res.get('log') or [])
    if res.get('result') != 'ok':
        e = SwapFail(res.get('step') or 'install', res.get('summary') or 'failed')
        e.half, e.not_held = bool(res.get('half')), bool(res.get('not_held'))
        raise e
    return res


# --- step 2: jt-waf-mgr-nginxswap.service --------------------------------------------------------------------------
def master():
    for f in ('/run/nginx.pid', '/var/run/nginx.pid'):
        try:
            with open(f) as fh:
                return int(fh.read().strip())
        except (OSError, ValueError):
            continue
    return None


def exe(pid):
    try:
        return os.readlink('/proc/%d/exe' % pid)
    except (OSError, TypeError):
        return None


def hot_upgrade(wait=15):
    """Move the running nginx to the program now on disk without stopping it: USR2, wait for the new master, then QUIT
    the old one. Returns the new master's pid."""
    old = master()
    if not old:
        raise SwapFail('upgrade', 'nginx is not running')
    pidfile = '/run/nginx.pid' if os.path.exists('/run/nginx.pid') else '/var/run/nginx.pid'
    os.kill(old, signal.SIGUSR2)
    t0 = time.time()
    while time.time() - t0 < wait:
        new = master()
        if os.path.exists(pidfile + '.oldbin') and new and new != old:
            time.sleep(1)
            try:
                os.kill(new, 0)             # the new master is still there (not dead right after writing its pid)
            except OSError:
                break
            if not _children(new):
                time.sleep(0.2)
                continue
            os.kill(old, signal.SIGQUIT)
            return new
        time.sleep(0.2)
    raise SwapFail('upgrade', 'the new nginx master did not start (the old one keeps running)')


def _children(pid):
    """Worker processes of a master."""
    out = []
    for d in os.listdir('/proc'):
        if d.isdigit():
            try:
                with open('/proc/%s/stat' % d) as fh:
                    if int(fh.read().rsplit(')', 1)[1].split()[1]) == pid:
                        out.append(int(d))
            except (OSError, ValueError, IndexError):
                continue
    return out


def place_module(src, target):
    """Rename the module into place: the running nginx keeps the file it loaded."""
    tmp = os.path.join(os.path.dirname(target), '.%s.jt-waf-mgr-new' % os.path.basename(target))
    shutil.copyfile(src, tmp)
    os.chmod(tmp, 0o644)
    os.replace(tmp, target)


def _installed(pkg):
    """The installed version, only when the package is fully installed (not half-configured)."""
    rc, out = _run(['dpkg-query', '-W', '-f=${db:Status-Abbrev}|${Version}', pkg], timeout=60)
    st, _, ver = (out or '').partition('|')
    return ver.strip() if rc == 0 and st.strip() in ('ii', 'hi') else None


def nginx_t(nginx):
    return _run([nginx, '-t'], timeout=120)[0] == 0


def running_new(pid0):
    pid = master()
    return pid and pid != pid0 and not (exe(pid) or '').endswith(' (deleted)')


def swap(plan, health, log):
    """Step 2 itself. health(urls) -> {url: status}."""
    pkg, nginx = plan['package'], plan['nginx']
    was_held = held(pkg)
    old_mod = os.path.join(plan['work'], 'previous-' + MODULE_NAME)
    shutil.copyfile(plan['target'], old_mod)
    urls = plan['health_urls']
    before = health(urls)
    pid0 = master()

    def back(why):
        """The previous package first, then its module: the module on disk always matches the program on disk."""
        msg = [why]
        try:
            pkg_back = True
            if plan.get('old_deb') and _installed(pkg) != plan['previous']:
                rc, out = _run(['dpkg', '--force-confold', '--force-confdef', '-i', plan['old_deb']], timeout=None)
                pkg_back = rc == 0 and _installed(pkg) == plan['previous']
                msg.append('previous package %s' % ('reinstalled' if pkg_back else 'NOT reinstalled: ' + (out or '').strip()[-200:]))
            if pkg_back:
                place_module(old_mod, plan['target'])
            else:
                plan['half'] = True     # the new program stays on disk, so does the new module that matches it
                msg.append('the new module stays with the new program on disk')
            pid = master()
            if pid and (exe(pid) or '').endswith(' (deleted)') and nginx_t(nginx):
                hot_upgrade()
            t_ok = nginx_t(nginx)
            msg.append('after restoring: nginx -t %s' % ('ok' if t_ok else 'FAILS -- look at it now'))
            if not t_ok or plan['mode'] == 'finish':
                plan['half'] = True     # finishing failed: the original broken state (the next restart fails)
        except BaseException as e:      # noqa: BLE001 -- reported; a person has to look
            plan['half'] = True
            msg.append('restoring failed: %s: %s' % (type(e).__name__, e))
        return '; '.join(msg)

    try:
        try:
            place_module(plan['module'], plan['target'])
            if plan.get('new_deb'):
                rc, out = _run(['dpkg', '--force-confold', '--force-confdef', '-i', plan['new_deb']], timeout=None)
                if rc != 0:
                    raise SwapFail('install', 'dpkg -i failed: %s' % (out or '').strip()[-300:])
                log.append('installed %s %s' % (pkg, plan['version']))
                time.sleep(1)
            if TERM:
                raise SwapFail('stopped', 'stopped by systemd (time limit)')
            if not running_new(pid0):
                # the package did not move nginx to the new program itself (or finishing an update): without stopping
                if not nginx_t(nginx):
                    raise SwapFail('test', 'nginx -t fails with the new program and module')
                hot_upgrade()
                time.sleep(1)
            if not running_new(pid0):
                raise SwapFail('upgrade', 'nginx does not run the new program')
            if not nginx_t(nginx):
                raise SwapFail('test', 'nginx -t fails after the update')
            if TERM:
                raise SwapFail('stopped', 'stopped by systemd (time limit)')
            after = health(urls)
            diff = {u: [before.get(u), after.get(u)] for u in urls if before.get(u) != after.get(u)}
            if diff:
                raise SwapFail('health', 'health checks changed: %s' % json.dumps(diff)[:300])
            log.append('nginx runs %s %s with the module; health checks as before (%d)' % (pkg, plan['version'], len(urls)))
        except SwapFail as e:
            raise SwapFail(e.step, back(e.summary))
        except BaseException as e:      # noqa: BLE001 -- also SystemExit / KeyboardInterrupt: put things back first
            raise SwapFail('install', back('%s: %s' % (type(e).__name__, e)))
    finally:
        if was_held or plan['mode'] == 'update':
            # installing drops the mark; a hand-built module needs it (dpkg may still hold its lock for a moment)
            for _ in range(5):
                if _run(['apt-mark', 'hold', pkg], timeout=120)[0] == 0 and held(pkg):
                    break
                time.sleep(3)
            else:
                log.append('WARNING: could not hold %s again: hold it by hand (apt-mark hold %s)' % (pkg, pkg))
                plan['not_held'] = True
    return {'result': 'ok', 'step': 'done', 'previous': plan['previous'], 'backup': plan['work']}


def main(argv=None):
    ap = argparse.ArgumentParser(prog='jt-waf-mgr-nginxswap')
    ap.add_argument('--config', default=None)
    a = ap.parse_args(argv)
    if os.geteuid() != 0:
        print('must run as root', file=sys.stderr)
        return 1
    from . import config as config_mod, integrity
    from .apply import Applier
    cfg = config_mod.load(a.config or config_mod.default_path())
    applier = Applier(cfg)
    base = work_dir(applier.state)
    log = []
    import fcntl
    os.makedirs(base, mode=0o700, exist_ok=True)
    lockf = open(os.path.join(base, 'swap.lock'), 'w')
    fcntl.flock(lockf, fcntl.LOCK_EX)
    # stopped by systemd (time limit): unwind through the finally blocks, so the hold mark is put back
    signal.signal(signal.SIGTERM, lambda *a: TERM.append(1))      # checked between the steps (dpkg is never cut)
    plan = {}
    try:
        res = integrity.verify_program(key_path=cfg['integrity']['release_key'])
        if res['status'] != 'ok' and not (res['status'] == 'not_installed' and res['dir'] != integrity.INSTALL_DIR):
            raise SwapFail('integrity', 'program integrity check failed (%s)' % (res.get('reason') or res['status']))
        p = os.path.join(base, 'request.json')
        st = os.lstat(p)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            raise SwapFail('request', 'the request is not root\'s own file')
        with open(p) as fh:
            plan = json.load(fh)
        if not os.path.realpath(plan['work']).startswith(os.path.realpath(base) + os.sep):
            raise SwapFail('request', 'the work directory is not root\'s own')
        out = swap(plan, applier.health, log)
    except SwapFail as e:
        out = {'result': 'failed', 'step': e.step, 'summary': e.summary}
    except BaseException as e:      # noqa: BLE001 -- SystemExit from SIGTERM too: a result is always written
        out = {'result': 'failed', 'step': 'install', 'summary': '%s: %s' % (type(e).__name__, str(e)[:300])}
    out['log'] = log
    out['half'] = bool(plan.get('half'))
    out['not_held'] = bool(plan.get('not_held'))
    with open(os.path.join(base, 'result.json.tmp'), 'w') as fh:
        json.dump(out, fh)
    os.replace(os.path.join(base, 'result.json.tmp'), os.path.join(base, 'result.json'))
    print(json.dumps(out), flush=True)
    return 0 if out['result'] == 'ok' else 1


if __name__ == '__main__':
    sys.exit(main())
