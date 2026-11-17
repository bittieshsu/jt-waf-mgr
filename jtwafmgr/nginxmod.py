"""Whether nginx can load its ModSecurity module -- now, and after the next system update.

An nginx dynamic module is built for one nginx version. When a system update brings a newer nginx and nothing
brings the matching module, nginx no longer loads the module (or no longer starts), and the easy way out is to take
the WAF away. Here:

- now: a throwaway nginx with only the production load_module lines runs `nginx -t` (as the service user, in a
  temporary directory, never the production configuration): it says whether every module loads with the installed
  nginx;
- next update (Debian / Ubuntu): the package lists apt already keeps (no download) say whether nginx has a newer
  version, whether nginx is held, and -- for a packaged module -- whether the module package's nginx-abi dependency
  matches the newer nginx. A module no package owns (built by hand) never follows an nginx update by itself.

The result is cached per program and module file (size and time) and read by the system check, the health API and
the alert.
"""
import os
import re
import shutil
import subprocess
import tempfile
import time

from . import util

TTL = 6 * 3600
_cache = {}


def _run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors='replace',
                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
        return p.returncode, (p.stdout or '') + (p.stderr or '')
    except (OSError, subprocess.SubprocessError) as e:
        return None, type(e).__name__


def modules(app):
    """The production load_module paths (absolute), and whether ModSecurity is among them or built into nginx."""
    try:
        mods = app.workflow.sandbox._modules()
    except Exception:       # noqa: BLE001 -- an unreadable configuration: nothing to load
        mods = []
    static = False
    rc, out = _run([app.cfg['paths']['nginx_bin'], '-V'])
    if rc == 0 and re.search(r'add-(?:dynamic-)?module=\S*modsecurity', out, re.I) and not any('modsecurity' in m.lower() for m in mods):
        static = 'add-module' in out.lower() and 'add-dynamic-module' not in out.lower()
    return mods, static


def load_test(nginx_bin, mods):
    """`nginx -t` of a configuration with only these load_module lines. Returns {'ok', 'error', 'incompatible'}."""
    if not mods:
        return {'ok': True, 'error': None, 'incompatible': []}
    d = tempfile.mkdtemp(prefix='jtwaf-modtest-')
    try:
        for x in ('logs', 'tmp'):
            os.makedirs(os.path.join(d, x))
        conf = os.path.join(d, 'nginx.conf')
        with open(conf, 'w') as fh:
            fh.write(''.join('load_module %s;\n' % m for m in mods))
            fh.write('pid %s/nginx.pid;\nerror_log %s/logs/error.log warn;\nevents { worker_connections 16; }\n'
                     'http { access_log off; client_body_temp_path %s/tmp/b; proxy_temp_path %s/tmp/p; '
                     'fastcgi_temp_path %s/tmp/f; uwsgi_temp_path %s/tmp/u; scgi_temp_path %s/tmp/s; }\n' % ((d,) * 7))
        rc, out = _run([nginx_bin, '-t', '-q', '-p', d + '/', '-c', conf, '-e', os.path.join(d, 'logs', 'error.log')])
        if rc is None:
            return {'ok': None, 'error': 'nginx could not be run: %s' % out, 'incompatible': []}
        bad = [m for m in mods if m in out and re.search(r'not binary compatible|version \d+ instead of \d+|dlopen\(\)', out)]
        if rc == 0:
            return {'ok': True, 'error': None, 'incompatible': []}
        line = next((ln for ln in out.splitlines() if 'emerg' in ln or 'error' in ln.lower()), out.strip()[:300])
        return {'ok': False, 'error': util.clip(line.strip(), 300), 'incompatible': bad}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _owner(path):
    if not shutil.which('dpkg-query'):
        return None
    rc, out = _run(['dpkg-query', '-S', path])
    if rc != 0:
        return ''
    return out.split(':', 1)[0].strip().split(',')[0].strip()


def _policy(pkg):
    rc, out = _run(['apt-cache', 'policy', pkg])
    if rc != 0:
        return None, None
    inst = re.search(r'^\s*Installed:\s*(\S+)', out, re.M)
    cand = re.search(r'^\s*Candidate:\s*(\S+)', out, re.M)
    inst = inst.group(1) if inst and inst.group(1) != '(none)' else None
    cand = cand.group(1) if cand and cand.group(1) != '(none)' else None
    return inst, cand


def _field(pkg, version, name):
    rc, out = _run(['apt-cache', 'show', '%s=%s' % (pkg, version)])
    if rc != 0:
        return ''
    m = re.search(r'^%s:\s*(.*)$' % re.escape(name), out, re.M)
    return m.group(1) if m else ''


def _abis(text):
    return set(re.findall(r'nginx-abi-[0-9][\w.~+-]*', text or ''))


def update_risk(nginx_bin, mods):
    """What the next system update would do to nginx and its modules (Debian / Ubuntu; no download)."""
    if not (shutil.which('apt-cache') and shutil.which('dpkg-query')):
        return {'supported': False}
    pkg = _owner(os.path.realpath(nginx_bin)) or _owner(nginx_bin)
    if not pkg:
        return {'supported': True, 'nginx_package': None, 'note': 'nginx is not from a package'}
    inst, cand = _policy(pkg)
    rc, held = _run(['apt-mark', 'showhold'])
    held = pkg in (held or '').split() if rc == 0 else None
    out = {'supported': True, 'nginx_package': pkg, 'installed': inst, 'candidate': cand, 'held': held,
           'update': bool(inst and cand and inst != cand), 'modules': []}
    provides = _abis(_field(pkg, cand, 'Provides')) if cand else set()
    for m in mods:
        mp = _owner(os.path.realpath(m)) or _owner(m)
        item = {'path': m, 'package': mp or None}
        if mp:
            mi, mc = _policy(mp)
            need = _abis(_field(mp, mc, 'Depends')) if mc else set()
            item.update(installed=mi, candidate=mc, needs=sorted(need))
            # a packaged module follows nginx when its candidate wants the nginx-abi the new nginx provides
            item['follows'] = (not out['update']) or (bool(need) and bool(need & provides))
        else:
            item['follows'] = not out['update']          # built by hand: never follows an update
        out['modules'].append(item)
    out['risk'] = out['update'] and not held and any(not x['follows'] for x in out['modules'])
    out['hand_built'] = [x['path'] for x in out['modules'] if not x['package']]
    return out


def _key(app, mods):
    parts = [app.cfg['paths']['nginx_bin']] + list(mods)
    sig = []
    for p in parts:
        try:
            st = os.stat(p)
            sig.append((p, st.st_size, st.st_mtime_ns))
        except OSError:
            sig.append((p, None, None))
    return tuple(sig)


def status(app, force=False, now=None):
    """{'modsecurity': loaded?, 'load': load_test(), 'update': update_risk(), 'checked_at'} -- cached."""
    now = now or time.time()
    mods, static = modules(app)
    key = _key(app, mods)
    hit = _cache.get('s')
    if not force and hit and hit[0] == key and now - hit[1] < TTL:
        return hit[2]
    nginx_bin = app.cfg['paths']['nginx_bin']
    st = {'modules': mods, 'modsecurity_module': any('modsecurity' in m.lower() for m in mods) or static,
          'static': static, 'nginx_version': app.site.nginx_version(), 'checked_at': util.iso(now)}
    st['load'] = load_test(nginx_bin, mods) if os.path.exists(nginx_bin) else {'ok': None, 'error': 'no nginx program',
                                                                                'incompatible': []}
    st['update'] = update_risk(nginx_bin, mods)
    _cache['s'] = (key, now, st)
    return st


def level(st):
    """ok / warning / critical with the reason key, for the system check and the health API."""
    if st['load'].get('ok') is False:
        return 'critical', 'module_does_not_load'
    if not st['modsecurity_module']:
        return 'warning', 'no_modsecurity_module'
    up = st.get('update') or {}
    if up.get('risk'):
        return 'warning', 'update_would_break'
    if up.get('supported') and up.get('hand_built') and up.get('held') is False:
        return 'warning', 'not_held'
    return 'ok', 'ok'
