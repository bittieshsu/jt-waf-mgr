"""Root: refresh apt's package lists for the repository nginx comes from, before the nginx update job looks (0.4.98).

The update job (jt-waf-mgr-nginxup.service, user jtwaf) asks apt which nginx comes next; apt answers from lists that
only root refreshes (the system's own daily timer can be a day behind a security release). This short root job
(jt-waf-mgr-nginx-aptrefresh.service; the nginxup timer, or "check now") runs `apt-get update` for the source lists
that name nginx's repositories only -- apt checks the signatures as always -- and then starts the update job. It takes no
input from the job: a request file only says "now" (removed without following links), and systemd limits how often.

  python3 -m jtwafmgr.aptrefresh [--package nginx]
"""
import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

REQUEST_DIR = '/var/lib/jt-waf-mgr/nginxup'
REQUEST = 'refresh.request'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


def _drop_request(d=REQUEST_DIR):
    try:
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        return
    try:
        os.unlink(REQUEST, dir_fd=fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def repo_urls(policy_text):
    """The repositories apt knows the package from (`apt-cache policy` lines '500 http://host/path suite/comp arch ...')."""
    out = []
    for m in re.finditer(r'^\s+-?\d+\s+((?:https?|mirror\+https?|tor\+https?)://\S+)\s+\S+', policy_text or '', re.M):
        u = m.group(1).split('+')[-1] if '+' in m.group(1).split('://')[0] else m.group(1)
        u = u.rstrip('/')
        if u not in out:
            out.append(u)
    return out


def source_files(urls, roots=('/etc/apt/sources.list', '/etc/apt/sources.list.d/*.list', '/etc/apt/sources.list.d/*.sources')):
    found = []
    for pat in roots:
        for p in sorted(glob.glob(pat)):
            try:
                with open(p, encoding='utf-8', errors='replace') as fh:
                    text = fh.read(1024 * 1024)
            except OSError:
                continue
            lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith('#')]
            if any(u in ln.replace(u + '/', u) for ln in lines for u in urls):
                found.append(p)
    return found


def refresh(package='nginx', run=subprocess.run, log=print):
    p = run(['apt-cache', 'policy', package], capture_output=True, text=True, timeout=120, env=ENV)
    urls = repo_urls(p.stdout)
    files = source_files(urls)
    if not files:
        log('aptrefresh: no source list names %s (%s)' % (package, ', '.join(urls) or 'no repository'))
        return 1
    tmp = tempfile.mkdtemp(prefix='jtwaf-aptrefresh-')
    try:
        os.chmod(tmp, 0o700)
        for i, f in enumerate(files):
            ext = '.sources' if f.endswith('.sources') else '.list'
            shutil.copyfile(f, os.path.join(tmp, '%02d%s' % (i, ext)))
        r = run(['apt-get', 'update', '-q', '-o', 'Dir::Etc::sourcelist=/dev/null', '-o', 'Dir::Etc::sourceparts=' + tmp,
                 '-o', 'APT::Get::List-Cleanup=0'], capture_output=True, text=True, timeout=600, env=ENV)
        log('aptrefresh: %s (%s): %s' % (package, ', '.join(files), 'ok' if r.returncode == 0 else
                                          'failed: ' + ((r.stderr or r.stdout or '').strip().splitlines() or [''])[-1][:300]))
        return 0 if r.returncode == 0 else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None):
    ap = argparse.ArgumentParser(prog='jtwafmgr.aptrefresh')
    ap.add_argument('--package', default='nginx')
    a = ap.parse_args(argv)
    if not re.fullmatch(r'[a-z0-9][a-z0-9.+-]{0,60}', a.package):
        return 2
    if os.geteuid() != 0:
        print('aptrefresh: run as root (jt-waf-mgr-nginx-aptrefresh.service)', file=sys.stderr)
        return 2
    _drop_request()
    try:
        return refresh(a.package, log=lambda m: print(m, flush=True))
    except (OSError, subprocess.SubprocessError) as e:
        print('aptrefresh: %s' % type(e).__name__, flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
