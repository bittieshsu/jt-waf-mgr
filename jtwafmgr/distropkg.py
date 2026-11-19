"""Whether a distribution package already carries the fix for a CVE (0.4.99).

Debian and Ubuntu backport security fixes without changing the upstream number: libbrotli1 1.0.9-2+deb12u1 has the
fix for CVE-2026-111497 although upstream fixed it only in 1.0.10. So the upstream number of such a package says
nothing about "affected". What does say it is the package's own change log, installed with it on this host
(/usr/share/doc/<package>/changelog.Debian.gz): the security team names every CVE it fixes there, and the installed
change log only has the entries up to the installed version. Nothing is downloaded.

    fixed       the installed package's change log names the CVE -> the threat does not affect this site
    not_listed  the change log can be read and does not name it -> the distribution has not fixed it (yet)
    unknown     a distribution's version, but its package or change log is not found here -> "check the
                distribution's advisory": never the urgent path on the upstream number alone
"""
import gzip
import os
import re

DPKG_STATUS = '/var/lib/dpkg/status'
DOC_DIR = '/usr/share/doc'
MAX_LOG = 8 * 1024 * 1024        # bytes of change log read (decompressed)
PKG_RE = re.compile(r'^[a-z0-9][a-z0-9+.-]{0,99}$')
# a distribution's own version: a Debian revision (1.0.9-2+deb12u1, 1.30.6-1~bookworm, 2:1.2-3ubuntu0.1)
DISTRO_VER = re.compile(r'^(?:\d+:)?[0-9][\w.+~]*-[\w.+~]+$')
# a version that names its distribution (+deb12u1, ~bookworm, ubuntu0.1, ~bpo12, .el9_4): a distribution's package
# even when it is not installed on this host (another host's software)
DISTRO_TAG = re.compile(r'(?:[+~](?:deb\d|bpo\d|ubuntu|[a-z]+\d*$)|ubuntu\d|\.el\d|\.fc\d)', re.I)
GENERIC = {'server', 'suite', 'open', 'source', 'http', 'library', 'common', 'core', 'tools', 'utils', 'python', 'perl'}


def is_distro_version(version):
    return bool(DISTRO_VER.match(str(version or '').strip()))


def _words(name):
    return {w for w in re.findall(r'[a-z0-9]+', (name or '').lower()) if len(w) >= 4 and w not in GENERIC}


def packages(product, version, status=None, maintainers=None):
    """The installed packages of this exact version whose name or source names the product: [(package, source)].
    maintainers: a dict filled with each package's Maintainer field (0.5.5: Debian's own package or not)."""
    words = _words(product)
    if not words or not version:
        return []
    try:
        with open(status or DPKG_STATUS, encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError:
        return []
    out = []
    for block in text.split('\n\n'):
        f = dict(re.findall(r'^([A-Za-z-]+): (.*)$', block, re.M))
        pkg = (f.get('Package') or '').strip()
        if not PKG_RE.match(pkg) or f.get('Version', '').strip() != version or 'installed' not in (f.get('Status') or ''):
            continue
        if ' not-installed' in f.get('Status', '') or 'config-files' in f.get('Status', ''):
            continue
        src = (f.get('Source') or pkg).split()[0].strip()
        names = re.sub(r'[^a-z0-9]', '', (pkg + ' ' + src).lower())
        if any(w in names for w in words):
            out.append((pkg, src))
            if maintainers is not None:
                maintainers[pkg] = (f.get('Maintainer') or '').strip()
    return out


def _changelog(pkg, doc_dir=None):
    """The installed change log of a package as text, or None."""
    for name in ('changelog.Debian.gz', 'changelog.gz'):
        p = os.path.join(doc_dir or DOC_DIR, pkg, name)
        try:
            with gzip.open(p, 'rb') as fh:
                return fh.read(MAX_LOG).decode('utf-8', 'replace')
        except (OSError, EOFError, gzip.BadGzipFile):
            continue
    return None


def is_debian(pkg, version, maintainer):
    """Debian's own package (its security tracker speaks for it): a Debian security update's version (+deb12u1), or a
    Debian maintainer (an address at debian.org or debian.net). nginx.org's own "1.30.7-1~bookworm" is not."""
    if re.search(r'[+~]deb\d+u\d', version or ''):
        return True
    return bool(re.search(r'@(?:[\w.-]+\.)?debian\.(?:org|net)\b', maintainer or '', re.I))


def check(product, version, cve, status=None, doc_dir=None):
    """{'result': 'fixed' | 'not_listed' | 'unknown', 'package': name or '', 'source': its source package or '',
    'debian': Debian's own package} for a distribution's version, or None (not a distribution's version)."""
    version = str(version or '').strip()
    if not is_distro_version(version) or not re.match(r'^CVE-\d{4}-\d{4,7}$', cve or ''):
        return None
    maint = {}
    pkgs = packages(product, version, status, maint)

    def out(result, pkg):
        src = dict(pkgs).get(pkg, '')
        return {'result': result, 'package': pkg, 'source': src, 'debian': bool(pkg) and is_debian(pkg, version, maint.get(pkg))}
    read = None
    for pkg, _src in pkgs:
        text = _changelog(pkg, doc_dir)
        if text is None:
            continue
        read = read or pkg
        lines = [ln for ln in text.splitlines() if re.search(r'(?<![\w-])%s(?!\d)' % re.escape(cve), ln)]
        if lines:
            if any(re.search(r'\brevert', ln, re.I) for ln in lines):
                return out('unknown', pkg)      # a fix taken back: a person reads it
            return out('fixed', pkg)
    if read:
        return out('not_listed', read)
    if not pkgs and not DISTRO_TAG.search(version):
        return None         # not installed here and nothing says a distribution built it ('18.0-20260404')
    return out('unknown', pkgs[0][0] if pkgs else '')


def apply(t, status=None, doc_dir=None):
    """The check on one threat: t['distro_check']; fixed -> t['affected'] = 'no' (the model's kept as
    t['affected_model'])."""
    from .intel import known_version
    dc = check(t.get('product'), known_version(t.get('our_version')), t.get('id') or '', status, doc_dir)
    if not dc:
        return None
    t['distro_check'] = dc
    if dc['result'] == 'fixed' and t.get('affected') != 'no':
        t['affected_model'], t['affected'] = t.get('affected'), 'no'
    return dc
