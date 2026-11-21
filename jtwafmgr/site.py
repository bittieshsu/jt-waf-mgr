"""Cached view of the site's nginx + ModSecurity configuration (re-read when files change)."""
import glob
import os
import subprocess
import threading
import time

from .modsecconf import ModsecConfig
from .nginxconf import NginxConfig


class Site:
    def __init__(self, cfg, check_every=30):
        self.cfg = cfg
        self.check_every = check_every
        self._lock = threading.Lock()
        self._nginx = None
        self._modsec = None
        self._checked = 0
        self._nginx_version = None

    def _stale(self):
        # 0.5.29: a file added to or removed from an include directory (a new vhost in sites-enabled/) changes no
        # known file's mtime; without this the web service kept the old view and its snapshots flapped against the CLI's
        for conf in (self._nginx, self._modsec):
            for pattern, found in getattr(conf, 'globs', {}).items():
                if tuple(sorted(glob.glob(pattern))) != found:
                    return True
        for files in (self._nginx.files, self._modsec.files):
            for f, mt in files.items():
                try:
                    if os.stat(f).st_mtime != mt:
                        return True
                except OSError:
                    return True
        return False

    def load(self, fresh=False):
        """fresh: look at the files now, not after check_every (the configuration fingerprint must never be taken
        from an older view than another process's, or the snapshots flap between the two)."""
        with self._lock:
            t = time.time()
            if self._nginx is None or ((fresh or t - self._checked > self.check_every) and self._stale()):
                n = NginxConfig(self.cfg['paths']['nginx_conf'])
                m = ModsecConfig(n, self.cfg)
                self._nginx, self._modsec = n, m
                self._index = {}
                for r in m.rules:
                    if r.id is not None:
                        self._index.setdefault(r.id, r)
            if t - self._checked > self.check_every:
                self._checked = t
            return self._nginx, self._modsec

    def rule(self, rid):
        self.load()
        return self._index.get(rid)

    def nginx_version(self):
        if self._nginx_version is None:
            try:
                p = subprocess.run([self.cfg['paths']['nginx_bin'], '-v'], capture_output=True, text=True, timeout=5)
                out = (p.stderr or p.stdout).strip()
                self._nginx_version = out.split('/', 1)[1].split()[0] if '/' in out else out or ''
            except (OSError, subprocess.SubprocessError):
                self._nginx_version = ''
        return self._nginx_version or None
