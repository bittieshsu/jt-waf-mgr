"""Unit tests (synthetic data only).

They also run on the production host, as root (release gate G10). Before any test builds a configuration, every default
path that points at the system (the apply spool, the managed rule files, the IP block list, the database, ...) is moved
under a temporary directory: a test that forgets to set one of them writes there, never into the host's own -- a
request left in the real spool would be applied to the real nginx by the root apply program.
"""
import atexit
import shutil
import tempfile

from jtwafmgr import config as _config

SYSTEM_PREFIXES = ('/var/lib/', '/var/log/', '/var/backups/', '/etc/nginx/', '/etc/jt-waf-mgr/', '/run/')
ROOT = tempfile.mkdtemp(prefix='jtwaf-tests-')
atexit.register(shutil.rmtree, ROOT, True)


def _move(d):
    for k, v in d.items():
        if isinstance(v, dict):
            _move(v)
        elif isinstance(v, str) and v.startswith(SYSTEM_PREFIXES):
            d[k] = ROOT + v


_move(_config.DEFAULTS)
