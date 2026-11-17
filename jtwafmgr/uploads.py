"""Files an administrator uploads in parts (a CrowdSec Hub archive, a CRS release): the web service and the nginx in
front of it take requests of up to 1 MB, so the page sends a file in pieces and this module puts it back together,
checking the size and the SHA-256 the page announced before anything uses it. The web service only stores the bytes;
the job that reads the file (jt-waf-mgr-hub.service, jt-waf-mgr-crs.service) unpacks and verifies it.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import time

CHUNK = 600 * 1024                 # bytes per piece (about 800 KB once base64 encoded)
LIMITS = {'hub': 64 * 1024 * 1024, 'crs': 16 * 1024 * 1024}
STALE = 3600                       # an upload left unfinished for an hour is removed
NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$')
PER_USER = 2                       # unfinished uploads at once
TOTAL = 4
FREE_AFTER = 512 * 1024 * 1024     # the database lives on the same disk: keep this much free


class UploadError(ValueError):
    def __init__(self, code, status=400, **details):
        super().__init__(code)
        self.code, self.status, self.details = code, status, details


def root(cfg):
    return os.path.join(os.path.dirname(os.path.abspath(cfg['paths']['db'])), 'uploads')


def _dir(cfg, uid):
    if not re.fullmatch(r'[0-9a-f]{32}', uid or ''):
        raise UploadError('not_found', 404)
    return os.path.join(root(cfg), uid)


def _meta(cfg, uid):
    try:
        with open(os.path.join(_dir(cfg, uid), 'meta.json'), encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        raise UploadError('not_found', 404)


def _save_meta(cfg, uid, m):
    p = os.path.join(_dir(cfg, uid), 'meta.json')
    with open(p + '.tmp', 'w', encoding='utf-8') as fh:
        json.dump(m, fh)
    os.replace(p + '.tmp', p)


def cleanup(cfg, now=None):
    now = now or time.time()
    r = root(cfg)
    for n in (os.listdir(r) if os.path.isdir(r) else []):
        p = os.path.join(r, n)
        try:
            if now - os.path.getmtime(p) > STALE:
                shutil.rmtree(p, ignore_errors=True)
        except OSError:
            pass


def start(cfg, kind, name, size, sha256, actor):
    if kind not in LIMITS:
        raise UploadError('invalid_kind')
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise UploadError('invalid_name')
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= LIMITS[kind]:
        raise UploadError('too_large', 413, limit=LIMITS[kind])
    if not isinstance(sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', sha256):
        raise UploadError('invalid_sha256')
    if kind == 'crs':
        from .crsupdate import UPLOAD_NAME
        if not UPLOAD_NAME.match(name):
            raise UploadError('invalid_name', 422, expected='coreruleset-<version>-minimal.tar.gz')
    cleanup(cfg)
    r = root(cfg)
    open_ = []
    for n in (os.listdir(r) if os.path.isdir(r) else []):
        try:
            with open(os.path.join(r, n, 'meta.json'), encoding='utf-8') as fh:
                open_.append(json.load(fh).get('actor'))
        except (OSError, ValueError):
            pass
    if len(open_) >= TOTAL or open_.count(actor) >= PER_USER:
        raise UploadError('too_many_uploads', 429)
    try:
        st = os.statvfs(os.path.dirname(r))
        if st.f_bavail * st.f_frsize - size < FREE_AFTER:
            raise UploadError('no_space', 507)
    except OSError:
        pass
    uid = secrets.token_hex(16)
    os.makedirs(_dir(cfg, uid), mode=0o700)
    _save_meta(cfg, uid, {'kind': kind, 'name': name, 'size': size, 'sha256': sha256, 'actor': actor, 'received': 0,
                          'next': 0, 'started': time.time()})
    return {'id': uid, 'chunk_bytes': CHUNK, 'chunks': (size + CHUNK - 1) // CHUNK}


def chunk(cfg, uid, index, data_b64, actor):
    m = _meta(cfg, uid)
    if m['actor'] != actor:
        raise UploadError('not_found', 404)
    if index != m['next']:
        raise UploadError('out_of_order', 409, expected=m['next'])
    try:
        data = base64.b64decode(data_b64 or '', validate=True)
    except (ValueError, TypeError):
        raise UploadError('invalid_data')
    if not data or len(data) > CHUNK or m['received'] + len(data) > m['size']:
        raise UploadError('invalid_data')
    with open(os.path.join(_dir(cfg, uid), 'data'), 'ab') as fh:
        fh.write(data)
    m['received'] += len(data)
    m['next'] += 1
    _save_meta(cfg, uid, m)
    return {'received': m['received'], 'size': m['size']}


def finish(cfg, uid, actor):
    """The whole file (path and meta) once its size and SHA-256 are what the page announced."""
    m = _meta(cfg, uid)
    if m['actor'] != actor:
        raise UploadError('not_found', 404)
    path = os.path.join(_dir(cfg, uid), 'data')
    h = hashlib.sha256()
    n = 0
    try:
        with open(path, 'rb') as fh:
            for b in iter(lambda: fh.read(1 << 20), b''):
                h.update(b)
                n += len(b)
    except OSError:
        raise UploadError('incomplete', 409)
    if n != m['size'] or h.hexdigest() != m['sha256']:
        shutil.rmtree(_dir(cfg, uid), ignore_errors=True)
        raise UploadError('checksum_mismatch', 422)
    return path, m


def discard(cfg, uid):
    try:
        shutil.rmtree(_dir(cfg, uid), ignore_errors=True)
    except UploadError:
        pass
