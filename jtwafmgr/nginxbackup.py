"""A copy of what an nginx update changes, for the person who approves it to keep (0.5.1): the nginx configuration,
the ModSecurity module in use, and the steps to put them back by hand -- before an update, or any time.

Built by the web service (it reads the configuration anyway); an administrator downloads it with a fresh one-time
code and the download is recorded. Private key files are left out (named in the manifest) and so is anything the
service cannot read; the root program keeps its own way back (nginxswap.py) whatever happens to this file.
"""
import hashlib
import io
import os
import re
import tarfile
import tempfile
import time

from . import util

MAX_TOTAL = 64 << 20            # the whole archive (configuration and module), uncompressed
MAX_FILE = 16 << 20
# private keys stay on the host: by name and by contents
KEY_NAME = re.compile(r'(\.key$|privkey|private|\.p12$|\.pfx$|\.jks$|htpasswd|\.pass$|passwd)', re.I)
KEY_TEXT = re.compile(rb'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----')

RESTORE = """jt-waf-mgr: nginx backup ({host}, {at})
============================================

nginx package: {package} {installed}{held}
ModSecurity module: {module} (SHA-256 {module_sha})
Files: nginx/ (the configuration as it was, private keys left out), module/, MANIFEST.sha256

Put it back by hand (as root), only if the update and jt-waf-mgr's own way back did not:
  1. Check the files: cd <this directory> && sha256sum -c MANIFEST.sha256
  2. The module:  install -m 644 module/{module_name} {module}
  3. The configuration: copy back only what changed, for example
       diff -ru nginx/ {conf_dir}/   then   cp -a nginx/<file> {conf_dir}/<file>
  4. nginx -t   and only when it passes:   systemctl reload nginx
     (a module change needs the running nginx to move to it: nginx -t, then `kill -USR2 $(cat /run/nginx.pid)`,
      and `kill -QUIT $(cat /run/nginx.pid.oldbin)` once the new master answers)
  5. The previous nginx package, if the update has to be undone and jt-waf-mgr cannot: apt-get install
     {package}={installed} (it is in /var/cache/apt/archives or apt's repository), then apt-mark hold {package}.

jt-waf-mgr's own way back (preferred): the nginx updates page, "Roll back to the previous nginx", or on the host:
  jt-waf-mgr nginx rollback --reason "..." --as <admin>   then   jt-waf-mgr changes approve <id> --note "..." --totp <code> --as <admin>
When the management page cannot be reached through nginx: ssh -L 8095:127.0.0.1:8095 <this host>, then open
http://localhost:8095 in Chrome or Edge on your own computer (the web service does not need nginx).

---- 中文 ----
nginx 套件：{package} {installed}{held_zh}
ModSecurity 模組：{module} (SHA-256 {module_sha})
內容：nginx/ (當時的 nginx 設定，不含私鑰)、module/、MANIFEST.sha256

只有在升級本身和 jt-waf-mgr 的退回都沒有成功時，才用 root 手動還原：
  1. 檢查檔案：sha256sum -c MANIFEST.sha256
  2. 模組：install -m 644 module/{module_name} {module}
  3. 設定：只複製改過的檔案 (先 diff -ru nginx/ {conf_dir}/)
  4. nginx -t 通過後才 systemctl reload nginx (換模組要讓 nginx 熱切換：USR2，新主程序正常後 QUIT 舊的)
  5. 要換回舊版 nginx 套件時：apt-get install {package}={installed}，再 apt-mark hold {package}
優先用 jt-waf-mgr 的「退回上一版 nginx」(網頁或上面的指令)。nginx 連不上時：ssh -L 8095:127.0.0.1:8095 這台主機，
在自己電腦用 Chrome 或 Edge 開 http://localhost:8095 (管理介面本身不需要 nginx)。

---- 日本語 ----
nginx パッケージ：{package} {installed}{held_ja}
ModSecurity モジュール：{module} (SHA-256 {module_sha})
内容：nginx/ (当時の nginx 設定、秘密鍵を除く)、module/、MANIFEST.sha256
更新と jt-waf-mgr のロールバックがどちらも失敗したときだけ、root で手動で戻します (手順は上の英語の 1～5)。
nginx 経由で管理画面に入れないとき：ssh -L 8095:127.0.0.1:8095 このホスト、Chrome または Edge で http://localhost:8095。
"""


def _add(tar, name, data, mtime):
    ti = tarfile.TarInfo(name)
    ti.size, ti.mtime, ti.mode = len(data), int(mtime), 0o600
    tar.addfile(ti, io.BytesIO(data))


def build(cfg, status=None, out_dir=None):
    """Write the archive into a private temporary file: (path, {'sha256', 'files', 'skipped', 'size'}). The caller
    streams it and removes it."""
    from .nginxswap import module_target
    conf = cfg['paths']['nginx_conf']
    conf_dir = os.path.dirname(os.path.abspath(conf))
    st = status or {}
    try:
        module = module_target(cfg['paths']['nginx_bin'])
    except Exception:       # noqa: BLE001 -- no module line: the configuration alone
        module = None
    now = time.time()
    total, files, skipped, manifest = 0, 0, [], []
    fd, path = tempfile.mkstemp(prefix='.nginx-backup-', suffix='.tar.gz', dir=out_dir)
    os.close(fd)
    try:
        with tarfile.open(path, 'w:gz') as tar:
            for root, dirs, names in os.walk(conf_dir, followlinks=False):
                dirs.sort()
                for n in sorted(names):
                    p = os.path.join(root, n)
                    rel = os.path.relpath(p, conf_dir)
                    if os.path.islink(p) or not os.path.isfile(p):
                        skipped.append((rel, 'not a regular file'))
                        continue
                    if KEY_NAME.search(rel):
                        skipped.append((rel, 'private key or password file: left on the host'))
                        continue
                    try:
                        fh = open(p, 'rb', opener=lambda f, fl: os.open(f, fl | os.O_NOFOLLOW))
                        with fh:
                            data = fh.read(MAX_FILE + 1)
                    except OSError:
                        skipped.append((rel, 'not readable by the service'))
                        continue
                    if len(data) > MAX_FILE or total + len(data) > MAX_TOTAL:
                        skipped.append((rel, 'too large'))
                        continue
                    if KEY_TEXT.search(data):
                        skipped.append((rel, 'holds a private key: left on the host'))
                        continue
                    _add(tar, 'nginx/' + rel, data, os.path.getmtime(p))
                    manifest.append('%s  nginx/%s' % (hashlib.sha256(data).hexdigest(), rel))
                    total += len(data)
                    files += 1
            module_sha = '-'
            if module:
                try:
                    with open(module, 'rb') as fh:
                        data = fh.read(MAX_FILE * 2 + 1)
                    if len(data) <= MAX_FILE * 2:
                        module_sha = hashlib.sha256(data).hexdigest()
                        _add(tar, 'module/' + os.path.basename(module), data, os.path.getmtime(module))
                        manifest.append('%s  module/%s' % (module_sha, os.path.basename(module)))
                        files += 1
                    else:
                        skipped.append((module, 'too large'))
                except OSError:
                    skipped.append((module, 'not readable by the service'))
            held = st.get('held')
            text = RESTORE.format(
                host=cfg['node']['id'], at=util.iso(now), package=st.get('package') or 'nginx', installed=st.get('installed') or '?',
                held=' (held)' if held else '', held_zh=' (已鎖定版本)' if held else '', held_ja=' (バージョン固定)' if held else '',
                module=module or '-', module_name=os.path.basename(module or 'module.so'), module_sha=module_sha,
                conf_dir=conf_dir)
            if skipped:
                text += '\nLeft out / 未放入 / 含めなかったもの:\n' + ''.join('  %s: %s\n' % s for s in skipped[:200])
            _add(tar, 'RESTORE.txt', text.encode(), now)
            _add(tar, 'MANIFEST.sha256', ('\n'.join(manifest) + '\n').encode(), now)
        h = hashlib.sha256()
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b''):
                h.update(chunk)
        return path, {'sha256': h.hexdigest(), 'files': files, 'skipped': len(skipped), 'size': os.path.getsize(path),
                      'module_sha256': module_sha}
    except BaseException:
        os.unlink(path)
        raise
