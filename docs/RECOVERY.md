# When nginx does not come back after an update

**English** · [繁體中文](RECOVERY.zh-TW.md) · [日本語](RECOVERY.ja.md)

jt-waf-mgr updates nginx and its ModSecurity module without stopping the service, and puts the previous package and
module back by itself when a step fails (the new program not running, `nginx -t`, health checks that answer
differently). This page is for what is left: an update that went wrong later, or a host where even that did not work.

## 1. What jt-waf-mgr keeps

- Before every nginx update (and every module switch or rollback) the root program keeps the previous nginx package and
  the module that was running, in its own directory (`/var/lib/jt-waf-mgr-apply/nginx-update/`). The newest successful
  updates stay there; the nginx updates page shows which change can be rolled back.
- "Download a backup" on the nginx updates page (and on the approval page of an nginx update) gives you a copy of the
  nginx configuration, the module in use and `RESTORE.txt` with the manual steps, before you approve. Private key and
  password files are left out. It takes a one-time code and is recorded.

## 2. The management page cannot be reached

The management page usually goes through nginx, but the web service itself does not need nginx: it listens on the host
(`127.0.0.1:8095` by default).

- From your own computer: `ssh -L 8095:127.0.0.1:8095 root@<WAF host>`, then open `http://localhost:8095` in Chrome or
  Edge and sign in as usual (checked with Chromium-based browsers).
- On the host, the command line does the same things (it does not go through nginx either):

```
jt-waf-mgr nginx status
jt-waf-mgr nginx rollback --reason "site broke after the update" --as <admin>
jt-waf-mgr changes approve <id> --note "roll back nginx: site broke" --totp <code> --as <admin>
jt-waf-mgr nginx backup -o /var/tmp/nginx-backup.tar.gz --totp <code> --as <admin>
```

A rollback is a change like any other nginx change: an administrator approves it with a one-time code and a note of at
least 10 characters, and the root program moves nginx back without stopping it, with the same health checks.

## 3. Rolling back by hand (when jt-waf-mgr cannot)

As root on the WAF host:

1. Look first: `systemctl status nginx`, `nginx -t`, `journalctl -u nginx -n 50`.
2. The module: the backup's `module/ngx_http_modsecurity_module.so`, or the kept `previous-ngx_http_modsecurity_module.so`
   in the newest directory under `/var/lib/jt-waf-mgr-apply/nginx-update/`:
   `install -m 644 <file> /usr/lib/nginx/modules/ngx_http_modsecurity_module.so`
3. The package, if it has to go back too: `old.deb` in that same directory (`dpkg -i old.deb`), or
   `apt-get install nginx=<previous version>`; then `apt-mark hold nginx`.
4. `nginx -t`; when it passes, `systemctl reload nginx` (a running nginx moves to another module only by
   `kill -USR2 $(cat /run/nginx.pid)`, then `kill -QUIT $(cat /run/nginx.pid.oldbin)` once the new master answers;
   when nginx is not running at all, `systemctl start nginx`).
5. Check the sites, then mark the "configuration changed outside" alert jt-waf-mgr raises as handled, with what you did.

## 4. Before the next update

- Set health URLs (Settings → Change workflow) for the sites that matter, the management page included: an update that breaks
  one of them is then put back by itself.
- Keep "Apply nginx security updates by themselves" off unless you want updates without approval; it is off by default
  and switching it on takes an administrator's one-time code.
