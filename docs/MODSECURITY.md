# Installing ModSecurity (nginx + libmodsecurity v3 + OWASP CRS 4)

**English** · [繁體中文](MODSECURITY.zh-TW.md) · [日本語](MODSECURITY.ja.md)

This guide starts from a host with only nginx (or nothing yet) and sets up the ModSecurity environment jt-waf-mgr
needs. You set up nginx, the ModSecurity module, `modsecurity.conf` and a main file (sections 1–5). The OWASP CRS is
then handled by jt-waf-mgr: it downloads, verifies and installs CRS 4 and keeps it current through approved changes
(section 6, the recommended way). Installing the CRS by hand still works (section 7). Sites that already run
ModSecurity do not have to follow this guide: compare with "What jt-waf-mgr needs" at the end of section 8.

On the first setup you change nginx's configuration yourself: `modsecurity on;` (section 3) and the management vhost
([README](../README.md#connect-to-the-management-interface)). After that jt-waf-mgr writes ModSecurity's rule files; it
reads nginx's configuration (to find the sites and ModSecurity's main file), runs `nginx -t` and reloads. It touches
nginx's configuration only in these ways, each through the change workflow (checks, approval, `nginx -t`, reload, put
back on failure):

- turning the WAF on or off for a site, deploying the blocked page: one marked `include` line added to or removed from
  the matching `server` blocks;
- temporary IP blocks: one list file of `deny` lines only, which you include once in `http { }`.

> Go live in log-only mode (`DetectionOnly`) first, watch the events in jt-waf-mgr for a while and handle false
> positives, then switch to blocking (`On`).

## 1. System and packages

- Debian 12 / 13: `libnginx-mod-http-modsecurity`; libmodsecurity 3.0.9 or later comes with it.
- Ubuntu 24.04: `libnginx-mod-http-modsecurity`; libmodsecurity 3.0.12 (package `libmodsecurity3t64`).
- Ubuntu 26.04: `libnginx-mod-http-modsecurity`; libmodsecurity 3.0.14 (package `libmodsecurity3t64`).
- Ubuntu 22.04: its libmodsecurity is older than 3.0.9; use 24.04 or build it yourself.

A new host (`--no-install-recommends`: the connector recommends the distribution's CRS 3, which apt would otherwise
install along with it):

```sh
sudo apt install --no-install-recommends nginx libnginx-mod-http-modsecurity
```

Check the package versions and sources, and the configuration actually loaded (a package installed is not a module or
rules loaded):

```sh
# version >= 3.0.9; nginx and the connector from the same repository
apt-cache policy nginx libnginx-mod-http-modsecurity libmodsecurity3 libmodsecurity3t64
# the effective configuration must have load_module, modsecurity on and modsecurity_rules_file
sudo nginx -T 2>/dev/null | grep -E 'load_module .*modsecurity|modsecurity (on|off)|modsecurity_rules_file'
```

The connector module must be compatible with the running nginx's version and module ABI (the Debian / Ubuntu packages
pair them through their `nginx-abi-*` dependency). With nginx.org's packages the distribution's module does not load:
use the distribution's nginx, or build the dynamic module from the same nginx version's source
(`./configure --with-compat --add-dynamic-module=ModSecurity-nginx`).

The distribution's `modsecurity-crs` package is CRS 3.3: **do not use it**. On a host that already has it, look at what
is actually included with `nginx -T` above. CRS 4 is installed by jt-waf-mgr (section 6) or by hand (section 7).

## 2. ModSecurity basics

The configuration lives in `/etc/nginx/modsec/`. Take `modsecurity.conf-recommended` and `unicode.mapping` from the
ModSecurity source at **the tag of your libmodsecurity version**
([github.com/owasp-modsecurity/ModSecurity](https://github.com/owasp-modsecurity/ModSecurity)).

```sh
sudo install -d -m 755 /etc/nginx/modsec
# the upstream version: apt-cache policy shows 3.0.9-1+deb12u2, use 3.0.9 (without the Debian / Ubuntu revision)
V=3.0.9
cd /etc/nginx/modsec
sudo curl -fLo modsecurity.conf https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/modsecurity.conf-recommended
sudo curl -fLO https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v$V/unicode.mapping
```

Check or change these lines in `modsecurity.conf`:

```apache
# log only first; On after watching (section 9)
SecRuleEngine DetectionOnly
SecAuditEngine RelevantOnly
SecAuditLogType Serial
# jt-waf-mgr reads JSON
SecAuditLogFormat JSON
SecAuditLog /var/log/modsecurity/modsec_audit.log
```

Keep the file's own `SecAuditLogParts`. jt-waf-mgr masks sensitive fields of the requests (passwords, tokens, cookies…)
before they reach its database, but **the raw audit log on the nginx host can still hold them**: open its directory and
file only to the accounts that need them (section 4).

## 3. Main file and nginx

`/etc/nginx/modsec/main.conf`:

```apache
Include /etc/nginx/modsec/modsecurity.conf
```

The recommended way needs only this line: when jt-waf-mgr installs the CRS it inserts the CRS includes after it, and
adoption adds jt-waf-mgr's managed rule files before and after the CRS rules. A site's own rule files are optional
(section 7); adoption works without them.

In nginx's `http { }` (every site) or a single `server { }`:

```nginx
modsecurity on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

## 4. Audit log directory and rotation

```sh
sudo install -d -m 750 -o root -g adm /var/log/modsecurity
```

`adm` is an example. jt-waf-mgr's service need not be in that group: `install.sh` finds the group (other than root) of
the audit log's directory and file and gives it to the systemd service as `SupplementaryGroups`.

`/etc/logrotate.d/modsecurity` (libmodsecurity does not reopen the file on reload, hence `copytruncate`):

```
/var/log/modsecurity/modsec_audit.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

## 5. Check nginx

```sh
sudo nginx -t && sudo systemctl reload nginx
```

The OWASP CRS is not loaded yet. The base rules in `modsecurity.conf` (a request body that does not parse, multipart
anomalies…) or responses matching `SecAuditLogRelevantStatus` can still produce log entries; once the CRS is in, check
with section 8 that the events carry **CRS rule ids**.

## 6. OWASP CRS 4 installed by jt-waf-mgr (recommended)

1. Install jt-waf-mgr as in the [README](../README.md#install), connect the management interface and enable the apply
   program (`sudo ./install.sh --enable-apply`). Run `sudo jt-waf-mgr check` (its output: section 9): `main_config`
   is the main file nginx loads; `crs.version` is empty at this point.
2. On the CRS page, switch on "keep the CRS current with this system".
3. jt-waf-mgr downloads the newest CRS 4.x once it has been out for `wait_days` (7 by default) and verifies it with the
   pinned CRS signing key.
4. "Compare in the sandbox and propose the install" creates a change.
5. Once a person approves it, jt-waf-mgr installs `crs-<version>`, creates the `crs` link and `crs-setup.conf`, and
   inserts the includes after `modsecurity.conf`. `main.conf` then reads:

   ```apache
   Include /etc/nginx/modsec/modsecurity.conf
   Include /etc/nginx/modsec/crs-setup.conf
   Include /etc/nginx/modsec/crs/rules/*.conf
   ```

6. Then adopt the configuration ("Rules → Managed rules", approved by an admin like any change): jt-waf-mgr's managed
   rule files go before and after the CRS rules (`/etc/nginx/modsec/jt-waf-mgr/before-crs.conf` and `after-crs.conf`).

Later CRS updates go the same way: download, verify, compare in the sandbox, approval by a person, install; three
versions are kept for rolling back.

## 7. The other way: the CRS by hand

Download the newest 4.x release and its `.asc` signature from the
[CRS GitHub releases](https://github.com/coreruleset/coreruleset/releases), verify it with `gpg --verify` as the CRS
documentation says, then unpack it. Name the directory `crs-<version>` and point the `crs` link at it: jt-waf-mgr can
then update and roll it back later (it recognises `crs-<version>` directories):

```sh
CRS=4.x.y                           # the actual version
cd /etc/nginx/modsec
sudo mkdir crs-$CRS
sudo tar xzf ~/coreruleset-$CRS.tar.gz -C crs-$CRS --strip-components=1   # the file name as on the releases page
sudo ln -sfn crs-$CRS crs           # upgrading the CRS later is only changing the link
sudo cp crs/crs-setup.conf.example crs-setup.conf
```

`/etc/nginx/modsec/main.conf` then reads:

```apache
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs-setup.conf
# optional: the site's own rules, before and after the CRS rules (create the files first, then remove the "#":
# including a file that does not exist makes the configuration fail to load)
# Include /etc/nginx/modsec/site-before-crs.conf
Include /etc/nginx/modsec/crs/rules/*.conf
# Include /etc/nginx/modsec/site-after-crs.conf
```

The two site files are optional and hold the site's own rules (exclusions, blocks). To use them, create them first
(empty is fine: `sudo touch /etc/nginx/modsec/site-before-crs.conf /etc/nginx/modsec/site-after-crs.conf`), then
uncomment the two lines. Without them, adoption adds empty managed files before and after the CRS rules; with them,
adoption imports their rules as they are and has `main.conf` load the files it manages. Either way later rule changes
go through jt-waf-mgr's workflow, and later CRS updates can be left to jt-waf-mgr as in section 6.

## 8. Test

Test with **the name of a protected site** (on a host with several sites, `localhost` can reach the default vhost or
only get a redirect). For an HTTPS site, `--resolve` connects to this host and keeps the right Host and SNI; give the
request a value used only this time, to find it in the log:

```sh
sudo nginx -t && sudo systemctl reload nginx
SITE=www.example.com                 # a protected site
T=jtwaf-test-$(date +%s)
curl -sk -o /dev/null -w '%{http_code}\n' --resolve $SITE:443:127.0.0.1 "https://$SITE/?q=<script>alert(1)</script>&t=$T"
sudo grep "$T" /var/log/modsecurity/modsec_audit.log | tail -n 1 | python3 -m json.tool | grep -iE '"(host|ruleid)"'
```

What counts: **this request, on this site, matched a CRS rule** (a `ruleId` of 9xxxxx). In log-only mode the response
code is unchanged (for example 200). Once jt-waf-mgr runs, the request also shows on its events page.

What jt-waf-mgr needs:

- `SecAuditLogFormat JSON`, and `SecAuditEngine` not `Off`;
- a main file that includes `modsecurity.conf`, loaded by nginx's `modsecurity on;` and `modsecurity_rules_file`;
- the service can pass through every directory of the audit log and read the file (`install.sh` sets this up from the
  file's group, section 4), and new events actually arrive;
- OWASP CRS 4, installed by jt-waf-mgr (section 6) or by hand (section 7).

## 9. Check, then block

Run `sudo jt-waf-mgr check`. It prints JSON; exit status 0 means no problem, 1 that there are problems (listed in
`problems`):

- `main_config`: the ModSecurity main file(s) nginx loads;
- `nginx_errors`, `modsec_errors`: configuration parse errors;
- `crs.version`, `crs.rule_count`, `crs.engine_mode`: the CRS version, its rule count, the value of `SecRuleEngine`;
- `warnings`: for example `audit_log_not_json`, `audit_engine_off`;
- `audit_log`, `audit_log_readable`, `audit_log_last_read`: the audit log; whether the service can read it (by the
  groups systemd gives the service; when a directory open only to those groups hides the file from the command line,
  by the service's last read, `null` when that cannot tell); and when the service last read it;
- `problems`: what keeps jt-waf-mgr from working, in words.

After watching for a while and handling false positives, set `SecRuleEngine` in `modsecurity.conf` to `On`, then check
and reload:

```sh
sudo nginx -t && sudo systemctl reload nginx
sudo jt-waf-mgr check                # crs.engine_mode should be On
```

Finally repeat the request of section 8: the answer should be 403, and the same request in the audit log matched a CRS
rule.
