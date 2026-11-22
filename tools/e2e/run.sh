#!/bin/sh
# Release gate: browser end-to-end test of every page (3 languages, light / dark, controls, charts) against a
# synthetic environment served by the code in this tree. Needs Playwright (JTWAF_NODE_MODULES).
#   tools/e2e/run.sh [screenshot dir]          (E2E_ONLY_SECURITY=1: only the security scan)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); TOP=$(cd "$HERE/../.." && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/jtwaf-e2e.XXXXXX"); SHOTS=${1:-$W/shots}; mkdir -p "$SHOTS"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
# the fixture site, with the IP block list included at the http level as an administrator would (0.5.2: blocks are
# refused while nginx does not load the list)
cp -r "$TOP/tests/fixtures/site" "$W/site"
mkdir -p "$W/nginx-blocks" && : > "$W/nginx-blocks/blocked-ips.conf"
sed -i "0,/include mime.types;/s||include mime.types;\n    include $W/nginx-blocks/blocked-ips.conf;|" "$W/site/nginx.conf"
cat > "$W/config.toml" <<CONF
[node]
id = "waf1"
[paths]
db = "$W/c.db"
nginx_conf = "$W/site/nginx.conf"
audit_log = "$W/modsec_audit.log"
nginx_bin = "/nonexistent/nginx"
[server]
secure_cookies = false
listen = "127.0.0.1:$PORT"
[syslog]
enabled = false
[collector]
backfill_rotated = false
[managed]
dir = "$W/managed"
spool = "$W/spool"
sandbox_dir = "$W/sandbox"
apply_state = "$W/apply-state"
[evidence]
access_logs = ["$W/access.log"]
[traffic]
logs = ["$W/traffic/*access.log"]
[dns]
enabled = true
dir = "$W/dns"
internal_servers = ["192.0.2.53"]
external_servers = ["198.51.100.53"]

[hub]
dir = "$W/hub"

[iprep]
enabled = true
dir = "$W/iprep"
documentation_nets_outside = true
internetdb = true
misp_url = "https://misp.example.com"
misp_api_key = "e2eSyntheticKey0000000000000000000000000"

[countries]
enabled = true
dir = "$W/countries"
rules_dir = "$W/country-lists"
[blocks]
enabled = true
file = "$W/nginx-blocks/blocked-ips.conf"
protected = ["198.51.100.0/25"]
[waf]
focus_sites = ["sso.example.com"]
[auth]
password_min_classes = 3
password_history = 3
password_max_age_days = 180
[ui]
login_notice = "Authorised use only."
[integrity]
anchor_file = "$W/anchors.jsonl"
[backup]
dir = "$W/backups"
[compliance]
level = "medium"
[geoip]
dir = "$W/geoip"
license_key_file = "$W/maxmind.key"
CONF
python3 "$HERE/setup.py" "$W" >/dev/null
echo "$PORT" > "$W/port"
cd "$TOP" && PYTHONDONTWRITEBYTECODE=1 python3 -m jtwafmgr --config "$W/config.toml" serve > "$W/server.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$W"' EXIT
sleep 2
if [ "${E2E_ONLY_SECURITY:-0}" != 1 ]; then node "$HERE/e2e.cjs" "$W" "$SHOTS"; fi
# the project site (docs/*.html) in a browser, every language: no script error, buttons with text, language switch
if [ "${E2E_ONLY_SECURITY:-0}" != 1 ]; then node "$TOP/tools/check_pages.cjs" "$TOP/docs"; fi
# black-box security checks on the same environment (stdlib; tools/security_scan.py)
python3 "$TOP/tools/security_scan.py" "$W"
cp "$W/security-report.json" "$SHOTS/" 2>/dev/null || true
