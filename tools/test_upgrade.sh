#!/bin/sh
# Release gate: install the PREVIOUS release into a throwaway staging root, put synthetic data in it, then
# upgrade to the NEW release with upgrade.sh exactly as on a server — plus the paths that must not break:
# --check changes nothing, data survives, the audit trail records the change, a refused downgrade, a
# refused upgrade while an apply is pending, an automatic rollback when the new version fails to start,
# and a manual rollback. systemd is replaced by tools/upgrade-test/fake_systemctl.sh (no containers, no
# root, nothing outside the staging directory). Then, in a second staging root: a fresh install of the NEW
# release, uninstall keeping the data, a reinstall that finds the data again, and uninstall --purge leaving
# nothing behind.
#
#   tools/test_upgrade.sh dist/jt-waf-mgr-OLD.tar.gz dist/jt-waf-mgr-NEW.tar.gz
set -eu
OLD_TGZ=$(readlink -f "${1:?previous release tarball}"); NEW_TGZ=$(readlink -f "${2:?new release tarball}")
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d "${TMPDIR:-/tmp}/jtwaf-upgrade-test.XXXXXX")
R="$W/root"; export JTWAF_ROOT="$R" FAKE_STATE="$W/state" JTWAF_SYSTEMCTL="$HERE/upgrade-test/fake_systemctl.sh"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
FAILS=0
pass() { printf '  PASS %s\n' "$*"; }
fail() { printf '  FAIL %s\n' "$*"; FAILS=$((FAILS + 1)); }
cleanup() { "$JTWAF_SYSTEMCTL" stop jt-waf-mgr.service >/dev/null 2>&1 || true
    JTWAF_ROOT="$W/fresh" FAKE_STATE="$W/state2" "$JTWAF_SYSTEMCTL" stop jt-waf-mgr.service >/dev/null 2>&1 || true
    [ "${KEEP:-0}" = 1 ] || rm -rf "$W"; }
trap cleanup EXIT
mkdir -p "$W/old" "$W/new" "$R"
tar -C "$W/old" -xzf "$OLD_TGZ"; tar -C "$W/new" -xzf "$NEW_TGZ"
OLDD=$(ls -d "$W"/old/jt-waf-mgr-*); NEWD=$(ls -d "$W"/new/jt-waf-mgr-*)
OLDV=${OLDD##*-}; NEWV=${NEWD##*-}
q() { python3 -I -c "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:$PORT$1', timeout=5))$2)"; }
db() { python3 -I -c "import sqlite3; print(sqlite3.connect('file:$W/data/jt-waf-mgr.db?mode=ro', uri=True).execute(\"$1\").fetchone()[0])"; }

echo "== install $OLDV into $R"
"$OLDD/install.sh" --root "$R" >/dev/null
cat > "$R/etc/jt-waf-mgr/config.toml" <<CONF
[node]
id = "upgrade-test"
[server]
listen = "127.0.0.1:$PORT"
secure_cookies = false
[paths]
db = "$W/data/jt-waf-mgr.db"
audit_log = "$W/data/modsec_audit.log"
nginx_conf = "$HERE/../tests/fixtures/site/nginx.conf"
nginx_bin = "/nonexistent/nginx"
[syslog]
enabled = false
[managed]
dir = "$W/data/managed"
spool = "$W/data/spool"
sandbox_dir = "$W/data/sandbox"
[integrity]
anchor_file = "$W/data/anchors.jsonl"
release_key = "$R/etc/jt-waf-mgr/release-key.pem"
[backup]
dir = "$W/data/backups"
CONF
if grep -q geoip "$OLDD/deploy/config.toml.example"; then printf '[geoip]\ndir = "%s"\nlicense_key_file = "%s"\n' "$W/data/geoip" "$W/data/mm.key" >> "$R/etc/jt-waf-mgr/config.toml"; fi
if grep -q apply_state "$OLDD/jtwafmgr/config.py"; then
    sed -i "s#^sandbox_dir = .*#&\napply_state = \"$W/data/apply-state\"#" "$R/etc/jt-waf-mgr/config.toml"
fi
mkdir -p "$W/data/spool"
python3 -c "
import sys; sys.path.insert(0, '$HERE/..')
from tests.helpers import record
open('$W/data/modsec_audit.log', 'w').write('\n'.join(record(ip='203.0.113.%d' % (i % 50 + 1), status=403 if i % 3 else 200, engine='Enabled', rules=[942100, 949110]) for i in range(120)) + '\n')"
PYTHONPATH="$R/usr/lib/jt-waf-mgr" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$R/etc/jt-waf-mgr/config.toml" user add alice --role admin >/dev/null
PYTHONPATH="$R/usr/lib/jt-waf-mgr" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$R/etc/jt-waf-mgr/config.toml" import "$W/data/modsec_audit.log" >/dev/null
"$JTWAF_SYSTEMCTL" enable jt-waf-mgr-apply.path; "$JTWAF_SYSTEMCTL" start jt-waf-mgr-apply.path
"$JTWAF_SYSTEMCTL" start jt-waf-mgr.service; sleep 3
[ "$(q /api/v1/meta "['version']")" = "$OLDV" ] && pass "$OLDV serving" || fail "$OLDV not serving"
EV0=$(db "SELECT COUNT(*) FROM events"); AU0=$(db "SELECT COUNT(*) FROM audit")
echo "   data: $EV0 events, $AU0 audit rows"

echo "== refusals"
touch "$W/data/spool/v9-c9.req"
if "$NEWD/upgrade.sh" >/dev/null 2>&1; then fail "upgrade ran with an apply pending"; else pass "refused while an apply request is pending"; fi
rm -f "$W/data/spool/v9-c9.req"
[ "$(q /api/v1/meta "['version']")" = "$OLDV" ] && pass "refusal changed nothing" || fail "refusal touched the service"

echo "== --check"
"$NEWD/upgrade.sh" --check > "$W/check.log" 2>&1 && pass "--check passes" || { fail "--check"; cat "$W/check.log"; }
[ -z "$(ls "$R/var/backups/jt-waf-mgr" 2>/dev/null | grep upgrade-)" ] && pass "--check made no backup" || fail "--check wrote a backup"

echo "== automatic rollback when $NEWV does not start"
if FAKE_FAIL_VERSION=$NEWV "$NEWD/upgrade.sh" > "$W/fail.log" 2>&1; then fail "upgrade reported success although start failed"; else pass "failed upgrade reported"; fi
grep -q "rolled back" "$W/fail.log" && pass "rolled back automatically" || { fail "no automatic rollback"; tail -20 "$W/fail.log"; }
[ "$(q /api/v1/meta "['version']")" = "$OLDV" ] && pass "$OLDV serving again" || fail "$OLDV not serving after rollback"
[ "$(db "SELECT COUNT(*) FROM events")" = "$EV0" ] && pass "events intact" || fail "events changed"
"$JTWAF_SYSTEMCTL" is-active jt-waf-mgr-apply.path && pass "apply trigger re-armed" || fail "apply trigger left disarmed"

echo "== upgrade $OLDV -> $NEWV"
"$NEWD/upgrade.sh" > "$W/up.log" 2>&1 && pass "upgrade succeeded" || { fail "upgrade failed"; tail -30 "$W/up.log"; }
[ "$(q /api/v1/meta "['version']")" = "$NEWV" ] && pass "$NEWV serving" || fail "$NEWV not serving"
[ "$(db "SELECT COUNT(*) FROM events")" = "$EV0" ] && pass "events kept ($EV0)" || fail "events lost"
[ "$(db "SELECT COUNT(*) FROM users WHERE username='alice'")" = 1 ] && pass "accounts kept" || fail "account lost"
[ "$(db "SELECT COUNT(*) FROM audit WHERE action='system.version_changed'")" -ge 1 ] && pass "audit trail records the version change" || fail "no version-change audit row"
"$JTWAF_SYSTEMCTL" is-active jt-waf-mgr-apply.path && pass "apply trigger re-armed" || fail "apply trigger left disarmed"
grep -q '"result":"ok"' "$R/var/backups/jt-waf-mgr/history.jsonl" && pass "history recorded" || fail "no history"
PYTHONPATH="$R/usr/lib/jt-waf-mgr" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$R/etc/jt-waf-mgr/config.toml" integrity >/dev/null && pass "integrity ok after upgrade" || fail "integrity after upgrade"

echo "== manual rollback"
"$NEWD/upgrade.sh" --rollback > "$W/rb.log" 2>&1 && pass "rollback succeeded" || { fail "rollback"; tail -20 "$W/rb.log"; }
[ "$(q /api/v1/meta "['version']")" = "$OLDV" ] && pass "$OLDV serving after rollback" || fail "$OLDV not serving"
[ "$(db "SELECT COUNT(*) FROM users WHERE username='alice'")" = 1 ] && pass "accounts intact after rollback" || fail "accounts lost"

[ -s "$R/etc/jt-waf-mgr/audit-rewinds.jsonl" ] && pass "rollbacks recorded as audit rewinds" || fail "no rewind record"

echo "== upgrade again (the path a site takes after fixing a problem)"
"$NEWD/upgrade.sh" > "$W/up2.log" 2>&1 && [ "$(q /api/v1/meta "['version']")" = "$NEWV" ] && pass "second upgrade ok" || fail "second upgrade"
PYTHONPATH="$R/usr/lib/jt-waf-mgr" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$R/etc/jt-waf-mgr/config.toml" integrity >/dev/null \
    && pass "integrity ok after rollbacks and re-upgrade (rewinds honoured)" || fail "integrity after re-upgrade"
if "$NEWD/upgrade.sh" >/dev/null 2>&1; then fail "re-upgrading to the same version was allowed"; else pass "same version refused"; fi

echo "== fresh install of $NEWV, uninstall, reinstall, uninstall --purge"
"$JTWAF_SYSTEMCTL" stop jt-waf-mgr.service >/dev/null 2>&1 || true
R2="$W/fresh"; V2="$R2/var/lib/jt-waf-mgr"; E2="$R2/etc/jt-waf-mgr"; D2="$W/data2"
PORT2=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
in2() { JTWAF_ROOT="$R2" FAKE_STATE="$W/state2" "$@"; }
cli2() { PYTHONPATH="$R2/usr/lib/jt-waf-mgr" PYTHONDONTWRITEBYTECODE=1 python3 -P -m jtwafmgr --config "$E2/config.toml" "$@"; }
q2() { python3 -I -c "import json,urllib.request; print(json.load(urllib.request.urlopen('http://127.0.0.1:$PORT2$1', timeout=5))$2)"; }
start2() {  # what install.sh does with systemd on a server: enable the triggers, start the service
    for f in "$R2"/etc/systemd/system/jt-waf-mgr-*.timer "$R2"/etc/systemd/system/jt-waf-mgr-*.path; do
        u=$(basename "$f"); [ "$u" = jt-waf-mgr-apply.path ] && continue
        in2 "$JTWAF_SYSTEMCTL" enable "$u"; in2 "$JTWAF_SYSTEMCTL" start "$u"; done
    in2 "$JTWAF_SYSTEMCTL" enable jt-waf-mgr.service; in2 "$JTWAF_SYSTEMCTL" start jt-waf-mgr.service
    i=0; until q2 /api/v1/meta "['version']" >/dev/null 2>&1 || [ $i -ge 20 ]; do sleep 0.5; i=$((i + 1)); done; }
mkdir -p "$R2" "$D2"
"$NEWD/install.sh" --root "$R2" > "$W/fresh-install.log" 2>&1 && pass "fresh install of $NEWV" || { fail "fresh install"; tail -20 "$W/fresh-install.log"; }
grep -q "first install; the key gets pinned" "$W/fresh-install.log" && [ -s "$E2/release-key.pem" ] && pass "release key pinned on the first install" || fail "release key not pinned"
[ -x "$R2/usr/bin/jt-waf-mgr" ] && [ -f "$R2/usr/lib/jt-waf-mgr/release/MANIFEST.sha256" ] && pass "program, command and signed manifest in place" || fail "program files missing"
NU=$(ls "$NEWD"/deploy/jt-waf-mgr*.service "$NEWD"/deploy/jt-waf-mgr*.timer "$NEWD"/deploy/jt-waf-mgr*.path | wc -l)
[ "$(ls "$R2"/etc/systemd/system/jt-waf-mgr*.service "$R2"/etc/systemd/system/jt-waf-mgr*.timer "$R2"/etc/systemd/system/jt-waf-mgr*.path | wc -l)" = "$NU" ] \
    && pass "all $NU systemd units of the release installed" || fail "systemd units: not every unit of deploy/ installed"
cat > "$E2/config.toml" <<CONF
[node]
id = "fresh-test"
[server]
listen = "127.0.0.1:$PORT2"
secure_cookies = false
[paths]
db = "$V2/jt-waf-mgr.db"
audit_log = "$D2/modsec_audit.log"
nginx_conf = "$HERE/../tests/fixtures/site/nginx.conf"
nginx_bin = "/nonexistent/nginx"
[syslog]
enabled = false
[managed]
dir = "$D2/managed"
spool = "$V2/spool"
sandbox_dir = "$V2/sandbox"
apply_state = "$R2/var/lib/jt-waf-mgr-apply"
[integrity]
anchor_file = "$V2/audit-anchors.jsonl"
release_key = "$E2/release-key.pem"
auth_logs = []
[backup]
dir = "$V2/backups"
[evidence]
access_logs = ["$D2/access.log"]
[traffic]
logs = ["$D2/access.log"]
[countries]
dir = "$V2/countries"
rules_dir = "$D2/managed/countries"
[blocks]
file = "$D2/blocked-ips.conf"
[crs]
dir = "$V2/crs"
[geoip]
dir = "$V2/geoip"
license_key_file = "$E2/maxmind-license.key"
CONF
mkdir -p "$V2/spool"
python3 -c "
import sys; sys.path.insert(0, '$HERE/..')
from tests.helpers import record
open('$D2/modsec_audit.log', 'w').write('\n'.join(record(ip='198.51.100.%d' % (i % 20 + 1), status=403, engine='Enabled', rules=[942100, 949110]) for i in range(30)) + '\n')"
cli2 user add bob --role admin >/dev/null && cli2 import "$D2/modsec_audit.log" >/dev/null && pass "first account and events on the fresh install" || fail "fresh install: user add / import"
start2
[ "$(q2 /api/v1/meta "['version']")" = "$NEWV" ] && pass "fresh $NEWV serving" || { fail "fresh $NEWV not serving"; tail -20 "$W/state2/service.log"; }
cli2 integrity >/dev/null && pass "integrity ok on the fresh install" || fail "integrity on the fresh install"
EV2=$(python3 -I -c "import sqlite3; print(sqlite3.connect('file:$V2/jt-waf-mgr.db?mode=ro', uri=True).execute('SELECT COUNT(*) FROM events').fetchone()[0])")

echo "== uninstall (keep data)"
# an uninstall.sh without the staging hooks would work on this machine itself: never run it
grep -q 'JTWAF_ROOT' "$NEWD/uninstall.sh" || { fail "uninstall.sh of $NEWV has no staging hooks (JTWAF_ROOT); not run"; echo "upgrade test: $FAILS FAILED"; KEEP=1; exit 1; }
in2 "$NEWD/uninstall.sh" > "$W/uninstall.log" 2>&1 && pass "uninstall succeeded" || { fail "uninstall"; tail -20 "$W/uninstall.log"; }
q2 /api/v1/meta "['version']" >/dev/null 2>&1 && fail "service still answers after uninstall" || pass "service stopped"
[ ! -e "$R2/usr/lib/jt-waf-mgr" ] && [ ! -e "$R2/usr/bin/jt-waf-mgr" ] && pass "program and command removed" || fail "program left behind"
[ -z "$(ls "$R2"/etc/systemd/system/ | grep jt-waf-mgr)" ] && pass "every unit file removed" || fail "unit files left: $(ls "$R2"/etc/systemd/system/ | grep jt-waf-mgr | tr '\n' ' ')"
[ -z "$(ls "$W/state2" | grep -E '\.(enabled|active|pid)$')" ] && pass "every unit disabled and stopped" || fail "units still enabled or running: $(ls "$W/state2" | grep -E '\.(enabled|active|pid)$' | tr '\n' ' ')"
[ -f "$V2/jt-waf-mgr.db" ] && [ -f "$E2/config.toml" ] && [ -f "$E2/release-key.pem" ] && pass "data, configuration and pinned key kept" || fail "data or configuration removed without --purge"

echo "== reinstall over the kept data"
"$NEWD/install.sh" --root "$R2" > "$W/reinstall.log" 2>&1 && pass "reinstall succeeded" || { fail "reinstall"; tail -20 "$W/reinstall.log"; }
grep -q "kept existing" "$W/reinstall.log" && grep -q "verifying the release with the pinned key" "$W/reinstall.log" \
    && pass "reinstall kept the configuration and verified with the pinned key" || fail "reinstall did not keep the configuration / pinned key"
start2
[ "$(q2 /api/v1/meta "['version']")" = "$NEWV" ] && pass "serving again after reinstall" || fail "not serving after reinstall"
[ "$(python3 -I -c "import sqlite3; c=sqlite3.connect('file:$V2/jt-waf-mgr.db?mode=ro', uri=True); print(c.execute(\"SELECT COUNT(*) FROM users WHERE username='bob'\").fetchone()[0], c.execute('SELECT COUNT(*) FROM events').fetchone()[0])")" = "1 $EV2" ] \
    && pass "account and events ($EV2) found again" || fail "data lost across uninstall and reinstall"
cli2 integrity >/dev/null && pass "integrity ok after reinstall" || fail "integrity after reinstall"

echo "== uninstall --purge"
mkdir -p "$R2/var/backups/jt-waf-mgr/upgrade-test" "$R2/var/lib/jt-waf-mgr-apply"
in2 "$NEWD/uninstall.sh" --purge > "$W/purge.log" 2>&1 && pass "uninstall --purge succeeded" || { fail "uninstall --purge"; tail -20 "$W/purge.log"; }
LEFT=$(find "$R2" -name '*jt-waf-mgr*' 2>/dev/null)
[ -z "$LEFT" ] && pass "nothing of jt-waf-mgr left (program, units, data, backups, configuration)" || fail "left behind: $(echo "$LEFT" | sed "s#$R2##" | tr '\n' ' ')"
[ -z "$(ls "$W/state2" | grep -E '\.(enabled|active|pid)$')" ] && pass "nothing enabled or running" || fail "units still enabled or running after --purge"

echo
[ "$FAILS" = 0 ] && echo "upgrade test: OK ($OLDV -> $NEWV)" || { echo "upgrade test: $FAILS FAILED (work dir kept: $W)"; KEEP=1; exit 1; }
