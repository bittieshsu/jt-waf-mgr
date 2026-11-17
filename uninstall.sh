#!/bin/sh
# jt-waf-mgr uninstaller.
#
#   sudo ./uninstall.sh            remove the services and the program; keep data and configuration
#   sudo ./uninstall.sh --purge    also remove the data (/var/lib/jt-waf-mgr, the apply program's state
#                                  /var/lib/jt-waf-mgr-apply, the upgrade backups /var/backups/jt-waf-mgr),
#                                  the configuration (/etc/jt-waf-mgr) and the jtwaf user
#
# The nginx configuration is never touched: the managed rule files (/etc/nginx/modsec/jt-waf-mgr) and the IP
# block list (/etc/nginx/jt-waf-mgr) stay, since nginx includes them; remove the includes and the management
# vhost yourself.
#
# Testing hooks (tools/test_upgrade.sh): JTWAF_ROOT=<staging root> works below that directory and runs
# as the current user; JTWAF_SYSTEMCTL=<program> replaces systemctl.
set -eu
ROOT=${JTWAF_ROOT:-}
SYSTEMCTL=${JTWAF_SYSTEMCTL:-systemctl}
PURGE=0
case "${1:-}" in
    --purge) PURGE=1 ;;
    "") ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac
[ -n "$ROOT" ] || [ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
UNITS="$ROOT/etc/systemd/system"

# Every jt-waf-mgr unit that is installed (not a fixed list, so a unit added in a later release is never
# left behind), plus the known names in case a unit file is already gone but still enabled. Triggers
# (.path, .timer) first, so nothing starts a service while it is being stopped.
units=$(
    { for f in "$UNITS"/jt-waf-mgr*.path "$UNITS"/jt-waf-mgr*.timer "$UNITS"/jt-waf-mgr*.service; do
          [ -f "$f" ] && basename "$f"; done
      for n in hub intel dns countries crs notify analyst geoip; do
          printf 'jt-waf-mgr-%s.path\njt-waf-mgr-%s.timer\njt-waf-mgr-%s.service\n' "$n" "$n" "$n"; done
      printf 'jt-waf-mgr-apply.path\njt-waf-mgr-apply.service\njt-waf-mgr.service\n'
    } | awk '!seen[$0]++' | awk '/\.path$/ {print 1, $0; next} /\.timer$/ {print 2, $0; next} {print 3, $0}' \
      | sort -s -k1,1n | cut -d' ' -f2)
for u in $units; do
    $SYSTEMCTL disable --now "$u" >/dev/null 2>&1 || true
    rm -f "$UNITS/$u"
done
rm -rf "$UNITS/jt-waf-mgr.service.d"
$SYSTEMCTL daemon-reload 2>/dev/null || true
rm -rf "$ROOT/usr/lib/jt-waf-mgr"
rm -f "$ROOT/usr/bin/jt-waf-mgr"
echo "removed the services and the program"
echo "note: the managed files in /etc/nginx/modsec/jt-waf-mgr and /etc/nginx/jt-waf-mgr stay in place (nginx includes them)"

if [ "$PURGE" = 1 ]; then
    # the audit anchors are append-only (chattr +a); in a container the flag is set from the host and
    # has to be cleared there first
    if [ -e "$ROOT/var/lib/jt-waf-mgr/audit-anchors.jsonl" ]; then
        chattr -a "$ROOT/var/lib/jt-waf-mgr/audit-anchors.jsonl" 2>/dev/null || true
    fi
    rm -rf "$ROOT/var/lib/jt-waf-mgr" "$ROOT/var/lib/jt-waf-mgr-apply" "$ROOT/var/backups/jt-waf-mgr" "$ROOT/etc/jt-waf-mgr" || {
        echo "error: could not remove everything (an append-only audit anchor file? clear it with chattr -a," >&2
        echo "  from the container host if this is a container), then run uninstall.sh --purge again" >&2
        exit 1; }
    if [ -z "$ROOT" ] && id jtwaf >/dev/null 2>&1; then userdel jtwaf; fi
    echo "removed data, backups, configuration and the jtwaf user"
else
    echo "kept /var/lib/jt-waf-mgr (database), /var/backups/jt-waf-mgr (upgrade backups) and /etc/jt-waf-mgr (configuration)"
fi
echo "nginx: remove the jt-waf-mgr includes and management vhost yourself if you added them"
