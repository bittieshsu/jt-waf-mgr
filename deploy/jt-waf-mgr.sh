#!/bin/sh
# Runs the jt-waf-mgr command line as the service user (the database belongs to it).
export PYTHONPATH=/usr/lib/jt-waf-mgr PYTHONDONTWRITEBYTECODE=1
# the one command that stays root: trusting a ModSecurity module file for nginx updates (root's own copy and list)
if [ "$(id -u)" = 0 ] && [ "${1:-}" = nginx-module-trust ]; then
    exec python3 -P -m jtwafmgr --config /etc/jt-waf-mgr/config.toml "$@"
fi
if [ "$(id -u)" = 0 ]; then
    exec runuser -u jtwaf -- python3 -m jtwafmgr --config /etc/jt-waf-mgr/config.toml "$@"
fi
exec python3 -m jtwafmgr --config /etc/jt-waf-mgr/config.toml "$@"
