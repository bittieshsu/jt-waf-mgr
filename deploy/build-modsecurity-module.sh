#!/bin/bash
# Build the ModSecurity-nginx connector module for one nginx version, ahead of an nginx update (never during it).
#
# Run it on a build host or the WAF host itself (needs a compiler and libmodsecurity's headers; see below), for the
# nginx version the next update brings. The result is a module file plus a small JSON description; jt-waf-mgr checks
# it against that nginx before the update is allowed, and root must trust it (done here when run as root on the WAF
# host). Nothing here changes the running nginx.
#
#   sudo ./build-modsecurity-module.sh                 # the nginx version apt would install next (candidate)
#   sudo ./build-modsecurity-module.sh 1.30.7-1~bookworm  # a given nginx package version (its source package)
#   sudo ./build-modsecurity-module.sh 1.30.7          # an upstream nginx version (nginx.org/download, NGINX_SHA256)
#   OUT=/tmp/mod ./build-modsecurity-module.sh 1.30.7  # where to put the result (default: ./modsecurity-module-<version>)
#   MODSECURITY_PREFIX=/usr/local/modsecurity-3.0.17 ./build-modsecurity-module.sh 1.30.7-1~bookworm
#                                                      # a libmodsecurity built from source (newer than the distribution's,
#                                                      # e.g. for security fixes): the module looks for it there (rpath),
#                                                      # so that directory must exist on the WAF host as well
#
# Needs: build-essential, libmodsecurity-dev (or your own libmodsecurity's headers: MODSECURITY_INC / MODSECURITY_LIB),
# libpcre2-dev, zlib1g-dev, libssl-dev, curl. The nginx source comes from the nginx.org source package when that
# repository's deb-src line is present (checked by apt), else from nginx.org/download (checked against the SHA-256
# given in NGINX_SHA256). The connector is pinned below, by version and SHA-256.
set -euo pipefail

CONNECTOR_VERSION=1.0.4
CONNECTOR_SHA256=6bdc7570911be884c1e43aaf85046137f9fde0cfa0dd4a55b853c81c45a13313
CONNECTOR_URL="https://github.com/owasp-modsecurity/ModSecurity-nginx/releases/download/v$CONNECTOR_VERSION/ModSecurity-nginx-v$CONNECTOR_VERSION.tar.gz"

die() { echo "build-modsecurity-module: $*" >&2; exit 1; }
for t in cc make curl tar sha256sum; do command -v "$t" >/dev/null || die "$t is missing (apt install build-essential curl)"; done

PKG_VERSION=""
if [ $# -ge 1 ] && [[ "$1" == *-* ]]; then
    PKG_VERSION="$1"                                  # a package version (1.30.7-1~bookworm): its source package
    NGINX_VERSION=${PKG_VERSION%%-*}
    NGINX_VERSION=${NGINX_VERSION#*:}
elif [ $# -ge 1 ]; then
    NGINX_VERSION="$1"
else
    PKG_VERSION=$(apt-cache policy nginx 2>/dev/null | awk '/Candidate:/ {print $2}')
    [ -n "$PKG_VERSION" ] && [ "$PKG_VERSION" != "(none)" ] || die "no nginx candidate from apt; give the version"
    NGINX_VERSION=${PKG_VERSION%%-*}
    NGINX_VERSION=${NGINX_VERSION#*:}
fi
[[ "$NGINX_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "not an nginx version: $NGINX_VERSION"
OUT=${OUT:-$PWD/modsecurity-module-$NGINX_VERSION}
mkdir -p "$OUT"
# the result goes only where the person running this alone can write (root's install must not be pointed elsewhere)
[ -L "$OUT" ] && die "$OUT is a symbolic link"
[ "$(stat -c %u "$OUT")" = "$(id -u)" ] || die "$OUT is not yours"
case "$(stat -c %A "$OUT")" in ?????w????|????????w?) die "$OUT is writable by others";; esac
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# the nginx source: the distribution's source package when there is one (apt checks its signature)
SRC=""
if [ -n "$PKG_VERSION" ] && apt-get source --download-only -qq "nginx=$PKG_VERSION" >/dev/null 2>&1; then
    tar xzf "nginx_$NGINX_VERSION.orig.tar.gz"
    SRC="apt-get source nginx=$PKG_VERSION"
else
    curl -fsSL -o nginx.tar.gz "https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
    if [ -n "${NGINX_SHA256:-}" ]; then
        echo "$NGINX_SHA256  nginx.tar.gz" | sha256sum -c --quiet || die "nginx-$NGINX_VERSION.tar.gz does not match NGINX_SHA256"
    else
        die "no deb-src for nginx: set NGINX_SHA256 to the SHA-256 published for nginx-$NGINX_VERSION.tar.gz"
    fi
    tar xzf nginx.tar.gz
    SRC="https://nginx.org/download/nginx-$NGINX_VERSION.tar.gz"
fi
[ -d "nginx-$NGINX_VERSION" ] || die "the nginx source did not unpack"

curl -fsSL -o connector.tar.gz "$CONNECTOR_URL"
echo "$CONNECTOR_SHA256  connector.tar.gz" | sha256sum -c --quiet || die "the connector tarball does not match its pinned SHA-256"
tar xzf connector.tar.gz

cd "nginx-$NGINX_VERSION"
LDOPT=()
if [ -n "${MODSECURITY_PREFIX:-}" ]; then
    [[ "$MODSECURITY_PREFIX" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "MODSECURITY_PREFIX must be an absolute path"
    [ -f "$MODSECURITY_PREFIX/include/modsecurity/modsecurity.h" ] && [ -e "$MODSECURITY_PREFIX/lib/libmodsecurity.so" ] \
        || die "no libmodsecurity in $MODSECURITY_PREFIX (include/modsecurity, lib)"
    export MODSECURITY_INC="$MODSECURITY_PREFIX/include" MODSECURITY_LIB="$MODSECURITY_PREFIX/lib"
    LDOPT=(--with-ld-opt="-Wl,-rpath,$MODSECURITY_PREFIX/lib")
fi
# --with-compat: the module loads into an nginx of this version built with other options (the distribution's)
./configure --with-compat "${LDOPT[@]}" --add-dynamic-module="../ModSecurity-nginx-v$CONNECTOR_VERSION" >"$WORK/configure.log" 2>&1 \
    || { tail -20 "$WORK/configure.log" >&2; die "configure failed"; }
make -j"$(nproc)" modules >"$WORK/make.log" 2>&1 || { tail -20 "$WORK/make.log" >&2; die "make failed"; }
# strip, hash (and trust) inside this script's own directory; only then is a copy put in $OUT, which others may write
MOD="$WORK/ngx_http_modsecurity_module.so"
strip --strip-unneeded -o "$MOD" objs/ngx_http_modsecurity_module.so
chmod 644 "$MOD"

. /etc/os-release
LIBMS=$(dpkg-query -W -f='${Package}=${Version}' 'libmodsecurity3*' 2>/dev/null | head -1 || true)
if [ -n "${MODSECURITY_PREFIX:-}" ]; then
    LIBMS="libmodsecurity $(PKG_CONFIG_PATH="$MODSECURITY_PREFIX/lib/pkgconfig" pkg-config --modversion modsecurity 2>/dev/null || echo '?') in $MODSECURITY_PREFIX"
fi
SHA=$(sha256sum "$MOD" | cut -d' ' -f1)
cat > "$WORK/module.json" <<EOF
{"module": "ngx_http_modsecurity_module.so", "sha256": "$SHA", "nginx_version": "$NGINX_VERSION",
 "nginx_package": "${PKG_VERSION}", "connector": "$CONNECTOR_VERSION", "libmodsecurity": "${LIBMS}",
 "os": "${ID}-${VERSION_ID}", "arch": "$(dpkg --print-architecture 2>/dev/null || uname -m)",
 "built_at": "$(date -Iseconds)", "source": "$SRC"}
EOF
# built here, as root, on a host with jt-waf-mgr: root trusts it for an nginx update (from this script's own copy)
TRUSTED=no
if [ "$(id -u)" = 0 ] && command -v jt-waf-mgr >/dev/null && [ -d /etc/jt-waf-mgr ]; then
    jt-waf-mgr nginx-module-trust "$MOD" --sha256 "$SHA" --note "built here for nginx ${PKG_VERSION:-$NGINX_VERSION}" && TRUSTED=yes
fi
install -m 644 "$MOD" "$OUT/ngx_http_modsecurity_module.so"
install -m 644 "$WORK/module.json" "$OUT/module.json"
echo "built $OUT/ngx_http_modsecurity_module.so for nginx ${PKG_VERSION:-$NGINX_VERSION}"
echo "SHA-256: $SHA"
if [ "$TRUSTED" = no ]; then
    echo "On the WAF host, after copying the file there:"
    echo "  sudo jt-waf-mgr nginx-module-trust ngx_http_modsecurity_module.so --sha256 $SHA"
fi
echo "Then upload the .so and module.json on the nginx updates page."
