#!/usr/bin/env bash
# Prove the image's XOAUTH2 plugin is the one we meant to ship and that Cyrus
# SASL actually loads it:
#   - every image: libsasl2 lists XOAUTH2 as a client mechanism, and PLAIN and
#     LOGIN as server mechanisms (inbound device AUTH)
#   - source-built images (Ubuntu/Debian/Alpine): the provenance record names
#     exactly the commit and tree in vendor/sasl-xoauth2/UPSTREAM, the plugin's
#     libraries all resolve, and no build toolchain leaked into the image
#   - AlmaLinux: the plugin is EPEL's package and no source-build record exists
# Offline: the container runs with --network none.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
cd "$(dirname "$0")/.."
upstream=vendor/sasl-xoauth2/UPSTREAM
field() { sed -n "s/^$1=//p" "$upstream"; }

# shellcheck disable=SC2016  # expanded inside the container
probe='
set -u
viewer=
for v in pluginviewer saslpluginviewer /usr/sbin/pluginviewer /usr/sbin/saslpluginviewer; do
  command -v "$v" >/dev/null 2>&1 && { viewer=$v; break; }
done
echo "viewer=${viewer:-none}"
[ -n "$viewer" ] && {
  echo "client=$("$viewer" -c 2>/dev/null | sed -n "/client side/{n;p;q}" | xargs)"
  echo "server=$("$viewer" -s 2>/dev/null | sed -n "/server side/{n;p;q}" | xargs)"
}
if command -v rpm >/dev/null 2>&1; then
  echo "kind=rpm"
  echo "rpm=$(rpm -q --qf "%{NAME}-%{VERSION}" sasl-xoauth2 2>/dev/null)"
else
  echo "kind=source"
fi
src=/usr/share/postfix-m365-relay/sasl-xoauth2.source
if [ -e "$src" ]; then
  sed "s/^/source./" "$src"
  libdir=$(sed -n "s/^libdir=//p" "$src")
  if [ -e "$libdir/libsasl-xoauth2.so" ]; then
    if ldd "$libdir/libsasl-xoauth2.so" | grep -q "not found"; then echo "ldd=unresolved"; else echo "ldd=ok"; fi
  else
    echo "ldd=missing-plugin"
  fi
fi
leaked=
for tool in gcc g++ cc c++ cmake make git; do
  command -v "$tool" >/dev/null 2>&1 && leaked="$leaked $tool"
done
echo "leaked=${leaked# }"
[ -e /tmp/sasl-xoauth2 ] && echo "scratch=present" || echo "scratch=absent"
'
out=$(docker run --rm --network none --user 0 --entrypoint /bin/bash "$image" -c "$probe")
get() { printf '%s\n' "$out" | sed -n "s/^$1=//p"; }

fail() { echo "container-sasl-plugin: $*" >&2; printf '%s\n' "$out" >&2; exit 1; }

[[ $(get viewer) != none ]] || fail "no SASL plugin viewer in the image"
[[ " $(get client) " == *" XOAUTH2 "* ]] || fail "XOAUTH2 is not a loaded client mechanism"
for mech in PLAIN LOGIN; do
  [[ " $(get server) " == *" $mech "* ]] || fail "$mech is not a loaded server mechanism"
done
[[ -z $(get leaked) ]] || fail "build tools leaked into the image: $(get leaked)"
[[ $(get scratch) == absent ]] || fail "builder scratch source left in the image"

case "$(get kind)" in
  source)
    [[ $(get source.version) == "$(field version)" ]] || fail "plugin version $(get source.version), UPSTREAM $(field version)"
    [[ $(get source.commit) == "$(field commit)" ]] || fail "plugin commit $(get source.commit), UPSTREAM $(field commit)"
    [[ $(get source.tree) == "$(field tree)" ]] || fail "plugin tree $(get source.tree), UPSTREAM $(field tree)"
    [[ $(get ldd) == ok ]] || fail "plugin libraries: $(get ldd)"
    echo "ok sasl-xoauth2 $(get source.version) built from vendored commit $(get source.commit); XOAUTH2 loads"
    ;;
  rpm)
    [[ $(get rpm) == sasl-xoauth2-* ]] || fail "EPEL sasl-xoauth2 package is not installed"
    [[ -z $(get source.version) ]] || fail "AlmaLinux image unexpectedly carries a source-built plugin"
    echo "ok $(get rpm) from EPEL; XOAUTH2 loads"
    ;;
  *) fail "unrecognized image kind" ;;
esac
