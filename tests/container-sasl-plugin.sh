#!/usr/bin/env bash
# Prove the image's XOAUTH2 plugin is the one we meant to ship and that Cyrus
# SASL actually loads it:
#   - every image: libsasl2 lists XOAUTH2 as a client mechanism, and PLAIN and
#     LOGIN as server mechanisms (inbound device AUTH), and no other mechanism
#   - source-built images (Ubuntu/Debian/Alpine): the provenance record names
#     exactly the commit and tree in vendor/sasl-xoauth2/UPSTREAM, the plugin's
#     libraries all resolve, and no build toolchain leaked into the image
#   - AlmaLinux: the plugin is EPEL's package and no source-build record exists
#   - every image: /etc/sasl-xoauth2.conf keeps the plugin's own token refresh
#     pointed at a dead local port and its token-revealing trace log off
#   - every image: the plugin reads exactly /etc/sasl-xoauth2.conf (a build with
#     another prefix reads e.g. /usr/local/etc and ignores ours; upstream #50)
#   - arm64: the plugin's segments are 64 KiB aligned, so it loads on 16K and
#     64K page kernels such as the Raspberry Pi 5's (upstream #91)
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
echo "conf=$(tr -d "\n" < /etc/sasl-xoauth2.conf 2>/dev/null)"
python3 - <<"PY"
import glob, re, struct
paths = glob.glob("/usr/lib*/sasl2/libsasl-xoauth2.so") + glob.glob("/usr/lib/*/sasl2/libsasl-xoauth2.so")
if not paths:
    print("plugin=missing")
    raise SystemExit
data = open(paths[0], "rb").read()
# Config path compiled in by CMake (CONFIG_FILE_FULL_PATH).
print("confpaths=" + " ".join(sorted({m.decode() for m in re.findall(rb"/[\w./-]*sasl-xoauth2\.conf", data)})))
# ELF64 little-endian: e_machine, then each PT_LOAD p_align.
machine, = struct.unpack_from("<H", data, 18)
phoff, = struct.unpack_from("<Q", data, 32)
phentsize, phnum = struct.unpack_from("<HH", data, 54)
aligns = [struct.unpack_from("<Q", data, phoff + i * phentsize + 48)[0]
          for i in range(phnum) if struct.unpack_from("<I", data, phoff + i * phentsize)[0] == 1]
print(f"machine={machine}")
print(f"minalign={min(aligns)}")
PY
'
out=$(docker run --rm --network none --user 0 --entrypoint /bin/bash "$image" -c "$probe")
get() { printf '%s\n' "$out" | sed -n "s/^$1=//p"; }

fail() { echo "container-sasl-plugin: $*" >&2; printf '%s\n' "$out" >&2; exit 1; }

[[ $(get viewer) != none ]] || fail "no SASL plugin viewer in the image"
[[ " $(get client) " == *" XOAUTH2 "* ]] || fail "XOAUTH2 is not a loaded client mechanism"
for mech in PLAIN LOGIN; do
  [[ " $(get server) " == *" $mech "* ]] || fail "$mech is not a loaded server mechanism"
done
# The build removes every other mechanism (postfix-install.sh, slim_image):
# nothing beyond what the relay uses may be loadable on either side.
for mech in ANONYMOUS CRAM-MD5 DIGEST-MD5 NTLM GSSAPI GS2-KRB5 OTP SRP SCRAM-SHA-1 SCRAM-SHA-256 SCRAM-SHA-512; do
  [[ " $(get client) $(get server) " != *" $mech "* ]] || fail "unused SASL mechanism $mech is still loadable"
done
[[ -z $(get leaked) ]] || fail "build tools leaked into the image: $(get leaked)"
[[ $(get scratch) == absent ]] || fail "builder scratch source left in the image"

# The plugin's refresh path is for delegated (user) tokens and would POST the
# token file's refresh_token plus client_secret; the relay mints its own tokens,
# so that path must stay unreachable. Its full failure trace logs the bearer
# token and refresh request verbatim, so it must stay off.
CONF=$(get conf) python3 - <<'PY' || fail "/etc/sasl-xoauth2.conf is not hardened"
import json, os, sys
from urllib.parse import urlsplit
conf = json.loads(os.environ["CONF"])
endpoint = urlsplit(conf["token_endpoint"])
problems = []
if (endpoint.hostname, endpoint.port) != ("127.0.0.1", 9):
    problems.append(f"token_endpoint {conf['token_endpoint']} is not the dead local port")
if conf.get("client_secret"):
    problems.append("client_secret is set")
for key in ("always_log_to_syslog", "log_full_trace_on_failure"):
    if conf.get(key) != "no":
        problems.append(f"{key} is {conf.get(key)!r}, want 'no'")
for p in problems:
    print(f"  {p}", file=sys.stderr)
sys.exit(1 if problems else 0)
PY

[[ $(get confpaths) == /etc/sasl-xoauth2.conf ]] || \
  fail "plugin reads '$(get confpaths)', not /etc/sasl-xoauth2.conf"
# e_machine 183 = AArch64.
if [[ $(get machine) == 183 ]]; then
  (( $(get minalign) >= 65536 )) || fail "arm64 plugin segment alignment $(get minalign) < 64 KiB"
fi

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
