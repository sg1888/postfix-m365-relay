#!/usr/bin/env bash
# List the distro package updates a published image is missing.
#
# Purpose:   Decide whether the scheduled refresh in publish-image.yml should
#            build and release a new patch version. Runs the image (as root,
#            entrypoint bypassed), refreshes its package index, and prints one
#            line per pending update:
#              <package> <installed> -> <available> [key] [security]
#            [key]      the package is one the relay depends on directly (list below)
#            [security] the distro published the update as a security fix
#            .github/scripts/refresh-decision.sh decides from this list and a
#            Trivy scan whether to release now or wait for the monthly release.
# Called by: .github/workflows/publish-image.yml (job "plan"), once per variant.
# When:      Daily schedule and manual runs of that workflow; by hand to preview.
# Created:   2026-10-12
# Usage:     .github/scripts/pending-updates.sh IMAGE [PLATFORM]
#              IMAGE     a published image, e.g. docker.io/sg1888/postfix-m365-relay:1.1.0
#              PLATFORM  docker platform to run, default linux/amd64
#            Exit status: 0 listed (possibly nothing), 2 image could not be pulled
#            or inspected.
set -euo pipefail

image=${1:?usage: pending-updates.sh IMAGE [PLATFORM]}
platform=${2:-linux/amd64}

# Packages whose updates alone justify a release: the mail path (Postfix, SASL,
# the XOAUTH2 plugin), TLS (OpenSSL, the CA bundle), the token/rotation code
# (Python, cryptography, curl), and the C library everything links against.
# On Ubuntu, Debian and Alpine the XOAUTH2 plugin is compiled into the image
# from the vendored source (vendor/sasl-xoauth2), so its own updates arrive by
# updating that copy; the libraries it links (libcurl, jsoncpp, libstdc++) are
# listed here instead.
# key_apt covers Ubuntu 24.04 and Debian 13 (python3.12 vs python3.13 names).
key_apt='postfix libsasl2-2 libsasl2-modules libsasl2-modules-db sasl2-bin ca-certificates openssl libssl3t64 python3 python3.12 libpython3.12-minimal python3.13 libpython3.13-minimal python3-cryptography curl libcurl4t64 libjsoncpp25 libjsoncpp26 libstdc++6 libc6 netcat-openbsd tzdata'
key_apk='postfix cyrus-sasl cyrus-sasl-login ca-certificates openssl libcrypto3 libssl3 python3 py3-cryptography curl libcurl jsoncpp libstdc++ musl netcat-openbsd tzdata bash'
key_alma='postfix cyrus-sasl cyrus-sasl-lib cyrus-sasl-plain sasl-xoauth2 ca-certificates openssl openssl-libs python3 python3-libs python3-cryptography curl libcurl glibc nmap-ncat tzdata'

# shellcheck disable=SC2016  # expanded inside the container, not here
probe='
set -eu
if command -v apt-get >/dev/null 2>&1; then
  echo "distro=apt"
  apt-get update -qq >/dev/null 2>&1
  # "Inst pkg [old] (new Origin:release/pocket, ... [arch])"
  apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | awk "/^Inst /{
    sec = (\$0 ~ /-security/) ? 1 : 0
    old = \$3; gsub(/[][]/, \"\", old)
    new = \$4; gsub(/[(]/, \"\", new)
    print \$2, old, new, sec
  }"
elif command -v apk >/dev/null 2>&1; then
  # apk has no per-update security flag; Alpine publishes advisories separately
  # (secdb), so Alpine updates count only through the key list.
  echo "distro=apk"
  apk update -q >/dev/null 2>&1
  # "name-1.2-r0 < 1.2-r1": installed package (name-version) and newer version.
  apk version -l "<" 2>/dev/null | awk "NR > 1 && \$2 == \"<\" {
    full = \$1; n = split(full, p, \"-\")
    name = p[1]; for (i = 2; i <= n - 2; i++) name = name \"-\" p[i]
    print name, p[n-1] \"-\" p[n], \$3, 0
  }"
else
  echo "distro=alma"
  dnf -q makecache >/dev/null 2>&1
  sec=$(dnf -q updateinfo list --security --updates 2>/dev/null | awk "{print \$3}")
  dnf -q check-update 2>/dev/null | awk "NF==3 && \$1 !~ /^(Obsoleting|Security:)/ {print \$1, \$2}" |
  while read -r nameArch new; do
    name=${nameArch%.*}
    old=$(rpm -q --qf "%{VERSION}-%{RELEASE}" "$name" 2>/dev/null | head -n1)
    s=0
    printf "%s\n" "$sec" | grep -q "^${name}-[0-9]" && s=1
    echo "$name $old $new $s"
  done || true
fi
'

out=$(docker run --rm --pull always --platform "$platform" --network bridge \
  --user 0 --entrypoint /bin/bash "$image" -c "$probe") || {
  echo "pending-updates: could not run $image ($platform)" >&2
  exit 2
}

distro=$(printf '%s\n' "$out" | sed -n 's/^distro=//p')
case "$distro" in
  apt) key=" $key_apt " ;;
  apk) key=" $key_apk " ;;
  alma) key=" $key_alma " ;;
  *) echo "pending-updates: unknown distro in $image" >&2; exit 2 ;;
esac

# No pending update is the normal case: grep then matches nothing and exits 1,
# which under pipefail would fail the whole check (2026-10-13: that released
# 1.2.1 for nothing). Only a failure to run the image is an error.
printf '%s\n' "$out" | { grep -v '^distro=' || true; } | while read -r name old new sec; do
  [ -n "$name" ] || continue
  tags=
  [[ $key == *" $name "* ]] && tags+=' [key]'
  [ "$sec" = 1 ] && tags+=' [security]'
  echo "$name $old -> $new$tags"
done
