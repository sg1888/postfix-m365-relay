#!/usr/bin/env bash
# Keep the images small and keep the build's trimming working:
#   - the unpacked filesystem stays under a per-distro budget (MB), so an
#     accidental dependency or a lost cleanup step fails CI instead of quietly
#     growing every user's download
#   - what slim_image (build-scripts/postfix-install.sh) removes stays removed:
#     man pages, docs other than license texts, Python's pip bootstrapper and
#     test suites, AlmaLinux's unused binutils
#   - license texts are still shipped
# Budgets are measured size plus about 15% headroom for ordinary distro
# updates (2026-10-13, arm64: Ubuntu 204, Debian 213, Alpine 90, AlmaLinux 282).
# Raise one deliberately, in a reviewed change, when the image legitimately grows.
set -euo pipefail

image=${1:-postfix-m365-relay:test}

# shellcheck disable=SC2016  # expanded inside the container
probe='
. /etc/os-release
echo "id=$ID"
echo "mb=$(( $(du -sxk / 2>/dev/null | cut -f1) / 1024 ))"
left=
[ -d /usr/share/man ] && left="$left /usr/share/man"
for py in /usr/lib/python3.* /usr/lib64/python3.*; do
  for p in ensurepip idlelib test; do [ -e "$py/$p" ] && left="$left $py/$p"; done
done
if [ -d /usr/share/doc ]; then
  extra=$(find /usr/share/doc -type f ! -name copyright | head -n1)
  [ -n "$extra" ] && left="$left $extra"
fi
command -v rpm >/dev/null 2>&1 && rpm -q binutils >/dev/null 2>&1 && left="$left binutils"
echo "left=${left# }"
licenses=$(find /usr/share/licenses /usr/share/doc -type f 2>/dev/null | wc -l)
[ -d /lib/apk/db ] && licenses=$((licenses + 1))   # Alpine records licenses in the apk db
echo "licenses=$licenses"
'
out=$(docker run --rm --network none --user 0 --entrypoint /bin/sh "$image" -c "$probe")
get() { printf '%s\n' "$out" | sed -n "s/^$1=//p"; }

case "$(get id)" in
  ubuntu) budget=235 ;;
  debian) budget=245 ;;
  alpine) budget=105 ;;
  almalinux) budget=325 ;;
  *) echo "container-image-size: unknown distro $(get id)" >&2; exit 1 ;;
esac

[[ -z $(get left) ]] || { echo "container-image-size: trimmed content is back: $(get left)" >&2; exit 1; }
(( $(get licenses) > 0 )) || { echo "container-image-size: no license texts shipped" >&2; exit 1; }
(( $(get mb) <= budget )) || {
  echo "container-image-size: $(get id) image is $(get mb) MB, budget $budget MB" >&2
  exit 1
}
echo "ok $(get id) image is $(get mb) MB (budget $budget MB); trimmed content stays trimmed"
