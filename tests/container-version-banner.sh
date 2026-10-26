#!/usr/bin/env bash
# The startup banner: the first thing in `docker logs` names the relay, its
# version and release date, and the Postfix and sasl-xoauth2 versions inside.
#
#   tests/container-version-banner.sh IMAGE [EXPECTED_VERSION]
#
# With EXPECTED_VERSION (the publish workflow passes the release being built),
# the image's own release file must carry it. Without it (CI and local builds),
# the banner must say "development build". Either way a hostile release file
# (control characters, terminal escapes) is shown as plain text, and the banner
# appears once even though setup mode re-executes the entrypoint.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
expected=${2:-}
name="postfix-m365-relay-version-banner"
fixture=$PWD/tests/.tmp-version-banner

cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$fixture"; }
trap cleanup EXIT
cleanup
install -d -m 0700 "$fixture"

# Run in setup mode (no configuration): the banner prints before anything else.
banner_of() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" --network none "$@" "$image" >/dev/null
  for _attempt in {1..20}; do
    docker logs "$name" 2>&1 | grep -q 'SETUP REQUIRED' && break
    sleep 0.5
  done
  docker logs "$name" 2>&1
}
# The banner's lines with the box borders and padding removed.
unboxed() { sed -n 's/^| *//; s/ *|$//p' <<< "$1"; }

raw=$(banner_of)
logs=$(unboxed "$raw")
grep -qx 'Starting Postfix M365 Relay' <<< "$logs" || { echo "no banner title:" >&2; echo "$raw" >&2; exit 1; }
[[ $(head -n1 <<< "$raw") =~ ^/-{68}\\$ ]] || { echo "banner is not first, or not boxed" >&2; echo "$raw" >&2; exit 1; }
[[ $(head -n2 <<< "$raw" | tail -n1) =~ ^\|\ +Starting\ Postfix\ M365\ Relay\ +\|$ ]] || { echo "title is not the banner's first line" >&2; exit 1; }
[[ -z $(grep -E '^[|/\\]' <<< "$raw" | awk 'length != 70') ]] || { echo "banner box lines are uneven" >&2; echo "$raw" >&2; exit 1; }
postfix=$(docker run --rm --entrypoint postconf "$image" -h mail_version)
grep -Eq "^Postfix: +${postfix//./\\.}$" <<< "$logs" || { echo "Postfix $postfix not in banner" >&2; exit 1; }
grep -Eq '^sasl-xoauth2: +[0-9]+\.[0-9]+' <<< "$logs" || { echo "no sasl-xoauth2 version" >&2; exit 1; }
grep -Eq '^Base OS: +[A-Za-z]' <<< "$logs" || { echo "no base OS" >&2; exit 1; }
[[ $(grep -c '^Starting Postfix M365 Relay$' <<< "$logs") -eq 1 ]] || { echo "banner printed more than once" >&2; exit 1; }

release=$(docker run --rm --entrypoint cat "$image" /usr/share/postfix-m365-relay/release)
if [[ -n $expected ]]; then
  grep -qx "version=$expected" <<< "$release" || { echo "release file: want version=$expected, have:" >&2; echo "$release" >&2; exit 1; }
  grep -Eqx 'released=[0-9]{4}-[0-9]{2}-[0-9]{2}' <<< "$release" || { echo "release file has no date" >&2; exit 1; }
  grep -Fqx "Version $expected" <<< "$logs" || { echo "banner does not show $expected" >&2; exit 1; }
  grep -Eq '^Released: +[0-9]{4}-' <<< "$logs" || { echo "banner does not show the date" >&2; exit 1; }
else
  grep -qx 'Development build (not a published release)' <<< "$logs" || { echo "dev build not labelled" >&2; exit 1; }
fi

# A published release file, and a hostile one: values are shown, escapes are not.
printf 'version=9.8.7\nvariant=alpine\nreleased=2026-10-21\nrevision=0123456789abcdef0123\n' > "$fixture/release"
logs=$(unboxed "$(banner_of -v "$fixture/release":/usr/share/postfix-m365-relay/release:ro)")
grep -Fqx 'Version 9.8.7' <<< "$logs" || { echo "version not shown" >&2; echo "$logs" >&2; exit 1; }
grep -Eq '^Variant: +alpine$' <<< "$logs" || { echo "release values not shown" >&2; echo "$logs" >&2; exit 1; }
grep -Eq '^Released: +2026-10-21$' <<< "$logs"
grep -Eq '^Commit: +0123456789ab$' <<< "$logs"
printf 'version=1.0\033[2J\033]0;owned\007\nvariant=x\r\n' > "$fixture/release"
raw=$(banner_of -v "$fixture/release":/usr/share/postfix-m365-relay/release:ro)
logs=$(unboxed "$raw")
if LC_ALL=C grep -q $'[\033\007\r]' <<< "$raw"; then
  echo "control characters from the release file reached the log" >&2; exit 1
fi
grep -Fqx 'Version 1.0[2J]0;owned' <<< "$logs" || { echo "hostile values not neutralised as expected" >&2; echo "$logs" >&2; exit 1; }
grep -Eq '^Variant: +x$' <<< "$logs" || { echo "hostile values not neutralised as expected" >&2; echo "$logs" >&2; exit 1; }

echo "ok startup banner shows relay ${expected:-development build}, Postfix $postfix, base OS and sasl-xoauth2, once"
