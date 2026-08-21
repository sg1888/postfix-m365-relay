#!/usr/bin/env bash
# Build each image variant and run the full offline suite against it. Variants
# run SEQUENTIALLY: the suite resource names are shared across images, so two
# images under test at once would collide. Within each variant the suites run in
# parallel via run-offline.sh (honour TEST_JOBS).
#
# By default only the host-native variants are built and tested. amd64 variants
# on an arm64 host build under QEMU and their cryptography tests can segfault
# under emulation -- those are validated natively in CI. Pass ALL=1 to also
# attempt the emulated amd64 variants locally (build confirmation is useful even
# when the emulated test run is unreliable).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"

# name | dockerfile | platform (empty = native) | extra build args
variants=(
  "ubuntu-native|build/postfix-m365-relay/Dockerfile.ubuntu||"
  "alma-native|build/postfix-m365-relay/Dockerfile||"
)
if [[ ${ALL:-0} == 1 ]]; then
  variants+=(
    "ubuntu-amd64|build/postfix-m365-relay/Dockerfile.ubuntu|linux/amd64|"
    "alma-amd64|build/postfix-m365-relay/Dockerfile|linux/amd64|"
  )
fi

results=()
for spec in "${variants[@]}"; do
  IFS='|' read -r name dockerfile platform buildargs <<<"$spec"
  tag="postfix-m365-relay:test-$name"
  printf '\n=========== BUILD %s (%s) ===========\n' "$name" "$tag"
  build=(docker build -f "$repo/$dockerfile" -t "$tag")
  [[ -n $platform ]] && build+=(--platform "$platform")
  # shellcheck disable=SC2206 -- deliberate word-split of space-separated args
  [[ -n $buildargs ]] && build+=($buildargs)
  build+=("$repo")
  if ! "${build[@]}"; then
    results+=("BUILD-FAIL $name")
    continue
  fi
  printf '\n=========== TEST %s ===========\n' "$name"
  if "$here/run-offline.sh" "$tag"; then
    results+=("PASS $name")
  else
    results+=("FAIL $name")
  fi
done

printf '\n=========== MATRIX SUMMARY ===========\n'
printf '%s\n' "${results[@]}"
if printf '%s\n' "${results[@]}" | grep -qE '^(FAIL|BUILD-FAIL) '; then
  exit 1
fi
