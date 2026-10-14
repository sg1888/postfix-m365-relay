#!/usr/bin/env bash
# Build each image variant and run the full offline suite against it. Variants
# run SEQUENTIALLY: the suite resource names are shared across images, so two
# images under test at once would collide. Within each variant the suites also
# run serially by default (TEST_JOBS=1, passed to run-offline.sh).
#
# By default only the host-native variants are built and tested. amd64 variants
# on an arm64 host build under QEMU and their cryptography tests can segfault
# under emulation -- those are validated natively in CI. Pass ALL=1 to also
# attempt the emulated amd64 variants locally (build confirmation is useful even
# when the emulated test run is unreliable).
set -uo pipefail
# Suites run one at a time unless TEST_JOBS says otherwise. Parallel runs on
# macOS Docker Desktop produce timing and bind-mount flakes (inbound-fullchain,
# the end-to-end recurring alias probe) that are not image defects, so a gate
# result is only trusted serially.
export TEST_JOBS=${TEST_JOBS:-1}
# The unified Dockerfile bind-mounts its build scripts, which requires BuildKit.
export DOCKER_BUILDKIT=1
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"

# Host-side shell unit tests are distro-independent -- run once, up front, as the
# cheap fast gate before any image build.
if ! "$here/bats-unit.sh"; then
  echo "bats unit tests FAILED" >&2
  exit 1
fi

# The vendored plugin's unit tests under sanitizers: also image-independent.
if ! "$here/sasl-xoauth2-sanitizers.sh"; then
  echo "sasl-xoauth2 sanitizer tests FAILED" >&2
  exit 1
fi
if ! "$here/sasl-xoauth2-fuzz.sh"; then
  echo "sasl-xoauth2 fuzzing FAILED" >&2
  exit 1
fi

# One Dockerfile, distro selected by the BASE_IMAGE build arg.
# name | dockerfile | platform (empty = native) | extra build args
variants=(
  "ubuntu-native|build/postfix-m365-relay/Dockerfile||--build-arg BASE_IMAGE=ubuntu:24.04"
  "alma-native|build/postfix-m365-relay/Dockerfile||--build-arg BASE_IMAGE=almalinux:10"
  "debian-native|build/postfix-m365-relay/Dockerfile||--build-arg BASE_IMAGE=debian:trixie-slim"
  "alpine-native|build/postfix-m365-relay/Dockerfile||--build-arg BASE_IMAGE=alpine:3.22"
)
if [[ ${ALL:-0} == 1 ]]; then
  variants+=(
    "ubuntu-amd64|build/postfix-m365-relay/Dockerfile|linux/amd64|--build-arg BASE_IMAGE=ubuntu:24.04"
    "alma-amd64|build/postfix-m365-relay/Dockerfile|linux/amd64|--build-arg BASE_IMAGE=almalinux:10"
    "debian-amd64|build/postfix-m365-relay/Dockerfile|linux/amd64|--build-arg BASE_IMAGE=debian:trixie-slim"
    "alpine-amd64|build/postfix-m365-relay/Dockerfile|linux/amd64|--build-arg BASE_IMAGE=alpine:3.22"
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
