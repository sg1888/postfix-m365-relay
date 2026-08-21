#!/usr/bin/env bash
# Run the complete pre-Microsoft release gate in the same order documented for
# maintainers. Keeping one audited runner prevents a local qualification from
# silently omitting a newly added suite while CI may retain descriptive steps.
# Every child uses reserved example identities and isolated Docker resources;
# no test needs tenant credentials or a route to a production relay.
#
# TEST_JOBS controls how many container suites run at once. Each suite namespaces
# its own containers, volumes, and networks and binds no host ports, so they
# never collide; the cap only keeps the timing-sensitive alert/verify/rotation
# loops honest under CPU load (unbounded risks timeout flakes). Default is
# min(4, cores). TEST_JOBS=1 forces serial execution with live per-suite output,
# which is easiest for debugging a single failing suite.
set -uo pipefail

image=${1:-postfix-m365-relay:test}
here="$(dirname "$0")"

cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
default_jobs=$(( cores < 4 ? cores : 4 ))
(( default_jobs >= 1 )) || default_jobs=1
jobs=${TEST_JOBS:-$default_jobs}

tests=(
  python-unit.sh
  container-sender-names.sh
  container-optional-sender.sh
  container-end-to-end.sh
  container-upstream-tls.sh
  container-spool-recovery.sh
  container-alert-incidents.sh
  container-alert-trigger-matrix.sh
  container-oauth-rotation-alert.sh
  container-inbound-tls-rotation-alert.sh
  container-invalid-alias-alert.sh
  container-config-matrix.sh
  container-first-run-config.sh
  container-sasl-user-lifecycle.sh
  container-network-policy.sh
  container-certificates.sh
  container-inbound-fullchain.sh
  container-policy.sh
)

# The static audit is the cheap gate: always first, always serial.
"$here/static.sh"

logdir=$(mktemp -d "${TMPDIR:-/tmp}/relay-tests.XXXXXX")
trap 'rm -rf "$logdir"' EXIT
fails=()

if [[ $jobs -le 1 ]]; then
  # Serial: stream each suite live so a failure is easy to watch, but still
  # collect every failure instead of aborting at the first one.
  for test_name in "${tests[@]}"; do
    printf '\n==> %s (%s)\n' "$test_name" "$image"
    "$here/$test_name" "$image" 2>&1 | tee "$logdir/$test_name.log"
    [[ ${PIPESTATUS[0]} -eq 0 ]] || fails+=("$test_name")
  done
else
  printf 'running %d suites, %d at a time, against %s\n\n' "${#tests[@]}" "$jobs" "$image"
  # Each child captures its own output to a per-suite log and prints one PASS/FAIL
  # line. Names are unique per suite, so concurrent runs never share a resource.
  printf '%s\n' "${tests[@]}" | xargs -P "$jobs" -I {} bash -c '
    t="$1"
    if "'"$here"'/$t" "'"$image"'" > "'"$logdir"'/$t.log" 2>&1; then
      echo "PASS $t"
    else
      echo "FAIL $t"
    fi
  ' _ {} | sort | tee "$logdir/summary.txt"
  while IFS= read -r line; do
    fails+=("${line#FAIL }")
  done < <(grep '^FAIL ' "$logdir/summary.txt" || true)
fi

if (( ${#fails[@]} > 0 )); then
  printf '\n%d suite(s) FAILED: %s\n' "${#fails[@]}" "${fails[*]}"
  for test_name in "${fails[@]}"; do
    printf '\n===== %s =====\n' "$test_name"
    cat "$logdir/$test_name.log"
  done
  exit 1
fi

printf '\nAll offline release tests passed for %s (jobs=%d)\n' "$image" "$jobs"
