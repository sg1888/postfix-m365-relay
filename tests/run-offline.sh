#!/usr/bin/env bash
# Run the complete pre-Microsoft release gate in the same order documented for
# maintainers. Keeping one audited runner prevents a local qualification from
# silently omitting a newly added suite while CI may retain descriptive steps.
# Every child uses reserved example identities and isolated Docker resources;
# no test needs tenant credentials or a route to a production relay.
set -euo pipefail

image=${1:-postfix-m365-relay:test}
tests=(
  python-unit.sh
  container-sender-names.sh
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

"$(dirname "$0")/static.sh"
for test_name in "${tests[@]}"; do
  printf '\n==> %s (%s)\n' "$test_name" "$image"
  "$(dirname "$0")/$test_name" "$image"
done
printf '\nAll offline release tests passed for %s\n' "$image"
