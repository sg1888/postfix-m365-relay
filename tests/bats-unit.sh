#!/usr/bin/env bash
# Host-side unit tests for the pure shell helpers in
# build/postfix-m365-relay/lib/text.sh. Distro-independent and container-free:
# the functions are pure, so these run on the host in milliseconds using the
# vendored bats-core -- no image build, no network. Run before the container
# suites as the cheap fast gate.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
exec "$here/vendor/bats-core/bin/bats" "$here/unit"
