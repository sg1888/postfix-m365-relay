#!/bin/sh
# Retry for the build scripts' package-manager steps. POSIX sh, no external
# tools beyond sleep, so it works in every base image (busybox, dash, bash) and
# in host-side bats tests (tests/unit/retry.bats).
#
# Package mirrors fail transiently. On 2026-10-26 an AlmaLinux mirror served a
# repomd.xml that was not XML; the v1.5.3 alma-v2 build failed on that single
# response, the other variants were already published, and the half-published
# release then failed every daily refresh until it was completed by hand.

# Attempts before giving up, and the base delay in seconds: attempt N waits
# N * RETRY_DELAY before the next one (20s, 40s, 60s by default).
RETRY_ATTEMPTS=${RETRY_ATTEMPTS:-4}
RETRY_DELAY=${RETRY_DELAY:-20}

# retry_refresh: run between attempts to drop the cached repository metadata,
# so a bad mirror response is fetched again rather than reused. Each package
# manager's branch sets it; empty means nothing to drop (apk --no-cache).
retry_refresh=

# with_retry COMMAND [ARG...]
# Run COMMAND until it succeeds, at most RETRY_ATTEMPTS times. Returns 0 on
# success, 1 once every attempt has failed. Only for idempotent steps (refresh
# metadata, upgrade, install).
with_retry() {
  _attempt=1
  until "$@"; do
    if [ "$_attempt" -ge "$RETRY_ATTEMPTS" ]; then
      echo "giving up after $_attempt attempts: $*" >&2
      return 1
    fi
    _wait=$((_attempt * RETRY_DELAY))
    echo "attempt $_attempt of $RETRY_ATTEMPTS failed: $*; retrying in ${_wait}s" >&2
    sleep "$_wait"
    if [ -n "$retry_refresh" ]; then
      $retry_refresh || true
    fi
    _attempt=$((_attempt + 1))
  done
}
