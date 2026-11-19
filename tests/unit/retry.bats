#!/usr/bin/env bats
# Unit tests for build/postfix-m365-relay/build-scripts/retry.sh, the retry that
# keeps one bad package-mirror response from failing a release build.

setup() {
  # shellcheck source=/dev/null
  source "$BATS_TEST_DIRNAME/../../build/postfix-m365-relay/build-scripts/retry.sh"
  RETRY_DELAY=0
  counter=$BATS_TEST_TMPDIR/count
  echo 0 > "$counter"
}

# Fails until it has been called $1 times.
succeed_on() {
  n=$(( $(cat "$counter") + 1 ))
  echo "$n" > "$counter"
  [ "$n" -ge "$1" ]
}

@test "a command that succeeds runs once" {
  run with_retry succeed_on 1
  [ "$status" -eq 0 ]
  [ "$(cat "$counter")" -eq 1 ]
}

@test "a transient failure is retried until it succeeds" {
  run with_retry succeed_on 3
  [ "$status" -eq 0 ]
  [ "$(cat "$counter")" -eq 3 ]
}

@test "a lasting failure gives up after RETRY_ATTEMPTS" {
  run with_retry succeed_on 99
  [ "$status" -eq 1 ]
  [ "$(cat "$counter")" -eq 4 ]
  [[ $output == *"giving up after 4 attempts"* ]]
}

@test "the metadata refresh runs between attempts, not before the first" {
  refreshes=$BATS_TEST_TMPDIR/refreshes
  : > "$refreshes"
  note_refresh() { echo x >> "$refreshes"; }
  retry_refresh=note_refresh
  run with_retry succeed_on 3
  [ "$status" -eq 0 ]
  [ "$(wc -l < "$refreshes")" -eq 2 ]
}

@test "a failing metadata refresh does not stop the retry" {
  retry_refresh=false
  run with_retry succeed_on 2
  [ "$status" -eq 0 ]
}
