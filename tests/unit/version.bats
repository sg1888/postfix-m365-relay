#!/usr/bin/env bats
# Unit tests for build/postfix-m365-relay/build-scripts/version.sh, the floor
# check that lets AlmaLinux builds accept any EPEL sasl-xoauth2 at or above the
# known-good minimum instead of breaking when EPEL ships a newer release.

setup() {
  # shellcheck source=/dev/null
  source "$BATS_TEST_DIRNAME/../../build/postfix-m365-relay/build-scripts/version.sh"
}

@test "equal versions satisfy the floor" {
  run version_at_least 0.27 0.27
  [ "$status" -eq 0 ]
}

@test "a newer minor version satisfies the floor" {
  run version_at_least 0.28 0.27
  [ "$status" -eq 0 ]
}

@test "a newer major version satisfies the floor" {
  run version_at_least 1.0 0.27
  [ "$status" -eq 0 ]
}

@test "two-digit fields compare numerically, not as text" {
  run version_at_least 0.100 0.27
  [ "$status" -eq 0 ]
  run version_at_least 0.9 0.27
  [ "$status" -eq 1 ]
}

@test "an older version fails the floor" {
  run version_at_least 0.26 0.27
  [ "$status" -eq 1 ]
}

@test "missing trailing fields count as zero" {
  run version_at_least 0.27 0.27.0
  [ "$status" -eq 0 ]
  run version_at_least 0.27.1 0.27
  [ "$status" -eq 0 ]
  run version_at_least 0.27 0.27.1
  [ "$status" -eq 1 ]
}

@test "leading zeros do not trip octal parsing" {
  run version_at_least 0.08 0.07
  [ "$status" -eq 0 ]
  run version_at_least 0.07 0.08
  [ "$status" -eq 1 ]
}

@test "malformed versions are rejected, not silently accepted" {
  run version_at_least "" 0.27
  [ "$status" -eq 2 ]
  run version_at_least 0.27-1.el10 0.27
  [ "$status" -eq 2 ]
  run version_at_least 0..27 0.27
  [ "$status" -eq 2 ]
  run version_at_least 0.27 abc
  [ "$status" -eq 2 ]
}
