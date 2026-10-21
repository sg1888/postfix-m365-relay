#!/usr/bin/env bats
# Unit tests for .github/scripts/refresh-decision.sh, which decides whether the
# scheduled package refresh releases: at once for a fixable CRITICAL/HIGH CVE,
# otherwise at most once a month.

setup() {
  decide="$BATS_TEST_DIRNAME/../../.github/scripts/refresh-decision.sh"
  updates="$BATS_TEST_TMPDIR/updates.txt"
}

# The real 2026-10-21 refresh (which released v1.4.1 under the old rule).
oct21() {
  cat > "$updates" <<'EOF'
## 1.4.0
liblzma5 5.6.1+really5.4.5-1ubuntu0.3 -> 5.6.1+really5.4.5-1ubuntu0.4 [security]
ca-certificates 20260601~24.04.1 -> 20260816ubuntu0.24.04.1 [key] [security]
## 1.4.0-alma-v3
glibc 2.39-142.el10_2.alma.1 -> 2.39-145.el10_2.alma.1 [key] [security]
## 1.4.0-debian
ca-certificates 20250419 -> 20250419+deb13u1 [key] [security]
## 1.4.0-alpine
ca-certificates 20260909-r0 -> 20261020-r0 [key]
EOF
}

@test "security updates without a serious CVE wait when this month already has a release" {
  oct21
  run "$decide" "$updates" 2026-10 2026-10
  [ "$status" -eq 0 ]
  [ "${lines[0]}" = "publish=false" ]
  [[ ${lines[1]} == *"5 pending updates held for the monthly release"* ]]
}

@test "the first run of a new month releases what is pending" {
  oct21
  run "$decide" "$updates" 2026-10 2026-11
  [ "${lines[0]}" = "publish=true" ]
  [[ ${lines[1]} == "reason=monthly: 5 pending updates"* ]]
}

@test "a new year counts as a new month" {
  oct21
  run "$decide" "$updates" 2026-12 2027-01
  [ "${lines[0]}" = "publish=true" ]
}

@test "nothing pending never releases, even in a new month" {
  printf '## 1.4.0\n## 1.4.0-debian\n' > "$updates"
  run "$decide" "$updates" 2026-09 2026-10
  [ "${lines[0]}" = "publish=false" ]
  [ "${lines[1]}" = "reason=nothing pending" ]
}

@test "a fixable HIGH CVE releases at once" {
  oct21
  cat >> "$updates" <<'EOF'
## 1.4.0-debian
libssl3t64 3.5.1-1 -> 3.5.1-1+deb13u2 [key] [security]
cve CVE-2026-4242 HIGH libssl3t64 3.5.1-1 -> 3.5.1-1+deb13u2
EOF
  run "$decide" "$updates" 2026-10 2026-10
  [ "${lines[0]}" = "publish=true" ]
  [ "${lines[1]}" = "reason=urgent: CVE-2026-4242 HIGH libssl3t64 3.5.1-1 -> 3.5.1-1+deb13u2 in 1.4.0-debian" ]
}

@test "several urgent CVEs are counted in the reason" {
  cat > "$updates" <<'EOF'
## 1.4.0-alpine
libcrypto3 3.5.1-r0 -> 3.5.2-r0 [key]
libssl3 3.5.1-r0 -> 3.5.2-r0 [key]
cve CVE-2026-1 CRITICAL libcrypto3 3.5.1-r0 -> 3.5.2-r0
cve CVE-2026-1 CRITICAL libssl3 3.5.1-r0 -> 3.5.2-r0
EOF
  run "$decide" "$updates" 2026-10 2026-10
  [ "${lines[0]}" = "publish=true" ]
  [[ ${lines[1]} == *"in 1.4.0-alpine and 1 more" ]]
}

@test "a CVE with no pending update for its package does not release" {
  cat > "$updates" <<'EOF'
## 1.4.0
tzdata 2026c -> 2026e [key]
cve CVE-2026-7 HIGH python3-cryptography 41.0.7 -> 42.0.4
EOF
  run "$decide" "$updates" 2026-10 2026-10
  [ "${lines[0]}" = "publish=false" ]
  [ "${lines[2]}" = "note=not fixable by a rebuild: CVE-2026-7 HIGH python3-cryptography 41.0.7 -> 42.0.4 in 1.4.0" ]
}

@test "a pending update in another image does not make a CVE fixable" {
  cat > "$updates" <<'EOF'
## 1.4.0
curl 8.5.0-1 -> 8.5.0-2 [key] [security]
## 1.4.0-debian
cve CVE-2026-9 HIGH curl 8.14.1-1 -> 8.14.1-2
EOF
  run "$decide" "$updates" 2026-10 2026-10
  [ "${lines[0]}" = "publish=false" ]
}

@test "force releases even with nothing pending" {
  printf '## 1.4.0\n' > "$updates"
  run "$decide" "$updates" 2026-10 2026-10 true
  [ "${lines[0]}" = "publish=true" ]
  [[ ${lines[1]} == "reason=forced by a manual run"* ]]
}
