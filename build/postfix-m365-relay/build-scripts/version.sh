#!/bin/sh
# Version helpers for the build scripts. POSIX sh, no external tools, so they
# work in every base image (busybox, dash, bash) and in host-side bats tests
# (tests/unit/version.bats).

# version_at_least HAVE MINIMUM
# Exit 0 when dotted numeric version HAVE >= MINIMUM, 1 when lower, 2 when
# either is not purely dotted digits. Missing fields count as 0, so 0.27 equals
# 0.27.0 and 0.28 > 0.27.9.
version_at_least() {
  _have=$1 _min=$2
  case "$_have" in ''|*[!0-9.]*|.*|*.|*..*) return 2 ;; esac
  case "$_min" in ''|*[!0-9.]*|.*|*.|*..*) return 2 ;; esac
  while [ -n "$_have$_min" ]; do
    _h=${_have%%.*} _m=${_min%%.*}
    case "$_have" in *.*) _have=${_have#*.} ;; *) _have= ;; esac
    case "$_min" in *.*) _min=${_min#*.} ;; *) _min= ;; esac
    _h=${_h:-0} _m=${_m:-0}
    # Compare as integers without leading-zero/octal surprises.
    _h=$(printf '%s' "$_h" | sed 's/^0*//'); _h=${_h:-0}
    _m=$(printf '%s' "$_m" | sed 's/^0*//'); _m=${_m:-0}
    [ "$_h" -gt "$_m" ] && return 0
    [ "$_h" -lt "$_m" ] && return 1
  done
  return 0
}
