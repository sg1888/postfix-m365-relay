#!/usr/bin/env bash
# Stable shell entry point for the durable Python incident manager.  Existing
# third-party automation may still call the original three-argument form, so it
# remains a one-shot notification; internal health callers use explicit
# open/recover transitions for deduplication and correlated recovery messages.
set -euo pipefail
case "${1:-}" in
  open|recover|notify)
    exec /usr/local/libexec/mail-relay/alert-event.py "$@"
    ;;
  info|warning|error)
    [[ $# -eq 3 ]] || { echo 'usage: alert.sh [open|recover|notify] ...' >&2; exit 64; }
    exec /usr/local/libexec/mail-relay/alert-event.py notify "$@"
    ;;
  *)
    echo 'usage: alert.sh open SEVERITY EVENT DETAIL | recover EVENT VALIDATION | notify SEVERITY EVENT DETAIL' >&2
    exit 64
    ;;
esac
