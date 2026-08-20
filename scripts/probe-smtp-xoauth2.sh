#!/usr/bin/env bash
# Prove SMTP AUTH with an OAuth token preserves the sender display name.
#
# This is the test that decides whether the Postfix XOAUTH2 relay gets built.
# Graph is closed (docs/DESIGN.md); basic auth works but expires at the end of December
# 2026; the plan assumes SMTP submission behaves the same when the credential is
# a token. That assumption is documented, reasonable, and untested here, which is
# exactly the kind of thing that has been wrong before in this project.
#
# It sends real mail and changes nothing: no container, no config, no Postfix.
# The certificate and app registration are the existing ones; the only tenant
# change needed is the SMTP.SendAsApp permission, which docs/14 records.
#
# Run --dry-run first: it prints the plan and requests no token.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage: probe-smtp-xoauth2.sh --to ADDRESS [options]

Sends two messages over SMTP AUTH XOAUTH2 with display names in the From header.
Report whether the names arrived intact.

Options:
  --to ADDRESS        Where to send the probes. Required -- you must be able to read it
  --mailbox ADDRESS   Mailbox to authenticate as (default: MAIL_SEND_MAILBOX)
  --sender ADDRESS    From address (default: MAIL_SEND_MAILBOX)
  --env-file FILE     Identifier env file (default: ./mail-relay.env)
  --key-file FILE     OAuth private key file (required for a real run)
  --cert-file FILE    OAuth public certificate file (required for a real run)
  --dry-run           Print the plan, request no token, send nothing
USAGE
  exit 2
}

recipient=""
mailbox=""
sender=""
dry_run=0
env_file=./mail-relay.env
key_file=""
cert_file=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --to) recipient=${2:?--to needs an address}; shift ;;
    --mailbox) mailbox=${2:?--mailbox needs an address}; shift ;;
    --sender) sender=${2:?--sender needs an address}; shift ;;
    --env-file) env_file=${2:?--env-file needs a path}; shift ;;
    --key-file) key_file=${2:?--key-file needs a path}; shift ;;
    --cert-file) cert_file=${2:?--cert-file needs a path}; shift ;;
    --dry-run) dry_run=1 ;;
    -h|--help) usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
  shift
done

[[ -n $recipient ]] || usage

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
# shellcheck disable=SC1091
source "$project_dir/scripts/load-env.sh" "$env_file"

: "${MAIL_RELAY_TENANT:?Set MAIL_RELAY_TENANT in $env_file}"
: "${MAIL_RELAY_CLIENT_ID:?Set MAIL_RELAY_CLIENT_ID in $env_file}"
: "${MAIL_SEND_MAILBOX:?Set MAIL_SEND_MAILBOX in $env_file}"

mailbox=${mailbox:-$MAIL_SEND_MAILBOX}
sender=${sender:-$MAIL_SEND_MAILBOX}

# A real run uses explicitly exported test credential files. The normal image
# keeps its private key inside a named volume; do not copy a production key out.
if (( ! dry_run )); then
  [[ -n $key_file && -n $cert_file ]] || { echo 'A real run needs --key-file and --cert-file for test credentials.' >&2; exit 1; }
  for file in "$key_file" "$cert_file"; do
    [[ -r $file ]] || { echo "Cannot read $file" >&2; exit 1; }
  done
fi

args=(
  --tenant "$MAIL_RELAY_TENANT"
  --client-id "$MAIL_RELAY_CLIENT_ID"
  --key-file "$key_file"
  --cert-file "$cert_file"
  --mailbox "$mailbox"
  --sender "$sender"
  --to "$recipient"
)
(( dry_run )) && args+=(--dry-run)

/usr/bin/python3 "$project_dir/scripts/probe-smtp-xoauth2.py" "${args[@]}"
