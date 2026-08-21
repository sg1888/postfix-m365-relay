#!/usr/bin/env bash
# Single source of truth for the "an operator must upload an OAuth certificate to
# Entra" condition. First boot, a manual reset, and automatic recovery all funnel
# through here so the durable flag, the pasteable public copy in the host-editable
# /config directory, and the wording of the repeated banner exist in exactly one
# place. Keeping it out of a restartable supervisor child means the state survives
# a container restart and is not re-derived from log scraping.
#
#   cert-action.sh require REASON THUMBPRINT PUBLIC_CERT_PATH
#       Record that an upload is needed, publish the pasteable copy to /config,
#       and print the banner once. Idempotent: re-running refreshes the export.
#   cert-action.sh remind
#       If an upload is still outstanding, re-publish the export when it went
#       missing and print the banner again. Driven by the periodic loops so the
#       notice repeats and cannot be lost in a sea of failed-delivery lines.
#   cert-action.sh clear
#       The certificate is trusted now: remove the flag and the pasteable copy.
#   cert-action.sh status
#       Exit 0 and print the state file when an upload is outstanding, else 1.
set -euo pipefail

STATE_DIR=${MAIL_STATE_DIR:-/var/lib/mail-relay}
ACTION_STATE=$STATE_DIR/cert-action-required
CONFIG_FILE=${MAIL_CONFIG_FILE:-/config/mail-relay.conf}
CONFIG_DIR=${CONFIG_FILE%/*}
[[ $CONFIG_DIR != "$CONFIG_FILE" ]] || CONFIG_DIR=.
EXPORT_CERT=$CONFIG_DIR/microsoft365-app-public-cert.pem
EXPORT_THUMB=$CONFIG_DIR/microsoft365-app-cert-thumbprint.txt

log() { printf '%s cert-action: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }

# A controlled slug only: require callers pass a reason with no whitespace or
# shell metacharacters, so the KEY=VALUE state file stays trivially parseable and
# no caller detail can smuggle a newline into it.
valid_reason() { [[ $1 =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]; }

publish_export() {
  local cert=$1 thumbprint=$2 owner
  [[ -f $cert ]] || return 0
  if [[ -d $CONFIG_DIR && -w $CONFIG_DIR ]]; then
    install -m 0644 "$cert" "$EXPORT_CERT"
    printf '%s\n' "$thumbprint" > "$EXPORT_THUMB"
    chmod 0644 "$EXPORT_THUMB"
    # Match the config directory's numeric owner so the administrator who
    # launched the stack can read and delete the export without sudo.
    owner=$(stat -c '%u:%g' "$CONFIG_DIR" 2>/dev/null || true)
    [[ -z ${owner:-} ]] || chown "$owner" "$EXPORT_CERT" "$EXPORT_THUMB" 2>/dev/null || true
  fi
}

banner() {
  local reason=$1 thumbprint=$2 cert=${3:-}
  log '>>> ACTION REQUIRED: upload the OAuth public certificate to your Microsoft 365 (Entra) app registration <<<'
  log "    reason:     $reason"
  log "    thumbprint: $thumbprint"
  if [[ -f $EXPORT_CERT ]]; then
    log "    file:       $EXPORT_CERT"
  else
    # No writable /config mount (advanced, env-only deployments): the log is the
    # only delivery channel, so print the PEM inline as a fallback.
    log '    file:       (no writable /config mount) printing the public certificate below'
    [[ -n $cert && -f $cert ]] && sed 's/^/    PUBLIC-CERTIFICATE: /' "$cert" || \
      log '    (public certificate unavailable) run: docker exec <container> relay-admin export-cert'
  fi
  log '    Mail is queued until Entra accepts it; the relay keeps retrying automatically.'
  log '    To start over instead, run: docker exec <container> relay-admin reset-oauth-cert'
}

read_state_field() {
  # Read one KEY=VALUE field from the state file without sourcing it.
  local field=$1 line
  [[ -f $ACTION_STATE ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line == "$field="* ]] && { printf '%s' "${line#*=}"; return 0; }
  done < "$ACTION_STATE"
}

case "${1:-}" in
  require)
    [[ $# -eq 4 ]] || { echo 'usage: cert-action.sh require REASON THUMBPRINT PUBLIC_CERT_PATH' >&2; exit 64; }
    reason=$2; thumbprint=$3; cert=$4
    valid_reason "$reason" || { echo 'cert-action: reason must be a lowercase slug' >&2; exit 64; }
    install -d -m 0700 "$STATE_DIR"
    tmp=$ACTION_STATE.tmp.$$
    {
      printf 'reason=%s\n' "$reason"
      printf 'thumbprint=%s\n' "$thumbprint"
      printf 'public_cert_path=%s\n' "$cert"
      printf 'since=%s\n' "$(date +%s)"
    } > "$tmp"
    mv -f "$tmp" "$ACTION_STATE"
    publish_export "$cert" "$thumbprint"
    banner "$reason" "$thumbprint" "$cert"
    ;;
  remind)
    [[ -f $ACTION_STATE ]] || exit 0
    reason=$(read_state_field reason)
    thumbprint=$(read_state_field thumbprint)
    cert=$(read_state_field public_cert_path)
    # Re-expose the pasteable copy if it went missing (e.g. a redeploy before the
    # first upload, or an operator deleted it by accident).
    [[ -f $EXPORT_CERT || -z $cert ]] || publish_export "$cert" "$thumbprint"
    banner "${reason:-certificate-upload}" "${thumbprint:-unavailable}" "$cert"
    ;;
  clear)
    removed=no
    [[ ! -e $ACTION_STATE ]] || { rm -f "$ACTION_STATE"; removed=yes; }
    [[ ! -e $EXPORT_CERT ]] || { rm -f "$EXPORT_CERT"; removed=yes; }
    [[ ! -e $EXPORT_THUMB ]] || { rm -f "$EXPORT_THUMB"; removed=yes; }
    [[ $removed == no ]] || log 'Microsoft 365 accepted the certificate; cleared the upload notice and export'
    ;;
  pointer)
    # One concise line, for the frequent token loop to keep the outstanding notice
    # visible between the verifier's fuller hourly banners without repeating it.
    [[ -f $ACTION_STATE ]] || exit 0
    log "ACTION REQUIRED (still pending): upload the OAuth certificate to Entra; see the latest full banner or run relay-admin export-cert"
    ;;
  status)
    [[ -f $ACTION_STATE ]] || exit 1
    cat "$ACTION_STATE"
    ;;
  *)
    echo 'usage: cert-action.sh require REASON THUMBPRINT PUBLIC_CERT_PATH | remind | pointer | clear | status' >&2
    exit 64
    ;;
esac
