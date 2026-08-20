#!/usr/bin/env bash
# Renew the SMTP server certificate used by device-facing STARTTLS.
#
# This certificate has no relationship to Entra authentication. Generated
# certificates live in their own directory, retain their RSA private key, and
# are renewed one year before expiry by default. Reusing the key makes the live
# update a single atomic certificate rename; replacing key and certificate as
# two ordinary writes can briefly give Postfix a mismatched pair.
set -euo pipefail

log() { printf '%s inbound-tls-rotation: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
fail() { log "FAILED: $*" >&2; exit 1; }

# TLS disabled means there is intentionally no server certificate to maintain.
[[ ${MAIL_INBOUND_TLS:-off} != off ]] || exit 0
cert=${MAIL_INBOUND_TLS_CERT_EFFECTIVE:?inbound TLS certificate path is absent}
key=${MAIL_INBOUND_TLS_KEY_EFFECTIVE:?inbound TLS key path is absent}
renew_days=${MAIL_INBOUND_TLS_RENEW_AT_DAYS:-365}
validity_days=${MAIL_INBOUND_TLS_VALIDITY_DAYS:-3650}
[[ $renew_days =~ ^[0-9]+$ && $validity_days =~ ^[0-9]+$ ]] || \
  fail 'validity and renewal thresholds must be whole days'
(( renew_days > 0 && validity_days > renew_days )) || \
  fail 'MAIL_INBOUND_TLS_VALIDITY_DAYS must exceed MAIL_INBOUND_TLS_RENEW_AT_DAYS'

if openssl x509 -checkend $((renew_days * 86400)) -noout -in "$cert" >/dev/null 2>&1; then
  exit 0
fi

if [[ ${MAIL_INBOUND_TLS_MANAGED:-no} != yes ]]; then
  # A mounted public-CA certificate may be renewed by ACME, an appliance, or a
  # secret manager. Mutating that mount would violate ownership and often fail
  # on read-only Docker secrets, so alert and let the external owner replace it.
  expiry=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2- || true)
  /usr/local/libexec/mail-relay/alert.sh warning inbound-tls-expiring \
    "BYO inbound STARTTLS certificate needs external renewal; expires ${expiry:-unknown}" || true
  log "BYO certificate is inside its ${renew_days}-day renewal window; external renewal required"
  exit 0
fi

staged=$cert.new
previous=$cert.previous
rm -f -- "$staged"
# --reuse-key writes only the staged public certificate. If generation or any
# validation fails, `set -e` exits and the live certificate remains unchanged.
/usr/local/libexec/mail-relay/rotate-smtp-relay-cert.py \
  --generate-only --reuse-key --key-path "$key" --cert-path "$staged" \
  --validity "$validity_days" --subject "${MAIL_RELAY_HOSTNAME:-postfix-m365-relay}" >/dev/null

key_digest=$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256)
cert_digest=$(openssl x509 -in "$staged" -pubkey -noout 2>/dev/null | \
  openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)
[[ -n $key_digest && $key_digest == "$cert_digest" ]] || fail 'staged certificate does not match the live key'
openssl x509 -checkend $((renew_days * 86400)) -noout -in "$staged" >/dev/null 2>&1 || \
  fail 'staged certificate does not extend beyond the renewal window'
chown root:root "$staged"; chmod 0644 "$staged"

# Keep one recoverable public-certificate backup. The private key does not move.
cp -p -- "$cert" "$previous"
mv -f -- "$staged" "$cert"
# The supervisor starts Postfix and this loop concurrently. If renewal is due on
# container boot, Postfix may not have reached "running" yet; in that case its
# first smtpd processes will read the already-swapped file and no reload is
# necessary. Treating that harmless startup race as failure would create a false
# certificate alarm even though the replacement is safely live on disk.
if postfix status >/dev/null 2>&1; then
  postfix reload >/dev/null
else
  log 'Postfix is still starting; it will read the renewed certificate at startup'
fi
expiry=$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2-)
log "renewed generated certificate with the existing key; expires $expiry"
/usr/local/libexec/mail-relay/alert.sh info inbound-tls-rotated \
  "Generated inbound STARTTLS certificate renewed; expires $expiry" || true
