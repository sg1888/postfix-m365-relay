#!/usr/bin/env bash
# Prepare all mutable state and all security-sensitive Postfix configuration,
# then hand PID 1 to the supervisor.  Keeping this bootstrap separate from the
# supervisor matters: a restartable child must never be able to half-rebuild
# credentials or policy while Postfix is accepting mail.
set -euo pipefail

log() { printf '%s postfix-m365-relay: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
fail() { log "FATAL: $*" >&2; exit 1; }

# Load ordinary configuration from a persistent, host-editable file. Docker and
# orchestration environments can still set any option directly; an explicitly
# supplied environment variable always wins over the file. The parser treats
# the file strictly as KEY=VALUE data and never `source`s or `eval`s it, so a
# display name containing `$()`, backticks, quotes, or dollar signs cannot run
# commands. Only relay/Postfix configuration names are accepted: allowing PATH,
# BASH_ENV, or other process-control names would turn a data file into code by a
# different route.
CONFIG_FILE=${MAIL_CONFIG_FILE:-/config/mail-relay.conf}
CONFIG_TEMPLATE=/usr/share/postfix-m365-relay/mail-relay.conf.example

allowed_config_name() {
  [[ $1 == MAIL_* || $1 == POSTFIX_* || $1 == TZ || $1 == RELAY_PORT ]]
}

variable_is_set() {
  # `[[ -v name ]]` would be concise but the repository's fast static checks
  # intentionally run on older Bash as well as the AlmaLinux runtime. `declare
  # -p` distinguishes an explicitly empty variable from an absent one without
  # evaluating its content and is portable across those supported shells.
  declare -p "$1" >/dev/null 2>&1
}

configuration_is_complete() {
  # This is only the setup-mode readiness check; render-config.sh remains the
  # authoritative validator. Parse enough data to know when a user has filled
  # the three required Microsoft identifiers, without exporting partial values
  # into PID 1. A later `exec` starts from the original Docker environment and
  # loads the completed file cleanly. Named senders (MAIL_SENDER_*) are
  # deliberately NOT required: with none set the relay collapses every message
  # to MAIL_SEND_MAILBOX and preserves the display name the sending app supplied.
  local line name value required
  declare -A candidate=()
  if [[ -r $CONFIG_FILE ]]; then
    while IFS= read -r line || [[ -n $line ]]; do
      line=${line%$'\r'}
      [[ -n $line && $line != \#* && $line == *=* ]] || continue
      name=${line%%=*}; value=${line#*=}
      [[ $name =~ ^[A-Z][A-Z0-9_]*$ ]] || continue
      candidate[$name]=$value
    done < "$CONFIG_FILE"
  fi
  # Environment overrides are evaluated without printing their values.
  while IFS='=' read -r name value; do candidate[$name]=$value; done < <(env)
  for required in MAIL_RELAY_TENANT MAIL_RELAY_CLIENT_ID MAIL_SEND_MAILBOX; do
    value=${candidate[$required]:-}
    [[ -n $value && $value != replace_me ]] || return 1
  done
}

load_config_file() {
  local line name value
  [[ -r $CONFIG_FILE ]] || return 0
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%$'\r'}
    [[ -n $line && $line != \#* ]] || continue
    [[ $line == *=* ]] || fail "$CONFIG_FILE contains a non-comment line without '='"
    name=${line%%=*}; value=${line#*=}
    [[ $name =~ ^[A-Z][A-Z0-9_]*$ ]] || fail "$CONFIG_FILE contains an invalid variable name"
    allowed_config_name "$name" || fail "$CONFIG_FILE may set only MAIL_*, POSTFIX_*, TZ, or RELAY_PORT"
    # Support simple matching quotes as a convenience, but perform no escape,
    # interpolation, or command-substitution processing inside them.
    if (( ${#value} >= 2 )) && { [[ $value == \"*\" ]] || [[ $value == \'*\' ]]; }; then
      value=${value:1:${#value}-2}
    fi
    # Docker/orchestrator environment is the highest-precedence layer. `-v`
    # distinguishes an explicit empty override from a variable that is absent.
    if ! variable_is_set "$name"; then
      printf -v "$name" '%s' "$value"
      export "$name"
    fi
  done < "$CONFIG_FILE"
  log "loaded persistent configuration from $CONFIG_FILE (environment overrides preserved)"
}

if ! configuration_is_complete; then
  if [[ ! -e $CONFIG_FILE ]]; then
    config_dir=${CONFIG_FILE%/*}
    [[ $config_dir != "$CONFIG_FILE" ]] || config_dir=.
    install -d -m 0700 "$config_dir" "$config_dir/secrets" 2>/dev/null || \
      fail "configuration is incomplete and $config_dir is not writable; mount ./config:/config"
    [[ -r $CONFIG_TEMPLATE ]] || fail "image configuration template is absent: $CONFIG_TEMPLATE"
    install -m 0600 "$CONFIG_TEMPLATE" "$CONFIG_FILE"
    # A bind-mounted host directory is normally owned by the administrator who
    # launched Compose. `install` runs as container root, which otherwise leaves
    # the first-run file root-owned and prevents that administrator from editing
    # the template without an extra sudo/chown step. Preserve the directory's
    # numeric owner for both the config and its future device-secret directory.
    # Named volumes remain root-owned, which is appropriate for their default
    # Docker-managed posture.
    config_owner=$(stat -c '%u:%g' "$config_dir")
    chown "$config_owner" "$CONFIG_FILE" "$config_dir/secrets"
    log "created first-run configuration at $CONFIG_FILE"
  fi
  log "SETUP REQUIRED: edit $CONFIG_FILE; waiting for tenant ID, client ID, and mailbox (named senders are optional)"
  trap 'exit 0' TERM INT
  while ! configuration_is_complete; do sleep 2 & wait $!; done
  log 'configuration now has the required values; restarting bootstrap validation'
  exec "$0" "$@"
fi
load_config_file

# Compare public material only. Hashing DER public keys proves a certificate and
# private key are a pair without ever printing or copying the private key.
private_public_digest() { openssl pkey -in "$1" -pubout -outform DER 2>/dev/null | openssl dgst -sha256; }
certificate_public_digest() { openssl x509 -in "$1" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256; }
validate_pair() {
  local role=$1 key=$2 cert=$3 key_digest cert_digest
  openssl pkey -in "$key" -noout >/dev/null 2>&1 || fail "invalid $role private key: $key"
  openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1 || fail "invalid or expired $role certificate: $cert"
  key_digest=$(private_public_digest "$key") || fail "could not derive the $role key's public identity"
  cert_digest=$(certificate_public_digest "$cert") || fail "could not derive the $role certificate's public identity"
  [[ $key_digest == "$cert_digest" ]] || fail "$role private key and certificate do not match"
}

STATE_DIR=${MAIL_STATE_DIR:-/var/lib/mail-relay}
RUN_DIR=${MAIL_RUN_DIR:-/run/mail-relay}
RELAY_PORT=${RELAY_PORT:-2525}
export STATE_DIR RUN_DIR RELAY_PORT

# `TZ` is understood by the C library used by Postfix and by the bundled tools.
# Validate it as an IANA tzdata name rather than accepting a path: an absolute
# path or `..` would let a typo make logging depend on an arbitrary host file.
# When TZ is absent, libc reads /etc/localtime.  Container engines do not copy
# the server's zone automatically, but an operator may bind-mount that file;
# otherwise Alma's image default is UTC.  Our machine-readable audit prefixes
# deliberately remain UTC (`date -u`) even when Postfix renders local time.
if [[ -n ${TZ:-} ]]; then
  [[ $TZ != /* && $TZ != *..* && -f /usr/share/zoneinfo/$TZ ]] || \
    fail "TZ must be an installed IANA timezone such as America/New_York"
fi
[[ ${MAIL_CA_BUNDLE_MAX_AGE_DAYS:-90} =~ ^[0-9]+$ ]] || \
  fail 'MAIL_CA_BUNDLE_MAX_AGE_DAYS must be a whole number of days'

# Secrets must enter through files. Environment values are visible in `docker
# inspect`, support bundles, and many process listings. The named checks catch
# documented variables; the PEM scan is a second line of defence for a private
# key accidentally pasted into an unrelated variable.
for forbidden in MAIL_SMTPD_USERS MAIL_RELAY_CLIENT_KEY MAIL_RELAY_CLIENT_CERT MAIL_INBOUND_TLS_KEY_PEM MAIL_INBOUND_TLS_CERT_PEM; do
  [[ -z ${!forbidden:-} ]] || fail "$forbidden contains secret material; use a documented *_FILE path (docs/SECRETS.md)"
done
while IFS='=' read -r name value; do
  case "$value" in *'-----BEGIN '*'PRIVATE KEY-----'*) fail "$name contains a private key; mount it as a file (docs/SECRETS.md)" ;; esac
done < <(env)

# /etc/postfix may be an empty tmpfs in the read-only deployment. Restore the
# package snapshot on every boot, then render from that clean baseline. This
# also prevents stale managed settings surviving an image upgrade.
install -d -m 0755 /etc/postfix "$STATE_DIR" "$STATE_DIR/secrets" "$STATE_DIR/inbound-tls"
install -d -m 0750 -o postfix -g postfix "$RUN_DIR" "$RUN_DIR/log"
cp -a /usr/share/postfix-defaults/. /etc/postfix/

# Outbound `secure` TLS authenticates smtp.office365.com against the distro CA
# store. A TLS-inspecting organization can add its public inspection root
# explicitly; silently trusting every presented certificate would collapse
# `secure` back to encryption without identity. The extra file is public trust
# material, never a private CA key, and is copied into tmpfs so the immutable
# package bundle remains untouched.
# The system trust bundle lives at different paths per distro family: RHEL/
# AlmaLinux use /etc/pki, Debian/Ubuntu use /etc/ssl. Check the EL path first so
# the AlmaLinux image is unaffected.
if [[ -s /etc/pki/tls/certs/ca-bundle.crt ]]; then
  system_ca=/etc/pki/tls/certs/ca-bundle.crt
elif [[ -s /etc/ssl/certs/ca-certificates.crt ]]; then
  system_ca=/etc/ssl/certs/ca-certificates.crt
else
  fail 'system CA bundle is absent (looked in /etc/pki/tls/certs and /etc/ssl/certs)'
fi
if [[ -n ${MAIL_UPSTREAM_CA_EXTRA_FILE:-} ]]; then
  extra_ca=$MAIL_UPSTREAM_CA_EXTRA_FILE
  [[ -f $extra_ca && -r $extra_ca ]] || fail 'MAIL_UPSTREAM_CA_EXTRA_FILE must be a readable certificate file'
  ! grep -q -- 'PRIVATE KEY-----' "$extra_ca" || fail 'MAIL_UPSTREAM_CA_EXTRA_FILE must never contain a private key'
  # Parse every PEM block and reject expired/not-yet-valid material at boot.
  # OpenSSL later performs the actual chain and hostname verification during
  # each SMTP connection; this check exists to make bad mounted data obvious.
  EXTRA_CA_PATH=$extra_ca python3 - <<'PY' || fail 'MAIL_UPSTREAM_CA_EXTRA_FILE contains invalid or non-current certificates'
import datetime
import os
import re
from pathlib import Path
from cryptography import x509

data = Path(os.environ["EXTRA_CA_PATH"]).read_bytes()
blocks = re.findall(br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.S)
if not blocks:
    raise ValueError("no PEM certificates")
now = datetime.datetime.now(datetime.timezone.utc)
for block in blocks:
    certificate = x509.load_pem_x509_certificate(block)
    try:
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
    except AttributeError:  # cryptography < 42 (e.g. Ubuntu 24.04 ships 41.x)
        not_before = certificate.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = certificate.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    if not not_before <= now <= not_after:
        raise ValueError("certificate is outside its validity interval")
PY
  combined_ca=$RUN_DIR/upstream-ca-bundle.pem
  temporary_ca=$combined_ca.tmp.$$
  install -m 0644 -o root -g root "$system_ca" "$temporary_ca"
  printf '\n' >> "$temporary_ca"
  cat "$extra_ca" >> "$temporary_ca"
  mv -f -- "$temporary_ca" "$combined_ca"
  export MAIL_UPSTREAM_CA_FILE_EFFECTIVE=$combined_ca
  log 'added an explicitly mounted corporate CA to the outbound SMTP trust bundle'
else
  export MAIL_UPSTREAM_CA_FILE_EFFECTIVE=$system_ca
fi

# The generated OAuth certificate's PUBLIC half must reach a human exactly once,
# to seed the Entra app registration (the bootstrap "one-way door": until one
# cert is trusted there, the relay cannot sign the proof that would let it roll
# its own keys). After that first upload the relay rotates itself via Graph and
# never needs the operator again. Export the public certificate as a clearly
# named file in the host-editable /config directory so it can be retrieved
# without `docker logs`, and remove it automatically once Microsoft accepts it
# (proven by a successful token mint). The canonical cert never leaves the state
# volume; only this pasteable public copy lives in /config, and only until used.
CONFIG_DIR=${CONFIG_FILE%/*}
[[ $CONFIG_DIR != "$CONFIG_FILE" ]] || CONFIG_DIR=.
BOOTSTRAP_CERT_EXPORT=$CONFIG_DIR/microsoft365-app-public-cert.pem
BOOTSTRAP_THUMBPRINT_EXPORT=$CONFIG_DIR/microsoft365-app-cert-thumbprint.txt

publish_bootstrap_cert() {
  local cert=$1 thumbprint=$2 owner
  if [[ -d $CONFIG_DIR && -w $CONFIG_DIR ]]; then
    install -m 0644 "$cert" "$BOOTSTRAP_CERT_EXPORT"
    printf '%s\n' "$thumbprint" > "$BOOTSTRAP_THUMBPRINT_EXPORT"
    chmod 0644 "$BOOTSTRAP_THUMBPRINT_EXPORT"
    # Match the config directory's numeric owner so the administrator who
    # launched the stack can read and delete the export without sudo, exactly as
    # first-run does for the config file itself.
    owner=$(stat -c '%u:%g' "$CONFIG_DIR" 2>/dev/null || true)
    [[ -z ${owner:-} ]] || chown "$owner" "$BOOTSTRAP_CERT_EXPORT" "$BOOTSTRAP_THUMBPRINT_EXPORT" 2>/dev/null || true
    log 'ACTION REQUIRED: upload this PUBLIC certificate to your Microsoft 365 (Entra) app registration, then the relay starts sending:'
    log "  file:       $BOOTSTRAP_CERT_EXPORT"
    log "  thumbprint: $thumbprint"
    log 'Mail is queued until Entra accepts it. This file is removed automatically once accepted.'
  else
    # No writable /config mount (advanced, env-only deployments): the log is the
    # only delivery channel, so print the PEM as a fallback.
    log 'ACTION REQUIRED: upload the following PUBLIC certificate to your Microsoft 365 (Entra) app registration.'
    log "Certificate SHA-1 thumbprint: $thumbprint"
    sed 's/^/PUBLIC-CERTIFICATE: /' "$cert"
    log 'The relay remains running and queues mail until Entra accepts this certificate.'
  fi
}

remove_bootstrap_cert() {
  # Called once a token mint proves Microsoft trusts the live certificate. Only
  # the pasteable copy is removed; the canonical cert stays in the state volume.
  local removed=no
  [[ ! -e $BOOTSTRAP_CERT_EXPORT ]] || { rm -f "$BOOTSTRAP_CERT_EXPORT"; removed=yes; }
  [[ ! -e $BOOTSTRAP_THUMBPRINT_EXPORT ]] || { rm -f "$BOOTSTRAP_THUMBPRINT_EXPORT"; removed=yes; }
  [[ $removed == no ]] || log "Microsoft 365 accepted the certificate; removed the bootstrap export from $CONFIG_DIR."
}

oauth_key=$STATE_DIR/secrets/mail_relay_client_key.pem
oauth_cert=$STATE_DIR/secrets/mail_relay_client_cert.pem
# A mounted pair is an import source, not the permanent live path. Copy it only
# when state is empty; copying it on every boot would silently undo a successful
# self-rotation by restoring the old certificate.
if [[ (! -s $oauth_key || ! -s $oauth_cert) && (-n ${MAIL_RELAY_CLIENT_KEY_FILE:-} || -n ${MAIL_RELAY_CLIENT_CERT_FILE:-}) ]]; then
  [[ -n ${MAIL_RELAY_CLIENT_KEY_FILE:-} && -n ${MAIL_RELAY_CLIENT_CERT_FILE:-} ]] || fail "provide both MAIL_RELAY_CLIENT_KEY_FILE and MAIL_RELAY_CLIENT_CERT_FILE"
  [[ -f $MAIL_RELAY_CLIENT_KEY_FILE && -r $MAIL_RELAY_CLIENT_KEY_FILE && -f $MAIL_RELAY_CLIENT_CERT_FILE && -r $MAIL_RELAY_CLIENT_CERT_FILE ]] || fail "the supplied OAuth key/cert paths must be readable regular files"
  install -m 0600 -o postfix -g postfix "$MAIL_RELAY_CLIENT_KEY_FILE" "$oauth_key"
  install -m 0644 -o postfix -g postfix "$MAIL_RELAY_CLIENT_CERT_FILE" "$oauth_cert"
  log 'imported the initial OAuth certificate into state; future rotations own the state copy'
fi
# First boot deliberately creates a credential even without Microsoft access.
# This lets an operator upload the public half while the private half never
# leaves the state volume. RSA-4096 is the OAuth identity; do not confuse it
# with the separately managed RSA-2048 inbound server certificate below.
if [[ ! -s $oauth_key || ! -s $oauth_cert ]]; then
  log 'generating the first OAuth client certificate (RSA 4096)'
  thumbprint=$(/usr/local/libexec/mail-relay/rotate-smtp-relay-cert.py \
    --generate-only --key-bits 4096 --validity "${MAIL_CERT_VALIDITY_DAYS:-730}" \
    --subject "${MAIL_RELAY_CERT_SUBJECT:-postfix-m365-relay}" \
    --key-path "$oauth_key" --cert-path "$oauth_cert")
  chown postfix:postfix "$oauth_key" "$oauth_cert"
  chmod 0600 "$oauth_key"; chmod 0644 "$oauth_cert"
  publish_bootstrap_cert "$oauth_cert" "$thumbprint"
fi
validate_pair OAuth "$oauth_key" "$oauth_cert"
# App-only OAuth identity is deliberately RSA-4096. Rejecting a weaker or
# different BYO key keeps imported credentials equivalent to generated ones and
# makes the security claim in documentation mechanically true.
openssl pkey -in "$oauth_key" -pubout -text -noout 2>/dev/null | \
  grep -q 'Public-Key: (4096 bit)' || fail 'OAuth private key must be RSA-4096'
export MAIL_RELAY_KEY_FILE=$oauth_key MAIL_RELAY_CERT_FILE=$oauth_cert

# Derive secure TLS defaults from the selected inbound trust model. In
# particular, ip-and-auth means both conditions, so it defaults to mandatory
# TLS and client-network rejection before SASL is considered.
MAIL_INBOUND_AUTH=${MAIL_INBOUND_AUTH:-ip}
case "$MAIL_INBOUND_AUTH" in smtp-auth|ip-or-auth|ip-and-auth) auth_enabled=yes ;; *) auth_enabled=no ;; esac
if [[ -z ${MAIL_INBOUND_TLS:-} ]]; then
  case "$MAIL_INBOUND_AUTH" in smtp-auth|ip-or-auth) MAIL_INBOUND_TLS=may ;; ip-and-auth) MAIL_INBOUND_TLS=require ;; *) MAIL_INBOUND_TLS=off ;; esac
fi
export MAIL_INBOUND_AUTH MAIL_INBOUND_TLS
[[ $auth_enabled == no || $MAIL_INBOUND_TLS != off ]] || fail "password auth requires MAIL_INBOUND_TLS=may or require"

# Inbound TLS is intentionally a different key pair from the Entra client
# credential. Sharing them would expose the OAuth private key to every SMTP
# client and would let ordinary web-certificate renewal break app auth.
if [[ $MAIL_INBOUND_TLS != off ]]; then
  inbound_validity=${MAIL_INBOUND_TLS_VALIDITY_DAYS:-3650}
  inbound_renew_at=${MAIL_INBOUND_TLS_RENEW_AT_DAYS:-365}
  [[ $inbound_validity =~ ^[0-9]+$ && $inbound_renew_at =~ ^[0-9]+$ ]] || \
    fail 'MAIL_INBOUND_TLS validity and renewal values must be whole days'
  (( inbound_renew_at > 0 && inbound_validity > inbound_renew_at )) || \
    fail 'MAIL_INBOUND_TLS_VALIDITY_DAYS must exceed MAIL_INBOUND_TLS_RENEW_AT_DAYS'
  export MAIL_INBOUND_TLS_VALIDITY_DAYS=$inbound_validity
  export MAIL_INBOUND_TLS_RENEW_AT_DAYS=$inbound_renew_at
  if [[ -n ${MAIL_INBOUND_TLS_CERT:-} || -n ${MAIL_INBOUND_TLS_KEY:-} ]]; then
    [[ -n ${MAIL_INBOUND_TLS_CERT:-} && -n ${MAIL_INBOUND_TLS_KEY:-} ]] || fail "provide both MAIL_INBOUND_TLS_CERT and MAIL_INBOUND_TLS_KEY"
    [[ -f $MAIL_INBOUND_TLS_CERT && -r $MAIL_INBOUND_TLS_CERT && -f $MAIL_INBOUND_TLS_KEY && -r $MAIL_INBOUND_TLS_KEY ]] || fail "the supplied inbound TLS certificate/key paths must be readable regular files"
    validate_pair 'inbound TLS' "$MAIL_INBOUND_TLS_KEY" "$MAIL_INBOUND_TLS_CERT"
    # MAIL_INBOUND_TLS_CERT may contain just the leaf certificate or, preferably
    # for a public/internal CA, the leaf followed by its intermediate issuers.
    # Certbot calls that file fullchain.pem.  Do not accept a separate "chain"
    # variable: Postfix's similarly named smtpd_tls_chain_files setting expects
    # key+leaf+issuers in a specific order, not an intermediates-only file.  An
    # earlier draft exposed that misleading knob before this semantic mismatch
    # was caught during the public-repository audit.
    export MAIL_INBOUND_TLS_CERT_EFFECTIVE=$MAIL_INBOUND_TLS_CERT
    export MAIL_INBOUND_TLS_KEY_EFFECTIVE=$MAIL_INBOUND_TLS_KEY
    export MAIL_INBOUND_TLS_MANAGED=no
  else
    inbound_key=$STATE_DIR/inbound-tls/key.pem
    inbound_cert=$STATE_DIR/inbound-tls/cert.pem
    if [[ ! -s $inbound_key || ! -s $inbound_cert ]] || ! openssl x509 -checkend 0 -noout -in "$inbound_cert" >/dev/null 2>&1; then
      log 'generating a separate self-signed inbound TLS certificate (RSA 2048)'
      /usr/local/libexec/mail-relay/rotate-smtp-relay-cert.py \
        --generate-only --key-bits 2048 --validity "$inbound_validity" \
        --subject "${MAIL_RELAY_HOSTNAME:-postfix-m365-relay}" \
        --key-path "$inbound_key" --cert-path "$inbound_cert" >/dev/null
      chown root:root "$inbound_key" "$inbound_cert"; chmod 0600 "$inbound_key"; chmod 0644 "$inbound_cert"
    fi
    validate_pair 'inbound TLS' "$inbound_key" "$inbound_cert"
    export MAIL_INBOUND_TLS_CERT_EFFECTIVE=$inbound_cert MAIL_INBOUND_TLS_KEY_EFFECTIVE=$inbound_key
    # This marker is more reliable than inferring ownership from a pathname.
    # Only state generated by this image may ever be replaced automatically.
    export MAIL_INBOUND_TLS_MANAGED=yes
  fi
fi

# sasldb2 is rebuilt in tmpfs on every boot. The plaintext source remains a
# mounted secret, and the command receives each password on stdin so it cannot
# appear in argv. We reject ambiguous records rather than guessing at them;
# passwords may contain additional colons because only the first is a separator.
if [[ $auth_enabled == yes ]]; then
  users_file=${MAIL_SMTPD_USERS_FILE:-/config/secrets/smtpd_users}
  [[ -f $users_file && -r $users_file ]] || fail "$MAIL_INBOUND_AUTH requires MAIL_SMTPD_USERS_FILE as a readable regular file (default /config/secrets/smtpd_users)"
  sasldb=$RUN_DIR/sasldb2
  install -m 0600 -o postfix -g postfix /dev/null "$sasldb"
  count=0
  while IFS= read -r record || [[ -n $record ]]; do
    record=${record%$'\r'}
    [[ -n $record && $record != \#* ]] || continue
    [[ $record == *:* ]] || fail "invalid device credential line (expected user:password; value not shown)"
    user=${record%%:*}; password=${record#*:}
    [[ $user =~ ^[a-z0-9._-]+$ ]] || fail "invalid device username: $user"
    [[ -n $password ]] || fail "empty password for device user $user"
    printf '%s\n' "$password" | saslpasswd2 -p -c -f "$sasldb" -u "${MAIL_RELAY_DOMAIN:-relay.example.local}" "$user" >/dev/null
    count=$((count + 1))
  done < "$users_file"
  (( count > 0 )) || fail "$users_file contains no device credentials"
  chown postfix:postfix "$sasldb"; chmod 0600 "$sasldb"
  log "loaded $count device credential(s) into ephemeral sasldb2"
fi

# Rendering happens only after credentials and TLS paths are known. master.cf
# is then narrowed to one unprivileged port: the package's port-25 listener is
# removed so EXPOSE and actual listening behaviour cannot diverge.
/usr/local/libexec/mail-relay/render-config.sh
postconf -e "myhostname=${MAIL_RELAY_HOSTNAME:-postfix-m365-relay.example.local}"
postconf -F 'smtp/unix/chroot=n'
postconf -X 'smtp/inet' 2>/dev/null || true
postconf -M "${RELAY_PORT}/inet=${RELAY_PORT} inet n - n - - smtpd"
postfix set-permissions >/dev/null 2>&1 || true

token_file=${MAIL_TOKEN_FILE:-$RUN_DIR/relay.json}
# Make one bounded mint attempt before Postfix can activate a persistent
# deferred queue.  In the first live restart test, Postfix started a few
# milliseconds ahead of the token loop, attempted XOAUTH2 with an empty tmpfs,
# and produced a misleading SASL failure before the next retry succeeded.  The
# token request itself has a 30-second network timeout, so this gate cannot hold
# the SMTP listener indefinitely.  If Entra is unavailable—or the first public
# certificate has not been uploaded yet—we deliberately continue: accepting and
# durably queueing new mail is safer than making the whole relay unavailable.
if /usr/local/libexec/mail-relay/refresh-smtp-token.py --min-remaining 1800; then
  log 'startup token check completed before Postfix activation'
  # A minted token proves Entra now trusts the live certificate, so the one-time
  # bootstrap export in /config has served its purpose and can be cleaned up.
  remove_bootstrap_cert
else
  log 'startup token mint failed; starting Postfix in queue-first mode while the supervised loop retries'
  # Not yet accepted by Microsoft. If a generated certificate exists but its
  # pasteable copy is missing (e.g. a redeploy before the first upload, or a lost
  # export), re-expose it so the operator can still complete the bootstrap.
  if [[ -d $CONFIG_DIR && -w $CONFIG_DIR && -s $oauth_cert && ! -e $BOOTSTRAP_CERT_EXPORT ]]; then
    existing_thumbprint=$(openssl x509 -in "$oauth_cert" -noout -fingerprint -sha1 2>/dev/null | sed 's/.*=//; s/://g')
    publish_bootstrap_cert "$oauth_cert" "${existing_thumbprint:-unavailable}"
  fi
fi
[[ -s $token_file ]] || log "token is not present yet; Postfix will queue mail while the token loop retries"
# exec makes the Bash supervisor the real PID 1, which is required for signal
# forwarding and orphan reaping. The PID-1 behaviour has a dedicated kill,
# restart, fatal-child, and clean-stop container regression test.
exec /usr/local/bin/relay-supervisor.sh
