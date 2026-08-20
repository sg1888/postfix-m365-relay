#!/usr/bin/env bash
# Render Postfix maps and the authoritative security block from environment
# configuration. This script is intentionally deterministic and side-effect
# free outside /etc/postfix plus the generated example in the state volume.
set -euo pipefail

log() { printf '%s render-config: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
fail() { log "FATAL: $*" >&2; exit 1; }
valid_email() { [[ $1 =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; }
regex_escape() { sed 's/[][(){}.^$*+?|\\]/\\&/g' <<<"$1"; }
display_name_escape() {
  # There are two parsers after Bash: Postfix's regexp-map replacement parser,
  # then the RFC 5322 quoted-string parser used by recipients. Escape for both
  # in the order shown. An early test used `Price $5`; Postfix treated $5 as a
  # missing capture group and skipped the rule. Doubling dollars is therefore
  # a correctness requirement, not cosmetic quoting.
  local value=$1
  value=${value//\\/\\\\}  # RFC quoted-string: preserve a literal backslash.
  value=${value//\"/\\\"}  # RFC quoted-string: preserve a literal quote.
  value=${value//\$/\$\$}    # Postfix regexp maps: $$ emits one literal dollar.
  printf '%s' "$value"
}

: "${MAIL_SEND_MAILBOX:?Set MAIL_SEND_MAILBOX}"
: "${MAIL_RELAY_TENANT:?Set MAIL_RELAY_TENANT}"
: "${MAIL_RELAY_CLIENT_ID:?Set MAIL_RELAY_CLIENT_ID}"
valid_email "$MAIL_SEND_MAILBOX" || fail "MAIL_SEND_MAILBOX must be a full email address"
[[ ${MAIL_AUTH_MODE:-microsoft-cert} == microsoft-cert ]] || fail "MAIL_AUTH_MODE=${MAIL_AUTH_MODE} is reserved but not implemented"

# Defaults describe the private, same-network collapse-mode posture. Published
# device access remains opt-in via the inbound auth/TLS variables.
RELAY_PORT=${RELAY_PORT:-2525}
MAIL_RELAY_DOMAIN=${MAIL_RELAY_DOMAIN:-relay.example.local}
MAIL_UPSTREAM_HOST=${MAIL_UPSTREAM_HOST:-smtp.office365.com}
MAIL_UPSTREAM_PORT=${MAIL_UPSTREAM_PORT:-587}
MAIL_UPSTREAM_TLS_SECURITY_LEVEL=${MAIL_UPSTREAM_TLS_SECURITY_LEVEL:-secure}
MAIL_SENDER_MODE=${MAIL_SENDER_MODE:-collapse}
MAIL_INBOUND_AUTH=${MAIL_INBOUND_AUTH:-ip}
MAIL_RELAY_MAX_SIZE=${MAIL_RELAY_MAX_SIZE:-3m}
MAIL_RELAY_RATE_LIMIT=${MAIL_RELAY_RATE_LIMIT:-200}
# Twelve hours gives an unattended relay enough time to survive a prolonged
# identity-provider or network outage without bouncing application mail.  This
# controls both normal deferred mail and deferred bounces; operators with a
# different delivery contract can use any Postfix-style single-unit duration.
MAIL_QUEUE_LIFETIME=${MAIL_QUEUE_LIFETIME:-12h}
MAIL_SENDER_NAME_FALLBACK=${MAIL_SENDER_NAME_FALLBACK:-the relay}
TOKEN_FILE=${MAIL_TOKEN_FILE:-/run/mail-relay/relay.json}

case "$MAIL_SENDER_MODE" in collapse|passthrough) ;; *) fail "MAIL_SENDER_MODE must be collapse or passthrough" ;; esac
case "$MAIL_UPSTREAM_TLS_SECURITY_LEVEL" in secure|encrypt) ;; *) fail "MAIL_UPSTREAM_TLS_SECURITY_LEVEL must be secure or encrypt" ;; esac
case "$MAIL_INBOUND_AUTH" in off|ip|smtp-auth|ip-or-auth|ip-and-auth) ;; *) fail "invalid MAIL_INBOUND_AUTH: $MAIL_INBOUND_AUTH" ;; esac
case "${MAIL_INBOUND_TLS:-}" in ''|off|may|require) ;; *) fail "MAIL_INBOUND_TLS must be off, may, or require" ;; esac

auth_enabled=no
case "$MAIL_INBOUND_AUTH" in
  smtp-auth|ip-or-auth|ip-and-auth) auth_enabled=yes ;;
esac
if [[ -z ${MAIL_INBOUND_TLS:-} ]]; then
  case "$MAIL_INBOUND_AUTH" in
    smtp-auth|ip-or-auth) MAIL_INBOUND_TLS=may ;;
    ip-and-auth) MAIL_INBOUND_TLS=require ;;
    *) MAIL_INBOUND_TLS=off ;;
  esac
fi
[[ $auth_enabled == no || $MAIL_INBOUND_TLS != off ]] || fail "password auth requires MAIL_INBOUND_TLS=may or require"
[[ $MAIL_INBOUND_AUTH != off || -z ${MAIL_TRUSTED_NETWORKS:-} ]] || fail "MAIL_TRUSTED_NETWORKS contradicts MAIL_INBOUND_AUTH=off"

case "$MAIL_RELAY_MAX_SIZE" in
  *k) max_size_bytes=$(( ${MAIL_RELAY_MAX_SIZE%k} * 1024 )) ;;
  *m) max_size_bytes=$(( ${MAIL_RELAY_MAX_SIZE%m} * 1024 * 1024 )) ;;
  *[0-9]) max_size_bytes=$MAIL_RELAY_MAX_SIZE ;;
  *) fail "MAIL_RELAY_MAX_SIZE must look like 3m, 500k, or bytes" ;;
esac
[[ $MAIL_QUEUE_LIFETIME =~ ^[0-9]+[smhdw]$ ]] || fail "MAIL_QUEUE_LIFETIME must look like 12h or 30m"

# Sender discovery accepts an arbitrary number of named applications. Exclude
# companion NAME variables and MAIL_SENDER_MODE itself; the latter was caught
# by a boot test after an early implementation accidentally treated it as an
# address named MODE.
mapfile -t sender_keys < <(compgen -A variable | sed -n '/^MAIL_SENDER_[A-Z0-9_]*$/p' | \
  sed '/^MAIL_SENDER_NAME_/d; /^MAIL_SENDER_MODE$/d' | sed 's/^MAIL_SENDER_//' | sort)
configured=()
for key in "${sender_keys[@]}"; do
  address_var=MAIL_SENDER_${key}
  name_var=MAIL_SENDER_NAME_${key}
  address=${!address_var-}
  name=${!name_var-}
  [[ -n $address && $address != replace_me ]] || continue
  valid_email "$address" || fail "$address_var must be a full email address"
  case "$name" in *$'\n'*|*$'\r'*) fail "$name_var must not contain a newline" ;; esac
  configured+=("$key")
done
(( ${#configured[@]} > 0 )) || fail "set at least one MAIL_SENDER_* address"

passthrough=()
# Passthrough is an allowlist, never a global bypass. Listed aliases retain
# their envelope/header identity; every unlisted sender still collapses to the
# licensed mailbox. First-match ordering in both generated maps enforces this.
if [[ $MAIL_SENDER_MODE == passthrough && -n ${MAIL_PASSTHROUGH_SENDERS:-} ]]; then
  IFS=$',; \t\n' read -ra candidates <<<"$MAIL_PASSTHROUGH_SENDERS"
  for address in "${candidates[@]}"; do
    [[ -n $address ]] || continue
    valid_email "$address" || fail "invalid MAIL_PASSTHROUGH_SENDERS address: $address"
    passthrough+=("${address,,}")
  done
fi

first_var=MAIL_SENDER_${configured[0]}
internal_domain=${!first_var#*@}
internal_domain_re=$(regex_escape "$internal_domain")

{
  echo '# Generated at container boot. Unknown envelope senders are rejected.'
  printf '%s OK\n' "$MAIL_SEND_MAILBOX"
  for key in "${configured[@]}"; do address_var=MAIL_SENDER_${key}; printf '%s OK\n' "${!address_var}"; done
} > /etc/postfix/sender_access

# Envelope identity controls Microsoft SendAs authorization. Header identity
# controls what people see. Both maps are required: changing only the visible
# From header creates mail that looks right locally but is refused upstream.
{
  echo '# Envelope rewriting. First match wins.'
  for address in "${passthrough[@]}"; do printf '/^%s$/ %s\n' "$(regex_escape "$address")" "$address"; done
  printf '/^.*$/ %s\n' "$MAIL_SEND_MAILBOX"
} > /etc/postfix/sender_canonical

{
  echo '# Outbound From-header rewriting. First match wins.'
  for address in "${passthrough[@]}"; do
    escaped=$(regex_escape "$address")
    printf '/^From:([[:space:]]*|.*<)%s>?[[:space:]]*$/ DUNNO\n' "$escaped"
  done
  for key in "${configured[@]}"; do
    address_var=MAIL_SENDER_${key}; name_var=MAIL_SENDER_NAME_${key}; name=${!name_var-}
    [[ -n $name && $name != replace_me ]] || continue
    safe_name=$(display_name_escape "$name")
    printf '/^From:([[:space:]]*|.*<)%s>?[[:space:]]*$/ REPLACE From: "%s" <%s>\n' \
      "$(regex_escape "${!address_var}")" "$safe_name" "$MAIL_SEND_MAILBOX"
  done
  printf '/^Reply-To:.*%s/ IGNORE\n' "$internal_domain_re"
  printf '/^Sender:.*%s/ IGNORE\n' "$internal_domain_re"
  printf '/^From:[[:space:]]*(.*)<[^>]*>[[:space:]]*$/ REPLACE From: $1<%s>\n' "$MAIL_SEND_MAILBOX"
  safe_fallback=$(display_name_escape "$MAIL_SENDER_NAME_FALLBACK")
  printf '/^From:[[:space:]]*[^<>[:space:]]+@[^<>[:space:]]+[[:space:]]*$/ REPLACE From: "%s" <%s>\n' \
    "$safe_fallback" "$MAIL_SEND_MAILBOX"
} > /etc/postfix/header_checks

printf '[%s]:%s %s:%s\n' "$MAIL_UPSTREAM_HOST" "$MAIL_UPSTREAM_PORT" "$MAIL_SEND_MAILBOX" "$TOKEN_FILE" > /etc/postfix/sasl_passwd
chmod 0600 /etc/postfix/sasl_passwd
if [[ -f /etc/postfix-m365-relay/main.cf ]]; then
  log 'using mounted /etc/postfix-m365-relay/main.cf'
  install -m 0644 /etc/postfix-m365-relay/main.cf /etc/postfix/main.cf
else
  cat > /etc/postfix/main.cf <<EOF
# Generated by postfix-m365-relay. Mount /etc/postfix-m365-relay/main.cf to supply a base file.
compatibility_level = 3.6
mydomain = $MAIL_RELAY_DOMAIN
myorigin = \$mydomain
mydestination =
inet_interfaces = all
inet_protocols = ipv4
smtpd_helo_required = yes
message_size_limit = $max_size_bytes
smtpd_client_message_rate_limit = $MAIL_RELAY_RATE_LIMIT
default_destination_concurrency_limit = 2
smtp_destination_concurrency_limit = 2
maximal_queue_lifetime = $MAIL_QUEUE_LIFETIME
bounce_queue_lifetime = $MAIL_QUEUE_LIFETIME
maillog_file = /var/log/mail-relay/postfix.log
EOF
  install -m 0644 /etc/postfix/main.cf /var/lib/mail-relay/generated-main.cf.example
fi

# User POSTFIX_name variables tune the unowned surface. The managed block below
# is applied afterwards and therefore wins for all security-sensitive settings.
while IFS='=' read -r name value; do
  [[ $name == POSTFIX_* ]] || continue
  setting=${name#POSTFIX_}; setting=${setting,,}
  [[ $setting =~ ^[a-z0-9_]+$ ]] || fail "invalid POSTFIX_ setting name: $name"
  postconf -e "$setting=$value"
done < <(env)

trusted=''
# User-supplied trust entries are additive and narrowly validated. Bare IPv4
# hosts become /32. All-address networks are rejected before Postfix starts;
# otherwise one typo would turn this container into an Internet open relay.
if [[ -n ${MAIL_TRUSTED_NETWORKS:-} ]]; then
  IFS=$',; \t\n' read -ra networks <<<"$MAIL_TRUSTED_NETWORKS"
  for network in "${networks[@]}"; do
    [[ -n $network ]] || continue
    [[ $network != 0.0.0.0/0 && $network != ::/0 ]] || fail "MAIL_TRUSTED_NETWORKS may not contain $network (open relay)"
    [[ $network =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || fail "invalid trusted IPv4/CIDR: $network"
    [[ $network == */* ]] || network=$network/32
    trusted+=" $network"
  done
fi
if [[ -n ${MAIL_SUBNET:-} ]]; then
  [[ $MAIL_SUBNET != 0.0.0.0/0 && $MAIL_SUBNET != ::/0 ]] || fail "MAIL_SUBNET may not be an all-addresses network"
  [[ $MAIL_SUBNET =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || fail "MAIL_SUBNET must be an IPv4 CIDR"
  docker_network=$MAIL_SUBNET
else
  # Discover only the container's own global interfaces. We originally
  # considered accepting Docker's host subnet as an implicit external input,
  # but that would make policy depend on engine-specific metadata. `ip` works
  # on Docker, Compose, and read-only deployments without a daemon socket.
  docker_network=$(ip -o -4 addr show scope global | awk '{print $4}' | \
    python3 -c 'import ipaddress,sys; print(" ".join(str(ipaddress.ip_interface(x).network) for x in sys.stdin.read().split()))')
fi
mynetworks="127.0.0.0/8 ${docker_network:-}$trusted"

loopback_map=/etc/postfix/loopback_clients
printf '127.0.0.0/8 PERMIT\n' > "$loopback_map"
case "$MAIL_INBOUND_AUTH" in
  off|ip) client_restrictions='permit_mynetworks, reject'; relay_restrictions='permit_mynetworks, reject' ;;
  smtp-auth) client_restrictions=''; relay_restrictions="check_client_access cidr:$loopback_map, permit_sasl_authenticated, reject" ;;
  ip-or-auth) client_restrictions=''; relay_restrictions='permit_mynetworks, permit_sasl_authenticated, reject' ;;
  ip-and-auth) client_restrictions='permit_mynetworks, reject'; relay_restrictions="check_client_access cidr:$loopback_map, permit_sasl_authenticated, reject" ;;
esac
case "$MAIL_INBOUND_TLS" in off) tls_level=none ;; may) tls_level=may ;; require) tls_level=encrypt ;; esac

# Remove a previous managed block, then remove each managed key from the base so
# every authoritative value exists exactly once inside the visible banner.
# Applying POSTFIX_* first and this block last is deliberate: users may tune the
# broad Postfix surface, but cannot override relay authorization, TLS-before-
# AUTH, sender admission, or OAuth transport settings. A regression test mounts
# a hostile main.cf with `mynetworks = 0.0.0.0/0` and proves these values win.
awk '/^# >>> postfix-m365-relay \(managed\) >>>$/{skip=1} !skip{print} /^# <<< postfix-m365-relay \(managed\) <<<$/{skip=0}' /etc/postfix/main.cf > /etc/postfix/main.cf.clean
mv /etc/postfix/main.cf.clean /etc/postfix/main.cf
managed_keys=(relayhost mynetworks smtpd_client_restrictions smtpd_relay_restrictions smtpd_recipient_restrictions smtpd_sender_restrictions sender_canonical_maps sender_canonical_classes smtp_header_checks smtp_sasl_auth_enable smtp_sasl_password_maps smtp_sasl_security_options smtp_sasl_mechanism_filter smtp_tls_security_level smtp_tls_CAfile smtp_tls_loglevel local_recipient_maps local_transport alias_maps alias_database smtpd_sasl_auth_enable smtpd_sasl_type smtpd_sasl_path smtpd_sasl_local_domain smtpd_sasl_security_options smtpd_sasl_tls_security_options smtpd_tls_auth_only broken_sasl_auth_clients smtpd_tls_security_level smtpd_tls_cert_file smtpd_tls_key_file smtpd_tls_chain_files smtpd_tls_loglevel)
for key in "${managed_keys[@]}"; do postconf -X "$key" 2>/dev/null || true; done
{
  echo '# >>> postfix-m365-relay (managed) >>>'
  echo "relayhost = [$MAIL_UPSTREAM_HOST]:$MAIL_UPSTREAM_PORT"
  echo "mynetworks = $mynetworks"
  echo "smtpd_client_restrictions = $client_restrictions"
  echo "smtpd_relay_restrictions = $relay_restrictions"
  echo "smtpd_recipient_restrictions = $relay_restrictions"
  echo 'smtpd_sender_restrictions = check_sender_access texthash:/etc/postfix/sender_access, reject'
  echo 'sender_canonical_maps = regexp:/etc/postfix/sender_canonical'
  echo 'sender_canonical_classes = envelope_sender'
  echo 'smtp_header_checks = regexp:/etc/postfix/header_checks'
  echo 'smtp_sasl_auth_enable = yes'
  echo 'smtp_sasl_password_maps = texthash:/etc/postfix/sasl_passwd'
  echo 'smtp_sasl_security_options ='
  echo 'smtp_sasl_mechanism_filter = xoauth2'
  echo "smtp_tls_security_level = $MAIL_UPSTREAM_TLS_SECURITY_LEVEL"
  echo "smtp_tls_CAfile = ${MAIL_UPSTREAM_CA_FILE_EFFECTIVE:?outbound CA bundle not prepared}"
  echo 'smtp_tls_loglevel = 1'
  echo 'local_recipient_maps ='
  echo 'local_transport = error:local delivery is disabled on this relay'
  echo 'alias_maps ='
  echo 'alias_database ='
  echo "smtpd_sasl_auth_enable = $auth_enabled"
  if [[ $auth_enabled == yes ]]; then
    echo 'smtpd_sasl_type = cyrus'
    echo 'smtpd_sasl_path = smtpd'
    echo "smtpd_sasl_local_domain = $MAIL_RELAY_DOMAIN"
    echo 'smtpd_sasl_security_options = noanonymous, noplaintext'
    echo 'smtpd_sasl_tls_security_options = noanonymous'
    echo 'smtpd_tls_auth_only = yes'
    echo 'broken_sasl_auth_clients = yes'
  fi
  echo "smtpd_tls_security_level = $tls_level"
  if [[ $MAIL_INBOUND_TLS != off ]]; then
    # The legacy-named cert/key settings remain supported by current Postfix and
    # let us point cert_file at a conventional fullchain.pem while retaining a
    # separately protected private key. smtpd_tls_chain_files is deliberately
    # cleared above: it is a replacement key+certificate-chain interface, not a
    # place for Certbot's intermediates-only chain.pem.
    echo "smtpd_tls_cert_file = ${MAIL_INBOUND_TLS_CERT_EFFECTIVE:?inbound TLS cert not prepared}"
    echo "smtpd_tls_key_file = ${MAIL_INBOUND_TLS_KEY_EFFECTIVE:?inbound TLS key not prepared}"
    echo 'smtpd_tls_loglevel = 1'
  fi
  echo '# <<< postfix-m365-relay (managed) <<<'
} >> /etc/postfix/main.cf

postfix check
log "rendered ${#configured[@]} sender(s), sender-mode=$MAIL_SENDER_MODE, inbound-auth=$MAIL_INBOUND_AUTH, inbound-tls=$MAIL_INBOUND_TLS"
