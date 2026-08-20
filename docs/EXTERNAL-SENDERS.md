# Letting devices outside Docker use the relay

> Trusted LAN only. Never publish this listener to the Internet. Bind the host
> port to one explicit LAN address and test rejection from an untrusted host.

The container always listens on port 2525 internally. Docker may publish that as
2525 or 587 on the host without granting the container privileged-port access.

## Tier 0: Docker only

This is the default. Compose uses `expose`, not `ports`, and the relay has no
host listener. Confirm with:

```bash
docker port postfix-m365-relay
```

Nothing should print. Private apps get a 220 banner from `postfix-m365-relay:2525`;
LAN hosts do not.

## Tier 1: IP allowlist

Use `MAIL_INBOUND_AUTH=ip` for fixed devices on controlled addresses:

```yaml
ports: ["192.0.2.10:2525:2525"]
environment:
  MAIL_INBOUND_AUTH: ip
  MAIL_INBOUND_TLS: off
  MAIL_TRUSTED_NETWORKS: 192.0.2.50/32,192.0.2.51/32
```

Use the narrowest CIDRs possible. `0.0.0.0/0` and `::/0` are refused at boot. IP
policy stops casual abuse but doesn't authenticate a device or encrypt LAN content.

## Tier 2: per-device SMTP AUTH (implemented)

The image uses Cyrus SASL's daemon-less sasldb2 backend—no `saslauthd` or Dovecot.
Server-side mechanisms are pinned to PLAIN and LOGIN, separate from the outbound
XOAUTH2 plugin.

Create a protected source file:

```text
printer:long-unique-printer-password
nas:another-long-unique-password
```

Mount as a Docker secret. At boot, the entrypoint validates usernames, feeds
passwords to `saslpasswd2`, and builds an ephemeral db under `/run/mail-relay`.
Passwords never appear in arguments or logs.

### Password only

```yaml
environment:
  MAIL_INBOUND_AUTH: smtp-auth
  MAIL_INBOUND_TLS: require
  MAIL_SMTPD_USERS_FILE: /run/secrets/smtpd_users
```

Every device and app must authenticate. Use a STARTTLS client, bare username like
`printer`, and a unique password.

### Mixed fleet: plaintext printer plus roaming authenticated device

```yaml
ports: ["192.0.2.10:2525:2525"]
environment:
  MAIL_INBOUND_AUTH: ip-or-auth
  MAIL_INBOUND_TLS: may
  MAIL_TRUSTED_NETWORKS: 192.0.2.50/32
  MAIL_SMTPD_USERS_FILE: /run/secrets/smtpd_users
secrets: [smtpd_users]
```

The old printer at `.50` may submit without TLS by IP. A device elsewhere must
issue STARTTLS before Postfix advertises AUTH. Content from the old printer is
plaintext on the LAN; the Microsoft hop is still encrypted.

### Why there is no plaintext SASL compatibility mode

Some older printers lack TLS/SSL. Don't give them AUTH credentials—SASL
PLAIN/LOGIN without TLS exposes passwords to network observers. This image never
advertises AUTH before STARTTLS and rejects early AUTH.

For a fixed legacy device, use `ip` or the allowlisted side of `ip-or-auth`,
leave authentication off, and restrict source address in `MAIL_TRUSTED_NETWORKS`
and at the firewall. Prefer a dedicated printer VLAN and `/32` per device. If it
must cross an untrusted network, run a TLS SMTP gateway locally instead of
plaintext passwords.

This distinction is important in mixed mode: `MAIL_INBOUND_TLS=may` permits the
allowlisted printer's unauthenticated SMTP session to remain plaintext, but it
does **not** permit plaintext authentication. A password-authenticated client
still has to complete STARTTLS first. `smtp-auth` and `ip-and-auth` consequently
do not work for clients that lack STARTTLS.

### Defense in depth

```yaml
environment:
  MAIL_INBOUND_AUTH: ip-and-auth
  MAIL_INBOUND_TLS: require
  MAIL_TRUSTED_NETWORKS: 192.0.2.0/28
```

Both IP and valid credentials required.

## TLS certificate choices

When TLS is on and no files are supplied, the container generates a self-signed
certificate. A device may need to trust or pin it. For your internal CA cert,
mount files via `MAIL_INBOUND_TLS_CERT` and `MAIL_INBOUND_TLS_KEY`, then restart
after renewal. Generated certs renew yearly before ten-year expiry, keeping the
same key. Pinned-cert clients need updated trust entries; CA-based trust is
preferable.

AlmaLinux 10's crypto policy rejects TLS 1.0 and 1.1. Devices limited to those
versions can't use password auth. Keep them on an isolated VLAN with IP policy—never
weaken the container.

## Credential lifecycle

Add or revoke a device by editing its line and restarting:

```bash
docker restart postfix-m365-relay
docker exec postfix-m365-relay relay-users list
```

After revocation, test that the removed device fails and others still work. The
source file remains the authority; editing sasldb2 is temporary and unsupported.

## Verification drill

Before handing the listener to a device:

1. Confirm Docker bound only the intended address: `docker port postfix-m365-relay`.
2. From a non-allowlisted host without credentials, attempt RCPT; it must fail.
3. For `may`, check pre-STARTTLS EHLO has no AUTH and early AUTH fails.
4. After STARTTLS, check exactly PLAIN and LOGIN are offered—never XOAUTH2.
5. Test the positive and negative halves of the selected policy.
6. Confirm the delivered display name and sender behavior.
7. Watch the relay log for unexpected connections for at least a day.

The isolated test suite confirms TLS-before-AUTH and every policy. Repeat this
from real devices on your actual LAN interface before calling it verified—local
container proof doesn't cover firewall, routing, address assignment, or device
firmware.

## Choosing

| Situation | Policy |
|---|---|
| Docker containers only | `off` or `ip`, no published port |
| fixed printer on isolated VLAN | `ip` |
| roaming devices with modern TLS | `smtp-auth` |
| old fixed printer plus modern roaming device | `ip-or-auth` + TLS `may` |
| managed devices needing defense in depth | `ip-and-auth` + TLS `require` |
| Internet reachable | unsupported; use a VPN |
