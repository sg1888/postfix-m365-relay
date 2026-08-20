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

The command should print nothing. An app on the private network should receive a
220 banner from `postfix-m365-relay:2525`; a LAN host should not connect.

## Tier 1: IP allowlist

Use `MAIL_INBOUND_AUTH=ip` for fixed devices on controlled addresses:

```yaml
ports: ["192.0.2.10:2525:2525"]
environment:
  MAIL_INBOUND_AUTH: ip
  MAIL_INBOUND_TLS: off
  MAIL_TRUSTED_NETWORKS: 192.0.2.50/32,192.0.2.51/32
```

Use the narrowest CIDRs possible. `0.0.0.0/0` and `::/0` are refused at boot.
IP policy prevents casual use from other addresses but does not authenticate a
device and does not encrypt content on the LAN.

## Tier 2: per-device SMTP AUTH (implemented)

The image uses Cyrus SASL's daemon-less sasldb2 auxprop backend. It never runs
`saslauthd` or Dovecot. The server-side mechanism list is pinned to PLAIN and
LOGIN and is separate from the outbound XOAUTH2 client plugin.

Create a protected source file:

```text
printer:long-unique-printer-password
nas:another-long-unique-password
```

Mount it as a Docker secret. At every boot the entrypoint validates usernames,
feeds passwords through stdin to `saslpasswd2`, and builds an ephemeral database
under `/run/mail-relay`. Passwords never appear in arguments or logs.

### Password only

```yaml
environment:
  MAIL_INBOUND_AUTH: smtp-auth
  MAIL_INBOUND_TLS: require
  MAIL_SMTPD_USERS_FILE: /run/secrets/smtpd_users
```

Every device and Docker application must authenticate. Use a client configured
for STARTTLS, a bare username such as `printer`, and its unique password.

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

Some older printers have no usable TLS or SSL support. Do not assign those
devices a relay username and password: SASL PLAIN/LOGIN without TLS exposes the
credentials to anyone who can observe the network. This image therefore never
advertises AUTH before STARTTLS and rejects an early AUTH attempt.

For a fixed legacy device, use `ip` or the allowlisted side of `ip-or-auth`,
leave authentication disabled on the device, and restrict its source address
both in `MAIL_TRUSTED_NETWORKS` and at the firewall. Prefer a dedicated printer
VLAN and a `/32` entry per device. If the device must cross an untrusted
network, run a TLS-capable SMTP gateway on its local segment rather than
carrying a reusable password in plaintext.

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

Both a permitted source IP and valid per-device credentials are required.

## TLS certificate choices

When TLS is on and no files are supplied, the container generates a separate
self-signed server certificate. A device may need to trust or pin it. For a
certificate from your internal CA, mount cert/key files with
`MAIL_INBOUND_TLS_CERT` and `MAIL_INBOUND_TLS_KEY`, then restart after renewal.
Generated certificates renew one year before their ten-year expiry while
keeping the same private key. A client that pins the exact leaf certificate may
still need its trust entry updated; CA-based trust is preferable where possible.

AlmaLinux 10's crypto policy rejects TLS 1.0 and 1.1. A device limited to those
versions cannot use password auth on this image. Keep it on an isolated VLAN and
use IP policy; do not weaken the whole container.

## Credential lifecycle

Add or revoke a device by editing its line and restarting:

```bash
docker restart postfix-m365-relay
docker exec postfix-m365-relay relay-users list
```

After revocation, test that the removed device fails and another credential
still works. The source file remains the authority; editing sasldb2 directly is
temporary and unsupported.

## Verification drill

Before handing the listener to a device:

1. Confirm Docker bound only the intended address: `docker port postfix-m365-relay`.
2. From a non-allowlisted host without credentials, attempt RCPT; it must fail.
3. For `may`, check pre-STARTTLS EHLO has no AUTH and early AUTH fails.
4. After STARTTLS, check exactly PLAIN and LOGIN are offered—never XOAUTH2.
5. Test the positive and negative halves of the selected policy.
6. Confirm the delivered display name and sender behavior.
7. Watch the relay log for unexpected connections for at least a day.

The isolated built-image suite has watched TLS-before-AUTH and every policy
truth table work. Repeat this drill from real devices on the intended published
LAN interface before calling that installation verified; local container proof
does not prove firewall, routing, address assignment, or device firmware.

## Choosing

| Situation | Policy |
|---|---|
| Docker containers only | `off` or `ip`, no published port |
| fixed printer on isolated VLAN | `ip` |
| roaming devices with modern TLS | `smtp-auth` |
| old fixed printer plus modern roaming device | `ip-or-auth` + TLS `may` |
| managed devices needing defense in depth | `ip-and-auth` + TLS `require` |
| Internet reachable | unsupported; use a VPN |
