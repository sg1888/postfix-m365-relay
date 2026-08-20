# postfix-m365-relay

Self-contained Postfix submission relay for Microsoft 365 app-only XOAUTH2.

```bash
docker pull sg1888/postfix-m365-relay:latest
```

Required configuration: `MAIL_RELAY_TENANT`, `MAIL_RELAY_CLIENT_ID`,
`MAIL_SEND_MAILBOX`, and at least one `MAIL_SENDER_*`. Add
`MAIL_ADMIN_EMAIL` for alerts and proof messages. Mount a persistent writable
directory at `/config`; first startup creates the commented
`mail-relay.conf` there and waits safely for required values. Persist
`/var/lib/mail-relay` and `/var/spool/postfix`; keep `/run/mail-relay` on tmpfs.
The default posture publishes no port.

Normal tags contain x86-64-v3 and arm64. Older x86 hardware uses the matching
`-x86-64-v2` tag. Pin a digest after testing.

Full setup, networking, security model, and device-relay recipes are in
the GitHub repository README and `docs/` directory.
