# postfix-m365-relay

Self-contained Postfix submission relay that handles Microsoft 365 app-only XOAUTH2 so your applications don't have to.

Set it up right: a dedicated unlicensed shared mailbox (under Microsoft's 50 GB limit) plus claims-less, group-scoped Exchange `Application SMTP.SendAsApp`. The app gets send-only—it cannot read mail. Read the full Microsoft setup guide in the GitHub repository before you grant it anything.

```bash
docker pull sg1888/postfix-m365-relay:latest
```

Required configuration: `MAIL_RELAY_TENANT`, `MAIL_RELAY_CLIENT_ID`, `MAIL_SEND_MAILBOX`, and at least one `MAIL_SENDER_*`. Add `MAIL_ADMIN_EMAIL` for alerts and proof messages. Mount a persistent writable directory at `/config`; first startup creates the commented `mail-relay.conf` there and waits for the required values. Persist `/var/lib/mail-relay` and `/var/spool/postfix`; keep `/run/mail-relay` on tmpfs. The default posture publishes no port.

The default `latest` (Ubuntu) runs on any x86-64 CPU — including virtual machines and older/budget chips — plus arm64. Optimized AlmaLinux builds are opt-in: `alma-v3` (needs AVX2) and `alma-v2` (needs SSE4.2, amd64 only). Pin a digest after testing.

Full setup, networking, security model, and device-relay recipes live in the GitHub repository README and `docs/` directory.
