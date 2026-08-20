# GitHub repository guide

Public source for `sg1888/postfix-m365-relay`, a Microsoft 365-only SMTP relay image. This repository holds the source, configuration examples, tests, and operational docs. It does not hold tenant credentials, private keys, mailbox exports, outage notes, or deployment history.

## Clone and inspect

```bash
git clone https://github.com/sg1888/postfix-m365-relay.git
cd postfix-m365-relay
git log --oneline --decorate -n 5
```

Start with [README.md](../README.md), then use its index to pick the installation, Microsoft setup, networking, secrets, and testing guide you need.

## GitHub Actions

Pull requests run static checks, container tests, and image builds. A tag matching `v*` triggers the release workflow and publishes the multi-architecture image to Docker Hub and GHCR. The workflow never reads a local `.env` file or repository copy of a private key.

Docker Hub publishing needs these GitHub repository secrets:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN` (a Docker Hub access token, not the account password)

GHCR uses the workflow-provided `GITHUB_TOKEN`. Configure package visibility and repository permissions in GitHub before your first release. See [RELEASING.md](RELEASING.md) for the complete release checklist.

## Local contribution gate

Run these checks before opening a pull request:

```bash
./tests/static.sh
./tests/run-offline.sh postfix-m365-relay:test
```

The offline runner uses disposable containers and reserved example identities. Don't point it at production relays or mailboxes. Live Microsoft tests are separate and require explicit operator approval; follow [TESTING.md](TESTING.md).

## Reporting a security issue

Don't open a public issue with a token, private key, SMTP transcript, or tenant-specific identifier. Use [SECURITY.md](../SECURITY.md) instead.
