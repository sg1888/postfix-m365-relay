# GitHub repository guide

This repository is the public source for `sg1888/postfix-m365-relay`, a
Microsoft 365-only SMTP relay image. The GitHub repository contains the image
source, public configuration examples, tests, and operational documentation.
It does not contain tenant credentials, private keys, mailbox exports, outage
notes, or private deployment history.

## Clone and inspect

```bash
git clone https://github.com/sg1888/postfix-m365-relay.git
cd postfix-m365-relay
git log --oneline --decorate -n 5
```

Start with [README.md](../README.md), then use the index there to choose the
installation, Microsoft setup, networking, secrets, and testing guide.

## GitHub Actions

Pull requests run the static checks, container tests, and image build. A tag
matching `v*` runs the release workflow and publishes the multi-architecture
image to Docker Hub and GHCR. The workflow never reads a local `.env` file or
repository copy of a private key.

The Docker Hub publish job requires these GitHub repository secrets:

- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN` (a Docker Hub access token, not the account password)

GHCR uses the workflow-provided `GITHUB_TOKEN`. Configure package visibility
and repository permissions in GitHub before the first release. See
[RELEASING.md](RELEASING.md) for the complete release checklist.

## Local contribution gate

Run the focused checks before opening a pull request:

```bash
./tests/static.sh
./tests/run-offline.sh postfix-m365-relay:test
```

The full offline runner uses disposable containers and reserved example
identities. It must not be pointed at a production relay or mailbox. Live
Microsoft tests are deliberately separate and require explicit operator
approval; follow [TESTING.md](TESTING.md).

## Reporting a security issue

Do not open a public issue containing a token, private key, SMTP transcript, or
tenant-specific identifier. Follow [SECURITY.md](../SECURITY.md) instead.
