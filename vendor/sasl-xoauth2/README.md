# Vendored sasl-xoauth2 packages

These are **upstream-built** `.deb` packages for
[`sasl-xoauth2`](https://github.com/tarickb/sasl-xoauth2), committed here so the
Ubuntu image build (`build/postfix-m365-relay/Dockerfile` with
`--build-arg BASE_IMAGE=ubuntu:24.04`, default `SXO_SOURCE=vendored`) never
depends on a third-party server being online.

They are **not compiled by us** — they are the exact artifacts the maintainer
published to the Launchpad PPA `ppa:sasl-xoauth2/stable`. Vendoring them protects
against the PPA going offline, being deleted, or the single maintainer stepping
away: the bytes we ship are frozen and checksum-pinned in `SHA256SUMS`.

## What's here

| File | For | Version |
|------|-----|---------|
| `sasl-xoauth2_0.27-1ubuntu1~noble1~ppa1_amd64.deb` | Ubuntu 24.04 (noble), amd64 | 0.27 |
| `sasl-xoauth2_0.27-1ubuntu1~noble1~ppa1_arm64.deb` | Ubuntu 24.04 (noble), arm64 | 0.27 |
| `SHA256SUMS` | integrity pin, verified at build time | — |

The build verifies the checksum before installing (`sha256sum -c`), so a
corrupted or swapped file fails the build rather than shipping silently.

## Why 0.27 is fine (and why the version barely matters here)

This relay **disables sasl-xoauth2's own token fetching** — its config points the
token endpoint at a dead address and the relay mints tokens itself. sasl-xoauth2
is used only to *present* a pre-minted token as the XOAUTH2 SASL mechanism. The
token-store JSON format (`access_token` + `expiry`) and that presenter have been
stable since early releases, so any version from ~0.20 up serves identically.
0.27 is simply the newest available and includes a 0.24 segfault-in-logging fix
worth having. Full analysis: `docs/BASE-IMAGE.md`.

## License

sasl-xoauth2 is open source (Apache-2.0). Redistributing these binaries is
permitted; the license and copyright travel inside each `.deb`
(`/usr/share/doc/sasl-xoauth2/copyright`).

## Refreshing / adding a series

Run `./refresh.sh` to re-download the pinned files and regenerate `SHA256SUMS`,
or edit the `WANT` list inside it to pull a different version or Ubuntu series.
Review the checksum diff before committing.
