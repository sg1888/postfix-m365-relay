# Vendored sasl-xoauth2 source

`src/` is an **unmodified** copy of one commit of
[tarickb/sasl-xoauth2](https://github.com/tarickb/sasl-xoauth2), the Cyrus SASL
plugin that presents the relay's OAuth token to Microsoft 365 as XOAUTH2.
[`UPSTREAM`](UPSTREAM) records which commit (tag, version, commit id, and Git
tree hash).

## How it is used

The Ubuntu, Debian and Alpine images compile the plugin from this directory in a
builder stage (`build/postfix-m365-relay/build-scripts/sasl-xoauth2-build.sh`).
The build fetches no source from the network; it only installs the distro's
compiler and libraries. It runs upstream's own unit tests, then copies just the
plugin `.so` into the image. The AlmaLinux images do not use this copy: they
install EPEL's signed `sasl-xoauth2` package.

At build time a single line of `src/CMakeLists.txt` is removed in a scratch copy
(`add_subdirectory(docs)`, which needs pandoc to render man pages). This
directory itself is never edited.

## Why vendored

- **Auditable.** The code that is compiled is in this repository, reviewable in
  a normal diff when it changes.
- **Reproducible.** A build does not depend on GitHub, or on upstream keeping a
  tag or the repository online.
- **Provably unmodified.** `UPSTREAM` carries Git's tree hash of the upstream
  commit. Two directories have the same tree hash only if every file's bytes,
  name and executable bit match, so the check below proves `src/` is exactly
  upstream's code without trusting anything outside this repository.

## Checks

```bash
vendor/sasl-xoauth2/update.sh --check    # offline: src/ hashes to UPSTREAM's tree
vendor/sasl-xoauth2/update.sh --verify   # online: and upstream's commit has that tree
```

`tests/vendor-sasl-xoauth2.sh` runs `--check` (it is part of `tests/static.sh`);
the CI suite also runs `--verify`. Each image records the version and commit it
was compiled from in `/usr/share/postfix-m365-relay/sasl-xoauth2.source`, and
`tests/container-sasl-plugin.sh` checks that it matches `UPSTREAM`.

## Code review

[`REVIEW.md`](REVIEW.md) is a full read of the plugin source at the vendored
version, with findings judged against how the relay configures it, and the tests
that enforce that configuration. `tests/sasl-xoauth2-sanitizers.sh` runs
upstream's unit tests under AddressSanitizer, LeakSanitizer and
UndefinedBehaviorSanitizer in CI.

## Updating

`.github/workflows/sasl-xoauth2-watch.yml` does this automatically: daily, it
looks for a newer upstream `release-*` tag, vendors it on a branch, runs the
full test suite, and proposes it as a pull request (or an issue). By hand:

```bash
vendor/sasl-xoauth2/update.sh release-0.29     # replaces src/, rewrites UPSTREAM
git diff -- vendor/sasl-xoauth2                # read what upstream changed
```

Then run `tests/run-matrix.sh`; `tests/container-sasl-plugin.sh` checks each
image was compiled from exactly the new `UPSTREAM` commit. Read upstream's
`ChangeLog` (first entries of `src/ChangeLog`) for what changed, check the code
diff against [`REVIEW.md`](REVIEW.md), and update that review.

## License

sasl-xoauth2 is Copyright 2020 Google LLC, licensed under the Apache License,
Version 2.0; see [`src/COPYING`](src/COPYING). It is redistributed here
unmodified.
