# Base image & CPU compatibility

This document explains **why the image is built the way it is**, why a stock
virtual machine can fail to start an AlmaLinux build, and how one Dockerfile
serves four base distros (Ubuntu, Debian, Alpine, AlmaLinux). It exists
because these decisions are non-obvious and have bitten real deployments.

## The symptom

On some machines — most often **virtual machines** — an AlmaLinux-based
container dies at startup with:

```
Fatal glibc error: CPU does not support x86-64-v3
```

Nothing else runs: no config sample is written, no listener opens. The container
crashes at process launch, before the entrypoint executes a single line. The
default `:latest` (Ubuntu) build does not have this problem — see below.

## The cause: x86-64 microarchitecture levels

64-bit x86 CPUs are grouped into feature *levels*. Each level requires the one
below it plus more instructions:

| Level | Adds | Roughly |
|-------|------|---------|
| v1 | baseline | any x86-64 CPU ever made |
| **v2** | SSE4.2, POPCNT | ~2009+ (Nehalem) |
| **v3** | AVX2, BMI, FMA | ~2013+ (Haswell) — **and not budget SKUs** |
| v4 | AVX-512 | high-end only |

Two facts combine into the failure:

1. **AlmaLinux 10 / RHEL 10 raised their minimum to v3.** The entire userspace
   (including glibc) is compiled for v3, so on a sub-v3 CPU glibc aborts every
   process. AlmaLinux publishes an official **v2 rebuild**, which is why this
   project also ships an `alma-v2` tag — but there is **no v1** AlmaLinux 10,
   so the floor for any AlmaLinux-10 image is **v2 (needs SSE4.2)**.

2. **"Modern CPU" does not guarantee v3.** Intel disables AVX2 on its budget
   lines (Celeron, Pentium, most Atom, N-series) regardless of year, so an
   8-year-old Celeron in a NAS has no AVX2. And crucially, **virtual machines**
   present a *virtual* CPU: the default QEMU/KVM model (`qemu64` / `kvm64`)
   advertises less than v2 — often not even SSE4.2 — hiding whatever the physical
   host actually supports.

## Why Docker doesn't "just pick the right one"

A common expectation is that a multi-arch image auto-selects the right build.
Docker's automatic selection works on **`os/architecture`** only — it chooses
`linux/amd64` vs `linux/arm64`. It does **not** select the amd64
microarchitecture *level*. Docker Engine's default image store ignores amd64
variant metadata and never reads `/proc/cpuinfo` to choose v2 over v3.

That is precisely why the AlmaLinux v2 and v3 builds are published as **separate
named tags** (`alma-v2`, `alma-v3`) rather than bundled into one auto-selecting
tag — bundling wouldn't auto-pick anyway. And it is why the **default `:latest` is
the universal Ubuntu build**: a v1-baseline image needs no micro-arch selection at
all, so the default puller never hits this trap.

## Choosing an image

| Your machine | Use |
|--------------|-----|
| Anything (default) — any x86-64 incl. default-CPU VMs, budget chips, arm64 | `:latest` / `:ubuntu` (universal) |
| Same CPUs, want newer Postfix (3.10) on glibc | `:debian` (amd64 + arm64) |
| Want the smallest image | `:alpine` (amd64 + arm64) |
| Has AVX2, want the AlmaLinux build | `:alma-v3` (amd64 + arm64) |
| Has SSE4.2 but not AVX2, want the AlmaLinux build | `:alma-v2` (amd64 only) |

### ARM and Raspberry Pi

Every tag except `alma-v2` includes `linux/arm64`. That covers the Raspberry Pi
3, 4, 5, Zero 2 W and Pi 2 v1.2 **on a 64-bit OS**; `uname -m` must print
`aarch64`. If it prints `armv7l` or `armv6l`, install the 64-bit Raspberry Pi OS
(Pi 3 and later, Zero 2 W).

32-bit ARM images are deliberately not built. Docker Engine 29 and later ship no
packages for 32-bit Raspberry Pi OS, and ARMv6 boards (Pi 1, Zero, Zero W) get
no official Docker packages at all; the original Pi 2 (v1.1) is the only board
left out.

The default `:latest` runs everywhere, so most people never need to choose. The
`alma-*` tags are opt-in for users who specifically want the AlmaLinux base. Quick
capability check inside the machine:

```bash
grep -o -m1 avx2 /proc/cpuinfo    # empty -> no AVX2 -> not v3-capable
grep -o -m1 sse4_2 /proc/cpuinfo  # empty -> not even v2-capable
```

Raising a VM's virtual CPU (e.g. Proxmox "Type: host", libvirt
`host-passthrough`) exposes the real flags and lets the v3 image run — but
expecting every user to change hypervisor settings is a poor out-of-box story,
which is why the universal Ubuntu build is the default.

## One Dockerfile, four base distros

Every variant is built from a **single** `build/postfix-m365-relay/Dockerfile`.
The base distro is selected by a build arg:

```bash
docker build -f build/postfix-m365-relay/Dockerfile \
  --build-arg BASE_IMAGE=ubuntu:24.04        -t relay:ubuntu .   # default :latest build
docker build -f build/postfix-m365-relay/Dockerfile \
  --build-arg BASE_IMAGE=debian:trixie-slim  -t relay:debian .
docker build -f build/postfix-m365-relay/Dockerfile \
  --build-arg BASE_IMAGE=alpine:3.22         -t relay:alpine .
docker build -f build/postfix-m365-relay/Dockerfile \
  --build-arg BASE_IMAGE=almalinux:10        -t relay:alma-v3 .  # opt-in AlmaLinux build
```

The Dockerfile itself carries **no** `apk`/`apt`/`dnf` conditionals. The
per-distro logic lives in two bind-mounted scripts that dispatch on the package
manager present:

- `build-scripts/sasl-xoauth2-build.sh` runs in a **builder stage** on the same
  base and compiles the XOAUTH2 plugin (below). It does nothing on AlmaLinux.
- `build-scripts/postfix-install.sh` runs in the runtime stage: package install,
  plugin install, and the sasl `smtpd.conf` seeding.

```sh
if command -v rpm && command -v dnf; then do_alma   # EPEL 0.27, arch assertions
elif command -v apt-get;             then do_apt    # Ubuntu, Debian
elif command -v apk;                 then do_apk    # Alpine
fi
```

**Why one file matters:** the runtime scripts are COPYed into the image by a
single COPY list shared by every distro. Previously two Dockerfiles each carried
their own COPY list, and a runtime file (`cert-action.sh`) once shipped to only
one image because a single list was updated. One Dockerfile makes that class of
drift impossible — a new runtime file is added once and reaches every variant.

The AlmaLinux-only microarch machinery (the `alma-v2` altarch EPEL release RPM,
`EXPECT_ALMALINUX_ARCH` guard, and the RPM arch/release assertions) lives inside
`do_alma`; it is inert on every other path.

### Why Ubuntu for the universal build

**Ubuntu is compiled at the original x86-64 baseline (v1).** A v1 image runs on
*every* x86-64 CPU, including the default QEMU virtual CPU. So one `linux/amd64`
image works everywhere — **no v2/v3 split, nothing to auto-detect** — with
`linux/arm64` published alongside. Debian and Alpine share that v1 baseline, so
either could take the default; Ubuntu holds it because existing deployments run
it and 24.04 has the longest standard support of the three (to 2029).

### How the plugin is obtained

`sasl-xoauth2` (the plugin this relay is built around) is packaged by **EPEL**
for the RPM world, which is what the AlmaLinux image installs: a signed build
from a public spec file. Debian and Alpine do not package it, and Ubuntu has it
only in the maintainer's PPA. (Alpine's `cyrus-sasl-xoauth2` in `edge/testing`
is a different, unrelated plugin that takes the raw token as the password; it
does not work with this relay's token-file design.)

Every non-Alma image therefore **compiles it from source**, in a builder stage,
from a copy of the upstream source kept in this repository
([`vendor/sasl-xoauth2`](../vendor/sasl-xoauth2/README.md)):

- `vendor/sasl-xoauth2/src` is an **unmodified** upstream commit.
  `vendor/sasl-xoauth2/UPSTREAM` records its tag, version, commit id and Git
  tree hash. `tests/static.sh` proves offline that the directory hashes to that
  tree (any changed byte, file or executable bit changes the hash); the CI suite
  also confirms online that upstream's commit has that tree.
- The build fetches no source over the network. It verifies the tree against
  `vendor/sasl-xoauth2/SHA256SUMS` (every file, no extras) and refuses to
  compile anything else.
- Upstream's own unit tests run (`ctest`) on the target architecture before
  anything ships.
- Only the plugin `.so` leaves the builder. The compiler and headers never
  reach the runtime image; `tests/container-sasl-plugin.sh` checks that, and
  that libsasl2 actually loads XOAUTH2.
- The builder records what it built in
  `/usr/share/postfix-m365-relay/sasl-xoauth2.source` (version, commit, tree,
  repo, plugin directory). The test above and the release jobs assert it; you
  can read it in any image.
- The plugin's runtime libraries (libcurl, jsoncpp, ...) are resolved from the
  compiled `.so` itself, so the runtime stage installs them by their real
  package names on each release.

To move to a newer upstream release, run
`vendor/sasl-xoauth2/update.sh release-X.Y`, read the diff, and run
`tests/run-matrix.sh`. The earlier vendored-`.deb`
and PPA modes were removed: a checksum on a prebuilt `.deb` proves only that the
file did not change, not what was compiled into it.

### Why the plugin *version* barely matters

This relay **disables sasl-xoauth2's token fetching** (its config points the
token endpoint at a dead `127.0.0.1:9`), and mints tokens itself in
`refresh-smtp-token.py`. sasl-xoauth2 only **presents** a pre-minted token as the
XOAUTH2 SASL mechanism. Reviewing the upstream `debian/changelog` across
0.20→0.27, every change is logging/tooling/packaging plus a configurable
`refresh_window` — **none** alter the token-store format or the presenter, and
the refresh path we don't use. So any version from ~0.20 up behaves identically
here. AlmaLinux ships EPEL's 0.27; every other image compiles 0.28 (the
`release-0.28` commit). The only plugin-code change between them is a fix in
`src/http.cc` for a curl handle used after cleanup, in the token refresh path
this relay disables. 0.28's other changes (Microsoft national-cloud endpoints,
a simpler Google flow) are in `sasl-xoauth2-tool` and the docs, which this
image does not ship. Upstream's record of each release is the `ChangeLog` file
at the top of https://github.com/tarickb/sasl-xoauth2.

## What keeps the shared codebase distro-agnostic

The runtime scripts run unchanged on every base because the distro differences
are feature-detected rather than hardcoded. These are the points that
would otherwise diverge, and how each is handled:

- **Cyrus SASL config path.** The plugin lives in `/usr/lib64/sasl2` on
  AlmaLinux, the multiarch `/usr/lib/<triplet>/sasl2` on Ubuntu/Debian, and
  `/usr/lib/sasl2` on Alpine. The install script writes `smtpd.conf` to
  `/etc/sasl2/smtpd.conf` on Alma and Alpine and to
  `/etc/postfix/sasl/smtpd.conf` on Ubuntu/Debian. `render-config.sh` finds it
  and sets `cyrus_sasl_config_path` explicitly: Debian 13's libsasl2 no longer
  looks in `/etc/postfix/sasl` by itself, so without it inbound AUTH fails with
  "unable to open Berkeley db /etc/sasldb2".
- **Alpine userland.** Alpine ships busybox, not bash; the image adds `bash`
  (the entrypoint and supervisor need it), GNU `grep` (the supervisor's log
  pipeline uses `--line-buffered`), and `netcat-openbsd` so the healthcheck's
  `nc` behaves as on the other images. `debian:trixie-slim` likewise lacks
  `procps` (`kill`, `pgrep`), which the apt install adds. Alpine's Postfix has no
  Berkeley DB, which does not matter here: the relay uses only `texthash:` and
  `regexp:` maps.
- **Package-manager checks.** `verify-relay.sh` feature-detects `rpm` →
  `dpkg-query` (CA-bundle age uses the ca-certificates changelog mtime on
  Debian). The `rpm` path is unchanged on AlmaLinux.
- **Cryptography API gap.** Ubuntu 24.04 ships `python3-cryptography` 41.x, which
  lacks the tz-aware `not_valid_*_utc` accessors (added in 42, present on EPEL).
  `rotate-smtp-relay-cert.py` and `entrypoint.sh` try the new API and fall back —
  no behavior change on AlmaLinux.
- **CA bundle path.** The RHEL CA path (`/etc/pki/tls/certs/ca-bundle.crt`) is
  detected per-distro in `entrypoint.sh` (falls back to
  `/etc/ssl/certs/ca-certificates.crt`); the `container-config-matrix.sh`
  assertion detects it the same way.

Every variant passes **all offline suites** (`tests/run-offline.sh`, 19 suites)
including display-name/sender-rewriting and end-to-end XOAUTH2 delivery.
`tests/run-matrix.sh` builds and tests every base from the one Dockerfile as the
local pre-push gate.

## amd64 is validated in CI, not locally

On an arm64 host the offline suite is **not reliably runnable under QEMU** for the
amd64 variants: the Rust-backed `cryptography` extension **segfaults
intermittently under emulation** (concurrency-dependent — clean in isolation,
crashes during busy container boot), and RSA keygen is slow enough under
emulation to trip readiness waits. These are **emulation artifacts, not image
defects**, so `run-matrix.sh` tests only the host-native variants by default
(`ALL=1` additionally *builds* the emulated amd64 variants for confirmation).

Real amd64 validation runs on a **native amd64 runner**: `.github/workflows/
test.yml` builds every base (`ubuntu:24.04`, `debian:trixie-slim`,
`alpine:3.22`, `almalinux:10`) from the unified
Dockerfile on `ubuntu-latest` and runs the full offline suite against each on
every PR and push. The `alma-v2` microarch build and the arm64 sub-manifests are
additionally asserted in `.github/workflows/publish-image.yml` on release.

### One known-flaky timing test — see the source comment

`container-policy.sh`'s smtpd-recovery window is a `TODO(revisit)`: recovery
latency after the deliberate wedge is variable (~3–15s) and the throttle mechanism
is not yet fully characterized. The window was widened 10 → 15 as a stopgap; the
deep dive (and adding failure-latency logging to that test) is deferred.

## Current shipped state

- **`:latest` / `:ubuntu`** — the Ubuntu v1 build (amd64 + arm64). The default;
  runs on every x86-64 CPU including bare-`qemu64` VMs, no hypervisor changes.
- **`:debian`** — Debian 13, v1 baseline (amd64 + arm64). Opt-in.
- **`:alpine`** — Alpine 3.22, the smallest image (amd64 + arm64). Opt-in.
- **`:alma-v3`** — AlmaLinux, AVX2 baseline (amd64 + arm64). Opt-in.
- **`:alma-v2`** — AlmaLinux altarch, SSE4.2 baseline (amd64 only). Opt-in.

The AlmaLinux images are **kept, not retired**: they serve users who want the
longer AlmaLinux support horizon (to 2035) or the EPEL packaging. Because all
bases now build from one Dockerfile and are gated together in CI, maintaining all
three tags costs a base-image arg and a build job each — not a second source of
truth. Retire an `alma-*` tag only if no one depends on that base; the universal
Ubuntu image already covers the CPU-compatibility need for everyone else.
