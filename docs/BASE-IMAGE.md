# Base image & CPU compatibility

This document explains **why the image is built the way it is**, why a stock
virtual machine can fail to start it, and what the Ubuntu prototype changes. It
exists because these decisions are non-obvious and have bitten real deployments.

## The symptom

On some machines — most often **virtual machines** — the container dies at
startup with:

```
Fatal glibc error: CPU does not support x86-64-v3
```

Nothing else runs: no config sample is written, no listener opens. The container
crashes at process launch, before the entrypoint executes a single line.

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
   project also ships a `-x86-64-v2` tag — but there is **no v1** AlmaLinux 10,
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

That is precisely why the v2 build is published as a **separate tag**
(`-x86-64-v2`) rather than bundled into `:latest` — bundling wouldn't auto-pick
anyway. The user must choose the tag.

## Choosing an image today (AlmaLinux builds)

| Your CPU / VM | Use |
|---------------|-----|
| Has AVX2 (most Core i-series, EPYC, modern server) | default `:latest` (v3) |
| Has SSE4.2 but not AVX2 (many VMs, budget CPUs) | `:latest-x86-64-v2` |
| Below SSE4.2 (bare `qemu64` VM) | neither works — raise the VM CPU model, or use the Ubuntu prototype below |
| ARM (Raspberry Pi, ARM server) | default `:latest` (arm64 auto-selected) |

Quick check inside the machine:

```bash
grep -o -m1 avx2 /proc/cpuinfo    # empty -> no AVX2 -> not v3-capable
grep -o -m1 sse4_2 /proc/cpuinfo  # empty -> not even v2-capable
```

Raising a VM's virtual CPU (e.g. Proxmox "Type: host", libvirt
`host-passthrough`) exposes the real flags and lets the v3 image run — but
expecting every user to change hypervisor settings is a poor out-of-box story,
which is why the Ubuntu variant exists.

## The Ubuntu prototype (`Dockerfile.ubuntu`)

**Ubuntu is compiled at the original x86-64 baseline (v1).** A v1 image runs on
*every* x86-64 CPU, including the default QEMU virtual CPU. So one `linux/amd64`
image works everywhere — **no v2/v3 split, nothing to auto-detect** — with
`linux/arm64` published alongside. This dissolves the whole problem rather than
managing it with tags.

### Why Ubuntu and not Debian

`sasl-xoauth2` (the plugin this relay is built around) is **not in Debian
stable/testing** — only in Debian `experimental` at the old 0.20. It is likewise
**not in Ubuntu's main archive**. The maintainer distributes current versions
through a **Launchpad PPA** (`ppa:sasl-xoauth2/stable`) built for Ubuntu series,
and through **EPEL** for the RPM world (which is what the AlmaLinux image uses).
So Ubuntu is the distro where we can get a recent plugin **without compiling**.

### How the plugin is obtained — three explicit modes

The Dockerfile exposes `--build-arg SXO_SOURCE=` with three documented choices,
so the sourcing decision is auditable rather than hidden:

| Mode | What it does | Trade-off |
|------|--------------|-----------|
| **`vendored`** (default) | Installs the `.deb` committed in `vendor/sasl-xoauth2/`, checksum-verified | No build-time network dependency; bytes pinned. Manual refresh for updates. **Supply-chain-safe default.** |
| `ppa` | `add-apt-repository ppa:sasl-xoauth2/stable` then apt-install | Always current, but the build **fails if the PPA is offline/removed**, and trusts a single-maintainer archive at build time |
| `source` | Compiles from a pinned upstream tag (`SXO_SOURCE_REF`) | No third-party binary at all, at the cost of a build toolchain and the maintenance the project otherwise avoids |

Vendoring is the default because it removes the one thing we can't control — a
single maintainer's PPA staying online — while still not compiling anything (the
`.deb` is upstream-built). See `vendor/sasl-xoauth2/README.md`.

### Why the plugin *version* barely matters

This relay **disables sasl-xoauth2's token fetching** (its config points the
token endpoint at a dead `127.0.0.1:9`), and mints tokens itself in
`refresh-smtp-token.py`. sasl-xoauth2 only **presents** a pre-minted token as the
XOAUTH2 SASL mechanism. Reviewing the upstream `debian/changelog` across
0.20→0.27, every change is logging/tooling/packaging plus a configurable
`refresh_window` — **none** alter the token-store format or the presenter, and
the refresh path we don't use. So any version from ~0.20 up behaves identically
here; 0.27 (vendored) is just the newest, and carries a 0.24 segfault-in-logging
fix worth having.

## Porting checklist (prototype is NOT yet verified)

`Dockerfile.ubuntu` is a prototype. It must pass the offline suite in
`docs/TESTING.md` before it can be trusted, and these Ubuntu-vs-AlmaLinux deltas
need verifying first:

- [ ] **Cyrus SASL config path.** Ubuntu uses a multiarch plugin dir
      (`/usr/lib/<triplet>/sasl2`) and Debian/Ubuntu Postfix looks for the SASL
      app config differently than EL. Confirm Postfix advertises XOAUTH2 and that
      `smtpd.conf` is found (the prototype writes `/etc/postfix/sasl/smtpd.conf`).
- [ ] **rpm-based checks in the runtime scripts.** `verify-relay.sh` reads
      `rpm -q --qf '%{INSTALLTIME}' ca-certificates` for CA-bundle age. On Ubuntu
      there is no `rpm`, so this reports a false failure — port it to `dpkg-query`.
- [ ] **Any other EL-isms** in `entrypoint.sh` / `render-config.sh` (package
      manager assumptions, paths).
- [ ] **Full offline + display-name / sender-rewriting tests** — that behavior is
      the reason this relay exists, so it must pass on the Ubuntu build.

## Transition plan for AlmaLinux

Until the Ubuntu build **passes the full test suite**, AlmaLinux remains the
supported, shipped image. Do not remove it prematurely. Suggested sequence:

1. Port the checklist items above; build and run the offline suite on Ubuntu.
2. Publish the Ubuntu image under a distinct tag (e.g. `:ubuntu` /
   `:latest-ubuntu`) so existing users are undisturbed while it soaks.
3. Once proven in real deployments (including a bare-`qemu64` VM), consider making
   the Ubuntu build the **default** `:latest` — it removes the CPU-compatibility
   trap and the v2/v3 tag split entirely.
4. Only then decide whether to retire the AlmaLinux v3/v2 images. Keep them as
   long as anyone depends on the longer AlmaLinux support horizon (to 2035) or the
   EPEL packaging; retire them once the Ubuntu image covers those needs.

The end state, if the Ubuntu build proves out, is **one universal amd64 image +
arm64**, no microarch tags, and no hypervisor changes required of users.
