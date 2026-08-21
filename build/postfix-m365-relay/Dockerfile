# syntax=docker/dockerfile:1.6
# Postfix with XOAUTH2, for relaying to Microsoft 365 on an app-only OAuth token.
#
# Why this exists at all: Microsoft is retiring basic authentication for SMTP
# AUTH at the end of 2026, and Graph does not provide the SMTP envelope/header
# behavior this relay needs. SMTP AUTH with an OAuth token preserves configured
# application display names; regression tests cover that behavior.
#
# ONE Dockerfile, two base distros, chosen by BASE_IMAGE:
#   - almalinux:10          x86-64-v3 baseline (needs AVX2); EPEL ships
#                           sasl-xoauth2 0.27, and AlmaLinux 10 is supported to
#                           2035. An x86-64-v2 rebuild is published from
#                           almalinux/10-base (SSE4.2), guarded by
#                           EXPECT_ALMALINUX_ARCH.
#   - ubuntu:24.04          x86-64 v1 baseline, so one amd64 image runs on every
#                           x86-64 CPU (including default-CPU VMs). sasl-xoauth2
#                           is not in Debian stable; obtained via the checksum-
#                           pinned vendored .deb by default (see SXO_SOURCE).
# The per-distro package install, sasl-xoauth2 sourcing, and sasl config seeding
# live in build-scripts/postfix-install.sh, dispatched by the package manager
# present. Runtime scripts are already distro-aware.
#
# Image update policy:
#   - the base tag is pinned; --pull refreshes patches inside it
#   - distro packages float, because that is where security fixes arrive
#   - the built image is digest-pinned afterwards by your own image-pinning step
# A rebuild without --pull reuses the cached base layer and ships last month's
# libraries while looking like it did something.
ARG BASE_IMAGE=almalinux:10
FROM ${BASE_IMAGE}

# almalinux (v2 build) arch guard; empty for the normal v3 and Ubuntu builds.
ARG EXPECT_ALMALINUX_ARCH=
# Ubuntu sasl-xoauth2 sourcing: vendored (default) | ppa | source. Ignored on Alma.
ARG SXO_SOURCE=vendored
# Upstream release tag used by SXO_SOURCE=source. Matches the vendored version.
ARG SXO_SOURCE_REF=release-0.27
# buildx populates TARGETARCH automatically (amd64 | arm64).
ARG TARGETARCH

# Install packages, source the sasl-xoauth2 plugin, and seed sasl/postfix config.
# The script and the vendored .deb set are bind-mounted (not COPYed) so they
# never land in an image layer.
RUN --mount=type=bind,source=build/postfix-m365-relay/build-scripts,target=/build-scripts \
    --mount=type=bind,source=vendor/sasl-xoauth2,target=/vendor-sasl-xoauth2 \
    EXPECT_ALMALINUX_ARCH="$EXPECT_ALMALINUX_ARCH" \
    SXO_SOURCE="$SXO_SOURCE" SXO_SOURCE_REF="$SXO_SOURCE_REF" \
    TARGETARCH="$TARGETARCH" \
    sh /build-scripts/postfix-install.sh

# One COPY list for both distros: any new runtime file is added here once and
# ships in every variant. (A duplicated per-distro COPY list is exactly how a
# runtime script once went missing from one image only.)
COPY build/postfix-m365-relay/entrypoint.sh build/postfix-m365-relay/relay-supervisor.sh \
     build/postfix-m365-relay/relay-users build/postfix-m365-relay/relay-admin \
     build/postfix-m365-relay/export-cert /usr/local/bin/
COPY build/postfix-m365-relay/render-config.sh build/postfix-m365-relay/verify-relay.sh \
     build/postfix-m365-relay/rotate-inbound-tls.sh build/postfix-m365-relay/alert.sh \
     build/postfix-m365-relay/cert-action.sh \
     scripts/alert-event.py \
     scripts/refresh-smtp-token.py \
     scripts/rotate-smtp-relay-cert.py /usr/local/libexec/mail-relay/
# Pure shell helpers sourced by render-config.sh / cert-action.sh. Kept in a lib/
# subdir beside them (same relative path in repo and image) and unit-tested by
# tests/unit/text.bats.
COPY build/postfix-m365-relay/lib/text.sh /usr/local/libexec/mail-relay/lib/text.sh
COPY mail-relay.conf.example /usr/share/postfix-m365-relay/mail-relay.conf.example
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/relay-supervisor.sh \
      /usr/local/bin/relay-users /usr/local/bin/relay-admin /usr/local/bin/export-cert \
      /usr/local/libexec/mail-relay/*

# Documentation only; the relay is reachable on the mail network and publishes
# no host port. 2525 rather than 587 so the container needs no
# CAP_NET_BIND_SERVICE.
EXPOSE 2525

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
