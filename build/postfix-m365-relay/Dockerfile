# Postfix with XOAUTH2, for relaying to Microsoft 365 on an app-only OAuth token.
#
# Why this exists at all: Microsoft is retiring basic authentication for SMTP
# AUTH at the end of 2026, and Graph does not provide the SMTP envelope/header
# behavior this relay needs. SMTP AUTH with an OAuth token preserves configured
# application display names; regression tests cover that behavior.
#
# AlmaLinux rather than Fedora or Alpine, decided by where the plugin is
# packaged and how long the base is supported:
#   - Alpine has no sasl-xoauth2 at all (checked: edge, 3.22, 3.21), so it would
#     mean compiling from a pinned commit, which is the standing maintenance
#     obligation this project rejected the pass-through plugin over.
#   - EPEL 9 froze at sasl-xoauth2 0.24 while upstream is 0.27.
#   - EPEL 10 ships 0.27, and AlmaLinux 10 is supported to 2035.
# The normal amd64 build uses x86-64-v3. CI also publishes an explicit
# linux/amd64/v2 variant from AlmaLinux's official 10-base manifest.
#
# Image update policy:
#   - the base tag is pinned; --pull refreshes patches inside it
#   - distro packages float, because that is where security fixes arrive
#   - the built image is digest-pinned afterwards by your own image-pinning step
# A rebuild without --pull reuses the cached base layer and ships last month's
# libraries while looking like it did something.
ARG BASE_IMAGE=almalinux:10
FROM ${BASE_IMAGE}
ARG EXPECT_ALMALINUX_ARCH=

# EPEL provides sasl-xoauth2. cyrus-sasl-plain is needed even though we never
# use PLAIN: the SASL client library will not offer a mechanism list without at
# least one conventional plugin present.
#
# Alma's x86-64-v2 image is slightly unusual: RPM reports the CPU as x86_64,
# while `almalinux-release` itself has architecture x86_64_v2.  Therefore we
# identify the image from that package instead of `uname` or `%{_arch}`.  The
# v2 rebuild of EPEL has its own release package, signing key, and repository;
# using Fedora's ordinary EPEL release RPM silently installs x86_64 (v3-baseline
# on EL10) packages.  We did exactly that in the first v2 build attempt and the
# build succeeded far enough to hide the compatibility error.  The conditional
# and the final RPM assertions below turn that observed failure into a hard,
# auditable build invariant.
RUN if [ -n "$EXPECT_ALMALINUX_ARCH" ]; then \
      test "$(rpm -q --qf '%{ARCH}' almalinux-release)" = "$EXPECT_ALMALINUX_ARCH"; \
    fi \
 && dnf -y upgrade \
 && if rpm -q --qf '%{ARCH}' almalinux-release | grep -qx x86_64_v2; then \
      dnf -y install --setopt=install_weak_deps=False \
        https://epel.repo.almalinux.org/10z/x86_64_v2/Packages/epel-release-almalinux-altarch-10-6.el10.alma_altarch.noarch.rpm; \
    else \
      dnf -y install --setopt=install_weak_deps=False \
        https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm; \
    fi \
 && dnf -y install --setopt=install_weak_deps=False \
      postfix cyrus-sasl cyrus-sasl-plain sasl-xoauth2 ca-certificates \
      python3 python3-cryptography openssl curl nmap-ncat iproute tzdata \
 && dnf clean all \
 && rm -rf /var/cache/dnf \
 && rpm -q sasl-xoauth2 | grep -q '^sasl-xoauth2-0\.27' \
 && if rpm -q --qf '%{ARCH}' almalinux-release | grep -qx x86_64_v2; then \
      test "$(rpm -q --qf '%{ARCH}' sasl-xoauth2)" = x86_64_v2 \
      && rpm -q --qf '%{RELEASE}' sasl-xoauth2 | grep -q '\.alma_altarch'; \
    fi \
 && python3 -c 'import cryptography' \
 && command -v saslpasswd2 >/dev/null \
 && test -d /usr/lib64/sasl2

# A documented hardened deployment makes /etc/postfix tmpfs. Keep the package's
# defaults somewhere durable so both normal and read-only boots can restore them.
RUN cp -a /etc/postfix /usr/share/postfix-defaults \
 && install -d -m 0755 /etc/sasl2 /usr/local/libexec/mail-relay \
      /usr/share/postfix-m365-relay /config \
 && printf '%s\n' \
      'pwcheck_method: auxprop' \
      'auxprop_plugin: sasldb' \
      'sasldb_path: /run/mail-relay/sasldb2' \
      'mech_list: PLAIN LOGIN' \
      > /etc/sasl2/smtpd.conf \
 && printf '%s\n' \
      '{"client_id":"unused-app-only-flow","client_secret":"","token_endpoint":"http://127.0.0.1:9/sasl-xoauth2-must-not-refresh","always_log_to_syslog":"no","log_to_syslog_on_failure":"yes","log_full_trace_on_failure":"no"}' \
      > /etc/sasl-xoauth2.conf \
 && ln -s /run/mail-relay/log /var/log/mail-relay

COPY build/postfix-m365-relay/entrypoint.sh build/postfix-m365-relay/relay-supervisor.sh \
     build/postfix-m365-relay/relay-users build/postfix-m365-relay/relay-admin /usr/local/bin/
COPY build/postfix-m365-relay/render-config.sh build/postfix-m365-relay/verify-relay.sh \
     build/postfix-m365-relay/rotate-inbound-tls.sh build/postfix-m365-relay/alert.sh \
     scripts/alert-event.py \
     scripts/refresh-smtp-token.py \
     scripts/rotate-smtp-relay-cert.py /usr/local/libexec/mail-relay/
COPY mail-relay.conf.example /usr/share/postfix-m365-relay/mail-relay.conf.example
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/relay-supervisor.sh \
      /usr/local/bin/relay-users /usr/local/bin/relay-admin /usr/local/libexec/mail-relay/*

# Documentation only; the relay is reachable on the mail network and publishes
# no host port. 2525 rather than 587 so the container needs no
# CAP_NET_BIND_SERVICE.
EXPOSE 2525

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
