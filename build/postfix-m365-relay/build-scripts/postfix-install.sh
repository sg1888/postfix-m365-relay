#!/bin/sh
# Build-time package install + SASL/XOAUTH2 sourcing + config seeding for the
# relay image. One script, both base distros: the unified Dockerfile bind-mounts
# it and the distro branch is chosen at build time from the package manager
# present. Runtime scripts are already distro-aware (verify-relay.sh, entrypoint)
# and are NOT touched here.
#
# Inputs (build args, exported into the RUN environment by the Dockerfile):
#   EXPECT_ALMALINUX_ARCH  assert almalinux-release arch (v2 build guard); may be empty
#   SXO_SOURCE             ubuntu sasl-xoauth2 source: vendored | ppa | source
#   SXO_SOURCE_REF         upstream tag for SXO_SOURCE=source
#   TARGETARCH             buildx target arch (amd64|arm64); falls back to dpkg
#
# Bind mounts provided by the Dockerfile RUN:
#   /build-scripts          this script
#   /vendor-sasl-xoauth2    checksum-pinned .deb set (ubuntu vendored mode)
set -eu

# The XOAUTH2 config the sasl-xoauth2 plugin loads. Deliberately points token
# refresh at a dead endpoint: this container never refreshes on its own -- the
# supervisor injects real tokens at runtime. Identical on both distros.
sasl_xoauth2_conf='{"client_id":"unused-app-only-flow","client_secret":"","token_endpoint":"http://127.0.0.1:9/sasl-xoauth2-must-not-refresh","always_log_to_syslog":"no","log_to_syslog_on_failure":"yes","log_full_trace_on_failure":"no"}'

# Cyrus SASL smtpd.conf body. Same content on both distros; only the path differs
# (EL keeps it in /etc/sasl2, Debian/Ubuntu discover it under /etc/postfix/sasl).
write_smtpd_conf() {
  printf '%s\n' \
    'pwcheck_method: auxprop' \
    'auxprop_plugin: sasldb' \
    'sasldb_path: /run/mail-relay/sasldb2' \
    'mech_list: PLAIN LOGIN' \
    > "$1"
}

# EPEL provides sasl-xoauth2. cyrus-sasl-plain is needed even though we never use
# PLAIN: the SASL client library will not offer a mechanism list without at least
# one conventional plugin present.
#
# Alma's x86-64-v2 image is unusual: RPM reports the CPU as x86_64 while
# almalinux-release itself has architecture x86_64_v2. We identify the image from
# that package instead of `uname`/`%{_arch}`. The v2 rebuild of EPEL has its own
# release package, signing key, and repository; using Fedora's ordinary EPEL
# release RPM silently installs x86_64 (v3-baseline on EL10) packages. The
# conditional and the final RPM assertions turn that observed failure into a
# hard, auditable build invariant.
do_alma() {
  if [ -n "${EXPECT_ALMALINUX_ARCH:-}" ]; then
    test "$(rpm -q --qf '%{ARCH}' almalinux-release)" = "$EXPECT_ALMALINUX_ARCH"
  fi

  dnf -y upgrade

  if rpm -q --qf '%{ARCH}' almalinux-release | grep -qx x86_64_v2; then
    dnf -y install --setopt=install_weak_deps=False \
      https://epel.repo.almalinux.org/10z/x86_64_v2/Packages/epel-release-almalinux-altarch-10-6.el10.alma_altarch.noarch.rpm
  else
    dnf -y install --setopt=install_weak_deps=False \
      https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm
  fi

  dnf -y install --setopt=install_weak_deps=False \
    postfix cyrus-sasl cyrus-sasl-plain sasl-xoauth2 ca-certificates \
    python3 python3-cryptography openssl curl nmap-ncat iproute tzdata
  dnf clean all
  rm -rf /var/cache/dnf

  rpm -q sasl-xoauth2 | grep -q '^sasl-xoauth2-0\.27'
  if rpm -q --qf '%{ARCH}' almalinux-release | grep -qx x86_64_v2; then
    test "$(rpm -q --qf '%{ARCH}' sasl-xoauth2)" = x86_64_v2
    rpm -q --qf '%{RELEASE}' sasl-xoauth2 | grep -q '\.alma_altarch'
  fi
  python3 -c 'import cryptography'
  command -v saslpasswd2 >/dev/null
  test -d /usr/lib64/sasl2

  # A documented hardened deployment makes /etc/postfix tmpfs. Keep the package's
  # defaults somewhere durable so both normal and read-only boots can restore them.
  cp -a /etc/postfix /usr/share/postfix-defaults
  install -d -m 0755 /etc/sasl2 /usr/local/libexec/mail-relay \
    /usr/share/postfix-m365-relay /config
  write_smtpd_conf /etc/sasl2/smtpd.conf
  printf '%s\n' "$sasl_xoauth2_conf" > /etc/sasl-xoauth2.conf
  ln -s /run/mail-relay/log /var/log/mail-relay
}

# libsasl2-modules provides the conventional PLAIN/LOGIN plugins (Cyrus SASL will
# not advertise a mechanism list without at least one present); sasl2-bin provides
# saslpasswd2/pluginviewer; netcat-openbsd gives the `nc` the healthcheck uses;
# iproute2 gives `ip` used by render-config.sh.
do_ubuntu() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    postfix libsasl2-2 libsasl2-modules sasl2-bin ca-certificates \
    python3 python3-cryptography openssl curl netcat-openbsd iproute2 tzdata
  rm -rf /var/lib/apt/lists/*

  # sasl-xoauth2 plugin: one of three sourcing modes.
  #   vendored (default) - install the checksum-pinned .deb from vendor/. No
  #                        build-time dependency on the PPA staying online.
  #   ppa                - apt-install the current version from the maintainer PPA.
  #   source             - compile from a pinned upstream tag; no third-party binary.
  target_arch="${TARGETARCH:-$(dpkg --print-architecture)}"
  case "${SXO_SOURCE:-vendored}" in
    vendored)
      # Verify the pinned checksum before trusting the file, then install just
      # this architecture's .deb and let apt resolve its runtime dependencies.
      deb="$(ls "/vendor-sasl-xoauth2/sasl-xoauth2_"*"_${target_arch}.deb")"
      ( cd /vendor-sasl-xoauth2 && grep -F "$(basename "$deb")" SHA256SUMS | sha256sum -c - )
      apt-get update
      apt-get install -y --no-install-recommends "$deb"
      rm -rf /var/lib/apt/lists/*
      ;;
    ppa)
      apt-get update
      apt-get install -y --no-install-recommends software-properties-common
      add-apt-repository -y ppa:sasl-xoauth2/stable
      apt-get update
      apt-get install -y --no-install-recommends sasl-xoauth2
      apt-get purge -y software-properties-common
      apt-get autoremove -y
      rm -rf /var/lib/apt/lists/*
      ;;
    source)
      apt-get update
      apt-get install -y --no-install-recommends \
        git cmake g++ make pkg-config libsasl2-dev libcurl4-openssl-dev libjsoncpp-dev
      git clone --depth 1 --branch "$SXO_SOURCE_REF" \
        https://github.com/tarickb/sasl-xoauth2.git /tmp/sxo-src
      cmake -S /tmp/sxo-src -B /tmp/sxo-build \
        -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_SYSCONFDIR=/etc \
        -DCMAKE_BUILD_TYPE=Release
      cmake --build /tmp/sxo-build --target install
      rm -rf /tmp/sxo-src /tmp/sxo-build
      apt-get purge -y git cmake g++ make pkg-config libsasl2-dev \
        libcurl4-openssl-dev libjsoncpp-dev
      apt-get autoremove -y
      rm -rf /var/lib/apt/lists/*
      ;;
    *)
      echo "unknown SXO_SOURCE=${SXO_SOURCE:-} (expected vendored|ppa|source)" >&2
      exit 1
      ;;
  esac

  # Prove the plugin is present and discoverable before the build succeeds. The
  # sasl2 plugin directory is multiarch on Ubuntu (/usr/lib/<triplet>/sasl2).
  saslauthd_dir="$(dirname "$(find /usr/lib -name 'libsasl-xoauth2.so*' -print -quit)")"
  test -n "$saslauthd_dir"
  echo "sasl-xoauth2 plugin installed in: $saslauthd_dir"
  command -v saslpasswd2 >/dev/null
  python3 -c 'import cryptography'

  # Keep the packaged Postfix defaults durable for read-only (tmpfs) boots.
  cp -a /etc/postfix /usr/share/postfix-defaults
  install -d -m 0755 /etc/postfix/sasl /usr/local/libexec/mail-relay \
    /usr/share/postfix-m365-relay /config
  write_smtpd_conf /etc/postfix/sasl/smtpd.conf
  printf '%s\n' "$sasl_xoauth2_conf" > /etc/sasl-xoauth2.conf
  ln -s /run/mail-relay/log /var/log/mail-relay
}

if command -v rpm >/dev/null 2>&1 && command -v dnf >/dev/null 2>&1; then
  do_alma
elif command -v apt-get >/dev/null 2>&1; then
  do_ubuntu
else
  echo "unsupported base image: neither dnf (AlmaLinux/EL) nor apt-get (Debian/Ubuntu) found" >&2
  exit 1
fi
