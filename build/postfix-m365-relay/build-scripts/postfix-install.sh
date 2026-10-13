#!/bin/sh
# Build-time package install + SASL/XOAUTH2 plugin install + config seeding for
# the relay image. One script, every base distro: the unified Dockerfile
# bind-mounts it and the distro branch is chosen at build time from the package
# manager present (dnf: AlmaLinux, apt-get: Ubuntu/Debian, apk: Alpine). Runtime
# scripts are already distro-aware (verify-relay.sh, entrypoint) and are NOT
# touched here.
#
# Inputs (build args, exported into the RUN environment by the Dockerfile):
#   EXPECT_ALMALINUX_ARCH  assert almalinux-release arch (v2 build guard); may be empty
#
# Bind mounts provided by the Dockerfile RUN:
#   /build-scripts          this script
#   /sasl-xoauth2-out       output of the sasl-xoauth2 builder stage
#                           (build-scripts/sasl-xoauth2-build.sh); empty on AlmaLinux
#
# Writes /usr/share/postfix-m365-relay/packages-refreshed (epoch seconds of the
# package upgrade), read at runtime by verify-relay.sh for the ca-bundle-age check.
set -eu

# shellcheck source=build/postfix-m365-relay/build-scripts/version.sh
. /build-scripts/version.sh

# Oldest EPEL sasl-xoauth2 the AlmaLinux images accept. A FLOOR, not a pin:
# EPEL updates the package in place, and a newer release must build (and is then
# proven by the container suites) instead of breaking every Alma release and the
# daily package refresh. Raise it only to refuse a known-bad older version.
SXO_EPEL_MIN_VERSION=0.27

# EPEL release package for AlmaLinux's x86-64-v2 rebuild. The newest one in the
# repository listing is used; this known-good name is the fallback if the
# listing cannot be read. The mirror keeps superseded versions, so the fallback
# stays installable.
altarch_epel_base=https://epel.repo.almalinux.org/10z/x86_64_v2/Packages/
altarch_epel_fallback=epel-release-almalinux-altarch-10-6.el10.alma_altarch.noarch.rpm

# The XOAUTH2 config the sasl-xoauth2 plugin loads. Deliberately points token
# refresh at a dead endpoint: this container never refreshes on its own -- the
# supervisor injects real tokens at runtime. Identical on every distro.
sasl_xoauth2_conf='{"client_id":"unused-app-only-flow","client_secret":"","token_endpoint":"http://127.0.0.1:9/sasl-xoauth2-must-not-refresh","always_log_to_syslog":"no","log_to_syslog_on_failure":"yes","log_full_trace_on_failure":"no"}'

# Cyrus SASL smtpd.conf body. Same content on every distro; only the path differs
# (EL and Alpine keep it in /etc/sasl2, Debian/Ubuntu discover it under
# /etc/postfix/sasl).
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
    altarch_epel=$(curl -fsS "$altarch_epel_base" 2>/dev/null |
      grep -o 'epel-release-almalinux-altarch-[0-9][^"<>]*\.noarch\.rpm' |
      sort -uV | tail -n1) || true
    altarch_epel=${altarch_epel:-$altarch_epel_fallback}
    echo "altarch EPEL release package: $altarch_epel"
    dnf -y install --setopt=install_weak_deps=False "$altarch_epel_base$altarch_epel"
  else
    dnf -y install --setopt=install_weak_deps=False \
      https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm
  fi

  dnf -y install --setopt=install_weak_deps=False \
    postfix cyrus-sasl cyrus-sasl-plain sasl-xoauth2 ca-certificates \
    python3 python3-cryptography openssl curl nmap-ncat iproute tzdata
  dnf clean all
  rm -rf /var/cache/dnf

  sxo_version=$(rpm -q --qf '%{VERSION}' sasl-xoauth2)
  echo "EPEL sasl-xoauth2 $sxo_version (floor $SXO_EPEL_MIN_VERSION)"
  version_at_least "$sxo_version" "$SXO_EPEL_MIN_VERSION" || {
    echo "EPEL sasl-xoauth2 $sxo_version is older than $SXO_EPEL_MIN_VERSION" >&2
    exit 1
  }
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

# Copy the plugin compiled by the builder stage into place and prove the dynamic
# linker resolves every library it needs. Used by every base except AlmaLinux.
install_built_plugin() {
  src=/sasl-xoauth2-out
  test -s "$src/usr/share/postfix-m365-relay/sasl-xoauth2.source"
  cp -a "$src/." /
  libdir=$(sed -n 's/^libdir=//p' /usr/share/postfix-m365-relay/sasl-xoauth2.source)
  test -e "$libdir/libsasl-xoauth2.so"
  if ldd "$libdir/libsasl-xoauth2.so" | grep -q 'not found'; then
    ldd "$libdir/libsasl-xoauth2.so" >&2
    echo "sasl-xoauth2 plugin has unresolved libraries" >&2
    exit 1
  fi
  echo "sasl-xoauth2 plugin installed in: $libdir"
  cat /usr/share/postfix-m365-relay/sasl-xoauth2.source
}

# Ubuntu and Debian. libsasl2-modules provides the conventional PLAIN/LOGIN
# plugins (Cyrus SASL will not advertise a mechanism list without at least one
# present); sasl2-bin provides saslpasswd2/pluginviewer; netcat-openbsd gives the
# `nc` the healthcheck uses; iproute2 gives `ip` used by render-config.sh. The
# plugin's own runtime libraries (libcurl, jsoncpp) are named by the builder,
# because their package names change between releases.
do_apt() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  # The base image is a periodic snapshot; security fixes published since
  # (openssl, glibc, ca-certificates, ...) arrive only through this upgrade.
  apt-get -y upgrade
  # shellcheck disable=SC2046 -- one package name per line, deliberately split
  apt-get install -y --no-install-recommends \
    postfix libsasl2-2 libsasl2-modules sasl2-bin ca-certificates \
    python3 python3-cryptography openssl curl netcat-openbsd iproute2 procps tzdata \
    $(cat /sasl-xoauth2-out/usr/share/postfix-m365-relay/sasl-xoauth2.deps)
  rm -rf /var/lib/apt/lists/*

  install_built_plugin
  command -v saslpasswd2 >/dev/null
  python3 -c 'import cryptography'

  install -d -m 0755 /etc/postfix/sasl /usr/local/libexec/mail-relay \
    /usr/share/postfix-m365-relay /config
  write_smtpd_conf /etc/postfix/sasl/smtpd.conf
  # Keep the packaged Postfix defaults durable for read-only (tmpfs) boots. Taken
  # after smtpd.conf is written: on Debian/Ubuntu it lives under /etc/postfix,
  # and the entrypoint restores /etc/postfix from this snapshot on every boot.
  cp -a /etc/postfix /usr/share/postfix-defaults
  printf '%s\n' "$sasl_xoauth2_conf" > /etc/sasl-xoauth2.conf
  ln -s /run/mail-relay/log /var/log/mail-relay
}

# Alpine. bash: the entrypoint and supervisor are bash scripts and Alpine ships
# only busybox sh. cyrus-sasl provides saslpasswd2 plus the PLAIN and sasldb
# plugins; cyrus-sasl-login adds LOGIN for the inbound mech_list. netcat-openbsd
# keeps the healthcheck's `nc` identical to the Debian images rather than
# busybox's. iproute2-minimal gives the full `ip` render-config.sh parses. GNU
# grep: the supervisor's log pipeline needs --line-buffered, which busybox grep
# lacks.
do_apk() {
  apk upgrade --no-cache
  # shellcheck disable=SC2046 -- one package name per line, deliberately split
  apk add --no-cache \
    bash grep postfix cyrus-sasl cyrus-sasl-login ca-certificates \
    python3 py3-cryptography openssl curl netcat-openbsd iproute2-minimal tzdata \
    $(cat /sasl-xoauth2-out/usr/share/postfix-m365-relay/sasl-xoauth2.deps)

  install_built_plugin
  command -v saslpasswd2 >/dev/null
  python3 -c 'import cryptography'

  cp -a /etc/postfix /usr/share/postfix-defaults
  install -d -m 0755 /etc/sasl2 /usr/local/libexec/mail-relay \
    /usr/share/postfix-m365-relay /config
  write_smtpd_conf /etc/sasl2/smtpd.conf
  printf '%s\n' "$sasl_xoauth2_conf" > /etc/sasl-xoauth2.conf
  ln -s /run/mail-relay/log /var/log/mail-relay
}

if command -v rpm >/dev/null 2>&1 && command -v dnf >/dev/null 2>&1; then
  do_alma
elif command -v apt-get >/dev/null 2>&1; then
  do_apt
elif command -v apk >/dev/null 2>&1; then
  do_apk
else
  echo "unsupported base image: need dnf (AlmaLinux/EL), apt-get (Debian/Ubuntu) or apk (Alpine)" >&2
  exit 1
fi

# Remove what a mail relay never uses, in this same layer so the bytes never
# reach the image. Each removal is chosen to be functionally inert; the
# container suites (container-sasl-plugin.sh, container-image-size.sh and the
# delivery tests) prove it on every distro.
slim_image() {
  # Documentation, man/info pages and message catalogs. License texts stay:
  # Debian keeps them as /usr/share/doc/<pkg>/copyright, EL in
  # /usr/share/licenses (untouched). /usr/share/locale/locale.alias stays for
  # glibc; compiled locales in /usr/lib/locale are not touched.
  if [ -d /usr/share/doc ]; then
    find /usr/share/doc -type f ! -name 'copyright' -delete
    find /usr/share/doc -depth -type d -empty -delete
  fi
  rm -rf /usr/share/man /usr/share/info /usr/share/lintian /usr/share/gtk-doc
  if [ -d /usr/share/locale ]; then
    find /usr/share/locale -mindepth 1 -maxdepth 1 -type d -exec rm -rf {} +
  fi

  # Python stdlib parts for interactive or development use only: the pip
  # bootstrapper, IDLE, Tk, turtle demos, 2to3, pydoc's topic data and the
  # interpreter's own test suites.
  for py in /usr/lib/python3.* /usr/lib64/python3.*; do
    [ -d "$py" ] || continue
    rm -rf "$py/ensurepip" "$py/idlelib" "$py/tkinter" "$py/turtledemo" \
      "$py/turtle.py" "$py/lib2to3" "$py/pydoc_data" "$py/test" \
      "$py/unittest/test"
  done

  # SASL mechanisms the relay never offers or uses. Inbound AUTH is PLAIN and
  # LOGIN (sasldb), outbound is XOAUTH2; everything else is attack surface.
  for dir in /usr/lib/sasl2 /usr/lib64/sasl2 /usr/lib/*/sasl2; do
    [ -d "$dir" ] || continue
    for mech in anonymous crammd5 digestmd5 gs2 gssapiv2 ntlm otp scram srp; do
      rm -f "$dir/lib$mech.so" "$dir/lib$mech.so."*
    done
  done

  # AlmaLinux's base image carries binutils (a linker toolchain, ~32 MB) that
  # nothing installed here needs. Removed only when rpm confirms no package
  # depends on it, so a future dependency skips this instead of failing the
  # build.
  if command -v rpm >/dev/null 2>&1; then
    tools=$(rpm -q binutils-gold binutils 2>/dev/null | grep -v 'is not installed' | sed 's/-[0-9].*//' | tr '\n' ' ' || true)
    tools=${tools% }
    if [ -n "$tools" ]; then
      # shellcheck disable=SC2086 -- package names, deliberately split
      if rpm -e --test $tools >/dev/null 2>&1; then
        rpm -e $tools
        echo "removed unused base packages: $tools"
      else
        echo "kept $tools: an installed package depends on it"
      fi
    fi
  fi
}
slim_image

# Package-refresh stamp: the moment this layer upgraded the distro packages,
# including the CA bundle. verify-relay.sh alerts (event ca-bundle-age) when it
# is older than MAIL_CA_BUNDLE_MAX_AGE_DAYS. A package's own date cannot serve:
# a distro may correctly ship the same ca-certificates for months, so its age
# says nothing about whether this image missed updates. Written in the same
# layer as the upgrade, a cached (stale) layer keeps its old, honest stamp.
date -u +%s > /usr/share/postfix-m365-relay/packages-refreshed
