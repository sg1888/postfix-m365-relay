#!/bin/sh
# Compile the sasl-xoauth2 SASL plugin from the vendored upstream source, in a
# throwaway builder stage of the same base image the runtime stage uses. Only
# the plugin itself and a provenance record leave this stage, through /out:
#
#   /out/<libdir>/sasl2/libsasl-xoauth2.so*                the plugin
#   /out/usr/share/postfix-m365-relay/sasl-xoauth2.source   version, commit, tree, repo
#   /out/usr/share/postfix-m365-relay/sasl-xoauth2.deps     runtime packages it links
#
# Why from source: a prebuilt .deb proves only that a file did not change since
# it was vendored, not what was compiled into it. The source compiled here is in
# the repository (vendor/sasl-xoauth2/src), recorded against its upstream commit
# in vendor/sasl-xoauth2/UPSTREAM. Debian and Alpine do not package this plugin.
#
# AlmaLinux keeps EPEL's sasl-xoauth2 (a signed distro build from a public spec),
# so on dnf this stage builds nothing and leaves /out empty.
#
# Bind mount provided by the Dockerfile RUN:
#   /sasl-xoauth2-vendor   vendor/sasl-xoauth2 (UPSTREAM, SHA256SUMS, src/)
set -eu

vendor=/sasl-xoauth2-vendor
out=/out
mkdir -p "$out"

if command -v dnf >/dev/null 2>&1; then
  echo "sasl-xoauth2: EL base, plugin comes from EPEL; nothing to build"
  exit 0
fi

field() { sed -n "s/^$1=//p" "$vendor/UPSTREAM"; }
version=$(field version)
commit=$(field commit)
tree=$(field tree)
repo=$(field repo)

# Refuse to compile anything but the recorded upstream files: every file's
# checksum matches, and there is no file the manifest does not list. (The Git
# tree hash in UPSTREAM is checked by tests/static.sh; this image has no git.)
( cd "$vendor/src" && sha256sum -c ../SHA256SUMS >/dev/null ) || {
  echo "vendored sasl-xoauth2 source does not match vendor/sasl-xoauth2/SHA256SUMS" >&2
  exit 1
}
listed=$(sed 's/^[0-9a-f]*  //' "$vendor/SHA256SUMS" | sort)
present=$(cd "$vendor/src" && find . -type f | sed 's|^\./||' | sort)
[ "$listed" = "$present" ] || {
  echo "vendored sasl-xoauth2 source has files SHA256SUMS does not list (or lacks listed ones)" >&2
  exit 1
}

# Work on a scratch copy; the vendored tree is a read-only bind mount and is
# never edited.
src=/tmp/sasl-xoauth2
cp -a "$vendor/src" "$src"
# Upstream derives its version from the first ChangeLog line, "... (0.28) ...".
src_version=$(head -n1 "$src/ChangeLog" | sed -e 's/.*(//' -e 's/).*//')
[ "$src_version" = "$version" ] || {
  echo "vendored source is sasl-xoauth2 '$src_version', UPSTREAM says $version" >&2
  exit 1
}

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    g++ make cmake pkg-config libsasl2-dev libcurl4-openssl-dev libjsoncpp-dev
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache build-base cmake pkgconf cyrus-sasl-dev curl-dev jsoncpp-dev
else
  echo "unsupported builder base: need apt-get or apk" >&2
  exit 1
fi

# The docs subdirectory needs pandoc only to render man pages; nothing here
# ships them.
sed -i '/add_subdirectory(docs)/d' "$src/CMakeLists.txt"

cmake -S "$src" -B /tmp/sxo-build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DCMAKE_INSTALL_SYSCONFDIR=/etc \
  -DEnableTests=ON
cmake --build /tmp/sxo-build -j "$(nproc)"
# Upstream's own unit tests, on the target architecture, before anything ships.
( cd /tmp/sxo-build && ctest --output-on-failure )
DESTDIR=/tmp/sxo-stage cmake --install /tmp/sxo-build --strip

# Keep only the plugin, at the path this distro's libsasl2 searches.
plugin=$(find /tmp/sxo-stage -name 'libsasl-xoauth2.so' -print | head -n1)
[ -n "$plugin" ] || { echo "plugin not produced" >&2; exit 1; }
plugin_dir=${plugin%/*}
rel_dir=${plugin_dir#/tmp/sxo-stage}
mkdir -p "$out$rel_dir" "$out/usr/share/postfix-m365-relay"
cp -a "$plugin_dir"/libsasl-xoauth2.so* "$out$rel_dir/"

# Runtime packages the plugin links against, so the runtime stage installs
# them by their real names on this release (libjsoncpp25 on Ubuntu 24.04,
# libjsoncpp26 on Debian 13, ...) instead of a hard-coded list.
# Only the libraries the plugin names itself (DT_NEEDED); each of those pulls in
# its own dependencies through the package manager.
deps=$out/usr/share/postfix-m365-relay/sasl-xoauth2.deps
needed_paths() {
  readelf -d "$plugin" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | while read -r soname; do
    ldd "$plugin" | awk -v s="$soname" '$1 == s && $3 ~ /^\// {print $3}'
  done
}
if command -v dpkg >/dev/null 2>&1; then
  needed_paths | while read -r lib; do
    for path in "$lib" "$(readlink -f "$lib")"; do
      pkg=$(dpkg -S "$path" 2>/dev/null | head -n1 | cut -d: -f1) && [ -n "$pkg" ] && { echo "$pkg"; break; }
    done
  done | sort -u > "$deps"
else
  needed_paths | while read -r lib; do
    apk info -q --who-owns "$(readlink -f "$lib")" 2>/dev/null | awk '{print $NF}' | head -n1
  done | sed -E 's/-[^-]+-r[0-9]+$//' | sort -u > "$deps"
fi
[ -s "$deps" ] || { echo "could not resolve the plugin's runtime packages" >&2; exit 1; }

printf 'version=%s\ncommit=%s\ntree=%s\nrepo=%s\nlibdir=%s\n' \
  "$version" "$commit" "$tree" "$repo" "$rel_dir" \
  > "$out/usr/share/postfix-m365-relay/sasl-xoauth2.source"

echo "sasl-xoauth2 $version ($commit) built into $rel_dir"
echo "runtime packages: $(tr '\n' ' ' < "$deps")"
