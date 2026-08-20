#!/usr/bin/env bash
# Re-download the vendored sasl-xoauth2 .deb packages and regenerate SHA256SUMS.
# Run from anywhere; it operates on its own directory. Review the checksum diff
# (git diff SHA256SUMS) before committing, and confirm the version bump is
# intentional.
#
# To change version or Ubuntu series, edit VERSION / SERIES / ARCHES below.
set -euo pipefail

VERSION="0.27-1ubuntu1"     # upstream package version (without the ~series~ppa1 tail)
SERIES="noble"              # Ubuntu series the .deb was built for (matches the base image)
ARCHES="amd64 arm64"
POOL="https://ppa.launchpadcontent.net/sasl-xoauth2/stable/ubuntu/pool/main/s/sasl-xoauth2"

cd "$(dirname "$0")"

# curl/wget may be intercepted in some environments; python3 is dependency-free.
for arch in $ARCHES; do
  file="sasl-xoauth2_${VERSION}~${SERIES}1~ppa1_${arch}.deb"
  echo "fetching $file"
  python3 - "$POOL/$file" "$file" <<'PY'
import sys, urllib.request
url, dest = sys.argv[1], sys.argv[2]
urllib.request.urlretrieve(url, dest)
PY
done

# Regenerate the integrity pin.
if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 sasl-xoauth2_*.deb > SHA256SUMS
else
  sha256sum sasl-xoauth2_*.deb > SHA256SUMS
fi

echo "done. Updated SHA256SUMS:"
cat SHA256SUMS
