#!/usr/bin/env bash
# Write the GitHub release page text for a release tagged by hand.
#
# Purpose:   The maintainer's own notes (the signed tag's message body), then
#            the commits since the previous
#            stable release with a comparison link, then the digest to pin and
#            the published tags. Markdown on stdout.
# Called by: .github/workflows/publish-image.yml (job release-notes) for a
#            release whose tag was pushed by hand. Automatic refreshes write
#            their own text (the pending updates that triggered them).
# When:      Once per release, after every image was published.
# Created:   2026-10-13
# Usage:     .github/scripts/release-notes.sh VERSION IMAGE DIGEST
#              VERSION  the tag, e.g. v1.2.3 (must exist in this clone)
#              IMAGE    e.g. docker.io/sg1888/postfix-m365-relay
#              DIGEST   the published manifest digest, sha256:...
#            Needs a clone with tags and history (actions/checkout
#            fetch-depth: 0). GITHUB_SERVER_URL and GITHUB_REPOSITORY, set in
#            GitHub Actions, give the comparison link.
set -euo pipefail

version=${1:?usage: release-notes.sh VERSION IMAGE DIGEST}
image=${2:?usage: release-notes.sh VERSION IMAGE DIGEST}
digest=${3:?usage: release-notes.sh VERSION IMAGE DIGEST}
git rev-parse -q --verify "refs/tags/$version" >/dev/null || { echo "release-notes: no tag $version" >&2; exit 1; }

# The previous stable release: the next lower X.Y.Z tag.
prev=$(git tag --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | grep -v -- - \
  | awk -v v="$version" 'found {print; exit} $0 == v {found = 1}')
# A prerelease tag (v1.3.0-rc1) is not in that list; use the stable tag below it.
[[ -n $prev || $version != *-* ]] || prev=$(git describe --tags --abbrev=0 --exclude '*-*' "$version^" 2>/dev/null || true)

notes=$(git for-each-ref "refs/tags/$version" --format='%(contents:body)' | sed -e :a -e '/^[[:space:]]*$/{$d;N;ba' -e '}')
if [[ -n ${notes//[[:space:]]/} ]]; then
  printf '%s\n\n' "$notes"
fi

echo "## Changes"
echo
if [[ -n $prev ]]; then
  changes=$(git log --no-merges --format='- %s (%h)' "$prev..$version^{commit}")
  if [[ -n $changes ]]; then
    printf '%s\n' "$changes"
  else
    echo "- No code changes since $prev; rebuilt with current distro packages."
  fi
  if [[ -n ${GITHUB_SERVER_URL:-} && -n ${GITHUB_REPOSITORY:-} ]]; then
    echo
    echo "Full comparison: $GITHUB_SERVER_URL/$GITHUB_REPOSITORY/compare/$prev...$version"
  fi
else
  echo "- First release."
fi
echo
echo "Pin: \`MAIL_IMAGE=$image@$digest\`"
echo
echo "Tags: \`${version#v}\`, \`${version#v}-alma-v3\`, \`${version#v}-alma-v2\` (Docker Hub and GHCR)."
