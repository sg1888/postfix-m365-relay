#!/usr/bin/env bash
# Maintain the vendored sasl-xoauth2 source (vendor/sasl-xoauth2/src).
#
# Purpose:   src/ is an unmodified copy of one upstream commit; the image's
#            builder stage compiles the XOAUTH2 plugin from it with no network
#            fetch. This script is the only thing that writes src/ and UPSTREAM,
#            and the proof that the two agree.
# Called by: tests/vendor-sasl-xoauth2.sh (--check), the CI suite (--verify),
#            and a maintainer moving to a new upstream release (TAG).
# Created:   2026-10-13
# Usage:     vendor/sasl-xoauth2/update.sh --check
#              Offline. src/ hashes to UPSTREAM's tree, src/ChangeLog's first
#              entry is UPSTREAM's version, and SHA256SUMS (what the image
#              build verifies) lists exactly src/'s files.
#            vendor/sasl-xoauth2/update.sh --verify
#              Online. Additionally fetch UPSTREAM's commit from upstream and
#              confirm that commit's tree is UPSTREAM's tree.
#            vendor/sasl-xoauth2/update.sh TAG      e.g. release-0.29
#              Replace src/ with that tag's commit and rewrite UPSTREAM. Review
#              `git diff vendor/sasl-xoauth2` before committing.
#
# The tree hash is Git's own content address for a directory: two directories
# hash equal only when every file's bytes, name and executable bit are equal.
# So `--check` proves src/ is byte-for-byte the upstream commit without trusting
# anything but this repository.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
rel="vendor/sasl-xoauth2/src"
upstream_file="$here/UPSTREAM"

field() { sed -n "s/^$1=//p" "$upstream_file"; }

# Git tree id of the working-tree directory $rel, using a throwaway index so the
# repository's real index is untouched. -f: hash exactly what is on disk, even a
# file an ignore rule would hide; a fresh clone then fails the check instead of
# silently matching.
working_tree_id() {
  local index
  index="$(mktemp)"
  rm -f "$index"
  (
    cd "$repo_root"
    GIT_INDEX_FILE="$index" git add -f -- "$rel"
    GIT_INDEX_FILE="$index" git write-tree --prefix="$rel/"
  )
  rm -f "$index"
}

# sha256sum (Linux) or shasum -a 256 (macOS); same output format.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# The checksum manifest the builder stage verifies (it has no git to compute a
# tree hash). Sorted, paths relative to src/.
write_manifest() {
  ( cd "$here/src" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do sha256 "$f"; done ) \
    > "$here/SHA256SUMS"
}

changelog_version() {
  head -n1 "$here/src/ChangeLog" | sed -e 's/.*(//' -e 's/).*//'
}

check() {
  local want got version
  want="$(field tree)"
  version="$(field version)"
  [[ -d $here/src ]] || { echo "missing $rel" >&2; return 1; }
  if ! git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "not a git checkout; cannot hash $rel" >&2
    return 1
  fi
  got="$(working_tree_id)"
  if [[ $got != "$want" ]]; then
    echo "$rel tree is $got, UPSTREAM says $want: the vendored source was modified" >&2
    echo "  (restore it with: vendor/sasl-xoauth2/update.sh $(field tag))" >&2
    return 1
  fi
  [[ $(changelog_version) == "$version" ]] || {
    echo "$rel/ChangeLog says $(changelog_version), UPSTREAM says $version" >&2
    return 1
  }
  [[ -s $here/src/COPYING ]] || { echo "$rel/COPYING (license) is missing" >&2; return 1; }
  # The manifest must describe exactly this tree, or the image build refuses it.
  local manifest
  manifest="$(cat "$here/SHA256SUMS")"
  write_manifest
  if [[ $(cat "$here/SHA256SUMS") != "$manifest" ]]; then
    printf '%s\n' "$manifest" > "$here/SHA256SUMS"
    echo "vendor/sasl-xoauth2/SHA256SUMS does not match $rel (rerun update.sh)" >&2
    return 1
  fi
  echo "ok vendored sasl-xoauth2 $version is upstream tree $want"
}

# Fetch one commit into a scratch repository. Prints the scratch path.
fetch_commit() {
  local scratch
  scratch="$(mktemp -d)"
  git init -q "$scratch"
  git -C "$scratch" fetch -q --depth 1 "$(field repo)" "$1"
  echo "$scratch"
}

verify() {
  check
  local scratch tree
  scratch="$(fetch_commit "$(field commit)")"
  tree="$(git -C "$scratch" rev-parse 'FETCH_HEAD^{tree}')"
  [[ $(git -C "$scratch" rev-parse FETCH_HEAD) == "$(field commit)" ]]
  rm -rf "$scratch"
  if [[ $tree != "$(field tree)" ]]; then
    echo "upstream commit $(field commit) has tree $tree, UPSTREAM says $(field tree)" >&2
    return 1
  fi
  echo "ok upstream commit $(field commit) has the same tree"
}

update() {
  local tag=$1 scratch commit tree version repo
  repo="$(field repo)"
  scratch="$(fetch_commit "refs/tags/$tag")"
  commit="$(git -C "$scratch" rev-parse 'FETCH_HEAD^{commit}')"
  tree="$(git -C "$scratch" rev-parse 'FETCH_HEAD^{tree}')"
  rm -rf "$here/src"
  mkdir -p "$here/src"
  git -C "$scratch" --work-tree="$here/src" checkout -q "$commit" -- .
  rm -rf "$scratch"
  version="$(changelog_version)"
  write_manifest
  cat > "$upstream_file" <<EOF
# Provenance of src/: an unmodified copy of one upstream commit.
# Written by update.sh; checked offline by tests/vendor-sasl-xoauth2.sh and
# online by \`update.sh --verify\`. \`tree\` is Git's content hash of that
# commit's file tree; src/ must hash to exactly this value.
repo=$repo
tag=$tag
version=$version
commit=$commit
tree=$tree
license=Apache-2.0 (src/COPYING)
EOF
  check
  cat <<EOF

Next steps:
  - read the upstream changes: git diff -- vendor/sasl-xoauth2/src
  - run tests/run-matrix.sh (tests/container-sasl-plugin.sh checks each image
    was compiled from this commit)
EOF
}

case "${1:-}" in
  --check) check ;;
  --verify) verify ;;
  -*|'') sed -n '2,25p' "$0" >&2; exit 2 ;;
  *) update "$1" ;;
esac
