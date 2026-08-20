#!/usr/bin/env bash
# Cut a new release. Pushes main, then a signed SemVer tag. The tag push is
# what triggers .github/workflows/publish-image.yml to build and publish the
# image to Docker Hub and GHCR; a plain push to main publishes nothing.
#
# Usage:
#   scripts/release.sh [patch|minor|major]   # bump last tag (default: patch)
#   scripts/release.sh 1.2.3                  # release an explicit version
#
# The next version is computed from the newest v* tag in git, so there is
# nothing to hand-edit. Requires a GPG signing key (tags are signed, matching
# docs/RELEASING.md); set SIGN=0 to fall back to an annotated tag.
set -euo pipefail

arg="${1:-patch}"
sign_flag="-s"
[ "${SIGN:-1}" = "0" ] && sign_flag="-a"

die() { echo "release: $*" >&2; exit 1; }

# --- resolve the next version ------------------------------------------------
last="$(git tag --list 'v*' --sort=-v:refname | head -n1)"
last="${last:-v0.0.0}"

if [[ "$arg" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  next="v${arg#v}"
elif [[ "$arg" == patch || "$arg" == minor || "$arg" == major ]]; then
  IFS=. read -r major minor patch <<<"${last#v}"
  case "$arg" in
    major) major=$((major + 1)); minor=0; patch=0 ;;
    minor) minor=$((minor + 1)); patch=0 ;;
    patch) patch=$((patch + 1)) ;;
  esac
  next="v${major}.${minor}.${patch}"
else
  die "unknown argument '$arg' (expected patch|minor|major or X.Y.Z)"
fi

# --- safety gates ------------------------------------------------------------
git rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository"
[ "$(git symbolic-ref --short HEAD)" = "main" ] || die "not on main"
git diff --quiet && git diff --cached --quiet || die "working tree not clean; commit first"
git rev-parse -q --verify "refs/tags/$next" >/dev/null && die "tag $next already exists"

git fetch --quiet origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse '@{u}' 2>/dev/null || echo none)" ] \
  || die "local main differs from origin/main; push or pull first"

# Best-effort CI gate: if gh is available, refuse to tag a red main.
if command -v gh >/dev/null 2>&1; then
  status="$(gh run list --branch main --limit 1 --json conclusion --jq '.[0].conclusion' 2>/dev/null || true)"
  [ -z "$status" ] || [ "$status" = "success" ] || die "latest main CI is '$status', not success"
fi

# --- confirm & ship ----------------------------------------------------------
echo "release: $last -> $next"
read -r -p "Tag and push $next? [y/N] " reply
[ "$reply" = "y" ] || [ "$reply" = "Y" ] || die "aborted"

git push origin main
git tag "$sign_flag" "$next" -m "postfix-m365-relay $next"
git push origin "$next"

echo "release: pushed $next; publish workflow is now running."
echo "  watch:  gh run watch --exit-status  (or the Actions tab)"
