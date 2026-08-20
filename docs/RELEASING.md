# Releasing images

Public source lives at `sg1888/postfix-m365-relay`. Pull requests and pushes to `main` run `.github/workflows/test.yml`; version tags run `.github/workflows/publish-image.yml`.

## Registry configuration

GitHub Container Registry uses the workflow-provided `GITHUB_TOKEN`. Configure these GitHub Actions repository secrets for Docker Hub:

- `DOCKERHUB_USERNAME`: Docker Hub namespace that owns `postfix-m365-relay`
- `DOCKERHUB_TOKEN`: scoped access token with push permission and description update

Never store a registry token in an env file, workflow, Compose file, build argument, image layer, issue, or workflow log.

## Test before tagging

1. Run every offline test in `docs/TESTING.md` against your candidate image.
2. Complete applicable live qualification with dedicated test objects.
3. Confirm no permission change in the past two hours.
4. Review the complete diff and run a privacy/secret scan.
5. Verify `main` CI passed from the exact commit you're tagging.

## Publish

Create a SemVer tag only after approval:

```bash
git tag -s v1.0.0 -m 'postfix-m365-relay v1.0.0'
git push origin v1.0.0
```

Or use `scripts/release.sh`, which computes the next version from the newest
`v*` tag, gates on a clean `main` (and green CI when `gh` is installed), then
pushes the branch and a signed tag:

```bash
scripts/release.sh patch   # v1.0.0 -> v1.0.1  (fix)
scripts/release.sh minor   # v1.0.0 -> v1.1.0  (feature)
scripts/release.sh major   # v1.0.0 -> v2.0.0  (breaking)
scripts/release.sh 1.2.3   # release an explicit version
```

The release workflow publishes standard tags with `linux/amd64` (x86-64-v3 baseline) and `linux/arm64`. Separately publishes matching `-x86-64-v2` tags built from AlmaLinux's official v2 base. Both Docker Hub and GHCR receive the same tags, provenance, and SBOM metadata.

## Verify published artifacts

A green build job doesn't guarantee success. Inspect and pull what users will actually receive:

```bash
docker buildx imagetools inspect docker.io/sg1888/postfix-m365-relay:1.0.0
docker buildx imagetools inspect ghcr.io/sg1888/postfix-m365-relay:1.0.0
docker pull docker.io/sg1888/postfix-m365-relay:1.0.0
docker pull docker.io/sg1888/postfix-m365-relay:1.0.0-x86-64-v2
```

Compare manifest platforms and digests, rerun the offline suite against pulled images, confirm v2 package architecture assertions, and verify the Docker Hub description renders from `docs/DOCKERHUB.md`. Record the immutable digest for operators to pin.
