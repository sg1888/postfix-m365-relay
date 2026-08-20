# Releasing images

The public source repository is `sg1888/postfix-m365-relay`. Pull requests and
pushes to `main` run `.github/workflows/test.yml`; version tags run
`.github/workflows/publish-image.yml`.

## Registry configuration

GitHub Container Registry uses the workflow-provided `GITHUB_TOKEN`. Configure
these GitHub Actions repository secrets for Docker Hub:

- `DOCKERHUB_USERNAME`: Docker Hub namespace that owns `postfix-m365-relay`;
- `DOCKERHUB_TOKEN`: scoped access token permitted to push that repository and
  update its description.

Never store a registry token in an env file, workflow, Compose file, build
argument, image layer, issue, or workflow log.

## Test before tagging

1. Run every offline test in `docs/TESTING.md` against a candidate image.
2. Complete applicable live qualification with dedicated test objects.
3. Confirm no permission change occurred inside the preceding two hours.
4. Review the complete diff and privacy/secret scan.
5. Confirm `main` CI passed from the exact commit being tagged.

## Publish

Create a SemVer tag only after approval:

```bash
git tag -s v1.0.0 -m 'postfix-m365-relay v1.0.0'
git push origin v1.0.0
```

The release workflow publishes normal tags containing `linux/amd64`
(x86-64-v3 baseline) and `linux/arm64`. It separately publishes matching
`-x86-64-v2` tags from AlmaLinux's official v2 base. Both Docker Hub and GHCR
receive the same tags, provenance, and SBOM metadata.

## Verify published artifacts

Do not infer success from a green build job. Inspect and anonymously pull what
users will receive:

```bash
docker buildx imagetools inspect docker.io/sg1888/postfix-m365-relay:1.0.0
docker buildx imagetools inspect ghcr.io/sg1888/postfix-m365-relay:1.0.0
docker pull docker.io/sg1888/postfix-m365-relay:1.0.0
docker pull docker.io/sg1888/postfix-m365-relay:1.0.0-x86-64-v2
```

Compare manifest platforms and digests, rerun the offline suite against pulled
images, confirm v2 package architecture assertions, and verify the Docker Hub
description rendered from `docs/DOCKERHUB.md`. Record the immutable digest that
operators should pin.
