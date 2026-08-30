# Static TDX verifier release

## Status

This repository contains a source-reviewed release path. This document does not
claim that a tag or GitHub release exists. Creating a tag is the separate
publication authorization boundary.

`.github/workflows/release-tdx-verifier.yml` runs only for a pushed tag matching
`cathedral-tdx-verifier-vMAJOR.MINOR.PATCH`. It has no branch, pull-request, or
manual-dispatch trigger. The job revalidates the exact tag shape before any
publishing command. It also refuses a tag whose commit is not reachable from the
current `origin/main`.

Before pushing a release tag, the operator must confirm GitHub immutable
releases are enabled for this repository and, through an authenticated
administrator view, confirm the release-tag ruleset has no bypass actors. Those
administrator-only facts are not read by the workflow. After publication, the
workflow requires GitHub to report the release as immutable.

Immediately before draft creation, the workflow anonymously requires:

- One active tag ruleset named
  `Protect Cathedral TDX verifier release tags`, whose only include is
  `refs/tags/cathedral-tdx-verifier-v*`, whose only rules restrict update and
  deletion, and which has no excluded refs.

The workflow reads the public rulesets API without credentials and fails closed
if the exact control is absent or differs. It never changes repository controls
and does not add a persistent GitHub credential. Publication uses only GitHub
Actions' ephemeral `GITHUB_TOKEN`. Configuring the controls is separate
administrator authorization.

GitHub omits bypass actors from anonymous ruleset responses. The public check
therefore does not claim to prove the no-bypass operator preflight.

## Fixed artifact contract

The workflow checks out the tagged commit and uses:

```text
Go 1.25.13
GOENV=off
GOTOOLCHAIN=local
GOWORK=off
CGO_ENABLED=0
GOOS=linux
GOARCH=amd64
GOAMD64=v1
go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w'
```

It refuses unless the resulting
`cathedral-tdx-verifier-linux-amd64` has SHA-256:

```text
4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148
```

It also rejects a dynamic loader, a dynamic segment, or a binary which is not
reported as stripped and statically linked. A mismatch stops before release
creation. Two builds use separate empty Go build caches and must compare
byte-for-byte. The tag job also runs `go vet`, the race-enabled verifier tests,
and the pinned `govulncheck` scan before either build.

## Independent reproduction

From the tagged source revision, with Go 1.25.13 installed:

```bash
cd cmd/cathedral-tdx-verifier
test "$(GOENV=off GOWORK=off GOTOOLCHAIN=local go env GOVERSION)" = go1.25.13
GOENV=off GOWORK=off GOTOOLCHAIN=local go mod verify
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  GOENV=off GOWORK=off GOTOOLCHAIN=local \
  go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w' \
  -o cathedral-tdx-verifier-linux-amd64 .
printf '%s  %s\n' \
  4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148 \
  cathedral-tdx-verifier-linux-amd64 \
  > cathedral-tdx-verifier-linux-amd64.sha256
sha256sum --check --strict cathedral-tdx-verifier-linux-amd64.sha256
```

Do not replace the expected digest merely because a build differs. First prove
the source revision, Go version, dependency checksums, target environment, and
flags. Any intentional verifier change requires a separately reviewed digest
update before a release tag is pushed.

## Publication boundary

The GitHub release receives exactly two explicit assets: the binary and its
checksum. The generated release notes come from
`docs/TDX_VERIFIER_RELEASE_NOTES_TEMPLATE.md` and bind the tag, source commit,
build contract, digest, provenance boundary, and limits of what the verifier
proves. GitHub adds automatic source archives outside the uploaded asset list.

Publishing a release does not prove installation or use. Production operators
must not use the raw asset SHA as Cathedral's verifier implementation digest.
They must compute the absolute-path-and-argv-bound digest described by
`scripts/release_pins.py` and `docs/RELEASE_CHECKLIST.md` after installing the
binary at its reviewed path.

The workflow passes `--verify-tag` and `--latest=false`, so it refuses a missing
remote tag and does not change GitHub's latest-release marker. It also re-fetches
and dereferences the protected remote tag immediately before draft creation.
It creates the release as a draft, uploads only the binary and checksum, and
verifies both assets' names, SHA-256 digests, byte sizes, and `uploaded` state
while the release remains a draft. An upload failure or byte mismatch cannot
publish a partial release. Only then does the workflow recheck the tag, publish
the draft, require `isImmutable=true`, revalidate the two assets, and recheck the
tag again. A green release job therefore binds the immutable release to the same
source commit used for the build. These checks do not enable the repository
controls.

After release creation, a separate job with no repository permissions or token
downloads both explicit assets from GitHub's public release URL and verifies the
checksum again. A green workflow run is the live anonymous-download proof. The
source-only checks in a pull request do not provide that proof.

## Installation boundary

Use the exact release tag. Download only from GitHub, then verify before moving
the binary into its reviewed absolute path or executing it:

```bash
tag=cathedral-tdx-verifier-vMAJOR.MINOR.PATCH
base="https://github.com/cathedralai/cathedral-sandbox/releases/download/${tag}"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output cathedral-tdx-verifier-linux-amd64 \
  "${base}/cathedral-tdx-verifier-linux-amd64"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output cathedral-tdx-verifier-linux-amd64.sha256 \
  "${base}/cathedral-tdx-verifier-linux-amd64.sha256"
sha256sum --check --strict cathedral-tdx-verifier-linux-amd64.sha256
test "$(sha256sum cathedral-tdx-verifier-linux-amd64 | cut -d ' ' -f 1)" = \
  4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148
```

The placeholder tag above is intentionally non-runnable. Replace it only with
the explicit reviewed tag. Do not download the verifier from a Cathedral API.
