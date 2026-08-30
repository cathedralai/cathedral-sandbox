# Cathedral static TDX verifier `{{TAG}}`

This is a source-pinned verifier artifact release. It is not evidence of a
deployment, a live quote, validator scoring, subnet emissions, or production
operation.

## Assets

- `cathedral-tdx-verifier-linux-amd64`
- `cathedral-tdx-verifier-linux-amd64.sha256`

The release workflow supplies only those two release assets. GitHub separately
provides its automatic source archives.

## Reproducible build contract

- Source repository: `https://github.com/cathedralai/cathedral-sandbox`
- Source revision: [`{{SOURCE_REVISION}}`](https://github.com/cathedralai/cathedral-sandbox/commit/{{SOURCE_REVISION}})
- Module: `cmd/cathedral-tdx-verifier`
- `go.mod` SHA-256: `{{GO_MOD_SHA256}}` ([source](https://github.com/cathedralai/cathedral-sandbox/blob/{{SOURCE_REVISION}}/cmd/cathedral-tdx-verifier/go.mod))
- `go.sum` SHA-256: `{{GO_SUM_SHA256}}` ([source](https://github.com/cathedralai/cathedral-sandbox/blob/{{SOURCE_REVISION}}/cmd/cathedral-tdx-verifier/go.sum))
- Toolchain: Go `1.25.13`, with automatic toolchain switching disabled
- Environment: `GOENV=off`, `GOWORK=off`
- Target: `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64`, `GOAMD64=v1`
- Flags: `-mod=readonly -trimpath -buildvcs=false -ldflags='-s -w'`
- Binary SHA-256: `4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148`
- Workflow: `.github/workflows/release-tdx-verifier.yml`

The literal build command is:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  GOENV=off GOWORK=off GOTOOLCHAIN=local \
  go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w' \
  -o cathedral-tdx-verifier-linux-amd64 .
```

Reproduce from the source revision, then require the exact SHA-256 above. A
different digest is a refusal, not a reason to update the checksum during a
release run.

This raw binary SHA-256 is not Cathedral's runtime verifier implementation
digest. After installation, operators must compute the absolute-path-and-argv
bound digest described by `scripts/release_pins.py`. This digest belongs to
the legacy provenance-verification library. It is not required by the current
direct validator.

## Provenance and trust boundary

The checksum binds the downloaded binary bytes to this release record. Trusting
it requires trusting the tagged source revision, the reviewed workflow, the
pinned GitHub Actions, the GitHub-hosted runner and release control plane, and
the repository maintainers authorized to create the tag.

The binary is a statically linked, stripped verifier. Its successful execution
proves only the checks it reports for the supplied quote and expected report
data. Callers must still enforce quote freshness, challenge binding, approved
TCB and measurement policy, stable platform identity, and the surrounding
validator authorization contract.
