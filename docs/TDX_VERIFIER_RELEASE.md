# Intel TDX verifier release

Cathedral's production Intel TDX quote-verification library is the static
linux/amd64 executable published in the
[`cathedral-tdx-verifier-v1.0.0`](https://github.com/cathedralai/cathedral-sandbox/releases/tag/cathedral-tdx-verifier-v1.0.0)
release.

| Field | Required value |
|---|---|
| Tag | `cathedral-tdx-verifier-v1.0.0` |
| Tagged source commit | `065852443ef423e16b77289086321807f226a50d` |
| Asset | `cathedral-tdx-verifier-linux-amd64` |
| Asset SHA-256 | `4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148` |
| Target | static, stripped Linux x86-64 executable |

## Install and verify

Download the asset directly from the GitHub release. Do not download the
verifier from a Cathedral API or substitute another binary.

```bash
tag=cathedral-tdx-verifier-v1.0.0
asset=cathedral-tdx-verifier-linux-amd64
base="https://github.com/cathedralai/cathedral-sandbox/releases/download/${tag}"

curl --fail --location --proto '=https' --proto-redir '=https' \
  --output "$asset" "$base/$asset"
curl --fail --location --proto '=https' --proto-redir '=https' \
  --output "$asset.sha256" "$base/$asset.sha256"
sha256sum --check --strict "$asset.sha256"
test "$(sha256sum "$asset" | cut -d ' ' -f 1)" = \
  4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148
chmod 0500 "$asset"
```

Pass the absolute executable path to Cathedral Validator's `--qvl` option.
The validator verifies the exact asset SHA-256 before using it.

The sandbox library's production verifier path has an additional installation
pin. Install the asset at one root-owned, non-writable absolute path and set:

```bash
export CATHEDRAL_TDX_VERIFY_CMD=/opt/cathedral/bin/cathedral-tdx-verifier
export CATHEDRAL_TDX_VERIFY_ARTIFACTS='["/opt/cathedral/bin/cathedral-tdx-verifier"]'
export CATHEDRAL_TDX_VERIFY_DIGEST="$(
  python scripts/tdx_verifier_digest.py \
    --command "$CATHEDRAL_TDX_VERIFY_CMD" \
    --artifact "$CATHEDRAL_TDX_VERIFY_CMD" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["digest"])'
)"
```

The asset SHA-256 identifies the published bytes. The implementation digest is
different: it binds the absolute path, fixed argument vector, sanitized
environment, working directory, and executable bytes. Do not use the raw asset
SHA-256 as `CATHEDRAL_TDX_VERIFY_DIGEST`.

## Runtime contract

The executable accepts exactly:

```text
cathedral-tdx-verifier /absolute/path/to/quote <128-lowercase-hex-reportdata>
```

It accepts Intel TDX quote v4 only. It verifies the quote signature, Intel PCK
chain, revocation data, and current Intel PCS collateral. The TDX platform,
TDX module, and quoting enclave must all be `UpToDate` with no advisory IDs.
Debug and migration must be disabled. The supplied 64-byte REPORTDATA must
match exactly.

On success it emits one bounded JSON object containing the verified REPORTDATA,
Cathedral launch measurement, raw TCB SVN, current TCB status, stable hashed
platform identity, rotating PCK and attestation-key fingerprints, and the exact
booleans `intel_verified=true` and `report_data_match=true`. On failure it
prints nothing on stdout and exits:

| Exit | Meaning | Validator verdict |
|---|---|---|
| `0` | The quote verified; the claims are on stdout. | PASS |
| `1` | The quote, its input, or its collateral is invalid. | FAIL |
| `3` | Intel's collateral service did not answer: a network or TLS error, a timeout, HTTP 5xx, or HTTP 408, 425 or 429. | INFRA |

Exit `3` says nothing about the miner, so it must not zero the machine. It is
chosen only for answers that describe Intel's service, never for an answer
about the request: any other 4xx, a refused redirect, a disallowed URL, or
collateral that does not verify exits `1`. A miner therefore cannot craft a
quote that turns into a validator-wide stop. Releases before this contract
exit `1` for every failure. Any other nonzero exit, such as a Go runtime panic
(`2`), is a failure of this run and must be read as `1`.

The verifier fetches collateral only from the two allowlisted Intel PCS hosts,
over bounded HTTPS requests using Intel's `standard` update channel. It never
prints the raw PPID used to derive the stable platform identity.

## Next release (not yet published)

The next release, `cathedral-tdx-verifier-v1.1.0`, is not yet published. Until
it is, v1.0.0 above is the release to install. It brings the exit `3` contract
above: an Intel collateral outage is reported as an outage, decided by the
latest collateral request only, and a platform, TDX module or QE that is not
fully current is always exit `1`. v1.0.0 exits `1` for every failure. It also
emits `image_measurement`, the v2 image identity from #267, which leaves out
the owner fields a host sets per VM.

| Field | Expected value |
|---|---|
| Tag | `cathedral-tdx-verifier-v1.1.0` |
| Asset SHA-256 | `6596a93aaef33ecb0e841ebcfe23221e68aac36d6971e0e138269be713babacc` |

That digest is the reproducible build of the verifier source on `main` after
#267, plus sandbox #253, under the flags below. Rebuilding the v1.0.0 source the same way reproduces
v1.0.0's published digest exactly, so the build is deterministic.

To publish it, a maintainer tags a commit on `main` whose
`cmd/cathedral-tdx-verifier` directory matches that source:

```bash
git diff --quiet 7031b0e82f710949f0fcb001ec4b05cb12ced95c <commit> -- cmd/cathedral-tdx-verifier
git tag cathedral-tdx-verifier-v1.1.0 <commit>
git push origin cathedral-tdx-verifier-v1.1.0
```

The workflow refuses to publish a build with any other digest. After it
publishes, update the table at the top of this page. Then cathedral-validator
re-pins `DIRECT_VALIDATOR_QVL_DIGEST` in
`cathedral_thin/independent_runtime/qvl.py` to the new digest, and operators
install the new asset. Only then does the validator see exit `3`.

## Release controls and limits

The tag-only release workflow uses Go 1.25.13, two separate empty build caches,
and fixed static-build flags. The builds must be byte-identical and match the
workflow's `EXPECTED_SHA256`, which is the digest in "Next release" above. The
workflow publishes exactly the binary and checksum, then downloads both
anonymously and checks them again.

A verified download proves which executable bytes you installed. It does not
prove a miner is running those bytes, prove quote freshness, enforce a machine
measurement allowlist, or prove a live deployment. The current direct validator
requests fresh evidence and uses the verifier's PASS verdict and stable platform
identity. It does not retain or gate on the emitted measurement.
