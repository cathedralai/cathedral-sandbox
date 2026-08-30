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
booleans `intel_verified=true` and `report_data_match=true`. Any verification,
network, parsing, or shape failure exits nonzero.

The verifier fetches collateral only from the two allowlisted Intel PCS hosts,
over bounded HTTPS requests using Intel's `standard` update channel. It never
prints the raw PPID used to derive the stable platform identity.

## Release controls and limits

The tag-only release workflow uses Go 1.25.13, two separate empty build caches,
and fixed static-build flags. The builds must be byte-identical and match the
digest above. The workflow publishes exactly the binary and checksum, then
downloads both anonymously and checks them again.

A verified download proves which executable bytes you installed. It does not
prove a miner is running those bytes, prove quote freshness, enforce a machine
measurement allowlist, or prove a live deployment. The current direct validator
requests fresh evidence and uses the verifier's PASS verdict and stable platform
identity. It does not retain or gate on the emitted measurement.
