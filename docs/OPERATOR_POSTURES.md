# Compute operator postures

Status reviewed: 2026-08-29.

The public phase is mainnet live testing. The fixed signed-fleet Intel TDX
audit image is published at the digest in
[`SN39_AUDIT_MINER_OPERATIONS.md`](SN39_AUDIT_MINER_OPERATIONS.md). Publication
is not deployment, current eligibility, or live proof. General self-service
provider onboarding remains operator-assisted.

New evidence and provenance verification default to
`validated_supply_v2` revision 1. `validated_supply_v1` remains available only
for explicit historical replay.

## Production

Use `cathedral worker serve` for an authenticated Intel TDX worker. The parser
does not accept no-auth, plain-HTTP non-loopback escape, TEE selection, GPU
composition, or public-route compatibility flags. The fixed TEE is Intel TDX.

Use these production runtime commands:

- `cathedral runtime canary`
- `cathedral runtime audit-attestation`
- `cathedral runtime run-epoch`

They accept only the signed policy-registry path and fixed Intel TDX profile.
They do not accept `--development`, `--cpu-tee`, `--measurements-file`, or GPU
identity/profile flags. Production admission requires a receipt issuer.
`run-epoch` is the only command in this group that creates a score report or
publishes it.

Production provenance verification returns nonzero for `NOT_PROVEN`, including
when `--allow-receipts-only` is present. Exit zero under `--production`
requires `PASS` with `assurance=full`.

## Development and preview

Use `cathedral worker develop` for local tests, AMD SEV-SNP friend testing, or
the TDX plus confidential-GPU audit preview. This is the only worker command
that accepts:

- `--development-no-auth`
- `--development-allow-non-loopback`
- `--tee tdx|snp`
- `--gpu-composite`

A non-loopback SNP friend worker still requires native TLS and the complete
signed-validator access bundle. Bearer authentication alone does not protect
the evidence route.

Use `cathedral runtime develop-canary` and
`cathedral runtime develop-audit-attestation` for development TDX, SNP, and
GPU preview checks. These commands never create an epoch, publish a report, or
issue an assurance receipt. SNP uses an explicit development measurements file.
GPU preview uses a signed policy profile plus all four GPU identity settings.

## Migration

Use `cathedral worker migrate` only for a bounded legacy collector transition.
It requires one explicit mode:

- `--migration-mode public-bootstrap-evidence` opens only the evidence route.
- `--migration-mode public-legacy-audit` opens evidence and canonical audit
  SAT. Fleet, capabilities, and noncanonical customer SAT remain protected.

Migration is fixed to authenticated Intel TDX with native TLS and the complete
signed-validator access bundle. It does not accept development, SNP, GPU, or
customer-SAT options. The replacement audit-image source invokes
`public-legacy-audit` internally. Operators cannot select a different image
posture through environment variables. The currently published digest predates
this command split and still invokes `worker serve` with `--tee tdx` and
`--allow-public-legacy-audit`. It does not emit the new effective-startup
record. The `worker migrate` image contract remains source-only until a
replacement digest and provenance are published and recorded.

The retained bridge implementation is limited to the two explicit
`WorkerServer` route controls. It remains for migration compatibility and is
not exposed by `worker serve`.

## Installed commands and startup record

The package installs `cathedral`, `cathedral-census`, `cathedral-prober`, and
`cathedral-snp-friend-probe`. It no longer installs the ambiguous
`cathedral-miner` or `cathedral-compute-validator` aliases.

Worker and admission-runtime startup emit
`cathedral_effective_startup_v1`. The record states the effective posture and
security-relevant booleans without printing bearer values, signing material,
environment contents, or filesystem paths.
