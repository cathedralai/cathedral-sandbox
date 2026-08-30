# Intel TDX machine contract

Intel TDX is Cathedral's scored confidential-CPU path. AMD SEV-SNP has its
own fixed worker and validator admission policy. This page is only the Intel
TDX contract.

This page defines the machine and quote contract. The repository README is the
operator run order. Cathedral Validator derives weights directly from miner
evidence. No publisher, signed weight vector, relay, or epoch service sits in
that path.

## Current image boundary

The current live-testing image is:

```text
ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99
```

That image starts `worker migrate --migration-mode public-legacy-audit`. It is
a bounded migration bridge, not the final production worker posture. Signed
validator access protects fleet discovery and all non-public routes, while
fresh evidence and canonical audit SAT remain public temporarily. A replacement
image must use the fixed `worker serve` production posture before this exception
is removed.

## Machine requirements

A production Intel TDX worker requires:

- a Linux TDX guest with readable and writable
  `/sys/kernel/config/tsm/report`;
- an HTTPS endpoint whose TLS private key is generated and held inside the
  guest;
- a certificate whose SPKI digest is bound into every fresh quote;
- the miner's public Bittensor hotkey, never its coldkey or wallet;
- a current signed validator-access snapshot, pinned public keys, durable
  replay state, and the worker's canonical public endpoint; and
- the worker and validator time, nonce, and request limits enforced by source.

The TLS private key must be an owner-only regular file. The worker refuses a
configured channel-binding digest that differs from the certificate it serves.

## Evidence flow

1. The validator opens the HTTPS endpoint and records its TLS SPKI digest.
2. It sends a fresh 32-byte nonce and the worker hotkey.
3. The worker computes the 64-byte
   `report_data_v2(nonce, hotkey, tls_spki_sha256)` value.
4. The worker writes that value to configfs-tsm `inblob`, reads `outblob`, and
   returns the quote. Only a bounded all-zero transport suffix is removed.
5. The validator verifies the quote, checks the REPORTDATA, and checks the live
   TLS SPKI again before sending protected work.

Production endpoints use HTTPS. For the required IP-literal axon, the first
handshake does not trust the self-signed certificate through a public CA. The
validator records its SPKI, then authenticates that key when fresh QVL-verified
REPORTDATA binds it to the miner hotkey and challenge. Later fleet and SAT
requests must retain the same SPKI and carry the validator's signed request.
Plain HTTP and authentication relaxations exist only under `worker develop`.

## Released verifier contract

Use the exact v1.0.0 binary and digest in
[TDX_VERIFIER_RELEASE.md](TDX_VERIFIER_RELEASE.md). The verifier accepts one
quote path and the independently computed expected REPORTDATA. It fails closed
unless all of these hold:

- the input is a valid Intel TDX quote v4;
- the quote signature, PCK chain, revocation data, and Intel collateral verify;
- the platform, TDX module, and quoting enclave are `UpToDate` with no
  advisories;
- collateral is current, and debug and migration are disabled;
- REPORTDATA matches the nonce, hotkey, and TLS SPKI binding exactly; and
- the quote yields a verified stable hashed platform identity.

The verifier also emits Cathedral's launch measurement. The current direct
validator does not retain it or use it as a weight gate. See
[MRTD.md](MRTD.md) for the separate sandbox-library policy path.

The sandbox library's strict policy path additionally requires the emitted
measurement to be in its verified policy and rejects malformed or unapproved
TCB and advisory claims. The direct SN39 validator uses the released QVL, live
TLS binding, canonical SAT result, and global hardware/TLS deduplication. It
does not consume the retired publisher or epoch path.

## Sandbox subprocess controls

These variables configure the sandbox library's production QVL subprocess:

| Variable | Production rule |
|---|---|
| `CATHEDRAL_TDX_VERIFY_CMD` | One absolute static x86-64 Linux executable, with no configured arguments |
| `CATHEDRAL_TDX_VERIFY_ARTIFACTS` | JSON list containing exactly the same executable path |
| `CATHEDRAL_TDX_VERIFY_DIGEST` | Execution-contract digest computed after installation |
| `CATHEDRAL_TDX_VERIFY_TIMEOUT` | 1 to 60 seconds, default 30 |
| `CATHEDRAL_TDX_VERIFY_MAX_OUTPUT` | 1 to 4,194,304 bytes, default 1,048,576 |

The executable and every path ancestor must be root-owned and not writable by
group or other users. Symlinks, interpreters, dynamic loaders, extra artifacts,
and changed bytes are rejected. The child runs from `/` with a fixed minimal
environment, closed inherited descriptors, no stdin, and a new process group.
Timeout, oversized output, invalid or duplicate-key JSON, nonzero exit, and
surviving descendants all reject the quote.

## What a pass proves

A complete pass proves a fresh Intel-verified quote bound to the miner hotkey
and the TLS key reached by the validator, plus a separately verified SAT
response from that endpoint. The stable platform identity lets the validator
identify collisions across UIDs and fleet entries. Every verified claimant in
a collision receives zero for that round.

It does not prove token emission, a particular OCI image unless that image is
separately bound into measured state, or future health after the checked
request. Each validator repeats the checks on fresh evidence.
