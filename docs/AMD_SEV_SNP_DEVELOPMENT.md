# AMD SEV-SNP development mode

Status: enabled for live development attestation and canonical SAT checks.

This mode verifies a friend-owned native AMD SEV-SNP guest without creating an
epoch score report. It never publishes, issues a receipt, writes weights, or
changes the fixed Intel TDX miner image.

Plain SEV, Azure vTPM attestation, and report version 6 are outside this mode.
The current verifier accepts native `/dev/sev-guest` reports for the reviewed
Milan, Genoa-family, and Turin paths supported by pinned `snpguest` 0.10.0.

## Compute worker

The worker hardware selector is:

```text
--tee tdx|snp
```

`tdx` remains the default. `snp` selects `/dev/sev-guest` collection. The SNP
collector uses:

| Setting | Default | Purpose |
|---|---:|---|
| `CATHEDRAL_SEV_GUEST_DEV` | `/dev/sev-guest` | Native Linux SNP guest device |
| `CATHEDRAL_SNPGUEST` | `snpguest` on `PATH` | AMD certificate and report verifier |
| `CATHEDRAL_SNPGUEST_TIMEOUT` | `30` seconds | Per-verifier action, clamped to 1 through 300 seconds |

The verifier accepts only the reviewed `snpguest` 0.10.0 binary with SHA-256
`70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0`.
Both the bounded friend probe and general verification path check the executable
is a non-symlink regular file with this exact digest before using it.

The verifier also pins the SHA-256 of the AMD ARK public key fetched from AMD
KDS. A self-signed replacement root is refused even if the guest trust store or
DNS is compromised:

| Product | AMD ARK SPKI SHA-256 |
|---|---|
| Milan | `9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9` |
| Genoa | `429a69c9422aa258ee4d8db5fcda9c6470ef15f8cd5a9cebd6cbc7d90b863831` |
| Turin | `4f125410563a2ab9a50356f9243f6fe0b6f73de98603f53f90339c70e9d7ad08` |

These pins were derived from the official AMD KDS `cert_chain` endpoints on
2026-08-29. Any AMD root rotation fails closed and needs a reviewed source
update before acceptance.

A remotely observed check needs HTTPS, a TLS key generated inside the guest,
and signed-validator authentication. Bearer tokens do not protect the evidence
endpoint and are not accepted as the sole guard for a public SNP worker.

For a local, inside-guest check, bind loopback and opt into the explicit
unauthenticated development mode. Issue the worker certificate from a local
development CA. The certificate must contain `IP:127.0.0.1` in its Subject
Alternative Name. Keep the CA key and worker key owner-only. The runtime must
trust the issuing CA through `SSL_CERT_FILE`; trusting only the worker process
does not configure the separate runtime process.

```bash
export CATHEDRAL_SNPGUEST=/absolute/path/to/reviewed/snpguest
cathedral worker develop \
  --tee snp \
  --hotkey '<public miner hotkey>' \
  --host 127.0.0.1 \
  --port 8081 \
  --tls-certificate /absolute/path/to/worker.crt \
  --tls-private-key /absolute/path/to/worker.key \
  --development-no-auth
```

For a remote friend test, configure the full signed-validator access bundle:
the finalized validator snapshot, pinned snapshot keys and digest, owner-only
replay state, minimum stake, and canonical public endpoint. The worker refuses
SNP on a non-loopback address without this bundle. It also refuses the public
bootstrap and legacy-audit compatibility flags. See
[signed validator access contract](WORK_REQUEST_V2.md) for each worker option. The
certificate must chain to the CA configured by the reviewing validator.

## Local reviewing runtime

The runtime selector is:

```text
--cpu-tee tdx|snp
```

`snp` exists only on the explicit development command surface, uses a loopback
HTTPS endpoint for local review, and is accepted only by these commands:

- `runtime develop-audit-attestation`, which verifies fresh evidence and the live TLS
  binding without dispatching work.
- `runtime develop-canary`, which performs the same check and then verifies one
  canonical 20-unit SAT response on the attested channel.

Create an owner-only development policy:

```json
{
  "allowed_measurements": ["<96 lowercase hex characters from the reviewed guest image>"],
  "min_tcb": 0
}
```

Then run in a second shell. Repeat the verifier path and add the issuing CA to
that process's trust store:

```bash
export CATHEDRAL_SNPGUEST=/absolute/path/to/reviewed/snpguest
export SSL_CERT_FILE=/absolute/path/to/development-ca.crt
cathedral runtime develop-canary \
  --cpu-tee snp \
  --registry-db /absolute/path/to/snp-dev-registry.sqlite \
  --ledger-db /absolute/path/to/snp-dev-ledger.sqlite \
  --measurements-file /absolute/path/to/snp-development-policy.json \
  --canary-hotkey '<public miner hotkey>' \
  --canary-endpoint 'https://127.0.0.1:8081'
```

The JSON result states `environment=development`,
`production_eligible=false`, `authorized_for_chain_write=false`,
`score_report_created=false`, and `receipt_issued=false`.

This Compute runtime does not sign remote validator requests. Use the
Validator repository's `cathedral-amd-sev-snp-dev-preview` command for a
friend-owned public endpoint. That separate command opens only the configured
validator hotkey, signs every protected request, supports a per-target TLS CA,
and remains no-write.

## Enforced refusals

Development SNP refuses:

- `runtime run-epoch`, including dry local epoch creation.
- Any publisher endpoint or `--publish` request.
- Receipt signing keys.
- The production signed policy-registry path.
- GPU composition.
- Every production runtime command. Production parsers do not expose an SNP selector.

The runtime keeps raw AMD CHIP_ID transient. It does not write the value to the
provider registry or a score report. The separate validator development preview
uses a scoped pseudonym and requires AMD `SINGLE_SOCKET=1` before treating a
CHIP_ID as a deduplication observation.

## Proof boundary

A successful canary proves fresh vendor-backed SNP evidence, the configured
measurement and TCB floor, nonce and hotkey binding, TLS SPKI continuity, and
one verified SAT round trip for that run.

It does not prove production eligibility, durable physical-machine identity,
customer receipt support, SN39 weight, subnet emission, or TAO earnings.
