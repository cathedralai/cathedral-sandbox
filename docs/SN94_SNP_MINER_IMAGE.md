# SN94 AMD SEV-SNP miner image

This is the separate immutable image contract for an AMD SEV-SNP miner. It is
not the Intel TDX audit-miner image and it has no fallback or compatibility
mode.

## Published release pin

The current anonymous `linux/amd64` image is:

```text
ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:3e1cb9144417e1e0d526445a43245e305e772cae0568202a332183071ef0c584
```

Its OCI revision label is
`dd7182ccd91ca25b566ff210025bdea5fda57c4c` and its fixed runtime-contract
label is `snp-signed-validator-fleet-v1`. The immutable digest proves the
published bytes available from GHCR. It does not prove a running SNP machine,
vendor evidence, validator admission, or an on-chain weight.

The image is fixed to Bittensor `finney` netuid 94 (label
`org.cathedral.image-chain=finney-94`) and refuses any other chain. The same
commit is also published for the testnet 584 rehearsal under the tag
`sha-dd7182ccd91ca25b566ff210025bdea5fda57c4c-test584`:

```text
ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:ed22b47631819fd709138065143223b6df75e2239880d05ec83ccded28dbc87a
```

That image carries `org.cathedral.image-chain=test-584` and refuses mainnet.
Use it only on testnet. One rehearsal on 2026-10-16 ran it in an AMD EPYC
Genoa SEV-SNP guest, where the testnet validator admitted it and set full
weight on netuid 584. That is testnet evidence for this commit, not an SN94
admission.

## Fixed behavior

The image starts this exact command:

```text
cathedral worker serve-snp
```

It fixes these properties:

- AMD SEV-SNP evidence from `/dev/sev-guest`.
- Official `snpguest` v0.10.0, SHA-256
  `70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0`.
- Native TLS on TCP `8081` with a new guest-owned private key at each start.
- Finney SN94 and signed validator requests only.
- The miner's public hotkey, public HTTPS endpoint, and a digest pin for the
  validator-access public-key file as its only Cathedral environment inputs.

The launcher requires an immutable image digest. It verifies the pulled
repository digest, architecture, and runtime label before start. It passes only
`/dev/sev-guest` into the read-only container, plus the signed validator-access
files and durable replay state. It does not pass a coldkey, wallet, chain RPC
credential, or snapshot-signing seed.

This digest check is local to the miner launcher. The remote SNP report proves
the admitted boot measurement, physical chip identity, request binding, and
live TLS key. It does not contain the OCI digest or prove continuous runtime
integrity after boot. Production weight therefore means admitted SNP hardware
plus verified SAT work, not remote proof of the published container image.

## Admission boundary

The worker serving evidence is necessary but insufficient for score. The
validator must also verify the AMD chain, report-data binding, TLS key,
processor generation, exact measurement, minimum reported TCB, distinct chip
identity, and SAT response. See [AMD SEV-SNP miner](AMD_SEV_SNP_FRIEND_TEST.md).
