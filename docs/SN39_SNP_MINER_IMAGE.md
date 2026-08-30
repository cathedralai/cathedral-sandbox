# SN39 AMD SEV-SNP miner image

This is the separate immutable image contract for an AMD SEV-SNP miner. It is
not the Intel TDX audit-miner image and it has no fallback or compatibility
mode.

## Release state

No digest is listed here until GitHub Actions publishes, attests, and proves
anonymous access to one. A source change and a green test suite do not prove a
published image, a running machine, or an on-chain weight.

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
- Finney SN39 and signed validator requests only.
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
