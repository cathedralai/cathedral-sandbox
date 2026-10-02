# Documentation

For mining, use the repository [README](../README.md). It is the only active
operator guide.

## Current operator references

- [Intel TDX image contract](SN94_AUDIT_MINER_IMAGE.md)
- [AMD SEV-SNP image contract](SN94_SNP_MINER_IMAGE.md)
- [Validator access and multi-machine fleet protocol](WORK_REQUEST_V2.md)
- [Intel TDX verifier release](TDX_VERIFIER_RELEASE.md)
- [Live Intel TDX check](LIVE_TDX_CHECK.md)
- [AMD SEV-SNP miner and first hardware proof](AMD_SEV_SNP_FRIEND_TEST.md)
- [Run an SNP miner on your own server, in order](SNP_OWN_SERVER_ONBOARDING.md)
- [Development tests](TESTING.md)

These pages explain a narrow contract. They do not replace the README's launch
order.

## Protocol and product-library references

The remaining documents specify library behavior such as receipts, workload
admission, key release, lifecycle state, provider contracts, and policy
registries. They are for developers and reviewers. They are not alternate SN94
mining paths.

[Central pool access](CENTRAL_POOL_ACCESS.md) specifies how Cathedral's central
service would authenticate to an opted-in miner, and what it may do there.

[Compute pool integrity](COMPUTE_POOL_INTEGRITY.md) records what the direct
validator checks before it pays a machine, where that protection ends, and the
proposed enclave-policy and signed-receipt changes.

The current Cathedral validator derives weights directly from miner evidence.
It does not consume the repository's older signed-vector publisher,
central-enrollment, burn, or provenance flows.

## Design proposals

- [TEE sandbox box](TEE_BOX.md): TDX and SEV-SNP boxes that run customer
  sandboxes under gVisor. Proposal only; not a mining path.
