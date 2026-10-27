# Documentation

For mining, start with the [repository overview](../README.md), then follow
[Mining Cathedral](MINING.md), the only active operator guide.

## Current operator references

AMD SEV-SNP is the SN94 miner path.

- [AMD SEV-SNP image contract](SN94_SNP_MINER_IMAGE.md)
- [AMD SEV-SNP miner and first hardware proof](AMD_SEV_SNP_FRIEND_TEST.md)
- [SNP hardware and admission, steps 1 to 3](SNP_OWN_SERVER_ONBOARDING.md)
- [Validator access and multi-machine fleet protocol](WORK_REQUEST_V2.md)
- [Development tests](TESTING.md)
- [Public leak guard](LEAK_GUARD.md)

Intel TDX is a legacy path.

- [Intel TDX image contract (legacy)](SN94_AUDIT_MINER_IMAGE.md)
- [Intel TDX verifier release (legacy)](TDX_VERIFIER_RELEASE.md)
- [Live Intel TDX check (legacy)](LIVE_TDX_CHECK.md)

These pages explain a narrow contract. They do not replace the mining guide's launch
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
