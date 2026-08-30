# Documentation

For mining, use the repository [README](../README.md). It is the only active
operator guide.

## Current operator references

- [Intel TDX image contract](SN39_AUDIT_MINER_IMAGE.md)
- [Validator access and multi-machine fleet protocol](WORK_REQUEST_V2.md)
- [Intel TDX verifier release](TDX_VERIFIER_RELEASE.md)
- [AMD SEV-SNP friend hardware test](AMD_SEV_SNP_FRIEND_TEST.md)
- [Development tests](TESTING.md)

These pages explain a narrow contract. They do not replace the README's launch
order.

## Protocol and product-library references

The remaining documents specify library behavior such as receipts, workload
admission, key release, lifecycle state, provider contracts, policy registries,
and confidential-GPU research. They are for developers and reviewers. They are
not alternate SN39 mining paths.

The current Cathedral validator derives weights directly from miner evidence.
It does not consume the repository's older signed-vector publisher,
central-enrollment, burn, or provenance flows.
