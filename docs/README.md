# Documentation

Cathedral turns independently operated machines from trusted operators into a
verifiable compute network. For mining on Bittensor SN94, start with the
[repository overview](../README.md), then follow
[Mining Cathedral](MINING.md), the only active operator guide.

Validator operators do not install from this repository; they use
[Cathedral Validator](https://github.com/cathedralai/cathedral-validator).

## Contents
<p><sub><strong>Operator path</strong></sub><br>
<strong>1. <a href="#current-operator-references">Current operator references</a></strong><br>
<strong>2. <a href="#founding-miners">Founding miners</a></strong><br>
<strong>3. <a href="#validators">Validators</a></strong><br><br>
<sub><strong>Support</strong></sub><br>
<strong>4. <a href="#protocol-and-product-library-references">Protocol and product-library references</a></strong><br>
<strong>5. <a href="#design-proposals">Design proposals</a></strong></p>

## Current operator references

- [AMD SEV-SNP miner and first hardware proof](AMD_SEV_SNP_FRIEND_TEST.md)
- [AMD SEV-SNP image contract](SN94_SNP_MINER_IMAGE.md)
- [Run an SNP miner on your own server, in order](SNP_OWN_SERVER_ONBOARDING.md)
- [Intel TDX image contract](SN94_AUDIT_MINER_IMAGE.md)
- [Validator access and multi-machine fleet protocol](WORK_REQUEST_V2.md)
- [Intel TDX verifier release](TDX_VERIFIER_RELEASE.md)
- [Live Intel TDX check](LIVE_TDX_CHECK.md)
- [Development tests](TESTING.md)
- [Public leak guard](LEAK_GUARD.md)

These pages explain a narrow contract. They do not replace the mining guide's launch
order.

## Founding miners

There is no published founding-miner program in this repository. See
[Founding miners](MINING.md#founding-miners) for the honest stub and the
list of terms Cathedral still needs to publish.

## Validators

The operator install, signed bootstrap, SNP policy template and weight-write
runbook live in
[cathedral-validator](https://github.com/cathedralai/cathedral-validator).
This repository serves miner evidence and SAT work. It does not write SN94
weights.

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

Cathedral's customer lease and sandbox products are live on SN94. The public
sealed tier runs on leased AMD SEV-SNP hosts, by request, not self-serve.
That product is not this mining path. The Escape Room is coming, but it is
not open.

## Design proposals

- [TEE sandbox box](TEE_BOX.md): a miner-run TDX or SEV-SNP box that hosts
  customer sandboxes under gVisor. This page is a design proposal, not a
  mining path and not a self-serve install. Cathedral's leased sealed product
  is separate and is not sold from this repository.
