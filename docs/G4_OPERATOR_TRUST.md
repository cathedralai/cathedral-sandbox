# G4 operator-controlled GPU workers

Status: code-only prelaunch path approved by the user. No hardware has been
provisioned or qualified. Private customer work and live rewards are disabled.

## What a miner supplies

One complete fleet is eight Google Spot `g4-standard-48` VMs, each with one
RTX PRO 6000 Blackwell Server Edition GPU. Each VM uses plain AMD SEV. Plain
SEV supplies no guest CPU attestation, so this profile does not claim TDX,
SEV-SNP, measured guest code, or protection from a malicious guest operator.
See [the bounded fleet planner](G4_FLEET_PLAN.md) for eight distinct VM requests,
Spot-only provisioning, fixed lifetime and no on-demand fallback or retry.

The physical profile is `gcp-g4-rtx-pro-6000-sev-v1`. The eight-instance offer
is `gcp-g4-rtx-pro-6000-8gpu-v1`. A worker must have exactly one GPU. The bundle
is never passed to a single worker. All eight endpoints must independently
verify and execute fresh work before the bundle can receive full fleet credit.

## Who is trusted

An explicitly approved operator retains cloud provisioning, guest root,
image maintenance, per-instance worker signing keys and TLS keys. The miner
may sponsor capacity and associate a hotkey, but cannot retain guest root or
extract those keys. Google retains control of the physical hardware. These
are two separate trust assumptions. Arbitrary miner metadata and a rented
Google VM do not establish trusted guest control.

The `cathedral.gpu_provider` module uses an operator-signed endorsement
and a separate per-instance Ed25519 worker key. No shared image-baked private
key is permitted. The validator's operator public keys are local trust roots;
they must come from an approved operator, never the miner's evidence response.

Before signing an endorsement, the operator must check the real cloud instance
through its authenticated provisioning control: immutable numeric project and
instance ID plus zone, `g4-standard-48`, `SPOT`, confidential type `SEV`, approved
image digest, guest/root custody and access policy, exact GPU UUID, hotkey,
worker public key, and native TLS SPKI. The endorsement expires within 24 hours.
Renewal requires continued custody. Revoking an operator key stops trusting its
endorsements. The code does not infer these checks from self-reported metadata.

## Fresh execution evidence

The local collector invokes pinned `nv-local-gpu-verifier==2.7.3` from
`/opt/cathedral/nv-verifier/bin/python`, requires NVIDIA success, checks CC ON,
sets and checks Ready state, and requires the exact single GPU UUID/model.
These commands share a 45-second deadline. Missing software, unexpected model,
verification failure, or timeout fails closed. There is no retry or CPU fallback.

Work uses the existing fixed CUDA driver kernel. The provider path
performs NVIDIA checks before work and again for completion, then signs the
fresh nonce, hotkey, TLS SPKI, endorsement digest and verifier transcript with
the per-instance key. Completion nonce commits the complete work request and
output digest. Admission and completion must preserve the same instance/GPU.

This is a trusted operator's signed report of local NVIDIA verification and
execution. It is not an independently replayable NVIDIA token or CPU quote.
The image digest is an operator endorsement, not a hardware measurement.
Correct output alone is not evidence of GPU execution.

Every verified result includes a domain-separated worker public-key fingerprint.
Validators must reject reuse across instances and require the same fingerprint
at admission and completion. The full fleet needs eight unique instances, GPU
identities, worker signing keys and TLS keys. Public listings need no raw keys.

## Start one worker

Prepare an approved guest with the NVIDIA confidential GPU driver, LKCA, UVM
persistence/container access required by NVIDIA, CUDA driver `libcuda.so.1`,
and `nv-local-gpu-verifier==2.7.3` installed in the fixed virtualenv above.
The operator must validate those hardware prerequisites later on an actual G4
guest. Installation or these source tests do not qualify the machine.

Provision a unique Ed25519 worker key into each guest with owner-only mode 0600.
Keep the operator signing key off the guest. Create an endorsement using
`cathedral.gpu_provider.sign_endorsement(claims, operator_key_id, operator_key)`
only after the provisioning/custody checks above. The complete claim grammar
is `validate_endorsement_claims` in that module. The approved operator-key file
is a JSON map of key ID to raw Ed25519 public key as 64 lowercase hex characters.
These must be real approved keys; the worker creates no example endorsements.

Reuse the validator-access setup, native TLS certificate, public endpoint and
fleet manifest from the README. Run on each of the eight operator-controlled
guests, supplying that guest's own endorsement, signing key, TLS key and endpoint:

```sh
cathedral worker serve-g4 \
  --host 0.0.0.0 --port 8081 --hotkey "$MINER_HOTKEY" \
  --tls-certificate /etc/cathedral/tls/worker.crt \
  --tls-private-key /etc/cathedral/tls/worker.key \
  --gpu-operator-endorsement /etc/cathedral/g4/endorsement.json \
  --gpu-worker-private-key /etc/cathedral/g4/worker-signing.pem \
  --gpu-operator-keys /etc/cathedral/g4/operator-public-keys.json \
  --validator-access-snapshot /etc/cathedral/validator-access/snapshot.json \
  --validator-access-keys /etc/cathedral/validator-access/public-keys.json \
  --validator-access-keys-digest "$VALIDATOR_ACCESS_KEYS_DIGEST" \
  --validator-access-state /var/lib/cathedral/validator-access.sqlite \
  --validator-minimum-stake-rao "$MINIMUM_VALIDATOR_STAKE_RAO" \
  --validator-network "$VALIDATOR_NETWORK" --validator-netuid "$VALIDATOR_NETUID" \
  --public-endpoint "$THIS_WORKER_HTTPS_ORIGIN" \
  --fleet-manifest /etc/cathedral/validator-access/fleet.json
```

Use the prelaunch network/subnet agreed with the validator operator. This command
does not register a chain axon, submit weights, rent machines, or trust a new
operator automatically. Its signed access configuration is mandatory. Each
primary's fleet manifest names the other seven HTTPS origins under the same
miner hotkey. Refresh validator access snapshots and endorsements before expiry.
Do not put private signing keys in images or fleet manifests.

`/v1/gpu-capabilities` reports the physical single-GPU profile as registered and
unverified. `/v1/gpu-evidence` returns `cathedral_gpu_provider_evidence_v1` with
an `evidence` object containing `endorsement`, `statement`, and `signature_hex`.
The native composite grammar is never reused for plain SEV. `/v1/gpu-work`
returns the same result envelope as native GPU work, with the provider object
in `completion_evidence`. `/v1/evidence` cannot produce a CPU quote on G4.

A work request can use 45 seconds of pre-work NVIDIA verification, 30 seconds
of CUDA execution and 45 seconds of completion verification. The validator
must allow 125 seconds per work request and process the eight endpoints with
bounded concurrency. There are no implicit hardware purchases, retries, or
Spot-to-on-demand fallback. A lost Spot worker makes the fleet incomplete.

## Item acceptance

```sh
python3 -m pytest -q tests/test_g4_local_collector.py tests/test_g4_provider.py tests/test_gpu_worker.py
```

These checks exercise pinned commands, one-GPU limits, signed TLS authorization,
operator and worker signatures, nonce/hotkey/TLS binding, stale or altered
evidence, failure responses and CPU evidence denial. NVIDIA/CUDA outputs are
explicitly synthetic in tests. Actual G4 execution remains unqualified.
