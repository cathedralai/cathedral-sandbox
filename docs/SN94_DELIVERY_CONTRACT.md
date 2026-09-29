# SN94 customer delivery contract

This branch adds canonical allocation grants, signed receipts and strict
admission checks. The separately reviewed
[pool appliance implementation](https://github.com/cathedralai/cathedral-pool/blob/8266eea61789aaf502b05fce788711ebaddca753/ops/attested_appliance/README.md)
uses these contracts in the actual Node lifecycle. This does not turn the
existing SAT image into a customer executor. The
[miner quickstart](SN94_MINER_QUICKSTART.md) remains the existing SAT lane.

## Implemented contract

`packages/delivery-contract/cathedral_delivery/__init__.py` is the canonical
source of `cathedral-delivery`. `cathedral/delivery.py` re-exports it for the
existing CLI; both wheels include that same source. The validator pins that distribution
by immutable commit without replacing its existing SNP verifier dependency.

A receipt has one canonical body and two Ed25519 signatures. The body binds the
miner, executor key, allocation attempt, sandbox, hardware, quote digest,
measurement, admission nonce and lease, interval, reserved resources, outcome,
and `retention_until`. Retention is at least 14 days after issue. Payloads,
commands, environment values and logs never belong in receipts.

- `sign_executor(body, key)` signs canonical bytes in the guest.
- `countersign_receipt(body, executor_signature=..., executor_key=...,
  control_plane_key=...)` verifies that exact signature, then countersigns.
- `verify_receipt(...)` checks both signatures, exact units and retention.
- `admit_delivery(...)` checks a raw TDX quote with the pinned vendor verifier,
  approved measurement, fresh admission nonce, TLS SPKI binding to the executor
  signer, stable hardware identity and strict vendor verdict.

The authority must compare the receipt with its durable allocation and observed
start/end before countersigning. The signature helper cannot do that on its
behalf. TDX does not by itself prove useful work or trusted elapsed time.
Unattested and lost executions have zero reward units. A self-reported
`verified` flag cannot admit an executor.

The `cathedral delivery-receipt check` command reads a public envelope and public
keys from stdin. Even when signatures verify, it reports `eligible: false` and
`admission: not_checked`. It never opens a wallet or writes chain state.

```bash
python3.12 -m venv .venv
.venv/bin/pip install '.[dev]'
.venv/bin/python scripts/test_sn94_delivery_cli.py
.venv/bin/python -m pytest tests/test_delivery_receipt.py
```

These tests use generated in-memory keys and synthetic quotes. They do not prove
hardware admission, a running executor, capacity, latency or live weights.

## Allocation and execution source

`cathedral_delivery.grants` signs exact CP allocation intent with a separate
signature domain. The grant binds boot/key/quote, project/job, physical hardware,
the original Node operation ID, slot/generation, exact create-body digest,
resource request, customer deadline and accounting-window duration. The current
offer is exactly 1 vCPU / 4 GiB per slot. `cathedral executor check-grant` checks
shape and authority signature only; it always reports `eligible: false`.

The pool implementation loads an immutable root through a fixed dm-verity
initramfs, keeps its signing key and replay state in private guest memory,
consumes RTMR3 before first job work, and reuses Node create/status/exec/files/
delete/TTL handlers. A continuous PID identity and monotonic interval gate its
terminal signed window segments. Process restart, key/state loss or ambiguous
cleanup cannot create positive delivery. CP must independently join those
segments to durable allocation observations and archive them with the raw
quote/key before countersigning and publishing complete accounting windows.
The API integration is tracked separately in API PR #1410; neither source
tests nor an offline signature check establish a qualified live service.

## Customer miner onboarding gates

The intended customer miner supplies TDX-capable bare metal with control of its
VMM when running one TD per sandbox. A cloud TD can serve the existing proposed
TD-per-job lane; containers inside it have a different isolation boundary.
Non-TDX supply must be labelled unattested and cannot earn this mechanism's
emissions. The current SAT worker is not evidence that either customer lane is
qualified.

The README alone does not yet provide a complete customer-miner join path:

1. The loader builder consumes a reviewed root image; this repository does not
   publish a qualified kernel/initrd/root image with a measured-launch policy.
   Root assembly must include the actual interpreter, attestation dependencies,
   Node/runsc, fixed workload, CP public authority and reviewed network setup.
2. Bare-metal VMM launch, TD replacement after a project's job, and endpoint
   registration are not provided by the existing SAT launcher. A host manager
   must implement those actions before miner onboarding can be unattended.
3. CP endpoint/region/hotkey approval and fresh quote admission must be deployed
   with the real pinned verifier and approved measurement. A miner cannot
   approve its own root hash, quote or capacity declaration.
4. Kernel RTMR support, measured boot, private-state loss, runsc isolation,
   timing bounds and CP-to-guest receipt recovery need hardware qualification.
5. The first fixed-image/no-egress offer needs further runtime capabilities to
   satisfy the Affine public-image/Dockerfile, DinD and 500-sandbox requirements.

The existing TDX appliance stack in PR #249 remains separate. It was not broadly
merged into this branch, and its capacity challenges are not customer receipts.
The one-binary/config/systemd customer-miner installation requirement remains
unmet until the release, host manager and enrollment steps above are supplied.
The existing SAT miner's config, launcher and systemd instructions remain
available in the quickstart, with its release and validator cutover gates.
