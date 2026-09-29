# SN94 customer delivery contract

This branch adds a canonical signed receipt codec and source-level admission
checks. It does not turn the existing SAT miner into a customer sandbox
executor. The [miner quickstart](SN94_MINER_QUICKSTART.md) remains the existing
SAT admission lane, staged with the published SN94 image pins.

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

## Supply contract and remaining gates

The intended customer miner supplies TDX-capable bare metal with control of its
VMM when running one TD per sandbox. A cloud TD can serve the existing proposed
TD-per-job lane; containers inside it have a different isolation boundary.
Non-TDX supply must be labelled unattested and cannot earn this mechanism's
emissions. The current SAT worker is not evidence that either customer lane is
qualified.

The running executor lifecycle still needs to connect:

1. Registration, capacity and region reporting to the control plane.
2. Fresh quote admission and the exact measured guest's signing key.
3. A durable allocation ID with an observed start and terminal outcome.
4. Guest signing and authority countersigning, then a validator receipt feed.
5. Receipt interval splitting at accounting windows, with stable attempt identity.

The existing TDX appliance stack in PR #249 is a separate, unqualified source
stack. It was not imported into this branch. Its old capacity challenges are
not customer delivery receipts. The one-binary/config/systemd customer executor
requirement remains unmet until that lifecycle is integrated and qualified.
The existing SAT miner's config, launcher and systemd instructions remain
available in the quickstart, with its release and validator cutover gates.
