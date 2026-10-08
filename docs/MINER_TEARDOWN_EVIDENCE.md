# Miner teardown evidence (draft)

Status: **schema + verify helpers** in `cathedral/miner_lifecycle_receipt.py`.
Does not activate miner rewards. Does not relax
`CUSTOMER_EXECUTION_SUPPLY_BOUNDARY.md` condition 3. Polaris production
reconciler that *issues* receipts is still to wire.

## Why

`PROVEN_ABSENT` today is honest only when Cathedral controls the resource
lifecycle (seed). A `subnet_hotkey` miner cannot self-prove teardown. Until
an independent Cathedral observation exists, miner customer attempts stay
shadow-only and cannot reach a reward-eligible terminal.

## Proposed schema: `cathedral_miner_lifecycle_receipt_v1`

Signed by the **Cathedral control plane** (or an operator key Cathedral
pins), never by the miner alone.

| Field | Meaning |
| --- | --- |
| `schema` | `cathedral_miner_lifecycle_receipt_v1` |
| `provider_hotkey` | Subnet hotkey that held the slot |
| `slot_id` / `attempt_id` / `assignment_digest` | Bind to the provider contract attempt |
| `action` | `reclaim` \| `delete` \| `relaunch_observed_absent` |
| `observed_at` | UTC time of the independent observation |
| `observation_class` | How Cathedral saw absence (see below) |
| `observation_digest` | sha256 of the canonical observation payload |
| `guest_boot_id` (optional) | Last boot id before reclaim, if known |
| `evidence_refs` | Bounded digests / credential-free HTTPS refs only |

### Allowed `observation_class` values (v1)

| Class | Meaning | Not allowed |
| --- | --- | --- |
| `central_guest_gone` | Cathedral reached the guest (central pool access) and confirmed the sandbox/lease resource is absent | Miner HTTP “I’m deleted” |
| `operator_host_reclaim` | Cathedral operator reclaimed/destroyed the VM/slot on infrastructure Cathedral controls or co-operates | Miner-local script output alone |
| `seed_analog_runsc_absent` | Same class of proof seed uses today (`runsc_absent`), when Cathedral runs the executor lifecycle on that host | Self-signed miner quote of teardown |

Rejected by verifiers: any receipt whose only evidence is miner-signed
“resource absent”, SAT proof, enrollment, or uptime.

## Mapping to the provider contract

1. Independent verifier accepts a `cathedral_miner_lifecycle_receipt_v1`.
2. Control plane sets `CleanupOutcome` to `PROVEN_ABSENT` with that
   `observation_digest` and `TerminalBasis.PROVIDER_ABSENCE`.
3. Only then may the attempt reach `SUCCEEDED` / charge / later shadow
   verified-work facts.
4. Reward activation remains a separate step (supply-boundary activation
   order 2–6).

## Implementation order

1. This draft (docs) — done.
2. Canonical JSON + Ed25519 verify helpers in `cathedral-sandbox` — **done**
   (`cathedral/miner_lifecycle_receipt.py`, tests). No production wiring.
3. Polaris issuer + in-process ingest — **done**
   (`polariscomputer` `cathedral_miner_lifecycle_issuer.py`,
   `docs/MINER_LIFECYCLE_RECEIPT_ISSUER.md`). Still needs live observation hooks.
4. Wire `resolve_cleanup` only from that verifier — never from miner
   self-report.
5. Shadow facts, then explicit reward-policy activation.

## Forbidden shortcuts

- Relaxing supply-boundary condition 3
- Treating `CUSTOMER_CLEANUP_DEADLINE` as `SUCCEEDED`
- Letting the miner’s tee-box or SAT evidence stand in for absence
