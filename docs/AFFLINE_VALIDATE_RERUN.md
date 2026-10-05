# Affline validate-rerun endpoint

**Route:** `POST /v1/affline/validate-rerun`  
**Auth:** `Authorization: Bearer <sandbox-key>`  
**Secret trigger:** when `CATHEDRAL_AFFLINE_RERUN_SECRET` is set, also require
`X-Cathedral-Affline-Trigger: <secret>`.  
**Cathedral signature:** **required** via `CATHEDRAL_AFFLINE_RERUN_SIGNING_SEED`
(32-byte hex). Missing seed → HTTP 503.

Always forces Affine **full re-run** and returns a signed
`cathedral_affline_rerun_receipt_v1`. Never returns `accept_receipt`. Never sets
`tee_claimed` / Affline sandbox TEE. See [AFFLINE_ATTESTATION_PLAN.md](AFFLINE_ATTESTATION_PLAN.md).

## Anti-fake (rejected)

Request must **not** set truthy: `tee_claimed`, `affline_sandbox_tee_claimed`,
`invent_live_tee`, `simulate_hardware_attestation`, `skip_rerun_authorized`,
`accept_receipt`, `fabricate_attestation`, or `force_full_rerun=false`.

## Request

```json
{
  "claim_base64": "<cathedral_affine_claim_v1 bytes>",
  "trusted_keys": { "schema": "cathedral_affine_claim_trusted_keys_v1", "keys": {} },
  "verify_code_base64": "...",
  "verify_inputs_base64": "...",
  "miner_payload_base64": "...",
  "run_id": "optional-operator-id"
}
```

## Response (Cathedral-signed)

```json
{
  "schema": "cathedral_affline_rerun_receipt_v1",
  "signer": "cathedral",
  "signing_key_id": "cathedral-affline-rerun-1",
  "signature": { "algorithm": "ed25519", "value_base64": "…" },
  "tee_claimed": false,
  "affline_sandbox_tee_claimed": false,
  "intel_tdx_asserted": false,
  "required_validator_action": "full_rerun",
  "force_full_rerun": true,
  "decision": { "action": "full_rerun", "full_rerun_result": { "passed": true, "score": 91 } },
  "full_rerun": { "triggered": true, "observed_digests": { "…" : "…" } },
  "honesty": {
    "this_endpoint_never_accept_receipt": true,
    "no_fabricated_attestation": true,
    "live_tee_gate_open": true
  },
  "attestation_plan": { "phase": "plan", "steps": ["A1"…"A5"] }
}
```

## Env

| Variable | Purpose |
|---|---|
| `CATHEDRAL_SANDBOX_KEYS` | Bearer keys |
| `CATHEDRAL_AFFLINE_RERUN_SECRET` | Shared trigger secret |
| `CATHEDRAL_AFFLINE_RERUN_SIGNING_SEED` | **Required** Cathedral Ed25519 seed (64 hex chars) |
| `CATHEDRAL_AFFLINE_RERUN_SIGNING_KEY_ID` | Optional key id |

## Demo

```bash
python3 cathedral-audit/demo/run_affline_validate_rerun_demo.py
```
