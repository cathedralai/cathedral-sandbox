# Affline attestation plan (honest, no fake TEE)

## Goal

Give Affline validators either:
1. a **Cathedral-signed full re-run receipt** (always available), or later
2. a **hardware-backed accept_receipt** path (live TDX/SNP only).

Never invent live TEE evidence. Affline sandboxes are **not** TEEs.

## Phases

| ID | Status | What | Artifact | TEE? |
|---|---|---|---|---|
| **A1** | available | Harbor / Affline sandbox trial | `cathedral_product_run_receipt_v1` (`required_validator_action=full_rerun`) | no |
| **A2** | available | Secret-triggered full re-run endpoint | `cathedral_affline_rerun_receipt_v1` (**Cathedral-signed**) | no |
| **A3** | available | CVM reference claim | `cathedral_affine_claim_v1` `binding_dev` | no |
| **A4** | **open gate** | Live TDX/SNP hardware re-verify on CvmHost | `evidence/affine-pilot/live-tee-claim-*.json` | **yes** |
| **A5** | blocked until A4 | Validator `accept_receipt` | `affine-claim validate` → `accept_receipt` | yes |

### A2 — this endpoint (now)

```
POST /v1/affline/validate-rerun
Authorization: Bearer <key>
X-Cathedral-Affline-Trigger: <secret>   # if CATHEDRAL_AFFLINE_RERUN_SECRET set
```

Requires `CATHEDRAL_AFFLINE_RERUN_SIGNING_SEED` (32-byte hex). Receipt always has:
- `signer: "cathedral"`
- Ed25519 `signature`
- `force_full_rerun: true`
- `tee_claimed: false`, `intel_tdx_asserted: false`
- embedded `attestation_plan`

**Anti-fake:** rejects `force_full_rerun=false`, `invent_live_tee`, `tee_claimed`, etc. Never returns `accept_receipt`.

### A4 — live attestation (plan)

On a real **CvmHost** with Intel TDX or AMD SNP:

```bash
# 1) Admit hardware CVM (tee=tdx|snp), evidence re-verifies
# 2) Issue claim with hardware gate:
python -m cathedral.cli affine-claim issue-from-cvm \
  --cvm-document running-cvm.json \
  --require-hardware \
  --verify-code code.bin --verify-inputs in.bin --miner-payload payload.bin \
  --signing-key-file seed.key --signing-key-id cathedral-affine-1 \
  --out evidence/affine-pilot/live-tee-claim-<id>.json

# 3) Validator path may accept_receipt only when claim has:
#    confidential_cpu + attestation_independently_verified + skip_rerun_eligible
#    + affline_sandbox_tee_claimed=false + digests match
python -m cathedral.cli affine-claim validate ...
```

Do **not** drop `live-tee-claim-*.json` from macOS/reference stubs.

### A5 — accept_receipt

Only after A4. Kings / disputes / spot checks still **full_rerun**.

## Forbidden

- `affline_sandbox_tee_claimed=true`
- Minting `confidential_cpu` without `verify_hardware_evidence`
- `accept_receipt` from `/v1/affline/validate-rerun`
- Fabricating `live-tee-claim-*.json` without CvmHost hardware

## Env

| Variable | Role |
|---|---|
| `CATHEDRAL_SANDBOX_KEYS` | Bearer auth |
| `CATHEDRAL_AFFLINE_RERUN_SECRET` | Optional trigger header secret |
| `CATHEDRAL_AFFLINE_RERUN_SIGNING_SEED` | **Required** 32-byte hex Cathedral seed |
| `CATHEDRAL_AFFLINE_RERUN_SIGNING_KEY_ID` | Optional key id (default `cathedral-affline-rerun-1`) |
