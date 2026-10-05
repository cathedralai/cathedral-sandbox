# Product run receipts (host-trusted, validator-aligned)

**Honesty:** These are **not** sealed TDX `cathedral_customer_receipt_v1` and
**not** console `cathedral_box_receipt_v1`. Every product-run receipt sets
`tee_claimed=false` and `attestation_class=none`. Verifiers **reject**
`tee_claimed=true`, `evidence.skip_rerun_authorized=true`, and
`execution.attestation_hardware=true`.

| Need | Schema |
|---|---|
| Present “Affline/Ditto/… run happened” with fields validators check | `cathedral_product_run_receipt_v1` |
| Affline skip-rerun | `cathedral_affine_claim_v1` (separate; live TEE still open) |
| Sealed one-shot / console | customer / box receipts only |

Policy **v2** requires signed `execution` + `evidence` shaped to each product’s
real checker (`affine_validator`, `ditto_profile`, `qualify-client.validate_health`
/ `validate_load`, Agent interactive dims, CVM `AttestationEvidence`).

## Binding rules (fail-closed)

| Product | Rule |
|---|---|
| Affline | Product receipts always stamp `required_validator_action=full_rerun` and `skip_rerun_authorized=false`. Affine digest quartet / `verify_outcome=passed\|failed` **only** when `affine_claim_id` + `affine_claim_sha256` are set. Harbor-only uses `verify_outcome=not_applicable` with digests omitted. |
| Affline | `related_schemas` may list `cathedral_affine_claim_v1` only when a claim is linked. |
| Ditto | `expects_isolation` ∈ `{0,1}` (matches `CATHEDRAL_EXPECTS_ISOLATION`). `tier=ditto-ready` requires `expects_isolation=1` and score exit 0. |
| Reliquary | Health must match `qualify-client.validate_health` keys; `health_sha256` digests that object; `load.row=N_of_M` requires `parallel=N`; `max_p95_ms≤1000`; qualified tier requires `kvm\|systrap` + `surface=v1_workers`. |
| Agent | Lifecycle `at` strictly increasing; terminal cols/rows ≤1000; tickets TTL 1..300. |
| CVM | `attestation_evidence` matches lifecycle evidence fields; `evidence_sha256` digests it; `quote_b64` starts with `ref.`; running ⇒ `last_attest_at>0`. |

## CLI

```bash
PYTHONPATH=. python3 -m cathedral.cli product-run-receipt issue \
  --product affline --surface v1_sandboxes --run-id harbor-demo-1 \
  --request req.json --result res.json \
  --execution affline-execution.json --evidence affline-evidence.json \
  --outcome succeeded \
  --signing-key-file seed.key --signing-key-id demo-key \
  --out affline-run-receipt.json
```

Builders: `build_affline_execution`, `build_ditto_execution`,
`build_reliquary_execution`, `build_agent_execution`, `build_cvm_execution`.

## Per-service validator fields

### Affline (`harbor_sandbox_trial`)
Harbor: `sandbox_id`, `image`, `network`, `create_request_sha256`, `exec.{cmd,exit,stdout,stderr,duration,timed_out}`, task/dataset/agent.
Affine (only with linked claim): digest quartet matching `affine_validator._digests_match`, `verify_outcome`, `claim_attestation_class`, `execution_profile_id`.
**Always** `required_validator_action=full_rerun` and `skip_rerun_authorized=false` on this schema.
`accept_receipt` is only possible via separate `cathedral_affine_claim_v1` with `confidential_cpu` + independent HW re-verify (live TEE still open). Proof demo: `cathedral-audit/demo/run_affine_validator_rerun_proof.py`.

### Ditto (`ditto_harness_slot`)
`network.mode=none`, profile resources (1/2/10), `ttl_seconds`, `entrypoint`,
`quota.{max_running∈2..8, rejected_429, retry_after_seconds, cap_trial_exercised}`,
`score_probe.{cmd_sha256,exit_code,result_sha256,…}`, `expects_isolation`.

### Reliquary (`reliquary_workers`)
Health: `status=ok`, `protocol_version=2`, `executor_id==allocation_id`,
`runtime_id`, `sandbox_backend=runsc`, `sandbox_platform`,
`pool.{pool_size=50,workers_alive=50,retire_worker_after_batch=true,worker_reap_failures_total=0,container_delete_failures_total=0}`,
`api.max_inflight=50`.
Load: `row`, `requests`, `successful`, `parallel`, `runtime_id`, `latency_ms`,
`failures=[]`, `max_p95_ms`. `runtime_digest_is_host_tee=false`.

### Agent (`agent_ide_session`)
`network.mode=public`, increasing freeze/thaw timestamps, terminals with
`started_at`/`connected`/dims/exit/output digests, `access_tickets[{ttl_seconds,issued_at,consumed}]`.

### CVM (`cvm_lifecycle`)
`attestation_evidence.{quote_b64,measurement,nonce,issued_at_unix,tee,gpu_bound}`
matching `AttestationEvidence.to_document()` (unix int), `labels.customer=cvm`,
increasing lifecycle, `tee_kind=reference` only on this schema.

## Demo evidence

`cathedral-audit/demo/run_product_run_receipts_demo.sh` →
`cathedral-audit/evidence/product-run-receipts/*-run-receipt.json`
(includes Harbor-only Affline + optional claim-linked Affline sample).
