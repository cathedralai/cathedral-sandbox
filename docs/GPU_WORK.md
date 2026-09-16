# Signed GPU work endpoints

This is a prelaunch worker implementation. Hardware-free acceptance passes do
not prove a live confidential-GPU run or reward. The native composite vendor
collector/verifier remains an external integration requirement; see
[GPU attestation](GPU_ATTESTATION.md) for its exact trust contract.

## Wire contract

All three GPU paths require the existing signed validator request, bound to
the worker hotkey, native TLS SPKI, HTTP path, request body, network and subnet.
Existing CPU evidence, capabilities and fleet schemas remain unchanged.

- `POST /v1/gpu-capabilities`, body `{}`: `cathedral_gpu_capability_v1`,
  `profile_id`, sorted `device_identity_digests`, `workload_id`, `elements`,
  `status: registered`, `verified: false`.
- `POST /v1/gpu-evidence`: the existing evidence-v2 request (`nonce_hex`,
  `assigned_hotkey`, `report_data_version: 2`, `channel_binding_type`,
  `channel_binding_digest_hex`). Returns `schema: cathedral_gpu_evidence_v1`
  and `evidence`, exactly one bounded TDX component and one GPU component.
- `POST /v1/gpu-work`: the exact request below. Returns
  `schema: cathedral_gpu_result_v1`, `request_digest`, `output_digest`,
  `device_identity_digests`, and `completion_evidence` in the same component
  format. GPU or completion failure returns 503 without a successful result.

The work request has exactly these fields:

```json
{
  "schema": "cathedral_gpu_work_v1",
  "challenge_id": "<64 lowercase hex>",
  "nonce": "<fresh 32-byte validator nonce, lowercase hex>",
  "assigned_hotkey": "<worker hotkey>",
  "profile_id": "<approved profile ID>",
  "device_identity_digests": ["sha256:<approved GPU identity digest>"],
  "seed": "<32-byte validator seed, lowercase hex>",
  "elements": 4096,
  "workload_id": "cuda_i32_vector_v1"
}
```

Canonical JSON uses sorted keys, no whitespace, ASCII escaping and no NaN.
`challenge_id` hashes `cathedral-gpu-work-v1\0` followed by canonical request
without `challenge_id`. `request_digest` hashes the complete canonical request
and is prefixed `sha256:`. The shared executable definitions are in
`cathedral.gpu_work`; validators should pin this contract version.

For index `i`, hash `cathedral-gpu-vector-v1\0`, the decoded seed, then little
endian uint32 `i`. The first and next two digest bytes, interpreted little
endian and masked with 32767, are the two input integers. The CUDA kernel
multiplies the vectors on every configured device. The output digest hashes
the little endian int32 products concatenated once per device, in sorted
identity order. The validator independently recomputes these bytes.

Completion nonce hashes `cathedral-gpu-completion-v1\0` followed by canonical
JSON of `{request, output_digest, device_identity_digests}`. Completion's fresh
composite evidence binds that nonce to the same worker and TLS key. The
validator must check admission and completion against the same signed profile
and exact GPU identities and reject duplicate work across retries/restarts.

## Execution and trust boundary

The worker submits the fixed embedded PTX through `libcuda.so.1`; it never
selects a CPU backend. It enumerates CUDA UUIDs and requires exact agreement
with the configured device identity set. Each job runs in a separate process;
a 30-second timeout terminates that process and its CUDA contexts. One job
per worker can run at a time. No customer code, input files or credentials
enter this bounded workload. A failed or interrupted challenge must be retried
with a fresh signed validator request; the validator owns credit deduplication.

A matching output alone does not establish GPU execution. That conclusion
also requires genuine composite attestation of the approved measured worker
and device session. A model string, collector response, capabilities response
or correct CPU-computable result cannot replace that verification. Topology
remains audit metadata; no new topology claim is introduced here.

The current native composite collector receives the existing challenge
contract. There is no assertion that two separately valid reports are joined.
Google Confidential Space's token-based collector and verifier are genuine
implementations preserved on superseded PR #42, but require their own explicit
provider-profile adapter; they are not compatible with the raw native quote
contract.

## Item acceptance

```sh
python3 -m pytest -q tests/test_gpu_worker.py tests/test_gpu.py tests/test_cli.py \
  -k 'gpu or production_runtime_parser'
```

This tests signed TLS transport, request/result binding, unsigned rejection,
unchanged CPU formats, explicit configuration, missing CUDA, timeout and wrong
output. The transport test uses synthetic evidence and an injected executor;
it is not live hardware evidence. The PTX path still needs an actual supported
GPU run and authentic admission/completion before live qualification.
