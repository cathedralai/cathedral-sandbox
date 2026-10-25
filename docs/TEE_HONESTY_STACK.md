# TEE honesty stack (TDX + SNP)

Status: **implemented** for shared admit root-pin; peer-subnet pattern.

Attestation **admits**. Verified work / measurement-allowed evidence **pays**.
Same controls for Intel TDX and AMD SEV-SNP; only the launch field differs.

## Controls

| # | Control | TDX | SNP | Where |
| --- | --- | --- | --- | --- |
| 1 | Complete vendor verify | QVL strict | snpguest + chain | `cathedral.verify` |
| 2 | Fresh REPORT_DATA v2 (nonce + hotkey + TLS SPKI) | quote body | report | `admission.admit` |
| 3 | Measurement allowlist | policy / list | policy / list | `admit` + `measurement_list` |
| 4 | Root bind to Cathedral central root | **MRCONFIGID** | **HOST_DATA** | `admit(..., expected_root_digest=)` + `tee_honesty.py` |
| 5 | Re-attest after customer release | `last_released_at` | same | `admit` |
| 6 | Fresh boot before new customer | RTMR3 zeros | relaunch / ops (no RTMR) | `require_fresh_boot` (TDX) |
| 7 | Admit ≠ pay | `measurement_allowed` + evidence | same | `admit` |

## Root pin API

```python
from cathedral.capacity.admission import admit
# after verify(...):
decision = admit(
    attested,
    quote,
    ...,
    expected_root_digest="sha256:<digest of central-root-keys.json>",
)
```

Refusal reasons: `root_binding_mismatch`, `root_binding_missing`, `root_binding_zero`.
Omit `expected_root_digest` for legacy callers (no remote root check).

SNP measurement-list images may include `"host_data": "<64 hex>"` so
`accept_release(..., expected_root_digest=)` pins the same digest.

## Polaris

`cathedral_tee_honesty.record_admit_honesty(...)` caches admit outcomes.
With `cathedral_unit_tee_honesty_gate_enabled=true`, hardware-TEE JobIntents
fail Security when a fresh observation shows admit/report_data/root failure.
Default **off**.

## What this does not replace

- A real SNP VMM stamp of HOST_DATA on cathedral-1/2 (#274)
- Job-pay / PROVEN_ABSENT (lifecycle issuer + policy)
- Custody enrollment for private miner supply
