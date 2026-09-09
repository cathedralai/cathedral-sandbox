# Customer attestation bundle

The customer receipt v1 contract and its CLI output remain unchanged. It does not
bind a raw quote or box identity, so an independent hardware verdict is refused
for a legacy receipt.

The new `cathedral_customer_attestation_receipt_v1` schema retains every required
customer receipt field and adds a signed `hardware_binding` object:

```
{"box_id":"box-0001","quote_sha256":"<64 lowercase hex>","report_data_hex":"<128 lowercase hex>"}
```

Its policy digest is SHA-256 of the exact ASCII bytes
`cathedral.customer-attestation-receipt.policy.v1`, prefixed with `sha256:`.
It uses the existing canonical JSON and Ed25519 receipt signature implementation,
trusted key validity checks, status checks, billing consistency and age checks.
TDX receipts retain `execution_class=tdx_cpu`, `profile_id=attest.v1` and
`cpu_tee=intel_tdx`. SNP receipts use `execution_class=snp_cpu`,
`profile_id=attest.snp.v1` and `cpu_tee=amd_sev_snp`. SNP sets
`report_data_match=true`, `intel_verified=null`, zero GPU count and null GPU,
guest binding and runtime execution assertion fields. Other required receipt
assertions retain the original validation rules.

The serialized bundle is:

```
{
  "schema": "cathedral_customer_attestation_bundle_v1",
  "receipt_base64": "<exact canonical signed receipt bytes>",
  "evidence": {
    "kind": "sev_snp",
    "quote_base64": "<raw hardware report>",
    "collateral": {
      "vcek_base64": "<DER>",
      "ask_base64": "<DER>",
      "ark_base64": "<DER>"
    }
  }
}
```

For TDX, `kind` is `tdx` and `collateral` is one base64 string containing the
`cathedral_tdx_collateral_v1` JSON emitted by the workstream 1 Go verifier.
The API producer must retain the corresponding report and collateral at admission.
Never substitute a quote from another report, receipt, or box.

The independent verifier requires an external local keyring and local policy:

```
{"allowed_measurements":["<approved measurement>"],"min_snp_tcb":0}
```

The real deployment floor must replace the example zero. TDX always retains the
strict Intel UpToDate and no-advisory checks. The bundle supplies no executable,
trusted root, allowed measurement or TCB policy.

Success reports `evidence_independently_verified=true` and
`verification_scope=cathedral_receipt_and_vendor_hardware` only after both the
receipt and vendor chain succeed. This proves authenticity and the signed
receipt-to-evidence association. It does not independently prove the receipt's
execution, billing or teardown assertions. Offline replay is historical evidence,
not a fresh challenge, and does not establish the latest vendor revocation state.
Use `max_age_seconds` to require bounded receipt age.

## API owner blocker

The CLI expects a new read-only route. Proposed contract:

- Method and path: `GET /v1/console/boxes/{box}/attestation/bundle`.
- Request body: none. `Accept: application/json`.
- Authentication: Cathedral customer bearer key, `pool:control`, scoped to the
  authenticated allocation owner. A box identifier is never ownership authority.
- Success: exactly the bundle JSON above. The signed `hardware_binding.box_id`
  must equal the requested box. `Cache-Control: no-store`.
- Missing capture or compatible receipt: HTTP 404 with
  `{"error":{"code":"evidence_unavailable","message":"offline evidence bundle is unavailable"}}`.
- Wrong owner: refuse without disclosing evidence. Never mint a new quote or
  change allocation state as a side effect of this read.

This route and producer are not implemented here. The indexed attestation summary,
quote download and receipt routes do not supply this combined signed contract.
No customer authorization or real producer path was exercised.

## Fixture and implementation provenance

`tests/fixtures/attestation/snp-real-rejected-bundle.json` embeds the original real
SNP report and its AMD certificates, with a synthetic test receipt signed by the
existing deterministic unit-test key. The keyring and policy are fixture-only.
The expected result is `policy` rejection because the original report violates
current VMPL and reserved-bit policy. It is not a passing vendor demonstration.

The receipt branch is stacked on workstream 1 at cathedral-sandbox commit
`ef91fe1b3927dd2818c226182244a222651dd5f8`. It imports the shared SNP and TDX
offline engines directly. Existing task-policy validation and all existing
receipt and SNP tests remain unchanged by the receipt commit.

The former cathedral-compute remote redirects to cathedral-sandbox. The receipt
checkout was updated to the current sandbox base before creating the draft.
