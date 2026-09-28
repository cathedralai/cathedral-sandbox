# Offline hardware verification

SNP: call `verify_snp_offline(report, expected_report_data, policy, vcek_der=..., ask_der=..., ark_der=...)`.
Inputs are immutable DER bytes. All three certificates are copied into the fresh
private verification directory. The ARK SPKI pins and snpguest binary digest are
unchanged. The external `certs_dir` guard remains in place.

Set `CATHEDRAL_SNP_CAPTURE_DIR` in an online admission process to retain successful
verification snapshots. Each private JSON file contains the report and its chain.
Capture happens exactly once, after the report passed every admission-policy check
and the vendor chain verified, and outside the KDS retry loop. Rejected reports and
offline replays are never captured. A capture failure (unreadable or unparseable
chain, unwritable directory) is logged as a warning and never changes or repeats the
verdict. This change does not configure or restart a service.

TDX: build `cmd/cathedral-tdx-verifier` and use:

```
cathedral-tdx-verifier /absolute/quote.bin <report-data-hex> --capture-collateral /absolute/collateral.json
cathedral-tdx-verifier /absolute/quote.bin <report-data-hex> --collateral-bundle /absolute/collateral.json
```

The bundle contains the quote SHA-256 and the bounded Intel response headers and
bodies consumed during verification. Offline verification has an in-memory getter
without an HTTP client or fallback. It retains the embedded Intel root, signed
collateral checks, certificate validity at the local clock, CRLs, UpToDate checks
for the platform, module and QE, debug and migration restrictions, and REPORT_DATA.
Expired collateral still fails. A successful offline verdict reports
`collateral_current=false` because the latest Intel publication was not checked.
This is separate from production admission, which still requires current collateral.

Set `CATHEDRAL_TDX_CAPTURE_DIR` in an online admission process to retain quote and
collateral together. Captures attest to vendor verification, not the later parent
measurement-policy result. A configured TDX capture write failure still fails
verification closed. Capture is opt-in and no live admission wiring was tested.

## Capture files

Both capture directories use the same layout, with mode 0700 directories and 0600 files:

- `<sha256>.json` is the evidence itself (SNP report and chain, or TDX quote and
  collateral). It is named by the SHA-256 of its exact bytes, so identical evidence
  is stored once.
- `<sha256>.meta.json` is a sidecar record kept out of the evidence bytes:
  `{"schema": "cathedral_capture_metadata_v1", "capture": "<sha256>.json",
  "capture_sha256": "<sha256>", "captured_at": "<UTC ISO-8601>",
  "admission_nonce_hex": <hex or null>, "box_id": <string or null>}`.
  The nonce is the admission nonce passed to `verify()`. The box ID is filled when
  the caller passes `capture_box_id=` to `verify()`, `verify_snp()` or
  `verify_snp_report_data()`, and is `null` otherwise. The sidecar records the first
  capture of those bytes; an identical later capture leaves it unchanged. It is
  context for audits, not signed evidence.

`tdx_offline.verify_tdx_offline` reuses the static Linux ELF implementation-digest
contract and executes only a private copy of the authenticated bytes. Its digest
and executable path must come from local trust configuration, never the bundle.

## Evidence limits

The checked-in SNP report remains byte-for-byte unchanged. It has VMPL 1 and
platform_info 0x65, including reserved bit 6. Current admission requires VMPL 0
and a clear reserved bit. It is a rejection fixture, not a successful admission
fixture. Its public AMD chain was captured from the URLs in
`tests/fixtures/snp/offline/sources.json`.

The local host is macOS arm64. The pinned snpguest release is a Linux executable,
and the local Docker daemon is unavailable. Real SNP subprocess verification,
including a different-chip VCEK negative control, remains unproven here.
A supplemental OpenSSL test with Python networking denied verifies the pinned
AMD root, ASK and VCEK signatures and the unchanged report ECDSA signature.
It does not replace the pinned snpguest execution or admission-policy check. Existing
hardware tests remain gated on a real SNP guest.

The upstream Go TDX fixture fails the unchanged strict policy with
`TDX TCB info reported by Intel PCS failed TCB status check: no matching TCB level found`. No successful
real-vendor offline TDX verdict has been demonstrated in this batch. Network-denied
negative tests and process-boundary tests are not a replacement for that proof.
