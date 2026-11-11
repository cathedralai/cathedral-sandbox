# cathedral-snp-verifier

Offline verifier for Cathedral sealed-hotel attestations and receipts on AMD SEV-SNP. Go standard library only. It never touches the network: the caller supplies the AMD certificates.

It is a second implementation of `room-kit/verify_receipts.py` and must stay in step with it. For documents the measured front produces, the canonical bytes are the same as Python's. For other input this checker is stricter and can say FAIL where the Python checker says PASS. It is designed never to say PASS where the Python checker says FAIL; the tests list the known cases.

Scope: binding schema `cathedral_sealed_hotel_binding_v1` only. A level 1 "hotel" binding is refused with `not_sealed`.

## What it checks, in order

1. Binding: sha256 of the canonical binding equals `binding_sha256` (`binding_hash_mismatch`).
2. Schema is the sealed one (`not_sealed`).
3. SNP report: REPORT_DATA is `binding_sha256` followed by 32 zero bytes (`report_data_mismatch`).
4. Measurement, chip id, reported TCB, HOST_DATA and policy in the report equal the binding (`report_field_mismatch`).
5. Debug is off: policy bit 19, and no `cathedral.debug=1` word on the kernel command line, split like Python `str.split()` (`debug_enabled`). A `kernel_cmdline` that is not a string is `bad_input`.
6. The measurement is in `--expected-measurement` when any is given (`measurement_not_allowed`). `--require-measurement` (library: `RequireMeasurement`) makes an empty list a failure (`no_expected_measurement`).
7. Product: from the report CPUID (version 3 and later) or `--product`; only Genoa and Milan are handled (`unsupported_product`).
8. AMD chain: ARK is self-signed (`ark_signature`), ARK signed ASK (`ask_signature`), the ARK DER sha256 is one of the pins (`ark_not_pinned`), ASK signed VCEK (`vcek_signature`). All RSA-PSS SHA-384, salt 48.
9. VCEK hwID and bootloader, TEE, SNP and microcode SPL equal the report (`vcek_mismatch`).
10. The report signature, ECDSA P-384 SHA-384 over the first 0x2A0 bytes, verifies with a P-384 VCEK key (`report_signature`).
11. Receipts: each statement names this binding (`receipt_binding_mismatch`), `receipt_sha256` equals sha256 of the canonical statement (`receipt_hash_mismatch`), the Ed25519 signature verifies with the binding's `receipt_key_ed25519_b64` (`receipt_signature`).
12. Chain: receipt 1 links to the binding and each next receipt links to the one before it when present (`chain_link`). With a head: the chain starts at 1 with no gap (`chain_gap`) and ends at the head (`chain_head`).

Malformed input gives `bad_input` or `receipt_malformed`. Every failure returns exactly one code. The PASS verdict says what was not checked: `measurement_checked` is false without `--expected-measurement`, `receipts_checked` is false without receipts.

## What it does NOT prove

- Approval of the measurement. The measurement list is the caller's. Image approval (a signed policy release) is a later step.
- Freshness. A valid attestation and receipts can be replayed; nothing here shows they are recent.
- That what a receipt says happened is true, beyond the measured code having signed it.
- That the receipts shown are all the receipts of a room. A head is named by the server and is not signed, so even a whole chain does not prove that nothing was cut from its end. A new boot or a restart of the receipts service makes a new key and a new chain. Rooms removed by the TTL reaper or a bulk delete get no delete receipt.
- Isolation of any sandbox.
- A minimum TCB. The reported TCB must match the VCEK and the binding, but there is no floor on it yet.
- Policy, tunables, TLS, owner and sandbox-link checks. The Python checker has them; this one does not.

## Run

```
go run . \
  --attestation snpverify/testdata/attestation.json \
  --receipts snpverify/testdata/receipts-first5.json \
  --ark snpverify/testdata/amd/ark.der --ask snpverify/testdata/amd/ask.der --vcek snpverify/testdata/amd/vcek.der \
  --ark-sha256 4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1
```

Flags: `--attestation FILE`, `--receipts FILE` (list, or object with a `receipts` list), `--receipt-header B64` (repeatable), `--ark`, `--ask`, `--vcek` (DER), `--ark-sha256 HEX` (repeatable, required, no default), `--expected-measurement HEX` (repeatable), `--require-measurement`, `--product Genoa|Milan`, `--head HEX`. Without `--head`, a `head` in an unfiltered receipts object is used, as in the Python tool, unless `--receipt-header` is given. Positional arguments are refused (exit 2).

Output is one JSON object on stdout with `verdict` PASS or FAIL, and `code` and `detail` on FAIL. Exit 0 on PASS, 1 on FAIL, 2 on usage error.

```
go test -race -count=1 ./...
```

## Use as a library

```go
import "github.com/cathedralai/cathedralconfidential/cmd/cathedral-snp-verifier/snpverify"

att, err := snpverify.ParseAttestation(attJSON)
if err == nil {
	_, err = snpverify.VerifyAttestation(att, snpverify.Options{
		ARK: ark, ASK: ask, VCEK: vcek, ARKPins: pins, // DER bytes and sha256 hex pins
		ExpectedMeasurements: approved, RequireMeasurement: true,
	})
}
var ve *snpverify.VerifyError
if errors.As(err, &ve) && ve.Code() == snpverify.CodeMeasurementNotAllowed { /* branch on the code */ }
```

## Differences from the Python checker

- Duplicate object keys are refused here; Python keeps the last one.
- Number literals are kept as written and are not re-floated (only `-0` becomes `0`). A receipt with `1E5` or `1.50` in its statement fails here with `receipt_hash_mismatch` when its hash was made the Python way.
- Unpaired UTF-16 surrogate escapes in JSON strings are refused; Python fails on them when it encodes.
- `kernel_cmdline`, when present, must be a string (Python crashes or treats falsy values as empty).
- Product: same rule as Python (CPUID family 0x19, model 0x10 or more is Genoa, else Milan; version 3 and later), but certificates are supplied, not fetched. Other products fail with `unsupported_product`.
- Receipts documents: a list, or an object whose `receipts` is a list; anything else fails. `head`, when present, must be a non-empty string; `filtered`, when present, must be a boolean. Each receipt needs string `receipt_sha256`, `signature_b64`, `binding_sha256`, `previous_receipt_sha256`, `action`, and an integer `sequence` of 1 or more.
- Receipt headers decode only the base64url alphabet (`A-Z a-z 0-9 - _`) with optional `=` padding and no trimming. Python also takes `+` and `/` and drops other bytes.
- Report and receipt-signature base64 uses the standard alphabet with padding; Go rejects stray bytes, Python drops them.
- Positional command-line arguments are refused.
- At least one ARK pin is required; Python makes the pin optional.
- The receipt schema field is not checked (as in Python).
- Certificate validity dates and revocation are not checked (as in Python).
- Hotel-level bindings, owner, TLS and sandbox-link checks are not implemented here.

## Canonical JSON

`Canonical` follows Python `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()` for the documents the measured front produces. Fixtures are in `snpverify/testdata/` (see its README).
