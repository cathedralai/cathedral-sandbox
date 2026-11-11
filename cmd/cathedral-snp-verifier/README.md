# cathedral-snp-verifier

Offline verifier for Cathedral sealed-hotel attestations and receipts on AMD SEV-SNP. Go standard library only. It never touches the network: the caller supplies the AMD certificates.

It is a second implementation of `room-kit/verify_receipts.py` and must stay in step with it.

The guarantee, and no wider: with the same pins and expected measurement, this checker says PASS only when the Python checker, run with its default options, says PASS. It can say FAIL where Python says PASS; those cases are listed under "Differences from the Python checker" and in the tests.

Precise scope: the comparison is this CLI given `--attestation`, `--receipts` or `--receipt-header`, `--ark-sha256` pins and at most one `--expected-measurement`, against `verify_receipts.py --attestation ... --receipts/--receipt-header ... --ark-sha256 ... [--expected-measurement ...]`. `--allowed-measurement` has no Python counterpart; the parity statement does not cover it.

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

13. Guest TLS fields (Python default mode): a binding that names `tls_spki_sha256` must name 64 lower-case hex, a base64 32-byte install key, a non-empty list of base64 32-byte install signers, and `hotel_key_source` `install` (`guest_tls_malformed`). No TLS key means nothing to check.
14. Network policy: each receipt that carries `network_policy` for a room has `network_policy_sha256` equal to sha256 of the canonical policy (`network_policy_mismatch`).
15. Tunables: each create receipt that carries `tunables` has `tunables_sha256` equal to sha256 of the canonical tunables (`tunables_mismatch`).
16. Sandbox link: a create receipt that carries `cathedral_sandbox_id` carries a lower-case UUID (`sandbox_link_malformed`).

Steps 13 to 16 run in the same order as the Python `main()`, after the receipts. `VerifyAll` runs steps 1 to 16 in that order; the CLI uses it.

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
  --attestation snpverify/testdata/attestation-proof.json \
  --receipts snpverify/testdata/receipts-first5.json \
  --ark snpverify/testdata/amd/ark.der --ask snpverify/testdata/amd/ask.der --vcek snpverify/testdata/amd/vcek.der \
  --ark-sha256 4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1
```

Flags: `--attestation FILE`, `--receipts FILE` (list, or object with a `receipts` list), `--receipt-header B64` (repeatable), `--ark`, `--ask`, `--vcek` (DER), `--ark-sha256 HEX` (repeatable, required, no default), `--expected-measurement HEX` (at most once; a repeat exits 2), `--allowed-measurement HEX` (repeatable, any match passes, no Python counterpart; not combinable with `--expected-measurement`), `--require-measurement` (satisfied by either measurement flag), `--product Genoa|Milan`. As in the Python tool, a `head` in an unfiltered receipts object is the head, unless `--receipt-header` is given; there is no `--head` flag. Positional arguments are refused (exit 2).

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
- Numbers are canonicalised as Python does: an integer literal stays an integer (`-0` becomes `0`), a literal with `.`, `e` or `E` is a float printed with Python's repr (`1E5` is `100000.0`, `1.50` is `1.5`, `1e-5` is `1e-05`). A receipt whose hash was made over a literal-preserving form fails here, as it does in Python.
- Refused here, where Python would fail or print something else: an integer with more than 4300 digits (Python's limit), a float that overflows (Python prints `Infinity`), nesting deeper than 100 levels (Python's recursion limit), receipt sequences more than 10,000,000 apart (Python runs out of memory).
- Unpaired UTF-16 surrogate escapes in JSON strings are refused; Python fails on them when it encodes.
- `kernel_cmdline`, when present, must be a string (Python crashes or treats falsy values as empty).
- Product: same rule as Python (CPUID family 0x19, model 0x10 or more is Genoa, else Milan; version 3 and later), but certificates are supplied, not fetched. Other products fail with `unsupported_product`. An override (`--product`) is used only when the report does not name the product; one that disagrees with the report fails.
- Where Python would crash on a missing or mistyped field in the policy, tunables, link or TLS checks (for example a policy that is not an object, or a room id that is a list), this checker fails with the code of that check.
- A create receipt with a non-integer status fails, rather than being read the way Python `int()` reads it.
- Receipts documents: a list, or an object whose `receipts` is a list; anything else fails. `head`, when present, must be a non-empty string; `filtered`, when present, must be a boolean. Each receipt needs string `receipt_sha256`, `signature_b64`, `binding_sha256`, `previous_receipt_sha256`, `action`, and an integer `sequence` of 1 or more.
- Statement fields have fixed JSON types here, and a wrong type fails with `receipt_malformed` where Python may accept it: `sandbox_id`, `cathedral_sandbox_id`, `network_policy_sha256`, `tunables_sha256` are a string or null; `network_policy` and `tunables` are an object or null; `status` is an integer that fits int64, or null; `issued_at`, when present, is an integer that fits int64; `sequence` is an integer of 1 or more.
- `--allowed-measurement` exists only here. There is no `--head` flag, and `--expected-measurement` may be given once.
- Receipt headers decode only the base64url alphabet (`A-Z a-z 0-9 - _`) with optional `=` padding and no trimming. Python also takes `+` and `/` and drops other bytes.
- Report and receipt-signature base64 uses the standard alphabet with padding; Go rejects stray bytes, Python drops them.
- Positional command-line arguments are refused.
- At least one ARK pin is required; Python makes the pin optional.
- The receipt schema field is not checked (as in Python).
- Certificate validity dates and revocation are not checked (as in Python).

### Not implemented

Owner and dedicated checks (`--owner-pubkey`), the peer-SPKI and `--require-tls` modes of the TLS check, `--origin` and `--broker` fetching, hotel-level bindings, and the `--cathedral-sandbox` option are not implemented. They are options a Python user must ask for, so their absence cannot turn a Python FAIL into a Go PASS under default options. Python's `--skip-amd` (not a default) is not offered either.

## Canonical JSON

`Canonical` follows Python `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()` as Python does, with the refusals listed above. Fixtures are in `snpverify/testdata/` (see its README).
