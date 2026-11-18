# cathedral-snp-verifier

Offline verifier for Cathedral sealed-hotel attestations and receipts on AMD SEV-SNP. Go standard library only. It never touches the network: the caller supplies the AMD certificates.

It is a second implementation of `room-kit/verify_receipts.py` and must stay in step with it.

The guarantee, and no wider: with the same pins and expected measurement, this checker says PASS only when the Python checker, run with its default options, says PASS. It can say FAIL where Python says PASS; those cases are listed under "Differences from the Python checker" and in the tests.

Precise scope: the comparison is this CLI given `--attestation`, `--receipts` or `--receipt-header`, `--ark-sha256` pins and at most one `--expected-measurement`, against `verify_receipts.py --attestation ... --receipts/--receipt-header ... --ark-sha256 ... [--expected-measurement ...]`. `--allowed-measurement` has no Python counterpart; the parity statement does not cover it.

Parity point: `room-kit/verify_receipts.py` at origin/main `b73f90e` (18 Nov 2026). The table under "Parity with the Python checker" lists every rejecting check of that file and where it lives here. When the Python checker gains a check, this table and the code move together.

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

17. Guest ingress: a binding that names `guest_ingress` must name a `cathedral_guest_ingress_v1` object with a 64 lower-case hex `tls_spki_sha256` (`guest_tls_malformed`). It runs right after step 13.
18. Receipt statements: `schema` is `cathedral_sealed_hotel_receipt_v1` (`receipt_schema`), no sequence appears twice (`receipt_sequence_repeat`), and each create with a `start_command` has a matching `start_command_sha256` (`start_command_mismatch`). Snapshot members are well formed for the action (`snapshot_malformed`, checked per receipt before anything else).
19. Snapshots and forks: each content hash recomputes from its two parts, repeats of a snapshot agree, and a fork whose snapshot receipt is in the list names a successful first snapshot of the same id, content and source room, earlier by sequence, and not after the snapshot's delete (`snapshot_edge`). A fork naming a receipt not in the list is not checked, as in Python.
20. Room numbering: a room whose receipts all carry `room_sequence` and `room_previous_receipt_sha256` runs 1 to n with no gap, no repeat and every link right; serial rooms and `room_end` follow their rules (`room_numbering`). A room with only some numbering is not claimed and not failed, as in Python. A receipts object's `count` and `room_head` must agree with the receipts (`list_document`).
21. Pool rooms: a pool create is receipt 1 of its room, its claim is receipt 2 with the right target, `pooled_from` and, when it succeeded, a lower-case UUID link and a positive `lifetime_seconds` (`pool_room`). A claimed room's link is added to `room_links`.
22. Network policy event types: `issued_at` and `status` are integers, `mode` is a string and `allow` a list, before the hash is compared (`network_policy_mismatch`).

The order at run time is Python's: the guest TLS and ingress checks (steps 13 and 17) run after the attestation and before the receipts; steps 14 to 16 and 19 to 22 run after the receipts. `VerifyAll` runs all of them in that order; the CLI uses it.

Malformed input gives `bad_input` or `receipt_malformed`. Every failure returns exactly one code. The PASS verdict says what was not checked: `measurement_checked` is false without `--expected-measurement`, `receipts_checked` is false without receipts.

## What it does NOT prove

- Approval of the measurement. The measurement list is the caller's. Image approval (a signed policy release) is a later step.
- Freshness. A valid attestation and receipts can be replayed; nothing here shows they are recent.
- That what a receipt says happened is true, beyond the measured code having signed it.
- That the receipts shown are all the receipts of a room. A head is named by the server and is not signed, so even a whole chain does not prove that nothing was cut from its end. A new boot or a restart of the receipts service makes a new key and a new chain. Rooms removed by the TTL reaper or a bulk delete get no delete receipt.
- Isolation of any sandbox.
- A minimum TCB. The reported TCB must match the VCEK and the binding, but there is no floor on it yet.
- The owner check for a dedicated machine, and the TLS modes that compare a peer key. The Python checker has them as options; this one does not.

## Run

```
go run . \
  --attestation snpverify/testdata/attestation-proof.json \
  --receipts snpverify/testdata/receipts-first5.json \
  --ark snpverify/testdata/amd/ark.der --ask snpverify/testdata/amd/ask.der --vcek snpverify/testdata/amd/vcek.der \
  --ark-sha256 4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1
```

Flags: `--attestation FILE`, `--receipts FILE` (list, or object with a `receipts` list), `--receipt-header B64` (repeatable), `--ark`, `--ask`, `--vcek` (DER), `--ark-sha256 HEX` (repeatable, required, no default), `--expected-measurement HEX` (at most once; a repeat exits 2), `--allowed-measurement HEX` (repeatable, any match passes, no Python counterpart; not combinable with `--expected-measurement`), `--require-measurement` (satisfied by either measurement flag), `--product Genoa|Milan`. As in the Python tool, a `head` in an unfiltered receipts object is the head, unless `--receipt-header` is given; there is no `--head` flag. Positional arguments are refused (exit 2).

On PASS or FAIL the output is one JSON object on stdout with `verdict`, and `code` and `detail` on FAIL. Exit 0 on PASS, 1 on FAIL. A usage error prints a message on stderr, no JSON, and exits 2.

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
- Documents are read under Python's raw-text limits (`load_json_bounded`): nesting of `[` and `{` deeper than 64, or a run of number characters (digits, signs, point, `e`) longer than 100, is refused. Also refused here: a float that overflows (Python prints `Infinity`), receipt sequences more than 10,000,000 apart (Python runs out of memory).
- Unpaired UTF-16 surrogate escapes in JSON strings are refused; Python fails on them when it encodes.
- `kernel_cmdline`, when present, must be a string (Python crashes or treats falsy values as empty).
- Product: same rule as Python (CPUID family 0x19, model 0x10 or more is Genoa, else Milan; version 3 and later), but certificates are supplied, not fetched. Other products fail with `unsupported_product`. An override (`--product`) is used only when the report does not name the product; one that disagrees with the report fails.
- Where Python would crash on a missing or mistyped field in the policy, tunables, link or TLS checks (for example a policy that is not an object, or a room id that is a list), this checker fails: with `receipt_malformed` when a statement field has the wrong type, otherwise with the code of that check.
- A create receipt with a non-integer status fails, rather than being read the way Python `int()` reads it.
- Receipts documents: a list, or an object whose `receipts` is a list; anything else fails. `head`, when present, must be a non-empty string; `filtered`, when present, must be a boolean. Each receipt needs string `receipt_sha256`, `signature_b64`, `binding_sha256`, `previous_receipt_sha256`, `action`, and an integer `sequence` of 1 or more.
- Statement fields have fixed JSON types here, and a wrong type fails with `receipt_malformed` where Python may accept it: `sandbox_id`, `cathedral_sandbox_id`, `network_policy_sha256`, `tunables_sha256` are a string or null; `network_policy` and `tunables` are an object or null; `status` is an integer that fits int64, or null; `issued_at`, when present, is an integer that fits int64; `sequence` is an integer of 1 or more.
- `--allowed-measurement` exists only here. There is no `--head` flag, and `--expected-measurement` may be given once.
- Receipt headers decode only the base64url alphabet (`A-Z a-z 0-9 - _`) with optional `=` padding and no trimming. Python also takes `+` and `/` and drops other bytes.
- `report_b64` and the receipt key are decoded strictly, as Python's shape check does (`validate=True`): standard alphabet and padding, no CR, LF, space or other byte. Receipt signatures use the same alphabet; Go's decoder ignores CR and LF there and rejects any other stray byte, where Python drops every byte outside the alphabet.
- Positional command-line arguments are refused.
- At least one ARK pin is required; Python makes the pin optional.
- `previous_receipt_sha256` must be a string here; Python also takes null. Integers that do not fit int64 (`room_sequence`, `lifetime_seconds`, `snapshot_size_bytes`, `count`) fail here; Python reads them. An empty `report_b64` fails here at the length check; Python's shape check passes it and fails at the same place.
- Certificate validity dates and revocation are not checked (as in Python).

### Not implemented

Owner and dedicated checks (`--owner-pubkey`), the peer-SPKI and `--require-tls` modes of the TLS and ingress checks, `--origin` and `--broker` fetching, archived bindings (`--operator-key-file`), hotel-level bindings, the `--cathedral-sandbox` option, `--min-genoa-snp-spl` and run mode (`--oneshot` and its flags) are not implemented. They are options a Python user must ask for, so their absence cannot turn a Python FAIL into a Go PASS under default options. A PASS here says nothing about them: no owner was checked, no TCB floor was applied, no run file was read, and no archived binding was loaded. Where Python needs an input this CLI cannot receive, it fails closed: receipts that name an earlier binding than the attestation fail with `receipt_binding_mismatch` (Python asks for `--broker` and `--operator-key-file`), and a hotel-level binding fails with `not_sealed`. Python's `--skip-amd` (not a default) is not offered either.

## Parity with the Python checker

`room-kit/verify_receipts.py` at `b73f90e`. Lines are in that file. "Status" is `ported` (added in this branch), `present` (already here before) or `N/A` with the reason.

| Python check | Line | Go | Status |
|---|---|---|---|
| Raw JSON limits: depth 64, number token 100 | 1417, 1423, 1500 | `snpverify/canonical.go` `checkRawLimits` | ported |
| Attestation shape: key is base64 of 32 bytes, `report_b64` strict base64, five report fields are strings | 1260 | `attestation.go` `checkAttestationShape`, `strictBase64` | ported |
| Receipt shape: statement object, string fields, integer sequence and status, string-or-null room | 1235 | `receipt.go` `validateReceipt` | present (Go is stricter on null `previous_receipt_sha256`) |
| Snapshot member presence and form per action | 889 to 955 | `snapshots.go` `checkSnapshotShapes` | ported |
| Receipt schema is the sealed one (AB#710) | 689 | `receipt.go` `VerifyReceipts` | ported |
| Binding, hash, signature per receipt | 691 to 702 | `receipt.go` `VerifyReceipts` | present |
| Repeated receipt sequence (AB#710) | 703 | `receipt.go` `VerifyReceipts` | ported |
| Chain links, gaps, head | 707 to 721 | `receipt.go` `VerifyReceipts` | present |
| Start command hash (AB#709) | 1215 | `receipt.go` `checkStartCommands` | ported |
| Snapshot content hash, repeats, fork edges, fork after delete (AB#604) | 958 to 1053 | `snapshots.go` `checkSnapshotEdges` | ported |
| Per-room numbering, serial rooms, `room_end` reason (AB#484) | 1069 to 1112, 1132 | `rooms.go` `checkRoomNumbering` | ported |
| List `count` and `room_head` | 1186 to 1203 | `rooms.go` `checkListDocument` | ported |
| Pool rooms and claims (AB#484) | 753 | `rooms.go` `checkPoolRooms` | ported |
| Pool claim link in `room_links` | 829 | `checks.go` `VerifyAllWithList` | ported |
| Policy event types, mode and allow shape | 1294 | `checks.go` `policyTimeline` | ported |
| Tunables hash | 732 | `checks.go` `roomTunables` | present |
| Sandbox link is a lower-case UUID | 829 | `checks.go` `roomLinks` | present |
| Guest TLS fields | 513 | `checks.go` `verifyGuestTLS` | present |
| Guest ingress key (AB#422) | 544 | `checks.go` `verifyGuestIngress` | ported |
| Empty `head` refused (AB#484) | main | `receipt.go` `ParseReceiptsDocument` | present |
| Attestation: binding hash, REPORT_DATA, fields, debug, measurement, AMD chain | 459 | `attestation.go`, `amd.go` | present |
| Receipts naming an earlier binding need the broker (AB#381) | 2469 | `receipt.go` `VerifyReceipts` | N/A: no broker input here; fails closed with `receipt_binding_mismatch` |
| Genoa SNP TCB floor `--min-genoa-snp-spl` (AB#809) | 490 | none | N/A: option, no flag here; not checked, and a PASS does not claim it |
| Owner key and signed creates `--owner-pubkey` | 637, 664 | none | N/A: option, not implemented; not checked |
| Peer TLS and ingress modes, `--origin`, install key | 513, 544, 570 | none | N/A: need a live peer; not checked |
| Run mode `--oneshot` (AB#484) | 2284 | none | N/A: separate mode, no flags here; usage error |
| Redirect refusal on Python HTTP clients (AB#749) | 288 | none | N/A: this CLI never uses the network |
| Failed pool delete keeps a room `unknown` | 817 | none | N/A: only an output state, no rejection |

Differential check: `CATHEDRAL_DIFF_OUT=$DIR go test ./snpverify` writes every parity case with the Go verdict, and `python3 -I scripts/differential_receipts.py $DIR/cases.json ../../room-kit/verify_receipts.py` runs Python over the same files and fails on any case Go passes and Python rejects. It covers the receipt and attestation-shape layer, not the AMD chain.

## Canonical JSON

`Canonical` follows Python `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()` as Python does, with the refusals listed above. Fixtures are in `snpverify/testdata/` (see its README).
