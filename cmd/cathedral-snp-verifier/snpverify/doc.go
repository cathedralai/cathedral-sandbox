// Package snpverify checks a Cathedral sealed-hotel attestation and its signed
// receipts on AMD SEV-SNP, offline. It is a second implementation of
// room-kit/verify_receipts.py and must stay in step with it.
//
// VerifyAttestation checks, in order: the binding hash; the sealed schema;
// REPORT_DATA committing to the binding; measurement, chip id, TCB, HOST_DATA
// and policy equal to the binding; debug off; the measurement allow list; the
// product (Genoa or Milan); then
// the AMD chain (ARK pinned and self-signed, ARK signs ASK, ASK signs VCEK, VCEK
// hwID and SPL extensions equal the report, report signature verifies with the
// VCEK). VerifyReceipts then checks each receipt's binding, hash and Ed25519
// signature, and the links of the chain.
//
// The package never fetches anything: the caller passes the AMD certificates
// (DER) and the ARK pins.
//
// ParseAttestation, ParseReport, ParseReceipts, DecodeReceiptHeader,
// VerifyAttestation, VerifyAMDChain, VerifyReceipts and VerifyAll return a *VerifyError
// with one stable Code on failure. ParseKeepingNumbers and Canonical return
// plain errors.
//
// The guarantee, and no wider: with the same pins and expected measurement,
// VerifyAll says PASS only when verify_receipts.py, run with its default
// options, says PASS. The comparison is the CLI given an attestation, receipts
// or receipt headers, ARK pins and at most one expected measurement, against
// verify_receipts.py with the same inputs. It can fail where Python passes (duplicate keys, huge
// numbers, deep nesting, statement fields of an unexpected JSON type and the other cases in the README). Canonical formats
// numbers as Python's json.dumps does after json.loads.
//
// VerifyAll runs the attestation, the guest TLS fields, the receipts, and the
// network policy, tunables and sandbox link checks, in the order of the Python
// main(). Use it rather than the parts.
package snpverify
