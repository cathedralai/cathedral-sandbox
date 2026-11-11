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
// VerifyAttestation, VerifyAMDChain and VerifyReceipts return a *VerifyError
// with one stable Code on failure. ParseKeepingNumbers and Canonical return
// plain errors.
//
// For documents the measured front produces, Canonical gives the same bytes as
// Python. For other input this package is stricter and can fail where the Python
// checker passes; it is designed never to pass where the Python checker fails.
package snpverify
