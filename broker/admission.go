// Capacity plane, slice 2: admission of joined hotels.
//
// A hotel that joins at runtime (hotels.go) takes rooms only after it passes
// admission:
//
//   - health: the sync loop got a good /room/health answer (h.ok). A hotel
//     that goes down leaves placement at once and must pass again.
//   - attestation, for a hotel of class sealed: GET <health>/room/attestation
//     answers an SEV-SNP binding and report that agree (attestationCheck).
//     The pass is good for attest_ttl_seconds (default 600). The sync loop
//     checks again every attest_every_seconds (default 60), and at once after
//     the hotel was down: a reboot gives a new binding.
//
// Operator hotels from the config file are not gated, unless the hotel sets
// "require_attestation": true. Miner hotels are gated whether they came from
// the config or a runtime join.
// Config "sealed_admission": "off" turns the attestation gate off for joined
// operator hotels only. Miner hotels and require_attestation hotels always
// require attestation, a nonempty sealed_measurements and the AMD chain; the
// rollback lever must not admit an unverified miner, and a hotel that opted
// in is ungated only by removing the field.
//
// What the broker checks is the check verify_receipts.py makes before the AMD
// signature: binding_sha256 is the SHA-256 of the binding as served, the
// report's REPORT_DATA commits to it, measurement, chip id, TCB, policy and
// HOST_DATA in the report equal the binding, debug is off in the policy and
// on the kernel command line. With config "sealed_measurements" or
// "sealed_host_data" set, the measurement and HOST_DATA must be in the list.
//
// AMD chain (VCEK, ASK, ARK and the report signature). The broker does not
// verify it itself: with config "amd_verifier" it runs the repository's own
// verifier, room-kit/verify_receipts.py, on the attestation exactly as the
// hotel served it, with --require-sealed and the pinned ARK (amd_chain.go).
// The broker adds no new cryptography. The chain check runs once per binding
// (a new binding comes only with a reboot). It is required for a miner hotel
// (miner_hotkey set) and a require_attestation hotel: without amd_verifier
// such a hotel is refused. A joined sealed hotel without either is
// chain-checked when amd_verifier is set.
//
// Guest TLS: only a miner hotel binds the broker's TLS channel to its
// attestation (tls_spki_sha256, miner_tls.go). An operator hotel, joined or
// require_attestation, is reached over its configured address as before.
//
// One hotel per chip: a hotel whose report carries the CHIP_ID of another
// admitted gated hotel is refused (at join, 409 chip_in_use) or held refused
// (in the sync loop) with the other hotel's id as reason. It is admitted when
// the other hotel leaves placement and its own next check passes. Every SNP
// guest on one host reports the same CHIP_ID, so two hotels with one chip are
// one machine counted twice. An ungated hotel has no attested chip and never
// holds one: a config hotel can share a machine with a gated hotel.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

const (
	defaultAttestTTL   = 10 * time.Minute
	defaultAttestEvery = time.Minute
	attestRetry        = 5 * time.Second // a hotel that failed is asked again this often
	snpReportMinLen    = 0x4A0
	snpPolicyDebugBit  = 1 << 19
)

// admission is the attestation state of a hotel. Guarded by broker.mu.
type admission struct {
	attestedAt  time.Time // last pass; zero: never, or cleared by a failure or a down hotel
	checkedAt   time.Time // last check, pass or fail
	reason      string    // why the last check failed; "" after a pass
	measurement string
	bindingSHA  string
	chipID      string // first 16 hex characters
	chipFull    string // the whole CHIP_ID (128 hex characters): one hotel per chip
	// reportID is the REPORT_ID of the report (64 hex characters): the
	// firmware sets it at SNP launch, so a new value means a new launch
	// (lend.go). Empty when the report carries all zeros there.
	reportID string
	// amd is the AMD chain result (product, ark_sha256, tcb) of the binding
	// amdBinding; nil when the chain was not checked.
	amd        map[string]any
	amdBinding string
	// receiptKey is receipt_key_ed25519_b64 from the attested binding.
	// REPORT_DATA commits to that binding, so this is the guest receipt
	// public key. Empty when the binding omitted a 32-byte key.
	receiptKey []byte
}

// errChipInUse is a check that passed for a chip another admitted hotel has.
type errChipInUse struct{ other, chip string }

func (e errChipInUse) Error() string {
	return fmt.Sprintf("chip %s... is already hotel %s; one hotel per chip", e.chip, e.other)
}

func (b *broker) attestTTL() time.Duration {
	if b.cfg.AttestTTLSeconds > 0 {
		return time.Duration(b.cfg.AttestTTLSeconds * float64(time.Second))
	}
	return defaultAttestTTL
}

func (b *broker) attestEvery() time.Duration {
	if b.cfg.AttestEverySeconds > 0 {
		return time.Duration(b.cfg.AttestEverySeconds * float64(time.Second))
	}
	return defaultAttestEvery
}

// strictAttestation reports whether h must pass the gate with a nonempty
// sealed_measurements and the AMD chain, whatever sealed_admission says: a
// miner hotel, or a hotel that set require_attestation.
func strictAttestation(h *hotel) bool {
	return h.cfg.MinerHotkey != "" || h.cfg.RequireAttestation
}

// strictKind names a strict hotel in a refusal reason.
func strictKind(h *hotel) string {
	if h.cfg.MinerHotkey != "" {
		return "a miner hotel"
	}
	return "a require_attestation hotel"
}

// needsAttestation reports whether h must pass the attestation gate: every
// strict hotel (strictAttestation), and a joined operator hotel of class
// sealed. Caller holds b.mu.
func (b *broker) needsAttestation(h *hotel) bool {
	return strictAttestation(h) || (h.runtime && b.cfg.SealedAdmission != "off" && hotelClass(h) == classSealed)
}

// admitted reports whether h passed admission. Health is h.ok, checked by
// admissibleFree; this is the attestation part. Caller holds b.mu.
func (b *broker) admitted(h *hotel, now time.Time) bool {
	if strictAttestation(h) && len(b.cfg.SealedMeasurements) == 0 {
		return false
	}
	// Older state may contain an unsealed miner or a runtime hotel that claimed
	// a sealed label. Keep both out of placement after a restart as well.
	if h.cfg.MinerHotkey != "" && !h.cfg.Sealed {
		return false
	}
	if h.cfg.MinerHotkey != "" && h.tlsPinErr != nil {
		return false
	}
	if h.runtime && !h.cfg.Sealed && h.labels()["sealed"] == "true" {
		return false
	}
	if !b.needsAttestation(h) {
		return true
	}
	return !h.adm.attestedAt.IsZero() && now.Sub(h.adm.attestedAt) < b.attestTTL()
}

// admissionState is "admitted", "pending" (no check yet) or "refused" for the
// hotel lists. Caller holds b.mu.
func (b *broker) admissionState(h *hotel, now time.Time) string {
	switch {
	case !h.ok:
		if h.adm.reason != "" {
			return "refused"
		}
		return "pending"
	case b.admitted(h, now):
		return "admitted"
	case h.adm.reason != "":
		return "refused"
	}
	return "pending"
}

// admissionDoc is the admission part of a hotel document. Caller holds b.mu.
func (b *broker) admissionDoc(h *hotel, now time.Time) map[string]any {
	d := map[string]any{"state": b.admissionState(h, now), "attestation_required": b.needsAttestation(h),
		"amd_chain_required": strictAttestation(h)}
	if h.adm.amd != nil && h.adm.amdBinding == h.adm.bindingSHA {
		d["amd_chain"] = h.adm.amd
	}
	if h.adm.reason != "" {
		d["reason"] = h.adm.reason
	}
	if !h.adm.attestedAt.IsZero() {
		d["attested_at"] = h.adm.attestedAt.UTC().Format(time.RFC3339)
		d["measurement"] = h.adm.measurement
		d["binding_sha256"] = h.adm.bindingSHA
		d["chip_id"] = h.adm.chipID
		if h.adm.reportID != "" {
			d["report_id"] = h.adm.reportID
		}
	}
	return d
}

// attestDue reports whether the sync loop should check h's attestation now.
// Caller holds b.mu.
func (b *broker) attestDue(h *hotel, now time.Time) bool {
	if !b.needsAttestation(h) {
		return false
	}
	if h.adm.checkedAt.IsZero() || h.adm.attestedAt.IsZero() {
		return now.Sub(h.adm.checkedAt) >= attestRetry
	}
	return now.Sub(h.adm.checkedAt) >= b.attestEvery()
}

// attestFetchErr is a check that did not get an answer. It does not clear an
// earlier pass: that pass runs out at attest_ttl_seconds, and health takes a
// dead hotel out sooner.
type attestFetchErr struct{ error }

// checkAttestation fetches and checks h's attestation. It does not lock.
func (b *broker) checkAttestation(ctx context.Context, h *hotel) (admission, error) {
	if strictAttestation(h) && len(b.cfg.SealedMeasurements) == 0 {
		return admission{}, errors.New(strictKind(h) + " needs a nonempty sealed_measurements allowlist")
	}
	var att struct {
		Binding    json.RawMessage `json:"binding"`
		BindingSHA string          `json:"binding_sha256"`
		Report     string          `json:"report_b64"`
	}
	status, _, raw, err := h.doBase(ctx, h.cfg.Health, "GET", "/room/attestation", nil, nil, 10*time.Second)
	if err != nil || status != 200 || json.Unmarshal(raw, &att) != nil {
		return admission{}, attestFetchErr{errors.New("the hotel did not answer GET /room/attestation")}
	}
	res, err := verifyAttestation(att.Binding, att.BindingSHA, att.Report, b.cfg.SealedMeasurements, b.cfg.SealedHostData)
	if err != nil {
		return res, err
	}
	if h.cfg.MinerHotkey != "" {
		if err := verifyMinerTLSBinding(att.Binding, h.cfg.TLSSPKISHA256); err != nil {
			return admission{}, err
		}
	}
	if b.cfg.AMDVerifier == nil && !strictAttestation(h) {
		return res, nil // chain not checked: an operator hotel with no verifier configured
	}
	if b.cfg.AMDVerifier == nil {
		return admission{}, errors.New(strictKind(h) + " needs the AMD chain check; set amd_verifier in the broker config")
	}
	b.mu.Lock()
	known := h.adm.amd != nil && h.adm.amdBinding == res.bindingSHA
	prev := h.adm.amd
	b.mu.Unlock()
	if !known {
		if prev, err = b.verifyAMDChain(ctx, raw); err != nil {
			return admission{}, err
		}
	}
	res.amd, res.amdBinding = prev, res.bindingSHA
	return res, nil
}

// snpBinding is the part of a sealed hotel's binding the broker compares.
type snpBinding struct {
	Level          string `json:"level"`
	Measurement    string `json:"measurement"`
	ChipID         string `json:"chip_id"`
	ReportedTCB    string `json:"reported_tcb"`
	Policy         string `json:"policy"`
	HostData       string `json:"host_data"`
	KernelCmdline  string `json:"kernel_cmdline"`
	ReceiptKeyB64  string `json:"receipt_key_ed25519_b64"`
	TLSSPKISHA256  string `json:"tls_spki_sha256"`
	HotelKeySource string `json:"hotel_key_source"`
}

func verifyMinerTLSBinding(rawBinding []byte, peerSPKI string) error {
	var bd snpBinding
	if json.Unmarshal(rawBinding, &bd) != nil || len(peerSPKI) != 64 || bd.TLSSPKISHA256 != peerSPKI {
		return errors.New("miner guest TLS key does not match its SNP binding")
	}
	if bd.HotelKeySource != "install" {
		return errors.New("miner hotel key was not installed inside the guest")
	}
	return nil
}

// verifyMinerBootstrap checks a keyless HTTPS attestation before the broker
// constructs any client that holds the hotel key.
func (b *broker) verifyMinerBootstrap(ctx context.Context, raw []byte, peerSPKI string) error {
	if len(b.cfg.SealedMeasurements) == 0 {
		return errors.New("a miner hotel needs a nonempty sealed_measurements allowlist")
	}
	var att struct {
		Binding    json.RawMessage `json:"binding"`
		BindingSHA string          `json:"binding_sha256"`
		Report     string          `json:"report_b64"`
	}
	if json.Unmarshal(raw, &att) != nil {
		return errors.New("miner attestation is not JSON")
	}
	if _, err := verifyAttestation(att.Binding, att.BindingSHA, att.Report, b.cfg.SealedMeasurements, b.cfg.SealedHostData); err != nil {
		return err
	}
	if err := verifyMinerTLSBinding(att.Binding, peerSPKI); err != nil {
		return err
	}
	if b.cfg.AMDVerifier == nil {
		return errors.New("a miner hotel needs the AMD chain check")
	}
	_, err := b.verifyAMDChain(ctx, raw)
	return err
}

// verifyAttestation is the check of the package comment. rawBinding is the
// binding exactly as the hotel served it (room_receipts.py serves canonical
// JSON, so these bytes are the bytes binding_sha256 was taken over).
func verifyAttestation(rawBinding []byte, bindingSHA, reportB64 string, measurements, hostData []string) (admission, error) {
	fail := func(format string, a ...any) (admission, error) { return admission{}, fmt.Errorf(format, a...) }
	if len(rawBinding) == 0 || rawBinding[0] != '{' {
		return fail("no binding")
	}
	sum := sha256.Sum256(rawBinding)
	bsha := hex.EncodeToString(sum[:])
	if !strings.EqualFold(bindingSHA, bsha) {
		return fail("binding_sha256 does not match the binding")
	}
	var bd snpBinding
	if err := json.Unmarshal(rawBinding, &bd); err != nil {
		return fail("binding is not a JSON object")
	}
	if bd.Level == "hotel" || reportB64 == "" {
		return fail("level 1 binding: the hotel has no SEV-SNP report")
	}
	report, err := base64.StdEncoding.DecodeString(reportB64)
	if err != nil {
		return fail("report_b64 is not base64")
	}
	if len(report) < snpReportMinLen {
		return fail("report is %d bytes, expected 1184", len(report))
	}
	want := append(append([]byte{}, sum[:]...), make([]byte, 32)...)
	if !bytes.Equal(report[0x50:0x90], want) {
		return fail("REPORT_DATA does not commit to the binding")
	}
	measurement := hex.EncodeToString(report[0x90:0xC0])
	if measurement != strings.ToLower(bd.Measurement) {
		return fail("report measurement differs from the binding")
	}
	if hex.EncodeToString(report[0x1A0:0x1E0]) != strings.ToLower(bd.ChipID) {
		return fail("report chip id differs from the binding")
	}
	if hex.EncodeToString(report[0x180:0x188]) != strings.ToLower(bd.ReportedTCB) {
		return fail("report TCB differs from the binding")
	}
	host := hex.EncodeToString(report[0xC0:0xE0])
	if host != strings.ToLower(bd.HostData) {
		return fail("report HOST_DATA differs from the binding")
	}
	policy := binary.LittleEndian.Uint64(report[0x08:0x10])
	if fmt.Sprintf("%#x", policy) != strings.ToLower(bd.Policy) {
		return fail("report policy differs from the binding")
	}
	if policy&snpPolicyDebugBit != 0 {
		return fail("guest policy allows debug")
	}
	for _, f := range strings.Fields(bd.KernelCmdline) {
		if f == "cathedral.debug=1" {
			return fail("debug build: the host can log in to this guest")
		}
	}
	if len(measurements) > 0 && !inFold(measurements, measurement) {
		return fail("measurement %s... is not in sealed_measurements", measurement[:16])
	}
	if len(hostData) > 0 && !inFold(hostData, host) {
		return fail("HOST_DATA %s... is not in sealed_host_data", host[:16])
	}
	chip := hex.EncodeToString(report[0x1A0:0x1E0])
	var receiptKey []byte
	if raw, decErr := base64.StdEncoding.DecodeString(bd.ReceiptKeyB64); decErr == nil && len(raw) == 32 {
		receiptKey = raw
	}
	return admission{measurement: measurement, bindingSHA: bsha, chipID: chip[:16], chipFull: chip, receiptKey: receiptKey,
		reportID: snpReportID(report)}, nil
}

// snpReportID is the REPORT_ID of an SEV-SNP attestation report as hex, or
// "" when it is all zeros. AMD SEV-SNP ABI, ATTESTATION_REPORT: REPORT_ID is
// at offset 0x140, 32 bytes, after HOST_DATA 0xC0 (32), ID_KEY_DIGEST 0xE0
// (48) and AUTHOR_KEY_DIGEST 0x110 (48), and before REPORT_ID_MA 0x160 (32)
// and REPORTED_TCB 0x180. (0x50 is REPORT_DATA, not REPORT_ID.)
func snpReportID(report []byte) string {
	id := report[0x140:0x160]
	if bytes.Equal(id, make([]byte, len(id))) {
		return ""
	}
	return hex.EncodeToString(id)
}

func inFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), v) {
			return true
		}
	}
	return false
}

// chipHolder is the admitted gated hotel other than h whose chip is chip, or
// nil. An ungated hotel (a config hotel without require_attestation) holds no
// chip: it was never attested. Caller holds b.mu.
func (b *broker) chipHolder(h *hotel, chip string, now time.Time) *hotel {
	for _, o := range b.hotelList() {
		if o != h && !o.leaving && b.needsAttestation(o) && o.adm.chipFull == chip && !o.adm.attestedAt.IsZero() && b.admitted(o, now) {
			return o
		}
	}
	return nil
}

// noteAttestation records a check and returns the error that decides it: err,
// or errChipInUse for a pass on a chip another admitted hotel has. Caller
// holds b.mu.
func (b *broker) noteAttestation(h *hotel, res admission, err error, now time.Time) error {
	was := b.admitted(h, now)
	h.adm.checkedAt = now
	if err == nil && res.chipFull != "" {
		if o := b.chipHolder(h, res.chipFull, now); o != nil {
			err = errChipInUse{other: o.cfg.ID, chip: res.chipID}
			// Keep what the check learned (chip, AMD result); only the pass is withheld.
			res.checkedAt, res.attestedAt, res.reason = now, time.Time{}, err.Error()
			h.adm = res
			if was || h.adm.reason != err.Error() {
				log.Printf("hotel %s refused: %v", h.cfg.ID, err)
			}
			return err
		}
	}
	var fe attestFetchErr
	switch {
	case err == nil:
		res.checkedAt, res.attestedAt = now, now
		h.adm = res
		if !was {
			log.Printf("hotel %s admitted: attestation passed (measurement %s...)", h.cfg.ID, res.measurement[:16])
		}
	case errors.As(err, &fe):
		h.adm.reason = err.Error() // an earlier pass stands until its TTL
	default:
		h.adm.attestedAt = time.Time{}
		if h.adm.reason != err.Error() || was {
			log.Printf("hotel %s refused: %v", h.cfg.ID, err)
		}
		h.adm.reason = err.Error()
	}
	return err
}

// syncAdmission runs the attestation step of the sync loop for h.
func (b *broker) syncAdmission(ctx context.Context, h *hotel, healthOK bool) {
	b.mu.Lock()
	due := healthOK && b.attestDue(h, time.Now())
	b.mu.Unlock()
	if !due {
		return
	}
	res, err := b.checkAttestation(ctx, h)
	b.mu.Lock()
	b.noteAttestation(h, res, err, time.Now())
	b.mu.Unlock()
}
