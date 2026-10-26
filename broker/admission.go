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
// Hotels from the config file are not gated: their behavior is unchanged.
// Config "sealed_admission": "off" turns the attestation gate off for joined
// hotels too (a rollback lever, not a mode to run in).
//
// What the broker checks is the check verify_receipts.py makes before the AMD
// signature: binding_sha256 is the SHA-256 of the binding as served, the
// report's REPORT_DATA commits to it, measurement, chip id, TCB, policy and
// HOST_DATA in the report equal the binding, debug is off in the policy and
// on the kernel command line. With config "sealed_measurements" or
// "sealed_host_data" set, the measurement and HOST_DATA must be in the list.
// The broker does not check the AMD signature chain (VCEK, ASK, ARK); the
// guest checks it offline with verify_receipts.py, as before. The broker adds
// no new cryptography.
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

// needsAttestation reports whether h must pass the attestation gate: a
// joined hotel of class sealed. Caller holds b.mu.
func (b *broker) needsAttestation(h *hotel) bool {
	return h.runtime && b.cfg.SealedAdmission != "off" && hotelClass(h) == classSealed
}

// admitted reports whether h passed admission. Health is h.ok, checked by
// admissibleFree; this is the attestation part. Caller holds b.mu.
func (b *broker) admitted(h *hotel, now time.Time) bool {
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
	d := map[string]any{"state": b.admissionState(h, now), "attestation_required": b.needsAttestation(h)}
	if h.adm.reason != "" {
		d["reason"] = h.adm.reason
	}
	if !h.adm.attestedAt.IsZero() {
		d["attested_at"] = h.adm.attestedAt.UTC().Format(time.RFC3339)
		d["measurement"] = h.adm.measurement
		d["binding_sha256"] = h.adm.bindingSHA
		d["chip_id"] = h.adm.chipID
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
	var att struct {
		Binding    json.RawMessage `json:"binding"`
		BindingSHA string          `json:"binding_sha256"`
		Report     string          `json:"report_b64"`
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := h.getJSON(ctx, h.cfg.Health, "/room/attestation", nil, &att); err != nil {
		return admission{}, attestFetchErr{errors.New("the hotel did not answer GET /room/attestation")}
	}
	return verifyAttestation(att.Binding, att.BindingSHA, att.Report, b.cfg.SealedMeasurements, b.cfg.SealedHostData)
}

// snpBinding is the part of a sealed hotel's binding the broker compares.
type snpBinding struct {
	Level         string `json:"level"`
	Measurement   string `json:"measurement"`
	ChipID        string `json:"chip_id"`
	ReportedTCB   string `json:"reported_tcb"`
	Policy        string `json:"policy"`
	HostData      string `json:"host_data"`
	KernelCmdline string `json:"kernel_cmdline"`
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
	return admission{measurement: measurement, bindingSHA: bsha, chipID: hex.EncodeToString(report[0x1A0:0x1A8])}, nil
}

func inFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), v) {
			return true
		}
	}
	return false
}

// noteAttestation records a check. Caller holds b.mu.
func (b *broker) noteAttestation(h *hotel, res admission, err error, now time.Time) {
	was := b.admitted(h, now)
	h.adm.checkedAt = now
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
