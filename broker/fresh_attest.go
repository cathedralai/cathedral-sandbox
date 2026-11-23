// Fresh attestation of miner hotels before new rooms (AB#947).
//
// Every keyed call to a miner hotel goes over TLS pinned to the key its
// AMD-verified boot report names (miner_tls.go), so a host replaying a stored
// document cannot finish the handshake. What the boot report cannot show is
// that the chip still vouches for the guest answering now: a guest TLS key
// that leaked (a guest compromise) and is used after that guest died or was
// replaced would keep passing the boot-report checks. A fresh report needs
// the chip's own signature over a value the broker just chose, so that
// impostor fails within one window.
//
// The check. For every admitted miner hotel (MinerHotkey != ""), the sync
// loop asks every miner_fresh_attest_seconds/2 (default 30 s, so 15 s), one
// check at a time per hotel:
//
//	POST <health>/room/attest {"report_data_hex": hex(sha512(
//	    "cathedral.broker.fresh/v1" || hotel id || admitted binding_sha256 (32 bytes) || nonce (32 random bytes)))}
//
// over the hotel's pinned client, with X-Cathedral-Guest: _broker_fresh (its
// own hotel rate-limit bucket; the guest id is reserved at config load). The
// answer passes only if its signed report has: REPORT_DATA equal to the value
// sent; REPORT_ID non-empty and equal to the admitted one; measurement,
// CHIP_ID, policy and LAUNCH_TCB equal to the admitted report's (REPORTED_TCB
// may change live, so only the firmware floor reads it); debug off; the
// measurement still in the live sealed_measurements; the AMD chain signs it
// (room-kit/verify_receipts.py --fresh-report, same pinned ARK and KDS cache)
// and checkGenoaTCBFloor passes. The answer's binding_sha256 and measurement
// members are unsigned and are not read.
//
// The gate. A miner hotel takes a new room only while its last pass for its
// admitted binding is younger than the window (admissibleFreeIn, and the
// recheck after a create's queue wait in createOne). Stale, failed or never
// checked: not a candidate, the create goes elsewhere or is sold out. Fresh
// state of an older binding is ignored. A check that got no answer (429, a
// timeout, the verifier busy or giving no verdict) keeps the last pass until
// its window ends; only a check that answered and failed clears it. admitted()
// does not read fresh state: the one-chip check, probation, the pool, escape
// nonces and the chain archive see admission only. Rooms already running are
// untouched. Operator hotels (no hotkey) are unchanged.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

const (
	freshGuestID            = "_broker_fresh"
	freshDomain             = "cathedral.broker.fresh/v1"
	defaultMinerFreshAttest = 30 * time.Second
	minMinerFreshAttest     = 5
	maxMinerFreshAttest     = 300
	freshAnswerMax          = 64 << 10
)

// The fresh check's bounds: the hotel call, and the wait for a verifier slot.
// Variables so tests can shorten them.
var (
	freshCallTimeout  = 10 * time.Second
	freshVerifierWait = 2 * time.Second
)

// freshProof is the fresh attestation state of a miner hotel. Guarded by
// broker.mu.
type freshProof struct {
	binding   string    // the admitted binding sha256 this state belongs to
	passedAt  time.Time // last pass for binding; zero: none, or cleared by a failed answer
	checkedAt time.Time // last check that finished, pass or not
	reason    string    // why the last check did not pass; "" after a pass
	running   bool      // a check is in flight (single flight per hotel)
	shownOK   bool      // the state last logged: one line per transition
}

// errFreshNoAnswer is a check that got no answer about the report. It does
// not clear an earlier pass: that pass runs out with its window.
type errFreshNoAnswer struct{ error }

func validateMinerFreshAttest(v float64) error {
	if v != 0 && (v < minMinerFreshAttest || v > maxMinerFreshAttest) {
		return fmt.Errorf("config: miner_fresh_attest_seconds must be from %d to %d (default 30)", minMinerFreshAttest, maxMinerFreshAttest)
	}
	return nil
}

// minerFreshAttest is the window a fresh pass stays good.
func (b *broker) minerFreshAttest() time.Duration {
	if b.cfg.MinerFreshAttestSeconds > 0 {
		return time.Duration(b.cfg.MinerFreshAttestSeconds * float64(time.Second))
	}
	return defaultMinerFreshAttest
}

// needsFresh reports whether h is gated on a fresh proof: a miner hotel.
func needsFresh(h *hotel) bool { return h.cfg.MinerHotkey != "" }

// freshAttestOK reports whether h may take a new room as far as fresh attestation
// goes: true for a hotel that needs none, else a pass for the admitted
// binding younger than the window. Caller holds b.mu.
func (b *broker) freshAttestOK(h *hotel, now time.Time) bool {
	if !needsFresh(h) {
		return true
	}
	f := h.freshAtt
	return f.binding != "" && f.binding == h.adm.bindingSHA && !f.passedAt.IsZero() && now.Sub(f.passedAt) < b.minerFreshAttest()
}

// freshHeldOut reports whether h would take rooms but for a stale proof: up,
// admitted, not leaving or draining. Caller holds b.mu.
func (b *broker) freshHeldOut(h *hotel, now time.Time) bool {
	return needsFresh(h) && h.ok && !h.leaving && !h.drain() && b.admitted(h, now) && !b.freshAttestOK(h, now)
}

// freshDoc is admission.fresh of a miner hotel's document, nil for others.
// Caller holds b.mu.
func (b *broker) freshDoc(h *hotel, now time.Time) map[string]any {
	if !needsFresh(h) {
		return nil
	}
	d := map[string]any{"ok": b.freshAttestOK(h, now), "max_age_seconds": b.minerFreshAttest().Seconds(), "at": nil}
	if f := h.freshAtt; f.binding != "" && f.binding == h.adm.bindingSHA {
		if !f.passedAt.IsZero() {
			d["at"] = f.passedAt.UTC().Format(time.RFC3339Nano)
		}
		if f.reason != "" {
			d["reason"] = f.reason
		}
	} else if h.adm.bindingSHA != "" {
		d["reason"] = "no fresh check of the admitted binding yet"
	}
	if _, ok := d["reason"]; !ok && !d["ok"].(bool) {
		d["reason"] = "the last fresh pass is older than max_age_seconds"
	}
	return d
}

// freshTarget is what a fresh check compares with: the admitted report.
type freshTarget struct {
	hotel, binding, reportID, measurement, chip, launchTCB string
	policy                                                 uint64
}

// freshDue reports whether the sync loop should run h's fresh check now and
// marks it running. Caller holds b.mu.
func (b *broker) freshDue(h *hotel, healthOK bool, now time.Time) (freshTarget, bool) {
	if !needsFresh(h) || !healthOK || h.leaving || h.freshAtt.running || !b.admitted(h, now) || h.adm.attestedAt.IsZero() {
		return freshTarget{}, false
	}
	if h.freshAtt.binding == h.adm.bindingSHA && !h.freshAtt.checkedAt.IsZero() && now.Sub(h.freshAtt.checkedAt) < b.minerFreshAttest()/2 {
		return freshTarget{}, false
	}
	h.freshAtt.running = true
	a := h.adm
	return freshTarget{hotel: h.cfg.ID, binding: a.bindingSHA, reportID: a.reportID, measurement: a.measurement,
		chip: a.chipFull, launchTCB: a.launchTCB, policy: a.policy}, true
}

// syncFresh runs the fresh step of the sync loop for h, after admission.
func (b *broker) syncFresh(ctx context.Context, h *hotel, healthOK bool) {
	b.mu.Lock()
	t, due := b.freshDue(h, healthOK, time.Now())
	b.mu.Unlock()
	if !due {
		return
	}
	gen := b.admGen.Load()
	// The window starts when the challenge goes out, not when the answer has
	// been verified: a slow hotel or verifier must not stretch a pass.
	issued := time.Now()
	err := b.checkFresh(ctx, h, t)
	b.mu.Lock()
	defer b.mu.Unlock()
	h.freshAtt.running = false
	// A reload changed the admission lists, the hotel was admitted with
	// another binding, or the sync loop stopped (a leave) while this check
	// ran: drop it; the next tick asks again.
	if b.admGen.Load() != gen || h.adm.bindingSHA != t.binding || ctx.Err() != nil {
		h.freshAtt.checkedAt = time.Time{}
		return
	}
	b.noteFresh(h, t.binding, err, issued, time.Now())
}

// noteFresh records a fresh check of binding whose challenge was issued at
// issued; a pass counts from then. Caller holds b.mu.
func (b *broker) noteFresh(h *hotel, binding string, err error, issued, now time.Time) {
	if h.freshAtt.binding != binding {
		h.freshAtt = freshProof{binding: binding, running: h.freshAtt.running, shownOK: h.freshAtt.shownOK}
	}
	h.freshAtt.checkedAt = now
	var na errFreshNoAnswer
	switch {
	case err == nil:
		h.freshAtt.passedAt, h.freshAtt.reason = issued, ""
	case errors.As(err, &na):
		h.freshAtt.reason = err.Error() // the last pass stands until its window ends
	default:
		h.freshAtt.passedAt, h.freshAtt.reason = time.Time{}, err.Error()
	}
	if ok := b.freshAttestOK(h, now); ok != h.freshAtt.shownOK {
		h.freshAtt.shownOK = ok
		if ok {
			log.Printf("hotel %s fresh attestation passed: takes new rooms", h.cfg.ID)
		} else {
			reason := h.freshAtt.reason
			if reason == "" {
				reason = "the last pass is older than the window"
			}
			log.Printf("hotel %s held out of placement: fresh attestation: %s", h.cfg.ID, reason)
		}
	}
}

// freshReportData is the REPORT_DATA a fresh check asks for.
func freshReportData(hotelID, binding string, nonce []byte) ([]byte, error) {
	bsha, err := hex.DecodeString(binding)
	if err != nil || len(bsha) != 32 {
		return nil, errors.New("the admitted binding_sha256 is not 32 bytes of hex")
	}
	hs := sha512.New()
	hs.Write([]byte(freshDomain))
	hs.Write([]byte(hotelID))
	hs.Write(bsha)
	hs.Write(nonce)
	return hs.Sum(nil), nil
}

// checkFresh asks h for a fresh report and checks it against t. It does not
// lock except to read the live lists. A nil error is a pass.
func (b *broker) checkFresh(ctx context.Context, h *hotel, t freshTarget) error {
	if t.reportID == "" {
		return errors.New("the admitted report has no REPORT_ID: a fresh report cannot be tied to its launch")
	}
	if b.cfg.AMDVerifier == nil {
		return errors.New("a fresh check needs the AMD chain check; set amd_verifier in the broker config")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return errFreshNoAnswer{fmt.Errorf("no nonce: %v", err)}
	}
	want, err := freshReportData(t.hotel, t.binding, nonce)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"report_data_hex": hex.EncodeToString(want)})
	status, _, raw, release, err := h.doHeadersMax(ctx, h.cfg.Health, "POST", "/room/attest", nil, body, freshCallTimeout,
		http.Header{guestHeader: {freshGuestID}}, answerRead{noRedirect: true, maxBytes: freshAnswerMax})
	release()
	switch {
	case errors.Is(err, errAnswerTooLarge):
		return errors.New("the fresh answer is over 64 KiB")
	case err != nil:
		return errFreshNoAnswer{fmt.Errorf("the hotel did not answer POST /room/attest: %v", err)}
	case status == http.StatusTooManyRequests:
		return errFreshNoAnswer{errors.New("POST /room/attest answered 429 (rate limited)")}
	case status != 200:
		return fmt.Errorf("POST /room/attest answered %d", status)
	}
	report, canon, err := freshAnswerReport(raw)
	if err != nil {
		return err
	}
	if err := checkFreshFields(report, want, t, b.sealedMeasurements()); err != nil {
		return err
	}
	// The verifier gets canon, built from the bytes just checked, never the
	// hotel's raw answer, so both sides check the same report.
	amd, err := b.runAMDVerifier(ctx, canon, []string{"--fresh-report", "", "--report-data-hex", hex.EncodeToString(want)}, 1,
		freshSlotAcquire(freshVerifierWait))
	var nv verifierNoVerdict
	switch {
	case errors.Is(err, errVerifierBusy) || errors.As(err, &nv):
		return errFreshNoAnswer{err}
	case err != nil:
		return err
	}
	return checkGenoaTCBFloor(base64.StdEncoding.EncodeToString(report), amd, b.cfg.MinGenoaSNPSPL, b.cfg.MinGenoaMicrocodeSPL)
}

// freshAnswerReport reads the report out of a POST /room/attest answer and
// returns it with canon, the answer the verifier must check: one key, the
// same report.
func freshAnswerReport(raw []byte) (report, canon []byte, err error) {
	var ans struct {
		Report string `json:"report_b64"`
	}
	if json.Unmarshal(raw, &ans) != nil || ans.Report == "" {
		return nil, nil, errors.New("the fresh answer has no report_b64")
	}
	report, err = base64.StdEncoding.DecodeString(ans.Report)
	if err != nil || len(report) < snpReportMinLen {
		return nil, nil, errors.New("the fresh report is not a 1184-byte SNP report")
	}
	canon, _ = json.Marshal(map[string]string{"report_b64": base64.StdEncoding.EncodeToString(report)})
	return report, canon, nil
}

// checkFreshFields compares a fresh report with the value sent and the
// admitted report. The signature is the verifier's (checkFresh).
func checkFreshFields(report, want []byte, t freshTarget, measurements []string) error {
	if !bytes.Equal(report[0x50:0x90], want) {
		return errors.New("fresh report REPORT_DATA is not the value sent (a replayed report)")
	}
	switch id := snpReportID(report); {
	case id == "":
		return errors.New("fresh report has no REPORT_ID")
	case id != t.reportID:
		return errors.New("fresh report REPORT_ID differs from the admitted launch")
	}
	measurement := hex.EncodeToString(report[0x90:0xC0])
	if measurement != t.measurement {
		return errors.New("fresh report measurement differs from the admitted one")
	}
	if hex.EncodeToString(report[0x1A0:0x1E0]) != t.chip {
		return errors.New("fresh report chip id differs from the admitted one")
	}
	policy := binary.LittleEndian.Uint64(report[0x08:0x10])
	if policy != t.policy {
		return errors.New("fresh report policy differs from the admitted one")
	}
	if policy&snpPolicyDebugBit != 0 {
		return errors.New("fresh report policy allows debug")
	}
	if hex.EncodeToString(report[0x1F0:0x1F8]) != t.launchTCB {
		return errors.New("fresh report LAUNCH_TCB differs from the admitted one")
	}
	if !inFold(measurements, measurement) {
		return fmt.Errorf("measurement %s... is no longer in sealed_measurements", measurement[:16])
	}
	return nil
}

// freshHeldOutCount is the operator capacity view's count of miner hotels
// held out for a stale proof. Caller holds b.mu.
func (b *broker) freshHeldOutCount(now time.Time) int {
	n := 0
	for _, h := range b.hotelList() {
		if b.freshHeldOut(h, now) {
			n++
		}
	}
	return n
}
