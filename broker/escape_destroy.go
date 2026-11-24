package main

// AB#683 fresh slot destroy path: the producer side of the API cleanup in
// bigailabs/polariscomputer polaris/services/escape_contest/fresh_destroy.py
// (docs/AB683_FRESH_DESTROY.md).
//
// A fresh slot is a sealed hotel labelled escape=true with max_slots 1. Each
// attempt gets one launch (one SNP REPORT_ID). When the attempt ends, the API
// asks the broker to destroy that launch, and only a new launch on a new
// REPORT_ID may serve the slot again.
//
//	POST /v1/broker/hotels/<id>/escape-destroy   operator key
//	    {"schema": "cathedral.escape.destroy_original/v1",
//	     "destroy_request_sha256", "attempt_id", "report_id",
//	     "binding_sha256", "measurement", "request_sha256"}
//	GET  /v1/broker/hotels/<id>/escape-retire    hotel key (the slot's host)
//	POST /v1/broker/hotels/<id>/escape-retire    hotel key
//	    {"schema": "cathedral.escape.retire_confirm/v1", "slot",
//	     "report_id", "binding_sha256", "state": "stopped"}
//
// The destroy route:
//   - is fenced to a launch this broker admitted on this slot: report_id,
//     binding_sha256 and measurement must be that launch's, and when this
//     broker sent the attempt's fresh create, attempt_id and request_sha256
//     must be that create's. Any other launch, attempt or slot is 409;
//   - records the request and retires the launch durably (state_dir
//     escape-slots.json) before it answers anything but a refusal. From then
//     on the launch is not admitted (admitted, noteAttestation), so no create
//     is placed on it, and its REPORT_ID never passes the gate again;
//   - answers 200 state "destroyed" only once the slot's host confirmed the
//     launch stopped. Until then 503 escape_destroy_pending, and the API
//     retries the identical request;
//   - replays the recorded answer byte for byte for the same
//     destroy_request_sha256 and the same fence. The same digest with another
//     fence, or another request for a launch or attempt that already has one,
//     is 409.
//
// The host learns of a retire by pulling: the slot's net-check timer
// (scripts/escape_slots/write-escape-units.sh) asks GET escape-retire with the
// slot's hotel key, hands each launch to the #496 supervisor, which stops the
// unit, confirms QEMU is gone, deletes scratch and relaunches, and then
// POSTs the confirm. No new host agent, no new port: the host calls the
// broker's own listener.
//
// The host also confirms a launch that is not the one its unit runs now
// (the supervisor's own retire after an ended attempt ran first, or the
// guest died): one unit runs one guest, so a launch that is not the current
// one is not running.

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	escapeDestroyRequestSchema = "cathedral.escape.destroy_original/v1"
	escapeDestroyResultSchema  = "cathedral.escape.destroy_result/v1"
	escapeRetireRequestSchema  = "cathedral.escape.retire_request/v1"
	escapeRetireConfirmSchema  = "cathedral.escape.retire_confirm/v1"
	escapeSlotsFile            = "escape-slots.json"
	escapeBodyMax              = 16 << 10 // fresh_destroy.py MAX_BODY_BYTES
	// escapeLaunchKeep bounds the launches remembered per slot. A dropped
	// launch is an old stopped one; a launch retire-requested and not yet
	// confirmed stopped is never dropped.
	escapeLaunchKeep = 32
	// escapeDestroyKeep bounds the destroy records per slot; answered ones
	// go first.
	escapeDestroyKeep = 256
	// defaultEscapeDestroyWait is how long the route waits for the host's
	// confirm before 503. The API gives the call 3 s.
	defaultEscapeDestroyWait = 2 * time.Second
)

var (
	escapeAttemptRE        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	escapeMeasurementRE    = regexp.MustCompile(`^[0-9a-f]{96}$`)
	errEscapeLaunchRetired = errors.New("this launch was retired by escape-destroy; only a new launch (new REPORT_ID) is admitted")
)

// escapeLaunch is one launch the broker admitted on an Escape hotel.
type escapeLaunch struct {
	ReportID    string        `json:"report_id"`
	BindingSHA  string        `json:"binding_sha256"`
	Measurement string        `json:"measurement"`
	AdmittedAt  time.Time     `json:"admitted_at"`
	RetireAt    time.Time     `json:"retire_requested_at"`
	StoppedAt   time.Time     `json:"stopped_at"`
	stopped     chan struct{} // closed when StoppedAt is set; nil until a waiter asks
}

func (l *escapeLaunch) retired() bool { return !l.RetireAt.IsZero() }

// escapeDestroy is one recorded destroy request and, once the host
// confirmed, its answer.
type escapeDestroy struct {
	DestroySHA  string    `json:"destroy_request_sha256"`
	AttemptID   string    `json:"attempt_id"`
	ReportID    string    `json:"report_id"`
	BindingSHA  string    `json:"binding_sha256"`
	Measurement string    `json:"measurement"`
	RequestSHA  string    `json:"request_sha256"`
	RequestedAt time.Time `json:"requested_at"`
	Result      string    `json:"result,omitempty"` // the 200 body, replayed byte for byte (a string so the file encoding cannot reformat it)
}

func (d *escapeDestroy) same(q escapeDestroyRequest) bool {
	return d.DestroySHA == q.DestroySHA && d.AttemptID == q.AttemptID && d.ReportID == q.ReportID &&
		d.BindingSHA == q.BindingSHA && d.Measurement == q.Measurement && d.RequestSHA == q.RequestSHA
}

type escapeSlotState struct {
	Launches []*escapeLaunch  `json:"launches"`
	Destroys []*escapeDestroy `json:"destroys"`
}

func (s *escapeSlotState) launch(report string) *escapeLaunch {
	for _, l := range s.Launches {
		if l.ReportID == report {
			return l
		}
	}
	return nil
}

// escapeDestroyRequest is the API's fence (fresh_destroy.py destroy_original).
type escapeDestroyRequest struct {
	DestroySHA, AttemptID, ReportID, BindingSHA, Measurement, RequestSHA string
}

var escapeDestroyKeys = []string{"schema", "destroy_request_sha256", "attempt_id", "report_id", "binding_sha256", "measurement", "request_sha256"}

var escapeRetireConfirmKeys = []string{"schema", "slot", "report_id", "binding_sha256", "state"}

// strictStringObject decodes raw as exactly one JSON object whose keys are
// exactly keys, each once, each a string. Anything else fails.
func strictStringObject(raw []byte, keys []string) (map[string]string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	out := map[string]string{}
	for dec.More() {
		tok, err := dec.Token()
		k, ok := tok.(string)
		if err != nil || !ok || !want[k] {
			return nil, false
		}
		if _, dup := out[k]; dup {
			return nil, false
		}
		var v string
		if dec.Decode(&v) != nil {
			return nil, false
		}
		out[k] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return out, len(out) == len(keys)
}

func nonZeroHex(re *regexp.Regexp, v string) bool {
	return re.MatchString(v) && strings.Trim(v, "0") != ""
}

func decodeEscapeDestroy(raw []byte) (escapeDestroyRequest, bool) {
	doc, ok := strictStringObject(raw, escapeDestroyKeys)
	if !ok || doc["schema"] != escapeDestroyRequestSchema {
		return escapeDestroyRequest{}, false
	}
	q := escapeDestroyRequest{DestroySHA: doc["destroy_request_sha256"], AttemptID: doc["attempt_id"], ReportID: doc["report_id"],
		BindingSHA: doc["binding_sha256"], Measurement: doc["measurement"], RequestSHA: doc["request_sha256"]}
	for _, v := range []string{q.DestroySHA, q.ReportID, q.BindingSHA, q.RequestSHA} {
		if !nonZeroHex(sha256HexRE, v) {
			return escapeDestroyRequest{}, false
		}
	}
	if !escapeAttemptRE.MatchString(q.AttemptID) || !nonZeroHex(escapeMeasurementRE, q.Measurement) {
		return escapeDestroyRequest{}, false
	}
	return q, true
}

// escapeDestroyResult is the 200 body fresh_destroy.py accepts: the fence
// with the result schema, plus slot and state.
func escapeDestroyResult(slot string, q escapeDestroyRequest) []byte {
	raw, _ := json.Marshal(map[string]string{ // map keys marshal sorted: one canonical form
		"schema": escapeDestroyResultSchema, "destroy_request_sha256": q.DestroySHA, "attempt_id": q.AttemptID,
		"report_id": q.ReportID, "binding_sha256": q.BindingSHA, "measurement": q.Measurement,
		"request_sha256": q.RequestSHA, "slot": slot, "state": "destroyed",
	})
	return raw
}

// ---------------------------------------------------------------- state

// escapeLaunchRetiredLocked: report is a launch of hotel id retired by
// escape-destroy. Caller holds b.mu.
func (b *broker) escapeLaunchRetiredLocked(id, report string) bool {
	if report == "" || b.escSlots == nil {
		return false
	}
	s := b.escSlots[id]
	if s == nil {
		return false
	}
	l := s.launch(report)
	return l != nil && l.retired()
}

// noteEscapeLaunch runs on every passing attestation, before it is applied.
// It refuses a retired launch, and remembers a new launch of an Escape hotel
// so a later destroy can be fenced to it. Caller holds b.mu.
func (b *broker) noteEscapeLaunch(h *hotel, res admission, now time.Time) error {
	if res.reportID == "" {
		return nil
	}
	if b.escapeLaunchRetiredLocked(h.cfg.ID, res.reportID) {
		return errEscapeLaunchRetired
	}
	if !h.cfg.Sealed || !h.isEscape() {
		return nil
	}
	if b.escSlots == nil {
		b.escSlots = map[string]*escapeSlotState{}
	}
	s := b.escSlots[h.cfg.ID]
	if s == nil {
		s = &escapeSlotState{}
		b.escSlots[h.cfg.ID] = s
	}
	if s.launch(res.reportID) != nil {
		return nil
	}
	s.Launches = append(s.Launches, &escapeLaunch{ReportID: res.reportID, BindingSHA: res.bindingSHA, Measurement: res.measurement, AdmittedAt: now.UTC()})
	s.prune()
	if err := b.saveEscapeSlotsLocked(); err != nil && b.cfg.StateDir != "" {
		// Not fatal for admission: the record matters only to a later destroy,
		// which refuses (409 unknown launch) until a save lands.
		log.Printf("escape slot %s: launch %s... not saved: %v", h.cfg.ID, res.reportID[:16], err)
	}
	return nil
}

func (s *escapeSlotState) prune() {
	for len(s.Launches) > escapeLaunchKeep {
		drop := -1
		for i, l := range s.Launches {
			if !l.retired() || !l.StoppedAt.IsZero() {
				drop = i
				break
			}
		}
		if drop < 0 {
			break
		}
		s.Launches = append(s.Launches[:drop], s.Launches[drop+1:]...)
	}
	for len(s.Destroys) > escapeDestroyKeep {
		drop := -1
		for i, d := range s.Destroys {
			if d.Result != "" {
				drop = i
				break
			}
		}
		if drop < 0 {
			break
		}
		s.Destroys = append(s.Destroys[:drop], s.Destroys[drop+1:]...)
	}
}

// saveEscapeSlotsLocked writes state_dir/escape-slots.json durably. Caller
// holds b.mu.
func (b *broker) saveEscapeSlotsLocked() error {
	if b.cfg.StateDir == "" {
		return errors.New("no state_dir: an escape destroy cannot be recorded durably")
	}
	raw, err := json.MarshalIndent(b.escSlots, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return err
	}
	return writeFileDurable(filepath.Join(b.cfg.StateDir, escapeSlotsFile), raw)
}

// loadEscapeSlots reads state_dir/escape-slots.json at start. A file that
// does not parse stops the broker: starting without it could admit a
// retired launch again.
func (b *broker) loadEscapeSlots() error {
	b.escSlots = map[string]*escapeSlotState{}
	if b.cfg.StateDir == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(b.cfg.StateDir, escapeSlotsFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var m map[string]*escapeSlotState
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%s: %w", escapeSlotsFile, err)
	}
	for id, s := range m {
		if s == nil {
			return fmt.Errorf("%s: slot %q is null", escapeSlotsFile, id)
		}
		for _, l := range s.Launches {
			if l == nil || !sha256HexRE.MatchString(l.ReportID) {
				return fmt.Errorf("%s: slot %q has a launch without a REPORT_ID", escapeSlotsFile, id)
			}
		}
		for _, d := range s.Destroys {
			if d == nil {
				return fmt.Errorf("%s: slot %q has a null destroy", escapeSlotsFile, id)
			}
		}
	}
	b.escSlots = m
	return nil
}

// ---------------------------------------------------------------- destroy route

func (b *broker) escapeDestroyWaitFor() time.Duration {
	if b.escDestroyWait > 0 {
		return b.escDestroyWait
	}
	return defaultEscapeDestroyWait
}

// escapeAnswer is what one pass of the destroy decision yields: a final
// answer (status and body), or a launch to wait on.
type escapeAnswer struct {
	status int
	body   []byte
	code   string
	msg    string
	wait   chan struct{}
}

func escapeRefuse(status int, code, msg string) escapeAnswer {
	return escapeAnswer{status: status, code: code, msg: msg}
}

// freshFenceLocked checks the attempt half of the fence against the fresh
// create this broker sent for the launch, if it still remembers one (in
// memory only; after a restart the launch fence stands alone, and the
// guest's durable reservation made that launch single-attempt).
func (b *broker) freshFenceLocked(q escapeDestroyRequest) bool {
	fr := &b.freshReplays
	fr.mu.Lock()
	defer fr.mu.Unlock()
	if fr.recs == nil {
		return true
	}
	byReport, byAttempt := fr.recs["report:"+q.ReportID], fr.recs["attempt:"+q.AttemptID]
	if byReport == nil && byAttempt == nil {
		return true
	}
	if byReport != byAttempt {
		return false // the attempt was sent to another launch, or the launch carried another attempt
	}
	var sent map[string]string
	if json.Unmarshal([]byte(byReport.freshRaw), &sent) != nil {
		return false
	}
	return sent["attempt_id"] == q.AttemptID && sent["report_id"] == q.ReportID && sent["request_sha256"] == q.RequestSHA
}

// escapeDestroyLocked decides one destroy request. Caller holds b.mu.
func (b *broker) escapeDestroyLocked(h *hotel, q escapeDestroyRequest, now time.Time) escapeAnswer {
	id := h.cfg.ID
	s := b.escSlots[id]
	var d *escapeDestroy
	if s != nil {
		for _, x := range s.Destroys {
			if x.DestroySHA == q.DestroySHA {
				d = x
				break
			}
		}
	}
	if d != nil && !d.same(q) {
		return escapeRefuse(409, "escape_destroy_mismatch", "this destroy_request_sha256 was recorded with another fence")
	}
	if d != nil && d.Result != "" {
		return escapeAnswer{status: 200, body: []byte(d.Result)}
	}
	if d == nil {
		if !h.cfg.Sealed || !h.isEscape() || h.cfg.MaxSlots != 1 {
			return escapeRefuse(409, "escape_slot_required", "escape-destroy is only for a sealed escape=true hotel with max_slots 1")
		}
		var l *escapeLaunch
		if s != nil {
			l = s.launch(q.ReportID)
		}
		if l == nil {
			return escapeRefuse(409, "escape_destroy_unknown_launch", "this broker admitted no such launch on hotel "+id)
		}
		if l.BindingSHA != q.BindingSHA || l.Measurement != q.Measurement {
			return escapeRefuse(409, "escape_destroy_fence_mismatch", "binding_sha256 or measurement is not that launch's")
		}
		for _, x := range s.Destroys {
			if x.ReportID == q.ReportID || x.AttemptID == q.AttemptID {
				return escapeRefuse(409, "escape_destroy_conflict", "another destroy request is recorded for this launch or attempt")
			}
		}
		if !b.freshFenceLocked(q) {
			return escapeRefuse(409, "escape_destroy_attempt_mismatch", "attempt_id or request_sha256 is not the fresh create this broker sent to that launch")
		}
		d = &escapeDestroy{DestroySHA: q.DestroySHA, AttemptID: q.AttemptID, ReportID: q.ReportID, BindingSHA: q.BindingSHA,
			Measurement: q.Measurement, RequestSHA: q.RequestSHA, RequestedAt: now.UTC()}
		retireBefore := l.RetireAt
		s.Destroys = append(s.Destroys, d)
		if !l.retired() {
			l.RetireAt = now.UTC()
		}
		s.prune()
		if err := b.saveEscapeSlotsLocked(); err != nil {
			s.Destroys = s.Destroys[:len(s.Destroys)-1]
			l.RetireAt = retireBefore
			log.Printf("escape slot %s: destroy of %s... not recorded: %v", id, q.ReportID[:16], err)
			return escapeRefuse(503, "escape_destroy_unsaved", "the destroy could not be recorded durably; nothing changed, retry")
		}
		log.Printf("escape slot %s: launch %s... retired by escape-destroy (attempt %s); waiting for the host to stop it", id, q.ReportID[:16], q.AttemptID)
	}
	l := s.launch(q.ReportID)
	if l == nil || !l.retired() {
		// Pruning never drops a launch retired and not yet stopped.
		return escapeRefuse(500, "escape_destroy_lost_launch", "the recorded launch is missing")
	}
	if l.StoppedAt.IsZero() {
		if l.stopped == nil {
			l.stopped = make(chan struct{})
		}
		return escapeAnswer{wait: l.stopped}
	}
	result := escapeDestroyResult(id, q)
	d.Result = string(result)
	if err := b.saveEscapeSlotsLocked(); err != nil {
		d.Result = ""
		return escapeRefuse(503, "escape_destroy_unsaved", "the host confirmed the stop, but the answer could not be recorded; retry")
	}
	return escapeAnswer{status: 200, body: result}
}

func (b *broker) handleEscapeDestroy(w http.ResponseWriter, r *http.Request, id string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, escapeBodyMax))
	if err != nil {
		writeErr(w, 413, "body_too_large", "escape-destroy body over 16 KiB")
		return
	}
	q, ok := decodeEscapeDestroy(raw)
	if !ok {
		writeErr(w, 400, "invalid_request", "body must be exactly the "+escapeDestroyRequestSchema+" fence")
		return
	}
	h := b.hotelByID(id)
	if h == nil {
		writeErr(w, 404, "hotel_not_found", "no hotel "+id)
		return
	}
	deadline := time.NewTimer(b.escapeDestroyWaitFor())
	defer deadline.Stop()
	for waited := false; ; waited = true {
		b.mu.Lock()
		a := b.escapeDestroyLocked(h, q, time.Now())
		b.mu.Unlock()
		if a.wait == nil {
			if a.body != nil {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(a.status)
				_, _ = w.Write(a.body)
				return
			}
			writeErr(w, a.status, a.code, a.msg)
			return
		}
		if waited {
			break
		}
		select {
		case <-a.wait:
		case <-deadline.C:
		case <-r.Context().Done():
			return
		}
	}
	// The record is durable and the launch retired; only the host's stop is
	// missing. Not destroyed: the API retries this same request.
	w.Header().Set("Retry-After", "5")
	writeErr(w, 503, "escape_destroy_pending", "the launch is retired and its host has not yet confirmed the VM stopped")
}

// ---------------------------------------------------------------- host channel

// isSlotHost: the request carries hotel h's own key, which the slot's host
// holds (sealed.env SEALED_API_KEY_FILE).
func isSlotHost(r *http.Request, h *hotel) bool {
	a := r.Header.Get("Authorization")
	if h.key == "" || len(a) < 8 || !strings.EqualFold(a[:7], "bearer ") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(a[7:])), []byte(h.key)) == 1
}

func (b *broker) handleEscapeRetire(w http.ResponseWriter, r *http.Request, id string) {
	h := b.hotelByID(id)
	if h == nil || !isSlotHost(r, h) {
		// One answer for an unknown hotel and a wrong key: no probing for ids.
		writeErr(w, 401, "unauthorized", "the slot's hotel key is required")
		return
	}
	switch r.Method {
	case "GET":
		b.mu.Lock()
		pending := []map[string]string{}
		if s := b.escSlots[id]; s != nil {
			for _, l := range s.Launches {
				if l.retired() && l.StoppedAt.IsZero() {
					pending = append(pending, map[string]string{"report_id": l.ReportID, "binding_sha256": l.BindingSHA})
				}
			}
		}
		b.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{"schema": escapeRetireRequestSchema, "slot": id, "retire": pending})
	case "POST":
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, escapeBodyMax))
		if err != nil {
			writeErr(w, 413, "body_too_large", "escape-retire body over 16 KiB")
			return
		}
		doc, ok := strictStringObject(raw, escapeRetireConfirmKeys)
		if !ok || doc["schema"] != escapeRetireConfirmSchema || doc["slot"] != id || doc["state"] != "stopped" ||
			!sha256HexRE.MatchString(doc["report_id"]) || !sha256HexRE.MatchString(doc["binding_sha256"]) {
			writeErr(w, 400, "invalid_request", "body must be exactly the "+escapeRetireConfirmSchema+" confirm for this slot")
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		var l *escapeLaunch
		if s := b.escSlots[id]; s != nil {
			l = s.launch(doc["report_id"])
		}
		if l == nil || !l.retired() || l.BindingSHA != doc["binding_sha256"] {
			writeErr(w, 409, "escape_retire_not_requested", "no retire is requested for that launch")
			return
		}
		if l.StoppedAt.IsZero() {
			l.StoppedAt = time.Now().UTC()
			if err := b.saveEscapeSlotsLocked(); err != nil {
				l.StoppedAt = time.Time{}
				writeErr(w, 503, "escape_retire_unsaved", "the stop could not be recorded durably; retry")
				return
			}
			if l.stopped != nil {
				close(l.stopped)
			}
			log.Printf("escape slot %s: host confirmed launch %s... stopped", id, l.ReportID[:16])
		}
		writeJSON(w, 200, map[string]any{"schema": escapeRetireConfirmSchema, "slot": id, "report_id": l.ReportID,
			"binding_sha256": l.BindingSHA, "state": "stopped"})
	default:
		writeErr(w, 405, "method_not_allowed", "escape-retire takes GET or POST")
	}
}
