package main

// AB#683 fresh create on the broker. The API's fresh dispatch (polariscomputer
// polaris/services/escape_contest/fresh_http.py) sends one create with
// X-Escape-Fresh and X-Escape-Expected-Launch; the guest (room-kit
// room_receipts.py fresh_create_check, sandbox #676) refuses a fresh create
// without both, reserves the attempt and launch on disk, and signs the
// assignment into the create receipt.
//
// The broker:
//   - takes both headers or neither: one alone, a repeated or malformed
//     value, or an unknown field is refused unsent;
//   - forwards both values byte for byte to the one hotel whose attested
//     binding is the expected binding_sha256, and only there: no other hotel,
//     no queue move, no retry, no "prefer" fallback, never a create without
//     the headers;
//   - answers a repeat of the same request (same guest, both header values
//     and body bytes) with the first answer, without a second hotel call, so a
//     lost reply can be recovered; any other request naming a known attempt
//     or launch is refused unsent.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

const (
	escapeFreshHeader    = "X-Escape-Fresh"
	escapeExpectedHeader = "X-Escape-Expected-Launch"
	escapeExpectedSchema = "cathedral.escape.expected_launch/v1"
	// escapeFreshHeaderMax is the guest's ESCAPE_FRESH_HEADER_MAX.
	escapeFreshHeaderMax = 1024
	// freshReplayMax bounds the remembered fresh creates. A finished one is
	// dropped after freshReplayTTL; past the bound new fresh creates are
	// refused (503) rather than forgetting an attempt early.
	freshReplayMax = 4096
	freshReplayTTL = 24 * time.Hour
	// freshSlotWait bounds a fresh create's wait for its hotel's create slot
	// when the create names no create_timeout_seconds.
	freshSlotWait = 60 * time.Second
)

// freshCreate is a validated fresh create: the two header values exactly as
// received and the fields the broker acts on.
type freshCreate struct {
	freshRaw, expectedRaw string
	attemptID, reportID   string
	requestSHA, binding   string
	bodySHA               string
	hotel                 *hotel // the hotel whose attested binding is binding
}

// headers is what goes to the hotel with the create.
func (f *freshCreate) headers() http.Header {
	return http.Header{escapeFreshHeader: {f.freshRaw}, escapeExpectedHeader: {f.expectedRaw}}
}

// headerObject decodes the one value of header into exactly keys, all
// strings. Unknown, missing, duplicate or non-string fields fail.
func headerObject(r *http.Request, header string, keys []string) (map[string]string, string, bool) {
	vals := r.Header.Values(header)
	if len(vals) != 1 || len(vals[0]) == 0 || len(vals[0]) > escapeFreshHeaderMax {
		return nil, "", false
	}
	raw := vals[0]
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, "", false
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
			return nil, "", false
		}
		if _, dup := out[k]; dup {
			return nil, "", false
		}
		var v string
		if dec.Decode(&v) != nil {
			return nil, "", false
		}
		out[k] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, "", false
	}
	if _, err := dec.Token(); err == nil { // anything after the object
		return nil, "", false
	}
	if len(out) != len(keys) {
		return nil, "", false
	}
	return out, raw, true
}

func freshIDsValid(doc map[string]string, shaKeys ...string) bool {
	if !freshIDRE.MatchString(doc["attempt_id"]) || !freshIDRE.MatchString(doc["report_id"]) {
		return false
	}
	for _, k := range shaKeys {
		if !sha256HexRE.MatchString(doc[k]) {
			return false
		}
	}
	return true
}

// hasFreshHeader: the request carries either fresh header.
func hasFreshHeader(r *http.Request) bool {
	_, a := r.Header[escapeFreshHeader]
	_, b := r.Header[escapeExpectedHeader]
	return a || b
}

// parseFreshCreate reads the fresh headers of a create. nil, nil: neither
// header, a plain create.
func parseFreshCreate(r *http.Request, raw []byte) (*freshCreate, *apiErr) {
	_, hasFresh := r.Header[escapeFreshHeader]
	_, hasExpected := r.Header[escapeExpectedHeader]
	if !hasFresh && !hasExpected {
		return nil, nil
	}
	if hasFresh != hasExpected {
		return nil, &apiErr{400, "escape_fresh_refused", "X-Escape-Fresh and X-Escape-Expected-Launch go together"}
	}
	fresh, freshRaw, ok := headerObject(r, escapeFreshHeader, []string{"schema", "attempt_id", "report_id", "request_sha256"})
	if !ok || fresh["schema"] != escapeFreshSchema || !freshIDsValid(fresh, "request_sha256") {
		return nil, &apiErr{400, "escape_fresh_invalid", "X-Escape-Fresh must be one JSON object of schema, attempt_id, report_id and request_sha256"}
	}
	exp, expRaw, ok := headerObject(r, escapeExpectedHeader, []string{"schema", "attempt_id", "report_id", "request_sha256", "binding_sha256"})
	if !ok || exp["schema"] != escapeExpectedSchema || !freshIDsValid(exp, "request_sha256", "binding_sha256") {
		return nil, &apiErr{400, "escape_expected_launch_invalid", "X-Escape-Expected-Launch must be one JSON object of schema, attempt_id, report_id, request_sha256 and binding_sha256"}
	}
	for _, k := range []string{"attempt_id", "report_id", "request_sha256"} {
		if fresh[k] != exp[k] {
			return nil, &apiErr{409, "escape_expected_launch_mismatch", "X-Escape-Fresh and X-Escape-Expected-Launch name different assignments"}
		}
	}
	if len(r.Header.Values("Idempotency-Key")) != 0 {
		return nil, &apiErr{400, "escape_fresh_idempotency_refused", "a fresh create is made without an Idempotency-Key"}
	}
	sum := sha256.Sum256(raw)
	return &freshCreate{
		freshRaw: freshRaw, expectedRaw: expRaw,
		attemptID: fresh["attempt_id"], reportID: fresh["report_id"],
		requestSHA: fresh["request_sha256"], binding: exp["binding_sha256"],
		bodySHA: hex.EncodeToString(sum[:]),
	}, nil
}

// freshPlainCreate refuses what the guest refuses on a fresh create, before
// any hotel is asked: a batch, a fork or workspace create (another hotel
// chosen by what it holds), or a create returning its bytes.
func freshPlainCreate(payload map[string]any, count int, wantBytes bool) *apiErr {
	if count != 1 || payload["snapshot_id"] != nil || payload["workspace"] != nil || wantBytes {
		return &apiErr{400, "escape_fresh_plain_create_required", "a fresh create is one plain create (count 1, no snapshot or workspace)"}
	}
	return nil
}

// pinFresh resolves the assigned hotel: the admitted Escape hotel whose
// current attested binding is the expected binding. The guest checks the same
// binding, so the create can only be signed there. pl.only pins it: pick
// returns that hotel or none, waitSlot never moves the create and fallbackFor
// never widens it.
//
// Only a guest holding the #659 fresh guest capability for that hotel may send
// it (freshGuestSlotHeld): the guest trusts the broker's hotel key, so a fresh
// create from any other guest would be signed and would consume the API
// guest's launch.
func (b *broker) pinFresh(g *guestState, f *freshCreate, pl *placement) *apiErr {
	if pl.only != nil {
		return &apiErr{400, "escape_fresh_plain_create_required", "a fresh create is one plain create (count 1, no snapshot or workspace)"}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	var pinned *hotel
	for _, h := range b.hotelList() {
		if h.adm.bindingSHA != "" && h.adm.bindingSHA == f.binding {
			pinned = h
			break
		}
	}
	if pinned == nil || !pinned.cfg.Sealed || !pinned.isEscape() || pinned.leaving || !b.admitted(pinned, now) {
		return &apiErr{409, "escape_expected_launch_unplaced", "no admitted Escape hotel holds the expected binding"}
	}
	if !freshGuestSlotHeld(g, g.limits, pinned.cfg.ID) {
		return &apiErr{403, "escape_fresh_not_enabled", "this guest does not hold the fresh guest capability for the hotel of the expected launch; the create was not sent"}
	}
	pl.only, pl.prefer = pinned, false
	if !pl.allows(pinned) {
		return &apiErr{409, "escape_expected_launch_unplaced", "the create's hotel selection does not reach the hotel of the expected binding"}
	}
	f.hotel = pinned
	pl.fresh = f
	return nil
}

// freshUnavailable is the answer when the pinned hotel has no free slot or
// stopped being admitted before the create was sent. Nothing was sent.
func freshUnavailable(f *freshCreate) createResult {
	return createResult{status: 503, doc: errDoc("escape_fresh_hotel_unavailable",
		"hotel "+f.hotel.cfg.ID+" of the expected launch has no free room or is not admitted; the create was not sent")}
}

// freshRecord is one remembered fresh create.
type freshRecord struct {
	guest, freshRaw, expectedRaw, bodySHA string
	done                                  chan struct{}
	finished                              time.Time
	result                                createResult
}

func (r *freshRecord) same(guest string, f *freshCreate) bool {
	return r.guest == guest && r.freshRaw == f.freshRaw && r.expectedRaw == f.expectedRaw && r.bodySHA == f.bodySHA
}

// freshReplays maps "attempt:<id>" and "report:<id>" to the create that
// first named them. In memory only: after a broker restart a repeat reaches
// the guest, whose durable reservation refuses it (409 escape_fresh_consumed).
type freshReplays struct {
	mu   sync.Mutex
	recs map[string]*freshRecord
}

// lookup finds an earlier create naming f's attempt or launch: the record
// when it is the same request, a refusal when it is another, nil, nil when
// neither is known.
func (fr *freshReplays) lookup(guest string, f *freshCreate) (*freshRecord, *apiErr) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	if fr.recs == nil {
		return nil, nil
	}
	return fr.lookupLocked(guest, f)
}

func (fr *freshReplays) lookupLocked(guest string, f *freshCreate) (*freshRecord, *apiErr) {
	ra, rr := fr.recs["attempt:"+f.attemptID], fr.recs["report:"+f.reportID]
	if ra == nil && rr == nil {
		return nil, nil
	}
	if ra != nil && ra == rr && ra.same(guest, f) {
		return ra, nil
	}
	return nil, &apiErr{409, "escape_fresh_replay_mismatch", "this attempt or launch was already sent with another request; the create was not sent"}
}

// claim returns (rec, true) when this request is new and the caller must run
// it and call finish; (rec, false) for a repeat of the same request (wait on
// rec.done, then replay rec.result); or an error.
func (fr *freshReplays) claim(guest string, f *freshCreate) (*freshRecord, bool, *apiErr) {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	if fr.recs == nil {
		fr.recs = map[string]*freshRecord{}
	}
	ka, kr := "attempt:"+f.attemptID, "report:"+f.reportID
	if rec, e := fr.lookupLocked(guest, f); rec != nil || e != nil {
		return rec, false, e
	}
	if len(fr.recs) >= 2*freshReplayMax {
		now := time.Now()
		for k, r := range fr.recs {
			if !r.finished.IsZero() && now.Sub(r.finished) > freshReplayTTL {
				delete(fr.recs, k)
			}
		}
		if len(fr.recs) >= 2*freshReplayMax {
			return nil, false, &apiErr{503, "escape_fresh_full", "too many fresh creates are remembered; the create was not sent"}
		}
	}
	rec := &freshRecord{guest: guest, freshRaw: f.freshRaw, expectedRaw: f.expectedRaw, bodySHA: f.bodySHA, done: make(chan struct{})}
	fr.recs[ka], fr.recs[kr] = rec, rec
	return rec, true, nil
}

// finish stores the answer of a claimed create and releases waiting repeats.
func (fr *freshReplays) finish(rec *freshRecord, res createResult) {
	fr.mu.Lock()
	rec.result = res
	rec.result.lost = nil
	rec.result.header = res.header.Clone()
	rec.finished = time.Now()
	fr.mu.Unlock()
	close(rec.done)
}

// replay is the stored answer of rec, marked as a replay.
func (fr *freshReplays) replay(rec *freshRecord) createResult {
	fr.mu.Lock()
	defer fr.mu.Unlock()
	res := rec.result
	res.header = rec.result.header.Clone()
	if res.header == nil {
		res.header = http.Header{}
	}
	res.header.Set("X-Broker-Escape-Fresh-Replay", "true")
	if rec.result.doc != nil {
		doc := make(map[string]any, len(rec.result.doc))
		for k, v := range rec.result.doc {
			doc[k] = v
		}
		res.doc = doc
	}
	return res
}

// await waits for rec to finish and returns its answer, or false when the
// repeat's own caller went away first.
func (fr *freshReplays) await(ctx context.Context, rec *freshRecord) (createResult, bool) {
	select {
	case <-rec.done:
		return fr.replay(rec), true
	case <-ctx.Done():
		return createResult{}, false
	}
}
