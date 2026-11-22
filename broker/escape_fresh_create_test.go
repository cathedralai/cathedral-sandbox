package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// AB#683: the broker create path forwards X-Escape-Fresh and
// X-Escape-Expected-Launch to the one hotel of the expected binding, never
// retries or falls back, and recovers a lost reply only for the same request.

var (
	freshBindingA = strings.Repeat("a1", 32)
	freshBindingB = strings.Repeat("b2", 32)
	freshReqSHA   = strings.Repeat("c3", 32)
)

// freshChain: hotels a and b are Escape hotels with their own bindings; c is
// an ordinary hotel. Every create the hotels get is recorded with its headers.
func freshChain(t *testing.T) (*testChain, *ownerSeen) {
	t.Helper()
	seen := &ownerSeen{headers: map[string][]http.Header{}}
	tc := r6Chain(t, "", seen.wrap(""))
	tc.b.mu.Lock()
	for id, binding := range map[string]string{"a": freshBindingA, "b": freshBindingB} {
		h := tc.b.hotelByID(id)
		h.cfgMu.Lock()
		enableEscapeHotel(h)
		h.cfgMu.Unlock()
		h.adm.bindingSHA = binding
	}
	tc.b.mu.Unlock()
	return tc, seen
}

type freshAssign struct {
	attempt, report, request, binding string
}

func defaultAssign() freshAssign {
	return freshAssign{"attempt-1", "launch-1", freshReqSHA, freshBindingB}
}

func (a freshAssign) headers() map[string]string {
	fresh, _ := json.Marshal(map[string]string{"schema": escapeFreshSchema, "attempt_id": a.attempt, "report_id": a.report, "request_sha256": a.request})
	exp, _ := json.Marshal(map[string]string{"schema": escapeExpectedSchema, "attempt_id": a.attempt, "report_id": a.report, "request_sha256": a.request, "binding_sha256": a.binding})
	return map[string]string{escapeFreshHeader: string(fresh), escapeExpectedHeader: string(exp)}
}

func freshCreateBody() map[string]any {
	return map[string]any{"image": "alpine:3.20"}
}

type freshAnswer struct {
	status int
	doc    map[string]any
	header http.Header
}

func freshPostCtx(ctx context.Context, tc *testChain, key string, body any, hdr map[string]string, extra http.Header) (freshAnswer, error) {
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", tc.srv.URL+"/v1/sandboxes", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+key)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for k, v := range extra {
		req.Header[k] = append(req.Header[k], v...)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return freshAnswer{}, err
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return freshAnswer{resp.StatusCode, doc, resp.Header}, nil
}

func freshPost(t *testing.T, tc *testChain, body any, hdr map[string]string, extra http.Header) freshAnswer {
	t.Helper()
	a, err := freshPostCtx(context.Background(), tc, "key1", body, hdr, extra)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func freshHotelCreates(seen *ownerSeen) map[string]int {
	out := map[string]int{}
	for _, id := range []string{"a", "b", "c"} {
		out[id] = len(seen.on(id))
	}
	return out
}

func noHotelCreate(t *testing.T, seen *ownerSeen) {
	t.Helper()
	if n := freshHotelCreates(seen); n["a"]+n["b"]+n["c"] != 0 {
		t.Fatalf("a refused fresh create reached a hotel: %v", n)
	}
}

func TestFreshCreateForwardsBothHeadersToTheHotelOfTheExpectedBinding(t *testing.T) {
	tc, seen := freshChain(t)
	for i, attempt := range []string{"attempt-1", "attempt-2", "attempt-3", "attempt-4"} {
		a := defaultAssign()
		a.attempt, a.report = attempt, "launch-"+attempt
		hdr := a.headers()
		ans := freshPost(t, tc, freshCreateBody(), hdr, nil)
		if ans.status != 202 || ans.doc["hotel"] != "b" || ans.header.Get("X-Room-Receipt") == "" {
			t.Fatalf("fresh create %d: %d %v %v", i, ans.status, ans.doc, ans.header)
		}
		got := seen.on("b")
		if len(got) != i+1 {
			t.Fatalf("hotel b creates %d, want %d", len(got), i+1)
		}
		last := got[len(got)-1]
		for _, k := range []string{escapeFreshHeader, escapeExpectedHeader} {
			if v := last.Values(k); len(v) != 1 || v[0] != hdr[k] {
				t.Fatalf("hotel got %s %q, want %q", k, v, hdr[k])
			}
		}
		if last.Get("Idempotency-Key") != "" {
			t.Fatalf("fresh create sent an Idempotency-Key")
		}
	}
	if n := freshHotelCreates(seen); n["a"] != 0 || n["c"] != 0 {
		t.Fatalf("fresh creates reached another hotel: %v", n)
	}
	// A plain create still carries neither header.
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}})
	for _, h := range seen.on("c") {
		if _, ok := h[escapeFreshHeader]; ok {
			t.Fatalf("plain create carried a fresh header: %v", h)
		}
		if _, ok := h[escapeExpectedHeader]; ok {
			t.Fatalf("plain create carried an expected launch header: %v", h)
		}
	}
}

func TestFreshCreateOneHeaderAloneIsRefusedUnsent(t *testing.T) {
	for _, keep := range []string{escapeFreshHeader, escapeExpectedHeader} {
		t.Run(keep, func(t *testing.T) {
			tc, seen := freshChain(t)
			hdr := defaultAssign().headers()
			ans := freshPost(t, tc, freshCreateBody(), map[string]string{keep: hdr[keep]}, nil)
			if ans.status != 400 || errCode(ans.doc) != "escape_fresh_refused" {
				t.Fatalf("%s alone: %d %v", keep, ans.status, ans.doc)
			}
			noHotelCreate(t, seen)
		})
	}
}

func TestFreshCreateMalformedHeadersAreRefusedUnsent(t *testing.T) {
	good := defaultAssign().headers()
	exp := func(mut func(m map[string]any)) map[string]string {
		var m map[string]any
		_ = json.Unmarshal([]byte(good[escapeExpectedHeader]), &m)
		mut(m)
		raw, _ := json.Marshal(m)
		return map[string]string{escapeFreshHeader: good[escapeFreshHeader], escapeExpectedHeader: string(raw)}
	}
	fresh := func(mut func(m map[string]any)) map[string]string {
		var m map[string]any
		_ = json.Unmarshal([]byte(good[escapeFreshHeader]), &m)
		mut(m)
		raw, _ := json.Marshal(m)
		return map[string]string{escapeFreshHeader: string(raw), escapeExpectedHeader: good[escapeExpectedHeader]}
	}
	dupKey := strings.Replace(good[escapeExpectedHeader], `{"attempt_id":"attempt-1"`, `{"attempt_id":"attempt-1","attempt_id":"attempt-1"`, 1)
	if dupKey == good[escapeExpectedHeader] {
		t.Fatalf("fixture: %s", dupKey)
	}
	cases := map[string]struct {
		hdr    map[string]string
		status int
		code   string
	}{
		"expected unknown field":  {exp(func(m map[string]any) { m["hotel"] = "b" }), 400, "escape_expected_launch_invalid"},
		"expected missing field":  {exp(func(m map[string]any) { delete(m, "binding_sha256") }), 400, "escape_expected_launch_invalid"},
		"expected wrong schema":   {exp(func(m map[string]any) { m["schema"] = "cathedral.escape.expected_launch/v0" }), 400, "escape_expected_launch_invalid"},
		"expected short binding":  {exp(func(m map[string]any) { m["binding_sha256"] = freshBindingB[:63] }), 400, "escape_expected_launch_invalid"},
		"expected upper binding":  {exp(func(m map[string]any) { m["binding_sha256"] = strings.ToUpper(freshBindingB) }), 400, "escape_expected_launch_invalid"},
		"expected number field":   {exp(func(m map[string]any) { m["attempt_id"] = 1 }), 400, "escape_expected_launch_invalid"},
		"expected duplicate key":  {map[string]string{escapeFreshHeader: good[escapeFreshHeader], escapeExpectedHeader: dupKey}, 400, "escape_expected_launch_invalid"},
		"expected not an object":  {map[string]string{escapeFreshHeader: good[escapeFreshHeader], escapeExpectedHeader: `["x"]`}, 400, "escape_expected_launch_invalid"},
		"expected trailing data":  {map[string]string{escapeFreshHeader: good[escapeFreshHeader], escapeExpectedHeader: good[escapeExpectedHeader] + `{}`}, 400, "escape_expected_launch_invalid"},
		"fresh unknown field":     {fresh(func(m map[string]any) { m["binding_sha256"] = freshBindingB }), 400, "escape_fresh_invalid"},
		"fresh bad report":        {fresh(func(m map[string]any) { m["report_id"] = "a/b" }), 400, "escape_fresh_invalid"},
		"fresh empty":             {map[string]string{escapeFreshHeader: "", escapeExpectedHeader: good[escapeExpectedHeader]}, 400, "escape_fresh_invalid"},
		"shared attempt differs":  {exp(func(m map[string]any) { m["attempt_id"] = "attempt-2" }), 409, "escape_expected_launch_mismatch"},
		"shared request differs":  {exp(func(m map[string]any) { m["request_sha256"] = strings.Repeat("d4", 32) }), 409, "escape_expected_launch_mismatch"},
		"unknown binding":         {freshAssign{"attempt-1", "launch-1", freshReqSHA, strings.Repeat("e5", 32)}.headers(), 409, "escape_expected_launch_unplaced"},
		"oversize expected value": {exp(func(m map[string]any) { m["attempt_id"] = strings.Repeat("x", 1100) }), 400, "escape_expected_launch_invalid"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tc, seen := freshChain(t)
			ans := freshPost(t, tc, freshCreateBody(), c.hdr, nil)
			if ans.status != c.status || errCode(ans.doc) != c.code {
				t.Fatalf("%d %v, want %d %s", ans.status, ans.doc, c.status, c.code)
			}
			noHotelCreate(t, seen)
		})
	}
}

func TestFreshCreateRefusesWhatTheGuestRefusesUnsent(t *testing.T) {
	hdr := defaultAssign().headers()
	cases := map[string]struct {
		body  map[string]any
		extra http.Header
		code  string
	}{
		"repeated fresh header": {freshCreateBody(), http.Header{escapeFreshHeader: {hdr[escapeFreshHeader]}}, "escape_fresh_invalid"},
		"idempotency key":       {freshCreateBody(), http.Header{"Idempotency-Key": {"create-1"}}, "escape_fresh_idempotency_refused"},
		"batch":                 {map[string]any{"image": "alpine:3.20", "count": 2}, nil, "escape_fresh_plain_create_required"},
		"fork":                  {map[string]any{"snapshot_id": "b.snap-1"}, nil, "escape_fresh_plain_create_required"},
		"other hotel named":     {map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}}, nil, "escape_expected_launch_unplaced"},
		"prefer other hotel":    {map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}, "placement": "prefer"}, nil, "escape_expected_launch_unplaced"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tc, seen := freshChain(t)
			ans := freshPost(t, tc, c.body, hdr, c.extra)
			if errCode(ans.doc) != c.code || ans.status < 400 || ans.status >= 500 {
				t.Fatalf("%d %v, want %s", ans.status, ans.doc, c.code)
			}
			noHotelCreate(t, seen)
		})
	}
}

func TestFreshCreateNeedsAnAdmittedEscapeHotel(t *testing.T) {
	tc, seen := freshChain(t)
	tc.b.mu.Lock()
	h := tc.b.hotelByID("c")
	h.adm.bindingSHA = strings.Repeat("f6", 32) // attested, not an Escape hotel
	tc.b.mu.Unlock()
	ans := freshPost(t, tc, freshCreateBody(), freshAssign{"attempt-1", "launch-1", freshReqSHA, strings.Repeat("f6", 32)}.headers(), nil)
	if ans.status != 409 || errCode(ans.doc) != "escape_expected_launch_unplaced" {
		t.Fatalf("non-Escape hotel: %d %v", ans.status, ans.doc)
	}
	noHotelCreate(t, seen)
}

// The pinned hotel refusing or failing is the answer: no second hotel, no
// second create on the same hotel.
func TestFreshCreateIsNeverRetriedOnAnotherHotel(t *testing.T) {
	for _, status := range []int{503, 500, 429} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			tc, seen := freshChain(t)
			f := tc.hotels["b"]
			f.mu.Lock()
			f.createFail = status
			f.mu.Unlock()
			ans := freshPost(t, tc, freshCreateBody(), defaultAssign().headers(), nil)
			if ans.status != status {
				t.Fatalf("pinned hotel answered %d, broker answered %d %v", status, ans.status, ans.doc)
			}
			if n := freshHotelCreates(seen); n["b"] != 1 || n["a"] != 0 || n["c"] != 0 {
				t.Fatalf("fresh create retried: %v", n)
			}
			// A plain create in the same state does move on (the control).
			if status != 429 {
				ok := freshPost(t, tc, map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}, nil, nil)
				if ok.status != 202 || ok.doc["hotel"] != "c" {
					t.Fatalf("plain create control: %d %v", ok.status, ok.doc)
				}
			}
		})
	}
}

// The pinned hotel with no free slot: the create is not moved to a free
// hotel, it answers once its wait ends, and nothing was sent.
func TestFreshCreateWaitsOnlyForItsOwnHotel(t *testing.T) {
	tc, seen := freshChain(t)
	h := tc.b.hotelByID("b")
	for i := 0; i < cap(h.sem); i++ {
		h.sem <- struct{}{}
	}
	body := freshCreateBody()
	body["create_timeout_seconds"] = 1
	ans := freshPost(t, tc, body, defaultAssign().headers(), nil)
	if ans.status != 503 || errCode(ans.doc) != "create_timeout" {
		t.Fatalf("full pinned hotel: %d %v", ans.status, ans.doc)
	}
	noHotelCreate(t, seen)
	for i := 0; i < cap(h.sem); i++ {
		<-h.sem
	}
}

func TestFreshCreateSameRequestReplaysTheFirstAnswer(t *testing.T) {
	tc, seen := freshChain(t)
	hdr := defaultAssign().headers()
	first := freshPost(t, tc, freshCreateBody(), hdr, nil)
	if first.status != 202 {
		t.Fatalf("first: %d %v", first.status, first.doc)
	}
	again := freshPost(t, tc, freshCreateBody(), hdr, nil)
	if again.status != 202 || again.doc["id"] != first.doc["id"] || again.header.Get("X-Room-Receipt") != first.header.Get("X-Room-Receipt") ||
		again.header.Get("X-Broker-Escape-Fresh-Replay") != "true" {
		t.Fatalf("repeat: %d %v %v, first %v", again.status, again.doc, again.header, first.doc)
	}
	if n := freshHotelCreates(seen); n["b"] != 1 {
		t.Fatalf("a repeat reached the hotel: %v", n)
	}
}

func TestFreshCreateReplayOfAnotherRequestIsRefused(t *testing.T) {
	tc, seen := freshChain(t)
	if first := freshPost(t, tc, freshCreateBody(), defaultAssign().headers(), nil); first.status != 202 {
		t.Fatalf("first: %d %v", first.status, first.doc)
	}
	otherRequest := defaultAssign()
	otherRequest.request = strings.Repeat("d4", 32)
	otherAttempt := defaultAssign()
	otherAttempt.attempt = "attempt-2"
	otherReport := defaultAssign()
	otherReport.report = "launch-2"
	cases := map[string]struct {
		key  string
		body map[string]any
		hdr  map[string]string
	}{
		"different request_sha256":   {"key1", freshCreateBody(), otherRequest.headers()},
		"same launch, other attempt": {"key1", freshCreateBody(), otherAttempt.headers()},
		"same attempt, other launch": {"key1", freshCreateBody(), otherReport.headers()},
		"different body":             {"key1", map[string]any{"image": "alpine:3.21"}, defaultAssign().headers()},
		"another guest":              {"key2", freshCreateBody(), defaultAssign().headers()},
	}
	for name, c := range cases {
		a, err := freshPostCtx(context.Background(), tc, c.key, c.body, c.hdr, nil)
		if err != nil {
			t.Fatal(err)
		}
		if a.status != 409 || errCode(a.doc) != "escape_fresh_replay_mismatch" {
			t.Fatalf("%s: %d %v", name, a.status, a.doc)
		}
	}
	if n := freshHotelCreates(seen); n["b"] != 1 || n["a"]+n["c"] != 0 {
		t.Fatalf("a refused replay reached a hotel: %v", n)
	}
}

// The caller goes away while the hotel creates the room: the room is kept
// and the repeat gets it, with no second create.
func TestFreshCreateLostReplyIsRecoveredByTheSameRequest(t *testing.T) {
	tc, seen := freshChain(t)
	f := tc.hotels["b"]
	f.mu.Lock()
	f.createDelay = 400 * time.Millisecond
	f.mu.Unlock()
	hdr := defaultAssign().headers()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := freshPostCtx(ctx, tc, "key1", freshCreateBody(), hdr, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first create should lose its reply: %v", err)
	}
	again := freshPost(t, tc, freshCreateBody(), hdr, nil)
	if again.status != 202 || again.doc["hotel"] != "b" || again.header.Get("X-Room-Receipt") == "" {
		t.Fatalf("repeat after a lost reply: %d %v", again.status, again.doc)
	}
	if n := freshHotelCreates(seen); n["b"] != 1 {
		t.Fatalf("hotel creates %v, want one", n)
	}
	f.mu.Lock()
	deleted := len(f.roomDeletes) + len(f.bulkDeletes)
	f.mu.Unlock()
	if deleted != 0 {
		t.Fatalf("the room of a lost reply was reaped")
	}
}

func TestFreshCreateConcurrentSameRequestSendsOneCreate(t *testing.T) {
	tc, seen := freshChain(t)
	f := tc.hotels["b"]
	f.mu.Lock()
	f.createDelay = 150 * time.Millisecond
	f.mu.Unlock()
	hdr := defaultAssign().headers()
	var wg sync.WaitGroup
	answers := make([]freshAnswer, 4)
	for i := range answers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, err := freshPostCtx(context.Background(), tc, "key1", freshCreateBody(), hdr, nil)
			if err != nil {
				t.Error(err)
			}
			answers[i] = a
		}(i)
	}
	wg.Wait()
	for _, a := range answers {
		if a.status != 202 || a.doc["id"] != answers[0].doc["id"] {
			t.Fatalf("answers %v", answers)
		}
	}
	if n := freshHotelCreates(seen); n["b"] != 1 {
		t.Fatalf("hotel creates %v, want one", n)
	}
}

func TestFreshCreateOnTheCompatAPIIsRefused(t *testing.T) {
	tc, seen := freshChain(t)
	ans := freshPost(t, tc, freshCreateBody(), defaultAssign().headers(), http.Header{"User-Agent": {"cathedral-harbor/1.0"}})
	if ans.status != 400 || !strings.Contains(string(freshJSON(ans.doc)), "escape_fresh_refused") {
		t.Fatalf("compat fresh create: %d %v", ans.status, ans.doc)
	}
	noHotelCreate(t, seen)
}

func freshJSON(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}
