package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// AB#819 (const load test): a hotel's data connections are a pool of
// data_conns slots; a call that finds none free waits at most
// data_conn_wait_seconds, then answers 503 sold_out with Retry-After.

// gateOf replaces a hotel's data pool with n slots and the given bound.
func gateOf(tc *testChain, hotelID string, n int, wait time.Duration) *connGate {
	g := &connGate{slots: make(chan struct{}, n), wait: wait}
	tc.b.hotelByID(hotelID).conns = g
	return g
}

// fillConns takes every free slot of g, as calls in flight would; the returned
// func gives them back.
func fillConns(g *connGate) func() {
	n := cap(g.slots) - len(g.slots)
	for i := 0; i < n; i++ {
		g.slots <- struct{}{}
	}
	return func() {
		for i := 0; i < n; i++ {
			<-g.slots
		}
	}
}

func TestDataPoolDefaultsAndConfigBounds(t *testing.T) {
	if n := dataConns(hotelConfig{Concurrency: 40}); n != 104 {
		t.Fatalf("default pool for concurrency 40: %d, want 104 (unchanged)", n)
	}
	if n := dataConns(hotelConfig{Concurrency: 40, DataConns: 400}); n != 400 {
		t.Fatalf("data_conns 400: %d", n)
	}
	for in, want := range map[int]time.Duration{0: 10 * time.Second, 3: 3 * time.Second, -1: -1} {
		if g := newConnGate(hotelConfig{Concurrency: 4, DataConnWaitSeconds: in}); g.wait != want {
			t.Fatalf("data_conn_wait_seconds %d: wait %v, want %v", in, g.wait, want)
		}
	}
	h := newHotel(hotelConfig{ID: "x", API: "http://127.0.0.1:1", Concurrency: 40}, "k")
	if cap(h.conns.slots) != 104 || h.client.Transport.(*http.Transport).MaxConnsPerHost != 104+16 {
		t.Fatalf("hotel pool %d / transport %d, want 104 / 120", cap(h.conns.slots), h.client.Transport.(*http.Transport).MaxConnsPerHost)
	}
	for _, bad := range []hotelConfig{{DataConns: -1}, {DataConns: maxDataConns + 1}, {DataConnWaitSeconds: -2}, {DataConnWaitSeconds: maxDataConnWaitSecs + 1}} {
		if checkDataConnConfig(bad) == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if err := checkDataConnConfig(hotelConfig{DataConns: 400, DataConnWaitSeconds: -1}); err != nil {
		t.Fatal(err)
	}
}

func TestJoinRefusesABadDataPool(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	for _, body := range []map[string]any{
		{"id": "d1", "api": "http://127.0.0.1:1", "key": strings.Repeat("k", 32), "data_conns": -5},
		{"id": "d2", "api": "http://127.0.0.1:1", "key": strings.Repeat("k", 32), "data_conn_wait_seconds": 9999},
	} {
		status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", body)
		if status != 400 || errCode(doc) != "invalid_hotel" {
			t.Fatalf("join %v: %d %v", body, status, doc)
		}
	}
}

func TestExecAnswers503SoldOutWhenNoHotelConnectionFrees(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	f := tc.hotels[hotelOf(bid)]
	g := gateOf(tc, hotelOf(bid), 2, 200*time.Millisecond)
	free := fillConns(g)
	f.mu.Lock()
	before := len(f.execs)
	f.mu.Unlock()

	start := time.Now()
	status, hdr, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes/"+bid+"/exec", map[string]any{"cmd": []string{"true"}})
	took := time.Since(start)

	if status != 503 || errCode(doc) != "sold_out" || hdr.Get("Retry-After") != "5" {
		t.Fatalf("exec with every connection busy: %d %v Retry-After %q", status, doc, hdr.Get("Retry-After"))
	}
	if took < 200*time.Millisecond || took > 3*time.Second {
		t.Fatalf("the wait was not bounded at 200 ms: %v", took)
	}
	f.mu.Lock()
	after := len(f.execs)
	f.mu.Unlock()
	if after != before {
		t.Fatal("a refused exec reached the hotel")
	}
	if g.waits.Load() != 1 || g.refused.Load() != 1 || g.waiting.Load() != 0 {
		t.Fatalf("counters: waits %d refused %d waiting %d", g.waits.Load(), g.refused.Load(), g.waiting.Load())
	}
	// The counters are on the stats page.
	_, stats := tc.call(t, "key1", "GET", "/v1/broker/stats", nil)
	found := false
	for _, x := range stats["hotels"].([]any) {
		hd := x.(map[string]any)
		if hd["id"] == hotelOf(bid) {
			c := hd["conns"].(map[string]any)
			found = c["data_conns"] == 2.0 && c["conns_in_use"] == 2.0 && c["conn_refused"] == 1.0 && c["conn_waits"] == 1.0
		}
	}
	if !found {
		t.Fatalf("stats lack the pool counters: %v", stats["hotels"])
	}

	free()
	if status, _, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes/"+bid+"/exec", map[string]any{"cmd": []string{"true"}}); status != 200 {
		t.Fatalf("exec once a connection is free: %d %v", status, doc)
	}
	if len(g.slots) != 0 {
		t.Fatalf("the exec kept its connection slot: %d in use", len(g.slots))
	}
}

func TestAWaitingCallGetsTheConnectionThatFrees(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	g := gateOf(tc, hotelOf(bid), 1, 5*time.Second)
	free := fillConns(g)
	time.AfterFunc(300*time.Millisecond, free)

	status, _, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes/"+bid+"/exec", map[string]any{"cmd": []string{"true"}})

	if status != 200 {
		t.Fatalf("exec after a wait: %d %v", status, doc)
	}
	if g.waits.Load() != 1 || g.refused.Load() != 0 {
		t.Fatalf("waits %d refused %d", g.waits.Load(), g.refused.Load())
	}
}

func TestMinusOneWaitsUntilTheCallDeadlineAsBefore(t *testing.T) {
	g := &connGate{slots: make(chan struct{}, 1), wait: -1}
	free := fillConns(g)
	time.AfterFunc(400*time.Millisecond, free)
	release, err := g.acquire(context.Background(), "x")
	if err != nil {
		t.Fatalf("an unbounded wait gave up: %v", err)
	}
	release()

	// The call's own deadline still ends the wait.
	free = fillConns(g)
	defer free()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := g.acquire(ctx, "x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
}

func TestBackgroundCleanupIgnoresTheBound(t *testing.T) {
	g := &connGate{slots: make(chan struct{}, 1), wait: 50 * time.Millisecond}
	free := fillConns(g)
	time.AfterFunc(300*time.Millisecond, free)
	release, err := g.acquire(waitForConnUntilDeadline(context.Background()), "x")
	if err != nil {
		t.Fatalf("a reap gave up after the bound: %v", err)
	}
	release()
	if g.refused.Load() != 0 {
		t.Fatal("counted as refused")
	}
}

func TestALongExecHoldsItsConnectionUntilItAnswers(t *testing.T) {
	tc, release := execChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	g := gateOf(tc, hotelOf(bid), 1, 200*time.Millisecond)

	// A background exec holds the one connection while the hotel runs it.
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/execs", map[string]any{"cmd": []string{"long"}}); status != 202 {
		t.Fatalf("background exec: %d %v", status, doc)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(g.slots) != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(g.slots) != 1 {
		t.Fatal("the running exec holds no connection slot")
	}
	// A second command now gets 503 after the bound, not a silent wait.
	status, hdr, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes/"+bid+"/exec", map[string]any{"cmd": []string{"true"}})
	if status != 503 || errCode(doc) != "sold_out" || hdr.Get("Retry-After") == "" {
		t.Fatalf("second exec: %d %v", status, doc)
	}
	// The slot comes back when the hotel answers.
	release()
	deadline = time.Now().Add(5 * time.Second)
	for len(g.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(g.slots) != 0 {
		t.Fatal("the finished exec did not give its slot back")
	}
}

func TestBackgroundExecThatGetsNoConnectionIsLostAsSoldOut(t *testing.T) {
	tc, _ := execChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	g := gateOf(tc, hotelOf(bid), 1, 100*time.Millisecond)
	defer fillConns(g)()

	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/execs", map[string]any{"cmd": []string{"job"}})
	if status != 202 {
		t.Fatalf("start: %d %v", status, doc)
	}
	_, doc = tc.call(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/"+doc["exec_id"].(string)+"?wait=10", nil)
	if doc["state"] != "lost" || doc["reason"] != "sold_out" {
		t.Fatalf("background exec with no connection: %v", doc)
	}
}

func TestCompatExecAnswers503SoldOutWithRetryAfter(t *testing.T) {
	tc, id, _ := compatExecChain(t, t.TempDir())
	tc.b.mu.Lock()
	rm := tc.b.byUUID[id]
	tc.b.mu.Unlock()
	if rm == nil {
		t.Fatalf("no broker room for compat room %s", id)
	}
	g := gateOf(tc, rm.h.cfg.ID, 1, 100*time.Millisecond)
	free := fillConns(g)

	resp, raw := compatPost(t, tc, "/v1/sandboxes/"+id+"/exec", mustMarshal(map[string]any{"cmd": []string{"echo"}}))
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "5" || !strings.Contains(string(raw), `"sold_out"`) {
		t.Fatalf("compat exec with no connection: %d %q %s", resp.StatusCode, resp.Header.Get("Retry-After"), raw)
	}
	// Not cached under its idempotency key: the retry runs.
	free()
	if resp, raw := compatPost(t, tc, "/v1/sandboxes/"+id+"/exec", mustMarshal(map[string]any{"cmd": []string{"echo"}})); resp.StatusCode != 200 {
		t.Fatalf("compat exec after: %d %s", resp.StatusCode, raw)
	}
}

// compatPost is clientCall that also returns the response headers.
func compatPost(t *testing.T, tc *testChain, path string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", tc.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("User-Agent", "cathedral-harbor/0.1.5")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

func TestCreateMovesOnFromAHotelWithNoFreeConnectionAndReapsNothing(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "a", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	gb := gateOf(tc, "b", 1, 100*time.Millisecond)
	freeB := fillConns(gb)

	// The only hotel is busy: 503 sold_out with Retry-After, nothing sent.
	status, hdr, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status != 503 || errCode(doc) != "sold_out" || hdr.Get("Retry-After") != "5" {
		t.Fatalf("create on a busy hotel: %d %v Retry-After %q", status, doc, hdr.Get("Retry-After"))
	}
	f := tc.hotels["b"]
	f.mu.Lock()
	creates, bulk := len(f.creates), len(f.bulkDeletes)
	f.mu.Unlock()
	if creates != 0 || bulk != 0 {
		t.Fatalf("busy hotel got %d creates and %d reaps", creates, bulk)
	}
	var backoff time.Time
	var failed int
	setHotel(tc, "b", func(h *hotel) { backoff, failed = h.backoffUntil, h.failed })
	if !backoff.IsZero() || failed != 0 {
		t.Fatalf("a busy hotel was rested (%v) or counted failed (%d)", backoff, failed)
	}

	// With another hotel up, the create lands there.
	setHotel(tc, "c", func(h *hotel) { h.ok = true })
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		status, _, doc = tc.rawCall(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	}()
	wg.Wait()
	if status != 202 || hotelOf(doc["id"].(string)) != "c" {
		t.Fatalf("create with c up: %d %v", status, doc)
	}
	freeB()
}

func TestBatchCreateOnABusyHotelCarriesRetryAfter(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "a", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	defer fillConns(gateOf(tc, "b", 1, 50*time.Millisecond))()

	status, hdr, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 2})
	if status != 503 || hdr.Get("Retry-After") != "5" {
		t.Fatalf("batch create on a busy hotel: %d %v Retry-After %q", status, doc, hdr.Get("Retry-After"))
	}
}

func TestEnrollerCannotSetTheDataPool(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	body := map[string]any{"id": "m1", "api": "https://127.0.0.1:1", "health": "https://127.0.0.1:1", "key": joinKey, "sealed": true,
		"miner_hotkey": minerHotkey, "data_conns": 2000}
	if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", body); status != 403 || errCode(doc) != "enroller_scope" {
		t.Fatalf("enroller join with data_conns: %d %v", status, doc)
	}
}

func TestHealthPortCallsAreNotGated(t *testing.T) {
	tc := newChain(t)
	h := tc.b.hotelByID("b")
	g := gateOf(tc, "b", 1, 50*time.Millisecond)
	defer fillConns(g)()
	// /room/... calls (attestation, receipts) go to the Health port and never
	// wait behind room calls: a full data pool must not cost a hotel its admission.
	status, _, _, err := h.doBase(context.Background(), h.cfg.Health, "GET", "/room/health", nil, nil, 5*time.Second)
	if err != nil || status != 200 {
		t.Fatalf("health-port call with the data pool full: %d %v", status, err)
	}
	if g.waits.Load() != 0 {
		t.Fatal("a /room/ call waited for a data slot")
	}
}

func TestGuestRoomDeleteWaitsPastTheBoundAsBefore(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	g := gateOf(tc, hotelOf(bid), 1, 50*time.Millisecond)
	time.AfterFunc(400*time.Millisecond, fillConns(g))

	status, _, doc := tc.rawCall(t, "key1", "DELETE", "/v1/sandboxes/"+bid, nil)

	if status != 204 && status != 200 {
		t.Fatalf("delete that waited for a connection: %d %v", status, doc)
	}
	if g.refused.Load() != 0 || g.waits.Load() != 1 {
		t.Fatalf("delete: waits %d refused %d", g.waits.Load(), g.refused.Load())
	}
}

func TestCompatFileWriteAnswers503SoldOut(t *testing.T) {
	tc, id, _ := compatExecChain(t, t.TempDir())
	tc.b.mu.Lock()
	rm := tc.b.byUUID[id]
	tc.b.mu.Unlock()
	defer fillConns(gateOf(tc, rm.h.cfg.ID, 1, 50*time.Millisecond))()

	req, _ := http.NewRequest("PUT", tc.srv.URL+"/v1/sandboxes/"+id+"/files?path=/work/a.txt", strings.NewReader("hello"))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("User-Agent", "cathedral-harbor/0.1.5")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "5" || !strings.Contains(string(raw), `"sold_out"`) {
		t.Fatalf("compat file write with no connection: %d %q %s", resp.StatusCode, resp.Header.Get("Retry-After"), raw)
	}
}
