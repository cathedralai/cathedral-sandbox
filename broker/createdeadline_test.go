package main

import (
	"testing"
	"time"
)

// AB#862: create_timeout_seconds bounds the wait for a hotel create slot.

// oneBusyHotel leaves only hotel b up, with its single create slot held.
func oneBusyHotel(t *testing.T, tc *testChain) *hotel {
	t.Helper()
	setHotel(tc, "a", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	tc.b.cfg.MaxQueueWaitSeconds = -1 // never move: the deadline is what ends the wait
	bh := tc.b.hotelByID("b")
	setHotel(tc, "b", func(h *hotel) {
		h.sem = make(chan struct{}, 1)
		h.sem <- struct{}{}
	})
	return bh
}

func TestCreateTimeoutEndsASlotWaitWith503AndNoRoom(t *testing.T) {
	tc := newChain(t)
	oneBusyHotel(t, tc)
	t0 := time.Now()
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "create_timeout_seconds": 1})
	took := time.Since(t0)
	if status != 503 || errCode(doc) != "create_timeout" {
		t.Fatalf("want 503 create_timeout, got %d %v", status, doc)
	}
	if took < 900*time.Millisecond || took > 5*time.Second {
		t.Fatalf("answered after %v, want about 1 s", took)
	}
	if n := createsOn(tc)["b"]; n != 0 {
		t.Fatalf("%d creates reached the hotel", n)
	}
	g := tc.b.guests["g1"]
	tc.b.mu.Lock()
	pending, queued, hq := g.pending, g.queued, tc.b.hotelByID("b").queued
	tc.b.mu.Unlock()
	if pending != 0 || queued != 0 || hq != 0 {
		t.Fatalf("counts left after the timeout: pending %d guest queued %d hotel queued %d", pending, queued, hq)
	}
}

func TestCreateTimeoutAnswerCarriesRetryAfter(t *testing.T) {
	tc := newChain(t)
	oneBusyHotel(t, tc)
	resp, _ := tc.postRaw(t, "key1", "/v1/sandboxes", mustMarshal(map[string]any{"image": "alpine:3.20", "create_timeout_seconds": 1}))
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "5" {
		t.Fatalf("want 503 with Retry-After 5, got %d %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

func TestCreateWithoutTimeoutStillWaitsForTheSlot(t *testing.T) {
	tc := newChain(t)
	bh := oneBusyHotel(t, tc)
	go func() {
		time.Sleep(1500 * time.Millisecond)
		<-bh.sem // the slot frees after the 1 s a deadline would have allowed
	}()
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status != 202 {
		t.Fatalf("create without a deadline: %d %v", status, doc)
	}
}

func TestCreateTimeoutDoesNotCutACreateAlreadySent(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "a", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	tc.hotels["b"].createDelay = 1500 * time.Millisecond
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "create_timeout_seconds": 1})
	if status != 202 {
		t.Fatalf("a create sent before the deadline must finish: %d %v", status, doc)
	}
}

func TestBatchCreateTimeoutKeepsSentRoomsAndCountsTheRest(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "a", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	tc.b.cfg.MaxQueueWaitSeconds = -1
	tc.hotels["b"].createDelay = 1500 * time.Millisecond
	setHotel(tc, "b", func(h *hotel) { h.sem = make(chan struct{}, 1) }) // one create at a time
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 3, "create_timeout_seconds": 1})
	if status != 202 {
		t.Fatalf("batch: %d %v", status, doc)
	}
	if n := doc["count"].(float64); n != 1 {
		t.Fatalf("started %v rooms, want 1: %v", n, doc)
	}
	errs, _ := doc["errors"].(map[string]any)
	if errs["503 create_timeout"] != float64(2) {
		t.Fatalf("errors %v, want 2 x 503 create_timeout", errs)
	}
	if n := createsOn(tc)["b"]; n != 1 {
		t.Fatalf("%d creates reached the hotel, want 1", n)
	}
}

func TestCreateTimeoutValuesAreCheckedAndNeverSentToTheHotel(t *testing.T) {
	tc := newChain(t)
	for _, v := range []any{0, -1, 721, 1.5, "10", true} {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "create_timeout_seconds": v})
		if status != 400 || errCode(doc) != "invalid_create_timeout" {
			t.Fatalf("create_timeout_seconds %v: want 400 invalid_create_timeout, got %d %v", v, status, doc)
		}
	}
	for _, v := range []any{nil, 1, 720} {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "create_timeout_seconds": v})
		if status != 202 {
			t.Fatalf("create_timeout_seconds %v: %d %v", v, status, doc)
		}
		if _, sent := tc.lastCreate(t)["create_timeout_seconds"]; sent {
			t.Fatalf("create_timeout_seconds %v reached the hotel", v)
		}
	}
}

func TestCompatCreateTimeoutEndsASlotWait(t *testing.T) {
	tc := newChain(t)
	oneBusyHotel(t, tc)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "sealed": false, "create_timeout_seconds": 1}), nil)
	if status != 503 {
		t.Fatalf("compat: want 503, got %d %v", status, doc)
	}
	if d, _ := doc["detail"].(map[string]any); d["error"] != "create_timeout" {
		t.Fatalf("compat error: %v", doc)
	}
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "create_timeout_seconds": 721}), nil)
	if status != 400 {
		t.Fatalf("compat 721: want 400, got %d %v", status, doc)
	}
}

func TestCompatExecWithoutTimeoutGets600Seconds(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	id := doc["id"].(string)
	lastTimeout := func() float64 {
		var got float64
		for _, f := range tc.hotels {
			f.mu.Lock()
			for _, e := range f.execs {
				got = e["timeout_seconds"].(float64)
			}
			f.mu.Unlock()
		}
		return got
	}
	for _, c := range []struct {
		body map[string]any
		want float64
	}{
		{map[string]any{"cmd": []string{"true"}}, 600},
		{map[string]any{"cmd": []string{"true"}, "timeout_seconds": 0}, 600},
		{map[string]any{"cmd": []string{"true"}, "timeout_seconds": 1800}, 1800},
		{map[string]any{"cmd": []string{"true"}, "timeout_seconds": 14400}, 14400},
	} {
		status, doc := tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/exec", mustMarshal(c.body), nil)
		if status != 200 {
			t.Fatalf("exec %v: %d %v", c.body, status, doc)
		}
		if got := lastTimeout(); got != c.want {
			t.Fatalf("exec %v: hotel got timeout %v, want %v", c.body, got, c.want)
		}
	}
	_, cat := tc.clientCall(t, "GET", "/v1/sandboxes/catalog", nil, nil)
	if cat["default_exec_seconds"] != float64(600) || cat["max_exec_seconds"] != float64(14400) {
		t.Fatalf("catalog: default %v max %v", cat["default_exec_seconds"], cat["max_exec_seconds"])
	}
	tc.b.cfg.MaxExecSeconds = 300 // an operator ceiling under 600 wins
	if status, _ := tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/exec", mustMarshal(map[string]any{"cmd": []string{"true"}}), nil); status != 200 || lastTimeout() != 300 {
		t.Fatalf("operator ceiling 300: hotel got %v", lastTimeout())
	}
}

func TestCreateTimeoutEndsTheWaitForAHotelConnection(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "a", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	bh := tc.b.hotelByID("b")
	// Every data connection to b is in use; the bounded wait is 30 s.
	bh.conns.wait = 30 * time.Second
	for i := 0; i < cap(bh.conns.slots); i++ {
		bh.conns.slots <- struct{}{}
	}
	t0 := time.Now()
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "create_timeout_seconds": 1})
	if status != 503 || errCode(doc) != "create_timeout" {
		t.Fatalf("want 503 create_timeout, got %d %v", status, doc)
	}
	if took := time.Since(t0); took > 5*time.Second {
		t.Fatalf("answered after %v, want about 1 s", took)
	}
	if n := createsOn(tc)["b"]; n != 0 {
		t.Fatalf("%d creates reached the hotel", n)
	}
	tc.b.mu.Lock()
	creating, failed := bh.creating, bh.failed
	tc.b.mu.Unlock()
	if creating != 0 || failed != 0 {
		t.Fatalf("hotel counts after a client deadline: creating %d failed %d", creating, failed)
	}
}

func TestCompatBatchCreateTimeoutAnswersTheFirstFailure(t *testing.T) {
	tc := newChain(t)
	oneBusyHotel(t, tc)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "sealed": false, "count": 3, "create_timeout_seconds": 1}), nil)
	if d, _ := doc["detail"].(map[string]any); status != 503 || d["error"] != "create_timeout" {
		t.Fatalf("compat count 3, no slot, deadline 1 s: %d %v", status, doc)
	}
	if n := createsOn(tc)["b"]; n != 0 {
		t.Fatalf("%d creates reached the hotel", n)
	}
}
