package main

import (
	"sync"
	"testing"
	"time"
)

func setHotel(tc *testChain, id string, fn func(h *hotel)) {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	fn(tc.b.hotelByID(id))
}

func TestQueuedCreateMovesToAnotherHotelAfterTheWaitLimit(t *testing.T) {
	tc := newChain(t)
	tc.b.cfg.MaxQueueWaitSeconds = 0.3
	tc.hotels["a"].createDelay = 1500 * time.Millisecond
	setHotel(tc, "a", func(h *hotel) { h.sem = make(chan struct{}, 1) }) // one create at a time
	setHotel(tc, "b", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	start := time.Now()
	var status int
	var doc map[string]any
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 4})
	}()
	time.Sleep(100 * time.Millisecond) // all 4 are queued at a; now b can take rooms
	setHotel(tc, "b", func(h *hotel) { h.ok = true })
	wg.Wait()
	took := time.Since(start)
	if status != 202 || doc["count"].(float64) != 4 {
		t.Fatalf("create: %d %v", status, doc)
	}
	on := createsOn(tc)
	if on["b"] < 2 || on["a"]+on["b"] != 4 {
		t.Fatalf("creates did not move: %v", on)
	}
	// One at a time at a would take 6 s.
	if took > 4*time.Second {
		t.Fatalf("took %v", took)
	}
	var moved int
	setHotel(tc, "a", func(h *hotel) { moved = h.moved })
	if moved < 2 {
		t.Fatalf("moved %d", moved)
	}
}

func TestQueuedCreateStaysWhenNoOtherHotelIsEligible(t *testing.T) {
	tc := newChain(t)
	tc.b.cfg.MaxQueueWaitSeconds = 0.1
	tc.hotels["a"].createDelay = 300 * time.Millisecond
	setHotel(tc, "a", func(h *hotel) { h.sem = make(chan struct{}, 1) })
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 3, "hotels": []string{"a"}})
	if status != 202 || doc["count"].(float64) != 3 {
		t.Fatalf("create: %d %v", status, doc)
	}
	if on := createsOn(tc); on["a"] != 3 || on["b"]+on["c"] != 0 {
		t.Fatalf("creates left the chosen hotel: %v", on)
	}
}

func share(tc *testChain, n int) map[string]int {
	out := map[string]int{}
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	for i := 0; i < n; i++ {
		if h := tc.b.pick(nil, placement{}); h != nil {
			out[h.cfg.ID]++
		}
	}
	return out
}

func TestWeightFollowsCPUHeadroomCreateTimeAndQueue(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "c", func(h *hotel) { h.ok = false })

	// Same free rooms; a at 99% CPU, b at 10%.
	setHotel(tc, "a", func(h *hotel) { h.cpuPct = 99 })
	setHotel(tc, "b", func(h *hotel) { h.cpuPct = 10 })
	if s := share(tc, 4000); s["b"] < 3600 {
		t.Fatalf("cpu: %v", s)
	}

	// Same CPU; a creates in 5 s, b in 0.5 s.
	setHotel(tc, "a", func(h *hotel) { h.cpuPct, h.createEWMA = 20, 5 })
	setHotel(tc, "b", func(h *hotel) { h.cpuPct, h.createEWMA = 20, 0.5 })
	if s := share(tc, 4000); s["b"] < 3600 {
		t.Fatalf("create time: %v", s)
	}

	// Same CPU and create time; a has a long queue. More free rooms at a do not win.
	setHotel(tc, "a", func(h *hotel) { h.createEWMA, h.queued, h.slots = 1, 60, 200 })
	setHotel(tc, "b", func(h *hotel) { h.createEWMA, h.queued, h.slots = 1, 0, 50 })
	// a: 140 free, 15 s expected wait; b: 50 free, no wait. b gets about 85%.
	if s := share(tc, 4000); s["b"] < 3200 {
		t.Fatalf("queue: %v", s)
	}

	// No data yet: weight is free rooms, as before.
	setHotel(tc, "a", func(h *hotel) { h.cpuPct, h.createEWMA, h.queued, h.slots = 0, 0, 0, 100 })
	setHotel(tc, "b", func(h *hotel) { h.cpuPct, h.createEWMA, h.queued, h.slots = 0, 0, 0, 100 })
	if s := share(tc, 4000); s["a"] < 1700 || s["b"] < 1700 {
		t.Fatalf("even: %v", s)
	}
}

func TestCreateTimeAverage(t *testing.T) {
	h := &hotel{}
	h.noteCreate(2 * time.Second)
	if h.createEWMA != 2 {
		t.Fatalf("first: %v", h.createEWMA)
	}
	h.noteCreate(0)
	if h.createEWMA < 1.59 || h.createEWMA > 1.61 {
		t.Fatalf("second: %v", h.createEWMA)
	}
}
