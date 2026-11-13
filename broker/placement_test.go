package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

	// Same CPU; a creates in 5 s, b in 0.5 s. b's weight is 10x a's, so b
	// expects 10/11 of 4000 = 3636 picks, standard deviation about 18. A floor
	// of 3600 sat two deviations below: it failed 14 of 400 local runs and once
	// on CI (2026-10-23, b 3597). 3500 is more than seven deviations below.
	setHotel(tc, "a", func(h *hotel) { h.cpuPct, h.createEWMA = 20, 5 })
	setHotel(tc, "b", func(h *hotel) { h.cpuPct, h.createEWMA = 20, 0.5 })
	if s := share(tc, 4000); s["b"] < 3500 {
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

// Run 5 rerun: creates that had left one hotel never went back to it, so a
// queue of 300 stayed on a full hotel while the hotel they had left was idle.
func TestQueuedCreateCanGoBackToAHotelItLeft(t *testing.T) {
	tc := newChain(t)
	tc.b.cfg.MaxQueueWaitSeconds = 0.2
	a, bh := tc.b.hotelByID("a"), tc.b.hotelByID("b")
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	setHotel(tc, "b", func(h *hotel) {
		h.sem = make(chan struct{}, 1)
		h.sem <- struct{}{} // b's only slot is busy for the whole test
		h.creating = 1
		h.createEWMA = 30
	})
	g := tc.b.guests["g1"]
	tc.b.mu.Lock()
	bh.queued++
	g.queued++
	tc.b.mu.Unlock()
	tried := map[*hotel]bool{a: true, bh: true} // it came from a earlier
	done := make(chan *hotel, 1)
	go func() { done <- tc.b.waitSlot(context.Background(), g, bh, placement{}, tried) }()
	select {
	case got := <-done:
		if got != a {
			t.Fatalf("moved to %v", got)
		}
		<-a.sem
	case <-time.After(3 * time.Second):
		t.Fatalf("the create stayed at the busy hotel")
	}
}

func TestQueuedCreateDoesNotMoveForASmallGain(t *testing.T) {
	tc := newChain(t)
	tc.b.cfg.MaxQueueWaitSeconds = 0.1
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	a, bh := tc.b.hotelByID("a"), tc.b.hotelByID("b")
	setHotel(tc, "a", func(h *hotel) {
		h.sem = make(chan struct{}, 1)
		h.sem <- struct{}{}
		h.creating = 1
		h.createEWMA = 1
		h.queued = 3
	})
	setHotel(tc, "b", func(h *hotel) {
		h.sem = make(chan struct{}, 1)
		h.sem <- struct{}{}
		h.creating = 1
		h.createEWMA = 1
		h.queued = 3
	})
	g := tc.b.guests["g1"]
	tc.b.mu.Lock()
	bh.queued++
	g.queued++
	tc.b.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	if got := tc.b.waitSlot(ctx, g, bh, placement{}, map[*hotel]bool{}); got != nil {
		t.Fatalf("got a slot at %v", got.cfg.ID)
	}
	var moved int
	setHotel(tc, "b", func(h *hotel) { moved = h.moved })
	if moved != 0 {
		t.Fatalf("moved %d times between equal hotels", moved)
	}
	_ = a
}

// ---------------------------------------------------------------- create failover (AB#338)

// failOnMiner joins sealed miner hotel m1 for guest g1, makes its creates
// fail with status (after starting the room when afterStart), and creates
// one room on m1 or b. The policy puts m1 in the prefer tier, so m1 is asked
// first and b is the failover.
func failOnMiner(t *testing.T, status int, afterStart bool) (*testChain, int, map[string]any) {
	t.Helper()
	tc := newChainState(t, t.TempDir())
	optInMiner(t, tc, "g1")
	m := joinMiner(t, tc, "m1", true, 5, nil)
	m.mu.Lock()
	m.createFail, m.createFailAfterStart = status, afterStart
	m.mu.Unlock()
	st, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"m1", "b"}})
	return tc, st, doc
}

// oneBilledRoom checks the no-double-charge property after a failover: the
// guest got one 202, owns one room, the quota counts one running room, and
// the failed hotel holds no room of the guest, also after its next sync
// (which would otherwise adopt an orphan under the guest label and bill it).
// wantFailed is m1's failure count: 1 for an error answer, 0 for a 2xx.
func oneBilledRoom(t *testing.T, tc *testChain, doc map[string]any, wantFailed int) {
	t.Helper()
	if !strings.HasPrefix(doc["id"].(string), "b.") || doc["hotel"] != "b" {
		t.Fatalf("room %v on hotel %v; want the failover hotel b", doc["id"], doc["hotel"])
	}
	if n, nb := creates(tc, "m1"), creates(tc, "b"); n != 1 || nb != 1 {
		t.Fatalf("create calls: m1 %d, b %d; want one each (one retry on another hotel)", n, nb)
	}
	syncNow(tc, "m1")
	syncNow(tc, "b")
	_, list := tc.call(t, "key1", "GET", "/v1/sandboxes", nil)
	_, q := tc.call(t, "key1", "GET", "/v1/quota", nil)
	running := q["guest"].(map[string]any)["running_sandboxes"]
	if list["count"] != 1.0 || running != 1.0 {
		t.Fatalf("one 202, but the guest lists %v rooms (%v) and quota says %v running; want 1", list["count"], list["sandboxes"], running)
	}
	m := tc.hotels["m1"]
	m.mu.Lock()
	left := len(m.rooms)
	m.mu.Unlock()
	tc.b.mu.Lock()
	created, failed := tc.b.guests["g1"].created, tc.b.hotelByID("m1").failed
	tc.b.mu.Unlock()
	if left != 0 || created != 1 {
		t.Fatalf("m1 still holds %d rooms, guest created count %d; want 0 and 1", left, created)
	}
	if failed != wantFailed {
		t.Fatalf("m1 failed count %d; want %d", failed, wantFailed)
	}
}

// A miner hotel that cannot start the room: the create moves to a healthy
// hotel in the same request, and m1 is asked for no delete (it has nothing).
func TestMinerCreateFailureFailsOverToAnotherHotel(t *testing.T) {
	tc, status, doc := failOnMiner(t, 500, false)
	if status != 202 {
		t.Fatalf("create with miner m1 failing: %d %v", status, doc)
	}
	oneBilledRoom(t, tc, doc, 1)
	if n := callsTo(tc.hotels["m1"], "DELETE /v1/sandboxes/"); n != 0 {
		t.Fatalf("m1 got %d room deletes; want 0", n)
	}
}

// A miner hotel (or a proxy in front of it) that started the room and then
// answered an error, or answered 2xx with no room id: the create still moves
// to another hotel, and the room m1 started is removed before the guest gets
// its answer, so the guest is not billed for two rooms.
func TestMinerCreateFailureAfterTheRoomStartedIsReaped(t *testing.T) {
	for _, status := range []int{500, 504, 200} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			tc, st, doc := failOnMiner(t, status, true)
			if st != 202 {
				t.Fatalf("create with miner m1 failing after start: %d %v", st, doc)
			}
			if n := callsTo(tc.hotels["m1"], "DELETE /v1/sandboxes/"); n != 1 {
				t.Fatalf("m1 got %d room deletes before the answer; want 1, for the room it started", n)
			}
			wantFailed := 1
			if status == 200 {
				wantFailed = 0 // the broker rests a hotel on errors only
			}
			oneBilledRoom(t, tc, doc, wantFailed)
		})
	}
}

// The reap trusts a room's own labels, not the hotel's label filter: a hotel
// that ignores the filter must not get another request's room deleted.
func TestReapKeepsRoomsOfOtherRequestsWhenTheHotelIgnoresTheFilter(t *testing.T) {
	tc := newChain(t)
	other := tc.room(t, "key2", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	hb := tc.b.hotelByID("b")
	upstream := hb.cfg.API
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method == "GET" && r.URL.Path == "/v1/sandboxes" {
			r.URL.RawQuery = "" // the hotel lists every room it holds
		}
		status, hdr, out := forwardTo(upstream, r, body)
		passThrough(w, status, hdr, out)
	}))
	t.Cleanup(proxy.Close)
	hb.cfg.API = proxy.URL
	tc.hotels["b"].mu.Lock()
	tc.hotels["b"].createFail, tc.hotels["b"].createFailAfterStart = 500, true
	tc.hotels["b"].mu.Unlock()
	setHotel(tc, "c", func(h *hotel) { h.ok = false }) // b is the only hotel: the create fails there
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}})
	if status != 500 {
		t.Fatalf("create on a failing b: %d %v", status, doc)
	}
	if n := callsTo(tc.hotels["b"], "DELETE /v1/sandboxes/"); n != 1 {
		t.Fatalf("b got %d room deletes; want 1, for the failed create's room only", n)
	}
	if st, d := tc.call(t, "key2", "GET", "/v1/sandboxes/"+other, nil); st != 200 {
		t.Fatalf("guest g2's room %s after g1's reap: %d %v", other, st, d)
	}
}
