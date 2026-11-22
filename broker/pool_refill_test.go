package main

// Tests of the ready-room refill policy and hotel bounds (AB#894, phase 2
// work order PR 3; design 6.1, 6.3).

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Per hotel at most refill_per_second pool creates a second, over all keys,
// and never above 4; a lower setting is the lower cap.
func TestRefillRateCaps(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, func(c *config) {
		c.ReadyRooms.Keys = append(c.ReadyRooms.Keys, readyRoomKeyEntry{Template: "lfm3-1.7b"})
	})
	poolSpacingFactor = 1.05
	f := pc.hotels["a"]
	pc.up("a")
	if st, _ := pc.operator("PUT", "/v1/broker/ready-rooms", map[string]any{"per_hotel": map[string]int{"node-22": 1},
		"refill_per_second": 5, "refill_during_claims": 1, "reserve_share": 0.25}); st != 400 {
		t.Fatalf("refill_per_second 5: %d, want 400 (at most 4)", st)
	}
	if st, doc := pc.operator("PUT", "/v1/broker/ready-rooms", map[string]any{"per_hotel": map[string]int{"node-22": 30, "lfm3-1.7b": 30},
		"refill_per_second": 4, "refill_during_claims": 1, "reserve_share": 0.25}); st != 200 {
		t.Fatalf("PUT: %d %v", st, doc)
	}
	if _, doc := pc.operator("GET", "/v1/broker/ready-rooms", nil); doc["creates_per_second_per_hotel_max"] != float64(4) {
		t.Fatalf("GET creates_per_second_per_hotel_max %v, want 4", doc["creates_per_second_per_hotel_max"])
	}
	probe := startSchedProbe(t)
	stop := make(chan struct{})
	f.createsReach(12, 30*time.Second, stop)
	pc.runPool(31*time.Second, stop)
	starts := f.createStarts()
	node, lfm := 0, 0
	for _, c := range f.creates() {
		if strings.Contains(string(c.body), nodeImage()) {
			node++
		} else {
			lfm++
		}
	}
	if w := probe.maxInWindowLate(starts, time.Second); w > 4 {
		t.Fatalf("%d pool creates within one second over both keys, want at most 4", w)
	}
	if len(starts) < 12 || node == 0 || lfm == 0 {
		t.Fatalf("%d creates in 30 s (%d node-22, %d lfm), want 12 over both keys", len(starts), node, lfm)
	}
	for i := 1; i < 12; i++ { // about 4 a second: spaced 263 ms
		if !probe.gapAtMost(starts[i-1], starts[i], 400*time.Millisecond) {
			t.Fatalf("creates %d and %d %s apart at 4 a second", i-1, i, starts[i].Sub(starts[i-1]))
		}
	}
	// A lower setting is the lower cap.
	g := newPoolChain(t, []string{"b"}, nil)
	poolSpacingFactor = 1.05
	g.up("b")
	g.putRefill(30, 2, 1)
	if _, doc := g.operator("GET", "/v1/broker/ready-rooms", nil); doc["creates_per_second_per_hotel_max"] != float64(2) {
		t.Fatalf("GET creates_per_second_per_hotel_max %v at refill 2, want 2", doc["creates_per_second_per_hotel_max"])
	}
	gstop := make(chan struct{})
	g.hotels["b"].createsReach(6, 30*time.Second, gstop)
	g.runPool(31*time.Second, gstop)
	if s := g.hotels["b"].createStarts(); probe.maxInWindowLate(s, time.Second) > 2 || len(s) < 6 {
		t.Fatalf("refill_per_second 2: %d creates in 30 s, %d within one second", len(s), probe.maxInWindowLate(s, time.Second))
	}
}

// Claims every 400 ms for 30 s on a hotel never stop its refill: no pause
// timer, at least 1 create a second throughout (the longest gap between two
// creates stays near 1 s, plus what a loaded machine adds: schedProbe).
func TestRefillNeverStopsUnderRepeatedBursts(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	pc.up("a")
	pc.putRefill(40, 4, 1)
	pc.fill("a", 40) // full, no pacing
	poolSpacingFactor = 1.05
	before := len(f.createStarts())
	probe := startSchedProbe(t)
	stop := make(chan struct{})
	claimed := 0
	go func() {
		defer close(stop)
		end := time.Now().Add(30 * time.Second)
		for time.Now().Before(end) {
			if pc.fakeClaim("a", 100*time.Millisecond) {
				claimed++
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()
	t0 := time.Now()
	pc.runPool(40*time.Second, stop)
	starts := f.createStarts()[before:]
	lost := probe.late(t0, time.Now()) // a loaded machine runs fewer claims and creates in 30 s
	if want := 60 - int(lost/(400*time.Millisecond)); claimed < want {
		t.Fatalf("%d claims in 30 s, want about 75 (at least %d, %s lost to load)", claimed, want, lost)
	}
	if want := 26 - int(lost/(1050*time.Millisecond)); len(starts) < want {
		t.Fatalf("%d creates during 30 s of claims, want at least %d (%s lost to load)", len(starts), want, lost)
	}
	prev := t0
	for _, s := range starts {
		if !probe.gapAtMost(prev, s, 1200*time.Millisecond) {
			t.Fatalf("refill paused %s during the claims (%s of it load)", s.Sub(prev), probe.late(prev, s.Add(probeSlack)))
		}
		prev = s
	}
}

// While a claim is in flight refill runs at refill_during_claims, and for 1 s
// after the last ends; a key below a quarter of its target refills at the
// full rate whatever the claims.
func TestRefillFloorBelowQuarter(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	h := pc.b.hotelByID("a")
	pc.up("a")
	pc.putRefill(40, 4, 1)
	rate := func(ready, claims int, endedAgo time.Duration) float64 {
		pc.b.mu.Lock()
		defer pc.b.mu.Unlock()
		ph := pc.b.pool.hotel("a")
		saved := ph.rooms
		ph.rooms = map[string]*poolRoom{}
		for i := 0; i < ready; i++ {
			ph.rooms[string(rune('a'+i))] = &poolRoom{state: poolReady, key: "node-22"}
		}
		ph.claims = claims
		ph.claimEnd = time.Time{}
		if endedAgo > 0 {
			ph.claimEnd = time.Now().Add(-endedAgo)
		}
		r := pc.b.poolRateLocked(h, ph, time.Now())
		ph.rooms, ph.claims, ph.claimEnd = saved, 0, time.Time{}
		return r
	}
	for _, c := range []struct {
		ready, claims int
		ago           time.Duration
		want          float64
	}{
		{20, 0, 0, 4},                      // no claims: the full rate
		{20, 1, 0, 1},                      // a claim in flight: refill_during_claims
		{20, 0, 500 * time.Millisecond, 1}, // and for 1 s after the last ends
		{20, 0, 1500 * time.Millisecond, 4},
		{10, 1, 0, 1}, // a quarter of 40 is not below it
		{9, 1, 0, 4},  // below a quarter: the full rate, claims or not
		{0, 3, 0, 4},
	} {
		if got := rate(c.ready, c.claims, c.ago); got != c.want {
			t.Fatalf("ready %d, claims %d, ended %s ago: rate %v, want %v", c.ready, c.claims, c.ago, got, c.want)
		}
	}
	// On the loop: a claim held in flight the whole time; the first 10 rooms
	// (below a quarter) come at the full rate, the next ones at 1 a second.
	// Gaps get what a loaded machine adds (schedProbe).
	poolSpacingFactor = 1.05
	probe := startSchedProbe(t)
	stop := make(chan struct{})
	pc.hotels["a"].createsReach(13, 40*time.Second, stop)
	pc.b.poolClaimBegin(h)
	pc.runPool(41*time.Second, stop)
	pc.b.poolClaimEnd(h)
	s := pc.hotels["a"].createStarts()
	if len(s) < 13 {
		t.Fatalf("%d creates in 40 s, want 10 fast ones and 3 slow ones", len(s))
	}
	for i := 1; i < 10; i++ {
		if !probe.gapAtMost(s[i-1], s[i], 500*time.Millisecond) {
			t.Fatalf("create %d came %s after the one before (%s of it load), below a quarter: want the full rate", i, s[i].Sub(s[i-1]), probe.late(s[i-1], s[i].Add(probeSlack)))
		}
	}
	for i := 11; i < len(s); i++ {
		if !probe.gapAtLeast(s[i-1], s[i], 950*time.Millisecond) {
			t.Fatalf("create %d came %s after the one before, above a quarter during a claim: want 1 a second", i, s[i].Sub(s[i-1]))
		}
	}
}

// The hotel bounds: every pool room at most 20% of the slots and 5% of the
// memory (an idle room's footprint); no pool create under 10% free slots or
// at 80% room disk or more. For a 480-slot hotel (nc-sealed-2 and -3 today)
// the bound is 96; for a 1,000-slot hotel 200.
func TestPoolRespectsSlotDiskAndMemoryBounds(t *testing.T) {
	type hotelView = map[string]any
	view := func(pc *poolChain) hotelView {
		_, doc := pc.operator("GET", "/v1/broker/ready-rooms", nil)
		return doc["hotels"].(map[string]any)["a"].(map[string]any)
	}
	fillTo := func(pc *poolChain, n int) {
		for i := 0; i < 4*n+20 && pc.counts("a").ready < n; i++ {
			pc.step("a")
		}
		pc.steps("a", 3)
	}
	t.Run("480 slots", func(t *testing.T) {
		pc := newPoolChain(t, []string{"a"}, nil)
		pc.hotels["a"].set(func(f *fakePoolHotel) { f.slots = 480 })
		pc.up("a")
		pc.target(100)
		fillTo(pc, 100)
		v := view(pc)
		if c := pc.counts("a"); c.ready != 96 || v["bound"] != float64(96) || v["bound_by_slots"] != float64(96) {
			t.Fatalf("480 slots, target 100: %+v, view %v; want 96 ready", c, v)
		}
		if why, _ := v["why_no_creates"].(string); !strings.Contains(why, "pool bound reached") {
			t.Fatalf("why_no_creates %q", why)
		}
		if n := len(pc.hotels["a"].creates()); n != 96 {
			t.Fatalf("%d creates, want 96", n)
		}
	})
	t.Run("1000 slots", func(t *testing.T) {
		pc := newPoolChain(t, []string{"a"}, nil)
		pc.up("a")
		pc.target(100)
		fillTo(pc, 100)
		if c, v := pc.counts("a"), view(pc); c.ready != 100 || v["bound"] != float64(200) {
			t.Fatalf("1,000 slots, target 100: %+v, view %v; want 100 ready, bound 200", c, v)
		}
	})
	t.Run("quarantine counts in the bound", func(t *testing.T) {
		pc := newPoolChain(t, []string{"a"}, nil)
		f := pc.hotels["a"]
		f.set(func(f *fakePoolHotel) { f.slots = 480 })
		for i := 0; i < 40; i++ {
			f.addRoom("q"+string(rune('a'+i/26))+string(rune('a'+i%26)), "pool", "claim")
		}
		pc.up("a")
		pc.target(100)
		fillTo(pc, 56)
		if c := pc.counts("a"); c.ready != 56 || c.quarantined != 40 {
			t.Fatalf("480 slots, 40 quarantined, target 100: %+v; want 56 ready", c)
		}
	})
	t.Run("free slots under 10%", func(t *testing.T) {
		pc := newPoolChain(t, []string{"a"}, nil)
		f := pc.hotels["a"]
		f.set(func(f *fakePoolHotel) { f.slots = 480 })
		f.addCustomerRooms(433) // 47 free: under 48
		pc.up("a")
		pc.target(10)
		pc.steps("a", 4)
		if n := len(f.creates()); n != 0 {
			t.Fatalf("%d pool creates with 47 of 480 slots free, want 0", n)
		}
		if why, _ := view(pc)["why_no_creates"].(string); !strings.Contains(why, "under 10%") {
			t.Fatalf("why_no_creates %q", why)
		}
		f.set(func(f *fakePoolHotel) { delete(f.rooms, "cust-0") }) // 48 free: 10%
		pc.sync("a")
		pc.letGo("a")
		pc.steps("a", 2)
		if n := len(f.creates()); n == 0 {
			t.Fatal("no pool create with 10% of the slots free")
		}
	})
	t.Run("room disk at 80%", func(t *testing.T) {
		pc := newPoolChain(t, []string{"a"}, nil)
		f := pc.hotels["a"]
		pc.up("a") // warm first: the catalog pre-pull itself waits at 80% (prewarm.go)
		full := 80.0
		f.set(func(f *fakePoolHotel) { f.diskPct = &full })
		pc.sync("a")
		pc.target(10)
		pc.steps("a", 4)
		if n := len(f.creates()); n != 0 {
			t.Fatalf("%d pool creates at 80%% room disk, want 0", n)
		}
		under := 79.9
		f.set(func(f *fakePoolHotel) { f.diskPct = &under })
		pc.sync("a")
		pc.steps("a", 2)
		if n := len(f.creates()); n == 0 {
			t.Fatal("no pool create at 79.9% room disk")
		}
	})
	t.Run("memory 5%", func(t *testing.T) {
		pc := newPoolChain(t, []string{"a"}, nil)
		pc.hotels["a"].set(func(f *fakePoolHotel) { f.memPct, f.memGiB = 25, 2 }) // an 8 GiB hotel: 409.6 MiB is 11 idle rooms
		pc.up("a")
		pc.target(100)
		fillTo(pc, 11)
		if c, v := pc.counts("a"), view(pc); c.ready != 11 || v["bound_by_memory"] != float64(11) || v["bound"] != float64(11) {
			t.Fatalf("8 GiB hotel, target 100: %+v, view %v; want 11 ready", c, v)
		}
	})
	t.Run("no memory reported", func(t *testing.T) {
		pc := newPoolChain(t, []string{"a"}, nil)
		pc.hotels["a"].set(func(f *fakePoolHotel) { f.memPct, f.memGiB = 0, 0 })
		pc.up("a")
		if v := view(pc); v["bound_by_memory"] != nil || v["bound"] != float64(200) {
			t.Fatalf("no memory reported: view %v, want the slot bound alone", v)
		}
	})
}

// Under 5% free slots the pool gives slots back to customers: ready rooms
// are deleted, oldest first, until 5% is free again, and no more; quarantined
// rooms are never deleted, even when nothing else is left.
func TestPoolYieldsSlotsToCustomersNeverDeletingQuarantine(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	f.set(func(f *fakePoolHotel) { f.slots = 480 })
	for i := 0; i < 10; i++ {
		f.addRoom("q"+string(rune('a'+i)), "pool", "claim")
	}
	pc.up("a")
	pc.target(30)
	pc.fill("a", 30)
	f.addCustomerRooms(430) // 480 - 10 - 30 - 430: 10 free, under 24 (5%)
	pc.sync("a")
	pc.steps("a", 3)
	dels := f.roomDeletes()
	if len(dels) != 14 {
		t.Fatalf("%d ready rooms given back, want 14 (to 24 free, 5%%)", len(dels))
	}
	for i, d := range dels {
		if want := "/v1/sandboxes/sbx-" + strconv.Itoa(i+1); d.path != want {
			t.Fatalf("give-back %d deleted %s, want %s: oldest first", i, d.path, want)
		}
	}
	if n := len(f.creates()); n != 30 {
		t.Fatalf("%d creates, want 30: no refill under 10%% free", n)
	}
	pc.letGo("a")
	f.addCustomerRooms(40) // full: only the 16 ready and the 10 quarantined are pool rooms
	pc.sync("a")
	for i := 0; i < 4; i++ {
		pc.steps("a", 2)
		pc.letGo("a")
	}
	for _, d := range f.roomDeletes() {
		if strings.HasPrefix(d.path, "/v1/sandboxes/q") {
			t.Fatalf("quarantined room %s deleted", d.path)
		}
	}
	if c := pc.counts("a"); c.ready != 0 || c.quarantined != 10 {
		t.Fatalf("after the hotel filled: %+v, want 0 ready and the 10 quarantined", c)
	}
}

// The spacing between two pool creates counts from when a create really
// starts: a slow delete earlier in the same step does not let the next
// step start another create at once (codex review of #663).
func TestPoolCreateSpacingCountsFromTheActualStart(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	pc.up("a")
	pc.putRefill(3, 1, 1) // 1 a second
	f.set(func(f *fakePoolHotel) { f.createTTL = 19 * time.Minute })
	pc.step("a") // sbx-1, retired on the next step
	f.set(func(f *fakePoolHotel) { f.createTTL, f.deleteDelay = 0, 1100*time.Millisecond })
	poolSpacingFactor = 1.05
	probe := startSchedProbe(t)
	time.Sleep(1100 * time.Millisecond) // the spacing since sbx-1 has passed
	pc.step("a")                        // deletes sbx-1 (1.1 s), then starts a create
	started := time.Now()
	pc.step("a") // at once: no create yet
	s := f.createStarts()
	// A loaded machine can hold the second step back past the spacing; then
	// a create is due, and the gaps below still decide.
	if len(s) != 2 && time.Since(started) < 900*time.Millisecond {
		t.Fatalf("%d creates, want 2 (sbx-1 and its replacement)", len(s))
	}
	time.Sleep(1200 * time.Millisecond)
	pc.step("a")
	s = f.createStarts()
	for i := 2; i < len(s); i++ {
		if !probe.gapAtLeast(s[i-1], s[i], time.Second) {
			t.Fatalf("creates %d and %d %s apart at 1 a second", i-1, i, s[i].Sub(s[i-1]))
		}
	}
	if len(s) < 3 {
		t.Fatalf("%d creates after the spacing passed, want 3", len(s))
	}
}

// A pool above its hotel's bound (the hotel reports fewer slots, or targets
// set under PR 2's target-only bound) is trimmed back to the bound: the
// oldest ready rooms go, quarantined rooms never (codex review of #663).
func TestPoolTrimsReadyRoomsAboveTheBound(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	f.addRoom("q1", "pool", "claim")
	f.addRoom("q2", "pool", "claim")
	pc.up("a")
	pc.target(20)
	pc.fill("a", 20)
	f.set(func(f *fakePoolHotel) { f.slots = 50 }) // bound 10: 2 quarantined and 8 ready
	pc.sync("a")
	pc.steps("a", 2)
	if c := pc.counts("a"); c.ready != 8 || c.quarantined != 2 {
		t.Fatalf("after the bound fell to 10: %+v, want 8 ready and 2 quarantined", c)
	}
	dels := f.roomDeletes()
	if len(dels) != 12 {
		t.Fatalf("%d deletes, want the 12 oldest ready rooms", len(dels))
	}
	for i, d := range dels {
		if want := "/v1/sandboxes/sbx-" + strconv.Itoa(i+1); d.path != want {
			t.Fatalf("trim %d deleted %s, want %s", i, d.path, want)
		}
	}
}

// A key whose image is not warm on a hotel gets no pool create there, so its
// empty count must not hold that hotel at the full rate during claims
// (Bugbot review of #663).
func TestRefillColdKeyDoesNotForceTheFullRate(t *testing.T) {
	lfm, _ := templateByName("lfm3-1.7b")
	pc := newPoolChain(t, []string{"a"}, func(c *config) {
		c.ReadyRooms.Keys = append(c.ReadyRooms.Keys, readyRoomKeyEntry{Template: "lfm3-1.7b"})
	})
	pc.hotels["a"].set(func(f *fakePoolHotel) { f.coldImages = map[string]bool{lfm.Image: true} })
	h := pc.b.hotelByID("a")
	pc.up("a")
	if st, doc := pc.operator("PUT", "/v1/broker/ready-rooms", map[string]any{"per_hotel": map[string]int{"node-22": 20, "lfm3-1.7b": 20},
		"refill_per_second": 4, "refill_during_claims": 1, "reserve_share": 0.25}); st != 200 {
		t.Fatalf("PUT: %d %v", st, doc)
	}
	pc.b.mu.Lock()
	ph := pc.b.pool.hotel("a")
	for i := 0; i < 10; i++ { // node-22 at half its target; lfm3-1.7b at 0 and cold here
		ph.rooms[strconv.Itoa(i)] = &poolRoom{state: poolReady, key: "node-22"}
	}
	ph.claims = 1
	got := pc.b.poolRateLocked(h, ph, time.Now())
	ph.rooms, ph.claims = map[string]*poolRoom{}, 0
	pc.b.mu.Unlock()
	if got != 1 {
		t.Fatalf("rate during a claim with a cold key at 0: %v, want 1 (refill_during_claims)", got)
	}
}

// Rooms already deleted but still in the hotel's room map are not in the
// pool's count, so they do not shrink the trim to a lower bound (Bugbot
// review of #663).
func TestPoolBoundTrimIgnoresRoomsAlreadyDeleted(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	pc.up("a")
	pc.target(20)
	pc.fill("a", 20)
	pc.target(15)
	pc.steps("a", 2) // 5 deleted, still in the room map until the sync drops them
	f.set(func(f *fakePoolHotel) { f.slots = 50 })
	pc.b.mu.Lock()
	pc.b.hotelByID("a").slots = 50 // the health answer, without a sync that would drop the deleted rooms
	pc.b.mu.Unlock()
	pc.steps("a", 2)
	if c := pc.counts("a"); c.ready != 10 {
		t.Fatalf("bound 10 with 5 rooms deleted and not yet gone: %+v, want 10 ready", c)
	}
}

// heldCreate fills hotel a of a 25-slot chain (bound 5) with 4 ready rooms,
// then starts a 5th create that the hotel lists at once and answers only
// when the returned gate is closed. lost: that answer is a 503, though the
// room and its receipt 1 were made. It returns the chain and the room's id
// once a sync has taken the listed room into the broker's room map.
func heldCreate(t *testing.T, lost bool) (*poolChain, string, chan struct{}) {
	t.Helper()
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	f.set(func(f *fakePoolHotel) { f.slots = 25 })
	h := pc.b.hotelByID("a")
	pc.up("a")
	pc.target(4)
	pc.fill("a", 4)
	gate := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
	})
	f.set(func(f *fakePoolHotel) { f.createGate, f.createLost = gate, lost })
	pc.target(5)
	pc.b.poolStep(context.Background(), h) // the 5th create starts and waits at the hotel
	waitFor(t, "the 5th room listed while its create is held", func() bool { return f.roomCount() == 5 })
	hid := ""
	f.set(func(f *fakePoolHotel) { hid = fmt.Sprintf("sbx-%d", f.n) })
	pc.sync("a")
	pc.b.mu.Lock()
	rm := h.rooms[hid]
	pc.b.mu.Unlock()
	if rm == nil || rm.guest != poolGuestID {
		t.Fatalf("the sync did not take in the listed room %s: the window under test is not open", hid)
	}
	return pc, hid, gate
}

// inFlightWindow runs syncs and pool steps of hotel a while the held create
// is in flight, and checks that the room counts once, through the create.
func inFlightWindow(t *testing.T, pc *poolChain, hid string) {
	t.Helper()
	h, f := pc.b.hotelByID("a"), pc.hotels["a"]
	for i := 0; i < 5; i++ {
		pc.b.poolStep(context.Background(), h)
		pc.sync("a")
	}
	if c := pc.counts("a"); c.ready != 4 || c.creating != 1 || c.held != 5 || c.stale != 0 || c.unverified != 0 || c.quarantined != 0 {
		t.Fatalf("a create in flight that the hotel lists already: %+v, want 4 ready, 1 creating, held 5 (the bound)\n%s", c, pc.debug("a"))
	}
	if d := f.roomDeletes(); len(d) != 0 {
		t.Fatalf("%d deletes while the create was in flight (first %s), want none", len(d), d[0].path)
	}
	if r := f.callsOf("GET", "/v1/sandboxes/"+hid+"/receipts"); len(r) != 0 {
		t.Fatalf("%d receipts reads of %s while its create was in flight, want none", len(r), hid)
	}
	pc.b.mu.Lock()
	alarm := pc.b.pool.hotel("a").alarm
	pc.b.mu.Unlock()
	if alarm != "" {
		t.Fatalf("alarm while the create was in flight: %s", alarm)
	}
}

// The hotel lists a room from the start of its create, before the create
// answers, and the sync loop takes in every listed room it does not know.
// A pool create in flight that a sync caught counts once: no ready room
// trimmed for it, no receipts read of it, no quarantine, no alarm; once the
// create answers the room is ready, once (coordinator's read of #663 at
// 18c6b5c, finding 1).
func TestPoolCreateInFlightListedCountsOnce(t *testing.T) {
	pc, hid, gate := heldCreate(t, false)
	inFlightWindow(t, pc, hid)
	close(gate)
	pc.quiesce()
	pc.steps("a", 2)
	h, f := pc.b.hotelByID("a"), pc.hotels["a"]
	if c := pc.counts("a"); c.ready != 5 || c.held != 5 || c.creating != 0 || c.unverified != 0 || c.quarantined != 0 || c.stale != 0 {
		t.Fatalf("after the create answered: %+v, want 5 ready, held 5\n%s", c, pc.debug("a"))
	}
	pc.b.mu.Lock()
	used, placed := h.used(), 0
	for _, r := range h.grid {
		if r != nil {
			placed++
		}
	}
	pr := pc.b.pool.hotel("a").rooms[hid]
	pc.b.mu.Unlock()
	if used != 5 || placed != 5 || pr == nil || pr.state != poolReady {
		t.Fatalf("after the create answered: %d slots used, %d placed, room %s %+v; want 5, 5 and the room ready", used, placed, hid, pr)
	}
	if len(f.roomDeletes()) != 0 || len(f.callsOf("GET", "/v1/sandboxes/"+hid+"/receipts")) != 0 {
		t.Fatalf("deletes %d, receipts reads of %s %d; want none", len(f.roomDeletes()), hid, len(f.callsOf("GET", "/v1/sandboxes/"+hid+"/receipts")))
	}
}

// A create whose answer is lost may still have made its room: once no create
// that could be its own is in flight, the listed room is taken in as
// unverified and its receipts decide, as before.
func TestPoolCreateLostAnswerRoomIsDecidedByItsReceipts(t *testing.T) {
	pc, hid, gate := heldCreate(t, true)
	inFlightWindow(t, pc, hid)
	close(gate)
	pc.quiesce()
	pc.sync("a")
	pc.steps("a", 3)
	if c := pc.counts("a"); c.ready != 5 || c.held != 5 || c.unverified != 0 || c.quarantined != 0 {
		t.Fatalf("after the lost answer: %+v, want the room read and ready (5 ready)\n%s", c, pc.debug("a"))
	}
	if r := pc.hotels["a"].callsOf("GET", "/v1/sandboxes/"+hid+"/receipts"); len(r) != 1 {
		t.Fatalf("%d receipts reads of %s, want 1 (after its create ended)", len(r), hid)
	}
}

// The hotel reports its used memory and its share, each rounded to 0.1, so
// the memory they give moves a little from one answer to the next. Where
// the memory bound is the smaller one, that must not delete and make ready
// rooms; a configured ram_gib comes first (coordinator's read of #663 at
// 18c6b5c, finding 2).
func TestPoolMemoryBoundHoldsWhenHealthNumbersMove(t *testing.T) {
	t.Run("from health", func(t *testing.T) {
		pc := newPoolChain(t, []string{"a"}, nil)
		f := pc.hotels["a"]
		f.set(func(f *fakePoolHotel) { f.slots, f.memGiB, f.memPct = 480, 0.7, 10.2 }) // 6.86 GiB: bound 10 by memory
		pc.up("a")
		pc.target(100)
		pc.fill("a", 10)
		for _, pct := range []float64{10.3, 10.2, 10.3} { // 10.3 alone: 6.80 GiB, bound 9
			f.set(func(f *fakePoolHotel) { f.memPct = pct })
			pc.sync("a")
			pc.steps("a", 3)
		}
		if c := pc.counts("a"); c.ready != 10 || c.stale != 0 {
			t.Fatalf("memory-bound hotel, its health moving by one rounding step: %+v, want 10 ready kept", c)
		}
		if d, n := len(f.roomDeletes()), len(f.creates()); d != 0 || n != 10 {
			t.Fatalf("%d deletes and %d creates, want 0 and 10", d, n)
		}
		_, doc := pc.operator("GET", "/v1/broker/ready-rooms", nil)
		if v := doc["hotels"].(map[string]any)["a"].(map[string]any); v["bound_by_memory"] != float64(10) {
			t.Fatalf("view: bound_by_memory %v, want 10 (the largest memory seen)", v["bound_by_memory"])
		}
	})
	t.Run("ram_gib first", func(t *testing.T) {
		pc := newPoolChain(t, []string{"a"}, func(c *config) { c.Hotels[0].RAMGiB = 6 }) // bound 8; health says 384 GiB
		pc.up("a")
		pc.target(100)
		_, doc := pc.operator("GET", "/v1/broker/ready-rooms", nil)
		if v := doc["hotels"].(map[string]any)["a"].(map[string]any); v["bound_by_memory"] != float64(8) || v["bound"] != float64(8) {
			t.Fatalf("ram_gib 6 with health of 38.4 of 384 GiB: bound_by_memory %v, bound %v; want 8 and 8", v["bound_by_memory"], v["bound"])
		}
	})
}

// A listed pool room the sync first saw before the oldest create in flight
// started cannot be that create's room: it is taken in as unverified at
// once. One first seen after it waits (poolMaybeInFlight).
func TestPoolTakesInARoomSeenBeforeTheOldestCreate(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	h := pc.b.hotelByID("a")
	pc.up("a")
	pc.b.mu.Lock()
	ph := pc.b.pool.hotel("a")
	start := time.Now()
	ph.started[&room{}] = start // a create in flight
	for hid, born := range map[string]time.Time{"before": start.Add(-time.Second), "after": start.Add(time.Second)} {
		h.rooms[hid] = &room{hid: hid, id: "a." + hid, h: h, guest: poolGuestID, state: stRunning, born: born}
	}
	pc.b.mu.Unlock()
	pc.b.poolPlan(h)
	pc.b.mu.Lock()
	before, after := ph.rooms["before"], ph.rooms["after"]
	delete(h.rooms, "before")
	delete(h.rooms, "after")
	ph.started = map[*room]time.Time{}
	pc.b.mu.Unlock()
	if before == nil || before.state != poolUnverified {
		t.Fatalf("a room first seen 1 s before the oldest create in flight: %+v, want it taken in as unverified", before)
	}
	if after != nil {
		t.Fatalf("a room first seen 1 s after the oldest create in flight started: %+v, want it left to the create", after)
	}
}

// A pool create never waits for a hotel data connection: when customer calls
// hold every one, the create is not sent, and creates spaced at the broker
// must not queue there and reach the hotel together once connections free
// up (Codex review of #663 at 58b5ff4).
func TestPoolCreatesNeverWaitForAHotelConnection(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, func(c *config) { c.Hotels[0].DataConns = 2 })
	poolSpacingFactor = 1.05
	f, h := pc.hotels["a"], pc.b.hotelByID("a")
	pc.up("a")
	pc.putRefill(30, 1, 1)
	var rels []func()
	for i := 0; i < 2; i++ { // customer calls hold every data connection
		rel, err := h.conns.acquire(context.Background(), "a")
		if err != nil {
			t.Fatal(err)
		}
		rels = append(rels, rel)
	}
	probe := startSchedProbe(t)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		pc.runPool(30*time.Second, stop)
		close(done)
	}()
	time.Sleep(2400 * time.Millisecond)
	for _, rel := range rels {
		rel()
	}
	freed := time.Now()
	f.createsReach(2, 20*time.Second, stop)
	<-done
	starts := f.createStarts()
	if w := probe.maxInWindowLate(starts, time.Second); w > 1 || len(starts) < 2 {
		t.Fatalf("refill 1 a second, every connection held for 2.4 s: %d creates, %d within one second; want 2, never more than 1 a second", len(starts), w)
	}
	// No backoff: the first slot after the connections free up sends.
	if !probe.gapAtMost(freed, starts[0], 1050*time.Millisecond+2*poolTick) {
		t.Fatalf("first create %s after the connections were free, want within one spacing", starts[0].Sub(freed))
	}
}

// A front that signs creates without "pool": true, or signs a binding unlike
// its /room/attestation, fails every receipt-1 proof. The real refill loop
// backs off 5 s, doubling to 1 min, so creates stay at or under the 1 a
// second the 1 s limit of #658 allowed (the bound never trips: each stale
// room is deleted at once), and after poolProofAlarmAfter failures in a row
// the ready_rooms alarm is set. A binding failure still asks for a new
// attestation at once. A ready create resets the count and the alarm.
func TestPoolProofFailuresBackOffAndAlarm(t *testing.T) {
	for _, tc := range []struct {
		name string
		bad  func(f *fakePoolHotel, on bool)
	}{
		{"no pool true", func(f *fakePoolHotel, on bool) { f.signNoPool = on }},
		{"binding unlike its attestation", func(f *fakePoolHotel, on bool) { f.signOtherBind = on }},
	} {
		t.Run(tc.name, func(t *testing.T) { testPoolProofFailuresBackOffAndAlarm(t, tc.bad) })
	}
}

func testPoolProofFailuresBackOffAndAlarm(t *testing.T, bad func(f *fakePoolHotel, on bool)) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	f.set(func(f *fakePoolHotel) { bad(f, true) })
	pc.up("a")
	pc.putRefill(10, 4, 4)
	poolSpacingFactor = 1.05
	alarmed := func() string {
		pc.b.mu.Lock()
		defer pc.b.mu.Unlock()
		return pc.b.pool.hotel("a").alarm
	}
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		end := time.Now().Add(25 * time.Second)
		for time.Now().Before(end) && alarmed() == "" {
			time.Sleep(10 * time.Millisecond)
		}
	}()
	t0 := time.Now()
	pc.runPool(26*time.Second, stop)
	elapsed := time.Since(t0)
	a := alarmed()
	if !strings.Contains(a, "receipt 1 proof") {
		t.Fatalf("alarm %q after %s, want the receipt 1 proof alarm", a, elapsed)
	}
	creates, deletes := len(f.creates()), len(f.roomDeletes())
	// Failures 1, 2, 3 at about 0, 5 and 15 s: at most a few creates in
	// flight each time, far under 4 a second.
	if limit := int(elapsed/time.Second) + 1; creates > limit || creates < poolProofAlarmAfter {
		t.Fatalf("%d creates in %s, want %d to %d (no more than 1 a second)", creates, elapsed, poolProofAlarmAfter, limit)
	}
	if deletes != creates {
		t.Fatalf("%d creates, %d deletes: every unproven room is deleted", creates, deletes)
	}
	starts := f.createStarts()
	if n := maxInWindow(starts, 5*time.Second); n > poolCreatesInFlight {
		t.Fatalf("%d creates within 5 s, want at most %d (one backoff round)", n, poolCreatesInFlight)
	}
	if g := starts[len(starts)-1].Sub(starts[0]); g < 14*time.Second {
		t.Fatalf("first to last of %d creates %s apart, want the 5 s then 10 s backoff (about 15 s)", creates, g)
	}
	pc.b.mu.Lock()
	ph := pc.b.pool.hotel("a")
	fails, wait := ph.proofFails, time.Until(ph.backoff)
	pc.b.mu.Unlock()
	if fails < poolProofAlarmAfter || wait < 10*time.Second {
		t.Fatalf("proof failures %d, backoff left %s; want at least %d and the doubled backoff", fails, wait, poolProofAlarmAfter)
	}

	// An honest front: past the backoff, the next ready create resets both.
	f.set(func(f *fakePoolHotel) { bad(f, false) })
	pc.b.mu.Lock()
	ph.backoff = time.Time{}
	pc.b.mu.Unlock()
	poolSpacingFactor = 0
	pc.fill("a", 1)
	pc.step("a") // the next step's alarm check sees the reset
	pc.b.mu.Lock()
	fails = ph.proofFails
	pc.b.mu.Unlock()
	if fails != 0 || alarmed() != "" {
		t.Fatalf("after a ready create: proof failures %d, alarm %q; want 0 and none", fails, alarmed())
	}
}
