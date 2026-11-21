package main

// Tests of the ready-room refill policy and hotel bounds (AB#894, phase 2
// work order PR 3; design 6.1, 6.3).

import (
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
	pc.runPool(3*time.Second, nil)
	starts := f.createStarts()
	node, lfm := 0, 0
	for _, c := range f.creates() {
		if strings.Contains(string(c.body), nodeImage()) {
			node++
		} else {
			lfm++
		}
	}
	if w := maxInWindow(starts, time.Second); w > 4 {
		t.Fatalf("%d pool creates within one second over both keys, want at most 4", w)
	}
	if len(starts) < 9 || node == 0 || lfm == 0 {
		t.Fatalf("%d creates in 3 s (%d node-22, %d lfm), want about 4 a second over both keys", len(starts), node, lfm)
	}
	// A lower setting is the lower cap.
	g := newPoolChain(t, []string{"b"}, nil)
	poolSpacingFactor = 1.05
	g.up("b")
	g.putRefill(30, 2, 1)
	g.runPool(3*time.Second, nil)
	if s := g.hotels["b"].createStarts(); maxInWindow(s, time.Second) > 2 || len(s) < 4 {
		t.Fatalf("refill_per_second 2: %d creates in 3 s, %d within one second", len(s), maxInWindow(s, time.Second))
	}
}

// Claims every 400 ms for 30 s on a hotel never stop its refill: no pause
// timer, at least 1 create a second throughout (the longest gap between two
// creates stays near 1 s).
func TestRefillNeverStopsUnderRepeatedBursts(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	pc.up("a")
	pc.putRefill(40, 4, 1)
	pc.fill("a", 40) // full, no pacing
	poolSpacingFactor = 1.05
	before := len(f.createStarts())
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
	if claimed < 60 {
		t.Fatalf("%d claims in 30 s, want about 75", claimed)
	}
	if len(starts) < 26 {
		t.Fatalf("%d creates during 30 s of claims, want at least 26", len(starts))
	}
	prev := t0
	for _, s := range starts {
		if gap := s.Sub(prev); gap > 1200*time.Millisecond {
			t.Fatalf("refill paused %s during the claims", gap)
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
	poolSpacingFactor = 1.05
	pc.b.poolClaimBegin(h)
	pc.runPool(6*time.Second, nil)
	pc.b.poolClaimEnd(h)
	s := pc.hotels["a"].createStarts()
	if len(s) < 12 {
		t.Fatalf("%d creates, want 10 fast ones and some slow ones", len(s))
	}
	for i := 1; i < 10; i++ {
		if gap := s[i].Sub(s[i-1]); gap > 500*time.Millisecond {
			t.Fatalf("create %d came %s after the one before, below a quarter: want the full rate", i, gap)
		}
	}
	for i := 11; i < len(s); i++ {
		if gap := s[i].Sub(s[i-1]); gap < 950*time.Millisecond {
			t.Fatalf("create %d came %s after the one before, above a quarter during a claim: want 1 a second", i, gap)
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
