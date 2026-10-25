package main

import "testing"

// A hotel reports its host memory use (host_mem_used_pct, from MemAvailable)
// in every health answer. Slots come from an install-time sizing with memory
// overcommit, so slots alone do not stop a machine from running out of
// memory when rooms use their limits. These tests pin the memory guard.

func TestHotelAtTheMemoryLimitTakesNoNewRooms(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "a", func(h *hotel) { h.memPct = 95 })
	setHotel(tc, "b", func(h *hotel) { h.memPct = 10 })
	setHotel(tc, "c", func(h *hotel) { h.memPct = 10 })
	on := share(tc, 300)
	if on["a"] != 0 {
		t.Fatalf("a hotel at 95%% memory got %d of 300 picks: %v", on["a"], on)
	}
	if on["b"] == 0 || on["c"] == 0 {
		t.Fatalf("hotels under the limit got no picks: %v", on)
	}
}

func TestAllHotelsAtTheMemoryLimitAnswerFullNotDown(t *testing.T) {
	tc := newChain(t)
	for _, id := range []string{"a", "b", "c"} {
		setHotel(tc, id, func(h *hotel) { h.memPct = 97 })
	}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status != 429 {
		t.Fatalf("create with every hotel at the memory limit: %d %v", status, doc)
	}
	if code := doc["error"].(map[string]any)["code"]; code != "no_free_rooms" {
		t.Fatalf("code %v", code)
	}
	if on := createsOn(tc); on["a"]+on["b"]+on["c"] != 0 {
		t.Fatalf("a create reached a hotel at the memory limit: %v", on)
	}
}

func TestMemoryLimitIsConfigurableAndCanBeTurnedOff(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "b", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })

	// Default limit 90: 89.9 takes rooms, 90 does not.
	setHotel(tc, "a", func(h *hotel) { h.memPct = 89.9 })
	if on := share(tc, 10); on["a"] != 10 {
		t.Fatalf("89.9%% under the default limit: %v", on)
	}
	setHotel(tc, "a", func(h *hotel) { h.memPct = 90 })
	if on := share(tc, 10); on["a"] != 0 {
		t.Fatalf("90%% at the default limit: %v", on)
	}

	tc.b.cfg.MemFullPct = 95
	if on := share(tc, 10); on["a"] != 10 {
		t.Fatalf("90%% under a limit of 95: %v", on)
	}

	tc.b.cfg.MemFullPct = -1 // off
	setHotel(tc, "a", func(h *hotel) { h.memPct = 99 })
	if on := share(tc, 10); on["a"] != 10 {
		t.Fatalf("limit off, 99%%: %v", on)
	}
}

func TestHotelWithNoMemoryReadingIsNotBlocked(t *testing.T) {
	// A hotel that never reported memory (an old hotel API, or no health
	// answer yet) has memPct 0. The guard must not treat that as a reading.
	tc := newChain(t)
	setHotel(tc, "b", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	if on := share(tc, 10); on["a"] != 10 {
		t.Fatalf("hotel with no memory reading: %v", on)
	}
}
