package main

import "testing"

// AB#577: a guest's live view lists only the hotels the guest may use, and
// the chain-wide room counts only where the guest owns a room.
func TestLiveSnapshotScopedToGuestHotels(t *testing.T) {
	tc := newChain(t)
	for _, id := range []string{"a", "b", "c"} {
		setHotel(tc, id, func(h *hotel) { h.slots = 0; h.resize(100); h.apiRunning = 7; h.apiDeleting = 3 })
	}
	tc.b.mu.Lock()
	g := tc.b.guests["g1"]
	g.limits.Hotels = []string{"b", "c"}
	tc.b.mu.Unlock()
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})

	doc := tc.b.snapshot(g)
	got := map[string]map[string]any{}
	for _, x := range doc["hotels"].([]any) {
		h := x.(map[string]any)
		got[h["id"].(string)] = h
	}
	if _, ok := got["a"]; ok || len(got) != 2 {
		t.Fatalf("g1 may use b and c only; view lists %d hotels: %v", len(got), got)
	}
	if _, ok := got["b"]["rooms_all"]; !ok {
		t.Fatalf("hotel b holds a g1 room; want rooms_all: %v", got["b"])
	}
	for _, k := range []string{"rooms_all", "deleting_all"} {
		if _, ok := got["c"][k]; ok {
			t.Fatalf("hotel c holds no g1 room; %s must be absent: %v", k, got["c"])
		}
	}
}

// An operator narrows a guest's list while it still has a room on a hotel
// it may no longer use: that hotel stays in the view with the guest's room
// and totals. A hotel it neither may use nor has rooms on stays hidden.
func TestLiveSnapshotKeepsHotelWithOwnRoomAfterNarrowing(t *testing.T) {
	tc := newChain(t)
	for _, id := range []string{"a", "b", "c"} {
		setHotel(tc, id, func(h *hotel) { h.slots = 0; h.resize(100); h.apiRunning = 7; h.apiDeleting = 3 })
	}
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	tc.b.mu.Lock()
	g := tc.b.guests["g1"]
	g.limits.Hotels = []string{"b"}
	tc.b.mu.Unlock()

	doc := tc.b.snapshot(g)
	got := map[string]map[string]any{}
	for _, x := range doc["hotels"].([]any) {
		h := x.(map[string]any)
		got[h["id"].(string)] = h
	}
	if _, ok := got["c"]; ok || len(got) != 2 {
		t.Fatalf("want a (own room) and b (allowed), not c; got %v", got)
	}
	if got["a"]["mine"].(map[string]int)["running"] != 1 || got["a"]["rooms_all"] != 7 || got["a"]["deleting_all"] != 3 {
		t.Fatalf("hotel a: want own running room and all-guest counts: %v", got["a"])
	}
	if _, ok := got["b"]["rooms_all"]; ok {
		t.Fatalf("hotel b holds no g1 room; rooms_all must be absent: %v", got["b"])
	}
	if doc["totals"].(map[string]any)["running"] != 1 {
		t.Fatalf("totals must count the room on a: %v", doc["totals"])
	}
}

// A room can sit in h.rooms with no square (slot -1 after a grid shrink or a
// failed place). It still makes the hotel the guest's, is counted once, and
// a hotel with no room of the guest stays hidden.
func TestLiveSnapshotKeepsHotelWithOffGridRoom(t *testing.T) {
	tc := newChain(t)
	for _, id := range []string{"a", "b", "c"} {
		setHotel(tc, id, func(h *hotel) { h.slots = 0; h.resize(100); h.apiRunning = 7; h.apiDeleting = 3 })
	}
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	tc.b.mu.Lock()
	// Shrink a's grid to nothing the room fits in: its square is gone, the room stays.
	ha := tc.b.hotelByID("a")
	for _, r := range ha.rooms {
		ha.grid[r.slot] = nil
		r.slot = -1
	}
	g := tc.b.guests["g1"]
	g.limits.Hotels = []string{"c"}
	tc.b.mu.Unlock()

	doc := tc.b.snapshot(g)
	got := map[string]map[string]any{}
	for _, x := range doc["hotels"].([]any) {
		h := x.(map[string]any)
		got[h["id"].(string)] = h
	}
	if len(got) != 3 {
		t.Fatalf("want a (off-grid room), b (grid room), c (allowed): %v", got)
	}
	if got["a"]["mine"].(map[string]int)["running"] != 1 || got["a"]["rooms_all"] != 7 {
		t.Fatalf("hotel a: want the off-grid room counted once with all-guest counts: %v", got["a"])
	}
	if doc["totals"].(map[string]any)["running"] != 2 {
		t.Fatalf("totals: want 2 running (one on a, one on b), got %v", doc["totals"])
	}
	// Positive control for the hidden case: no room at all, not allowed.
	tc.b.mu.Lock()
	for _, r := range ha.rooms {
		tc.b.release(ha, r)
	}
	tc.b.mu.Unlock()
	for _, x := range tc.b.snapshot(g)["hotels"].([]any) {
		if x.(map[string]any)["id"] == "a" {
			t.Fatalf("hotel a holds no g1 room and is not allowed; must be hidden")
		}
	}
}
