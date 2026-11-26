package main

import "testing"

// Bugbot on #770: release, a new owner and lend open a pin_only hotel, so each
// needs a known room count, not only zero creates, queued creates and claims.
func TestOwnershipChangesOfAPinOnlyHotelNeedAKnownRoomCount(t *testing.T) {
	for _, state := range []struct {
		name string
		set  func(h *hotel)
		undo func(h *hotel)
	}{
		{"lost create unresolved", func(h *hotel) { h.lostPending = 1 }, func(h *hotel) { h.lostPending = 0 }},
		{"unreaped record", func(h *hotel) { h.unreaped = map[string]*unreapedBatch{"b1": {guest: "g2"}} }, func(h *hotel) { h.unreaped = nil }},
		{"no room list yet", func(h *hotel) { h.roomsUnchecked = true }, func(h *hotel) { h.roomsUnchecked = false }},
	} {
		// release
		tc := pinChain(t)
		setHotel(tc, "a", state.set)
		if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": nil}); status != 409 || errCode(doc) != "rooms_active" {
			t.Fatalf("%s: release: %d %v", state.name, status, doc)
		}
		setHotel(tc, "a", state.undo)
		if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": nil}); status != 200 {
			t.Fatalf("%s: release once known: %d %v", state.name, status, doc)
		}
		// a new owner
		tc = pinChain(t)
		setHotel(tc, "a", state.set)
		if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": "g1"}); status != 409 || errCode(doc) != "rooms_active" {
			t.Fatalf("%s: new owner: %d %v", state.name, status, doc)
		}
		setHotel(tc, "a", state.undo)
		if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": "g1"}); status != 200 {
			t.Fatalf("%s: new owner once known: %d %v", state.name, status, doc)
		}
		// lend, as patchHotel applies it (the attestation call is not the point here)
		tc = pinChain(t)
		a := tc.b.hotelByID("a")
		setHotel(tc, "a", state.set)
		tc.b.mu.Lock()
		a.cfgMu.Lock()
		e := lendChange{lend: true, owner: "g2", reportID: "r1"}.applyLend(a)
		a.cfgMu.Unlock()
		tc.b.mu.Unlock()
		if e == nil || e.status != 409 || e.code != "rooms_active" || !a.pinOnly() {
			t.Fatalf("%s: lend: %v pin %v", state.name, e, a.pinOnly())
		}
		setHotel(tc, "a", state.undo)
		tc.b.mu.Lock()
		a.cfgMu.Lock()
		e = lendChange{lend: true, owner: "g2", reportID: "r1"}.applyLend(a)
		a.cfgMu.Unlock()
		tc.b.mu.Unlock()
		if e != nil || a.pinOnly() || a.lentFrom() != "g2" {
			t.Fatalf("%s: lend once known: %v pin %v", state.name, e, a.pinOnly())
		}
	}
}
