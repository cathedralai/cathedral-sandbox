package main

import "testing"

// Astra r4 finding 4 (cheap part): a pin_only runtime hotel keeps its
// unresolved creates, so it may not leave (and rejoin with none) until they
// resolve.
func TestPinOnlyRuntimeHotelCannotLeaveWithUnresolvedCreates(t *testing.T) {
	tc := knownChain(t)
	joinOperatorSealed(t, tc, "j1", 4)
	if status, doc := patchHotelDoc(t, tc, "j1", map[string]any{"reserved_for": "g2", "pin_only": true}); status != 200 {
		t.Fatalf("pin j1: %d %v", status, doc)
	}
	if status, doc := patchHotelDoc(t, tc, "j1", map[string]any{"drain": true}); status != 200 {
		t.Fatalf("drain: %d %v", status, doc)
	}
	for _, c := range []struct {
		name string
		set  func(h *hotel)
		undo func(h *hotel)
	}{
		{"lost create pending", func(h *hotel) { h.lostPending = 1 }, func(h *hotel) { h.lostPending = 0 }},
		{"unreaped record", func(h *hotel) { h.unreaped = map[string]*unreapedBatch{"b1": {guest: "g2"}} }, func(h *hotel) { h.unreaped = nil }},
	} {
		setHotel(tc, "j1", c.set)
		status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/j1", nil)
		if status != 409 || errCode(doc) != "hotel_not_empty" {
			t.Fatalf("%s: leave: %d %v", c.name, status, doc)
		}
		if tc.b.hotelByID("j1") == nil {
			t.Fatalf("%s: the hotel left", c.name)
		}
		setHotel(tc, "j1", c.undo)
	}
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/j1", nil); status != 204 {
		t.Fatalf("leave once resolved: %d %v", status, doc)
	}
}
