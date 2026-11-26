package main

import (
	"strings"
	"testing"
)

// Chaser HOLD on #770: the broker cannot prove from its clocks that a
// dispatched create has stopped, so an owner change of a pin_only hotel is an
// operator procedure that needs the hotel drained.
func TestOwnerChangeOfAPinOnlyHotelNeedsADrain(t *testing.T) {
	tc := pinChain(t) // generation 1, owner g2, not drained
	for _, c := range []struct {
		name string
		body map[string]any
	}{
		{"reference change", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1}},
		{"new owner", map[string]any{"reserved_for": "g1"}},
		{"release", map[string]any{"reserved_for": nil}},
		{"pin_only off", map[string]any{"pin_only": false}},
	} {
		status, doc := patchHotelDoc(t, tc, "a", c.body)
		if status != 409 || errCode(doc) != "owner_change_needs_drain" {
			t.Fatalf("%s undrained: %d %v", c.name, status, doc)
		}
		if msg := doc["error"].(map[string]any)["message"].(string); !strings.Contains(msg, "before drain") ||
			!strings.Contains(msg, "not terminal proof") || !strings.Contains(msg, "drain the hotel") {
			t.Fatalf("%s: the reason must put customer-work checks before drain: %s", c.name, msg)
		}
		wantReservation(t, getHotelDoc(t, tc, "a"), "g2", "owner:g2", 1)
	}
	// A PATCH that changes nothing about the owner is not refused.
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2"}); status != 200 {
		t.Fatalf("same owner and ref: %d %v", status, doc)
	}
	// Drained, the change reaches the existing checks and passes on an empty hotel.
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"drain": true}); status != 200 {
		t.Fatalf("drain: %d %v", status, doc)
	}
	setHotel(tc, "a", func(h *hotel) { h.creating = 1 })
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("drained but busy: %d %v", status, doc)
	}
	setHotel(tc, "a", func(h *hotel) { h.creating = 0 })
	status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1})
	if status != 200 {
		t.Fatalf("drained and empty: %d %v", status, doc)
	}
	wantReservation(t, doc, "g2", "owner:g2:2", 2)
}

// O3 is the one-time switch on: the hotel is not pin_only yet, so it needs no
// drain. The fail-closed audit is automatic and is never refused.
func TestSwitchOnNeedsNoDrainAndTheAuditIsNeverRefused(t *testing.T) {
	tc := knownChain(t)
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "pin_only": true}); status != 200 || doc["pin_only"] != true || doc["drain"] != false {
		t.Fatalf("O3 undrained: %d %v", status, doc)
	}
	a := tc.b.hotelByID("a")
	tc.b.mu.Lock()
	a.rooms["x1"] = &room{h: a, guest: "g1", hid: "x1", id: "a.x1", state: stRunning}
	changed := tc.b.checkReservedRooms(a)
	tc.b.mu.Unlock()
	if !changed || a.pinOnly() {
		t.Fatalf("audit on an undrained pin_only hotel: changed %v pin %v", changed, a.pinOnly())
	}
}
