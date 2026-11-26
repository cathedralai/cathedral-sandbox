package main

import (
	"context"
	"testing"
	"time"
)

// Astra r6: the protections follow the lost-create record, not the hotel's
// current pin_only flag.

func holdRecord(tc *testChain, id string) {
	setHotel(tc, id, func(h *hotel) {
		h.unreaped = map[string]*unreapedBatch{"b1": {guest: "g2", lostHold: true, holdUntil: time.Now().Add(time.Hour)}}
	})
}

func endHold(tc *testChain, id string) {
	setHotel(tc, id, func(h *hotel) {
		for _, ub := range h.unreaped {
			ub.holdUntil = time.Now().Add(-time.Second)
		}
	})
	tc.b.syncHotel(context.Background(), tc.b.hotelByID(id)) // a list asked after the deadline: empty
}

func TestSwitchingPinOnlyOffNeedsAKnownRoomCount(t *testing.T) {
	tc := pinChain(t)
	holdRecord(tc, "a")
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"pin_only": false}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("switch off with a held record: %d %v", status, doc)
	}
	if !tc.b.hotelByID("a").pinOnly() {
		t.Fatal("a refused PATCH cleared pin_only")
	}
	endHold(tc, "a")
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"pin_only": false}); status != 200 || doc["pin_only"] != false {
		t.Fatalf("switch off after the deadline: %d %v", status, doc)
	}
}

func TestHeldRecordGuardsOwnershipChangesAfterPinOnlyIsCleared(t *testing.T) {
	// The flag is gone (any automatic clear); the record still guards.
	tc := pinChain(t)
	holdRecord(tc, "a")
	setHotel(tc, "a", func(h *hotel) { h.cfg.PinOnly = false })
	a := tc.b.hotelByID("a")
	for _, body := range []map[string]any{{"reserved_for": nil}, {"reserved_for": "g1"}} {
		if status, doc := patchHotelDoc(t, tc, "a", body); status != 409 || errCode(doc) != "rooms_active" {
			t.Fatalf("%v with a held record: %d %v", body, status, doc)
		}
	}
	tc.b.mu.Lock()
	a.cfgMu.Lock()
	e := lendChange{lend: true, owner: "g2", reportID: "r1"}.applyLend(a)
	a.cfgMu.Unlock()
	tc.b.mu.Unlock()
	if e == nil || e.code != "rooms_active" {
		t.Fatalf("lend with a held record: %v", e)
	}
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/a", nil); status == 204 {
		t.Fatalf("leave with a held record: %d %v", status, doc)
	}
	endHold(tc, "a")
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": "g1"}); status != 200 {
		t.Fatalf("new owner after the deadline: %d %v", status, doc)
	}
}

func TestFailClosedClearDoesNotOpenTheHotelWhileARecordIsHeld(t *testing.T) {
	tc := pinChain(t)
	a := tc.b.hotelByID("a")
	holdRecord(tc, "a")
	// The audit finds a foreign room: pin_only is cleared and the hotel is lent.
	tc.b.mu.Lock()
	a.rooms["x1"] = &room{h: a, guest: "g1", hid: "x1", id: "a.x1", state: stRunning}
	changed := tc.b.checkReservedRooms(a)
	delete(a.rooms, "x1")
	tc.b.mu.Unlock()
	if !changed || a.pinOnly() {
		t.Fatalf("audit: changed %v pin %v", changed, a.pinOnly())
	}
	setHotel(tc, "a", func(h *hotel) { h.cfg.LentReportID = "r1" }) // a baseline, so a reclaim reaches its checks
	// A reclaim (a new owner) and a release are refused while the record holds.
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": "g1"}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("reclaim with a held record: %d %v", status, doc)
	}
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": nil}); status == 200 {
		t.Fatalf("release with a held record: %d %v", status, doc)
	}
	endHold(tc, "a")
	tc.b.mu.Lock()
	known := a.occupancyKnown()
	tc.b.mu.Unlock()
	if !known {
		t.Fatal("occupancy should be known after the deadline")
	}
	// A reclaim now passes the guard (it then needs a new attestation: 502).
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": "g1"}); errCode(doc) == "rooms_active" {
		t.Fatalf("reclaim after the deadline still guarded: %d %v", status, doc)
	}
}
