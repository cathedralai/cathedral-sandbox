package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// Astra r5: a metered request whose rooms were all removed while its cleanup
// was still busy keeps no phantom allowance slot, yet the create deadline still
// holds the pin_only hotel.
func TestFullyRemovedBusyCleanupChargesNoAllowanceButStillHolds(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	markRoomsKnown(tc)
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g1", "pin_only": true}); status != 200 {
		t.Fatalf("pin a: %d %v", status, doc)
	}
	ha := tc.b.hotelByID("a")
	f := tc.hotels["a"]
	f.mu.Lock()
	f.createFail, f.createFailAfterStart, f.listFail = 503, true, true // the room starts, the reply is a 503, the cleanup list fails
	f.mu.Unlock()

	g := tc.b.guests["g1"]
	pl := placement{guest: "g1", ids: map[string]bool{"a": true}, dedicated: "a", dedicatedGen: 1, image: "alpine:3.20"}
	batchID := newUUID()
	labels := map[string]any{guestLabel: "g1", batchLabel: batchID}
	body, _ := json.Marshal(map[string]any{"image": "alpine:3.20", "labels": labels})
	res := tc.b.createOne(context.Background(), g, body, labels, time.Now(), pl)
	if len(res.lost) != 1 {
		t.Fatalf("lost: %v (status %d)", res.lost, res.status)
	}
	if tc.b.reapOrphans(ha, g, batchID, nil, 1, len(res.lostGuarded), res.lostUntil) {
		t.Fatal("the first cleanup should have failed")
	}
	f.mu.Lock()
	f.createFail, f.createFailAfterStart, f.listFail = 0, false, false
	f.mu.Unlock()
	// The background retry lists the room and removes it.
	pinWait(t, func() bool { return callsTo(f, "DELETE /v1/sandboxes/") >= 1 })
	pinWait(t, func() bool { tc.b.mu.Lock(); defer tc.b.mu.Unlock(); return !ha.unreaped[batchID].busy })
	// Settlement ran before `reaped`: the record is busy again here.
	tc.b.mu.Lock()
	ub := ha.unreaped[batchID]
	if ub == nil {
		tc.b.mu.Unlock()
		t.Fatal("the record is gone")
	}
	ub.busy = true
	tc.b.mu.Unlock()
	tc.b.settleUncertain(g, batchID, []createResult{res}, nil)
	tc.b.mu.Lock()
	ub.busy = false
	tc.b.mu.Unlock()

	// No phantom slot: the metered guest (one room at a time) can create.
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}); status != 202 {
		t.Fatalf("create after the cleanup finished: %d %v", status, doc)
	}
	// The hotel stays held until the create deadline.
	tc.b.syncHotel(context.Background(), ha)
	change := map[string]any{"reserved_for": "g1", "reservation_ref": "owner:g1:2", "expect_generation": 1}
	if status, doc := patchHotelDoc(t, tc, "a", change); status != 409 {
		t.Fatalf("reference change before the deadline: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	ub.holdUntil = time.Now().Add(-time.Second)
	tc.b.mu.Unlock()
	tc.b.syncHotel(context.Background(), ha)
	if status, doc := patchHotelDoc(t, tc, "a", change); status != 200 {
		t.Fatalf("after the deadline: %d %v", status, doc)
	}
}
