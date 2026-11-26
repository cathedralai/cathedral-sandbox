package main

import (
	"testing"
	"time"
)

// Astra r7 finding 2: forgetting a dead miner hotel drops it with its
// lost-create record; it waits for the hold's deadline. (There is no
// automatic forget: the operator key is the only caller, and there is no force
// flag, so it is refused.)
func TestForgetWaitsForALostCreateHoldToEnd(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g := newRebootingGuest(t, "m1")
	h, _ := joinWithRoom(t, tc, "m1", g)
	goDown(t, tc, h, g, minerForgetDownFor+time.Minute) // down past the 10 minute threshold
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true}); status != 200 {
		t.Fatalf("drain: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	h.unreaped = map[string]*unreapedBatch{"b1": {guest: "g1", lostHold: true, holdUntil: time.Now().Add(2 * time.Minute)}}
	tc.b.mu.Unlock()
	forget := "/v1/broker/hotels/m1?forget_rooms=true"
	if status, doc := tc.call(t, "operator-key", "DELETE", forget, nil); status != 409 || errCode(doc) != "forget_refused" {
		t.Fatalf("forget before the hold ended: %d %v", status, doc)
	}
	if tc.b.hotelByID("m1") == nil {
		t.Fatal("the hotel was forgotten with its hold")
	}
	tc.b.mu.Lock()
	for _, ub := range h.unreaped {
		ub.holdUntil = time.Now().Add(-time.Second)
	}
	tc.b.mu.Unlock()
	if status, doc := tc.call(t, "operator-key", "DELETE", forget, nil); status != 204 {
		t.Fatalf("forget after the hold ended: %d %v", status, doc)
	}
}
