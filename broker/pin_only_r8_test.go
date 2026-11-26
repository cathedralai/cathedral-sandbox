package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Bugbot on #770 at 45a70d5: whether an attempt must leave a fence is decided
// when it is sent, not when its reply is processed.

// lostReplyProxy puts a proxy before hotel id whose creates lose their reply
// (and run onPost first, if set).
func lostReplyProxy(t *testing.T, tc *testChain, id string, onPost func()) {
	t.Helper()
	h := tc.b.hotelByID(id)
	upstream := h.cfg.API
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			if onPost != nil {
				onPost()
			}
			hijackClose(w)
			return
		}
		body, _ := io.ReadAll(r.Body)
		status, hdr, out := forwardTo(upstream, r, body)
		passThrough(w, status, hdr, out)
	}))
	t.Cleanup(proxy.Close)
	setHotel(tc, id, func(h *hotel) { h.cfg.API = proxy.URL })
}

func clearPinFlag(h *hotel) {
	h.cfgMu.Lock()
	h.cfg.PinOnly = false
	h.cfgMu.Unlock()
}

// (a) The flag is cleared while the create is in flight, then the reply is lost.
func TestFlagClearedMidFlightStillInstallsTheFences(t *testing.T) {
	tc := pinChain(t)
	a := tc.b.hotelByID("a")
	lostReplyProxy(t, tc, "a", func() { tc.b.mu.Lock(); clearPinFlag(a); tc.b.mu.Unlock() })
	// 409: once the flag is gone the retry's marker is stale; the lost attempt
	// is what matters here.
	if status, _ := tc.callWith(t, "key2", dedMark(1), "POST", "/v1/sandboxes", dedBody()); status != 502 && status != 409 {
		t.Fatalf("create with a lost reply: %d", status)
	}
	if a.pinOnly() {
		t.Fatal("the flag should be cleared")
	}
	tc.b.mu.Lock()
	held := a.lostHeldLocked()
	a.backoffUntil = time.Time{} // the failed create rested it
	tc.b.mu.Unlock()
	if !a.quarantined() || !held {
		t.Fatalf("quarantined %v, record held %v", a.quarantined(), held)
	}
	for i := 0; i < 40; i++ {
		status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
		if status != 202 || doc["hotel"] == "a" {
			t.Fatalf("unmarked create %d: %d %v", i, status, doc)
		}
	}
}

// (b) Between the lost reply and reapOrphans there is no record yet; the gates
// still hold, after the flag is gone too.
func TestGatesHoldBetweenALostReplyAndTheRecord(t *testing.T) {
	tc := pinChain(t)
	a := tc.b.hotelByID("a")
	lostReplyProxy(t, tc, "a", nil)
	g := tc.b.guests["g2"]
	pl := placement{guest: "g2", ids: map[string]bool{"a": true}, dedicated: "a", dedicatedGen: 1, image: "alpine:3.20"}
	res := tc.b.createOne(context.Background(), g, []byte(`{"image":"alpine:3.20"}`), map[string]any{}, time.Now(), pl)
	if len(res.lost) != 1 {
		t.Fatalf("lost %v", res.lost)
	}
	// switch-off with the flag still set
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"pin_only": false}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("switch off: %d %v", status, doc)
	}
	// the flag is gone (switch-off elsewhere, or the audit)
	clearPinFlag(a)
	for _, body := range []map[string]any{{"reserved_for": nil}, {"reserved_for": "g1"}} {
		if status, doc := patchHotelDoc(t, tc, "a", body); status != 409 || errCode(doc) != "rooms_active" {
			t.Fatalf("%v: %d %v", body, status, doc)
		}
	}
	tc.b.mu.Lock()
	a.cfgMu.Lock()
	e := lendChange{lend: true, owner: "g2", reportID: "r1"}.applyLend(a)
	a.cfgMu.Unlock()
	tc.b.mu.Unlock()
	if e == nil || e.code != "rooms_active" {
		t.Fatalf("lend: %v", e)
	}
	// reclaim: the hotel is lent (as after the audit)
	setHotel(tc, "a", func(h *hotel) {
		h.cfgMu.Lock()
		h.cfg.LentFrom, h.cfg.LentReportID, h.cfg.ReservedFor = "g2", "r0", ""
		h.cfgMu.Unlock()
	})
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": "g1"}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("reclaim: %d %v", status, doc)
	}
}

func TestLeaveRefusedBetweenALostReplyAndTheRecord(t *testing.T) {
	tc := knownChain(t)
	joinOperatorSealed(t, tc, "j1", 4)
	if status, doc := ownerPatch(t, tc, "j1", map[string]any{"reserved_for": "g2", "pin_only": true}); status != 200 {
		t.Fatalf("pin j1: %d %v", status, doc)
	}
	if status, doc := patchHotelDoc(t, tc, "j1", map[string]any{"drain": true}); status != 200 {
		t.Fatalf("drain: %d %v", status, doc)
	}
	j := tc.b.hotelByID("j1")
	lostReplyProxy(t, tc, "j1", nil)
	setHotel(tc, "j1", func(h *hotel) { h.drain(); h.cfgMu.Lock(); h.cfg.Drain = false; h.cfgMu.Unlock() })
	g := tc.b.guests["g2"]
	pl := placement{guest: "g2", ids: map[string]bool{"j1": true}, dedicated: "j1", dedicatedGen: 1, image: "alpine:3.20"}
	res := tc.b.createOne(context.Background(), g, []byte(`{"image":"alpine:3.20"}`), map[string]any{}, time.Now(), pl)
	if len(res.lost) != 1 {
		t.Fatalf("lost %v (status %d)", res.lost, res.status)
	}
	clearPinFlag(j)
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/j1", nil); status != 409 || errCode(doc) != "hotel_not_empty" {
		t.Fatalf("leave: %d %v", status, doc)
	}
}
