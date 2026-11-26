package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Astra r7 finding 1: the fail-closed audit clears reserved_for and pin_only,
// but a hotel that holds a lost create stays closed to unmarked placement
// until the create deadline.
func TestQuarantinedHotelTakesNoSharedCreateAfterTheAuditClearsPinOnly(t *testing.T) {
	tc := pinChain(t)
	a := tc.b.hotelByID("a")
	upstream := a.cfg.API
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			hijackClose(w) // reply lost
			return
		}
		body, _ := io.ReadAll(r.Body)
		status, hdr, out := forwardTo(upstream, r, body)
		passThrough(w, status, hdr, out)
	}))
	t.Cleanup(proxy.Close)
	setHotel(tc, "a", func(h *hotel) { h.cfg.API = proxy.URL })

	g := tc.b.guests["g2"]
	pl := placement{guest: "g2", ids: map[string]bool{"a": true}, dedicated: "a", dedicatedGen: 1, image: "alpine:3.20"}
	res := tc.b.createOne(context.Background(), g, []byte(`{"image":"alpine:3.20"}`), map[string]any{}, time.Now(), pl)
	if len(res.lost) != 1 || !a.quarantined() {
		t.Fatalf("lost %v quarantined %v", res.lost, a.quarantined())
	}
	setHotel(tc, "a", func(h *hotel) { h.cfg.API = upstream; h.backoffUntil = time.Time{} })
	// The audit finds a foreign room: reserved_for and pin_only are cleared.
	tc.b.mu.Lock()
	a.rooms["x1"] = &room{h: a, guest: "g1", hid: "x1", id: "a.x1", state: stRunning}
	changed := tc.b.checkReservedRooms(a)
	delete(a.rooms, "x1")
	tc.b.mu.Unlock()
	if !changed || a.pinOnly() || a.reservedFor() != "" {
		t.Fatalf("audit: changed %v pin %v owner %q", changed, a.pinOnly(), a.reservedFor())
	}
	// g1 is a pool guest: its creates never land on a, and naming it is refused.
	for i := 0; i < 60; i++ {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
		if status != 202 || doc["hotel"] == "a" {
			t.Fatalf("shared create %d: %d %v", i, status, doc)
		}
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}}); status != 409 {
		t.Fatalf("naming the quarantined hotel: %d %v", status, doc)
	}
	// Capacity leaves it out of g1's totals (B7).
	_, doc := tc.call(t, "key1", "GET", "/v1/broker/capacity", nil)
	if n := doc["classes"].(map[string]any)[classSealed].(map[string]any)["hotels"]; n != float64(2) {
		t.Fatalf("g1's totals count the quarantined hotel: %v", n)
	}
	// After the deadline it takes shared creates again.
	a.quarantineUntil.Store(time.Now().Add(-time.Second).UnixNano())
	setHotel(tc, "a", func(h *hotel) { h.backoffUntil = time.Time{} }) // the failed create rested it
	landed := false
	for i := 0; i < 200 && !landed; i++ {
		_, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
		landed = doc["hotel"] == "a"
	}
	if !landed {
		t.Fatal("the hotel never took a shared create after the deadline")
	}
}
