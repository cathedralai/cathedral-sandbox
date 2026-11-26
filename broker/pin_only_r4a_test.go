package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Astra r4 finding 2: between the cleanup that installs the hold and
// settleUncertain, an empty sync must not erase it.
func TestEmptySyncBetweenCleanupAndSettlementKeepsTheHold(t *testing.T) {
	tc := pinChain(t) // generation 1
	ha := tc.b.hotelByID("a")
	upstream := ha.cfg.API
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			hijackClose(w) // reply lost; the hotel starts nothing (yet)
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
	batchID := newUUID()
	labels := map[string]any{guestLabel: "g2", batchLabel: batchID}
	res := tc.b.createOne(context.Background(), g, []byte(`{"image":"alpine:3.20"}`), labels, time.Now(), pl)
	if len(res.lost) != 1 {
		t.Fatalf("lost: %v (status %d)", res.lost, res.status)
	}
	// createMany's first step: the cleanup pass finds nothing and the request
	// is retained...
	if !tc.b.reapOrphans(ha, g, batchID, nil, 1, len(res.lostGuarded), res.lostUntil) {
		t.Fatal("cleanup not confirmed")
	}
	// ...and an empty sync runs before settleUncertain takes b.mu.
	tc.b.syncHotel(context.Background(), ha)
	change := map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1}
	if status, doc := patchHotelDoc(t, tc, "a", change); status != 409 {
		t.Fatalf("reference change after the sync erased the hold: %d %v", status, doc)
	}
	tc.b.settleUncertain(g, batchID, []createResult{res}, nil)
	if status, doc := patchHotelDoc(t, tc, "a", change); status != 409 {
		t.Fatalf("reference change after settlement: %d %v", status, doc)
	}
}
