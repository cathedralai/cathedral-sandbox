package main

import (
	"strings"
	"testing"
	"time"
)

// Astra impl r1 fixes on PR #770 (pin_only.go, AB#982).

// Finding 1: the probe decides and claims under one b.mu hold, and keeps the
// claim for the whole probe.
func TestProbeHoldsAClaimSoPinOnlyCannotSwitchMidProbe(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2"}); status != 200 {
		t.Fatalf("reserve: %d %v", status, doc)
	}
	setHotel(tc, "a", func(h *hotel) { h.ok, h.roomsUnchecked = true, false })
	tc.b.mu.Lock()
	tc.b.guests["g2"].cfg.Ops = true
	tc.b.mu.Unlock()
	tc.hotels["a"].createDelay = 800 * time.Millisecond
	done := make(chan int, 1)
	go func() {
		status, _ := tc.call(t, "key2", "POST", "/v1/broker/probe", map[string]any{})
		done <- status
	}()
	// The probe's room create has reached the hotel: it is mid-probe.
	pinWait(t, func() bool {
		f := tc.hotels["a"]
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, c := range f.calls {
			if strings.HasPrefix(c, "POST /v1/sandboxes") {
				return true
			}
		}
		return false
	})
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"pin_only": true}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("pin_only switched during a probe: %d %v", status, doc)
	}
	if s := <-done; s != 200 {
		t.Fatalf("probe: %d", s)
	}
	tc.b.mu.Lock()
	n := tc.b.hotelByID("a").claims
	tc.b.mu.Unlock()
	if n != 0 {
		t.Fatalf("probe left %d claims", n)
	}
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"pin_only": true}); status != 200 {
		t.Fatalf("switch after the probe: %d %v", status, doc)
	}
}
