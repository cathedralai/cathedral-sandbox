package main

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Astra impl r1 fixes on PR #770 (pin_only.go, AB#982).

// Finding 1: the probe decides and claims under one b.mu hold, and keeps the
// claim for the whole probe.
func TestProbeHoldsAClaimSoPinOnlyCannotSwitchMidProbe(t *testing.T) {
	tc := knownChain(t)
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

// Finding 2: a room the hotel returns after the client left (or one the
// tunables check rejects) is in h.rooms in the same b.mu hold that ends
// h.creating. A sampler that takes b.mu in a loop must never see the hotel
// with no creating, no rooms, and a create the hotel already answered.
func TestReapedRoomIsRegisteredWithTheEndOfCreating(t *testing.T) {
	for _, tunables := range []bool{false, true} {
		for i := 0; i < 60; i++ {
			tc := newChain(t)
			a := tc.b.hotelByID("a")
			setHotel(tc, "b", func(h *hotel) { h.ok = false })
			setHotel(tc, "c", func(h *hotel) { h.ok = false })
			tc.hotels["a"].createDelay = 15 * time.Millisecond
			body := []byte(`{"image":"alpine:3.20"}`)
			if tunables {
				body = []byte(`{"image":"alpine:3.20","tunables":{"x":1}}`)
			}
			ctx, cancel := context.WithCancel(context.Background())
			var stop, bad atomic.Bool
			var sampled sync.WaitGroup
			for k := 0; k < 8; k++ { // many waiters on b.mu: one gets it in the gap
				sampled.Add(1)
				go func() {
					defer sampled.Done()
					for !stop.Load() {
						f := tc.hotels["a"]
						f.mu.Lock()
						answered := len(f.creates) > 0
						f.mu.Unlock()
						tc.b.mu.Lock()
						if answered && a.creating == 0 && a.queued == 0 && len(a.rooms) == 0 {
							bad.Store(true)
						}
						tc.b.mu.Unlock()
					}
				}()
			}
			go func() { time.Sleep(5 * time.Millisecond); cancel() }()
			g := tc.b.guests["g1"]
			pl := placement{guest: "g1", ids: map[string]bool{"a": true}, image: "alpine:3.20"}
			res := tc.b.createOne(ctx, g, body, map[string]any{}, time.Now(), pl)
			stop.Store(true)
			sampled.Wait()
			cancel()
			if bad.Load() {
				t.Fatalf("tunables=%v run %d: the hotel looked empty after its create answered (status %d)", tunables, i, res.status)
			}
		}
	}
}

// Finding 3: zero rooms before the first good room list is unknown, not empty.
func TestPinOnlySwitchAndReferenceChangeRefuseWhileRoomsAreUnknown(t *testing.T) {
	tc := pinChain(t) // pin_only, generation 1
	change := map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1}
	for _, c := range []struct {
		name string
		set  func(h *hotel)
		undo func(h *hotel)
	}{
		{"restart: no room list yet", func(h *hotel) { h.roomsUnchecked = true }, func(h *hotel) { h.roomsUnchecked = false }},
		{"last room list failed", func(h *hotel) { h.listOK = false }, func(h *hotel) { h.listOK = true }},
		{"unconfirmed create cleanup", func(h *hotel) { h.unreaped = map[string]*unreapedBatch{"b1": {guest: "g2"}} }, func(h *hotel) { h.unreaped = nil }},
	} {
		setHotel(tc, "a", c.set)
		if status, doc := patchHotelDoc(t, tc, "a", change); status != 409 || errCode(doc) != "rooms_active" {
			t.Fatalf("%s: reference change: %d %v", c.name, status, doc)
		}
		wantReservation(t, getHotelDoc(t, tc, "a"), "g2", "owner:g2", 1)
		setHotel(tc, "a", c.undo)
	}
	// A real restart: the counters are empty and the hotel is unchecked.
	tc.start(t)
	if status, doc := patchHotelDoc(t, tc, "a", change); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("after restart: %d %v", status, doc)
	}
	// The switch is refused too: a plain reserved hotel, count unknown.
	if status, doc := patchHotelDoc(t, tc, "b", map[string]any{"reserved_for": "g1"}); status != 200 {
		t.Fatalf("reserve b: %d %v", status, doc)
	}
	if status, doc := patchHotelDoc(t, tc, "b", map[string]any{"pin_only": true}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("switch with unknown rooms: %d %v", status, doc)
	}
	markRoomsKnown(tc)
	if status, doc := patchHotelDoc(t, tc, "a", change); status != 200 {
		t.Fatalf("once known and empty: %d %v", status, doc)
	}
}
