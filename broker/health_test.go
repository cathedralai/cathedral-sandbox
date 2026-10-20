package main

import (
	"context"
	"testing"
	"time"
)

func TestHotelWithLateHealthStaysInPlacementWhileRoomCallsAnswer(t *testing.T) {
	tc := newChain(t)
	h := tc.b.hotelByID("a")
	tc.b.syncHotel(context.Background(), h) // one good health answer: slots known
	tc.hotels["a"].mu.Lock()
	tc.hotels["a"].healthFail = true
	tc.hotels["a"].mu.Unlock()
	setHotel(tc, "a", func(h *hotel) { h.lastOK = time.Now().Add(-time.Minute) }) // health late for a minute

	// No room call for a minute either: the hotel is down.
	h.lastAnswer.Store(time.Now().Add(-time.Minute).UnixNano())
	tc.b.syncHotel(context.Background(), h)
	var ok, late bool
	setHotel(tc, "a", func(h *hotel) { ok, late = h.ok, h.healthLate })
	if ok {
		t.Fatalf("hotel with no answers marked up")
	}

	// A room call answers: the hotel stays in placement, marked health late.
	setHotel(tc, "a", func(h *hotel) { h.ok = true })
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	tc.b.syncHotel(context.Background(), h)
	setHotel(tc, "a", func(h *hotel) { ok, late = h.ok, h.healthLate })
	if !ok || !late {
		t.Fatalf("ok=%v late=%v, want true true", ok, late)
	}
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}}); id == "" {
		t.Fatalf("no room")
	}

	// Health answers again: late clears.
	tc.hotels["a"].mu.Lock()
	tc.hotels["a"].healthFail = false
	tc.hotels["a"].mu.Unlock()
	tc.b.syncHotel(context.Background(), h)
	setHotel(tc, "a", func(h *hotel) { ok, late = h.ok, h.healthLate })
	if !ok || late {
		t.Fatalf("after health: ok=%v late=%v", ok, late)
	}
}

func TestHotelThatNeverAnsweredHealthIsNotUpFromRoomCalls(t *testing.T) {
	tc := newChain(t)
	h := tc.b.hotelByID("b")
	tc.hotels["b"].healthFail = true
	h.lastAnswer.Store(time.Now().UnixNano())
	tc.b.syncHotel(context.Background(), h)
	var ok bool
	setHotel(tc, "b", func(h *hotel) { ok = h.ok })
	if ok {
		t.Fatalf("a hotel with no health answer ever must not be up (its slots are unknown)")
	}
}
