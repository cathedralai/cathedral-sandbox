package main

import (
	"testing"
)

// AB#532: a hotel that holds a catalog image is preferred for a create of that
// image, and a cold hotel still takes the create when no warm hotel has room.

const warmImage = "alpine:3.20" // room-1x4 catalog image

func warmUp(tc *testChain, on bool, warm ...string) {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	tc.b.cfg.PrewarmCatalog = on
	tc.b.hotelByID("a").ok = false // sealed hotel: keep the fixture to b and c
	// Measured create times would pin every create to the first hotel used.
	for _, id := range []string{"b", "c"} {
		tc.b.hotelByID(id).createEWMA = 1
	}
	for _, id := range warm {
		h := tc.b.hotelByID(id)
		h.warm = map[string]bool{warmImage: true}
	}
}

func warmCreates(t *testing.T, tc *testChain, n int) map[string]int {
	t.Helper()
	got := map[string]int{}
	for i := 0; i < n; i++ {
		setHotel(tc, "b", func(h *hotel) { h.createEWMA = 1 })
		setHotel(tc, "c", func(h *hotel) { h.createEWMA = 1 })
		h, _, _ := createdOn(t, tc, map[string]any{"template": "room-1x4"})
		got[h]++
	}
	return got
}

func TestWarmHotelIsPreferredForACatalogImage(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, true, "b")
	if got := warmCreates(t, tc, 30); got["b"] != 30 {
		t.Fatalf("want all 30 on warm hotel b, got %v", got)
	}
}

func TestColdHotelStillTakesTheCreateWhenTheWarmOneIsFull(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, true, "b")
	setHotel(tc, "b", func(h *hotel) { h.slots = 0 })
	got := warmCreates(t, tc, 5)
	if got["b"] != 0 || got["c"] != 5 {
		t.Fatalf("want all 5 on cold hotel c, got %v", got)
	}
}

func TestWarmIsIgnoredWhenTheFlagIsOff(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, false, "b")
	if got := warmCreates(t, tc, 40); got["c"] == 0 {
		t.Fatalf("flag off: want creates on both hotels, got %v", got)
	}
}

func TestNoWarmHotelKeepsTheSpread(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, true)
	if got := warmCreates(t, tc, 40); got["b"] == 0 || got["c"] == 0 {
		t.Fatalf("no warm hotel: want creates on both, got %v", got)
	}
}

func TestPrewarmMarksCatalogImagesWarmAndDownClearsThem(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, true)
	h := tc.b.hotelByID("b")
	tc.b.prewarmHotel(h)
	tc.b.mu.Lock()
	warm := h.warm[warmImage]
	tc.b.mu.Unlock()
	if !warm {
		t.Fatal("alpine:3.20 not warm after prewarm")
	}
	if n := len(tc.hotels["b"].prefetch); n == 0 {
		t.Fatal("hotel got no prefetch call")
	}
	tc.b.mu.Lock()
	tc.b.hotelWentDown(h)
	cleared := len(h.warm) == 0
	tc.b.mu.Unlock()
	if !cleared {
		t.Fatal("warm set not cleared when the hotel went down")
	}
}
