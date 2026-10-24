package main

import (
	"context"
	"testing"
	"time"
)

// "placement": "prefer" falls back only when every named hotel is down or
// full, only to a hotel of the same class, and only inside the guest's list.
// "require" (the default) keeps the 503 a pinned caller asked for.

func downHotel(tc *testChain, id string) {
	setHotel(tc, id, func(h *hotel) { h.ok = false; h.downSince = time.Now() })
}

func TestPreferFallsBackToAnotherUnsealedHotel(t *testing.T) {
	tc := newChain(t)
	downHotel(tc, "b")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "placement": "prefer"})
	if status != 202 {
		t.Fatalf("prefer with the named hotel down: %d %v", status, doc)
	}
	if doc["hotel"] != "c" || doc["placement_fallback"] != true {
		t.Fatalf("want a fallback to the other unsealed hotel c, got hotel=%v fallback=%v", doc["hotel"], doc["placement_fallback"])
	}
}

func TestPreferUsesTheNamedHotelWhileItIsUp(t *testing.T) {
	tc := newChain(t)
	for i := 0; i < 3; i++ {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "placement": "prefer"})
		if status != 202 || doc["hotel"] != "b" || doc["placement_fallback"] != nil {
			t.Fatalf("named hotel up: %d hotel=%v fallback=%v", status, doc["hotel"], doc["placement_fallback"])
		}
	}
}

func TestRequireKeepsThe503(t *testing.T) {
	tc := newChain(t)
	downHotel(tc, "b")
	for _, body := range []map[string]any{
		{"image": "alpine:3.20", "hotels": []string{"b"}},
		{"image": "alpine:3.20", "hotels": []string{"b"}, "placement": "require"},
	} {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", body)
		if status != 503 || errCode(doc) != "hotels_unavailable" {
			t.Fatalf("require with the named hotel down: %d %v", status, doc)
		}
	}
}

func TestPreferNeverMovesASealedCreateToAnUnsealedHotel(t *testing.T) {
	// Without a guest hotel list a sealed create never falls back.
	tc := newChain(t)
	downHotel(tc, "a")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}, "placement": "prefer"})
	if status != 503 || errCode(doc) != "hotels_unavailable" {
		t.Fatalf("sealed prefer, no guest list: %d %v", status, doc)
	}
	// With a list that holds only unsealed spares, it still never falls back.
	tc = limitedChain(t, guestLimits{Hotels: []string{"a", "b", "c"}})
	downHotel(tc, "a")
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}, "placement": "prefer"})
	if status != 503 || errCode(doc) != "hotels_unavailable" {
		t.Fatalf("sealed prefer moved to an unsealed hotel: %d %v", status, doc)
	}
}

func TestPreferMovesASealedCreateToTheGuestsOtherSealedHotel(t *testing.T) {
	tc := limitedChain(t, guestLimits{Hotels: []string{"a", "c"}})
	setHotel(tc, "c", func(h *hotel) {
		h.cfgMu.Lock()
		h.cfg.Sealed, h.cfg.Labels = true, map[string]string{"sealed": "true"}
		h.cfgMu.Unlock()
	})
	downHotel(tc, "a")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}, "placement": "prefer"})
	if status != 202 || doc["hotel"] != "c" || doc["placement_fallback"] != true {
		t.Fatalf("sealed prefer to the guest's other sealed hotel: %d %v", status, doc)
	}
}

func TestPreferStaysInsideTheGuestsHotelList(t *testing.T) {
	tc := limitedChain(t, guestLimits{Hotels: []string{"b"}})
	downHotel(tc, "b")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "placement": "prefer"})
	if status != 503 || errCode(doc) != "hotels_unavailable" {
		t.Fatalf("prefer left the guest's hotel list: %d %v", status, doc)
	}
}

func TestPreferKeepsTheOtherLabelRules(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "c", func(h *hotel) {
		h.cfgMu.Lock()
		h.cfg.Labels = map[string]string{"zone": "far"}
		h.cfgMu.Unlock()
	})
	downHotel(tc, "b")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "placement": "prefer", "exclude_hotel_labels": map[string]string{"zone": "far"}})
	if status != 503 || errCode(doc) != "hotels_unavailable" {
		t.Fatalf("prefer ignored exclude_hotel_labels: %d %v", status, doc)
	}
}

func TestPlacementMustBeRequireOrPrefer(t *testing.T) {
	tc := newChain(t)
	for _, v := range []any{"anywhere", 1, true} {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "placement": v})
		if status != 400 || errCode(doc) != "invalid_hotel_selection" {
			t.Fatalf("placement %v: %d %v", v, status, doc)
		}
	}
}

func TestHotelListShowsDownSince(t *testing.T) {
	tc := newChain(t)
	downHotel(tc, "b")
	status, doc := tc.call(t, "key1", "GET", "/v1/broker/hotels", nil)
	if status != 200 {
		t.Fatalf("hotels: %d %v", status, doc)
	}
	for _, x := range doc["hotels"].([]any) {
		h := x.(map[string]any)
		switch h["id"] {
		case "b":
			if s, _ := h["down_since"].(string); s == "" {
				t.Fatalf("down hotel b has no down_since: %v", h)
			}
		default:
			if h["down_since"] != nil {
				t.Fatalf("up hotel %v has down_since %v", h["id"], h["down_since"])
			}
		}
	}
}

func TestPreferKeepsTheCallersOwnSealedLabelRules(t *testing.T) {
	// Codex review on #323: a fallback must not replace the request's own
	// exclude_hotel_labels {"sealed": "false"} with its class rule.
	tc := newChain(t)
	setHotel(tc, "c", func(h *hotel) {
		h.cfgMu.Lock()
		h.cfg.Labels = map[string]string{"sealed": "false"}
		h.cfgMu.Unlock()
	})
	downHotel(tc, "b")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "placement": "prefer", "exclude_hotel_labels": map[string]string{"sealed": "false"}})
	if status != 503 || errCode(doc) != "hotels_unavailable" {
		t.Fatalf("fallback ignored exclude_hotel_labels sealed=false: %d %v", status, doc)
	}
}

func makeSealed(tc *testChain, id string) {
	setHotel(tc, id, func(h *hotel) {
		h.cfgMu.Lock()
		h.cfg.Sealed, h.cfg.Labels = true, map[string]string{"sealed": "true"}
		h.cfgMu.Unlock()
	})
}

func TestPreferSealedFallbackNeedsTheGuestsList(t *testing.T) {
	// Two sealed hotels, guest without a hotel list: the named sealed hotel
	// is down, the other sealed hotel is up, and still no fallback.
	tc := newChain(t)
	makeSealed(tc, "c")
	downHotel(tc, "a")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}, "placement": "prefer"})
	if status != 503 || errCode(doc) != "hotels_unavailable" {
		t.Fatalf("sealed fallback without a guest list: %d %v", status, doc)
	}
}

func TestPreferMixedClassNeverFallsBack(t *testing.T) {
	tc := newChain(t)
	downHotel(tc, "a")
	downHotel(tc, "b")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"a", "b"}, "placement": "prefer"})
	if status != 503 || errCode(doc) != "hotels_unavailable" {
		t.Fatalf("mixed sealed and unsealed named hotels fell back: %d %v", status, doc)
	}
}

func TestPlacementIsNotSentToTheHotel(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "placement": "prefer"})
	if status != 202 {
		t.Fatalf("create: %d %v", status, doc)
	}
	f := tc.hotels["b"]
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.creates) == 0 {
		t.Fatal("hotel b got no create")
	}
	if _, ok := f.creates[len(f.creates)-1]["placement"]; ok {
		t.Fatalf("hotel got the placement field: %v", f.creates[len(f.creates)-1])
	}
}

func TestDownSinceFollowsHealth(t *testing.T) {
	tc := newChain(t)
	f := tc.hotels["b"]
	f.mu.Lock()
	f.healthFail = true
	f.mu.Unlock()
	setHotel(tc, "b", func(h *hotel) { h.lastOK = time.Now().Add(-time.Hour); h.lastAnswer.Store(0) })
	h := tc.b.hotelByID("b")
	tc.b.syncHotel(context.Background(), h)
	tc.b.mu.Lock()
	ok, since := h.ok, h.downSince
	tc.b.mu.Unlock()
	if ok || since.IsZero() {
		t.Fatalf("after failed health: ok=%v down_since=%v", ok, since)
	}
	f.mu.Lock()
	f.healthFail = false
	f.mu.Unlock()
	tc.b.syncHotel(context.Background(), h)
	tc.b.mu.Lock()
	ok, since = h.ok, h.downSince
	tc.b.mu.Unlock()
	if !ok || !since.IsZero() {
		t.Fatalf("after good health: ok=%v down_since=%v", ok, since)
	}
}
