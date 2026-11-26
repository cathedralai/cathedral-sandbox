package main

import "testing"

// Contract with the API: the owner's capacity entry carries the hotel's
// reservation_generation, and nobody else gets it.
func TestOwnerCapacityEntryCarriesTheReservationGeneration(t *testing.T) {
	tc := pinChain(t) // generation 1
	entry := func(key, id string) map[string]any {
		t.Helper()
		status, doc := tc.call(t, key, "GET", "/v1/broker/capacity", nil)
		if status != 200 {
			t.Fatalf("capacity: %d %v", status, doc)
		}
		for _, x := range doc["hotels"].([]any) {
			if h := x.(map[string]any); h["id"] == id {
				return h
			}
		}
		return nil
	}
	a := entry("key2", "a")
	if a == nil || a["pin_only"] != true || a["reservation_generation"] != float64(1) {
		t.Fatalf("owner entry: %v", a)
	}
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1}); status != 200 {
		t.Fatalf("ref change: %d %v", status, doc)
	}
	if a := entry("key2", "a"); a["reservation_generation"] != float64(2) {
		t.Fatalf("after the ref change: %v", a)
	}
	// A hotel the guest does not own never shows it (b is in the pool).
	if b := entry("key2", "b"); b == nil || b["reservation_generation"] != nil {
		t.Fatalf("pool hotel entry: %v", b)
	}
	if entry("key1", "a") != nil {
		t.Fatal("g1 sees hotel a")
	}
}
