package main

import (
	"testing"
	"time"
)

// AB#869: a guest's views of hotel health (capacity, /v1/broker/hotels,
// /v1/status) count the same hotels placement can use, and capacity says
// when each hotel last answered health.

func statusCounts(t *testing.T, tc *testChain, key string) (hotels, up float64) {
	t.Helper()
	status, doc := tc.call(t, key, "GET", "/v1/status", nil)
	if status != 200 {
		t.Fatalf("status: %d %v", status, doc)
	}
	return doc["hotels"].(float64), doc["hotels_up"].(float64)
}

func hotelIDs(doc map[string]any) map[string]bool {
	out := map[string]bool{}
	list, _ := doc["hotels"].([]any)
	for _, x := range list {
		out[x.(map[string]any)["id"].(string)] = true
	}
	return out
}

func TestStatusCountsOnlyTheGuestsOwnHotels(t *testing.T) {
	tc := newChain(t) // hotels a, b, c
	reserve(t, tc, "c", "g2")
	setHotel(tc, "b", func(h *hotel) { h.ok = false })
	if n, up := statusCounts(t, tc, "key1"); n != 2 || up != 1 {
		t.Fatalf("g1 (c is reserved for g2, b down): hotels %v up %v, want 2 and 1", n, up)
	}
	if n, up := statusCounts(t, tc, "key2"); n != 3 || up != 2 {
		t.Fatalf("g2 reaches all three: hotels %v up %v", n, up)
	}
	// An ops key keeps the fleet view.
	tc.b.mu.Lock()
	tc.b.guests["g1"].cfg.Ops = true
	tc.b.mu.Unlock()
	if n, up := statusCounts(t, tc, "key1"); n != 3 || up != 2 {
		t.Fatalf("ops key: hotels %v up %v, want the fleet 3 and 2", n, up)
	}
}

func TestOwnHostsOnlyGuestViewsSkipMinerHotels(t *testing.T) {
	tc := newChain(t)
	markMiner(tc, "b", true)
	optIntoMiners(t, tc) // the policy reaches b; only own_hosts_only keeps g1 off it
	guestPatch(t, tc, map[string]any{"own_hosts_only": true})
	if n, _ := statusCounts(t, tc, "key1"); n != 2 {
		t.Fatalf("status counts the miner hotel: %v", n)
	}
	for _, path := range []string{"/v1/broker/capacity", "/v1/broker/hotels"} {
		status, doc := tc.call(t, "key1", "GET", path, nil)
		ids := hotelIDs(doc)
		if status != 200 || ids["b"] || !ids["a"] || !ids["c"] {
			t.Fatalf("%s: %d hotels %v, want a and c only", path, status, ids)
		}
	}
}

func TestCapacityTellsWhenEachHotelLastAnsweredHealth(t *testing.T) {
	tc := newChain(t)
	at := time.Now().Add(-3 * time.Second)
	setHotel(tc, "a", func(h *hotel) { h.lastOK, h.healthLate = at, false })
	setHotel(tc, "b", func(h *hotel) { h.lastOK, h.healthLate = at, true })
	setHotel(tc, "c", func(h *hotel) { h.lastOK = time.Time{} })
	status, doc := tc.call(t, "key1", "GET", "/v1/broker/capacity", nil)
	if status != 200 {
		t.Fatalf("capacity: %d %v", status, doc)
	}
	got := map[string]map[string]any{}
	for _, x := range doc["hotels"].([]any) {
		e := x.(map[string]any)
		got[e["id"].(string)] = e
	}
	for _, id := range []string{"a", "b"} {
		s, _ := got[id]["last_ok_at"].(string)
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil || !ts.Equal(at.UTC().Truncate(time.Second)) {
			t.Fatalf("%s last_ok_at %q (err %v), want %s", id, s, err, at.UTC().Format(time.RFC3339))
		}
	}
	if got["a"]["health_late"] != false || got["b"]["health_late"] != true {
		t.Fatalf("health_late a=%v b=%v", got["a"]["health_late"], got["b"]["health_late"])
	}
	if v, ok := got["c"]["last_ok_at"]; !ok || v != nil {
		t.Fatalf("a hotel never healthy has last_ok_at null, got %v (present %v)", v, ok)
	}
}
