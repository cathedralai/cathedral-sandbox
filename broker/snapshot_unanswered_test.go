package main

import (
	"strings"
	"testing"
)

// AB#866: a fork or delete by bare snapshot name asks every hotel. A hotel
// that did not answer may hold the name, so it must not be read as "not
// found": a hotel that is up answers 502 hotel_unreachable (retry); a hotel
// already known down keeps 404, naming the hotel, so a long-down hotel does
// not turn every unknown name into a retry loop.

func snapshotOnB(t *testing.T, tc *testChain, name string) string {
	t.Helper()
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", map[string]any{"name": name})
	if status != 202 {
		t.Fatalf("snapshot: %d %v", status, doc)
	}
	return doc["result"].(map[string]any)["snapshot_id"].(string)
}

func setHotelOK(tc *testChain, id string, ok bool) {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	tc.b.hotelByID(id).ok = ok
}

func TestBareSnapshotLookupWithAnUnansweredUpHotelIs502(t *testing.T) {
	tc := newChain(t)
	snapshotOnB(t, tc, "keep")
	tc.hotels["b"].mu.Lock()
	tc.hotels["b"].snapListFail = true
	tc.hotels["b"].mu.Unlock()
	before := createsOn(tc)

	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/v1/sandboxes", map[string]any{"snapshot_id": "keep"}},
		{"DELETE", "/v1/snapshots/keep", nil},
	} {
		status, doc := tc.call(t, "key1", c.method, c.path, c.body)
		msg, _ := doc["error"].(map[string]any)["message"].(string)
		if status != 502 || errCode(doc) != "hotel_unreachable" || !strings.Contains(msg, "b") || !strings.Contains(msg, "<hotel>.<snapshot id>") {
			t.Fatalf("%s %s with hotel b unanswered: %d %v", c.method, c.path, status, doc)
		}
	}
	if after := createsOn(tc); after["a"] != before["a"] || after["b"] != before["b"] || after["c"] != before["c"] {
		t.Fatalf("a fork with its hotel unanswered started a room: %v -> %v", before, after)
	}
	if len(tc.hotels["b"].snaps) != 1 {
		t.Fatalf("snapshot on b was deleted: %v", tc.hotels["b"].snaps)
	}
}

func TestBareSnapshotLookupWithOnlyKnownDownHotelsUnansweredIs404NamingThem(t *testing.T) {
	tc := newChain(t)
	tc.hotels["b"].mu.Lock()
	tc.hotels["b"].snapListFail = true
	tc.hotels["b"].mu.Unlock()
	setHotelOK(tc, "b", false)

	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": "nope"})
	msg, _ := doc["error"].(map[string]any)["message"].(string)
	if status != 404 || errCode(doc) != "snapshot_not_found" || !strings.Contains(msg, "hotel b") {
		t.Fatalf("unknown name with hotel b down: %d %v", status, doc)
	}
}

func TestBareSnapshotLookupHitWinsOverAnUnansweredHotel(t *testing.T) {
	tc := newChain(t)
	snapshotOnB(t, tc, "keep")
	tc.hotels["c"].mu.Lock()
	tc.hotels["c"].snapListFail = true
	tc.hotels["c"].mu.Unlock()
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": "keep"}); status != 202 {
		t.Fatalf("fork found on b with c unanswered: %d %v", status, doc)
	}
	// Every hotel answered and none has it: plain 404, no hotel named.
	tc.hotels["c"].mu.Lock()
	tc.hotels["c"].snapListFail = false
	tc.hotels["c"].mu.Unlock()
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": "nope"})
	msg, _ := doc["error"].(map[string]any)["message"].(string)
	if status != 404 || errCode(doc) != "snapshot_not_found" || msg != "no snapshot nope" {
		t.Fatalf("unknown name, all answered: %d %v", status, doc)
	}
}
