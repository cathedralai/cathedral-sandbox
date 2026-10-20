package main

import (
	"net/http"
	"strings"
	"testing"
)

// limitedChain is newChain with hotel "a" sealed and limits on guest g1.
func limitedChain(t *testing.T, lim guestLimits) *testChain {
	t.Helper()
	tc := newChain(t)
	tc.b.hotelByID("a").cfg.Sealed = true
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits = lim
	tc.b.mu.Unlock()
	return tc
}

func hotelOf(id string) string { h, _, _ := strings.Cut(id, "."); return h }

func TestSealedByDefaultUnsealedOnlyWhenAsked(t *testing.T) {
	tc := limitedChain(t, guestLimits{DefaultSealed: true})
	for i := 0; i < 5; i++ {
		if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"}); hotelOf(id) != "a" {
			t.Fatalf("default create went to %s, want the sealed hotel", id)
		}
		if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "sealed": false}); hotelOf(id) == "a" {
			t.Fatalf("sealed=false create went to the sealed hotel: %s", id)
		}
	}
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}}); hotelOf(id) != "c" {
		t.Fatalf("named hotel c, got %s", id)
	}
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "exclude_hotel_labels": map[string]string{"sealed": "true"}}); hotelOf(id) == "a" {
		t.Fatalf("excluded sealed, got %s", id)
	}
	// The broker removes "sealed" before it calls the hotel.
	for _, f := range tc.hotels {
		for _, c := range f.creates {
			if _, ok := c["sealed"]; ok {
				t.Fatalf("hotel got the sealed field: %v", c)
			}
		}
	}
	// Guest g2 has no sealed default: a plain create never goes to the sealed hotel.
	for i := 0; i < 5; i++ {
		if id := tc.room(t, "key2", map[string]any{"image": "alpine:3.20"}); hotelOf(id) == "a" {
			t.Fatalf("g2 plain create went to the sealed hotel: %s", id)
		}
	}
}

func TestClientCreateIsSealedByDefault(t *testing.T) {
	tc := limitedChain(t, guestLimits{DefaultSealed: true})
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	if n := len(tc.hotels["a"].creates); n != 1 {
		t.Fatalf("sealed hotel creates = %d, want 1", n)
	}
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "sealed": false}), nil)
	if status != 201 || len(tc.hotels["a"].creates) != 1 {
		t.Fatalf("unsealed client create: %d %v, sealed creates %d", status, doc, len(tc.hotels["a"].creates))
	}
}

func TestForkIgnoresTheSealedDefault(t *testing.T) {
	tc := limitedChain(t, guestLimits{DefaultSealed: true})
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "sealed": false})
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", map[string]any{"name": "s"})
	if status != 202 {
		t.Fatalf("snapshot: %d %v", status, doc)
	}
	snap := doc["result"].(map[string]any)["snapshot_id"].(string)
	if id := tc.room(t, "key1", map[string]any{"snapshot_id": snap}); hotelOf(id) != hotelOf(room) {
		t.Fatalf("fork on %s, snapshot on %s", id, room)
	}
}

func TestGuestHotelSet(t *testing.T) {
	tc := limitedChain(t, guestLimits{Hotels: []string{"a", "b"}})
	for i := 0; i < 20; i++ {
		if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"}); hotelOf(id) != "b" {
			t.Fatalf("create outside the hotel set or on the sealed hotel: %s", id)
		}
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}}); status != 400 || errCode(doc) != "unknown_hotel" {
		t.Fatalf("hotel outside the set: %d %v", status, doc)
	}
	status, doc := tc.call(t, "key1", "GET", "/v1/broker/hotels", nil)
	if status != 200 {
		t.Fatalf("hotels: %d", status)
	}
	var ids []string
	for _, h := range doc["hotels"].([]any) {
		ids = append(ids, h.(map[string]any)["id"].(string))
	}
	if strings.Join(ids, ",") != "a,b" {
		t.Fatalf("hotel list %v, want a,b", ids)
	}
}

func TestRoomLimit(t *testing.T) {
	tc := limitedChain(t, guestLimits{MaxRooms: 3})
	for i := 0; i < 3; i++ {
		tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status != 429 || errCode(doc) != "room_limit" {
		t.Fatalf("4th room: %d %v", status, doc)
	}
	// A batch that does not fit is refused as a whole; no hotel gets a create.
	before := createsOn(tc)
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 2}); status != 429 || errCode(doc) != "room_limit" {
		t.Fatalf("batch: %d %v", status, doc)
	}
	after := createsOn(tc)
	for id := range before {
		if before[id] != after[id] {
			t.Fatalf("refused batch reached hotel %s", id)
		}
	}
	// The client path is limited too.
	if status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil); status != 429 {
		t.Fatalf("client create over the limit: %d %v", status, doc)
	}
	// Another guest is not affected.
	tc.room(t, "key2", map[string]any{"image": "alpine:3.20"})
	// The guest sees its limit in /v1/quota.
	_, q := tc.call(t, "key1", "GET", "/v1/quota", nil)
	if gq := q["guest"].(map[string]any); gq["max_rooms"] != float64(3) || gq["running_sandboxes"] != float64(3) {
		t.Fatalf("quota guest %v", gq)
	}
}

func TestDefaultRoomLimitIs1000(t *testing.T) {
	tc := limitedChain(t, guestLimits{})
	for _, h := range tc.b.hotelList() {
		h.slots = 2000
	}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 1001})
	if status != 429 || errCode(doc) != "room_limit" {
		t.Fatalf("1,001 rooms: %d %v", status, doc)
	}
}

func TestCreateRateLimit(t *testing.T) {
	tc := limitedChain(t, guestLimits{MaxCreatesPerMinute: 2})
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`))
	req.Header.Set("Authorization", "Bearer key1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("3rd create in a minute: %d, Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
}

func TestGuestsCannotReachEachOthersRooms(t *testing.T) {
	tc := limitedChain(t, guestLimits{})
	mine := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	theirs := tc.room(t, "key2", map[string]any{"image": "alpine:3.20"})
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/sandboxes/" + theirs},
		{"POST", "/v1/sandboxes/" + theirs + "/exec"},
		{"DELETE", "/v1/sandboxes/" + theirs},
		{"POST", "/v1/sandboxes/" + theirs + "/snapshot"},
	} {
		if status, doc := tc.call(t, "key1", c.method, c.path, map[string]any{"command": "id"}); status != 404 || errCode(doc) != "sandbox_not_found" {
			t.Fatalf("g1 %s %s: %d %v", c.method, c.path, status, doc)
		}
	}
	if status, _ := tc.call(t, "key2", "DELETE", "/v1/sandboxes/"+mine, nil); status != 404 {
		t.Fatalf("g2 deleted g1's room: %d", status)
	}
	// The list asks each hotel with the guest's own label only.
	_, doc := tc.call(t, "key1", "GET", "/v1/sandboxes", nil)
	for _, s := range doc["sandboxes"].([]any) {
		if s.(map[string]any)["id"] == theirs {
			t.Fatalf("g1 list shows g2's room")
		}
	}
}

func TestOperatorChangesGuestLimitsAtRuntime(t *testing.T) {
	tc := limitedChain(t, guestLimits{})
	if status, _ := tc.call(t, "key1", "PATCH", "/v1/broker/guests/g1", map[string]any{"max_rooms": 1}); status != 401 {
		t.Fatalf("guest key changed limits: %d", status)
	}
	status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"max_rooms": 1, "default_sealed": true, "hotels": []string{"a", "b"}})
	if status != 200 || doc["max_rooms"] != float64(1) || doc["default_sealed"] != true {
		t.Fatalf("patch: %d %v", status, doc)
	}
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"}); hotelOf(id) != "a" {
		t.Fatalf("after patch, create on %s", id)
	}
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 429 {
		t.Fatalf("over the patched limit: %d", status)
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"hotels": []string{"zz"}}); status != 400 || errCode(doc) != "unknown_hotel" {
		t.Fatalf("unknown hotel: %d %v", status, doc)
	}
	if status, _ := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"max_room": 5}); status != 400 {
		t.Fatalf("unknown field accepted: %d", status)
	}
	if status, _ := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/nobody", map[string]any{"max_rooms": 5}); status != 404 {
		t.Fatalf("unknown guest: %d", status)
	}
	status, doc = tc.call(t, "operator-key", "GET", "/v1/broker/guests", nil)
	if status != 200 || len(doc["guests"].([]any)) != 2 {
		t.Fatalf("list: %d %v", status, doc)
	}
	if strings.Contains(mustString(doc), "sha256") {
		t.Fatalf("guest list shows key hashes")
	}
}

func TestProbeAndCounterResetNeedOps(t *testing.T) {
	tc := limitedChain(t, guestLimits{})
	if status, _ := tc.call(t, "key1", "POST", "/v1/broker/probe", nil); status != 403 {
		t.Fatalf("probe without ops: %d", status)
	}
	if status, _ := tc.call(t, "key1", "POST", "/v1/broker/stats", nil); status != 403 {
		t.Fatalf("stats reset without ops: %d", status)
	}
	if status, _ := tc.call(t, "key1", "GET", "/v1/broker/stats", nil); status != 200 {
		t.Fatalf("stats read: %d", status)
	}
	tc.b.guests["g1"].cfg.Ops = true
	if status, _ := tc.call(t, "key1", "POST", "/v1/broker/stats", nil); status != 200 {
		t.Fatalf("stats reset with ops: %d", status)
	}
}

func mustString(v any) string { return string(mustMarshal(v)) }
