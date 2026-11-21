package main

import (
	"net/http"
	"strings"
	"testing"
)

// AB#865: count on the compat create, and a count above a key limit is a 400.

func TestCompatCreateCountStartsEveryRoom(t *testing.T) {
	tc := newChain(t)
	before := 0
	for _, n := range createsOn(tc) {
		before += n
	}
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "count": 5}), nil)
	if status != 201 {
		t.Fatalf("count 5: %d %v", status, doc)
	}
	rooms, _ := doc["sandboxes"].([]any)
	if len(rooms) != 5 || doc["count"] != float64(5) {
		t.Fatalf("want 5 rooms, got %v", doc)
	}
	after := 0
	for _, n := range createsOn(tc) {
		after += n
	}
	if after-before != 5 {
		t.Fatalf("%d hotel creates, want 5", after-before)
	}
	seen := map[string]bool{}
	for _, r := range rooms {
		v := r.(map[string]any)
		id, _ := v["id"].(string)
		if id == "" || seen[id] || v["state"] == nil || v["hotel"] == nil {
			t.Fatalf("room view %v", v)
		}
		seen[id] = true
		if st, got := tc.clientCall(t, "GET", "/v1/sandboxes/"+id, nil, nil); st != 200 || got["id"] != id {
			t.Fatalf("GET %s: %d %v", id, st, got)
		}
	}
}

func TestCompatCreateCountOneKeepsTheSingleAnswer(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "count": 1}), nil)
	if status != 201 || doc["sandboxes"] != nil {
		t.Fatalf("count 1: %d %v", status, doc)
	}
	if id, _ := doc["id"].(string); id == "" {
		t.Fatalf("count 1 has no id: %v", doc)
	}
}

func TestCompatCreateCountPartialFailureIsCounted(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "a", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	setHotel(tc, "b", func(h *hotel) { h.slots = 2 }) // room for 2 of the 4
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "sealed": false, "count": 4}), nil)
	if status != 201 {
		t.Fatalf("partial: %d %v", status, doc)
	}
	errs, _ := doc["errors"].(map[string]any)
	got := 0
	for _, n := range errs {
		got += int(n.(float64))
	}
	if doc["count"] == float64(0) || int(doc["count"].(float64))+got != 4 {
		t.Fatalf("rooms %v + errors %v != 4", doc["count"], errs)
	}
}

func TestCompatCreateCountValuesAreChecked(t *testing.T) {
	tc := newChain(t)
	for _, v := range []any{0, -2, 1001, 2.5, "5", true} {
		status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "count": v}), nil)
		if d, _ := doc["detail"].(map[string]any); status != 400 || d["error"] != "invalid_count" {
			t.Fatalf("count %v: want 400 invalid_count, got %d %v", v, status, doc)
		}
	}
	if n := len(tc.b.guests["g1"].admits); n != 0 {
		t.Fatalf("refused counts used %d rate slots", n)
	}
}

func TestCompatCreateCountReplaysWithTheSameKey(t *testing.T) {
	tc := newChain(t)
	hdr := map[string]string{"Idempotency-Key": "batch-1"}
	status, first := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "count": 3}), hdr)
	if status != 201 {
		t.Fatalf("first: %d %v", status, first)
	}
	creates := 0
	for _, n := range createsOn(tc) {
		creates += n
	}
	status, again := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "count": 3}), hdr)
	if status != 201 || mustMarshalString(again) != mustMarshalString(first) {
		t.Fatalf("replay differs: %d %v vs %v", status, again, first)
	}
	after := 0
	for _, n := range createsOn(tc) {
		after += n
	}
	if after != creates {
		t.Fatalf("replay started %d more rooms", after-creates)
	}
}

func mustMarshalString(v any) string { return string(mustMarshal(v)) }

func TestCountOverTheRateLimitIs400NotARetryLoop(t *testing.T) {
	tc := limitedChain(t, guestLimits{MaxCreatesPerMinute: 2})
	for _, compat := range []bool{false, true} {
		req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20","count":3}`))
		req.Header.Set("Authorization", "Bearer key1")
		if compat {
			req, _ = http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes", strings.NewReader(`{"template":"room-1x4","count":3}`))
			req.Header.Set("Authorization", "Bearer key1")
			req.Header.Set("User-Agent", "cathedral-harbor/0.1.5")
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body [512]byte
		n, _ := resp.Body.Read(body[:])
		resp.Body.Close()
		if resp.StatusCode != 400 || resp.Header.Get("Retry-After") != "" || !strings.Contains(string(body[:n]), "count_over_rate_limit") {
			t.Fatalf("compat=%v count 3 over a limit of 2: %d Retry-After %q %s", compat, resp.StatusCode, resp.Header.Get("Retry-After"), body[:n])
		}
	}
	// A count at the limit still passes.
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 2}); status != 202 {
		t.Fatalf("count 2 at a limit of 2: %d %v", status, doc)
	}
}

func TestCountOverTheRoomLimitIs400(t *testing.T) {
	tc := limitedChain(t, guestLimits{MaxRooms: 2})
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 3})
	if status != 400 || errCode(doc) != "count_over_room_limit" {
		t.Fatalf("count 3 over max_rooms 2: %d %v", status, doc)
	}
}
