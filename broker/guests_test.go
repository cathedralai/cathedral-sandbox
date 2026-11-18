package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// limitedChain is newChain with hotel "a" sealed and limits on guest g1.
func limitedChain(t *testing.T, lim guestLimits) *testChain {
	t.Helper()
	tc := newChain(t)
	ungatedSealed(tc.b.hotelByID("a"))
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits = lim
	tc.b.mu.Unlock()
	return tc
}

func hotelOf(id string) string { h, _, _ := strings.Cut(id, "."); return h }

func totalCreates(tc *testChain) int {
	n := 0
	for _, c := range createsOn(tc) {
		n += c
	}
	return n
}

// AB#776: every hotel is sealed, so "sealed": false has no class to go to
// and is refused before any hotel is called. default_sealed changes nothing:
// a guest with it and a guest without it both reach every hotel.
func TestSealedFalseIsRefusedAndDefaultSealedChangesNothing(t *testing.T) {
	tc := limitedChain(t, guestLimits{DefaultSealed: true})
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "sealed": false})
	if status != 400 || errCode(doc) != "sealed_only" {
		t.Fatalf(`native create "sealed": false: %d %v, want 400 sealed_only`, status, doc)
	}
	if n := totalCreates(tc); n != 0 {
		t.Fatalf("a refused create reached a hotel: %v", createsOn(tc))
	}
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "sealed": true}); hotelOf(id) == "" {
		t.Fatalf(`"sealed": true create: %s`, id)
	}
	// With and without default_sealed, a plain create and one naming any
	// hotel are placed alike.
	for _, key := range []string{"key1", "key2"} {
		tc.room(t, key, map[string]any{"image": "alpine:3.20"})
		for _, id := range []string{"a", "b", "c"} {
			if got := tc.room(t, key, map[string]any{"image": "alpine:3.20", "hotels": []string{id}}); hotelOf(got) != id {
				t.Fatalf("%s named %s, got %s", key, id, got)
			}
		}
	}
	// The broker removes "sealed" before it calls the hotel.
	for _, f := range tc.hotels {
		for _, c := range f.creates {
			if _, ok := c["sealed"]; ok {
				t.Fatalf("hotel got the sealed field: %v", c)
			}
		}
	}
}

func TestClientCreateSealedFalseIsRefused(t *testing.T) {
	tc := limitedChain(t, guestLimits{DefaultSealed: true})
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "sealed": false}), nil)
	detail, _ := doc["detail"].(map[string]any)
	if status != 400 || detail["error"] != "sealed_only" {
		t.Fatalf(`client create "sealed": false: %d %v, want 400 sealed_only`, status, doc)
	}
	if n := totalCreates(tc); n != 0 {
		t.Fatalf("a refused create reached a hotel: %v", createsOn(tc))
	}
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "sealed": true}), nil)
	if status != 201 {
		t.Fatalf(`client create "sealed": true: %d %v`, status, doc)
	}
}

func TestForkGoesToTheSnapshotsHotel(t *testing.T) {
	tc := limitedChain(t, guestLimits{DefaultSealed: true})
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", map[string]any{"name": "s"})
	if status != 202 {
		t.Fatalf("snapshot: %d %v", status, doc)
	}
	snap := doc["result"].(map[string]any)["snapshot_id"].(string)
	if id := tc.room(t, "key1", map[string]any{"snapshot_id": snap}); hotelOf(id) != hotelOf(room) {
		t.Fatalf("fork on %s, snapshot on %s", id, room)
	}
	// default_sealed changes nothing; "sealed": true is accepted on a fork.
	tc.b.guests["g1"].limits.DefaultSealed = false
	if id := tc.room(t, "key1", map[string]any{"snapshot_id": snap, "sealed": true}); hotelOf(id) != hotelOf(room) {
		t.Fatalf("explicit sealed fork on %s, snapshot on %s", id, room)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": snap, "sealed": false})
	if status != 400 || errCode(doc) != "sealed_only" {
		t.Fatalf(`fork with "sealed": false: %d %v`, status, doc)
	}
}

func TestGuestHotelSet(t *testing.T) {
	tc := limitedChain(t, guestLimits{Hotels: []string{"a", "b"}})
	for i := 0; i < 20; i++ {
		if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"}); hotelOf(id) != "a" && hotelOf(id) != "b" {
			t.Fatalf("create outside the hotel set: %s", id)
		}
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}}); status != 409 || errCode(doc) != "unknown_hotel" {
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

func TestFileMutationsForwardOnlyForTheRoomOwner(t *testing.T) {
	tc := newChain(t)
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	var hotelCalls atomic.Int32
	hotel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hotelCalls.Add(1)
		if r.URL.Query().Get("path") != "/work/demo" {
			t.Errorf("hotel path = %q", r.URL.Query().Get("path"))
		}
		_, tail, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/sandboxes/"), "/")
		switch r.Method + " /" + tail {
		case "PUT /directories":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"path":"/work/demo","created":true}`))
		case "DELETE /entries":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"code":"directory_not_empty"}}`))
		default:
			t.Errorf("unexpected hotel request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(hotel.Close)
	tc.b.hotelByID(hotelOf(id)).cfg.API = hotel.URL
	for _, req := range []struct{ method, tail string }{
		{"PUT", "directories"}, {"DELETE", "entries"},
	} {
		status, _, err := rawCall(tc, "key2", "", req.method, "/v1/sandboxes/"+id+"/"+req.tail+"?path=/work/demo", nil)
		if err != nil || status != http.StatusNotFound {
			t.Fatalf("foreign guest %s: status %d, err %v", req.tail, status, err)
		}
	}
	if hotelCalls.Load() != 0 {
		t.Fatalf("foreign guest reached hotel %d times", hotelCalls.Load())
	}
	for _, req := range []struct {
		method, tail string
		want         int
		body         string
	}{
		{"PUT", "directories", 200, `{"path":"/work/demo","created":true}`},
		{"DELETE", "entries", 409, `{"error":{"code":"directory_not_empty"}}`},
	} {
		status, raw, err := rawCall(tc, "key1", "", req.method, "/v1/sandboxes/"+id+"/"+req.tail+"?path=/work/demo", nil)
		if err != nil || status != req.want || string(raw) != req.body {
			t.Fatalf("owner %s: status %d, body %s, err %v", req.tail, status, raw, err)
		}
	}
	if hotelCalls.Load() != 2 {
		t.Fatalf("owner reached hotel %d times, want 2", hotelCalls.Load())
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
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"}); hotelOf(id) != "a" && hotelOf(id) != "b" {
		t.Fatalf("after patch, create on %s, want a or b", id)
	}
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 429 {
		t.Fatalf("over the patched limit: %d", status)
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"hotels": []string{"zz"}}); status != 409 || errCode(doc) != "unknown_hotel" {
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

func TestLimitsComeFromTheConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.json"
	raw := `{"listen":"127.0.0.1:0","hotels":[],"guests":[{"id":"x","key_sha256":"ab","max_rooms":7,"max_creates_per_minute":3,"default_sealed":true,"hotels":["h1"],"ops":true}]}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := loadBroker(path)
	if err != nil {
		t.Fatal(err)
	}
	g := b.guests["x"]
	if l := g.limits; l.maxRooms() != 7 || l.MaxCreatesPerMinute != 3 || !l.DefaultSealed || len(l.Hotels) != 1 || l.Hotels[0] != "h1" || !g.cfg.Ops {
		t.Fatalf("limits %+v ops %v", g.limits, g.cfg.Ops)
	}
}

// A dedicated hotel stays dedicated: an ops guest's probe must not start a
// room on a hotel outside that guest's own hotel list.
func TestProbeKeepsToGuestHotels(t *testing.T) {
	tc := limitedChain(t, guestLimits{Hotels: []string{"b", "c"}})
	tc.b.guests["g1"].cfg.Ops = true
	if status, doc := tc.call(t, "key1", "POST", "/v1/broker/probe", nil); status != 200 {
		t.Fatalf("probe: %d %v", status, doc)
	}
	if n := len(tc.hotels["a"].creates); n != 0 {
		t.Fatalf("probe started %d room(s) on hotel a, outside the guest's list", n)
	}
	if len(tc.hotels["b"].creates) == 0 {
		t.Fatalf("probe did not reach an allowed hotel")
	}
}
