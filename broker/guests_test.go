package main

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
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

func TestForkOfASealedSnapshotStaysSealed(t *testing.T) {
	tc := limitedChain(t, guestLimits{DefaultSealed: true})
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	if hotelOf(room) != "a" {
		t.Fatalf("room on %s", room)
	}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", map[string]any{"name": "s"})
	if status != 202 {
		t.Fatalf("snapshot: %d %v", status, doc)
	}
	snap := doc["result"].(map[string]any)["snapshot_id"].(string)
	if id := tc.room(t, "key1", map[string]any{"snapshot_id": snap}); hotelOf(id) != "a" {
		t.Fatalf("fork on %s", id)
	}
	// A guest without the default forks a sealed snapshot with "sealed": true.
	tc.b.guests["g1"].limits.DefaultSealed = false
	if id := tc.room(t, "key1", map[string]any{"snapshot_id": snap, "sealed": true}); hotelOf(id) != "a" {
		t.Fatalf("explicit sealed fork on %s", id)
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

// A create from a broker-built image obeys the sealed default and the hotel
// set: it never lands on an unsealed hotel only because that hotel built it.
func TestBuiltImageObeysSealedDefaultAndHotelSet(t *testing.T) {
	tc := limitedChain(t, guestLimits{DefaultSealed: true, Hotels: []string{"a", "b"}})
	tc.hotels["a"].failBuild = true // the sealed hotel cannot build at first
	body, ctype := buildForm(t, "FROM alpine:3.20\n", []byte("ctx"))
	_, doc := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	imgID := doc["image_id"].(string)
	view := waitImage(t, tc, imgID)
	if view["state"] == "ready" {
		t.Fatalf("image ready for a sealed-default guest with no sealed build: %v", view)
	}
	if len(tc.hotels["c"].builds) != 0 {
		t.Fatalf("a hotel outside the guest's set built the image")
	}
	before := createsOn(tc)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": imgID}), nil)
	detail, _ := doc["detail"].(map[string]any)
	if status != 409 || detail["error"] != "image_not_ready" {
		t.Fatalf("create with the image only on an unsealed hotel: %d %v", status, doc)
	}
	if after := createsOn(tc); after["b"] != before["b"] {
		t.Fatalf("create went to the unsealed hotel that built the image")
	}
	// An explicit unsealed create may use the unsealed build.
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": imgID, "sealed": false}), nil)
	if status != 201 || createsOn(tc)["b"] != before["b"]+1 {
		t.Fatalf("unsealed create from the image: %d %v", status, doc)
	}
	// The sealed hotel builds on the next try; then a plain create goes there.
	tc.hotels["a"].mu.Lock()
	tc.hotels["a"].failBuild = false
	tc.hotels["a"].mu.Unlock()
	tc.b.compat.mu.Lock()
	tc.b.compat.images[imgID].failedAt["a"] = time.Now().Add(-2 * time.Minute)
	tc.b.compat.mu.Unlock()
	status, _ = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": imgID}), nil)
	if status != 409 {
		t.Fatalf("create while the sealed build runs: %d", status)
	}
	if v := waitImage(t, tc, imgID); v["state"] != "ready" {
		t.Fatalf("view after the sealed build: %v", v)
	}
	before = createsOn(tc)
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": imgID}), nil)
	if status != 201 || createsOn(tc)["a"] != before["a"]+1 {
		t.Fatalf("sealed create from the image: %d %v", status, doc)
	}
}

func TestOperatorAddsAGuestAtRuntimeAndItSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	add := map[string]any{"id": "polaris", "key_sha256": sha("key3"), "max_rooms": 2, "hotels": []string{"b", "c"}}

	if status, _ := tc.call(t, "key1", "POST", "/v1/broker/guests", add); status != 401 {
		t.Fatalf("guest key added a guest: %d", status)
	}
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/guests", add)
	if status != 201 || doc["id"] != "polaris" || doc["runtime"] != true || doc["ops"] != false {
		t.Fatalf("add: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/guests", add); status != 409 || errCode(doc) != "guest_exists" {
		t.Fatalf("second add: %d %v", status, doc)
	}
	same := map[string]any{"id": "other", "key_sha256": sha("key1")}
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/guests", same); status != 409 || errCode(doc) != "key_in_use" {
		t.Fatalf("reused key: %d %v", status, doc)
	}
	for _, bad := range []map[string]any{
		{"id": "Bad_ID", "key_sha256": sha("k")},
		{"id": "x", "key_sha256": "key-in-clear"},
		{"id": "x", "key_sha256": sha("k"), "hotels": []string{"zz"}},
		{"id": "x", "key_sha256": sha("k"), "ops": true},
	} {
		if status, _ := tc.call(t, "operator-key", "POST", "/v1/broker/guests", bad); status != 400 {
			t.Fatalf("bad add %v: %d", bad, status)
		}
	}
	if raw, _ := os.ReadFile(dir + "/" + runtimeGuestsFile); strings.Contains(string(raw), "key3") || !strings.Contains(string(raw), sha("key3")) {
		t.Fatalf("guests.json: %s", raw)
	}

	// The new key works at once, inside its hotel set and room limit.
	if id := tc.room(t, "key3", map[string]any{"image": "alpine:3.20"}); hotelOf(id) == "a" {
		t.Fatalf("runtime guest got hotel a: %s", id)
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/polaris", map[string]any{"max_rooms": 1}); status != 200 || doc["max_rooms"] != float64(1) {
		t.Fatalf("patch: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/guests/polaris", nil); status != 409 || errCode(doc) != "guest_has_rooms" {
		t.Fatalf("delete with rooms: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/guests/g1", nil); status != 409 || errCode(doc) != "config_guest" {
		t.Fatalf("delete config guest: %d %v", status, doc)
	}

	// After a restart the guest and its patched limit come back.
	tc.start(t)
	status, doc = tc.call(t, "operator-key", "GET", "/v1/broker/guests", nil)
	var found map[string]any
	for _, g := range doc["guests"].([]any) {
		if m := g.(map[string]any); m["id"] == "polaris" {
			found = m
		}
	}
	if status != 200 || found == nil || found["max_rooms"] != float64(1) || found["runtime"] != true {
		t.Fatalf("after restart: %d %v", status, doc)
	}
	if status, _ := tc.call(t, "key3", "GET", "/v1/quota", nil); status != 200 {
		t.Fatalf("runtime key after restart: %d", status)
	}
}

func TestRuntimeGuestNeedsAStateDir(t *testing.T) {
	tc := newChain(t)
	add := map[string]any{"id": "polaris", "key_sha256": sha("key3")}
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/guests", add); status != 409 || errCode(doc) != "no_state_dir" {
		t.Fatalf("add without state_dir: %d %v", status, doc)
	}
}
