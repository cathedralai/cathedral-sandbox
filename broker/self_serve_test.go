package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const ssID = "acct-0123456789abcdef0123"

// selfServeChain is a chain with state_dir and a self_serve block (ceiling
// 5, every sealed hotel). edit may change the config first. Every hotel
// lists its rooms once, so no recount is pending.
func selfServeChain(t *testing.T, edit func(*config)) *testChain {
	t.Helper()
	tc := newChainState(t, t.TempDir())
	ssEdit(t, tc, func(c *config) {
		c.SelfServe = &selfServeConfig{IDPrefix: "acct-", MaxRoomsCeiling: 5, MaxCreatesPerMinute: 120,
			Policy: &guestPolicy{Allow: []selector{{Class: classSealed}}}}
		if edit != nil {
			edit(c)
		}
	})
	return tc
}

// ssEdit changes the config file and restarts the broker (with one sync).
func ssEdit(t *testing.T, tc *testChain, fn func(*config)) {
	t.Helper()
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	fn(&c)
	out, _ := json.Marshal(c)
	if err := os.WriteFile(tc.cfgPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
}

func ssBody(key string, maxRooms int) map[string]any {
	return map[string]any{"key_sha256": sha(key), "max_rooms": maxRooms}
}

func (tc *testChain) putSelfServe(t *testing.T, id string, body map[string]any, want int) map[string]any {
	t.Helper()
	status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/"+id, body)
	if status != want {
		t.Fatalf("PUT self-serve %s: %d %v, want %d", id, status, doc, want)
	}
	return doc
}

func (tc *testChain) listSelfServe(t *testing.T) []any {
	t.Helper()
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/self-serve", nil)
	if status != 200 {
		t.Fatalf("GET self-serve: %d %v", status, doc)
	}
	return doc["guests"].([]any)
}

func ssKeyWorks(t *testing.T, tc *testChain, key string) bool {
	t.Helper()
	status, _ := tc.call(t, key, "GET", "/v1/sandboxes", nil)
	return status == 200
}

func TestSelfServeCreateRotateRevoke(t *testing.T) {
	tc := selfServeChain(t, nil)
	doc := tc.putSelfServe(t, ssID, ssBody("ss-key-1", 2), 201)
	if doc["created"] != true || doc["key_changed"] != true || doc["revoked"] != false || doc["max_rooms"] != 2.0 ||
		doc["max_creates_per_minute"] != 120.0 || doc["max_rooms_ceiling"] != 5.0 {
		t.Fatalf("create answer %v", doc)
	}
	if strings.Contains(string(mustMarshal(doc)), sha("ss-key-1")) {
		t.Fatal("the PUT answer holds the key hash")
	}
	g := tc.b.guestByID(ssID)
	tc.b.mu.Lock()
	lim := g.limits
	tc.b.mu.Unlock()
	if !g.selfServe || !lim.Metered || lim.Postpaid || len(lim.Hotels) != 0 || lim.Policy != tc.b.cfg.SelfServe.Policy ||
		lim.OwnHostsOnly || lim.DefaultSealed || lim.MaxCreatesPerMinute != 120 || lim.MaxRooms != 2 {
		t.Fatalf("forced settings: %+v", lim)
	}
	// Closed until the ledger sends an allowance.
	if status, doc := tc.call(t, "ss-key-1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_lease_expired" {
		t.Fatalf("create before any allowance: %d %v", status, doc)
	}
	tc.putAllowance(t, ssID, allowanceBody(1, 2))
	bid := tc.room(t, "ss-key-1", map[string]any{"image": "alpine:3.20"})

	// Rotation: the old key stops at once, the new one sees the room.
	doc = tc.putSelfServe(t, ssID, ssBody("ss-key-2", 2), 200)
	if doc["created"] != false || doc["key_changed"] != true {
		t.Fatalf("rotate answer %v", doc)
	}
	if status, _ := tc.call(t, "ss-key-1", "GET", "/v1/sandboxes", nil); status != 401 {
		t.Fatalf("old key after rotation: %d", status)
	}
	if status, doc := tc.call(t, "ss-key-2", "GET", "/v1/sandboxes/"+bid, nil); status != 200 {
		t.Fatalf("room with the new key: %d %v", status, doc)
	}
	if tc.b.guestByID(ssID) != g {
		t.Fatal("rotation replaced the guest: its counters and pending creates would be lost")
	}
	// The same key again changes nothing.
	if doc := tc.putSelfServe(t, ssID, ssBody("ss-key-2", 2), 200); doc["key_changed"] != false {
		t.Fatalf("same key again: %v", doc)
	}

	// Revoke: the key leaves at once; the guest and its room stay.
	status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/self-serve/"+ssID, nil)
	if status != 200 || doc["revoked"] != true {
		t.Fatalf("revoke: %d %v", status, doc)
	}
	if ssKeyWorks(t, tc, "ss-key-2") {
		t.Fatal("revoked key still works")
	}
	list := tc.listSelfServe(t)
	if len(list) != 1 {
		t.Fatalf("list %v", list)
	}
	e := list[0].(map[string]any)
	if e["id"] != ssID || e["revoked"] != true || e["active_rooms"] != 1.0 || e["max_rooms"] != 2.0 || e["created_at"] == "" {
		t.Fatalf("list entry %v", e)
	}
	if tc.b.guestByID(ssID) == nil {
		t.Fatal("revoke removed the guest")
	}
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/self-serve/"+ssID, nil); status != 200 || doc["revoked"] != true {
		t.Fatalf("second revoke: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/self-serve/acct-unknown1", nil); status != 404 || errCode(doc) != "guest_not_found" {
		t.Fatalf("revoke unknown: %d %v", status, doc)
	}
	// A later PUT re-keys it.
	tc.putSelfServe(t, ssID, ssBody("ss-key-3", 2), 200)
	if status, doc := tc.call(t, "ss-key-3", "GET", "/v1/sandboxes/"+bid, nil); status != 200 {
		t.Fatalf("room after re-key: %d %v", status, doc)
	}
	raw, _ := os.ReadFile(filepath.Join(tc.b.cfg.StateDir, selfServeFile))
	if strings.Contains(string(mustMarshal(tc.listSelfServe(t))), sha("ss-key-3")) || strings.Contains(string(raw), sha("ss-key-2")) {
		t.Fatal("the list holds a hash, or the file still holds a replaced hash")
	}
}

func TestSelfServeRoutesNeedTheOperatorKey(t *testing.T) {
	tc := selfServeChain(t, nil)
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 1), 201)
	for _, key := range []string{"key1", "ss-key-1", "reader-key", "enroller-key", "nope"} {
		for _, m := range []string{"GET", "PUT", "DELETE"} {
			path := "/v1/broker/self-serve"
			if m != "GET" {
				path += "/" + ssID
			}
			if status, doc := tc.call(t, key, m, path, ssBody("ss-key-9", 1)); status != 401 {
				t.Fatalf("%s %s with %s: %d %v", m, path, key, status, doc)
			}
		}
	}
	if !ssKeyWorks(t, tc, "ss-key-1") || ssKeyWorks(t, tc, "ss-key-9") {
		t.Fatal("a refused call changed the key")
	}
}

func TestSelfServeMaxRoomsBounds(t *testing.T) {
	tc := selfServeChain(t, nil)
	for _, body := range []map[string]any{
		ssBody("ss-key-1", 0), ssBody("ss-key-1", 6), ssBody("ss-key-1", -1),
		{"key_sha256": sha("ss-key-1")},
	} {
		if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/"+ssID, body); status != 400 || errCode(doc) != "invalid_limit" {
			t.Fatalf("PUT %v: %d %v", body, status, doc)
		}
	}
	for _, body := range []map[string]any{
		{"key_sha256": "abc", "max_rooms": 1}, {"max_rooms": 1}, {"key_sha256": strings.Repeat("g", 64), "max_rooms": 1},
	} {
		if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/"+ssID, body); status != 400 || errCode(doc) != "invalid_key_sha256" {
			t.Fatalf("PUT %v: %d %v", body, status, doc)
		}
	}
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/"+ssID, map[string]any{"key_sha256": sha("k"), "max_rooms": 1, "postpaid": true}); status != 400 || errCode(doc) != "invalid_json" {
		t.Fatalf("unknown field: %d %v", status, doc)
	}
	if tc.b.guestByID(ssID) != nil {
		t.Fatal("a refused PUT made a guest")
	}
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 5), 201)
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 1), 200)
	g := tc.b.guestByID(ssID)
	tc.b.mu.Lock()
	n := g.limits.maxRooms()
	tc.b.mu.Unlock()
	if n != 1 {
		t.Fatalf("max_rooms after the change: %d", n)
	}
	// The broker's room limit holds it: one room, then room_limit.
	tc.putAllowance(t, ssID, allowanceBody(1, 5))
	tc.room(t, "ss-key-1", map[string]any{"image": "alpine:3.20"})
	if status, doc := tc.call(t, "ss-key-1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 429 || errCode(doc) != "room_limit" {
		t.Fatalf("second room at max_rooms 1: %d %v", status, doc)
	}
	// The operator's guest PATCH cannot change a forced setting.
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/"+ssID, map[string]any{"max_rooms": 900}); status != 409 || errCode(doc) != "self_serve_guest" {
		t.Fatalf("PATCH a self-serve guest: %d %v", status, doc)
	}
}

func TestSelfServeIDAndKeyRefusals(t *testing.T) {
	tc := selfServeChain(t, func(c *config) {
		c.MeterKeySHA256 = sha("meter-key")
		// A config file guest whose id fits the prefix, as const would.
		c.Guests = append(c.Guests, guestConfig{ID: "acct-const01", KeySHA256: sha("const-key"), NextKeySHA256: sha("const-next"), ViewTokenSHA256: sha("const-view"), guestLimits: guestLimits{Postpaid: true}})
	})
	for _, id := range []string{"acct-", "acct-AB12345", "other-123456", "acct-" + strings.Repeat("a", 60), "_broker_fresh", "acct-a.b123"} {
		if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/"+id, ssBody("ss-key-1", 1)); status != 400 || errCode(doc) != "invalid_guest_id" {
			t.Fatalf("PUT id %q: %d %v", id, status, doc)
		}
	}
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/acct-const01", ssBody("ss-key-1", 1)); status != 409 || errCode(doc) != "guest_exists" {
		t.Fatalf("PUT a config file guest's id: %d %v", status, doc)
	}
	if status, _ := tc.call(t, "operator-key", "DELETE", "/v1/broker/self-serve/acct-const01", nil); status != 404 {
		t.Fatalf("DELETE a config file guest: %d", status)
	}
	if !ssKeyWorks(t, tc, "const-key") {
		t.Fatal("the config file guest lost its key")
	}
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 1), 201)
	for _, key := range []string{"key1", "key2", "view1", "const-key", "const-next", "const-view", "operator-key", "reader-key", "enroller-key", "meter-key", "ss-key-1"} {
		if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/acct-second01", ssBody(key, 1)); status != 409 || errCode(doc) != "key_in_use" {
			t.Fatalf("PUT with the hash of %s: %d %v", key, status, doc)
		}
		if key != "ss-key-1" {
			if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/"+ssID, ssBody(key, 1)); status != 409 || errCode(doc) != "key_in_use" {
				t.Fatalf("rotate onto the hash of %s: %d %v", key, status, doc)
			}
		}
	}
	if tc.b.guestByID("acct-second01") != nil || !ssKeyWorks(t, tc, "ss-key-1") {
		t.Fatal("a refused PUT changed something")
	}
}

func TestSelfServeReservedIDsAreRefused(t *testing.T) {
	tc := selfServeChain(t, func(c *config) { c.SelfServe.IDPrefix = "cathedral-" })
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/"+poolGuestID, ssBody("ss-key-1", 1)); status != 409 || errCode(doc) != "guest_exists" {
		t.Fatalf("PUT the pool guest id: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/"+freshGuestID, ssBody("ss-key-1", 1)); status != 400 && status != 409 {
		t.Fatalf("PUT the fresh guest id: %d %v", status, doc)
	}
	if tc.b.guestByID(poolGuestID) != nil || tc.b.guestByID(freshGuestID) != nil {
		t.Fatal("a reserved id became a guest")
	}
}

// A self-serve guest never reaches a hotel reserved for another guest, even
// when the self_serve policy names it.
func TestSelfServeCannotReachAReservedHotel(t *testing.T) {
	tc := selfServeChain(t, func(c *config) {
		c.Hotels[0].ReservedFor = "g2" // hotel "a", as nc-sealed is for const
		c.SelfServe.Policy = &guestPolicy{Prefer: []selector{{Hotel: "a"}}, Allow: []selector{{Hotel: "a"}, {Class: classSealed}}}
	})
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 5), 201)
	tc.putAllowance(t, ssID, allowanceBody(1, 5))
	g := tc.b.guestByID(ssID)
	tc.b.mu.Lock()
	tier := g.tierOf(tc.b.hotelByID("a"))
	tc.b.mu.Unlock()
	if tier != "" {
		t.Fatalf("self-serve guest reaches reserved hotel a at tier %q", tier)
	}
	before := createsOn(tc)["a"]
	for i := 0; i < 4; i++ {
		bid := tc.room(t, "ss-key-1", map[string]any{"image": "alpine:3.20"})
		if strings.HasPrefix(bid, "a.") {
			t.Fatalf("room %s placed on reserved hotel a", bid)
		}
	}
	if status, doc := tc.call(t, "ss-key-1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}}); status < 400 {
		t.Fatalf("create asking for reserved hotel a: %d %v", status, doc)
	}
	if after := createsOn(tc)["a"]; after != before {
		t.Fatalf("reserved hotel a got %d creates from a self-serve guest", after-before)
	}
	// The policy alone: nothing but hotel a, so nothing at all.
	ssEdit(t, tc, func(c *config) { c.SelfServe.Policy = &guestPolicy{Allow: []selector{{Hotel: "a"}}} })
	if status, doc := tc.call(t, "ss-key-1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status < 400 {
		t.Fatalf("create with only reserved hotel a in the policy: %d %v", status, doc)
	}
	if after := createsOn(tc)["a"]; after != before {
		t.Fatalf("reserved hotel a got %d creates from a self-serve guest", after-before)
	}
}

func TestSelfServeSurvivesARestart(t *testing.T) {
	tc := selfServeChain(t, nil)
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 3), 201)
	tc.putSelfServe(t, "acct-revoked01", ssBody("ss-key-r", 1), 201)
	if status, _ := tc.call(t, "operator-key", "DELETE", "/v1/broker/self-serve/acct-revoked01", nil); status != 200 {
		t.Fatal("revoke")
	}
	tc.putAllowance(t, ssID, allowanceBody(1, 3))
	bid := tc.room(t, "ss-key-1", map[string]any{"image": "alpine:3.20"})
	before := tc.listSelfServe(t)
	path := filepath.Join(tc.b.cfg.StateDir, selfServeFile)
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("self-serve file: %v %v", fi, err)
	}
	tc.restart(t) // a new broker from the same state_dir
	after := tc.listSelfServe(t)
	if string(mustMarshal(before)) != string(mustMarshal(after)) {
		t.Fatalf("list before %v, after %v", before, after)
	}
	if status, doc := tc.call(t, "ss-key-1", "GET", "/v1/sandboxes/"+bid, nil); status != 200 {
		t.Fatalf("room after restart: %d %v", status, doc)
	}
	if ssKeyWorks(t, tc, "ss-key-r") {
		t.Fatal("a revoked key works after a restart")
	}
	// Loaded before the allowances: the stored allowance is the guest's.
	if v := tc.getAllowance(t, ssID); v["metered"] != true || v["cap"] != 3.0 || v["issue"] != 1.0 {
		t.Fatalf("allowance after restart %v", v)
	}
	tc.room(t, "ss-key-1", map[string]any{"image": "alpine:3.20"})
}

func TestSelfServeCorruptFileFailsClosed(t *testing.T) {
	tc := selfServeChain(t, nil)
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 3), 201)
	path := filepath.Join(tc.b.cfg.StateDir, selfServeFile)
	if err := os.WriteFile(path, []byte(`{"version": 1, "guests": {"`+ssID+`": {"key_sha256": "`), 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	if ssKeyWorks(t, tc, "ss-key-1") {
		t.Fatal("a key from a corrupt file works")
	}
	if l := tc.listSelfServe(t); len(l) != 0 {
		t.Fatalf("list after a corrupt file: %v", l)
	}
	aside, _ := filepath.Glob(path + ".corrupt-*")
	if len(aside) != 1 {
		t.Fatalf("corrupt file not kept aside: %v", aside)
	}
	if raw, _ := os.ReadFile(aside[0]); !strings.HasPrefix(string(raw), `{"version": 1`) {
		t.Fatalf("aside file %s", raw)
	}
	// The API sends the key again: it works.
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 3), 201)
	if !ssKeyWorks(t, tc, "ss-key-1") {
		t.Fatal("key after a new PUT")
	}
	// A wrong version is refused the same way.
	if err := os.WriteFile(path, []byte(`{"version": 2, "guests": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	if ssKeyWorks(t, tc, "ss-key-1") {
		t.Fatal("a key from a version 2 file works")
	}
}

func TestSelfServeFileGuestWinsAnIDAtStart(t *testing.T) {
	tc := selfServeChain(t, nil)
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 3), 201)
	ssEdit(t, tc, func(c *config) {
		c.Guests = append(c.Guests, guestConfig{ID: ssID, KeySHA256: sha("file-key")})
	})
	if ssKeyWorks(t, tc, "ss-key-1") || !ssKeyWorks(t, tc, "file-key") {
		t.Fatal("the self-serve entry won over the config file guest")
	}
	if g := tc.b.guestByID(ssID); g == nil || g.selfServe {
		t.Fatalf("guest %s: %+v", ssID, g)
	}
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/"+ssID, ssBody("ss-key-2", 1)); status != 409 || errCode(doc) != "guest_exists" {
		t.Fatalf("PUT a skipped id: %d %v", status, doc)
	}
	// The skipped entry stays in the file across other saves.
	tc.putSelfServe(t, "acct-other0001", ssBody("ss-key-3", 1), 201)
	raw, _ := os.ReadFile(filepath.Join(tc.b.cfg.StateDir, selfServeFile))
	if !strings.Contains(string(raw), ssID) || !strings.Contains(string(raw), "acct-other0001") {
		t.Fatalf("file after a save %s", raw)
	}
	if strings.Contains(string(raw), sha("ss-key-1")) {
		t.Fatalf("a skipped entry kept its key hash: %s", raw)
	}
	// The file guest goes: the old self-serve key does not come back.
	ssEdit(t, tc, func(c *config) { c.Guests = c.Guests[:len(c.Guests)-1] })
	if ssKeyWorks(t, tc, "ss-key-1") {
		t.Fatal("a skipped entry's key came back")
	}
	if g := tc.b.guestByID(ssID); g == nil || !g.selfServe {
		t.Fatalf("guest %s after the file guest left: %+v", ssID, g)
	}
	tc.putSelfServe(t, ssID, ssBody("ss-key-4", 1), 200)
	if !ssKeyWorks(t, tc, "ss-key-4") {
		t.Fatal("re-key after the file guest left")
	}
}

// At start an entry whose key hash is already taken (a config file guest's,
// or an earlier self-serve entry's) is revoked, and the file says so.
func TestSelfServeDuplicateKeyIsRevokedAtStart(t *testing.T) {
	tc := selfServeChain(t, nil)
	path := filepath.Join(tc.b.cfg.StateDir, selfServeFile)
	doc := selfServeFileDoc{Version: 1, Guests: map[string]selfServeEntry{
		"acct-dup000a": {KeySHA256: sha("dup"), MaxRooms: 1},
		"acct-dup000b": {KeySHA256: strings.ToUpper(sha("dup")), MaxRooms: 1},
		"acct-file001": {KeySHA256: sha("key1"), MaxRooms: 1},
		"acct-good001": {KeySHA256: sha("good"), MaxRooms: 1},
	}}
	raw, _ := json.Marshal(doc)
	if err := os.MkdirAll(tc.b.cfg.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	if g := tc.b.guestFromKey(keyedRequest("dup")); g == nil || g.cfg.ID != "acct-dup000a" {
		t.Fatalf("dup key reaches %+v, want acct-dup000a (loaded first)", g)
	}
	if g := tc.b.guestFromKey(keyedRequest("key1")); g == nil || g.cfg.ID != "g1" {
		t.Fatalf("key1 reaches %+v, want the config file guest g1", g)
	}
	if !ssKeyWorks(t, tc, "good") {
		t.Fatal("an entry with its own key was revoked")
	}
	revoked := map[string]bool{}
	for _, e := range tc.listSelfServe(t) {
		m := e.(map[string]any)
		revoked[m["id"].(string)] = m["revoked"].(bool)
	}
	if !revoked["acct-dup000b"] || !revoked["acct-file001"] || revoked["acct-dup000a"] || revoked["acct-good001"] {
		t.Fatalf("revoked %v", revoked)
	}
	var f selfServeFileDoc
	raw, _ = os.ReadFile(path)
	if err := json.Unmarshal(raw, &f); err != nil || f.Guests["acct-dup000b"].KeySHA256 != "" || f.Guests["acct-file001"].KeySHA256 != "" || f.Guests["acct-dup000a"].KeySHA256 != sha("dup") {
		t.Fatalf("file after start %s", raw)
	}
}

// A DELETE whose write fails answers 500; a retry writes again, so its 200
// means a restart keeps the revoke.
func TestSelfServeRevokeRetryIsDurable(t *testing.T) {
	tc := selfServeChain(t, nil)
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 1), 201)
	tmp := filepath.Join(tc.b.cfg.StateDir, selfServeFile+".tmp")
	if err := os.Mkdir(tmp, 0o700); err != nil { // the temporary file cannot be opened
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/self-serve/"+ssID, nil); status != 500 || errCode(doc) != "state_write_failed" {
			t.Fatalf("DELETE %d while the write fails: %d %v", i, status, doc)
		}
		if ssKeyWorks(t, tc, "ss-key-1") {
			t.Fatal("the key works after a failed revoke")
		}
	}
	if err := os.Remove(tmp); err != nil {
		t.Fatal(err)
	}
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/self-serve/"+ssID, nil); status != 200 || doc["revoked"] != true {
		t.Fatalf("DELETE after the repair: %d %v", status, doc)
	}
	tc.restart(t)
	if ssKeyWorks(t, tc, "ss-key-1") {
		t.Fatal("the revoked key works after a restart")
	}
}

func reloadChain(t *testing.T, tc *testChain, fn func(*config)) (int, map[string]any) {
	t.Helper()
	raw, _ := os.ReadFile(tc.cfgPath)
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	fn(&c)
	out, _ := json.Marshal(c)
	if err := os.WriteFile(tc.cfgPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return tc.call(t, "operator-key", "POST", "/v1/broker/config/reload", map[string]string{"sha256": sha(string(out))})
}

func TestSelfServeKeysSurviveAReload(t *testing.T) {
	tc := selfServeChain(t, nil)
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 3), 201)
	g := tc.b.guestByID(ssID)
	if status, doc := reloadChain(t, tc, func(c *config) {
		c.Guests = append(c.Guests, guestConfig{ID: "g3", KeySHA256: sha("key3")})
	}); status != 200 {
		t.Fatalf("reload: %d %v", status, doc)
	}
	if !ssKeyWorks(t, tc, "ss-key-1") || !ssKeyWorks(t, tc, "key3") || tc.b.guestByID(ssID) != g {
		t.Fatal("a reload dropped the self-serve key or replaced its guest")
	}
	// A file guest with a self-serve id, or a self-serve key, is refused.
	if status, doc := reloadChain(t, tc, func(c *config) {
		c.Guests = append(c.Guests, guestConfig{ID: ssID, KeySHA256: sha("file-key")})
	}); status != 409 || errCode(doc) != "guest_exists" {
		t.Fatalf("reload with a self-serve id: %d %v", status, doc)
	}
	if status, doc := reloadChain(t, tc, func(c *config) {
		c.Guests = c.Guests[:len(c.Guests)-1]
		c.Guests = append(c.Guests, guestConfig{ID: "g4", KeySHA256: sha("ss-key-1")})
	}); status != 409 || errCode(doc) != "key_in_use" {
		t.Fatalf("reload with a self-serve key: %d %v", status, doc)
	}
	if !ssKeyWorks(t, tc, "ss-key-1") || tc.b.guestByID(ssID) != g || tc.b.guestByID("g4") != nil {
		t.Fatal("a refused reload changed something")
	}
	// A rotation after a reload is kept by the next reload.
	tc.putSelfServe(t, ssID, ssBody("ss-key-2", 3), 200)
	if status, doc := reloadChain(t, tc, func(c *config) { c.Guests = c.Guests[:len(c.Guests)-1] }); status != 200 {
		t.Fatalf("reload: %d %v", status, doc)
	}
	if ssKeyWorks(t, tc, "ss-key-1") || !ssKeyWorks(t, tc, "ss-key-2") {
		t.Fatal("a reload brought back a rotated key or dropped the new one")
	}
}

// PUTs and reloads at once: none loses another's keys (run with -race).
func TestSelfServePutsAndReloadsKeepEveryKey(t *testing.T) {
	tc := selfServeChain(t, nil)
	raw, _ := os.ReadFile(tc.cfgPath)
	sum := sha(string(raw))
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("acct-race%04d", i)
			if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/self-serve/"+id, ssBody(id, 1)); status != 201 {
				t.Errorf("PUT %s: %d %v", id, status, doc)
			}
		}(i)
		go func() {
			defer wg.Done()
			if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/config/reload", map[string]string{"sha256": sum}); status != 200 {
				t.Errorf("reload: %d %v", status, doc)
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 12; i++ {
		id := fmt.Sprintf("acct-race%04d", i)
		if !ssKeyWorks(t, tc, id) {
			t.Fatalf("key of %s lost", id)
		}
	}
	if !ssKeyWorks(t, tc, "key1") || !ssKeyWorks(t, tc, "key2") {
		t.Fatal("file guest keys lost")
	}
}

func TestSelfServeOffAnswers404(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		path := "/v1/broker/self-serve"
		if m != "GET" {
			path += "/" + ssID
		}
		for _, key := range []string{"operator-key", "key1"} {
			if status, doc := tc.call(t, key, m, path, ssBody("ss-key-1", 1)); status != 404 {
				t.Fatalf("%s %s with %s, feature off: %d %v", m, path, key, status, doc)
			}
		}
	}
	if tc.b.guestByID(ssID) != nil {
		t.Fatal("feature off made a guest")
	}
}

func TestSelfServeConfigIsChecked(t *testing.T) {
	pol := &guestPolicy{Allow: []selector{{Class: classSealed}}}
	for _, tt := range []struct {
		ss   selfServeConfig
		dir  string
		want string
	}{
		{selfServeConfig{IDPrefix: "acct-", MaxRoomsCeiling: 50, MaxCreatesPerMinute: 120}, "s", "policy is required"},
		{selfServeConfig{IDPrefix: "acct-", MaxRoomsCeiling: 50, MaxCreatesPerMinute: 120, Policy: &guestPolicy{}}, "s", "at least one prefer or allow"},
		{selfServeConfig{IDPrefix: "", MaxRoomsCeiling: 50, MaxCreatesPerMinute: 120, Policy: pol}, "s", "id_prefix"},
		{selfServeConfig{IDPrefix: "Acct_", MaxRoomsCeiling: 50, MaxCreatesPerMinute: 120, Policy: pol}, "s", "id_prefix"},
		{selfServeConfig{IDPrefix: "acct-", MaxRoomsCeiling: 0, MaxCreatesPerMinute: 120, Policy: pol}, "s", "max_rooms_ceiling"},
		{selfServeConfig{IDPrefix: "acct-", MaxRoomsCeiling: 50, MaxCreatesPerMinute: 0, Policy: pol}, "s", "max_creates_per_minute"},
		{selfServeConfig{IDPrefix: "acct-", MaxRoomsCeiling: 50, MaxCreatesPerMinute: 120, Policy: pol}, "", "needs state_dir"},
	} {
		ss := tt.ss
		err := validateSelfServe(config{StateDir: tt.dir, SelfServe: &ss})
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("%+v: %v, want %q", tt.ss, err, tt.want)
		}
	}
	ss := selfServeConfig{IDPrefix: "acct-", MaxRoomsCeiling: 50, MaxCreatesPerMinute: 120, Policy: pol}
	if err := validateSelfServe(config{StateDir: "s", SelfServe: &ss}); err != nil {
		t.Fatal(err)
	}
}

func TestAllowanceRefusalAnswersItsCode(t *testing.T) {
	tc := selfServeChain(t, nil)
	tc.putSelfServe(t, ssID, ssBody("ss-key-1", 3), 201)
	bad := allowanceBody(1, 0)
	bad["refusal"] = "broke"
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/"+ssID+"/allowance", bad); status != 400 || errCode(doc) != "invalid_allowance" {
		t.Fatalf("bad refusal: %d %v", status, doc)
	}
	// Unset: unchanged.
	tc.putAllowance(t, ssID, allowanceBody(1, 0))
	if status, doc := tc.call(t, "ss-key-1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("cap 0, no refusal: %d %v", status, doc)
	}
	issue := 2
	for code, msg := range allowanceRefusals {
		body := allowanceBody(issue, 0)
		issue++
		body["refusal"] = code
		if v := tc.putAllowance(t, ssID, body); v["refusal"] != code {
			t.Fatalf("view %v", v)
		}
		status, doc := tc.call(t, "ss-key-1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
		if status != 402 || errCode(doc) != code || doc["error"].(map[string]any)["message"] != msg {
			t.Fatalf("cap 0 with refusal %s: %d %v", code, status, doc)
		}
	}
	if allowanceRefusals["insufficient_balance"] != "Your Cathedral balance cannot cover a room. Add credit at https://cathedral.computer/console or with Gamma, then retry." {
		t.Fatal("insufficient_balance message")
	}
	// Stored in the version 1 file, kept across a restart.
	body := allowanceBody(issue, 0)
	body["refusal"] = "insufficient_balance"
	tc.putAllowance(t, ssID, body)
	raw, _ := os.ReadFile(filepath.Join(tc.b.cfg.StateDir, allowancesFile))
	var f allowanceFile
	if err := json.Unmarshal(raw, &f); err != nil || f.Version != 1 || f.Guests[ssID].Refusal != "insufficient_balance" {
		t.Fatalf("allowance file %s", raw)
	}
	tc.restart(t)
	if status, doc := tc.call(t, "ss-key-1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "insufficient_balance" {
		t.Fatalf("after restart: %d %v", status, doc)
	}
	// A lease that expired still answers allowance_lease_expired: the refusal
	// is the cap's reason only.
	tc.ageLease(ssID, 3600e9)
	if status, doc := tc.call(t, "ss-key-1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_lease_expired" {
		t.Fatalf("expired lease with a refusal: %d %v", status, doc)
	}
}

// A refusal answers an extension at the cap too, and a file without the
// field reads as before.
func TestAllowanceRefusalOnExtensionAndOldFiles(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	body := allowanceBody(2, 0)
	body["refusal"] = "key_disabled"
	tc.putAllowance(t, "g1", body)
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/heartbeat", map[string]any{"ttl_seconds": 60}); status != 402 || errCode(doc) != "key_disabled" {
		t.Fatalf("extension at cap 0 with a refusal: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/thaw", nil); status != 402 || errCode(doc) != "key_disabled" {
		t.Fatalf("thaw at cap 0 with a refusal: %d %v", status, doc)
	}
	tc.putAllowance(t, "g1", allowanceBody(3, 0))
	raw, _ := os.ReadFile(filepath.Join(tc.b.cfg.StateDir, allowancesFile))
	if strings.Contains(string(raw), "refusal") {
		t.Fatalf("an unset refusal is written: %s", raw)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/heartbeat", map[string]any{"ttl_seconds": 60}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("extension at cap 0, refusal cleared: %d %v", status, doc)
	}
}
