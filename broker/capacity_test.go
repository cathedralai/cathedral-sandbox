package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

// Capacity plane slice 1: guest policy (prefer, allow, deny), the tiered
// placer and the capacity catalog. Hotels: "a" sealed (shared), "nc" sealed
// (denied to the policy guest), "b" and "c" unsealed. No network: every
// hotel is a fake in this process.

// polarisSealed is the example policy of the PR: prefer sealed, allow
// unsealed, deny nc, at most 10 rooms.
var polarisSealed = map[string]any{
	"max_rooms": 10,
	"policy": map[string]any{
		"prefer": []any{map[string]any{"class": "sealed"}},
		"allow":  []any{map[string]any{"class": "unsealed"}},
		"deny":   []any{map[string]any{"hotel": "nc"}},
	},
}

// addHotel adds a fake hotel to the chain (as a config hotel would be).
func addFakeHotel(t *testing.T, tc *testChain, id string, sealed bool) {
	t.Helper()
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	tc.hotels[id] = f
	h := newHotel(hotelConfig{ID: id, Name: id, API: hs.URL, Health: hs.URL, Concurrency: 4, Sealed: sealed}, "hotel-key")
	if err := tc.b.addHotel(h); err != nil {
		t.Fatal(err)
	}
	setHotel(tc, id, func(h *hotel) { h.ok, h.slots = true, 100 })
}

// policyChain is a chain with a sealed "a", a sealed "nc" and guest g1 on
// the polaris-sealed policy, set through the operator PATCH.
func policyChain(t *testing.T, stateDir string) *testChain {
	t.Helper()
	tc := newChainState(t, stateDir)
	tc.b.hotelByID("a").cfg.Sealed = true
	addFakeHotel(t, tc, "nc", true)
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", polarisSealed); status != 200 {
		t.Fatalf("set policy: %d %v", status, doc)
	}
	return tc
}

func createdOn(t *testing.T, tc *testChain, body map[string]any) (hotelID, tier, roomID string) {
	t.Helper()
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", body)
	if status != 202 {
		t.Fatalf("create %v: %d %v", body, status, doc)
	}
	h, _ := doc["hotel"].(string)
	tr, _ := doc["placement_tier"].(string)
	return h, tr, doc["id"].(string)
}

func creates(tc *testChain, id string) int {
	f := tc.hotels[id]
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.creates)
}

var plain = map[string]any{"image": "alpine:3.20"}

func TestSealedPreferLandsOnSharedSealedNeverOnDenied(t *testing.T) {
	tc := policyChain(t, "")
	for i := 0; i < 8; i++ {
		h, tier, _ := createdOn(t, tc, plain)
		if h != "a" || tier != "prefer" {
			t.Fatalf("create %d: hotel %s tier %s, want a prefer", i, h, tier)
		}
	}
	if n := creates(tc, "nc"); n != 0 {
		t.Fatalf("denied hotel nc got %d creates", n)
	}
}

func TestPreferFullFallsBackToAllowThenBackToPrefer(t *testing.T) {
	tc := policyChain(t, "")
	setHotel(tc, "a", func(h *hotel) { h.slots = 1 })
	h1, tier1, room1 := createdOn(t, tc, plain)
	if h1 != "a" || tier1 != "prefer" {
		t.Fatalf("first create: %s %s, want a prefer", h1, tier1)
	}
	// Sealed is full: the next create goes to an unsealed hotel, tier allow.
	h2, tier2, _ := createdOn(t, tc, plain)
	if (h2 != "b" && h2 != "c") || tier2 != "allow" {
		t.Fatalf("prefer full: %s %s, want b or c allow", h2, tier2)
	}
	// A sealed create never falls back to unsealed: it waits for sealed.
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "sealed": true}); status != 429 || errCode(doc) != "no_free_rooms" {
		t.Fatalf("sealed create with sealed full: %d %v", status, doc)
	}
	// The sealed room goes away and the sync loop sees it: back to prefer.
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+room1, nil); status != 204 {
		t.Fatalf("delete: %d", status)
	}
	// The sync loop drops a deleted room once the hotel no longer lists it;
	// do that step here without waiting for its grace period.
	setHotel(tc, "a", func(h *hotel) {
		for _, rm := range h.rooms {
			if rm.id == room1 {
				tc.b.release(h, rm)
			}
		}
	})
	tc.b.mu.Lock()
	free := tc.b.freeFor(tc.b.hotelByID("a"))
	tc.b.mu.Unlock()
	if free != 1 {
		t.Fatalf("a free after delete = %d, want 1", free)
	}
	if h3, tier3, _ := createdOn(t, tc, plain); h3 != "a" || tier3 != "prefer" {
		t.Fatalf("slot freed: %s %s, want a prefer", h3, tier3)
	}
}

func TestDenyFenceNeverChoosesADeniedHotel(t *testing.T) {
	tc := policyChain(t, "")
	// nc is the only hotel with a free room.
	setHotel(tc, "a", func(h *hotel) { h.slots = 0 })
	setHotel(tc, "b", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.cfg.Drain = true })
	for _, body := range []map[string]any{
		plain,
		{"image": "alpine:3.20", "sealed": true},
	} {
		if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", body); status == 202 {
			t.Fatalf("create %v placed with only the denied hotel free: %v", body, doc)
		}
	}
	// Naming the denied hotel is refused as an unknown hotel.
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"nc"}, "placement": "prefer"}); status != 409 || errCode(doc) != "unknown_hotel" {
		t.Fatalf("named denied hotel: %d %v", status, doc)
	}
	// Deny wins even over a prefer selector that names the hotel itself.
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"policy": map[string]any{
		"prefer": []any{map[string]any{"hotel": "nc"}, map[string]any{"label": map[string]string{"sealed": "true"}}},
		"deny":   []any{map[string]any{"hotel": "nc"}},
	}}); status != 200 {
		t.Fatalf("patch: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", plain); status == 202 {
		t.Fatalf("deny lost to prefer: %v", doc)
	}
	if n := creates(tc, "nc"); n != 0 {
		t.Fatalf("denied hotel nc got %d creates", n)
	}
}

func TestAutoFreeCapacityUsesEveryHotelOfTheClass(t *testing.T) {
	dir := t.TempDir()
	tc := policyChain(t, dir)
	addFakeHotel(t, tc, "s2", true)
	setHotel(tc, "a", func(h *hotel) { h.slots = 1 })
	setHotel(tc, "s2", func(h *hotel) { h.slots = 1 })
	// Two creates under one guest land on two different sealed hotels.
	h1, t1, _ := createdOn(t, tc, plain)
	h2, t2, _ := createdOn(t, tc, plain)
	if h1 == h2 || t1 != "prefer" || t2 != "prefer" || (h1 != "a" && h1 != "s2") || (h2 != "a" && h2 != "s2") {
		t.Fatalf("two creates: %s/%s and %s/%s, want a and s2, both prefer", h1, t1, h2, t2)
	}
	// A sealed hotel joins at runtime: the guest uses it with no policy edit.
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}, attestation: snpAttestation(t, attestOpts{})}
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	tc.hotels["s3"] = f
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "s3", "api": hs.URL, "key": joinKey, "sealed": true, "verify": false}); status != 201 {
		t.Fatalf("join s3: %d %v", status, doc)
	}
	setHotel(tc, "s3", func(h *hotel) { h.ok, h.slots = true, 10 })
	admitNow(t, tc, "s3") // the sync loop's attestation step (slice 2 admission)
	h3, t3, _ := createdOn(t, tc, plain)
	if h3 != "s3" || t3 != "prefer" {
		t.Fatalf("after join: %s %s, want s3 prefer", h3, t3)
	}
	status, doc := tc.call(t, "key1", "GET", "/v1/broker/capacity", nil)
	if status != 200 || !listed(doc, "s3") {
		t.Fatalf("catalog does not list the joined hotel: %d %v", status, doc)
	}
}

func TestCapHonestyRefusesAtMaxRooms(t *testing.T) {
	tc := policyChain(t, "")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 10})
	if status != 202 || doc["count"] != float64(10) {
		t.Fatalf("10 rooms: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", plain)
	if status != 429 || errCode(doc) != "room_limit" {
		t.Fatalf("room 11: %d %v, want 429 room_limit", status, doc)
	}
	total := 0
	for id := range tc.hotels {
		total += creates(tc, id)
	}
	if total != 10 {
		t.Fatalf("hotels got %d creates, want 10 (no overbook)", total)
	}
}

func listed(doc map[string]any, id string) bool {
	_, ok := catalogEntry(doc, id)
	return ok
}

func catalogEntry(doc map[string]any, id string) (map[string]any, bool) {
	list, _ := doc["hotels"].([]any)
	for _, x := range list {
		if e, _ := x.(map[string]any); e["id"] == id {
			return e, true
		}
	}
	return nil, false
}

func TestCatalogTruth(t *testing.T) {
	tc := policyChain(t, "")
	addFakeHotel(t, tc, "s2", true)
	addFakeHotel(t, tc, "d", false)
	addFakeHotel(t, tc, "m", false)
	// One hotel per reason a free slot is not a free room.
	setHotel(tc, "c", func(h *hotel) { h.ok = false })                                 // down
	setHotel(tc, "s2", func(h *hotel) { h.cfg.Drain = true })                          // draining
	setHotel(tc, "d", func(h *hotel) { h.backoffUntil = time.Now().Add(time.Minute) }) // resting after a failure
	setHotel(tc, "m", func(h *hotel) { h.memPct = 95 })                                // memory full
	setHotel(tc, "a", func(h *hotel) { h.slots = 3 })

	// Operator: every hotel, with the right class.
	status, op := tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	if status != 200 {
		t.Fatalf("operator catalog: %d %v", status, op)
	}
	wantClass := map[string]string{"a": "sealed", "nc": "sealed", "s2": "sealed", "b": "unsealed", "c": "unsealed", "d": "unsealed", "m": "unsealed"}
	for id, class := range wantClass {
		e, ok := catalogEntry(op, id)
		if !ok || e["class"] != class {
			t.Fatalf("operator catalog %s: %v (want class %s)", id, e, class)
		}
	}
	if e, _ := catalogEntry(op, "a"); e["free_rooms"] != float64(3) {
		t.Fatalf("a free_rooms = %v, want 3", e["free_rooms"])
	}

	// Guest: the policy's hotels only, with the tier; nc is hidden.
	status, gv := tc.call(t, "key1", "GET", "/v1/broker/capacity", nil)
	if status != 200 {
		t.Fatalf("guest catalog: %d %v", status, gv)
	}
	if listed(gv, "nc") {
		t.Fatalf("guest catalog shows the denied hotel nc: %v", gv)
	}
	wantTier := map[string]string{"a": "prefer", "s2": "prefer", "b": "allow", "c": "allow", "d": "allow", "m": "allow"}
	for id, tier := range wantTier {
		if e, ok := catalogEntry(gv, id); !ok || e["tier"] != tier {
			t.Fatalf("guest catalog %s: %v (want tier %s)", id, e, tier)
		}
	}
	if first := gv["hotels"].([]any)[0].(map[string]any); first["tier"] != "prefer" {
		t.Fatalf("guest catalog does not list prefer first: %v", first)
	}

	// Free rooms in the catalog are exactly the hotels a create can use.
	for id := range wantTier {
		e, _ := catalogEntry(gv, id)
		free := e["free_rooms"].(float64)
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{id}})
		if free > 0 && (status != 202 || doc["hotel"] != id) {
			t.Fatalf("catalog says %s has %v free, create got %d %v", id, free, status, doc)
		}
		if free == 0 && status == 202 {
			t.Fatalf("catalog says %s has no free room, create placed %v", id, doc)
		}
	}

	// The operator key is required for the full view; another guest sees
	// only what its own (absent) policy reaches.
	status, g2 := tc.call(t, "key2", "GET", "/v1/broker/capacity", nil)
	if e, _ := catalogEntry(g2, "a"); status != 200 || e["tier"] != "hotels" {
		t.Fatalf("g2 catalog: %d %v", status, g2)
	}
}

func TestNoPolicyGuestBehavesAsBefore(t *testing.T) {
	// const: a guest with only a hotel list. No policy, no tier, same hotels.
	tc := limitedChain(t, guestLimits{Hotels: []string{"b"}})
	for i := 0; i < 5; i++ {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", plain)
		if status != 202 || doc["hotel"] != "b" {
			t.Fatalf("create %d: %d %v", i, status, doc)
		}
		if _, ok := doc["placement_tier"]; ok {
			t.Fatalf("no-policy create has placement_tier: %v", doc)
		}
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}}); status != 409 || errCode(doc) != "unknown_hotel" {
		t.Fatalf("hotel outside the list: %d %v", status, doc)
	}
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/guests", nil)
	if status != 200 {
		t.Fatalf("guests: %d", status)
	}
	for _, x := range doc["guests"].([]any) {
		g := x.(map[string]any)
		if g["id"] == "g1" && g["policy"] != nil {
			t.Fatalf("g1 has a policy: %v", g)
		}
	}
	status, cat := tc.call(t, "key1", "GET", "/v1/broker/capacity", nil)
	if status != 200 || len(cat["hotels"].([]any)) != 1 || !listed(cat, "b") {
		t.Fatalf("no-policy catalog: %d %v", status, cat)
	}
}

func TestPolicyPatchValidatesAndClears(t *testing.T) {
	tc := policyChain(t, "")
	for _, bad := range []map[string]any{
		{"policy": map[string]any{"prefer": []any{map[string]any{"class": "gold"}}}},
		{"policy": map[string]any{"prefer": []any{map[string]any{"class": "sealed", "hotel": "a"}}}},
		{"policy": map[string]any{"deny": []any{map[string]any{"hotel": "nc"}}}},
		{"policy": map[string]any{"prefer": []any{map[string]any{"zone": "x"}}}},
	} {
		if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", bad); status != 400 || errCode(doc) != "invalid_policy" {
			t.Fatalf("bad policy %v: %d %v", bad, status, doc)
		}
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"policy": nil}); status != 200 || doc["policy"] != nil {
		t.Fatalf("clear: %d %v", status, doc)
	}
	// Without the policy, g1 is back to the old rules: a plain create never
	// goes to a sealed hotel.
	if h, tier, _ := createdOn(t, tc, plain); h == "a" || h == "nc" || tier != "" {
		t.Fatalf("after clear: %s %s", h, tier)
	}
}

func TestUnsealedCreateUnderPolicyGoesToAllow(t *testing.T) {
	tc := policyChain(t, "")
	h, tier, _ := createdOn(t, tc, map[string]any{"image": "alpine:3.20", "sealed": false})
	if (h != "b" && h != "c") || tier != "allow" {
		t.Fatalf("sealed=false: %s %s, want b or c allow", h, tier)
	}
}

// Hotel reservation: a hotel dedicated to one guest (const on nc-sealed
// today) is out of every other guest's reach until the operator releases it.

func reserve(t *testing.T, tc *testChain, hotelID string, owner any) {
	t.Helper()
	status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/"+hotelID, map[string]any{"reserved_for": owner})
	if status != 200 || doc["reserved_for"] != owner {
		t.Fatalf("reserve %s for %v: %d %v", hotelID, owner, status, doc)
	}
}

// reservedChain: g1 on the polaris-sealed policy with no deny, g2 the owner
// of sealed hotel "nc" through a hotel list (the const shape).
func reservedChain(t *testing.T) *testChain {
	t.Helper()
	tc := newChain(t)
	tc.b.hotelByID("a").cfg.Sealed = true
	addFakeHotel(t, tc, "nc", true)
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"policy": map[string]any{
		"prefer": []any{map[string]any{"class": "sealed"}},
		"allow":  []any{map[string]any{"class": "unsealed"}},
	}}); status != 200 {
		t.Fatalf("policy: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g2", map[string]any{"hotels": []string{"nc"}}); status != 200 {
		t.Fatalf("g2 list: %d %v", status, doc)
	}
	reserve(t, tc, "nc", "g2")
	return tc
}

func ownerCreate(t *testing.T, tc *testChain) string {
	t.Helper()
	status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "sealed": true})
	if status != 202 {
		t.Fatalf("owner create: %d %v", status, doc)
	}
	return doc["hotel"].(string)
}

func TestReservedHotelNeverChosenForAnotherGuest(t *testing.T) {
	tc := reservedChain(t)
	// nc is the only hotel with a free room.
	setHotel(tc, "a", func(h *hotel) { h.slots = 0 })
	setHotel(tc, "b", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	for _, body := range []map[string]any{plain, {"image": "alpine:3.20", "sealed": true}} {
		if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", body); status == 202 {
			t.Fatalf("g1 placed on a hotel reserved for g2: %v", doc)
		}
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"nc"}}); status != 409 || errCode(doc) != "unknown_hotel" {
		t.Fatalf("g1 named the reserved hotel: %d %v", status, doc)
	}
	if n := creates(tc, "nc"); n != 0 {
		t.Fatalf("reserved hotel got %d creates from another guest", n)
	}
	// Hidden from g1's catalog, shown to the owner and the operator.
	if _, cat := tc.call(t, "key1", "GET", "/v1/broker/capacity", nil); listed(cat, "nc") {
		t.Fatalf("g1 catalog shows the reserved hotel: %v", cat)
	}
	if _, cat := tc.call(t, "key2", "GET", "/v1/broker/capacity", nil); !listed(cat, "nc") {
		t.Fatalf("owner catalog hides its hotel: %v", cat)
	}
	if _, cat := tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil); func() bool { e, _ := catalogEntry(cat, "nc"); return e["reserved_for"] != "g2" }() {
		t.Fatalf("operator catalog: %v", cat)
	}
	// The owner still uses it.
	if h := ownerCreate(t, tc); h != "nc" {
		t.Fatalf("owner create on %s, want nc", h)
	}
}

func TestReleasedHotelJoinsThePool(t *testing.T) {
	tc := reservedChain(t)
	setHotel(tc, "a", func(h *hotel) { h.slots = 0 })
	if h := ownerCreate(t, tc); h != "nc" {
		t.Fatalf("owner before release: %s", h)
	}
	if h, tier, _ := createdOn(t, tc, plain); h == "nc" || tier != "allow" {
		t.Fatalf("g1 before release: %s %s, want an unsealed allow hotel", h, tier)
	}
	reserve(t, tc, "nc", nil) // release: no guest config edit
	if h, tier, _ := createdOn(t, tc, plain); h != "nc" || tier != "prefer" {
		t.Fatalf("g1 after release: %s %s, want nc prefer", h, tier)
	}
	if _, cat := tc.call(t, "key1", "GET", "/v1/broker/capacity", nil); !listed(cat, "nc") {
		t.Fatalf("released hotel missing from g1 catalog: %v", cat)
	}
	if h := ownerCreate(t, tc); h != "nc" {
		t.Fatalf("owner after release: %s", h)
	}
	// An explicit guest deny still fences a released hotel.
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", polarisSealed); status != 200 {
		t.Fatalf("deny: %d %v", status, doc)
	}
	if h, _, _ := createdOn(t, tc, plain); h == "nc" {
		t.Fatalf("deny lost to a released hotel")
	}
}

func TestReservedForValidation(t *testing.T) {
	tc := newChain(t)
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"reserved_for": "nobody"}); status != 409 || errCode(doc) != "unknown_guest" {
		t.Fatalf("unknown guest: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"reserved_for": 7}); status != 400 {
		t.Fatalf("bad type: %d %v", status, doc)
	}
	if status, _ := tc.call(t, "key1", "PATCH", "/v1/broker/hotels/a", map[string]any{"reserved_for": "g1"}); status != 401 {
		t.Fatalf("guest key reserved a hotel: %d", status)
	}
}
