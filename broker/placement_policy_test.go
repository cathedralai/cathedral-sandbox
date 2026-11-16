package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Placement policy (AB#336): reserved customers stay on Cathedral's own
// hotels; the shared pool uses graduated miner hotels first and falls back to
// the own fleet.
//
// Test chain: a is an own sealed hotel, b and c are own unsealed hotels.
// m1 and m2 are joined, attested sealed miner hotels (hotkey, guest TLS).

// guestPatch sets guest g1's limits through the operator route.
func guestPatch(t *testing.T, tc *testChain, body map[string]any) map[string]any {
	t.Helper()
	status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", body)
	if status != 200 {
		t.Fatalf("patch guest %v: %d %v", body, status, doc)
	}
	return doc
}

// graduate adds graduated=true to a miner hotel's labels (the operator does
// this when the miner leaves probation, AB#334).
func graduate(tc *testChain, id string) {
	setHotel(tc, id, func(h *hotel) {
		h.cfgMu.Lock()
		defer h.cfgMu.Unlock()
		labels := map[string]string{}
		for k, v := range h.cfg.Labels {
			labels[k] = v
		}
		labels["graduated"] = "true"
		h.cfg.Labels = labels
	})
}

// joinMiner joins an attested sealed miner hotel the way the founding-miner
// path does (operator join with miner_hotkey, guest TLS pinned by the
// attestation), with slots rooms and optional extra labels, and admits it.
func joinGradMiner(t *testing.T, tc *testChain, id string, slots int, labels map[string]string, chip byte) *minerHotel {
	t.Helper()
	m, url := newMinerHotel(t, slots, snpAttestation(t, attestOpts{chip: chip}))
	tc.hotels[id] = m.fakeHotel
	body := map[string]any{"id": id, "api": url, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey, "max_slots": slots}
	if labels != nil {
		body["labels"] = labels
	}
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", body); status != 201 {
		t.Fatalf("join %s: %d %v", id, status, doc)
	}
	syncNow(tc, id)
	if a := admissionOf(t, tc, id); a["state"] != "admitted" {
		t.Fatalf("%s admission: %v", id, a)
	}
	return m
}

// sharedPoolPolicy is the shared pool's policy: graduated miner hotels first,
// then any own hotel. A miner hotel in probation has no graduated label, so
// no selector opts into it.
var sharedPoolPolicy = map[string]any{
	"prefer": []any{map[string]any{"label": map[string]any{"miner": "true", "graduated": "true"}}},
	"allow":  []any{map[string]any{"class": "sealed"}, map[string]any{"class": "unsealed"}},
}

// A reserved customer (const) with own_hosts_only never lands on a miner
// hotel, even with a policy that prefers miner hotels and with a graduated
// miner and a label-only miner hotel free.
func TestReservedGuestNeverPlacesOnAMinerHotel(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinGradMiner(t, tc, "m1", 50, map[string]string{"graduated": "true"}, 1)
	markMiner(tc, "c", false)
	optIntoMiners(t, tc)
	// Control: the same guest without the limit goes to the miners.
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 10})
	if status != 202 {
		t.Fatalf("control: %d %v", status, doc)
	}
	if on := createsOn(tc); on["m1"] == 0 {
		t.Fatalf("control reached no hotkey miner %v; the test proves nothing", on)
	}
	if v := guestPatch(t, tc, map[string]any{"own_hosts_only": true}); v["own_hosts_only"] != true {
		t.Fatalf("guest view: %v", v)
	}
	before := createsOn(tc)
	for i := 0; i < 5; i++ {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
		if status != 202 || (doc["hotel"] != "a" && doc["hotel"] != "b") {
			t.Fatalf("create %d: %d hotel=%v %v", i, status, doc["hotel"], doc)
		}
	}
	// A create that sends own_hosts_only false cannot turn the guest limit off.
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 5, "own_hosts_only": false})
	if status != 202 || doc["count"].(float64) != 5 {
		t.Fatalf("batch: %d %v", status, doc)
	}
	after := createsOn(tc)
	if after["m1"] != before["m1"] || after["c"] != before["c"] || (after["a"]+after["b"])-(before["a"]+before["b"]) != 10 {
		t.Fatalf("reserved guest reached a miner hotel: before %v after %v", before, after)
	}
	// Naming the miner hotels matches nothing.
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"m1", "c"}})
	if status != 409 {
		t.Fatalf("named miner hotels: %d %v", status, doc)
	}
	// The guest catalog does not list miner hotels either.
	status, doc = tc.call(t, "key1", "GET", "/v1/broker/capacity", nil)
	if status != 200 {
		t.Fatalf("capacity: %d %v", status, doc)
	}
	for _, e := range doc["hotels"].([]any) {
		if id := e.(map[string]any)["id"]; id == "m1" || id == "c" {
			t.Fatalf("guest catalog lists miner hotel %v: %v", id, doc["hotels"])
		}
	}
}

// With every own hotel down, a reserved guest gets the no-room answer, not a
// miner hotel.
func TestReservedGuestWithOwnFleetDownGetsNoMinerHotel(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinGradMiner(t, tc, "m1", 50, map[string]string{"graduated": "true"}, 1)
	markMiner(tc, "c", false)
	optIntoMiners(t, tc)
	guestPatch(t, tc, map[string]any{"own_hosts_only": true})
	downHotel(tc, "a")
	downHotel(tc, "b")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status < 400 {
		t.Fatalf("own fleet down: %d %v", status, doc)
	}
	if on := createsOn(tc); on["m1"]+on["c"] != 0 {
		t.Fatalf("reserved guest reached a miner hotel: %v", on)
	}
}

// The shared pool takes graduated miner hotels first, never a miner in
// probation, and falls back to the own fleet when the graduated miners are
// full or down.
func TestSharedPoolUsesGraduatedMinersThenOwnFleet(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinGradMiner(t, tc, "m1", 3, map[string]string{"graduated": "true"}, 1)
	joinGradMiner(t, tc, "m2", 50, nil, 2) // probation: no graduated label
	guestPatch(t, tc, map[string]any{"policy": sharedPoolPolicy})

	for i := 0; i < 3; i++ {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
		if status != 202 || doc["hotel"] != "m1" || doc["placement_tier"] != tierPrefer {
			t.Fatalf("create %d: want graduated m1 in the prefer tier: %d %v", i, status, doc)
		}
	}

	// Graduated miner full (3 slots): the own fleet takes the rest, the
	// probation miner still takes none.
	for i := 0; i < 4; i++ {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
		if status != 202 || doc["placement_tier"] != tierAllow {
			t.Fatalf("fallback create %d: %d %v", i, status, doc)
		}
		if h := doc["hotel"]; h != "a" && h != "b" && h != "c" {
			t.Fatalf("fallback create %d went to %v", i, h)
		}
	}
	if on := createsOn(tc); on["m1"] != 3 || on["m2"] != 0 || on["a"]+on["b"]+on["c"] != 4 {
		t.Fatalf("graduated full: %v", on)
	}

	// Graduated miner down (with room): same fallback.
	setHotel(tc, "m1", func(h *hotel) { h.slots = 50 })
	downHotel(tc, "m1")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 2})
	if status != 202 {
		t.Fatalf("down create: %d %v", status, doc)
	}
	if on := createsOn(tc); on["m1"] != 3 || on["m2"] != 0 || on["a"]+on["b"]+on["c"] != 6 {
		t.Fatalf("graduated down: %v", on)
	}

	// A probation miner is out of reach even when named.
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"m2"}})
	if status < 400 || createsOn(tc)["m2"] != 0 {
		t.Fatalf("named probation miner: %d %v", status, doc)
	}

	// Once it graduates, it takes shared-pool rooms in the prefer tier.
	graduate(tc, "m2")
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status != 202 || doc["hotel"] != "m2" || doc["placement_tier"] != tierPrefer {
		t.Fatalf("graduated m2: %d %v", status, doc)
	}
}

func TestOwnHostsOnlyGuestPatchAndConfig(t *testing.T) {
	tc := newChain(t)
	for _, v := range []any{"yes", 1} {
		status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"own_hosts_only": v})
		if status != 400 {
			t.Fatalf("own_hosts_only %v: %d %v", v, status, doc)
		}
	}
	if v := guestPatch(t, tc, map[string]any{"own_hosts_only": true}); v["own_hosts_only"] != true {
		t.Fatalf("set: %v", v)
	}
	if v := guestPatch(t, tc, map[string]any{"max_rooms": 5}); v["own_hosts_only"] != true {
		t.Fatalf("another PATCH cleared it: %v", v)
	}
	if v := guestPatch(t, tc, map[string]any{"own_hosts_only": false}); v["own_hosts_only"] != false {
		t.Fatalf("clear: %v", v)
	}
	// The config file field decodes into the guest limits.
	var gc guestConfig
	if err := decodeStrict(`{"id":"const","key_sha256":"x","own_hosts_only":true}`, &gc); err != nil || !gc.OwnHostsOnly {
		t.Fatalf("config: %v %+v", err, gc)
	}
}

func decodeStrict(s string, v any) error {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
