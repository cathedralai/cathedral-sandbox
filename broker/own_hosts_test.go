package main

import (
	"testing"
	"time"
)

// "own_hosts_only": true keeps a create on Cathedral's own hotels: no miner
// hotel is ever picked, on the first pick or on any failover (a retry after a
// hotel fails the create, a "prefer" fallback, a queue move).

// markMiner makes hotel id a miner hotel: by hotkey (the guest must opt in
// with a policy) or by the miner label alone.
func markMiner(tc *testChain, id string, hotkey bool) {
	setHotel(tc, id, func(h *hotel) {
		h.cfgMu.Lock()
		defer h.cfgMu.Unlock()
		labels := map[string]string{}
		for k, v := range h.cfg.Labels {
			labels[k] = v
		}
		labels["miner"] = "true"
		if hotkey {
			h.cfg.MinerHotkey = minerHotkey
			labels["miner_hotkey"] = minerHotkey
		}
		h.cfg.Labels = labels
	})
}

// optIntoMiners gives guest g1 a policy that prefers miner hotels, so only
// the flag keeps a create off them.
func optIntoMiners(t *testing.T, tc *testChain) {
	t.Helper()
	status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"policy": map[string]any{
		"prefer": []any{map[string]any{"label": map[string]any{"miner": "true"}}},
		"allow":  []any{map[string]any{"class": "unsealed"}, map[string]any{"class": "sealed"}},
	}})
	if status != 200 {
		t.Fatalf("set policy: %d %v", status, doc)
	}
}

func ownCreate(extra map[string]any) map[string]any {
	body := map[string]any{"image": "alpine:3.20", "own_hosts_only": true}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func TestOwnHostsOnlyNeverPicksAMinerHotel(t *testing.T) {
	tc := newChain(t)
	markMiner(tc, "b", true)
	markMiner(tc, "c", false)
	optIntoMiners(t, tc)
	// Control: without the flag the policy sends creates to the miners.
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 10})
	if status != 202 {
		t.Fatalf("control create: %d %v", status, doc)
	}
	if on := createsOn(tc); on["b"]+on["c"] == 0 {
		t.Fatalf("control: no create reached a miner hotel %v; the test proves nothing", on)
	}
	before := createsOn(tc)
	for i := 0; i < 10; i++ {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", ownCreate(nil))
		if status != 202 || doc["hotel"] != "a" {
			t.Fatalf("own_hosts_only create %d: %d hotel=%v %v", i, status, doc["hotel"], doc)
		}
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", ownCreate(map[string]any{"count": 10}))
	if status != 202 || doc["count"].(float64) != 10 {
		t.Fatalf("own_hosts_only batch: %d %v", status, doc)
	}
	after := createsOn(tc)
	if after["b"] != before["b"] || after["c"] != before["c"] || after["a"]-before["a"] != 20 {
		t.Fatalf("own_hosts_only reached a miner hotel: before %v after %v", before, after)
	}
}

func TestOwnHostsOnlyIsNotSentToTheHotel(t *testing.T) {
	tc := newChain(t)
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", ownCreate(map[string]any{"hotels": []string{"b"}})); status != 202 {
		t.Fatalf("create: %d %v", status, doc)
	}
	f := tc.hotels["b"]
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.creates) != 1 {
		t.Fatalf("want one create at b, got %d", len(f.creates))
	}
	if _, ok := f.creates[0]["own_hosts_only"]; ok {
		t.Fatalf("the hotel got the broker field own_hosts_only: %v", f.creates[0])
	}
}

func TestOwnHostsOnlyWithOnlyMinerHotelsMatchesNone(t *testing.T) {
	tc := newChain(t)
	markMiner(tc, "b", false)
	markMiner(tc, "c", false)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", ownCreate(map[string]any{"hotels": []string{"b", "c"}}))
	if status != 409 || errCode(doc) != "no_matching_hotel" {
		t.Fatalf("only miner hotels named: %d %v", status, doc)
	}
}

func TestOwnHostsOnlyMustBeABool(t *testing.T) {
	tc := newChain(t)
	for _, v := range []any{"yes", 1, map[string]any{}} {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "own_hosts_only": v})
		if status != 400 || errCode(doc) != "invalid_hotel_selection" {
			t.Fatalf("own_hosts_only %v: %d %v", v, status, doc)
		}
	}
	// false and null are the default: any hotel.
	for _, v := range []any{false, nil} {
		if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "own_hosts_only": v}); status != 202 {
			t.Fatalf("own_hosts_only %v: %d %v", v, status, doc)
		}
	}
}

// Failover 1: the named own hotel is down and "prefer" would fall back to a
// hotel of the same class. The only one is a miner hotel, so there is no
// fallback.
func TestOwnHostsOnlyPreferFallbackSkipsMinerHotels(t *testing.T) {
	tc := newChain(t)
	markMiner(tc, "c", false)
	downHotel(tc, "b")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "placement": "prefer"})
	if status != 202 || doc["hotel"] != "c" {
		t.Fatalf("control: prefer without the flag should fall back to c: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", ownCreate(map[string]any{"hotels": []string{"b"}, "placement": "prefer"}))
	if status != 503 || errCode(doc) != "hotels_unavailable" {
		t.Fatalf("own_hosts_only prefer fell back: %d %v", status, doc)
	}
	if n := createsOn(tc)["c"]; n != 1 {
		t.Fatalf("miner hotel c got %d creates, want only the control's 1", n)
	}
}

// Failover 2: the own hotel fails the create (registry outage). The retry may
// go to any other eligible hotel; the only free one is a miner hotel.
func TestOwnHostsOnlyRetryAfterAHotelFailureSkipsMinerHotels(t *testing.T) {
	tc := newChain(t)
	markMiner(tc, "c", false)
	downHotel(tc, "a")
	tc.hotels["b"].pullOutage = true
	// Control: without the flag the retry lands on the miner hotel c.
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}})
	if status != 202 || doc["hotel"] != "c" {
		t.Fatalf("control: retry without the flag should land on c: %d %v", status, doc)
	}
	tc.hotels["c"].mu.Lock()
	tc.hotels["c"].creates = nil
	tc.hotels["c"].mu.Unlock()
	setHotel(tc, "b", func(h *hotel) { h.backoffUntil = time.Time{} }) // the outage rested b; let it take the next create
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", ownCreate(map[string]any{"hotels": []string{"b", "c"}}))
	if status != 502 {
		t.Fatalf("own hotel failed, only a miner left: %d %v", status, doc)
	}
	if n := createsOn(tc)["c"]; n != 0 {
		t.Fatalf("retry reached the miner hotel c (%d creates)", n)
	}
}

// Failover 3: a create queued on a slow own hotel past max_queue_wait moves
// only to another own hotel, never to a free miner hotel.
func TestOwnHostsOnlyQueueMoveSkipsMinerHotels(t *testing.T) {
	tc := newChain(t)
	tc.b.cfg.MaxQueueWaitSeconds = 0.2
	markMiner(tc, "c", false)
	downHotel(tc, "a")
	tc.hotels["b"].createDelay = 400 * time.Millisecond
	setHotel(tc, "b", func(h *hotel) { h.sem = make(chan struct{}, 1) })
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", ownCreate(map[string]any{"count": 3}))
	if status != 202 || doc["count"].(float64) != 3 {
		t.Fatalf("queued own_hosts_only creates: %d %v", status, doc)
	}
	on := createsOn(tc)
	if on["c"] != 0 || on["b"] != 3 {
		t.Fatalf("a queued own_hosts_only create moved to the miner hotel: %v", on)
	}
}

// Every miner marker counts: hotkey, miner label, and the miner- id prefix
// of a miner join.
func TestOwnHostsOnlyExcludesEveryMinerMarker(t *testing.T) {
	own := placement{ownHostsOnly: true}
	optIn := &guestPolicy{Prefer: []selector{{Label: map[string]string{"miner": "true"}}}}
	cases := map[string]*hotel{
		"hotkey": {cfg: hotelConfig{ID: "m1", MinerHotkey: minerHotkey, Labels: map[string]string{"miner": "true"}}},
		"label":  {cfg: hotelConfig{ID: "m2", Labels: map[string]string{"miner": "true"}}},
		"prefix": {cfg: hotelConfig{ID: "miner-0a1b"}},
	}
	for name, h := range cases {
		if own.selects(h) {
			t.Fatalf("%s miner hotel selected with own_hosts_only", name)
		}
		withPolicy := placement{ownHostsOnly: true, policy: optIn}
		if withPolicy.selects(h) {
			t.Fatalf("%s miner hotel selected with own_hosts_only and a miner opt-in policy", name)
		}
	}
	if !own.selects(&hotel{cfg: hotelConfig{ID: "seed-1"}}) {
		t.Fatalf("an own hotel was not selected with own_hosts_only")
	}
}
