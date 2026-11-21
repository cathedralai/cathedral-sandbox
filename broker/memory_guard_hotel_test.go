package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// AB#855: a hotel may carry its own mem_full_pct. A sealed box that holds
// 1,000+ rooms on 16x CPU and 20x RAM overcommit needs a lower memory mark
// than the broker-wide 90, without lowering it for every other hotel.

func TestHotelMemFullPctOverridesTheBrokerWideLimit(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	p80 := 80.0
	setHotel(tc, "a", func(h *hotel) { h.memPct = 85; h.cfg.MemFullPct = &p80 })
	setHotel(tc, "b", func(h *hotel) { h.memPct = 85 })
	on := share(tc, 50)
	if on["a"] != 0 {
		t.Fatalf("hotel a at 85%% with its own limit 80 got %d of 50 picks: %v", on["a"], on)
	}
	if on["b"] != 50 {
		t.Fatalf("hotel b at 85%% under the broker-wide 90 should take every pick: %v", on)
	}

	// The hotel's limit may also be above the broker-wide one.
	p95 := 95.0
	setHotel(tc, "a", func(h *hotel) { h.memPct = 92; h.cfg.MemFullPct = &p95 })
	setHotel(tc, "b", func(h *hotel) { h.memPct = 92 })
	on = share(tc, 50)
	if on["a"] != 50 || on["b"] != 0 {
		t.Fatalf("at 92%%: a (limit 95) should take all, b (broker-wide 90) none: %v", on)
	}

	// The broker-wide -1 (off) does not switch off a hotel's own limit.
	tc.b.cfg.MemFullPct = -1
	setHotel(tc, "a", func(h *hotel) { h.memPct = 96 })
	setHotel(tc, "b", func(h *hotel) { h.memPct = 99 })
	on = share(tc, 50)
	if on["a"] != 0 || on["b"] != 50 {
		t.Fatalf("broker-wide off: a at 96%% over its own 95 must take none, b all: %v", on)
	}
}

func TestPatchSetsAndClearsHotelMemFullPct(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "b", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	setHotel(tc, "a", func(h *hotel) { h.memPct = 85 })
	if on := share(tc, 10); on["a"] != 10 {
		t.Fatalf("85%% under the default 90: %v", on)
	}

	status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"mem_full_pct": 80})
	if status != 200 || doc["mem_full_pct"] != 80.0 || doc["mem_full"] != true {
		t.Fatalf("PATCH mem_full_pct 80: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status != 503 || doc["error"].(map[string]any)["code"] != "hotels_unavailable" || createsOn(tc)["a"] != 0 {
		t.Fatalf("create with the only up hotel over its own limit: %d %v", status, doc)
	}

	status, doc = tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"mem_full_pct": nil})
	if status != 200 || doc["mem_full_pct"] != 90.0 || doc["mem_full"] != false {
		t.Fatalf("PATCH mem_full_pct null back to the broker-wide 90: %d %v", status, doc)
	}
	if on := share(tc, 10); on["a"] != 10 {
		t.Fatalf("after clearing: %v", on)
	}

	// Other PATCH fields leave the hotel's limit as it is.
	tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"mem_full_pct": 70})
	if status, doc = tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"max_slots": 50}); status != 200 || doc["mem_full_pct"] != 70.0 {
		t.Fatalf("max_slots PATCH changed mem_full_pct: %d %v", status, doc)
	}
}

func TestPatchRefusesBadHotelMemFullPct(t *testing.T) {
	tc := newChain(t)
	for _, bad := range []any{0, -1, 100.5, 101, "80", true} {
		status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"mem_full_pct": bad})
		if status != 400 {
			t.Fatalf("mem_full_pct %v: %d %v", bad, status, doc)
		}
	}
	tc.b.mu.Lock()
	got := tc.b.hotelByID("a").cfg.MemFullPct
	tc.b.mu.Unlock()
	if got != nil {
		t.Fatalf("a refused PATCH changed the hotel: %v", *got)
	}
	// A miner enrollment key may only drain.
	if status, _ := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"drain": true, "mem_full_pct": 80}); status != 403 {
		t.Fatalf("enroller set mem_full_pct: %d", status)
	}
}

func TestConfigHotelMemFullPctIsLoadedAndValidated(t *testing.T) {
	tc := newChain(t)
	raw, _ := os.ReadFile(tc.cfgPath)
	var cfg map[string]any
	_ = json.Unmarshal(raw, &cfg)
	hotels := cfg["hotels"].([]any)
	write := func(v any) {
		hotels[0].(map[string]any)["mem_full_pct"] = v
		out, _ := json.Marshal(cfg)
		if err := os.WriteFile(tc.cfgPath, out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []any{0, 101, -5} {
		write(bad)
		if _, err := loadBroker(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "mem_full_pct") {
			t.Fatalf("config hotel mem_full_pct %v loaded: %v", bad, err)
		}
	}
	write(80)
	b, err := loadBroker(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if h := b.hotelByID("a"); h.cfg.MemFullPct == nil || *h.cfg.MemFullPct != 80 || b.memFullLimit(h) != 80 {
		t.Fatalf("config hotel a mem_full_pct not loaded: %v", h.cfg.MemFullPct)
	}
	if h := b.hotelByID("b"); b.memFullLimit(h) != defaultMemFullPct {
		t.Fatalf("hotel b without its own value: %v", b.memFullLimit(h))
	}
}

func TestRuntimeHotelMemFullPctAtJoinAndPatchSurvivesRestart(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	if status, _ := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "bad", "api": "https://x.invalid", "key": joinKey, "mem_full_pct": 0}); status != 400 {
		t.Fatalf("join with mem_full_pct 0: %d", status)
	}
	joinMiner(t, tc, "m1", true, 4, nil)
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"mem_full_pct": 75}); status != 200 || doc["mem_full_pct"] != 75.0 {
		t.Fatalf("PATCH runtime hotel: %d %v", status, doc)
	}
	tc.start(t) // a runtime hotel's PATCH is saved (hotels.json)
	tc.b.mu.Lock()
	got := tc.b.memFullLimit(tc.b.hotelByID("m1"))
	tc.b.mu.Unlock()
	if got != 75 {
		t.Fatalf("mem_full_pct after restart: %v", got)
	}
}
