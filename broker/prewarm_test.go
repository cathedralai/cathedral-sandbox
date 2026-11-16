package main

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// AB#532: a hotel that holds a catalog image is preferred for a create of that
// image, and a cold hotel still takes the create when no warm hotel has room.

const warmImage = "alpine:3.20" // room-1x4 catalog image

func warmUp(tc *testChain, on bool, warm ...string) {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	tc.b.cfg.PrewarmCatalog = on
	tc.b.hotelByID("a").ok = false // sealed hotel: keep the fixture to b and c
	// Measured create times would pin every create to the first hotel used.
	for _, id := range []string{"b", "c"} {
		tc.b.hotelByID(id).createEWMA = 1
	}
	for _, id := range warm {
		h := tc.b.hotelByID(id)
		h.warm = map[string]bool{warmImage: true}
	}
}

func warmCreates(t *testing.T, tc *testChain, n int) map[string]int {
	t.Helper()
	got := map[string]int{}
	for i := 0; i < n; i++ {
		setHotel(tc, "b", func(h *hotel) { h.createEWMA = 1 })
		setHotel(tc, "c", func(h *hotel) { h.createEWMA = 1 })
		h, _, _ := createdOn(t, tc, map[string]any{"template": "room-1x4"})
		got[h]++
	}
	return got
}

func TestWarmHotelIsPreferredForACatalogImage(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, true, "b")
	if got := warmCreates(t, tc, 30); got["b"] != 30 {
		t.Fatalf("want all 30 on warm hotel b, got %v", got)
	}
}

func TestColdHotelStillTakesTheCreateWhenTheWarmOneIsFull(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, true, "b")
	setHotel(tc, "b", func(h *hotel) { h.slots = 0 })
	got := warmCreates(t, tc, 5)
	if got["b"] != 0 || got["c"] != 5 {
		t.Fatalf("want all 5 on cold hotel c, got %v", got)
	}
}

func TestWarmIsIgnoredWhenTheFlagIsOff(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, false, "b")
	if got := warmCreates(t, tc, 40); got["c"] == 0 {
		t.Fatalf("flag off: want creates on both hotels, got %v", got)
	}
}

func TestNoWarmHotelKeepsTheSpread(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, true)
	if got := warmCreates(t, tc, 40); got["b"] == 0 || got["c"] == 0 {
		t.Fatalf("no warm hotel: want creates on both, got %v", got)
	}
}

func TestPrewarmMarksCatalogImagesWarmAndDownClearsThem(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, true)
	h := tc.b.hotelByID("b")
	tc.b.prewarmHotel(h)
	tc.b.mu.Lock()
	warm := h.warm[warmImage]
	tc.b.mu.Unlock()
	if !warm {
		t.Fatal("alpine:3.20 not warm after prewarm")
	}
	if n := len(tc.hotels["b"].prefetch); n == 0 {
		t.Fatal("hotel got no prefetch call")
	}
	tc.b.mu.Lock()
	tc.b.hotelWentDown(h)
	cleared := len(h.warm) == 0
	tc.b.mu.Unlock()
	if !cleared {
		t.Fatal("warm set not cleared when the hotel went down")
	}
}

func compatWarmCreates(t *testing.T, tc *testChain, n int) map[string]int {
	t.Helper()
	got := map[string]int{}
	for i := 0; i < n; i++ {
		setHotel(tc, "b", func(h *hotel) { h.createEWMA = 1 })
		setHotel(tc, "c", func(h *hotel) { h.createEWMA = 1 })
		before := map[string]int{"b": creates(tc, "b"), "c": creates(tc, "c")}
		status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
		if status != 201 {
			t.Fatalf("compat create: %d %v", status, doc)
		}
		for _, id := range []string{"b", "c"} {
			got[id] += creates(tc, id) - before[id]
		}
	}
	return got
}

func TestCompatCreatePrefersWarmHotel(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, true, "b")
	if got := compatWarmCreates(t, tc, 30); got["b"] != 30 {
		t.Fatalf("want all 30 compat creates on warm hotel b, got %v", got)
	}
}

func TestCompatCreateIgnoresWarmWhenTheFlagIsOff(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, false, "b")
	if got := compatWarmCreates(t, tc, 40); got["b"] == 0 || got["c"] == 0 {
		t.Fatalf("flag off: want compat creates on both hotels, got %v", got)
	}
}

func TestCompatCreateFallsBackToColdWhenWarmIsFull(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, true, "b")
	setHotel(tc, "b", func(h *hotel) { h.slots = 0 })
	if got := compatWarmCreates(t, tc, 5); got["c"] != 5 {
		t.Fatalf("want all 5 on cold hotel c, got %v", got)
	}
}

// withPrewarm writes prewarm_catalog and prewarm_catalog_hotels into the
// chain's config and restarts the broker over the same hotels.
func withPrewarm(t *testing.T, tc *testChain, on bool, hotels ...string) {
	t.Helper()
	if err := writePrewarm(tc, on, hotels); err != nil {
		t.Fatal(err)
	}
	tc.start(t)
}

func writePrewarm(tc *testChain, on bool, hotels []string) error {
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		return err
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	cfg.PrewarmCatalog, cfg.PrewarmCatalogHotels = on, hotels
	raw, _ = json.Marshal(cfg)
	return os.WriteFile(tc.cfgPath, raw, 0o600)
}

// comeUp takes hotels b and c down and runs one sync step on each, so each
// has an up edge. Hotel a (sealed) stays out of it.
func comeUp(tc *testChain) {
	for _, id := range []string{"a", "b", "c"} {
		setHotel(tc, id, func(h *hotel) { h.ok = false })
	}
	syncNow(tc, "b")
	syncNow(tc, "c")
}

const prefetchCall = "POST /v1/images/prefetch"

// AB#532 option B: prewarm_catalog_hotels limits the pull to the hotels it
// names; the others take no prefetch and hold nothing warm.
func TestPrewarmHotelsListLimitsThePullToNamedHotels(t *testing.T) {
	tc := newChain(t)
	withPrewarm(t, tc, true, "b")
	comeUp(tc)
	waitFor(t, "prefetch on hotel b", func() bool { return callsTo(tc.hotels["b"], prefetchCall) > 0 })
	waitFor(t, "alpine:3.20 warm on b", func() bool {
		tc.b.mu.Lock()
		defer tc.b.mu.Unlock()
		return tc.b.hotelByID("b").warm[warmImage]
	})
	time.Sleep(200 * time.Millisecond) // a pull on c would run in the background
	if n := callsTo(tc.hotels["c"], prefetchCall); n != 0 {
		t.Fatalf("hotel c is not in prewarm_catalog_hotels but got %d prefetch calls", n)
	}
	tc.b.mu.Lock()
	cWarm := len(tc.b.hotelByID("c").warm)
	tc.b.mu.Unlock()
	if cWarm != 0 {
		t.Fatalf("hotel c holds %d warm images", cWarm)
	}
}

// An empty prewarm_catalog_hotels keeps the broker-wide behaviour: every
// hotel that comes up pulls.
func TestPrewarmHotelsEmptyPullsOnEveryHotel(t *testing.T) {
	tc := newChain(t)
	withPrewarm(t, tc, true)
	if len(tc.b.cfg.PrewarmCatalogHotels) != 0 {
		t.Fatalf("default prewarm_catalog_hotels: %v", tc.b.cfg.PrewarmCatalogHotels)
	}
	comeUp(tc)
	for _, id := range []string{"b", "c"} {
		waitFor(t, "prefetch on hotel "+id, func() bool { return callsTo(tc.hotels[id], prefetchCall) > 0 })
	}
}

// The flag off still pulls nowhere, list or not.
func TestPrewarmFlagOffPullsNowhere(t *testing.T) {
	tc := newChain(t)
	withPrewarm(t, tc, false)
	comeUp(tc)
	for _, id := range []string{"b", "c"} {
		if tc.b.prewarms(tc.b.hotelByID(id)) {
			t.Fatalf("flag off: hotel %s would prewarm", id)
		}
	}
}

// Config load refuses an id that is not a hotel in the config file, and a
// list without prewarm_catalog on; a list of known hotels loads.
func TestPrewarmHotelsConfigRefusesUnknownIDs(t *testing.T) {
	for _, c := range []struct {
		on     bool
		hotels []string
	}{
		{true, []string{"nc-sealed-3"}}, // not a hotel in this config
		{true, []string{"b", "nope"}},
		{true, []string{""}},
		{false, []string{"b"}}, // the list alone would do nothing
	} {
		tc := newChain(t)
		if err := writePrewarm(tc, c.on, c.hotels); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBroker(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "prewarm_catalog_hotels") {
			t.Errorf("prewarm_catalog %v, hotels %q: err %v, want a prewarm_catalog_hotels refusal", c.on, c.hotels, err)
		}
	}
	tc := newChain(t)
	withPrewarm(t, tc, true, "b", "c")
	if !slices.Equal(tc.b.cfg.PrewarmCatalogHotels, []string{"b", "c"}) {
		t.Errorf("loaded prewarm_catalog_hotels %v", tc.b.cfg.PrewarmCatalogHotels)
	}
}
