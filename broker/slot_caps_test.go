package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Room caps on miner hotels (AB#335, placement.go).

const hotkeyB = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"

// capsBroker is a broker with own own sealed-class hotels ("o0"..) and one
// miner hotel per entry of miners ("m0"..), each the hotkey given, all with
// slots rooms, up and admitted.
func capsBroker(t *testing.T, own int, miners []string, slots int) *broker {
	t.Helper()
	b := scaleBroker(t, 0, nil)
	b.cfg.SealedMeasurements = []string{strings.Repeat("ab", 48)}
	add := func(id string, fn func(h *hotel)) {
		h := newHotel(hotelConfig{ID: id, API: "http://127.0.0.1:1", Health: "http://127.0.0.1:1", Concurrency: 4,
			Labels: map[string]string{"sealed": "true"}}, "k")
		h.ok, h.slots = true, slots
		if fn != nil {
			fn(h)
		}
		if err := b.addHotelRestored(h); err != nil { // restored: skip the hotel-count caps
			t.Fatal(err)
		}
	}
	for i := 0; i < own; i++ {
		add(fmt.Sprintf("o%d", i), nil)
	}
	for i, k := range miners {
		add(fmt.Sprintf("m%d", i), func(h *hotel) {
			h.runtime, h.cfg.Sealed, h.cfg.MinerHotkey = true, true, k
			h.cfg.Labels = map[string]string{"sealed": "true", "miner": "true", "miner_hotkey": k}
			h.adm.attestedAt = time.Now()
		})
	}
	return b
}

// minerPolicy prefers miner hotels and allows the rest.
func minerPolicy() placement {
	return placement{guest: "g", policy: &guestPolicy{
		Prefer: []selector{{Label: map[string]string{"miner": "true"}}},
		Allow:  []selector{{Class: classSealed}, {Class: classUnsealed}},
	}}
}

// fill places rooms one at a time until pick says no, as creates would.
func fill(b *broker, pl placement) map[string]int {
	got := map[string]int{}
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		h := b.pick(nil, pl)
		if h == nil {
			return got
		}
		h.creating++
		got[h.cfg.ID]++
	}
}

// minerRooms is the rooms in use per hotkey and on unreserved miner hotels.
func minerRooms(b *broker) (map[string]int, int) {
	by, pool := map[string]int{}, 0
	for _, h := range b.hotelList() {
		if h.cfg.MinerHotkey == "" {
			continue
		}
		by[h.cfg.MinerHotkey] += h.used()
		if h.reservedFor() == "" {
			pool += h.used()
		}
	}
	return by, pool
}

func TestMinerCapsOffLeaveMinerHotelsUncapped(t *testing.T) {
	b := capsBroker(t, 1, []string{minerHotkey, minerHotkey}, 10)
	b.mu.Lock()
	if mb := b.minerBudgetNow(); mb != nil {
		b.mu.Unlock()
		t.Fatalf("caps off, budget %+v", mb)
	}
	for _, h := range b.hotelList() {
		if f := b.admissibleFree(h, time.Now()); f != 10 {
			b.mu.Unlock()
			t.Fatalf("hotel %s free %d, want 10", h.cfg.ID, f)
		}
	}
	b.mu.Unlock()
	got := fill(b, minerPolicy())
	if got["m0"] != 10 || got["m1"] != 10 || got["o0"] != 10 {
		t.Fatalf("caps off: %v", got)
	}
}

func TestPerHotkeyRoomCapHoldsAcrossTheHotkeysHotels(t *testing.T) {
	b := capsBroker(t, 0, []string{minerHotkey, minerHotkey, hotkeyB}, 10)
	b.cfg.MinerMaxRoomsPerHotkey = 5
	got := fill(b, minerPolicy())
	if got["m0"]+got["m1"] != 5 || got["m2"] != 5 {
		t.Fatalf("per-hotkey cap 5: %v", got)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, h := range b.hotelList() {
		if f := b.admissibleFree(h, time.Now()); f != 0 {
			t.Fatalf("hotel %s at its hotkey cap shows %d free", h.cfg.ID, f)
		}
	}
}

func TestPoolShareCapsMinerRoomsAndSkipsReservedHotels(t *testing.T) {
	// 3 own hotels x 10 = 30 own slots; share 0.25: miners take at most
	// 0.25/0.75 x 30 = 10 pool rooms, a quarter of the full pool of 40.
	b := capsBroker(t, 3, []string{minerHotkey, minerHotkey, hotkeyB, hotkeyB, minerHotkey}, 10)
	b.cfg.MinerPoolShare = 0.25
	b.hotelByID("m4").cfg.ReservedFor = "g" // reserved for the guest: not the shared pool
	got := fill(b, minerPolicy())
	pool := got["m0"] + got["m1"] + got["m2"] + got["m3"]
	if pool != 10 || got["m4"] != 10 || got["o0"]+got["o1"]+got["o2"] != 30 {
		t.Fatalf("share 0.25 of 30 own slots: pool miner rooms %d, reserved %d, own %d (%v)", pool, got["m4"], got["o0"]+got["o1"]+got["o2"], got)
	}
	// The operator view reads the share back.
	rec := httptest.NewRecorder()
	b.handleCapacity(rec, nil, false)
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	mp, _ := doc["miner_pool"].(map[string]any)
	pol, _ := doc["admission_policy"].(map[string]any)
	if mp["own_slots"] != float64(30) || mp["miner_room_cap"] != float64(10) || mp["miner_rooms"] != float64(10) || pol["miner_pool_share"] != 0.25 {
		t.Fatalf("readback: miner_pool %v policy %v", mp, pol)
	}
}

func TestCatalogTotalsCountAMinerCapOnce(t *testing.T) {
	// Four miner hotels of one hotkey with 10 free each, hotkey cap 6: the
	// sealed class has 6 miner rooms free, not 4 x 6.
	b := capsBroker(t, 1, []string{minerHotkey, minerHotkey, minerHotkey, minerHotkey}, 10)
	b.cfg.MinerMaxRoomsPerHotkey = 6
	rec := httptest.NewRecorder()
	b.handleCapacity(rec, nil, false)
	var doc struct {
		Hotels  []map[string]any        `json:"hotels"`
		Classes map[string]*classTotals `json:"classes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.Classes[classSealed].FreeRooms; got != 10+6 {
		t.Fatalf("sealed free_rooms %d, want 16", got)
	}
	for _, h := range doc.Hotels {
		if strings.HasPrefix(h["id"].(string), "m") && h["free_rooms"] != float64(6) {
			t.Fatalf("hotel %v free_rooms %v, want 6", h["id"], h["free_rooms"])
		}
	}
	if _, ok := doc.Hotels[0]["miner_pool"]; ok {
		t.Fatal("no share configured, no miner_pool readback")
	}
}

func TestCreateRefusedOnlyByACapSaysSo(t *testing.T) {
	b := capsBroker(t, 0, []string{minerHotkey}, 10)
	b.cfg.MinerMaxRoomsPerHotkey = 2
	pl := placement{guest: "g", policy: &guestPolicy{Prefer: []selector{{Label: map[string]string{"miner": "true"}}}}}
	if got := fill(b, pl); got["m0"] != 2 {
		t.Fatalf("fill: %v", got)
	}
	res := b.noRoomReason(pl)
	r, _ := res.doc["reason"].(map[string]int)
	if res.status != 429 || r["full"] != 1 || r["miner_capped"] != 1 {
		t.Fatalf("capped: %d %v", res.status, res.doc)
	}
	b.cfg.MinerMaxRoomsPerHotkey = 0 // caps off: no miner_capped key
	b.mu.Lock()
	b.hotelByID("m0").creating = 10
	b.mu.Unlock()
	res = b.noRoomReason(pl)
	if r, _ := res.doc["reason"].(map[string]int); r["full"] != 1 {
		t.Fatalf("full: %v", res.doc)
	} else if _, ok := r["miner_capped"]; ok {
		t.Fatalf("caps off: %v", r)
	}
}

// TestMinerCapsHoldUnderConcurrentPlacement places, starts and ends rooms
// from many goroutines at once, as createOne does (pick and queued++ in one
// b.mu hold), and checks both caps after every placement. Run with -race.
func TestMinerCapsHoldUnderConcurrentPlacement(t *testing.T) {
	b := capsBroker(t, 3, []string{minerHotkey, minerHotkey, minerHotkey, hotkeyB, hotkeyB, hotkeyB}, 20)
	b.cfg.MinerMaxRoomsPerHotkey = 25
	b.cfg.MinerPoolShare = 0.4 // 0.4/0.6 x 60 own slots = 40
	const perKey, poolCap = 25, 40
	pl := minerPolicy()
	var wg sync.WaitGroup
	var errs []string // appended under b.mu
	var peakPool, peakKey int
	for w := 0; w < 64; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for i := 0; i < 200; i++ {
				b.mu.Lock()
				h := b.pick(nil, pl)
				if h == nil {
					b.mu.Unlock()
					continue
				}
				h.queued++
				by, pool := minerRooms(b)
				for k, n := range by {
					if n > perKey {
						errs = append(errs, fmt.Sprintf("hotkey %s holds %d rooms, cap %d", k[:6], n, perKey))
					}
					peakKey = max(peakKey, n)
				}
				if pool > poolCap {
					errs = append(errs, fmt.Sprintf("pool miner rooms %d, cap %d", pool, poolCap))
				}
				peakPool = max(peakPool, pool)
				b.mu.Unlock()
				time.Sleep(time.Duration(rng.Intn(200)) * time.Microsecond)
				b.mu.Lock()
				h.queued-- // the create starts
				h.creating++
				b.mu.Unlock()
				time.Sleep(time.Duration(rng.Intn(200)) * time.Microsecond)
				if rng.Intn(3) > 0 { // most rooms end; the rest stay to the end
					b.mu.Lock()
					h.creating--
					b.mu.Unlock()
				}
			}
		}(int64(w))
	}
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("%d cap breaches, first: %s", len(errs), errs[0])
	}
	if peakPool != poolCap {
		t.Fatalf("the share cap never filled (peak %d of %d): the test did not press on it", peakPool, poolCap)
	}
	if peakKey < perKey-5 {
		t.Fatalf("hotkey peak %d: the test did not press on the per-hotkey cap", peakKey)
	}
}

// TestQueuedMoveBetweenMinerHotelsKeepsItsRoom: a create queued on one miner
// hotel at the hotkey cap may move to another hotel of that hotkey: it holds
// its room already, it does not take a new one.
func TestQueuedMoveBetweenMinerHotelsKeepsItsRoom(t *testing.T) {
	b := capsBroker(t, 0, []string{minerHotkey, minerHotkey}, 10)
	b.cfg.MinerMaxRoomsPerHotkey = 2 // the busy create on m0 and the queued one
	b.cfg.MaxQueueWaitSeconds = 0.05
	m0, m1 := b.hotelByID("m0"), b.hotelByID("m1")
	m0.sem = make(chan struct{}, 1)
	m0.sem <- struct{}{} // m0's one create slot is busy
	g := &guestState{}
	b.mu.Lock()
	m0.queued, g.queued = 1, 1
	m0.creating = 1 // the busy slot: deep queue on m0, so the move is a clear gain
	m0.createEWMA = 5
	b.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got := b.waitSlot(ctx, g, m0, minerPolicy(), map[*hotel]bool{m0: true})
	if got != m1 {
		t.Fatalf("create stayed on %v, want a move to m1", got)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if m0.queued != 0 || m1.queued != 1 {
		t.Fatalf("queued m0 %d m1 %d", m0.queued, m1.queued)
	}
	if by, _ := minerRooms(b); by[minerHotkey] != 2 {
		t.Fatalf("hotkey rooms %d, want 2", by[minerHotkey])
	}
}

// TestMinerRoomCapHoldsUnderConcurrentCreates drives the real create path:
// concurrent POST /v1/sandboxes from a guest that prefers miner hotels.
func TestMinerRoomCapHoldsUnderConcurrentCreates(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 10, nil)
	joinMiner(t, tc, "m2", true, 10, nil)
	admitNow(t, tc, "m1")
	admitNow(t, tc, "m2")
	optInMiner(t, tc, "g1")
	tc.b.mu.Lock()
	tc.b.cfg.MinerMaxRoomsPerHotkey = 3
	tc.b.mu.Unlock()
	const n = 12
	var wg sync.WaitGroup
	ok := make(chan bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
			ok <- status == 202 || status == 201 || status == 200
		}()
	}
	wg.Wait()
	close(ok)
	good := 0
	for v := range ok {
		if v {
			good++
		}
	}
	on := createsOn(tc)
	if good != n || on["m1"]+on["m2"] != 3 || on["a"]+on["b"]+on["c"] != n-3 {
		t.Fatalf("%d of %d created; creates per hotel %v; want 3 on miners", good, n, on)
	}
}

func TestMinerCapConfigIsChecked(t *testing.T) {
	for _, c := range []struct {
		field string
		v     any
		ok    bool
	}{
		{"miner_max_rooms_per_hotkey", -1, false},
		{"miner_max_rooms_per_hotkey", 4, true},
		{"miner_pool_share", -0.1, false},
		{"miner_pool_share", 1, false},
		{"miner_pool_share", 1.5, false},
		{"miner_pool_share", 0.3, true},
	} {
		dir := t.TempDir()
		raw, _ := json.Marshal(map[string]any{c.field: c.v})
		p := filepath.Join(dir, "config.json")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadBroker(p)
		if (err == nil) != c.ok || (err != nil && !strings.Contains(err.Error(), c.field)) {
			t.Fatalf("%s=%v: err %v", c.field, c.v, err)
		}
	}
}
