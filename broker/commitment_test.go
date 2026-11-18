package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func withMinCommitment(t *testing.T, tc *testChain, slots int, hours float64) {
	t.Helper()
	editConfig(t, tc, func(c *config) { c.MinerMinCommitment = &capacityCommitment{Slots: slots, DailyHours: hours} })
}

func TestJoinRefusesCommitmentBelowMinimum(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	withMinCommitment(t, tc, 4, 12)
	_, url := newMinerHotel(t, 8, snpAttestation(t, attestOpts{chip: chipOf("m1")}))
	join := func(extra map[string]any) (int, map[string]any) {
		body := map[string]any{"id": "m1", "api": url, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey}
		for k, v := range extra {
			body[k] = v
		}
		return tc.call(t, "operator-key", "POST", "/v1/broker/hotels", body)
	}
	for name, c := range map[string]struct {
		extra  map[string]any
		status int
		code   string
	}{
		"missing":        {nil, 422, "commitment_required"},
		"few slots":      {map[string]any{"commitment": map[string]any{"slots": 2, "daily_hours": 20}}, 422, "commitment_below_minimum"},
		"few hours":      {map[string]any{"commitment": map[string]any{"slots": 8, "daily_hours": 6}}, 422, "commitment_below_minimum"},
		"zero slots":     {map[string]any{"commitment": map[string]any{"slots": 0, "daily_hours": 20}}, 400, "invalid_commitment"},
		"over a day":     {map[string]any{"commitment": map[string]any{"slots": 8, "daily_hours": 25}}, 400, "invalid_commitment"},
		"over max_slots": {map[string]any{"max_slots": 4, "commitment": map[string]any{"slots": 8, "daily_hours": 20}}, 400, "invalid_commitment"},
	} {
		if status, doc := join(c.extra); status != c.status || errCode(doc) != c.code {
			t.Fatalf("%s: %d %v", name, status, doc)
		}
		if tc.b.hotelByID("m1") != nil {
			t.Fatalf("%s: refused hotel was stored", name)
		}
	}
	status, doc := join(map[string]any{"commitment": map[string]any{"slots": 4, "daily_hours": 12}})
	if status != 201 {
		t.Fatalf("join at the minimum: %d %v", status, doc)
	}
	c, _ := doc["commitment"].(map[string]any)
	if c["slots"] != float64(4) || c["daily_hours"] != float64(12) {
		t.Fatalf("commitment readback: %v", doc["commitment"])
	}
	// The floor is published to miners with the admission policy.
	_, scoped := tc.call(t, "enroller-key", "GET", "/v1/broker/capacity", nil)
	policy, _ := scoped["admission_policy"].(map[string]any)
	floor, _ := policy["miner_min_commitment"].(map[string]any)
	if floor["slots"] != float64(4) || floor["daily_hours"] != float64(12) {
		t.Fatalf("policy floor: %v", policy)
	}
}

func TestCommitmentOptionalWithoutMinimumAndOnlyForMiners(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 2, nil)
	_, doc := tc.call(t, "operator-key", "GET", "/v1/broker/hotels/m1", nil)
	if v, ok := doc["commitment"]; !ok || v != nil {
		t.Fatalf("miner without a floor joins without a commitment: %v", doc)
	}
	_, url := newOperatorHotel(t, 2, nil)
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "op1", "api": url, "key": joinKey, "commitment": map[string]any{"slots": 2, "daily_hours": 10},
	})
	if status != 400 || errCode(doc) != "invalid_commitment" || tc.b.hotelByID("op1") != nil {
		t.Fatalf("operator hotel with a commitment: %d %v", status, doc)
	}
}

func TestEnrollerJoinDeclaresCommitmentAndItSurvivesRestart(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	withMinCommitment(t, tc, 2, 8)
	_, url := newMinerHotel(t, 4, snpAttestation(t, attestOpts{chip: chipOf("m1")}))
	body := map[string]any{"id": "m1", "api": url, "health": url, "key": joinKey, "sealed": true,
		"miner_hotkey": minerHotkey, "commitment": map[string]any{"slots": 4, "daily_hours": 20}}
	if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", body); status != 201 {
		t.Fatalf("enroller join with a commitment: %d %v", status, doc)
	}
	// A tighter floor after the join does not drop the restored hotel.
	withMinCommitment(t, tc, 8, 24)
	h := tc.b.hotelByID("m1")
	if h == nil || h.cfg.Commitment == nil || *h.cfg.Commitment != (capacityCommitment{Slots: 4, DailyHours: 20}) {
		t.Fatalf("commitment after restart: %+v", h)
	}
}

func TestConfigRefusesBadCommitmentFields(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(c *config){
		"negative floor":      func(c *config) { c.MinerMinCommitment = &capacityCommitment{Slots: -1} },
		"floor over a day":    func(c *config) { c.MinerMinCommitment = &capacityCommitment{Slots: 1, DailyHours: 25} },
		"config hotel commit": func(c *config) { c.Hotels[1].Commitment = &capacityCommitment{Slots: 1, DailyHours: 1} },
	} {
		var c config
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatal(err)
		}
		edit(&c)
		out, _ := json.Marshal(c)
		if err := os.WriteFile(tc.cfgPath, out, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBroker(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "commitment") {
			t.Fatalf("%s: loaded: %v", name, err)
		}
	}
}

// TestDeliveryIsMeasuredAgainstTheCommitment drives recordDelivery with a
// fake clock across a UTC midnight.
func TestDeliveryIsMeasuredAgainstTheCommitment(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 8, map[string]any{"commitment": map[string]any{"slots": 4, "daily_hours": 0.01}})
	h := tc.b.hotelByID("m1")
	b := tc.b
	t0 := time.Date(2026, 11, 13, 23, 57, 0, 0, time.UTC)
	b.mu.Lock()
	h.delivery = delivery{}
	h.adm.attestedAt = t0 // admitted for the whole run (TTL 10 min)
	b.mu.Unlock()
	tick := func(after time.Duration, offered int, ok bool) {
		b.mu.Lock()
		defer b.mu.Unlock()
		h.ok = ok
		b.recordDelivery(h, offered, t0.Add(after), true)
	}
	tick(0, 8, true)                // first tick: nothing to credit yet
	tick(30*time.Second, 8, true)   // 30 s at commitment, 4 slots counted (capped)
	tick(60*time.Second, 2, true)   // 30 s up, below the committed slots
	tick(120*time.Second, 8, true)  // 60 s gap: a stalled loop, not credited
	tick(130*time.Second, 8, false) // down: nothing
	tick(140*time.Second, 8, true)  // 10 s at commitment
	h.cfgMu.Lock()
	h.cfg.Drain = true
	h.cfgMu.Unlock()
	tick(150*time.Second, 8, true) // drained: nothing
	h.cfgMu.Lock()
	h.cfg.Drain = false
	h.cfgMu.Unlock()
	b.mu.Lock()
	d := *h.delivery.today
	b.mu.Unlock()
	if d.day != "2026-11-13" || d.upSec != 70 || d.atCommitSec != 40 || d.slotSec != 4*30+2*30+4*10 {
		t.Fatalf("day 1: %+v", d)
	}
	tick(180*time.Second, 8, true) // 00:00:00 the next day: 30 s, the day rolls over
	b.mu.Lock()
	doc := b.commitmentDoc(h)
	b.mu.Unlock()
	prev, _ := doc["previous_day"].(map[string]any)
	today, _ := doc["today"].(map[string]any)
	if prev["day"] != "2026-11-13" || prev["met"] != true || prev["since"] != "2026-11-13T23:57:00Z" {
		t.Fatalf("previous day: %v", prev)
	}
	if today["day"] != "2026-11-14" || today["met"] != false || today["hours_up"] != 0.01 || today["slot_hours_committed"] != 0.04 {
		t.Fatalf("today: %v", today)
	}
}

// TestSyncLoopCountsReportedSlots checks the hook in syncHotel: a hotel that
// reports 0 slots is up but not at its commitment.
func TestSyncLoopCountsReportedSlots(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	m := joinMiner(t, tc, "m1", true, 4, map[string]any{"commitment": map[string]any{"slots": 4, "daily_hours": 12}})
	time.Sleep(20 * time.Millisecond)
	syncNow(tc, "m1")
	h := tc.b.hotelByID("m1")
	tc.b.mu.Lock()
	first := *h.delivery.today
	tc.b.mu.Unlock()
	if first.upSec <= 0 || first.atCommitSec != first.upSec {
		t.Fatalf("hotel at its commitment: %+v", first)
	}
	m.slots.Store(0)
	time.Sleep(20 * time.Millisecond)
	syncNow(tc, "m1")
	tc.b.mu.Lock()
	second := *h.delivery.today
	tc.b.mu.Unlock()
	if second.upSec <= first.upSec || second.atCommitSec != first.atCommitSec || second.slotSec != first.slotSec {
		t.Fatalf("0 slots reported must count up time only: %+v then %+v", first, second)
	}
	_, doc := tc.call(t, "operator-key", "GET", "/v1/broker/hotels/m1", nil)
	c, _ := doc["commitment"].(map[string]any)
	if c["today"] == nil {
		t.Fatalf("hotel document lacks today's delivery: %v", doc)
	}
}

// TestHealthFailDoesNotCreditStaleSlots: room calls can keep the hotel up
// while /room/health fails; delivery must not credit the last known slot count.
func TestHealthFailDoesNotCreditStaleSlots(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	m := joinMiner(t, tc, "m1", true, 8, map[string]any{"commitment": map[string]any{"slots": 4, "daily_hours": 12}})
	time.Sleep(20 * time.Millisecond)
	syncNow(tc, "m1")
	h := tc.b.hotelByID("m1")
	tc.b.mu.Lock()
	first := *h.delivery.today
	tc.b.mu.Unlock()
	if first.atCommitSec <= 0 {
		t.Fatalf("expected initial slot credit: %+v", first)
	}
	// Health is late (past okWindow) but room calls still answer: hotel stays up.
	m.setHealthFail(true)
	tc.b.mu.Lock()
	h.lastOK = time.Now().Add(-time.Minute)
	tc.b.mu.Unlock()
	h.lastAnswer.Store(time.Now().UnixNano())
	time.Sleep(20 * time.Millisecond)
	syncNow(tc, "m1")
	tc.b.mu.Lock()
	second := *h.delivery.today
	ok, late := h.ok, h.healthLate
	tc.b.mu.Unlock()
	if !ok || !late {
		t.Fatalf("expected up via room calls with late health: ok=%v late=%v", ok, late)
	}
	if second.atCommitSec != first.atCommitSec || second.slotSec != first.slotSec {
		t.Fatalf("stale slots credited after health fail: %+v then %+v", first, second)
	}
	if second.upSec <= first.upSec {
		t.Fatalf("uptime should still count while room calls answer: %+v then %+v", first, second)
	}
}
