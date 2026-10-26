package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Capacity plane slice 2 at scale: 500+ hotels in one broker, placed by pick
// directly (no HTTP), and joins racing creates through the HTTP routes.

// scaleBroker is a broker with n hotels "h000".. that answer health, with
// shape(i, h) applied to each. No sync loops run.
func scaleBroker(t *testing.T, n int, shape func(i int, h *hotel)) *broker {
	t.Helper()
	b := &broker{guests: map[string]*guestState{}, byKey: map[string]*guestState{}, byUUID: map[string]*room{}, compat: newCompat()}
	for i := 0; i < n; i++ {
		h := newHotel(hotelConfig{ID: fmt.Sprintf("h%03d", i), API: "http://127.0.0.1:1", Health: "http://127.0.0.1:1", Concurrency: 4}, "k")
		h.ok, h.slots = true, 100
		if shape != nil {
			shape(i, h)
		}
		if err := b.addHotel(h); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func TestPlacementIsFairAcross500Hotels(t *testing.T) {
	const n, picks = 500, 50000
	b := scaleBroker(t, n, nil)
	count := map[string]int{}
	b.mu.Lock()
	for i := 0; i < picks; i++ {
		count[b.pick(nil, placement{guest: "g"}).cfg.ID]++
	}
	b.mu.Unlock()
	// Equal hotels: about picks/n = 100 each; the band is 5 standard deviations.
	for _, h := range b.hotelList() {
		if c := count[h.cfg.ID]; c < 50 || c > 150 {
			t.Fatalf("hotel %s got %d of %d picks, want about %d", h.cfg.ID, c, picks, picks/n)
		}
	}

	// Weight follows free rooms: hotels with twice the free rooms get about twice the picks.
	b = scaleBroker(t, n, func(i int, h *hotel) {
		if i%2 == 0 {
			h.slots = 200
		}
	})
	big, small := 0, 0
	b.mu.Lock()
	for i := 0; i < picks; i++ {
		var j int
		fmt.Sscanf(b.pick(nil, placement{guest: "g"}).cfg.ID, "h%03d", &j)
		if j%2 == 0 {
			big++
		} else {
			small++
		}
	}
	b.mu.Unlock()
	if r := float64(big) / float64(small); r < 1.85 || r > 2.15 {
		t.Fatalf("200-room hotels / 100-room hotels = %.3f, want about 2", r)
	}
}

// TestFillingA600HotelPoolRespectsEveryRule fills 600 hotels of every kind
// with one policy guest, one room at a time, as creates would:
//   - each hotel takes exactly its cap (max_slots / slots), never more;
//   - draining, down, not-admitted, reserved and denied hotels get nothing;
//   - the preferred class fills before the first room spills to the allowed one;
//   - when nothing fits, pick says so (nil) and the reason counts every state.
func TestFillingA600HotelPoolRespectsEveryRule(t *testing.T) {
	const n = 600
	kind := func(i int) string {
		switch i % 12 {
		case 0:
			return "draining"
		case 1:
			return "down"
		case 2:
			return "pending" // joined sealed, no attestation pass
		case 3:
			return "reserved" // for another guest
		case 4:
			return "denied" // miner label, which the policy denies
		case 5, 6, 7:
			return "sealed" // joined sealed, admitted
		default:
			return "unsealed"
		}
	}
	b := scaleBroker(t, n, func(i int, h *hotel) {
		h.slots = 1 + i%7 // caps from 1 to 7
		switch kind(i) {
		case "draining":
			h.cfg.Drain = true
		case "down":
			h.ok = false
		case "pending":
			h.runtime, h.cfg.Labels = true, map[string]string{"sealed": "true"}
		case "reserved":
			h.cfg.ReservedFor = "other"
		case "denied":
			h.runtime, h.cfg.Labels = true, map[string]string{"sealed": "true", "miner": "true"}
			h.adm.attestedAt = time.Now()
		case "sealed":
			h.runtime, h.cfg.Labels = true, map[string]string{"sealed": "true", "miner": "true", "pool": "open"}
			h.adm.attestedAt = time.Now()
		}
	})
	// The denied hotels are denied by id, one selector each (a deny list
	// that grows with the pool).
	pol := &guestPolicy{
		Prefer: []selector{{Class: classSealed}},
		Allow:  []selector{{Class: classUnsealed}},
	}
	want := map[string]int{}
	var sealedCap, unsealedCap int
	for i, h := range b.hotelList() {
		switch kind(i) {
		case "denied":
			pol.Deny = append(pol.Deny, selector{Hotel: h.cfg.ID})
		case "sealed":
			want[h.cfg.ID] = h.slots
			sealedCap += h.slots
		case "unsealed":
			want[h.cfg.ID] = h.slots
			unsealedCap += h.slots
		}
	}
	pl := placement{guest: "g", policy: pol}
	got := map[string]int{}
	placed, spilled := 0, false
	b.mu.Lock()
	for {
		h := b.pick(nil, pl)
		if h == nil {
			break
		}
		tier := pol.tier(h)
		if tier == tierAllow {
			if !spilled && placed != sealedCap {
				b.mu.Unlock()
				t.Fatalf("spilled to %s after %d rooms; the preferred class has %d", h.cfg.ID, placed, sealedCap)
			}
			spilled = true
		} else if spilled {
			b.mu.Unlock()
			t.Fatalf("preferred hotel %s chosen after the spill", h.cfg.ID)
		}
		h.creating++ // the room is in flight: it counts as used
		got[h.cfg.ID]++
		placed++
		if placed > sealedCap+unsealedCap {
			b.mu.Unlock()
			t.Fatalf("placed more rooms than the pool has")
		}
	}
	b.mu.Unlock()
	if placed != sealedCap+unsealedCap {
		t.Fatalf("placed %d rooms, the pool has %d", placed, sealedCap+unsealedCap)
	}
	for i, h := range b.hotelList() {
		if got[h.cfg.ID] != want[h.cfg.ID] {
			t.Fatalf("hotel %s (%s) got %d rooms, want %d", h.cfg.ID, kind(i), got[h.cfg.ID], want[h.cfg.ID])
		}
	}
	res := b.noRoom(pl)
	r, _ := res.doc["reason"].(map[string]int)
	// Matching: everything but reserved and denied (100 of 600).
	if res.status != 503 || r["matching"] != 500 || r["draining"] != 50 || r["down"] != 50 || r["pending_admission"] != 50 || r["full"] != 350 {
		t.Fatalf("no room: %d %v", res.status, res.doc)
	}
}

// TestConcurrentJoinsLeavesAndCreates races hotel joins, updates, leaves,
// catalog reads and creates through the HTTP routes (run with -race). Every
// room the hotels started must be a room the guests got back, on a hotel
// that is still in the set, and hotels.json must hold exactly the joined
// hotels that did not leave.
func TestConcurrentJoinsLeavesAndCreates(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	const joins, creators, perCreator = 40, 6, 20
	miners := make([]*minerHotel, joins)
	urls := make([]string, joins)
	for i := range miners {
		miners[i], urls[i] = newMinerHotel(t, 3, snpAttestation(t, attestOpts{}))
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[string]int{} // hotel -> rooms the guests got
	left := map[string]bool{}
	errs := []string{}
	note := func(s string) { mu.Lock(); errs = append(errs, s); mu.Unlock() }

	wg.Add(1)
	go func() { // joins, each followed by one sync step
		defer wg.Done()
		for i := 0; i < joins; i++ {
			id := fmt.Sprintf("j%02d", i)
			status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{
				"id": id, "api": urls[i], "key": joinKey, "sealed": i%2 == 0, "miner_hotkey": minerHotkey})
			if status != 201 {
				note(fmt.Sprintf("join %s: %d %v", id, status, doc))
				continue
			}
			syncNow(tc, id)
		}
	}()
	wg.Add(1)
	go func() { // updates, catalog reads and leaves of empty hotels
		defer wg.Done()
		for i := 0; i < joins; i++ {
			id := fmt.Sprintf("j%02d", i)
			tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/"+id, map[string]any{"max_slots": 2})
			tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
			tc.call(t, "key1", "GET", "/v1/broker/capacity", nil)
			if i%5 == 0 {
				if status, _ := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/"+id, nil); status == 204 {
					mu.Lock()
					left[id] = true
					mu.Unlock()
				}
			}
		}
	}()
	for c := 0; c < creators; c++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perCreator; i++ {
				status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "sealed": i%2 == 0})
				switch status {
				case 202:
					mu.Lock()
					got[doc["hotel"].(string)]++
					mu.Unlock()
				case 429, 503:
				default:
					note(fmt.Sprintf("create: %d %v", status, doc))
				}
			}
		}()
	}
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("%d errors, first: %s", len(errs), errs[0])
	}
	for id, f := range tc.hotels {
		if n := creates(tc, id); n != got[id] {
			t.Fatalf("hotel %s started %d rooms, guests got %d", id, n, got[id])
		}
		_ = f
	}
	for i, m := range miners {
		id := fmt.Sprintf("j%02d", i)
		m.mu.Lock()
		n := len(m.creates)
		m.mu.Unlock()
		if n != got[id] {
			t.Fatalf("hotel %s started %d rooms, guests got %d", id, n, got[id])
		}
		if left[id] && n > 0 {
			t.Fatalf("hotel %s left with %d rooms", id, n)
		}
		if (tc.b.hotelByID(id) == nil) != left[id] {
			t.Fatalf("hotel %s: in set %v, left %v", id, tc.b.hotelByID(id) != nil, left[id])
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, runtimeHotelsFile))
	if err != nil {
		t.Fatal(err)
	}
	var saved []hotelConfig
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("hotels.json: %v", err)
	}
	if len(saved) != joins-len(left) {
		t.Fatalf("hotels.json has %d hotels, want %d", len(saved), joins-len(left))
	}
	for _, hc := range saved {
		if left[hc.ID] || !strings.HasPrefix(hc.ID, "j") || hc.MinerHotkey != minerHotkey {
			t.Fatalf("hotels.json entry %+v", hc)
		}
	}
}
