package main

// Tests of the ready-room pool lifecycle (AB#894, phase 2 work order PR 2).

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// readingsOfRun is the usage readings of run in pc's log.
func (pc *poolChain) readingsOfRun(run string) []usageReading {
	pc.t.Helper()
	mustFlush(pc.t, pc.b.usageMeter)
	return readingsOf(logReadings(pc.t, filepath.Join(pc.stateDir, usageDirName)), run)
}

func notBillable(r usageReading) bool { return r.Billable != nil && !*r.Billable }

// A pool create sends exactly the five keys the receipts front signs as a
// pool create, with the two labels and no Idempotency-Key, and no secret.
func TestPoolCreateBodyIsExactlyThePoolKeys(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	pc.up("a")
	pc.target(1)
	pc.fill("a", 1)
	creates := pc.hotels["a"].creates()
	if len(creates) != 1 {
		t.Fatalf("%d creates, want 1", len(creates))
	}
	want := `{"image":"` + nodeImage() + `","labels":{"broker_guest":"cathedral-pool","cathedral_pool":"1"},` +
		`"network":{"allow":[],"mode":"deny_all"},"resources":{"disk_gib":10,"memory_gib":4,"vcpu":1},"ttl_seconds":14400}`
	if got := string(creates[0].body); got != want {
		t.Fatalf("create body\n%s\nwant\n%s", got, want)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(creates[0].body, &doc); err != nil || len(doc) != 5 {
		t.Fatalf("create body has %d keys (%v)", len(doc), err)
	}
	for _, k := range []string{"image", "resources", "network", "labels", "ttl_seconds"} {
		if doc[k] == nil {
			t.Fatalf("create body lacks %s", k)
		}
	}
	hdr := creates[0].header
	if v := hdr.Values("Idempotency-Key"); len(v) != 0 {
		t.Fatalf("pool create sent Idempotency-Key %v", v)
	}
	if strings.Contains(string(creates[0].body), "hotel-key") || strings.Contains(strings.ToLower(string(creates[0].body)), "secret") {
		t.Fatal("pool create body carries a key or secret")
	}
	for k := range hdr {
		if strings.HasPrefix(strings.ToLower(k), "x-owner") || strings.EqualFold(k, "X-Cathedral-Guest") {
			t.Fatalf("pool create sent header %s", k)
		}
	}
}

// A room whose create answer carries no verified pool receipt 1 is never
// ready: it was made in this process and never handed out, so it is deleted.
func TestPoolRoomWithoutPoolReceiptIsDeleted(t *testing.T) {
	for name, knob := range map[string]func(f *fakePoolHotel){
		"no pool flag":      func(f *fakePoolHotel) { f.signNoPool = true },
		"another key":       func(f *fakePoolHotel) { f.signOtherKey = true },
		"another room":      func(f *fakePoolHotel) { f.signOtherRoom = true },
		"no receipt header": func(f *fakePoolHotel) { f.noReceipt = true },
	} {
		t.Run(name, func(t *testing.T) {
			pc := newPoolChain(t, []string{"a"}, nil)
			f := pc.hotels["a"]
			pc.up("a")
			f.set(knob)
			pc.target(1)
			pc.step("a")
			if c := pc.counts("a"); c.ready != 0 || c.held != 0 {
				t.Fatalf("counts %+v, want nothing held\n%s", c, pc.debug("a"))
			}
			dels := f.roomDeletes()
			if len(dels) != 1 || dels[0].path != "/v1/sandboxes/sbx-1" || f.roomCount() != 0 {
				t.Fatalf("deletes %v, rooms left %d; want sbx-1 deleted", dels, f.roomCount())
			}
			rs := pc.readingsOfRun("a.sbx-1")
			if len(rs) != 2 || !notBillable(rs[0]) || !notBillable(rs[1]) || rs[1].State != "ended" || rs[0].Guest != poolGuestID {
				t.Fatalf("readings of the deleted room %+v", rs)
			}
			// The same hotel with an honest receipt: the next room is ready.
			f.set(func(f *fakePoolHotel) {
				f.signNoPool, f.signOtherKey, f.signOtherRoom, f.noReceipt = false, false, false, false
			})
			pc.fill("a", 1)
			if n := len(f.roomDeletes()); n != 1 {
				t.Fatalf("%d deletes after an honest create, want 1", n)
			}
		})
	}
}

// After a broker restart every pool-labelled room is read through the
// front: ready only with exactly one receipt, a verified pool receipt 1;
// otherwise quarantined. None is deleted. Reads stay at 20 a second or less.
func TestPoolRestartVerifiesByReceipts(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	pc.up("a")
	pc.target(30)
	pc.fill("a", 2) // made by this broker: sbx-1, sbx-2
	f.addRoom("r-pool", "pool")
	f.addRoom("r-claimed", "pool", "claim")
	f.addRoom("r-none")
	f.addRoom("r-create", "create")
	for i := 0; i < 22; i++ {
		f.addRoom("r-more-"+string(rune('a'+i)), "pool")
	}
	pc.start() // restart: nothing of the pool is in memory
	pc.up("a")
	pc.target(30)
	pc.step("a")
	for i := 0; i < 10 && pc.counts("a").unverified > 0; i++ {
		pc.step("a")
	}
	c := pc.counts("a")
	if c.ready < 25 || c.quarantined != 3 {
		t.Fatalf("counts %+v, want 25 ready (2 made before, r-pool, 22 more) and 3 quarantined\n%s", c, pc.debug("a"))
	}
	pc.b.mu.Lock()
	ph := pc.b.pool.hotel("a")
	for id, want := range map[string]poolRoomState{"sbx-1": poolReady, "sbx-2": poolReady, "r-pool": poolReady,
		"r-claimed": poolQuarantined, "r-none": poolQuarantined, "r-create": poolQuarantined} {
		if pr := ph.rooms[id]; pr == nil || pr.state != want {
			pc.b.mu.Unlock()
			t.Fatalf("room %s: %v, want %s\n%s", id, pr, want, pc.debug("a"))
		}
	}
	pc.b.mu.Unlock()
	if n := len(f.roomDeletes()); n != 0 {
		t.Fatalf("%d deletes after the restart, want 0", n)
	}
	reads := f.callsOf("GET", "/v1/sandboxes/")
	var at []time.Time
	for _, r := range reads {
		if strings.HasSuffix(r.path, "/receipts") {
			at = append(at, r.at)
		}
	}
	if len(at) != 28 {
		t.Fatalf("%d receipts reads, want 28 (one per room)", len(at))
	}
	for i := range at {
		n := 0
		for j := i; j < len(at) && at[j].Sub(at[i]) < time.Second; j++ {
			n++
		}
		if n > 20 {
			t.Fatalf("%d receipts reads within one second from read %d, want at most 20", n, i)
		}
	}
	st, doc := pc.operator("GET", "/v1/broker/ready-rooms", nil)
	ha, _ := doc["hotels"].(map[string]any)["a"].(map[string]any)
	if st != 200 || ha["quarantined"] != float64(3) || ha["mapped"] != float64(0) || ha["claiming"] != float64(0) {
		t.Fatalf("GET ready-rooms %d %v", st, ha)
	}
}

// Pool creates go only to operator, shared, sealed hotels with a verified
// attestation where the image is warm.
func TestPoolOnlyOnOperatorSealedAttestedWarmHotels(t *testing.T) {
	ids := []string{"ok", "cold", "unattested", "unsealed", "reserved", "gate-off", "miner"}
	pc := newPoolChain(t, ids, func(c *config) {
		for i := range c.Hotels {
			switch c.Hotels[i].ID {
			case "unsealed":
				c.Hotels[i].Sealed = false
			case "reserved":
				c.Hotels[i].ReservedFor = "g1"
			case "gate-off":
				c.Hotels[i].SealedAdmission = sealedAdmissionOff
			}
		}
	})
	gate := make(chan struct{})
	t.Cleanup(func() { close(gate) })
	pc.hotels["cold"].set(func(f *fakePoolHotel) { f.prefetchGate = gate })
	pc.hotels["unattested"].set(func(f *fakePoolHotel) { f.attestFail = true })
	for _, id := range []string{"ok", "reserved", "gate-off", "miner"} {
		pc.up(id)
	}
	for _, id := range []string{"cold", "unattested", "unsealed"} {
		pc.sync(id)
		pc.sync(id)
	}
	// A miner hotel joins at runtime with guest TLS; here an admitted, warm
	// operator hotel is given a hotkey, so only the operator rule refuses it.
	pc.b.mu.Lock()
	pc.b.hotelByID("miner").cfg.MinerHotkey = minerHotkey
	pc.b.mu.Unlock()
	pc.target(2)
	for i := 0; i < 4; i++ {
		for _, id := range ids {
			pc.step(id)
		}
	}
	for _, id := range ids {
		n := len(pc.hotels[id].creates())
		if id == "ok" && n != 2 {
			t.Fatalf("hotel ok: %d creates, want 2", n)
		}
		if id != "ok" && n != 0 {
			t.Fatalf("hotel %s: %d pool creates, want 0", id, n)
		}
	}
	_, doc := pc.operator("GET", "/v1/broker/ready-rooms", nil)
	hs := doc["hotels"].(map[string]any)
	for id, why := range map[string]string{"cold": "not warm", "unattested": "no verified attestation", "unsealed": "not a sealed hotel",
		"reserved": "reserved for a guest", "gate-off": "no verified attestation", "miner": "miner hotel"} {
		if got, _ := hs[id].(map[string]any)["why_no_creates"].(string); !strings.Contains(got, why) {
			t.Fatalf("hotel %s: why_no_creates %q, want %q", id, got, why)
		}
	}
}

// Pool readings are not billable from the first one, under the pool guest,
// and a sync that sees a new pool room does not wait for a durable turn. A
// customer room's readings are as before: no billable field.
func TestPoolReadingsAreNotBillable(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	pc.up("a")
	pc.target(1)
	pc.fill("a", 1)
	f.set(func(f *fakePoolHotel) {
		f.rooms["cust-1"] = &fakePoolRoom{id: "cust-1", labels: map[string]string{guestLabel: "g1"}, expires: time.Now().Add(time.Hour)}
	})
	for i := 0; i < 3; i++ {
		pc.sync("a")
	}
	rs := pc.readingsOfRun("a.sbx-1")
	if len(rs) == 0 {
		t.Fatal("no reading of the pool room")
	}
	for _, r := range rs {
		if r.Guest != poolGuestID || !notBillable(r) {
			t.Fatalf("pool reading %+v", r)
		}
	}
	cust := pc.readingsOfRun("a.cust-1")
	if len(cust) != 1 || cust[0].Billable != nil || cust[0].Guest != "g1" {
		t.Fatalf("customer readings %+v, want one billable reading", cust)
	}
	raw, _ := json.Marshal(cust[0])
	if strings.Contains(string(raw), "billable") {
		t.Fatalf("customer reading line %s carries billable", raw)
	}
	// A hung disk: a sync that sees a new pool room must not wait for it.
	release := make(chan struct{})
	old := usageSyncFile
	usageSyncFile = func(f *os.File) error { <-release; return old(f) }
	defer func() { close(release); usageSyncFile = old }()
	f.addRoom("r-new", "pool")
	t0 := time.Now()
	pc.sync("a")
	if d := time.Since(t0); d > usageTurnWait/2 {
		t.Fatalf("sync took %s with a new pool room on a hung disk; it waited for a durable turn", d)
	}
}

// A pool create starts no sooner than 1 s after the previous answer on the
// same hotel: no hotel ever gets 2 pool creates in one second.
func TestPoolCreatesAtMostOneASecondPerHotel(t *testing.T) {
	pc := newPoolChain(t, []string{"a", "b"}, nil)
	poolCreateEvery = time.Second
	pc.up("a")
	pc.up("b")
	pc.target(10)
	ctx, cancel := context.WithCancel(context.Background())
	go pc.b.runPool(ctx)
	time.Sleep(3500 * time.Millisecond)
	cancel()
	waitFor(t, "pool steps to end", func() bool {
		pc.b.mu.Lock()
		defer pc.b.mu.Unlock()
		for _, ph := range pc.b.pool.hotels {
			if ph.busy {
				return false
			}
		}
		return true
	})
	for _, id := range []string{"a", "b"} {
		c := pc.hotels[id].creates()
		if len(c) < 3 || len(c) > 4 {
			t.Fatalf("hotel %s: %d creates in 3.5 s, want 3 or 4", id, len(c))
		}
		for i := 1; i < len(c); i++ {
			if gap := c[i].at.Sub(c[i-1].at); gap < time.Second {
				t.Fatalf("hotel %s: creates %d and %d %s apart", id, i-1, i, gap)
			}
		}
	}
}
