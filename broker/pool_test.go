package main

// Tests of the ready-room pool lifecycle (AB#894, phase 2 work order PR 2).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// letGo makes hotel id's room map drop rooms its list no longer shows, as the
// sync loop does after its grace times.
func (pc *poolChain) letGo(id string) {
	h := pc.b.hotelByID(id)
	for i := 0; i < 2; i++ {
		pc.b.mu.Lock()
		for _, rm := range h.rooms {
			rm.since, rm.vanished = time.Now().Add(-time.Minute), time.Now().Add(-time.Minute)
		}
		pc.b.mu.Unlock()
		pc.sync(id)
	}
}

// readingsOfRun is the usage readings of run in pc's log.
func (pc *poolChain) readingsOfRun(run string) []usageReading {
	pc.t.Helper()
	mustFlush(pc.t, pc.b.usageMeter)
	return readingsOf(logReadings(pc.t, filepath.Join(pc.stateDir, usageDirName)), run)
}

// breakJournal stops pc's broker's journal, writes one record, and removes
// every segment, so the next open finds a listed segment missing.
func (pc *poolChain) breakJournal() {
	pc.t.Helper()
	pc.b.pool.close()
	j, _, err := openClaimJournal(pc.stateDir)
	if err != nil {
		pc.t.Fatal(err)
	}
	if err := <-j.append(claimRecord{Kind: "won", Body: json.RawMessage(`{"request_key":"k1"}`)}); err != nil {
		pc.t.Fatal(err)
	}
	_ = j.close()
	segs, _ := filepath.Glob(filepath.Join(pc.stateDir, claimJournalDirName, "gen-*", "*.jsonl"))
	if len(segs) == 0 {
		pc.t.Fatal("the journal has no segment to remove")
	}
	for _, s := range segs {
		if err := os.Remove(s); err != nil {
			pc.t.Fatal(err)
		}
	}
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
			// The failed proof backs the hotel's creates off 5 s.
			pc.b.mu.Lock()
			ph := pc.b.pool.hotel("a")
			fails, wait := ph.proofFails, time.Until(ph.backoff)
			ph.backoff = time.Time{} // past the backoff
			pc.b.mu.Unlock()
			if fails != 1 || wait < 4*time.Second || wait > poolRetryFirst {
				t.Fatalf("proof failures %d, backoff left %s; want 1 and about 5 s", fails, wait)
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

// A binding change (a receipts front restart) turns every ready room stale:
// deleted and replaced under the new binding, never ready again. Seen by the
// next attestation, or at once by a create receipt that names another
// binding.
func TestPoolRoomsTurnStaleOnBindingChange(t *testing.T) {
	t.Run("next attestation", func(t *testing.T) {
		pc := newPoolChain(t, []string{"a"}, func(c *config) { c.AttestEverySeconds = 0.001 })
		f := pc.hotels["a"]
		pc.up("a")
		pc.target(3)
		pc.fill("a", 3)
		f.set(func(f *fakePoolHotel) { f.newBinding() })
		pc.sync("a") // attests: the new binding
		pc.step("a")
		dels := f.roomDeletes()
		if len(dels) != 3 {
			t.Fatalf("%d deletes after the binding change, want the 3 stale rooms\n%s", len(dels), pc.debug("a"))
		}
		for _, d := range dels {
			if d.path != "/v1/sandboxes/sbx-1" && d.path != "/v1/sandboxes/sbx-2" && d.path != "/v1/sandboxes/sbx-3" {
				t.Fatalf("deleted %s, not an old room", d.path)
			}
		}
		pc.letGo("a")
		pc.fill("a", 3)
		if n := len(f.roomDeletes()); n != 3 {
			t.Fatalf("%d deletes, want 3: the new rooms are ready under the new binding\n%s", n, pc.debug("a"))
		}
	})
	t.Run("receipt names another binding", func(t *testing.T) {
		pc := newPoolChain(t, []string{"a"}, nil)
		f := pc.hotels["a"]
		pc.up("a")
		pc.target(2)
		pc.fill("a", 2)
		f.set(func(f *fakePoolHotel) { f.newBinding() })
		pc.target(3)
		pc.step("a") // the create's receipt names the new binding; attestation still has the old one
		dels := f.roomDeletes()
		if c := pc.counts("a"); len(dels) != 1 || dels[0].path != "/v1/sandboxes/sbx-3" || c.ready != 0 || c.stale != 2 {
			t.Fatalf("deletes %v, counts %+v; want the new room deleted and both ready rooms stale\n%s", dels, c, pc.debug("a"))
		}
		pc.b.mu.Lock()
		again := pc.b.hotelByID("a").adm.checkedAt.IsZero()
		pc.b.mu.Unlock()
		if !again {
			t.Fatal("the hotel is not attested again at once")
		}
		pc.sync("a") // attests: the new binding
		pc.step("a")
		if n := len(f.roomDeletes()); n != 3 {
			t.Fatalf("%d deletes, want the 2 stale rooms deleted too\n%s", n, pc.debug("a"))
		}
		pc.letGo("a")
		pc.fill("a", 3)
		if n := len(f.roomDeletes()); n != 3 {
			t.Fatalf("%d deletes, want 3: the new rooms are ready under the new binding\n%s", n, pc.debug("a"))
		}
	})
}

// A guest reboot wipes every room: the sync loop ends their runs (not
// billable), the pool forgets them, and refill waits until the hotel is
// attested again and the image is warm again.
func TestPoolRoomsGoneAfterGuestReboot(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	h := pc.b.hotelByID("a")
	pc.up("a")
	pc.target(2)
	pc.fill("a", 2)
	gate := make(chan struct{})
	var open sync.Once
	t.Cleanup(func() { open.Do(func() { close(gate) }) }) // a failed test must not leave a pre-pull hanging
	f.set(func(f *fakePoolHotel) {
		f.healthFail = true
		f.rooms = map[string]*fakePoolRoom{}
		f.newBinding()
		f.prefetchGate = gate // the image is cold after the reboot until this opens
	})
	pc.b.mu.Lock()
	h.lastOK = time.Now().Add(-time.Minute) // health has been missing past okWindow
	h.lastAnswer.Store(time.Now().Add(-time.Minute).UnixNano())
	pc.b.mu.Unlock()
	pc.sync("a") // down: attestation and warm marks are gone
	pc.steps("a", 3)
	if n := len(f.creates()); n != 2 {
		t.Fatalf("%d creates while the hotel is down, want the 2 from before", n)
	}
	f.set(func(f *fakePoolHotel) { f.healthFail = false })
	pc.sync("a") // up again: attested under the new binding, the pre-pull waits at the gate
	pc.letGo("a")
	pc.steps("a", 3)
	if n := len(f.creates()); n != 2 {
		t.Fatalf("%d creates while the image is cold, want 2", n)
	}
	if c := pc.counts("a"); c.held != 0 {
		t.Fatalf("pool still holds %+v after the reboot\n%s", c, pc.debug("a"))
	}
	if n := len(f.roomDeletes()); n != 0 {
		t.Fatalf("%d deletes of rooms the reboot removed, want 0", n)
	}
	for _, run := range []string{"a.sbx-1", "a.sbx-2"} {
		rs := pc.readingsOfRun(run)
		if len(rs) == 0 || rs[len(rs)-1].State != "ended" {
			t.Fatalf("run %s not ended: %+v", run, rs)
		}
		for _, r := range rs {
			if !notBillable(r) {
				t.Fatalf("run %s has a billable reading %+v", run, r)
			}
		}
	}
	open.Do(func() { close(gate) })
	waitFor(t, "warm again", func() bool {
		pc.b.mu.Lock()
		defer pc.b.mu.Unlock()
		return h.warm[nodeImage()]
	})
	pc.fill("a", 2)
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

// A delivered claimed room whose journal record was lost (a segment removed)
// is quarantined after the restart, never deleted, even with every target 0,
// and its readings stay on the pool guest, not billable. The same holds with
// a complete journal: the deletion rule is the room's proof, not the journal.
func TestPoolManagerNeverDeletesAnUnprovenRoom(t *testing.T) {
	for _, broken := range []bool{true, false} {
		name := "journal complete"
		if broken {
			name = "journal segment removed"
		}
		t.Run(name, func(t *testing.T) {
			pc := newPoolChain(t, []string{"a"}, nil)
			f := pc.hotels["a"]
			f.addRoom("claimed", "pool", "claim") // a room a customer got through a claim
			if broken {
				pc.breakJournal()
			}
			pc.start()
			want := "complete"
			if broken {
				want = "incomplete"
			}
			if pc.b.pool.journalState != want {
				t.Fatalf("journal %s, want %s (%s)", pc.b.pool.journalState, want, pc.b.pool.journalWhy)
			}
			pc.up("a")
			for i := 0; i < 5; i++ {
				pc.sync("a")
				pc.step("a")
			}
			pc.b.mu.Lock()
			pr := pc.b.pool.hotel("a").rooms["claimed"]
			pc.b.mu.Unlock()
			if pr == nil || pr.state != poolQuarantined {
				t.Fatalf("claimed room %v, want quarantined\n%s", pr, pc.debug("a"))
			}
			if n := len(f.roomDeletes()); n != 0 || f.roomCount() != 1 {
				t.Fatalf("%d deletes, %d rooms; want the claimed room kept", n, f.roomCount())
			}
			rs := pc.readingsOfRun("a.claimed")
			if len(rs) == 0 {
				t.Fatal("no reading of the claimed room")
			}
			for _, r := range rs {
				if r.Guest != poolGuestID || !notBillable(r) {
					t.Fatalf("reading %+v, want the pool guest and not billable", r)
				}
			}
		})
	}
}

// Quarantine that fills a hotel's pool bound stops refill there, deletes
// nothing and raises an alarm; the other hotel fills. Quarantined rooms
// count in the bound (20% of slots, PR 3): a hotel with more slots has room
// for only the difference.
func TestQuarantineFillingTheBoundStopsRefill(t *testing.T) {
	pc := newPoolChain(t, []string{"a", "b"}, nil)
	fa := pc.hotels["a"]
	fa.set(func(f *fakePoolHotel) { f.slots = 15 }) // bound 3
	for _, id := range []string{"q1", "q2", "q3"} {
		fa.addRoom(id, "pool", "claim")
	}
	pc.up("a")
	pc.up("b")
	pc.target(10)
	pc.steps("a", 5)
	pc.fill("b", 10)
	if c := pc.counts("a"); c.quarantined != 3 || c.ready != 0 {
		t.Fatalf("hotel a %+v, want 3 quarantined and nothing else\n%s", c, pc.debug("a"))
	}
	if n := len(fa.creates()); n != 0 {
		t.Fatalf("%d pool creates on the full hotel, want 0", n)
	}
	if n := len(fa.roomDeletes()); n != 0 {
		t.Fatalf("%d deletes on hotel a, want 0", n)
	}
	_, doc := pc.operator("GET", "/v1/broker/ready-rooms", nil)
	ha := doc["hotels"].(map[string]any)["a"].(map[string]any)
	alarm, _ := ha["alarm"].(string)
	if !strings.Contains(alarm, "3 pool rooms quarantined") || !strings.Contains(alarm, "no pool refill") || ha["bound"] != float64(3) {
		t.Fatalf("alarm %q, hotel %v", alarm, ha)
	}
	fa.set(func(f *fakePoolHotel) { f.slots = 25 }) // bound 5
	pc.sync("a")
	pc.fill("a", 2)
	pc.steps("a", 3)
	if c := pc.counts("a"); c.ready != 2 || c.quarantined != 3 {
		t.Fatalf("hotel a with bound 5: %+v, want 2 ready and 3 quarantined", c)
	}
}

// On an incomplete journal, or one that could not be opened, the manager
// creates and deletes nothing.
func TestPoolManagerOffWhenJournalIncomplete(t *testing.T) {
	for _, how := range []string{"incomplete", "unavailable"} {
		t.Run(how, func(t *testing.T) {
			pc := newPoolChain(t, []string{"a"}, nil)
			f := pc.hotels["a"]
			f.addRoom("r-pool", "pool") // provably unclaimed and over target 0: deleted on a complete journal
			switch how {
			case "incomplete":
				pc.breakJournal()
			case "unavailable":
				pc.b.pool.close()
				_ = os.RemoveAll(filepath.Join(pc.stateDir, claimJournalDirName))
				_ = os.Remove(filepath.Join(pc.stateDir, claimJournalIDName))
				if err := os.WriteFile(filepath.Join(pc.stateDir, claimJournalDirName), []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			pc.start()
			if pc.b.pool.journalState != how {
				t.Fatalf("journal %s, want %s", pc.b.pool.journalState, how)
			}
			pc.up("a")
			pc.target(3)
			for i := 0; i < 5; i++ {
				pc.sync("a")
				pc.step("a")
			}
			pc.target(0)
			pc.steps("a", 3)
			if n := len(f.creates()); n != 0 {
				t.Fatalf("%d creates on a journal %s, want 0", n, how)
			}
			if n := len(f.roomDeletes()); n != 0 {
				t.Fatalf("%d deletes on a journal %s, want 0", n, how)
			}
			_, doc := pc.operator("GET", "/v1/broker/ready-rooms", nil)
			ha := doc["hotels"].(map[string]any)["a"].(map[string]any)
			if ha["pool_creates"] != false || !strings.Contains(ha["why_no_creates"].(string), "claim journal "+how) {
				t.Fatalf("GET hotel a %v", ha)
			}
			if j := doc["journal"].(map[string]any); j["state"] != how {
				t.Fatalf("GET journal %v", j)
			}
		})
	}
}

// Pool creates go only to operator, shared hotels with a verified
// attestation where the image is warm. (Every hotel is sealed since AB#776:
// the loader refuses any other, so there is no unsealed case to test here.)
func TestPoolOnlyOnOperatorSealedAttestedWarmHotels(t *testing.T) {
	ids := []string{"ok", "cold", "unattested", "reserved", "gate-off", "miner"}
	pc := newPoolChain(t, ids, func(c *config) {
		for i := range c.Hotels {
			switch c.Hotels[i].ID {
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
	for _, id := range []string{"cold", "unattested"} {
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
	for id, why := range map[string]string{"cold": "not warm", "unattested": "no verified attestation",
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

// At refill_per_second 1 a pool create starts at least 1 s after the
// previous one on the same hotel: no hotel gets 2 pool creates in one second.
func TestPoolCreatesAtMostOneASecondPerHotel(t *testing.T) {
	pc := newPoolChain(t, []string{"a", "b"}, nil)
	poolSpacingFactor = 1.05
	pc.up("a")
	pc.up("b")
	if st, doc := pc.operator("PUT", "/v1/broker/ready-rooms", map[string]any{"per_hotel": map[string]int{"node-22": 10},
		"refill_per_second": 1, "refill_during_claims": 1, "reserve_share": 0.25}); st != 200 {
		t.Fatalf("PUT: %d %v", st, doc)
	}
	probe := startSchedProbe(t)
	stop := make(chan struct{})
	go func() { // until both hotels have 3 creates
		defer close(stop)
		for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
			if len(pc.hotels["a"].creates()) >= 3 && len(pc.hotels["b"].creates()) >= 3 {
				return
			}
		}
	}()
	pc.runPool(21*time.Second, stop)
	for _, id := range []string{"a", "b"} {
		c := pc.hotels[id].creates()
		if len(c) < 3 {
			t.Fatalf("hotel %s: %d creates in 20 s, want 3", id, len(c))
		}
		for i := 1; i < len(c); i++ {
			// A loaded machine can make one arrival late after its start
			// and so shorten the gap after it (schedProbe).
			if !probe.gapAtLeast(c[i-1].at, c[i].at, time.Second) {
				t.Fatalf("hotel %s: creates %d and %d %s apart", id, i-1, i, c[i].at.Sub(c[i-1].at))
			}
		}
	}
}

// Ready rooms retire at 20 minutes left: deleted and replaced.
func TestPoolRetiresAtTwentyMinutesLeft(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	pc.up("a")
	f.set(func(f *fakePoolHotel) { f.createTTL = 19 * time.Minute })
	pc.target(1)
	pc.step("a") // sbx-1, 19 minutes left
	f.set(func(f *fakePoolHotel) { f.createTTL = 0 })
	pc.step("a") // retired and deleted
	pc.letGo("a")
	pc.fill("a", 1)
	dels := f.roomDeletes()
	if len(dels) != 1 || dels[0].path != "/v1/sandboxes/sbx-1" {
		t.Fatalf("deletes %v, want sbx-1 retired", dels)
	}
}

// The rollback: targets 0 by the route deletes the rooms the manager proved
// unclaimed and nothing else.
func TestPoolRollbackToTargetsZeroDeletesOnlyProvenRooms(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	f.addRoom("q1", "pool", "claim")
	f.addRoom("q2")
	pc.up("a")
	pc.target(5)
	pc.fill("a", 3)
	pc.target(0)
	pc.steps("a", 2)
	dels := f.roomDeletes()
	if len(dels) != 3 {
		t.Fatalf("%d deletes, want the 3 ready rooms", len(dels))
	}
	for _, d := range dels {
		if strings.HasSuffix(d.path, "/q1") || strings.HasSuffix(d.path, "/q2") {
			t.Fatalf("deleted quarantined room %s", d.path)
		}
	}
	pc.letGo("a")
	pc.step("a")
	_, doc := pc.operator("GET", "/v1/broker/ready-rooms", nil)
	ha := doc["hotels"].(map[string]any)["a"].(map[string]any)
	if ha["ready"] != float64(0) || ha["quarantined"] != float64(2) || ha["mapped"] != float64(0) {
		t.Fatalf("after the rollback: %v", ha)
	}
}

// The manager acts on a hotel only after its room list has answered once
// since start: before that, an empty room map means nobody looked, so it
// neither makes rooms nor reads any.
func TestPoolWaitsForTheFirstRoomList(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	f.addRoom("r-pool", "pool")
	f.set(func(f *fakePoolHotel) { f.listFail = true })
	h := pc.b.hotelByID("a")
	img := nodeImage()
	waitFor(t, "hotel a admitted and warm", func() bool {
		pc.sync("a")
		pc.b.mu.Lock()
		defer pc.b.mu.Unlock()
		return pc.b.admitted(h, time.Now()) && h.warm[img]
	})
	pc.target(2)
	pc.steps("a", 3)
	if n := len(f.creates()); n != 0 {
		t.Fatalf("%d creates before the first room list, want 0", n)
	}
	_, doc := pc.operator("GET", "/v1/broker/ready-rooms", nil)
	ha := doc["hotels"].(map[string]any)["a"].(map[string]any)
	if ha["listed_since_start"] != false || !strings.Contains(ha["why_no_creates"].(string), "no room list since start") {
		t.Fatalf("GET hotel a before its first list: %v", ha)
	}
	f.set(func(f *fakePoolHotel) { f.listFail = false })
	pc.sync("a")
	pc.fill("a", 2)
	if n := len(f.creates()); n != 1 {
		t.Fatalf("%d creates, want 1: r-pool, read after the first list, is one of the 2", n)
	}
}

// A pool create that fails is not tried again for 5 s on that hotel, even
// with no wait between creates.
func TestPoolFailedCreateWaitsBeforeTheNext(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	pc.up("a")
	f.set(func(f *fakePoolHotel) { f.createFail = true })
	pc.target(2)
	pc.steps("a", 5)
	if n := len(f.creates()); n != 1 {
		t.Fatalf("%d create attempts on a failing hotel, want 1 in 5 s", n)
	}
	if c := pc.counts("a"); c.held != 0 {
		t.Fatalf("pool holds %+v after a failed create", c)
	}
}

// After a restart, a room whose receipts prove it unclaimed but whose image
// is no ready_rooms key is deleted, like an over-target room.
func TestPoolRestartDeletesAProvenRoomOfNoKey(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	f.addRoom("r-other", "pool-other-image")
	pc.up("a")
	pc.steps("a", 3)
	dels := f.roomDeletes()
	if len(dels) != 1 || dels[0].path != "/v1/sandboxes/r-other" {
		t.Fatalf("deletes %v, want r-other\n%s", dels, pc.debug("a"))
	}
}

// With two keys, a cold image of one key stops only that key's pool creates:
// the other key's warm image still fills (codex review of #658).
func TestPoolColdKeyDoesNotStopAWarmKey(t *testing.T) {
	lfm, _ := templateByName("lfm3-1.7b")
	pc := newPoolChain(t, []string{"a"}, func(c *config) {
		c.ReadyRooms.Keys = append(c.ReadyRooms.Keys, readyRoomKeyEntry{Template: "lfm3-1.7b"})
	})
	f := pc.hotels["a"]
	f.set(func(f *fakePoolHotel) { f.coldImages = map[string]bool{lfm.Image: true} })
	pc.up("a")
	st, doc := pc.operator("PUT", "/v1/broker/ready-rooms", map[string]any{"per_hotel": map[string]int{"node-22": 2, "lfm3-1.7b": 1},
		"refill_per_second": 4, "refill_during_claims": 1, "reserve_share": 0.25})
	if st != 200 {
		t.Fatalf("PUT: %d %v", st, doc)
	}
	pc.steps("a", 4)
	var node, other int
	for _, c := range f.creates() {
		switch {
		case strings.Contains(string(c.body), nodeImage()):
			node++
		default:
			other++
		}
	}
	if node != 2 || other != 0 {
		t.Fatalf("creates: %d node-22, %d of the cold key; want 2 and 0\n%s", node, other, pc.debug("a"))
	}
	_, doc = pc.operator("GET", "/v1/broker/ready-rooms", nil)
	ha := doc["hotels"].(map[string]any)["a"].(map[string]any)
	if why, _ := ha["cold_keys"].([]any); len(why) != 1 || why[0] != "lfm3-1.7b" {
		t.Fatalf("GET hotel a: %v", ha)
	}
}

// The disk rule is read again just before a pool create is sent: a hotel
// whose room disk crossed its admission line after the step's plan gets no
// pool create (codex review of #658).
func TestPoolCreateRechecksDiskBeforeItIsSent(t *testing.T) {
	limit := 80.0
	pc := newPoolChain(t, []string{"a"}, func(c *config) { c.Hotels[0].DiskAdmitUsedPct = &limit })
	f := pc.hotels["a"]
	h := pc.b.hotelByID("a")
	pc.up("a")
	pc.target(1)
	w := pc.b.poolPlan(h)
	if w == nil || w.create == nil {
		t.Fatal("the plan made no create")
	}
	full := 90.0
	pc.b.mu.Lock()
	h.roomDataPct = &full // the room disk crossed the line after the plan
	pc.b.mu.Unlock()
	pc.b.poolCreate(context.Background(), h, *w.create, w.att)
	if n := len(f.creates()); n != 0 {
		t.Fatalf("%d pool creates on a hotel over its disk line, want 0", n)
	}
	if c := pc.counts("a"); c.held != 0 {
		t.Fatalf("pool holds %+v", c)
	}
}

// The target is read again just before a pool create is sent: a rollback to
// targets 0 made while the step ran stops the create it had planned.
func TestPoolCreateRechecksTheTargetBeforeItIsSent(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	h := pc.b.hotelByID("a")
	pc.up("a")
	pc.target(1)
	w := pc.b.poolPlan(h)
	if w == nil || w.create == nil {
		t.Fatal("the plan made no create")
	}
	pc.target(0) // the rollback, between the plan and the create
	pc.b.poolCreate(context.Background(), h, *w.create, w.att)
	if n := len(f.creates()); n != 0 {
		t.Fatalf("%d pool creates after targets 0, want 0", n)
	}
}

// failJournalOpens makes the next n journal opens fail with err, then opens
// for real; it returns the number of opens tried so far and the time the
// first good open started.
func failJournalOpens(t *testing.T, n int, err error) func() (int, time.Time) {
	t.Helper()
	var mu sync.Mutex
	tries := 0
	var good time.Time
	old := poolOpenJournal
	poolOpenJournal = func(stateDir string) (*claimJournal, claimJournalHeads, error) {
		mu.Lock()
		tries++
		fail := tries <= n
		if !fail && good.IsZero() {
			good = time.Now()
		}
		mu.Unlock()
		if fail {
			return nil, claimJournalHeads{}, err
		}
		return old(stateDir)
	}
	oldEvery := poolJournalRetry
	poolJournalRetry = 50 * time.Millisecond
	t.Cleanup(func() { poolOpenJournal, poolJournalRetry = old, oldEvery })
	return func() (int, time.Time) {
		mu.Lock()
		defer mu.Unlock()
		return tries, good
	}
}

// A journal open that fails for a reason other than loss (a head file that
// cannot be read; the lock a broker still running on the same state_dir
// holds) is tried again on a timer: after two failures the third open brings
// the pool to "complete" with no broker restart. Nothing is created or
// deleted while it fails, and the receipts reads of the rooms found come
// before the first create.
func TestPoolJournalOpenIsRetriedUntilItOpens(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	f.addRoom("r-pool", "pool")
	f.addRoom("r-stale", "pool")
	tries := failJournalOpens(t, 2, errors.New("claim journal: a head file cannot be read"))
	pc.start() // the first open, at load, fails
	if pc.b.pool.journalState != "unavailable" {
		t.Fatalf("journal %s after a failed open, want unavailable", pc.b.pool.journalState)
	}
	pc.up("a")
	pc.target(3)
	_, doc := pc.operator("GET", "/v1/broker/ready-rooms", nil)
	j := doc["journal"].(map[string]any)
	if j["state"] != "unavailable" || !strings.Contains(j["why"].(string), "head file cannot be read") || j["next_try"] == nil {
		t.Fatalf("GET journal while unavailable: %v", j)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pc.b.runPool(ctx)
	waitFor(t, "the journal to open on a retry", func() bool {
		pc.b.mu.Lock()
		defer pc.b.mu.Unlock()
		return pc.b.pool.journalState == "complete"
	})
	waitFor(t, "the pool to fill", func() bool { return pc.counts("a").ready == 3 })
	cancel()
	n, good := tries()
	if n != 3 {
		t.Fatalf("%d journal opens, want 3 (two failed, one good)", n)
	}
	creates := f.creates()
	if len(creates) != 1 || len(f.roomDeletes()) != 0 {
		t.Fatalf("%d creates, %d deletes; want 1 create (2 rooms were proven by receipts) and no delete", len(creates), len(f.roomDeletes()))
	}
	if !creates[0].at.After(good) {
		t.Fatalf("a create at %s, before the journal opened at %s", creates[0].at, good)
	}
	var lastRead time.Time
	for _, c := range f.callsOf("GET", "/v1/sandboxes/") {
		if strings.HasSuffix(c.path, "/receipts") && c.at.After(lastRead) {
			lastRead = c.at
		}
	}
	if lastRead.IsZero() || !creates[0].at.After(lastRead) {
		t.Fatalf("first create at %s, last receipts read at %s: the reads must come first", creates[0].at, lastRead)
	}
}

// An incomplete journal is never opened again: a person looks.
func TestPoolIncompleteJournalIsNeverRetried(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	pc.breakJournal()
	tries := failJournalOpens(t, 0, nil)
	pc.start()
	if pc.b.pool.journalState != "incomplete" {
		t.Fatalf("journal %s, want incomplete", pc.b.pool.journalState)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go pc.b.runPool(ctx)
	time.Sleep(10 * poolJournalRetry)
	cancel()
	if n, _ := tries(); n != 1 {
		t.Fatalf("%d opens of an incomplete journal, want 1 (at load)", n)
	}
}

// Stopping the broker while the open waits for its next try leaves no
// retry running and no journal open.
func TestPoolJournalRetryStopsWithTheBroker(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	tries := failJournalOpens(t, 1<<30, errors.New("claim journal: claims/ is locked by another broker"))
	pc.start()
	ctx, cancel := context.WithCancel(context.Background())
	go pc.b.runPool(ctx)
	waitFor(t, "a retry", func() bool { n, _ := tries(); return n >= 2 })
	cancel()
	pc.b.pool.close() // returns only once the retry has stopped
	n, _ := tries()
	time.Sleep(5 * poolJournalRetry)
	if m, _ := tries(); m != n {
		t.Fatalf("opens went on after the stop: %d then %d", n, m)
	}
	pc.b.mu.Lock()
	j, state := pc.b.pool.journal, pc.b.pool.journalState
	pc.b.mu.Unlock()
	if j != nil || state != "unavailable" {
		t.Fatalf("after the stop: journal %v, state %s", j, state)
	}
}

// After a restart (or a late journal open) no pool create comes before the
// first receipts read of every room found, even when the reads take more
// than one step (at most 20 a step).
func TestPoolCreatesWaitForEveryFirstReceiptsRead(t *testing.T) {
	pc := newPoolChain(t, []string{"a"}, nil)
	f := pc.hotels["a"]
	for i := 0; i < 25; i++ {
		f.addRoom(fmt.Sprintf("r-%02d", i), "pool")
	}
	pc.start()
	pc.up("a")
	pc.target(30)
	pc.steps("a", 4)
	var lastRead time.Time
	reads := 0
	for _, c := range f.callsOf("GET", "/v1/sandboxes/") {
		if strings.HasSuffix(c.path, "/receipts") {
			reads++
			if c.at.After(lastRead) {
				lastRead = c.at
			}
		}
	}
	creates := f.creates()
	if reads != 25 || len(creates) == 0 {
		t.Fatalf("%d reads, %d creates after 4 steps; want 25 reads and then creates", reads, len(creates))
	}
	if !creates[0].at.After(lastRead) {
		t.Fatalf("first create at %s before the last first read at %s", creates[0].at, lastRead)
	}
}
