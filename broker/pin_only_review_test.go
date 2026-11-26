package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Astra impl r1 fixes on PR #770 (pin_only.go, AB#982).

// Finding 1: the probe decides and claims under one b.mu hold, and keeps the
// claim for the whole probe.
func TestProbeHoldsAClaimSoPinOnlyCannotSwitchMidProbe(t *testing.T) {
	tc := knownChain(t)
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": "g2"}); status != 200 {
		t.Fatalf("reserve: %d %v", status, doc)
	}
	setHotel(tc, "a", func(h *hotel) { h.ok, h.roomsUnchecked = true, false })
	tc.b.mu.Lock()
	tc.b.guests["g2"].cfg.Ops = true
	tc.b.mu.Unlock()
	tc.hotels["a"].createDelay = 800 * time.Millisecond
	done := make(chan int, 1)
	go func() {
		status, _ := tc.call(t, "key2", "POST", "/v1/broker/probe", map[string]any{})
		done <- status
	}()
	// The probe's room create has reached the hotel: it is mid-probe.
	pinWait(t, func() bool {
		f := tc.hotels["a"]
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, c := range f.calls {
			if strings.HasPrefix(c, "POST /v1/sandboxes") {
				return true
			}
		}
		return false
	})
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"pin_only": true}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("pin_only switched during a probe: %d %v", status, doc)
	}
	if s := <-done; s != 200 {
		t.Fatalf("probe: %d", s)
	}
	tc.b.mu.Lock()
	n := tc.b.hotelByID("a").claims
	tc.b.mu.Unlock()
	if n != 0 {
		t.Fatalf("probe left %d claims", n)
	}
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"pin_only": true}); status != 200 {
		t.Fatalf("switch after the probe: %d %v", status, doc)
	}
}

// Finding 2: a room the hotel returns after the client left (or one the
// tunables check rejects) is in h.rooms in the same b.mu hold that ends
// h.creating. A sampler that takes b.mu in a loop must never see the hotel
// with no creating, no rooms, and a create the hotel already answered.
func TestReapedRoomIsRegisteredWithTheEndOfCreating(t *testing.T) {
	for _, tunables := range []bool{false, true} {
		for i := 0; i < 60; i++ {
			tc := newChain(t)
			a := tc.b.hotelByID("a")
			setHotel(tc, "b", func(h *hotel) { h.ok = false })
			setHotel(tc, "c", func(h *hotel) { h.ok = false })
			tc.hotels["a"].createDelay = 15 * time.Millisecond
			body := []byte(`{"image":"alpine:3.20"}`)
			if tunables {
				body = []byte(`{"image":"alpine:3.20","tunables":{"x":1}}`)
			}
			ctx, cancel := context.WithCancel(context.Background())
			var stop, bad atomic.Bool
			var sampled sync.WaitGroup
			for k := 0; k < 8; k++ { // many waiters on b.mu: one gets it in the gap
				sampled.Add(1)
				go func() {
					defer sampled.Done()
					for !stop.Load() {
						f := tc.hotels["a"]
						f.mu.Lock()
						answered := len(f.creates) > 0
						f.mu.Unlock()
						tc.b.mu.Lock()
						if answered && a.creating == 0 && a.queued == 0 && len(a.rooms) == 0 {
							bad.Store(true)
						}
						tc.b.mu.Unlock()
					}
				}()
			}
			go func() { time.Sleep(5 * time.Millisecond); cancel() }()
			g := tc.b.guests["g1"]
			pl := placement{guest: "g1", ids: map[string]bool{"a": true}, image: "alpine:3.20"}
			res := tc.b.createOne(ctx, g, body, map[string]any{}, time.Now(), pl)
			stop.Store(true)
			sampled.Wait()
			cancel()
			if bad.Load() {
				t.Fatalf("tunables=%v run %d: the hotel looked empty after its create answered (status %d)", tunables, i, res.status)
			}
		}
	}
}

// Finding 3: zero rooms before the first good room list is unknown, not empty.
func TestPinOnlySwitchAndReferenceChangeRefuseWhileRoomsAreUnknown(t *testing.T) {
	tc := pinChain(t) // pin_only, generation 1
	change := map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1}
	for _, c := range []struct {
		name string
		set  func(h *hotel)
		undo func(h *hotel)
	}{
		{"restart: no room list yet", func(h *hotel) { h.roomsUnchecked = true }, func(h *hotel) { h.roomsUnchecked = false }},
		{"last room list failed", func(h *hotel) { h.listOK = false }, func(h *hotel) { h.listOK = true }},
		{"unconfirmed create cleanup", func(h *hotel) { h.unreaped = map[string]*unreapedBatch{"b1": {guest: "g2"}} }, func(h *hotel) { h.unreaped = nil }},
	} {
		setHotel(tc, "a", c.set)
		if status, doc := ownerPatch(t, tc, "a", change); status != 409 || errCode(doc) != "rooms_active" {
			t.Fatalf("%s: reference change: %d %v", c.name, status, doc)
		}
		wantReservation(t, getHotelDoc(t, tc, "a"), "g2", "owner:g2", 1)
		setHotel(tc, "a", c.undo)
	}
	// A real restart: the counters are empty and the hotel is unchecked.
	tc.start(t)
	if status, doc := ownerPatch(t, tc, "a", change); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("after restart: %d %v", status, doc)
	}
	// The switch is refused too: a plain reserved hotel, count unknown.
	if status, doc := ownerPatch(t, tc, "b", map[string]any{"reserved_for": "g1"}); status != 200 {
		t.Fatalf("reserve b: %d %v", status, doc)
	}
	if status, doc := patchHotelDoc(t, tc, "b", map[string]any{"pin_only": true}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("switch with unknown rooms: %d %v", status, doc)
	}
	markRoomsKnown(tc)
	if status, doc := ownerPatch(t, tc, "a", change); status != 200 {
		t.Fatalf("once known and empty: %d %v", status, doc)
	}
}

// Finding 4: pin_only and its fence are never acknowledged without a state_dir.
func TestPinOnlyNeedsADurableStateDir(t *testing.T) {
	tc := newChain(t) // no state_dir
	markRoomsKnown(tc)
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": "g2", "pin_only": true}); status != 409 || errCode(doc) != "no_state_dir" {
		t.Fatalf("pin_only without state_dir: %d %v", status, doc)
	}
	if tc.b.hotelByID("a").pinOnly() || tc.b.hotelByID("a").reservedFor() != "" {
		t.Fatal("an unsaved PATCH changed the hotel")
	}
	// A pin_only hotel that exists anyway takes no reservation change unsaved.
	setHotel(tc, "a", func(h *hotel) { h.cfg.ReservedFor, h.cfg.PinOnly = "g2", true })
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "x"}); status != 409 || errCode(doc) != "no_state_dir" {
		t.Fatalf("ref change without state_dir: %d %v", status, doc)
	}

	// The config file: pin_only needs state_dir at load and in -check-config.
	tc = knownChain(t)
	raw, _ := os.ReadFile(tc.cfgPath)
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.StateDir = ""
	c.Hotels[0].ReservedFor, c.Hotels[0].PinOnly = "g2", true
	raw, _ = json.Marshal(c)
	if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBroker(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "state_dir") {
		t.Fatalf("load: %v", err)
	}
	if err := checkConfigFile(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "state_dir") {
		t.Fatalf("-check-config: %v", err)
	}
	c.StateDir = t.TempDir()
	raw, _ = json.Marshal(c)
	if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkConfigFile(tc.cfgPath); err != nil {
		t.Fatalf("-check-config with a state_dir: %v", err)
	}
}

// Finding 5: a release (reserved_for null) is a reserved_for change: refused
// while creates, queued creates or claims are outstanding, and pin_only stays.
func TestReleaseIsRefusedWhileCreatesOrClaimsAreOutstanding(t *testing.T) {
	tc := pinChain(t)
	for _, field := range []string{"creating", "queued", "claims"} {
		setHotel(tc, "a", func(h *hotel) {
			switch field {
			case "creating":
				h.creating = 1
			case "queued":
				h.queued = 1
			default:
				h.claims = 1
			}
		})
		status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": nil})
		if status != 409 || errCode(doc) != "rooms_active" {
			t.Fatalf("%s: release: %d %v", field, status, doc)
		}
		if !tc.b.hotelByID("a").pinOnly() || tc.b.hotelByID("a").reservedFor() != "g2" {
			t.Fatalf("%s: a refused release changed the hotel", field)
		}
		// The same owner is no change and stays allowed.
		if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2"}); status != 200 {
			t.Fatalf("%s: same owner: %d %v", field, status, doc)
		}
		setHotel(tc, "a", func(h *hotel) { h.creating, h.queued, h.claims = 0, 0, 0 })
	}
	// An ordinary reserved hotel (not pin_only) is refused the same way, and
	// released once idle; its own rooms never blocked a release.
	if status, doc := ownerPatch(t, tc, "b", map[string]any{"reserved_for": "g1"}); status != 200 {
		t.Fatalf("reserve b: %d %v", status, doc)
	}
	setHotel(tc, "b", func(h *hotel) {
		h.claims = 1
		h.rooms["x1"] = &room{h: h, guest: "g1", hid: "x1", id: "b.x1", state: stRunning}
	})
	if status, doc := ownerPatch(t, tc, "b", map[string]any{"reserved_for": nil}); status != 409 {
		t.Fatalf("plain hotel, claim held: %d %v", status, doc)
	}
	setHotel(tc, "b", func(h *hotel) { h.claims = 0 })
	if status, doc := ownerPatch(t, tc, "b", map[string]any{"reserved_for": nil}); status != 200 {
		t.Fatalf("plain hotel, idle apart from its own room: %d %v", status, doc)
	}
	if status, doc := ownerPatch(t, tc, "a", map[string]any{"reserved_for": nil}); status != 200 || doc["pin_only"] != false {
		t.Fatalf("idle release: %d %v", status, doc)
	}
}

// Finding 6: the import decides and claims in one b.mu hold, on the hotel's
// ownership as it is then. (The gap between the old limitsAllow and the claim
// cannot be forced from outside; this pins the single-hold decision.)
func TestCompatImportClaimsOnlyWhereTheGuestMayPull(t *testing.T) {
	tc := pinChain(t)
	g1, g2 := tc.b.guests["g1"], tc.b.guests["g2"]
	a, b := tc.b.hotelByID("a"), tc.b.hotelByID("b")
	if _, ok := tc.b.claimForImport(g1, a); ok {
		t.Fatal("g1 may not pull on a hotel reserved for g2")
	}
	if _, ok := tc.b.claimForImport(g2, a); ok {
		t.Fatal("the owner's unmarked import must not pull on a pin_only hotel")
	}
	// b is idle and in the pool; reserve it for g2 and g1 loses it at once.
	if _, ok := tc.b.claimForImport(g1, b); !ok {
		t.Fatal("g1 should pull on a pool hotel")
	}
	tc.b.releaseClaim(b)
	if status, doc := ownerPatch(t, tc, "b", map[string]any{"reserved_for": "g2"}); status != 200 {
		t.Fatalf("reserve b: %d %v", status, doc)
	}
	if _, ok := tc.b.claimForImport(g1, b); ok {
		t.Fatal("g1 claimed a hotel just reserved for g2")
	}
	tc.b.mu.Lock()
	n := a.claims + b.claims
	tc.b.mu.Unlock()
	if n != 0 {
		t.Fatalf("claims left behind: %d", n)
	}
}

// Astra r2: a create whose reply is lost leaves a room the broker has not
// recorded yet. Until cleanup confirms it gone, the hotel's occupancy is
// unknown, so a same-owner reference change must wait.
func TestReferenceChangeWaitsForALostCreateToBeReaped(t *testing.T) {
	tc := pinChain(t) // generation 1
	ha := tc.b.hotelByID("a")
	upstream := ha.cfg.API
	gate := make(chan struct{})
	var held sync.Once
	reached := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		status, hdr, out := forwardTo(upstream, r, body)
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/sandboxes":
			hijackClose(w) // the hotel started the room; the reply never arrives
		case r.Method == "GET" && r.URL.Path == "/v1/sandboxes":
			held.Do(func() { close(reached) }) // the reap pass: pause it here
			<-gate
			passThrough(w, status, hdr, out)
		default:
			passThrough(w, status, hdr, out)
		}
	}))
	t.Cleanup(proxy.Close)
	setHotel(tc, "a", func(h *hotel) { h.cfg.API = proxy.URL })

	done := make(chan int, 1)
	go func() {
		status, _ := tc.callWith(t, "key2", dedMark(1), "POST", "/v1/sandboxes", dedBody())
		done <- status
	}()
	<-reached // reply lost, cleanup not finished
	change := map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1}
	status, doc := ownerPatch(t, tc, "a", change)
	if status != 409 || errCode(doc) != "rooms_active" {
		close(gate)
		t.Fatalf("reference change while the lost create is unresolved: %d %v", status, doc)
	}
	close(gate)
	if s := <-done; s != 502 {
		t.Fatalf("create: %d", s)
	}
	// Cleanup found the room gone, but an empty list proves absence only once
	// the create deadline has passed (Astra r3): the record is retained.
	if status, doc := ownerPatch(t, tc, "a", change); status != 409 {
		t.Fatalf("before the create deadline: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	for _, ub := range ha.unreaped {
		ub.holdUntil = time.Now().Add(-time.Second)
	}
	tc.b.mu.Unlock()
	tc.b.syncHotel(context.Background(), ha)
	status, doc = ownerPatch(t, tc, "a", change)
	if status != 200 {
		t.Fatalf("after the deadline and an empty list: %d %v", status, doc)
	}
	wantReservation(t, doc, "g2", "owner:g2:2", 2)
}

// Astra r3: an empty cleanup list proves nothing while the hotel may still be
// starting the create. The list answers empty, and only then does the hotel
// start the room; the reference change must wait until the create deadline has
// passed and a list asked after it shows no room.
func TestReferenceChangeWaitsPastAnEmptyCleanupListForALateRoom(t *testing.T) {
	tc := pinChain(t) // generation 1
	ha := tc.b.hotelByID("a")
	upstream := ha.cfg.API
	var mu sync.Mutex
	var heldCreate []byte
	var heldReq *http.Request
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/sandboxes":
			mu.Lock()
			heldCreate, heldReq = body, r.Clone(context.Background())
			mu.Unlock()
			hijackClose(w) // reply lost; the hotel has not started the room yet
		case r.Method == "GET" && r.URL.Path == "/v1/sandboxes":
			status, hdr, out := forwardTo(upstream, r, body) // the snapshot: empty
			mu.Lock()
			cb, cr := heldCreate, heldReq
			heldCreate = nil
			mu.Unlock()
			if cb != nil { // now the hotel starts the room
				forwardTo(upstream, cr, cb)
			}
			passThrough(w, status, hdr, out)
		default:
			status, hdr, out := forwardTo(upstream, r, body)
			passThrough(w, status, hdr, out)
		}
	}))
	t.Cleanup(proxy.Close)
	setHotel(tc, "a", func(h *hotel) { h.cfg.API = proxy.URL })

	if status, _ := tc.callWith(t, "key2", dedMark(1), "POST", "/v1/sandboxes", dedBody()); status != 502 {
		t.Fatalf("create with a lost reply: %d", status)
	}
	if n := len(tc.hotels["a"].creates); n != 1 {
		t.Fatalf("the hotel started %d rooms; want the late one", n)
	}
	change := map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1}
	if status, doc := ownerPatch(t, tc, "a", change); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("reference change after an empty list, room just appeared: %d %v", status, doc)
	}
	// A sync lists the room: it is a leftover, reaped, and the record stays.
	tc.b.syncHotel(context.Background(), ha)
	pinWait(t, func() bool { return callsTo(tc.hotels["a"], "DELETE /v1/sandboxes/") >= 1 })
	pinWait(t, func() bool {
		tc.b.mu.Lock()
		defer tc.b.mu.Unlock()
		for _, ub := range ha.unreaped {
			if ub.busy {
				return false
			}
		}
		return true
	})
	if status, doc := ownerPatch(t, tc, "a", change); status != 409 {
		t.Fatalf("reference change before the create deadline: %d %v", status, doc)
	}
	// The deadline passes; a list asked after it shows no room.
	tc.b.mu.Lock()
	for _, ub := range ha.unreaped {
		ub.holdUntil = time.Now().Add(-time.Second)
	}
	tc.b.mu.Unlock()
	tc.b.syncHotel(context.Background(), ha)
	if status, doc := ownerPatch(t, tc, "a", change); status != 200 {
		t.Fatalf("after the deadline and an empty list: %d %v", status, doc)
	}
}
