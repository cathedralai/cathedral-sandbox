package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The broker hold of a dedicated custom SNP guest (custom_guest_hold.go,
// AB#1008, spec r9 7.2 and 14.1 "Broker hold"). Hotels "a", "b" and "c" from
// the config file, each with the hotel secret routes; guests g1 (key1, the
// reservation guest: the platform guest, or the owner's direct guest on the
// self-serve path) and g2 (key2); a state_dir. Hotel "a" is reserved for g1
// under ref "order-1" at generation 1 and drained (H2).

const (
	holdLaunch = "cg-0123456789ab"
	holdRef    = "cg:" + holdLaunch + ":1"
)

type holdChain struct {
	*testChain
	sh  map[string]*secretHotel
	dir string
}

// newHoldChain builds the chain; fileDrainA is hotel a's drain in the config
// file. pinOnly: the platform path (pin_only on), else the self-serve path.
func newHoldChain(t *testing.T, pinOnly, fileDrainA bool) *holdChain {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "hotel.key")
	if err := os.WriteFile(key, []byte("hotel-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	hc := &holdChain{testChain: &testChain{hotels: map[string]*fakeHotel{}}, sh: map[string]*secretHotel{}, dir: filepath.Join(dir, "state")}
	cfg := config{StateDir: hc.dir, OperatorKeySHA256: sha("operator-key"), InsecureCookie: true,
		Guests: []guestConfig{{ID: "g1", KeySHA256: sha("key1")}, {ID: "g2", KeySHA256: sha("key2")}}}
	for _, id := range []string{"a", "b", "c"} {
		f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
		s := &secretHotel{fakeHotel: f, values: map[string]map[string]string{}}
		hs := httptest.NewServer(s)
		t.Cleanup(hs.Close)
		hc.hotels[id], hc.sh[id] = f, s
		cfg.Hotels = append(cfg.Hotels, hotelConfig{ID: id, Name: id, API: hs.URL, Health: hs.URL, KeyFile: key, Concurrency: 4, Sealed: true,
			SealedAdmission: sealedAdmissionOff, Drain: id == "a" && fileDrainA}) // AB#776, see newChainState
	}
	raw, _ := json.Marshal(cfg)
	hc.cfgPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(hc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	hc.start(t)
	markRoomsKnown(hc.testChain)
	body := map[string]any{"reserved_for": "g1", "reservation_ref": "order-1", "expect_generation": 0}
	if pinOnly {
		body["pin_only"] = true
	}
	if status, doc := patchHotelDoc(t, hc.testChain, "a", body); status != 200 {
		t.Fatalf("reserve a: %d %v", status, doc)
	}
	if status, doc := patchHotelDoc(t, hc.testChain, "a", map[string]any{"drain": true}); status != 200 {
		t.Fatalf("H2 drain: %d %v", status, doc)
	}
	return hc
}

// restart restarts the broker on the same config and state_dir; the rooms
// are unchecked again, as after a real restart.
func (hc *holdChain) restart(t *testing.T) { hc.start(t) }

func h3Body(gen int) map[string]any {
	return map[string]any{"reserved_for": "g1", "reservation_ref": holdRef,
		"custom_guest_hold": map[string]any{"launch": holdLaunch, "kit_down": false}, "expect_generation": gen}
}

func kitDownBody(gen int) map[string]any {
	return map[string]any{"custom_guest_hold": map[string]any{"launch": holdLaunch, "kit_down": true}, "expect_generation": gen}
}

func restoreBody(gen int) map[string]any {
	return map[string]any{"reserved_for": "g1", "reservation_ref": "order-1", "custom_guest_hold": nil, "drain": true, "expect_generation": gen}
}

func (hc *holdChain) patch(t *testing.T, body map[string]any) (int, map[string]any) {
	t.Helper()
	return patchHotelDoc(t, hc.testChain, "a", body)
}

func (hc *holdChain) mustPatch(t *testing.T, what string, body map[string]any) map[string]any {
	t.Helper()
	status, doc := hc.patch(t, body)
	if status != 200 {
		t.Fatalf("%s: %d %v", what, status, doc)
	}
	return doc
}

func (hc *holdChain) fence(t *testing.T) map[string]any {
	t.Helper()
	doc := hc.mustPatch(t, "H3", h3Body(1))
	wantHold(t, doc, holdLaunch, false)
	wantReservation(t, doc, "g1", holdRef, 2)
	return doc
}

func (hc *holdChain) kitDown(t *testing.T) {
	t.Helper()
	wantHold(t, hc.mustPatch(t, "H7", kitDownBody(2)), holdLaunch, true)
}

func wantHold(t *testing.T, doc map[string]any, launch string, kitDown bool) {
	t.Helper()
	v, ok := doc["custom_guest_hold"]
	if !ok {
		t.Fatalf("operator view has no custom_guest_hold key: %v", doc)
	}
	if launch == "" {
		if v != nil {
			t.Fatalf("custom_guest_hold %v, want null", v)
		}
		return
	}
	m, _ := v.(map[string]any)
	if m["launch"] != launch || m["kit_down"] != kitDown {
		t.Fatalf("custom_guest_hold %v, want launch %s kit_down %v", v, launch, kitDown)
	}
}

func wantRefused(t *testing.T, what string, status int, doc map[string]any, wantStatus int, code string) {
	t.Helper()
	if status != wantStatus || errCode(doc) != code {
		t.Fatalf("%s: %d %v, want %d %s", what, status, doc, wantStatus, code)
	}
}

func savedRecord(t *testing.T, dir string) map[string]reservationRecord {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, reservationsFile))
	if os.IsNotExist(err) {
		return nil
	}
	var out map[string]reservationRecord
	if err != nil || json.Unmarshal(raw, &out) != nil {
		t.Fatalf("%s: %v %s", reservationsFile, err, raw)
	}
	return out
}

func secretHotels(t *testing.T, out string) map[string]any {
	t.Helper()
	var doc map[string]any
	_ = json.Unmarshal([]byte(out), &doc)
	h, _ := doc["hotels"].(map[string]any)
	return h
}

func (hc *holdChain) secret(t *testing.T, method, name, value string) (int, string) {
	t.Helper()
	path, body := "/v1/secrets", ""
	if name != "" {
		path += "/" + name
	}
	if value != "" {
		body = `{"value":"` + value + `"}`
	}
	return secretCall(t, hc.srv.URL, "key1", method, path, body, nil)
}

// secretWithin is secret for a call that must not reach the paused hotel:
// one admitted there would wait for the gate, so the test fails instead of
// hanging.
func (hc *holdChain) secretWithin(t *testing.T, method, name, value string) (int, string) {
	t.Helper()
	type answer struct {
		status int
		out    string
	}
	ch := make(chan answer, 1)
	go func() {
		path, body := "/v1/secrets/"+name, ""
		if value != "" {
			body = `{"value":"` + value + `"}`
		}
		s, out := secretCallNoFatal(hc.srv.URL, "key1", method, path, body)
		ch <- answer{s, out}
	}()
	select {
	case a := <-ch:
		return a.status, a.out
	case <-time.After(5 * time.Second):
		t.Fatalf("%s %s waited for the held hotel: admission is not closed", method, name)
	}
	return 0, ""
}

// secretCallNoFatal is secretCall for a goroutine other than the test's.
func secretCallNoFatal(url, key, method, path, body string) (int, string) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, url+path, rd)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (hc *holdChain) hasSecret(id, name string) bool {
	s := hc.sh[id]
	s.smu.Lock()
	defer s.smu.Unlock()
	_, ok := s.values["g1"][name]
	return ok
}

func (hc *holdChain) setDown(id string, down bool) {
	s := hc.sh[id]
	s.smu.Lock()
	s.down = down
	s.smu.Unlock()
}

func (hc *holdChain) counts(t *testing.T) (secretCalls, claims int, closed string) {
	t.Helper()
	hc.b.mu.Lock()
	defer hc.b.mu.Unlock()
	h := hc.b.hotelByID("a")
	return h.secretCalls, h.claims, h.secretClosed
}

// pauseSecretCalls pauses every secret call admitted to hotel a until the
// returned release runs; admitted reports each admission.
func pauseSecretCalls(t *testing.T) (admitted chan struct{}, release func()) {
	t.Helper()
	gate := make(chan struct{})
	admitted = make(chan struct{}, 64)
	old := afterSecretAdmit
	afterSecretAdmit = func(id string) {
		if id == "a" {
			admitted <- struct{}{}
			<-gate
		}
	}
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(func() { release(); afterSecretAdmit = old })
	return admitted, release
}

func waitAdmitted(t *testing.T, admitted chan struct{}) {
	t.Helper()
	select {
	case <-admitted:
	case <-time.After(5 * time.Second):
		t.Fatal("no secret call admitted to a")
	}
}

// ---------------------------------------------------------------- H3

func TestHoldSetAtH3IsRefusedUnlessTheHotelIsKnownEmptyAndDrained(t *testing.T) {
	for _, pinOnly := range []bool{true, false} {
		name := "self-serve"
		if pinOnly {
			name = "platform"
		}
		t.Run(name, func(t *testing.T) {
			hc := newHoldChain(t, pinOnly, false)
			noGen := h3Body(1)
			delete(noGen, "expect_generation")
			status, doc := hc.patch(t, noGen)
			wantRefused(t, "without expect_generation", status, doc, 400, "invalid_json")
			status, doc = hc.patch(t, h3Body(0))
			wantRefused(t, "stale expect_generation", status, doc, 409, "reservation_conflict")

			hc.mustPatch(t, "undrain", map[string]any{"drain": false})
			status, doc = hc.patch(t, h3Body(1))
			wantRefused(t, "undrained", status, doc, 409, "owner_change_needs_drain")
			hc.mustPatch(t, "drain", map[string]any{"drain": true})

			for _, c := range []struct {
				what string
				set  func(h *hotel, v int)
			}{
				{"one room", func(h *hotel, v int) {
					if v > 0 {
						h.rooms["held-room"] = &room{}
					} else {
						delete(h.rooms, "held-room")
					}
				}},
				{"one create", func(h *hotel, v int) { h.creating = v }},
				{"one queued create", func(h *hotel, v int) { h.queued = v }},
				{"one claim", func(h *hotel, v int) { h.claims = v }},
			} {
				setHotel(hc.testChain, "a", func(h *hotel) { c.set(h, 1) })
				status, doc = hc.patch(t, h3Body(1))
				wantRefused(t, c.what, status, doc, 409, "rooms_active")
				setHotel(hc.testChain, "a", func(h *hotel) { c.set(h, 0) })
			}
			// Zero rooms with no good room list is unknown, not empty, on a
			// hotel that is not pin_only too.
			setHotel(hc.testChain, "a", func(h *hotel) { h.listOK = false })
			status, doc = hc.patch(t, h3Body(1))
			wantRefused(t, "unknown occupancy", status, doc, 409, "rooms_active")
			setHotel(hc.testChain, "a", func(h *hotel) { h.listOK = true })
			wantHold(t, getHotelDoc(t, hc.testChain, "a"), "", false)
			wantReservation(t, getHotelDoc(t, hc.testChain, "a"), "g1", "order-1", 1)

			doc = hc.fence(t)
			if doc["drain"] != true {
				t.Fatalf("held hotel drain %v", doc["drain"])
			}
			if r := savedRecord(t, hc.dir)["a"]; r.CustomGuestHold == nil || *r.CustomGuestHold != (customGuestHold{Launch: holdLaunch}) || r.Ref != holdRef || r.Generation != 2 {
				t.Fatalf("saved record %+v", r)
			}
			// The same hold again at the current generation: 200, no change.
			doc = hc.mustPatch(t, "same body again", h3Body(2))
			wantReservation(t, doc, "g1", holdRef, 2)
			wantHold(t, doc, holdLaunch, false)
			// Another launch's hold.
			other := h3Body(2)
			other["custom_guest_hold"] = map[string]any{"launch": "cg-ffffffffffff", "kit_down": false}
			status, doc = hc.patch(t, other)
			wantRefused(t, "another launch", status, doc, 409, "custom_guest_hold_conflict")
		})
	}
}

func TestHoldIsRefusedOnAJoinedHotelAndWhenMalformed(t *testing.T) {
	hc := newHoldChain(t, true, false)
	setHotel(hc.testChain, "c", func(h *hotel) { h.runtime = true })
	status, doc := patchHotelDoc(t, hc.testChain, "c", map[string]any{"custom_guest_hold": map[string]any{"launch": holdLaunch, "kit_down": false}, "expect_generation": 0})
	wantRefused(t, "joined hotel", status, doc, 409, "custom_guest_hold_unsupported")
	setHotel(hc.testChain, "c", func(h *hotel) { h.runtime = false })
	for _, bad := range []any{map[string]any{"launch": "cg-0123"}, map[string]any{"launch": "order-1", "kit_down": false}, "held"} {
		status, doc = hc.patch(t, map[string]any{"custom_guest_hold": bad, "expect_generation": 1})
		wantRefused(t, "malformed hold", status, doc, 400, "invalid_json")
	}
}

// ---------------------------------------------------------------- while set

func TestAHeldHotelRefusesEveryTupleLendPinOnlyAndUndrainChange(t *testing.T) {
	hc := newHoldChain(t, true, false)
	hc.fence(t)
	for _, c := range []struct {
		what string
		body map[string]any
	}{
		{"reserved_for", map[string]any{"reserved_for": "g2"}},
		{"release", map[string]any{"reserved_for": nil}},
		{"reservation_ref", map[string]any{"reserved_for": "g1", "reservation_ref": "order-2"}},
		{"lend", map[string]any{"lend": true}},
		{"pin_only off", map[string]any{"pin_only": false}},
		{"drain false", map[string]any{"drain": false}},
		{"drain false with the generation", map[string]any{"drain": false, "expect_generation": 2}},
	} {
		status, doc := hc.patch(t, c.body)
		wantRefused(t, c.what, status, doc, 409, "custom_guest_held")
	}
	// drain true and fields the hold does not cover still apply.
	hc.mustPatch(t, "drain true", map[string]any{"drain": true})
	hc.mustPatch(t, "max_slots", map[string]any{"max_slots": 3})
	// kit_down true never goes back.
	hc.kitDown(t)
	status, doc := hc.patch(t, h3Body(2))
	wantRefused(t, "kit_down back to false", status, doc, 409, "custom_guest_held")
	// A clear needs drain true in the same request.
	noDrain := restoreBody(2)
	delete(noDrain, "drain")
	status, doc = hc.patch(t, noDrain)
	wantRefused(t, "clear without drain", status, doc, 400, "invalid_hotel")
	// The restoring PATCH passes.
	doc = hc.mustPatch(t, "restore", restoreBody(2))
	wantHold(t, doc, "", false)
	wantReservation(t, doc, "g1", "order-1", 3)
	if r := savedRecord(t, hc.dir)["a"]; r.CustomGuestHold != nil || r.Ref != "order-1" {
		t.Fatalf("saved record after the restore %+v", r)
	}
}

func TestHeldHotelDrainSurvivesAReloadAndTheDirectGuestPlacesNothing(t *testing.T) {
	// Self-serve path: the owner's direct guest g1 can reach a. The file
	// drains a (H2), a reload then undrains it in the file.
	for _, held := range []bool{true, false} {
		hc := newHoldChain(t, false, true)
		if held {
			hc.fence(t)
		}
		status, doc := reloadChainFile(t, hc.testChain, func(c *config) { c.Hotels[0].Drain = false })
		if status != 200 {
			t.Fatalf("reload: %d %v", status, doc)
		}
		h := hc.b.hotelByID("a")
		if h.cfgDrain() || h.drain() != held {
			t.Fatalf("held %v: cfg drain %v, drain() %v", held, h.cfgDrain(), h.drain())
		}
		before := createsOn(hc.testChain)["a"]
		status, doc = hc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
		placed := createsOn(hc.testChain)["a"] - before
		if held && (status == 202 || placed != 0) {
			t.Fatalf("held hotel took a direct-guest create: %d %v", status, doc)
		}
		if !held && (status != 202 || placed != 1) {
			t.Fatalf("positive control: undrained hotel took no create: %d %v (placed %d)", status, doc, placed)
		}
	}
}

// reloadChainFile edits the config file and reloads it live.
func reloadChainFile(t *testing.T, tc *testChain, fn func(c *config)) (int, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	fn(&c)
	raw, _ = json.Marshal(c)
	if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return tc.call(t, "operator-key", "POST", "/v1/broker/config/reload", map[string]string{"sha256": sha(string(raw))})
}

func TestHeldHotelTakesNoClaimFromPrewarmReplayPrefetchOrImport(t *testing.T) {
	hc := newHoldChain(t, false, false)
	hc.fence(t)
	check := func(when string) {
		t.Helper()
		a := hc.b.hotelByID("a")
		setHotel(hc.testChain, "a", func(h *hotel) {
			hc.b.cfg.PrewarmCatalog = true
			h.guestWant = map[string]map[string]time.Time{"g1": {guestImage: time.Now()}}
		})
		hc.b.prewarmHotel(a)
		hc.b.replayGuestPrefetch(a)
		g := hc.b.guestByID("g1")
		if _, ok := hc.b.claimForImport(g, a); ok {
			t.Fatalf("%s: image import took a claim on the held hotel", when)
		}
		status, doc := hc.call(t, "key1", "POST", "/v1/images/prefetch", map[string]any{"images": []string{"alpine:3.20"}, "hotels": []string{"a"}})
		hc.hotels["a"].mu.Lock()
		pulls := len(hc.hotels["a"].prefetch)
		hc.hotels["a"].mu.Unlock()
		if pulls != 0 {
			t.Fatalf("%s: %d pulls reached the held hotel (prefetch answer %d %v)", when, pulls, status, doc)
		}
		if _, claims, _ := hc.counts(t); claims != 0 {
			t.Fatalf("%s: claims %d", when, claims)
		}
	}
	check("after H3")
	hc.restart(t) // the come-up schedules both again
	check("after a restart while held")

	// restart-check reports the claim count; restart_ok does not use it.
	setHotel(hc.testChain, "a", func(h *hotel) { h.claims = 2 })
	_, doc := hc.call(t, "operator-key", "GET", "/v1/broker/hotels/a/restart-check", nil)
	c, _ := doc["check"].(map[string]any)
	if c == nil {
		c = doc
	}
	if c["claims"] != float64(2) {
		t.Fatalf("restart-check claims: %v", doc)
	}
	setHotel(hc.testChain, "a", func(h *hotel) { h.claims = 0 })
}

// ---------------------------------------------------------------- H7

func TestKitDownNeedsNoRoomListButNoCountedWork(t *testing.T) {
	hc := newHoldChain(t, true, false)
	hc.fence(t)
	// The kit stopped: the room list fails.
	setHotel(hc.testChain, "a", func(h *hotel) { h.listOK, h.ok = false, false })
	status, doc := hc.patch(t, map[string]any{"custom_guest_hold": map[string]any{"launch": "cg-ffffffffffff", "kit_down": true}, "expect_generation": 2})
	wantRefused(t, "another launch", status, doc, 409, "custom_guest_hold_conflict")
	status, doc = hc.patch(t, kitDownBody(1))
	wantRefused(t, "changed generation", status, doc, 409, "reservation_conflict")
	for _, c := range []struct {
		what string
		set  func(h *hotel, v int)
	}{
		{"a create", func(h *hotel, v int) { h.creating = v }},
		{"a queued create", func(h *hotel, v int) { h.queued = v }},
		{"a claim", func(h *hotel, v int) { h.claims = v }},
	} {
		setHotel(hc.testChain, "a", func(h *hotel) { c.set(h, 1) })
		status, doc = hc.patch(t, kitDownBody(2))
		wantRefused(t, c.what, status, doc, 409, "rooms_active")
		setHotel(hc.testChain, "a", func(h *hotel) { c.set(h, 0) })
	}
	hc.kitDown(t)
	if r := savedRecord(t, hc.dir)["a"]; r.CustomGuestHold == nil || !r.CustomGuestHold.KitDown || r.Generation != 2 {
		t.Fatalf("saved record %+v", r)
	}
	hc.mustPatch(t, "kit_down again", kitDownBody(2))
}

func TestKitDownAfterABrokerRestartWithRoomsUnchecked(t *testing.T) {
	hc := newHoldChain(t, true, false)
	hc.fence(t)
	// A crash between H6 and H7, then a broker restart: rooms unchecked.
	hc.restart(t)
	setHotel(hc.testChain, "a", func(h *hotel) { h.ok = false })
	if h := hc.b.hotelByID("a"); !h.roomsUnchecked {
		t.Fatal("restart left the rooms checked")
	}
	wantHold(t, getHotelDoc(t, hc.testChain, "a"), holdLaunch, false)
	hc.kitDown(t)
	// A lost hold (a record dropped) is set again by the same kit_down.
	setHotel(hc.testChain, "a", func(h *hotel) { h.cfgMu.Lock(); h.cfg.CustomGuestHold = nil; h.cfgMu.Unlock() })
	hc.kitDown(t)
}

func TestKitDownWaitsForASecretCallAdmittedBeforeIt(t *testing.T) {
	hc := newHoldChain(t, true, false)
	hc.fence(t)
	admitted, release := pauseSecretCalls(t)
	type answer struct {
		status int
		out    string
	}
	put := make(chan answer, 1)
	go func() {
		s, out := hc.secret(t, "PUT", "PIP_TOKEN", testSecretValue)
		put <- answer{s, out}
	}()
	waitAdmitted(t, admitted)
	// The kit stops while the PUT waits before its send.
	hc.setDown("a", true)
	for i := 0; i < 3; i++ {
		status, doc := hc.patch(t, kitDownBody(2))
		wantRefused(t, "H7 with a PUT in flight", status, doc, 409, "secret_calls_in_flight")
	}
	if n, _, closed := hc.counts(t); n != 1 || closed != holdLaunch {
		t.Fatalf("in flight %d, closed %q", n, closed)
	}
	release()
	a := <-put
	if hotels := secretHotels(t, a.out); hotels["a"] == "done" {
		t.Fatalf("the paused PUT landed on the stopped kit: %s", a.out)
	}
	if n, _, _ := hc.counts(t); n != 0 {
		t.Fatalf("in flight after the PUT ended: %d", n)
	}
	hc.kitDown(t)
	if s, out := hc.secret(t, "DELETE", "PIP_TOKEN", ""); s != 204 { // a counts as not found
		t.Fatalf("DELETE after kit_down: %d %s", s, out)
	}
	// The return: the kit is back with an empty store, the hold is cleared.
	hc.setDown("a", false)
	hc.mustPatch(t, "restore", restoreBody(2))
	if hc.hasSecret("a", "PIP_TOKEN") {
		t.Fatal("the restarted kit holds the PUT's value")
	}
}

func TestKitDownClosesSecretAdmissionUnderAStreamOfCalls(t *testing.T) {
	hc := newHoldChain(t, true, false)
	for _, id := range []string{"b", "c"} {
		hc.sh[id].values["g1"] = map[string]string{"OLD_1": "v", "OLD_2": "v", "OLD_3": "v"}
	}
	hc.fence(t)
	admitted, release := pauseSecretCalls(t) // the stopped kit drops SYNs: each call takes its full timeout
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); hc.secret(t, "PUT", "EARLY", testSecretValue) }()
	waitAdmitted(t, admitted)

	// Control: with admission still open, a new call is admitted too, so a
	// stream of them would keep the count above 0 for ever.
	wg.Add(1)
	go func() { defer wg.Done(); hc.secret(t, "PUT", "SECOND", testSecretValue) }()
	waitAdmitted(t, admitted)
	if n, _, _ := hc.counts(t); n != 2 {
		t.Fatalf("control: in flight %d, want 2", n)
	}

	status, doc := hc.patch(t, kitDownBody(2))
	wantRefused(t, "first H7 attempt", status, doc, 409, "secret_calls_in_flight")
	// Admission is closed: the stream's calls answer at once, no call to a.
	for i, name := range []string{"OLD_1", "OLD_2", "OLD_3"} {
		s, out := hc.secretWithin(t, "DELETE", name, "")
		if s != 502 || !strings.Contains(out, "secrets_partial") || secretHotels(t, out)["a"] != "unreachable" {
			t.Fatalf("DELETE %d in the closed window: %d %s", i, s, out)
		}
		if s, out := hc.secretWithin(t, "PUT", "NEW", testSecretValue); secretHotels(t, out)["a"] != "unreachable" {
			t.Fatalf("PUT in the closed window: %d %s", s, out)
		}
		if n, _, _ := hc.counts(t); n != 2 {
			t.Fatalf("in flight %d after a closed-window call, want 2", n)
		}
	}
	hc.setDown("a", true)
	release()
	wg.Wait()
	hc.kitDown(t)
	// After kit_down the skipped hotel counts as not found: the DELETEs the
	// ledger kept are now confirmed.
	hc.sh["b"].smu.Lock()
	hc.sh["b"].values["g1"]["OLD_1"] = "v"
	hc.sh["b"].smu.Unlock()
	if s, out := hc.secret(t, "DELETE", "OLD_1", ""); s != 204 {
		t.Fatalf("DELETE after kit_down: %d %s", s, out)
	}
}

func TestABrokerRestartInTheClosedWindowOpensAdmissionAndH7PassesAgain(t *testing.T) {
	hc := newHoldChain(t, true, false)
	hc.fence(t)
	admitted, release := pauseSecretCalls(t)
	done := make(chan struct{})
	go func() { defer close(done); hc.secret(t, "PUT", "EARLY", testSecretValue) }()
	waitAdmitted(t, admitted)
	status, doc := hc.patch(t, kitDownBody(2))
	wantRefused(t, "H7 before the restart", status, doc, 409, "secret_calls_in_flight")
	// The stopped kit fails the call; the test server's Close waits for it.
	hc.setDown("a", true)
	release()
	<-done
	if _, _, closed := hc.counts(t); closed != holdLaunch {
		t.Fatalf("closure before the restart %q", closed)
	}
	hc.restart(t)
	if n, _, closed := hc.counts(t); n != 0 || closed != "" {
		t.Fatalf("after the restart: in flight %d, closed %q", n, closed)
	}
	if s, out := hc.secret(t, "PUT", "OPEN_AGAIN", testSecretValue); secretHotels(t, out)["a"] != "failed" {
		t.Fatalf("restart did not open admission: %d %s", s, out)
	}
	hc.kitDown(t)
}

// ---------------------------------------------------------------- secrets

func TestKitDownDeleteCountsTheHeldHotelAsNotFound(t *testing.T) {
	for _, held := range []bool{true, false} {
		hc := newHoldChain(t, true, false)
		for _, id := range []string{"a", "b"} {
			hc.sh[id].values["g1"] = map[string]string{"BOTH": "v"}
		}
		hc.sh["a"].values["g1"]["ONLY_A"] = "v"
		hc.fence(t)
		hc.setDown("a", true) // the kit stopped
		if held {
			hc.kitDown(t)
		}
		s, out := hc.secret(t, "DELETE", "BOTH", "")
		if held && (s != 204 || hc.hasSecret("b", "BOTH")) {
			t.Fatalf("DELETE with kit_down: %d %s", s, out)
		}
		if !held && (s != 502 || !strings.Contains(out, "secrets_partial")) {
			t.Fatalf("positive control, kit stopped without kit_down: %d %s", s, out)
		}
		s, out = hc.secret(t, "DELETE", "ONLY_A", "")
		if held && (s != 404 || secretHotels(t, out)["a"] != "not_found") {
			t.Fatalf("DELETE of a name only on the held hotel: %d %s", s, out)
		}
	}
}

func TestPutAndListSkipAKitDownHotelAndReachItAfterTheClear(t *testing.T) {
	hc := newHoldChain(t, true, false)
	hc.fence(t)
	hc.kitDown(t)
	s, out := hc.secret(t, "PUT", "PIP_TOKEN", testSecretValue)
	if h := secretHotels(t, out); s != 200 || h["a"] != nil || h["b"] != "done" || hc.hasSecret("a", "PIP_TOKEN") {
		t.Fatalf("PUT with kit_down: %d %s", s, out)
	}
	hc.sh["a"].smu.Lock()
	n := len(hc.sh["a"].headers)
	hc.sh["a"].smu.Unlock()
	s, out = hc.secret(t, "GET", "", "")
	hc.sh["a"].smu.Lock()
	reached := len(hc.sh["a"].headers) - n
	hc.sh["a"].smu.Unlock()
	if s != 200 || strings.Contains(out, `"a"`) || reached != 0 {
		t.Fatalf("list with kit_down: %d %s (calls to a: %d)", s, out, reached)
	}
	hc.mustPatch(t, "restore", restoreBody(2))
	if s, out := hc.secret(t, "PUT", "PIP_TOKEN", testSecretValue); s != 200 || secretHotels(t, out)["a"] != "done" || !hc.hasSecret("a", "PIP_TOKEN") {
		t.Fatalf("PUT after the clear: %d %s", s, out)
	}
}

func TestADeleteBeforeKitDownReachesTheRunningKit(t *testing.T) {
	hc := newHoldChain(t, true, false)
	hc.sh["a"].values["g1"] = map[string]string{"PIP_TOKEN": "v"}
	hc.fence(t)
	if s, out := hc.secret(t, "PUT", "OTHER", testSecretValue); s != 200 || secretHotels(t, out)["a"] != "done" {
		t.Fatalf("PUT between H3 and H6: %d %s", s, out)
	}
	if s, out := hc.secret(t, "DELETE", "PIP_TOKEN", ""); s != 204 || hc.hasSecret("a", "PIP_TOKEN") {
		t.Fatalf("DELETE between H3 and H6: %d %s", s, out)
	}
	hc.mustPatch(t, "abort restore", restoreBody(2))
	if _, out := hc.secret(t, "GET", "", ""); strings.Contains(out, "PIP_TOKEN") {
		t.Fatalf("the kit lists the deleted name after the abort: %s", out)
	}
}

func TestAFailedRestoreSaveRollsBackBeforeAWaitingPutReadsTheHold(t *testing.T) {
	for _, saveFails := range []bool{true, false} {
		hc := newHoldChain(t, true, false)
		hc.fence(t)
		hc.kitDown(t)
		paused, resume := make(chan struct{}), make(chan struct{})
		oldHook, oldSync := beforeHotelPatchSave, durableSync
		beforeHotelPatchSave = func(id string) {
			if id == "a" {
				close(paused)
				<-resume
			}
		}
		if saveFails {
			durableSync = func(f *os.File) error { return os.ErrPermission }
		}
		patched := make(chan int, 1)
		go func() { s, _ := hc.patch(t, restoreBody(2)); patched <- s }()
		<-paused
		type answer struct {
			status int
			out    string
		}
		put := make(chan answer, 1)
		go func() { s, out := hc.secret(t, "PUT", "PIP_TOKEN", testSecretValue); put <- answer{s, out} }()
		time.Sleep(200 * time.Millisecond) // the PUT waits for b.mu, which the PATCH holds
		close(resume)
		s := <-patched
		durableSync = oldSync
		beforeHotelPatchSave = oldHook
		a := <-put
		reached := secretHotels(t, a.out)["a"] != nil || hc.hasSecret("a", "PIP_TOKEN")
		if saveFails {
			if s != 500 || reached {
				t.Fatalf("failed save: PATCH %d, PUT %s (reached a %v)", s, a.out, reached)
			}
			wantHold(t, getHotelDoc(t, hc.testChain, "a"), holdLaunch, true)
			if s, out := hc.secret(t, "DELETE", "PIP_TOKEN", ""); s != 204 {
				t.Fatalf("DELETE after the rolled-back clear: %d %s", s, out)
			}
			hc.mustPatch(t, "restore after the failed save", restoreBody(2))
			if hc.hasSecret("a", "PIP_TOKEN") {
				t.Fatal("the kit holds the name after the return")
			}
		} else if s != 200 || !reached {
			t.Fatalf("saved clear: PATCH %d, PUT %s (reached a %v)", s, a.out, reached)
		}
	}
}

// ---------------------------------------------------------------- persistence

func TestTheClearingPatchSavesDrainTrueAfterAReloadUndrainedTheFile(t *testing.T) {
	for _, drainBefore := range []bool{true, false} {
		hc := newHoldChain(t, true, drainBefore)
		if !drainBefore {
			// The file must say true before a reload can set it false.
			if s, doc := reloadChainFile(t, hc.testChain, func(c *config) { c.Hotels[0].Drain = true }); s != 200 {
				t.Fatalf("reload: %d %v", s, doc)
			}
		}
		hc.fence(t)
		if s, doc := reloadChainFile(t, hc.testChain, func(c *config) { c.Hotels[0].Drain = false }); s != 200 {
			t.Fatalf("reload: %d %v", s, doc)
		}
		if h := hc.b.hotelByID("a"); h.cfgDrain() || !h.drain() {
			t.Fatalf("after the reload: cfg drain %v drain() %v", h.cfgDrain(), h.drain())
		}
		// The restore: the drain the file set is false, so a pin_only owner
		// change waits for a real drain first (owner_change_needs_drain).
		s, doc := hc.patch(t, restoreBody(2))
		wantRefused(t, "restore on an undrained hotel", s, doc, 409, "owner_change_needs_drain")
		hc.mustPatch(t, "drain", map[string]any{"drain": true})
		doc = hc.mustPatch(t, "restore", restoreBody(2))
		if doc["drain"] != true {
			t.Fatalf("restore answer drain %v", doc["drain"])
		}
		raw, _ := os.ReadFile(filepath.Join(hc.dir, drainsFile))
		if !strings.Contains(string(raw), `"drain": true`) {
			t.Fatalf("%s: %s", drainsFile, raw)
		}
		// A crash before the drain-restore step, then a restart: still drained.
		hc.restart(t)
		markRoomsKnown(hc.testChain)
		if h := hc.b.hotelByID("a"); !h.drain() {
			t.Fatal("restart reopened the hotel")
		}
		doc = hc.mustPatch(t, "drain restore", map[string]any{"drain": drainBefore})
		if doc["drain"] != drainBefore {
			t.Fatalf("drain after the restore step %v, want %v", doc["drain"], drainBefore)
		}
	}
}

func TestTheHoldSurvivesARestartAndASwapInBothStates(t *testing.T) {
	for _, kitDown := range []bool{false, true} {
		hc := newHoldChain(t, true, false)
		hc.fence(t)
		if kitDown {
			hc.kitDown(t)
		}
		hc.restart(t)
		wantHold(t, getHotelDoc(t, hc.testChain, "a"), holdLaunch, kitDown)
		// A swap that captured its config before the hold: an unrelated guest
		// key and the platform guest's policy differ.
		editConfig(t, hc.testChain, func(c *config) {
			c.Guests[1].KeySHA256 = sha("key2-next")
			c.Guests[0].Policy = &guestPolicy{Allow: []selector{{Class: classSealed}}, Deny: []selector{{Label: map[string]string{"miner": "true"}}}}
		})
		doc := getHotelDoc(t, hc.testChain, "a")
		wantHold(t, doc, holdLaunch, kitDown)
		wantReservation(t, doc, "g1", holdRef, 2)
		if doc["drain"] != true {
			t.Fatalf("held hotel drain after the swap %v", doc["drain"])
		}
		s, out := hc.secret(t, "PUT", "PIP_TOKEN", testSecretValue)
		if got := secretHotels(t, out)["a"]; kitDown == (got != nil) {
			t.Fatalf("kit_down %v: PUT after the swap %d %s", kitDown, s, out)
		}
	}
}

func TestAHoldKeepsItsReservationBaselineWhenTheFileChanges(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	hc := newHoldChain(t, true, false) // saved with config_reserved_for ""
	hc.fence(t)
	editConfig(t, hc.testChain, func(c *config) { c.Hotels[0].ReservedFor = "g2" })
	doc := getHotelDoc(t, hc.testChain, "a")
	wantHold(t, doc, holdLaunch, false)
	wantReservation(t, doc, "g1", holdRef, 2)
	if !strings.Contains(logs.String(), "HOLD KEPT: hotel a") {
		t.Fatalf("no OPS alert for the kept record: %s", logs.String())
	}
	if r := savedRecord(t, hc.dir)["a"]; r.ConfigReservedFor != "" {
		t.Fatalf("baseline moved to %q", r.ConfigReservedFor)
	}
	markRoomsKnown(hc.testChain)
	hc.mustPatch(t, "R12 restore", restoreBody(2))
	if r := savedRecord(t, hc.dir)["a"]; r.ConfigReservedFor != "" || r.CustomGuestHold != nil {
		t.Fatalf("record after the restore %+v", r)
	}
	hc.restart(t)
	wantReservation(t, getHotelDoc(t, hc.testChain, "a"), "g2", nil, 4)
}

func TestAFailedHoldSaveLeavesNoHoldAndNoFileOrJoinCanSetOne(t *testing.T) {
	hc := newHoldChain(t, true, false)
	old := durableSync
	durableSync = func(f *os.File) error { return os.ErrPermission }
	s, doc := hc.patch(t, h3Body(1))
	durableSync = old
	wantRefused(t, "H3 with a failing save", s, doc, 500, "state_write_failed")
	doc = getHotelDoc(t, hc.testChain, "a")
	wantHold(t, doc, "", false)
	wantReservation(t, doc, "g1", "order-1", 1)
	if r := savedRecord(t, hc.dir)["a"]; r.CustomGuestHold != nil {
		t.Fatalf("hold on disk after a failed save: %+v", r)
	}
	hc.restart(t)
	wantHold(t, getHotelDoc(t, hc.testChain, "a"), "", false)

	// The config file cannot carry it.
	raw, _ := os.ReadFile(hc.cfgPath)
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Hotels[1].CustomGuestHold = &customGuestHold{Launch: holdLaunch}
	bad, _ := json.Marshal(c)
	badPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(badPath, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBroker(badPath); err == nil || !strings.Contains(err.Error(), "custom_guest_hold") {
		t.Fatalf("config file with custom_guest_hold: %v", err)
	}
	if err := checkConfigFile(badPath); err == nil || !strings.Contains(err.Error(), "custom_guest_hold") {
		t.Fatalf("-check-config passed custom_guest_hold: %v", err)
	}
	if s, doc := reloadChainFile(t, hc.testChain, func(c *config) { c.Hotels[1].CustomGuestHold = &customGuestHold{Launch: holdLaunch} }); s == 200 {
		t.Fatalf("reload with custom_guest_hold: %d %v", s, doc)
	}
	// Nor a join.
	s, doc = hc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "j1", "api": "http://192.0.2.10:8080", "sealed": true, "key": "k",
		"custom_guest_hold": map[string]any{"launch": holdLaunch, "kit_down": false}})
	wantRefused(t, "join with custom_guest_hold", s, doc, 400, "invalid_hotel")
}

func TestTheOperatorViewAlwaysCarriesTheHoldKey(t *testing.T) {
	hc := newHoldChain(t, true, false)
	wantHold(t, getHotelDoc(t, hc.testChain, "b"), "", false)
	hc.fence(t)
	wantHold(t, getHotelDoc(t, hc.testChain, "a"), holdLaunch, false)
	_, doc := hc.call(t, "key1", "GET", "/v1/broker/hotels", nil)
	raw, _ := json.Marshal(doc)
	if strings.Contains(string(raw), "custom_guest_hold") {
		t.Fatalf("guest view carries the hold: %s", raw)
	}
}

// Astra on 71f6702 (P1): the operator read-back must never show a tuple a
// failed save later undoes. Two H3 copies carry expect_generation G; one
// moves the hotel to G+1 in memory, then its save fails and rolls back. A GET
// in that window must answer G with no hold, never G+1 with no hold, or the
// API's retry fence (settle_unresolved) clears its guard while the delayed
// copy can still match G.
func TestTheOperatorReadBackNeverShowsATupleAFailedSaveUndoes(t *testing.T) {
	for _, saveFails := range []bool{true, false} {
		hc := newHoldChain(t, true, false)
		paused, resume := make(chan struct{}), make(chan struct{})
		oldHook, oldSync := beforeHotelPatchSave, durableSync
		beforeHotelPatchSave = func(id string) {
			if id == "a" {
				close(paused)
				<-resume
			}
		}
		if saveFails {
			durableSync = func(f *os.File) error { return os.ErrPermission }
		}
		patched := make(chan int, 1)
		go func() { s, _ := hc.patch(t, h3Body(1)); patched <- s }()
		<-paused // G+1 and the hold are in memory, not saved
		read := make(chan map[string]any, 1)
		go func() {
			_, doc := hc.call(t, "operator-key", "GET", "/v1/broker/hotels/a", nil)
			read <- doc
		}()
		time.Sleep(200 * time.Millisecond) // the GET runs while the PATCH holds the save
		close(resume)
		s := <-patched
		durableSync, beforeHotelPatchSave = oldSync, oldHook
		doc := <-read
		if saveFails {
			if s != 500 {
				t.Fatalf("failed save: PATCH %d", s)
			}
			wantReservation(t, doc, "g1", "order-1", 1)
			wantHold(t, doc, "", false)
			// The delayed copy with G then wins, as it must: nothing was saved.
			hc.fence(t)
			continue
		}
		if s != 200 {
			t.Fatalf("saved H3: PATCH %d", s)
		}
		wantReservation(t, doc, "g1", holdRef, 2)
		wantHold(t, doc, holdLaunch, false)
	}
}
