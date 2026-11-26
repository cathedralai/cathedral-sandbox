package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// pin_only (pin_only.go, AB#982 Track A). Hotels "a", "b", "c" from
// newChainState; guests g1 (key1) and g2 (key2). Hotel "a" is reserved for g2
// and pin_only: g2 plays the platform guest P.

const dedHeader = dedicatedHotelHeader

func pinChain(t *testing.T) *testChain {
	t.Helper()
	tc := newChainState(t, t.TempDir())
	status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2", "pin_only": true})
	if status != 200 || doc["pin_only"] != true {
		t.Fatalf("pin a: %d %v", status, doc)
	}
	wantReservation(t, doc, "g2", "owner:g2", 1)
	// A reserved hotel takes no room before its first room list (lend.go).
	setHotel(tc, "a", func(h *hotel) { h.roomsUnchecked = false })
	return tc
}

// callWith is tc.call plus request headers.
func (tc *testChain) callWith(t *testing.T, key string, hdr map[string]string, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, tc.srv.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+key)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, doc
}

func dedBody() map[string]any {
	return map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}, "placement": "require"}
}

func dedMark(gen int) map[string]string {
	return map[string]string{dedHeader: "a;gen=" + string(rune('0'+gen))}
}

func hotelGen(tc *testChain, id string) uint64 {
	_, gen := tc.b.hotelByID(id).pinState()
	return gen
}

func TestPinOnlyMarkerAcceptedOnlyFromTheOwnerWithTheExactBody(t *testing.T) {
	tc := pinChain(t)
	before := createsOn(tc)
	bad := []struct {
		name string
		key  string
		hdr  map[string]string
		body map[string]any
	}{
		{"not the owner", "key1", dedMark(1), dedBody()},
		{"two hotels", "key2", dedMark(1), map[string]any{"image": "alpine:3.20", "hotels": []string{"a", "b"}, "placement": "require"}},
		{"other hotel in body", "key2", dedMark(1), map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "placement": "require"}},
		{"placement prefer", "key2", dedMark(1), map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}, "placement": "prefer"}},
		{"no placement", "key2", dedMark(1), map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}}},
		{"not pin_only", "key2", map[string]string{dedHeader: "b;gen=0"}, map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "placement": "require"}},
		{"unknown hotel", "key2", map[string]string{dedHeader: "zz;gen=1"}, map[string]any{"image": "alpine:3.20", "hotels": []string{"zz"}, "placement": "require"}},
		{"no generation", "key2", map[string]string{dedHeader: "a"}, dedBody()},
		{"bad generation", "key2", map[string]string{dedHeader: "a;gen=x"}, dedBody()},
	}
	for _, c := range bad {
		status, doc := tc.callWith(t, c.key, c.hdr, "POST", "/v1/sandboxes", c.body)
		if status != 400 || errCode(doc) != "invalid_dedicated_hotel" {
			t.Fatalf("%s: %d %v", c.name, status, doc)
		}
	}
	// A wrong generation is 409, not 400.
	status, doc := tc.callWith(t, "key2", dedMark(0), "POST", "/v1/sandboxes", dedBody())
	if status != 409 || errCode(doc) != "dedicated_generation_stale" {
		t.Fatalf("stale: %d %v", status, doc)
	}
	if got := createsOn(tc); got["a"] != before["a"] || got["b"] != before["b"] || got["c"] != before["c"] {
		t.Fatalf("a refused marker started a room: %v -> %v", before, got)
	}
	status, doc = tc.callWith(t, "key2", dedMark(1), "POST", "/v1/sandboxes", dedBody())
	if status != 202 || doc["hotel"] != "a" {
		t.Fatalf("owner with the exact body: %d %v", status, doc)
	}
}

func TestPinOnlyMarkerRefusedOnEveryOtherRoute(t *testing.T) {
	tc := pinChain(t)
	for _, c := range []struct{ method, path string }{
		{"POST", "/v1/images/prefetch"},
		{"POST", "/v1/workspaces"},
		{"GET", "/v1/sandboxes"},
		{"POST", "/v1/snapshots/x"},
		{"GET", "/v1/broker/hotels"},
	} {
		body := map[string]any{"images": []string{"alpine:3.20"}, "hotels": []string{"a"}, "name": "w"}
		status, doc := tc.callWith(t, "key2", dedMark(1), c.method, c.path, body)
		if status != 400 || errCode(doc) != "invalid_dedicated_hotel" {
			t.Fatalf("%s %s: %d %v", c.method, c.path, status, doc)
		}
	}
	if n := len(tc.hotels["a"].prefetch); n != 0 {
		t.Fatalf("hotel a got %d prefetches", n)
	}
}

func TestPinOnlySharedCreatesNeverLandOnTheHotel(t *testing.T) {
	tc := pinChain(t)
	// Free hotels b and c are idle; a is the owner's, so before pin_only these
	// creates could land on a.
	for i := 0; i < 40; i++ {
		status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
		if status != 202 || doc["hotel"] == "a" {
			t.Fatalf("shared create %d: %d %v", i, status, doc)
		}
	}
	// A pilot pin or a server template pin is a hotels list naming a: refused,
	// with require and with prefer, and a "hotels": ["a","b"] list lands on b.
	for _, body := range []map[string]any{
		{"image": "alpine:3.20", "hotels": []string{"a"}},
		{"image": "alpine:3.20", "hotels": []string{"a"}, "placement": "require"},
		{"image": "alpine:3.20", "hotels": []string{"a"}, "placement": "prefer"},
	} {
		status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", body)
		if status != 409 || errCode(doc) != "no_matching_hotel" {
			t.Fatalf("%v: %d %v", body, status, doc)
		}
	}
	status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"a", "b"}})
	if status != 202 || doc["hotel"] != "b" {
		t.Fatalf("a,b list: %d %v", status, doc)
	}
	if n := createsOn(tc)["a"]; n != 0 {
		t.Fatalf("hotel a got %d unmarked creates", n)
	}
	// pick never chooses it for a shared placement, and does for the marker.
	shared := placement{guest: "g2"}
	ded := placement{guest: "g2", ids: map[string]bool{"a": true}, dedicated: "a", dedicatedGen: 1}
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	for i := 0; i < 200; i++ {
		if h := tc.b.pick(nil, shared); h != nil && h.cfg.ID == "a" {
			t.Fatal("pick chose the pin_only hotel for a shared placement")
		}
	}
	if h := tc.b.pick(nil, ded); h == nil || h.cfg.ID != "a" {
		t.Fatalf("pick for the marker: %v", h)
	}
	ded.dedicatedGen = 2
	if h := tc.b.pick(nil, ded); h != nil {
		t.Fatalf("pick with a stale generation: %v", h.cfg.ID)
	}
}

func TestPinOnlyQueuedSharedCreateIsPlacedAgainAtTheRecheck(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2"}); status != 200 {
		t.Fatalf("reserve: %d %v", status, doc)
	}
	a := tc.b.hotelByID("a")
	setHotel(tc, "a", func(h *hotel) {
		h.roomsUnchecked = false
		h.sem = make(chan struct{}, 1)
		h.sem <- struct{}{} // the create queues on a
	})
	setHotel(tc, "b", func(h *hotel) { h.ok = false })
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	g := tc.b.guests["g2"]
	pl := placement{guest: "g2", ids: map[string]bool{"a": true}, image: "alpine:3.20"}
	done := make(chan createResult, 1)
	go func() {
		done <- tc.b.createOne(context.Background(), g, []byte(`{"image":"alpine:3.20"}`), map[string]any{}, time.Now(), pl)
	}()
	pinWait(t, func() bool { tc.b.mu.Lock(); defer tc.b.mu.Unlock(); return a.queued == 1 })
	// The switch itself is refused while a create is queued (B5)...
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"pin_only": true}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("pin with a queued create: %d %v", status, doc)
	}
	// ...so the operator-less race is forced here: the hotel turns pin_only
	// while the create waits.
	tc.b.mu.Lock()
	a.cfgMu.Lock()
	a.cfg.PinOnly = true
	a.cfg.ReservationGeneration++
	a.cfgMu.Unlock()
	tc.b.mu.Unlock()
	<-a.sem // the slot frees: the recheck must put the create back
	select {
	case res := <-done:
		if res.status == 202 {
			t.Fatalf("a shared create queued before the switch landed on the pin_only hotel: %v", res.doc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("create did not end")
	}
	if n := len(tc.hotels["a"].creates); n != 0 {
		t.Fatalf("hotel a got %d creates", n)
	}
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	if a.queued != 0 || g.queued != 0 {
		t.Fatalf("counts left behind: a.queued %d g.queued %d", a.queued, g.queued)
	}
}

func TestPinOnlyQueueMoveNeverChoosesTheHotel(t *testing.T) {
	tc := pinChain(t)
	tc.b.cfg.MaxQueueWaitSeconds = 0.1
	bh := tc.b.hotelByID("b")
	setHotel(tc, "c", func(h *hotel) { h.ok = false })
	setHotel(tc, "b", func(h *hotel) {
		h.sem = make(chan struct{}, 1)
		h.sem <- struct{}{}
		h.creating = 1
		h.createEWMA = 30 // a is far faster, and idle
	})
	g := tc.b.guests["g2"]
	tc.b.mu.Lock()
	bh.queued++
	g.queued++
	tc.b.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	if got := tc.b.waitSlot(ctx, g, bh, placement{guest: "g2"}, map[*hotel]bool{bh: true}); got != nil {
		t.Fatalf("the queued shared create moved to %s", got.cfg.ID)
	}
}

func TestPinOnlyDedicatedStaleAtTheDispatchRecheck(t *testing.T) {
	tc := pinChain(t)
	a := tc.b.hotelByID("a")
	setHotel(tc, "a", func(h *hotel) {
		h.sem = make(chan struct{}, 1)
		h.sem <- struct{}{}
	})
	g := tc.b.guests["g2"]
	pl := placement{guest: "g2", ids: map[string]bool{"a": true}, dedicated: "a", dedicatedGen: 1, image: "alpine:3.20"}
	done := make(chan createResult, 1)
	go func() {
		done <- tc.b.createOne(context.Background(), g, []byte(`{"image":"alpine:3.20"}`), map[string]any{}, time.Now(), pl)
	}()
	pinWait(t, func() bool { tc.b.mu.Lock(); defer tc.b.mu.Unlock(); return a.queued == 1 })
	// The owner changes while the create waits for its slot.
	tc.b.mu.Lock()
	a.cfgMu.Lock()
	a.cfg.ReservationGeneration++
	a.cfgMu.Unlock()
	tc.b.mu.Unlock()
	<-a.sem
	select {
	case res := <-done:
		code, _ := res.doc["error"].(map[string]string)
		if res.status != 409 || code["code"] != "dedicated_generation_stale" {
			t.Fatalf("recheck: %d %v", res.status, res.doc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("create did not end")
	}
	if n := len(tc.hotels["a"].creates); n != 0 {
		t.Fatalf("a stale dedicated create reached the hotel (%d)", n)
	}
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	if a.queued != 0 || g.queued != 0 || a.creating != 0 {
		t.Fatalf("counts left behind: queued %d g.queued %d creating %d", a.queued, g.queued, a.creating)
	}
}

func TestPinOnlyStaleMarkerIsRefusedAfterTheReferenceChanges(t *testing.T) {
	tc := pinChain(t)
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1}); status != 200 {
		t.Fatalf("ref change on an empty hotel: %d %v", status, doc)
	}
	if status, doc := tc.callWith(t, "key2", dedMark(1), "POST", "/v1/sandboxes", dedBody()); status != 409 || errCode(doc) != "dedicated_generation_stale" {
		t.Fatalf("old marker: %d %v", status, doc)
	}
	if status, doc := tc.callWith(t, "key2", dedMark(2), "POST", "/v1/sandboxes", dedBody()); status != 202 {
		t.Fatalf("new marker: %d %v", status, doc)
	}
}

// pinWait polls cond for up to 5 seconds.
func pinWait(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestPinOnlySwitchWaitsForCreatesQueuedAndClaims(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2"}); status != 200 {
		t.Fatalf("reserve: %d %v", status, doc)
	}
	for _, field := range []string{"creating", "queued", "claims"} {
		setHotel(tc, "a", func(h *hotel) {
			switch field {
			case "creating":
				h.creating = 1
			case "queued":
				h.queued = 1
			case "claims":
				h.claims = 1
			}
		})
		for _, body := range []map[string]any{
			{"pin_only": true},
			{"reserved_for": "g1"}, // any reserved_for change (reserveErr)
		} {
			if status, doc := patchHotelDoc(t, tc, "a", body); status != 409 || errCode(doc) != "rooms_active" {
				t.Fatalf("%s=1 %v: %d %v", field, body, status, doc)
			}
		}
		setHotel(tc, "a", func(h *hotel) { h.creating, h.queued, h.claims = 0, 0, 0 })
	}
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"pin_only": true}); status != 200 || doc["pin_only"] != true {
		t.Fatalf("empty hotel: %d %v", status, doc)
	}
}

func TestPinOnlyClaimHeldByAPrefetchBlocksTheSwitchAndPruningKeepsPullingJobs(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2"}); status != 200 {
		t.Fatalf("reserve: %d %v", status, doc)
	}
	tc.hotels["a"].pullDelay = 600 * time.Millisecond
	status, doc := tc.call(t, "key2", "POST", "/v1/images/prefetch", map[string]any{"images": []string{"alpine:3.20"}, "hotels": []string{"a"}})
	if status != 202 {
		t.Fatalf("prefetch: %d %v", status, doc)
	}
	id := doc["prefetch_id"].(string)
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"pin_only": true}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("switch during a prefetch selected before it: %d %v", status, doc)
	}
	// An old job that still pulls survives pruning; an old finished one does not.
	old := time.Now().Add(-2 * prefetchKeep)
	tc.b.prefetch.mu.Lock()
	tc.b.prefetch.jobs["pf_old_pulling"] = &prefetchJob{ID: "pf_old_pulling", guest: "g2", Created: old, Hotels: map[string]*prefetchHotel{"a": {State: "pulling"}}}
	tc.b.prefetch.jobs["pf_old_done"] = &prefetchJob{ID: "pf_old_done", guest: "g2", Created: old, Hotels: map[string]*prefetchHotel{"a": {State: "done"}}}
	tc.b.prefetch.mu.Unlock()
	if status, doc := tc.call(t, "key2", "POST", "/v1/images/prefetch", map[string]any{"images": []string{"alpine:3.20"}, "hotels": []string{"b"}}); status != 202 {
		t.Fatalf("second prefetch: %d %v", status, doc)
	}
	tc.b.prefetch.mu.Lock()
	_, kept := tc.b.prefetch.jobs["pf_old_pulling"]
	_, dropped := tc.b.prefetch.jobs["pf_old_done"]
	tc.b.prefetch.mu.Unlock()
	if !kept || dropped {
		t.Fatalf("pruning: pulling job kept %v, finished job still there %v", kept, dropped)
	}
	waitPrefetch(t, tc, "key2", id)
	pinWait(t, func() bool { tc.b.mu.Lock(); defer tc.b.mu.Unlock(); return tc.b.hotelByID("a").claims == 0 })
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"pin_only": true}); status != 200 {
		t.Fatalf("switch after the pulls: %d %v", status, doc)
	}
	// And now a prefetch naming a selects nothing: it is a shared call.
	if status, doc := tc.call(t, "key2", "POST", "/v1/images/prefetch", map[string]any{"images": []string{"alpine:3.20"}, "hotels": []string{"a"}}); status != 409 {
		t.Fatalf("prefetch on a pin_only hotel: %d %v", status, doc)
	}
	// A prefetch with no hotels list never pulls on a.
	callsBefore := len(tc.hotels["a"].prefetch)
	status, doc = tc.call(t, "key2", "POST", "/v1/images/prefetch", map[string]any{"images": []string{"alpine:3.21"}})
	if status != 202 {
		t.Fatalf("open prefetch: %d %v", status, doc)
	}
	waitPrefetch(t, tc, "key2", doc["prefetch_id"].(string))
	if _, on := doc["hotels"].(map[string]any)["a"]; on || len(tc.hotels["a"].prefetch) != callsBefore {
		t.Fatalf("an unmarked prefetch reached the pin_only hotel: %v", doc["hotels"])
	}
}

// gateWorkspaceCreates puts a gate in front of hotel id's workspace create,
// so the call stays open until the returned func runs.
func gateWorkspaceCreates(t *testing.T, wc *wsChain, id string) (release func()) {
	t.Helper()
	gate := make(chan struct{})
	var once sync.Once
	inner := wc.ws[id]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/v1/workspaces" {
			<-gate
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	wc.b.mu.Lock()
	wc.b.hotelByID(id).cfg.API = srv.URL
	wc.b.mu.Unlock()
	return func() { once.Do(func() { close(gate) }) }
}

func TestPinOnlyClaimHeldByAWorkspaceCreateBlocksTheSwitch(t *testing.T) {
	wc := newWSChain(t)
	wc.b.cfg.StateDir = t.TempDir()
	wc.b.cfg.OperatorKeySHA256 = sha("operator-key")
	if status, doc := patchHotelDoc(t, wc.testChain, "a", map[string]any{"reserved_for": "g2"}); status != 200 {
		t.Fatalf("reserve: %d %v", status, doc)
	}
	setHotel(wc.testChain, "a", func(h *hotel) { h.roomsUnchecked = false })
	release := gateWorkspaceCreates(t, wc, "a")
	defer release()
	done := make(chan int, 1)
	go func() {
		status, _ := wc.call(t, "key2", "POST", "/v1/workspaces", map[string]any{"name": "repo", "hotels": []string{"a"}})
		done <- status
	}()
	pinWait(t, func() bool { wc.b.mu.Lock(); defer wc.b.mu.Unlock(); return wc.b.hotelByID("a").claims == 1 })
	if status, doc := patchHotelDoc(t, wc.testChain, "a", map[string]any{"pin_only": true}); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("switch during a workspace create: %d %v", status, doc)
	}
	release()
	if s := <-done; s != 201 {
		t.Fatalf("workspace create: %d", s)
	}
	wc.b.mu.Lock()
	n := wc.b.hotelByID("a").claims
	wc.b.mu.Unlock()
	if n != 0 {
		t.Fatalf("claim left behind: %d", n)
	}
	if status, doc := patchHotelDoc(t, wc.testChain, "a", map[string]any{"pin_only": true}); status != 200 {
		t.Fatalf("switch after: %d %v", status, doc)
	}
	// A workspace create now never selects a.
	if status, doc := wc.call(t, "key2", "POST", "/v1/workspaces", map[string]any{"name": "repo2", "hotels": []string{"a"}}); status != 409 {
		t.Fatalf("workspace on a pin_only hotel: %d %v", status, doc)
	}
}

func TestPinOnlyPrewarmAndReplaySkipTheHotel(t *testing.T) {
	tc := newChain(t)
	warmUp(tc, true)
	setHotel(tc, "a", func(h *hotel) { h.cfg.ReservedFor, h.cfg.PinOnly = "g1", true })
	a := tc.b.hotelByID("a")
	tc.b.prewarmHotel(a)
	if n := len(tc.hotels["a"].prefetch); n != 0 {
		t.Fatalf("prewarm pulled %d images on a pin_only hotel", n)
	}
	setHotel(tc, "a", func(h *hotel) { h.guestWant = map[string]map[string]time.Time{"g1": {guestImage: time.Now()}} })
	tc.b.replayGuestPrefetch(a)
	if n := len(tc.hotels["a"].prefetch); n != 0 {
		t.Fatalf("replay pulled %d images on a pin_only hotel", n)
	}
	tc.b.mu.Lock()
	claims := a.claims
	tc.b.mu.Unlock()
	if claims != 0 {
		t.Fatalf("claims left: %d", claims)
	}
}

func TestPinOnlyReplayChecksBeforeEachPull(t *testing.T) {
	tc := newChain(t)
	h := tc.b.hotelByID("b")
	setHotel(tc, "b", func(h *hotel) {
		h.guestWant = map[string]map[string]time.Time{"g1": {}}
		for _, ref := range []string{"r1:1", "r2:1", "r3:1", "r4:1", "r5:1", "r6:1", "r7:1", "r8:1"} {
			h.guestWant["g1"][ref] = time.Now()
		}
	})
	tc.hotels["b"].pullDelay = 200 * time.Millisecond
	done := make(chan struct{})
	go func() { tc.b.replayGuestPrefetch(h); close(done) }()
	pinWait(t, func() bool {
		tc.hotels["b"].mu.Lock()
		defer tc.hotels["b"].mu.Unlock()
		return len(tc.hotels["b"].prefetch) > 0
	})
	// 8 refs, 4 at a time: the last 4 start only after the first 4 end, and
	// by then the hotel is pin_only.
	setHotel(tc, "b", func(h *hotel) { h.cfgMu.Lock(); h.cfg.ReservedFor, h.cfg.PinOnly = "g1", true; h.cfgMu.Unlock() })
	<-done
	tc.hotels["b"].mu.Lock()
	n := len(tc.hotels["b"].prefetch)
	tc.hotels["b"].mu.Unlock()
	if n > prefetchPerHotel {
		t.Fatalf("the replay went on after the hotel turned pin_only: %d pulls", n)
	}
}

func TestPinOnlyReplayStopsWhenTheGuestLosesTheHotelOrTheGenerationMoves(t *testing.T) {
	for _, name := range []string{"guest loses it", "generation moves"} {
		tc := newChain(t)
		h := tc.b.hotelByID("b")
		setHotel(tc, "b", func(h *hotel) {
			h.guestWant = map[string]map[string]time.Time{"g1": {}}
			for _, ref := range []string{"r1:1", "r2:1", "r3:1", "r4:1", "r5:1", "r6:1", "r7:1", "r8:1"} {
				h.guestWant["g1"][ref] = time.Now()
			}
		})
		tc.hotels["b"].pullDelay = 200 * time.Millisecond
		done := make(chan struct{})
		go func() { tc.b.replayGuestPrefetch(h); close(done) }()
		pinWait(t, func() bool {
			tc.hotels["b"].mu.Lock()
			defer tc.hotels["b"].mu.Unlock()
			return len(tc.hotels["b"].prefetch) > 0
		})
		if name == "guest loses it" {
			tc.b.mu.Lock()
			tc.b.guests["g1"].limits.Hotels = []string{"c"}
			tc.b.mu.Unlock()
		} else {
			h.cfgMu.Lock()
			h.cfg.ReservationGeneration++
			h.cfgMu.Unlock()
		}
		<-done
		tc.hotels["b"].mu.Lock()
		n := len(tc.hotels["b"].prefetch)
		tc.hotels["b"].mu.Unlock()
		if n > prefetchPerHotel {
			t.Fatalf("%s: the replay went on: %d pulls", name, n)
		}
	}
}

func TestPinOnlyReservedForChangeClearsItAndASameOwnerPatchKeepsIt(t *testing.T) {
	tc := pinChain(t)
	// A same-owner PATCH keeps it (drain, and a ref change on an empty hotel).
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"drain": false}); status != 200 || doc["pin_only"] != true {
		t.Fatalf("drain: %d %v", status, doc)
	}
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2"}); status != 200 || doc["pin_only"] != true {
		t.Fatalf("same owner: %d %v", status, doc)
	}
	// A restart keeps it (hotel-reservations.json), with the generation.
	tc.start(t)
	doc := getHotelDoc(t, tc, "a")
	if doc["pin_only"] != true {
		t.Fatalf("after restart: %v", doc)
	}
	wantReservation(t, doc, "g2", "owner:g2:2", 2)
	raw, _ := os.ReadFile(filepath.Join(tc.b.cfg.StateDir, reservationsFile))
	if !strings.Contains(string(raw), `"pin_only": true`) {
		t.Fatalf("%s: %s", reservationsFile, raw)
	}
	// A new owner clears it, and so does a release; the same PATCH may set it.
	status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g1"})
	if status != 200 || doc["pin_only"] != false || doc["reservation_generation"] != float64(3) {
		t.Fatalf("new owner: %d %v", status, doc)
	}
	status, doc = patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "pin_only": true})
	if status != 200 || doc["pin_only"] != true || doc["reservation_generation"] != float64(4) {
		t.Fatalf("new owner and pin_only in one PATCH: %d %v", status, doc)
	}
	status, doc = patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": nil})
	if status != 200 || doc["pin_only"] != false {
		t.Fatalf("release: %d %v", status, doc)
	}
	tc.start(t)
	if doc := getHotelDoc(t, tc, "a"); doc["pin_only"] != false {
		t.Fatalf("after release and restart: %v", doc)
	}
	// pin_only needs a reservation and no lend.
	for _, body := range []map[string]any{{"pin_only": true}, {"reserved_for": nil, "pin_only": true}, {"reserved_for": "g2", "lend": true, "pin_only": true}} {
		if status, doc := patchHotelDoc(t, tc, "a", body); status != 400 {
			t.Fatalf("%v: %d %v", body, status, doc)
		}
	}
}

func TestPinOnlyIsOperatorOnly(t *testing.T) {
	tc := pinChain(t)
	status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"drain": true, "pin_only": false})
	if status != 403 {
		t.Fatalf("enroller: %d %v", status, doc)
	}
	if status, _ := tc.call(t, "key2", "PATCH", "/v1/broker/hotels/a", map[string]any{"pin_only": false}); status == 200 {
		t.Fatal("a guest key changed pin_only")
	}
	if !tc.b.hotelByID("a").pinOnly() {
		t.Fatal("pin_only changed")
	}
}

func TestPinOnlyFailClosedAuditAndLendClearIt(t *testing.T) {
	tc := pinChain(t)
	a := tc.b.hotelByID("a")
	// The fail-closed audit: a room of another guest on a reserved hotel.
	tc.b.mu.Lock()
	a.rooms["x1"] = &room{h: a, guest: "g1", hid: "x1", id: "a.x1", state: stRunning}
	changed := tc.b.checkReservedRooms(a)
	tc.b.mu.Unlock()
	if !changed || a.pinOnly() || a.reservedFor() != "" {
		t.Fatalf("audit: changed %v pin %v owner %q", changed, a.pinOnly(), a.reservedFor())
	}
	// A lend and a reclaim, applied as patchHotel applies them.
	tc2 := pinChain(t)
	a2 := tc2.b.hotelByID("a")
	tc2.b.mu.Lock()
	a2.cfgMu.Lock()
	e := lendChange{lend: true, owner: "g2", reportID: "r1"}.applyLend(a2)
	a2.cfgMu.Unlock()
	tc2.b.mu.Unlock()
	if e != nil || a2.pinOnly() || a2.lentFrom() != "g2" {
		t.Fatalf("lend: %v pin %v lent %q", e, a2.pinOnly(), a2.lentFrom())
	}
	a2.cfgMu.Lock()
	a2.cfg.PinOnly = true // a bad state a reclaim must still clear
	a2.cfgMu.Unlock()
	tc2.b.mu.Lock()
	a2.cfgMu.Lock()
	e = lendChange{reclaim: true, owner: "g2", lentID: "r1", reportID: "r2"}.applyLend(a2)
	a2.cfgMu.Unlock()
	tc2.b.mu.Unlock()
	if e != nil || a2.pinOnly() || a2.reservedFor() != "g2" {
		t.Fatalf("reclaim: %v pin %v owner %q", e, a2.pinOnly(), a2.reservedFor())
	}
}

func TestPinOnlyNeedsAReservationInTheConfigFileAndOnJoin(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	raw, _ := os.ReadFile(tc.cfgPath)
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Hotels[0].PinOnly = true // no reserved_for
	raw, _ = json.Marshal(c)
	if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBroker(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "pin_only") {
		t.Fatalf("config pin_only without reserved_for: %v", err)
	}
	// A join with pin_only and no reservation is 400.
	tc = newChainState(t, t.TempDir())
	_, url := newOperatorHotel(t, 4, snpAttestation(t, attestOpts{chip: chipOf("j1")}))
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "j1", "api": url, "key": joinKey, "sealed": true, "pin_only": true})
	if status != 400 || errCode(doc) != "invalid_hotel" {
		t.Fatalf("join: %d %v", status, doc)
	}
	// The enroller may not send it.
	status, doc = tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", map[string]any{"id": "j1", "api": url, "key": joinKey, "sealed": true, "pin_only": true, "miner_hotkey": minerHotkey})
	if status != 403 {
		t.Fatalf("enroller join: %d %v", status, doc)
	}
}

func TestPinOnlyOfAJoinedHotelIsKeptInHotelsJSON(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	joinOperatorSealed(t, tc, "j1", 4)
	if status, doc := patchHotelDoc(t, tc, "j1", map[string]any{"reserved_for": "g2", "pin_only": true}); status != 200 || doc["pin_only"] != true {
		t.Fatalf("pin joined: %d %v", status, doc)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, runtimeHotelsFile))
	if !strings.Contains(string(raw), `"pin_only": true`) {
		t.Fatalf("hotels.json: %s", raw)
	}
	if status, doc := patchHotelDoc(t, tc, "j1", map[string]any{"reserved_for": nil}); status != 200 || doc["pin_only"] != false {
		t.Fatalf("release: %d %v", status, doc)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, runtimeHotelsFile))
	if strings.Contains(string(raw), "pin_only") {
		t.Fatalf("hotels.json keeps pin_only after the release: %s", raw)
	}
}

func TestPinOnlyCapacityListsTheHotelAndLeavesItOutOfTotals(t *testing.T) {
	tc := pinChain(t)
	status, doc := tc.call(t, "key2", "GET", "/v1/broker/capacity", nil)
	if status != 200 {
		t.Fatalf("capacity: %d %v", status, doc)
	}
	var seen bool
	for _, x := range doc["hotels"].([]any) {
		h := x.(map[string]any)
		if h["id"] == "a" {
			seen = h["pin_only"] == true
		} else if h["pin_only"] != nil {
			t.Fatalf("hotel %v marked pin_only", h["id"])
		}
	}
	if !seen {
		t.Fatalf("a not listed with pin_only: %v", doc["hotels"])
	}
	sealed := doc["classes"].(map[string]any)[classSealed].(map[string]any)
	if sealed["hotels"] != float64(2) {
		t.Fatalf("totals count the pin_only hotel: %v", sealed)
	}
	// The guest hotel list and the operator view show it too.
	status, doc = tc.call(t, "key2", "GET", "/v1/broker/hotels", nil)
	if status != 200 {
		t.Fatalf("hotels: %d %v", status, doc)
	}
	listed := false
	for _, x := range doc["hotels"].([]any) {
		if h := x.(map[string]any); h["id"] == "a" && h["pin_only"] == true {
			listed = true
		}
	}
	if !listed {
		t.Fatalf("a missing from /v1/broker/hotels: %v", doc)
	}
	status, doc = tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	if status != 200 {
		t.Fatal(status)
	}
	// /v1/status counts what g2 can use without a marker.
	status, doc = tc.call(t, "key2", "GET", "/v1/status", nil)
	if status != 200 || doc["hotels"] != float64(2) {
		t.Fatalf("status: %d %v", status, doc)
	}
	// g1 sees neither the hotel nor a pin_only field.
	_, doc = tc.call(t, "key1", "GET", "/v1/broker/capacity", nil)
	for _, x := range doc["hotels"].([]any) {
		if x.(map[string]any)["id"] == "a" {
			t.Fatalf("g1 sees a: %v", x)
		}
	}
}

func TestPinOnlyReferenceChangeNeedsAnEmptyHotel(t *testing.T) {
	tc := pinChain(t) // generation 1, ref owner:g2
	a := tc.b.hotelByID("a")
	change := func(ref string, gen uint64) (int, map[string]any) {
		return patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": ref, "expect_generation": gen})
	}
	// Refused while a room exists, a create is counted, one is queued or a
	// claim is held; generation and ref stay.
	for _, c := range []struct {
		name string
		set  func(h *hotel)
		undo func(h *hotel)
	}{
		{"room", func(h *hotel) { h.rooms["x1"] = &room{h: h, guest: "g2", hid: "x1", id: "a.x1", state: stRunning} }, func(h *hotel) { delete(h.rooms, "x1") }},
		{"creating", func(h *hotel) { h.creating = 1 }, func(h *hotel) { h.creating = 0 }},
		{"queued", func(h *hotel) { h.queued = 1 }, func(h *hotel) { h.queued = 0 }},
		{"claim", func(h *hotel) { h.claims = 1 }, func(h *hotel) { h.claims = 0 }},
	} {
		setHotel(tc, "a", c.set)
		status, doc := change("owner:g2:x", 1)
		if status != 409 || errCode(doc) != "rooms_active" {
			t.Fatalf("%s: %d %v", c.name, status, doc)
		}
		wantReservation(t, getHotelDoc(t, tc, "a"), "g2", "owner:g2", 1)
		setHotel(tc, "a", c.undo)
	}
	// A generation mismatch still reads as a conflict first.
	if status, doc := change("owner:g2:x", 9); status != 409 || errCode(doc) != "reservation_conflict" {
		t.Fatalf("mismatch: %d %v", status, doc)
	}
	// Empty: accepted, and the generation goes up by exactly one.
	status, doc := change("owner:g2:x", 1)
	if status != 200 {
		t.Fatalf("empty: %d %v", status, doc)
	}
	wantReservation(t, doc, "g2", "owner:g2:x", 2)
	if doc["pin_only"] != true {
		t.Fatalf("pin_only lost: %v", doc)
	}
	// The same ref again is no change: it needs no empty hotel.
	setHotel(tc, "a", func(h *hotel) { h.creating = 1 })
	if status, doc := change("owner:g2:x", 2); status != 200 {
		t.Fatalf("unchanged ref: %d %v", status, doc)
	}
	setHotel(tc, "a", func(h *hotel) { h.creating = 0 })
	_ = a
}

func TestPinOnlyReferenceChangeIsRefusedWhileADedicatedCreateIsInFlight(t *testing.T) {
	tc := pinChain(t)
	tc.hotels["a"].createDelay = 700 * time.Millisecond
	type result struct {
		status int
		doc    map[string]any
	}
	done := make(chan result, 1)
	go func() {
		status, doc := tc.callWith(t, "key2", dedMark(1), "POST", "/v1/sandboxes", dedBody())
		done <- result{status, doc}
	}()
	// Past the B4 recheck the create is counted in h.creating until it ends.
	pinWait(t, func() bool { tc.b.mu.Lock(); defer tc.b.mu.Unlock(); return tc.b.hotelByID("a").creating == 1 })
	status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1})
	if status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("during the create: %d %v", status, doc)
	}
	if got := hotelGen(tc, "a"); got != 1 {
		t.Fatalf("generation moved to %d", got)
	}
	res := <-done
	if res.status != 202 {
		t.Fatalf("create: %d %v", res.status, res.doc)
	}
	// The room it made counts too; once it is deleted the change goes through.
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1}); status != 409 {
		t.Fatalf("with the room: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key2", "DELETE", "/v1/sandboxes/"+res.doc["id"].(string), nil); status != 204 && status != 200 {
		t.Fatalf("delete: %d %v", status, doc)
	}
	// The sync loop frees a deleted room once the hotel stops listing it
	// (main.go syncHotel); done here directly.
	tc.b.mu.Lock()
	for _, rm := range tc.b.hotelByID("a").rooms {
		tc.b.release(tc.b.hotelByID("a"), rm)
	}
	tc.b.mu.Unlock()
	status, doc = patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1})
	if status != 200 {
		t.Fatalf("empty again: %d %v", status, doc)
	}
	wantReservation(t, doc, "g2", "owner:g2:2", 2)
	// The marker issued at generation 1 is stale now.
	if status, doc := tc.callWith(t, "key2", dedMark(1), "POST", "/v1/sandboxes", dedBody()); status != 409 || errCode(doc) != "dedicated_generation_stale" {
		t.Fatalf("old marker: %d %v", status, doc)
	}
}

func TestPinOnlyProbeSkipsTheHotel(t *testing.T) {
	tc := pinChain(t)
	setHotel(tc, "a", func(h *hotel) { h.ok = true })
	tc.b.mu.Lock()
	tc.b.guests["g2"].cfg.Ops = true
	tc.b.mu.Unlock()
	status, doc := tc.call(t, "key2", "POST", "/v1/broker/probe", map[string]any{})
	if status != 200 {
		t.Fatalf("probe: %d %v", status, doc)
	}
	hs, _ := doc["hotels"].(map[string]any)
	a, _ := hs["a"].(map[string]any)
	if a == nil || !strings.Contains(a["error"].(string), "pin_only") {
		t.Fatalf("probe of a: %v", doc)
	}
	if n := createsOn(tc)["a"]; n != 0 {
		t.Fatalf("the probe started %d rooms on a", n)
	}
}

func TestPinOnlyPrewarmStopsMidRunWhenTheHotelTurnsPinOnlyOrChangesOwner(t *testing.T) {
	for _, name := range []string{"pin_only", "generation"} {
		tc := newChain(t)
		tc.b.mu.Lock()
		tc.b.cfg.PrewarmCatalog = true
		tc.b.mu.Unlock()
		tc.hotels["b"].pullDelay = 200 * time.Millisecond
		h := tc.b.hotelByID("b")
		done := make(chan struct{})
		go func() { tc.b.prewarmHotel(h); close(done) }()
		pinWait(t, func() bool {
			tc.hotels["b"].mu.Lock()
			defer tc.hotels["b"].mu.Unlock()
			return len(tc.hotels["b"].prefetch) > 0
		})
		h.cfgMu.Lock()
		if name == "pin_only" {
			h.cfg.ReservedFor, h.cfg.PinOnly = "g1", true
		} else {
			h.cfg.ReservationGeneration++
		}
		h.cfgMu.Unlock()
		<-done
		tc.hotels["b"].mu.Lock()
		n := len(tc.hotels["b"].prefetch)
		tc.hotels["b"].mu.Unlock()
		if n != 1 {
			t.Fatalf("%s: prewarm made %d pulls; want 1 (the one in flight)", name, n)
		}
		tc.b.mu.Lock()
		claims := h.claims
		tc.b.mu.Unlock()
		if claims != 0 {
			t.Fatalf("%s: claim left behind: %d", name, claims)
		}
	}
}
