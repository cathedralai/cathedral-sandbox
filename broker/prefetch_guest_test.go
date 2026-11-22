package main

import (
	"strings"
	"testing"
	"time"
)

// AB#859: a guest prefetch warms the hotels it pulled on for that guest's
// creates, one ref per hotel call, and is replayed when the hotel comes back.
// AB#861: a hotel whose scratch is at its admission line pulls nothing.

const guestImage = "python:3.12-slim" // not a catalog image: only a guest prefetch warms it

// guestFixture keeps creates to hotels b and c with equal measured times.
func guestFixture(t *testing.T) *testChain {
	tc := newChain(t)
	setHotel(tc, "a", func(h *hotel) { h.ok = false })
	return tc
}

func guestCreates(t *testing.T, tc *testChain, key string, n int) map[string]int {
	t.Helper()
	got := map[string]int{}
	for i := 0; i < n; i++ {
		setHotel(tc, "b", func(h *hotel) { h.createEWMA = 1 })
		setHotel(tc, "c", func(h *hotel) { h.createEWMA = 1 })
		status, doc := tc.call(t, key, "POST", "/v1/sandboxes", map[string]any{"image": guestImage})
		if status != 202 {
			t.Fatalf("create: %d %v", status, doc)
		}
		got[doc["hotel"].(string)]++
	}
	return got
}

func prefetchDone(t *testing.T, tc *testChain, key string, body map[string]any) map[string]any {
	t.Helper()
	status, doc := tc.call(t, key, "POST", "/v1/images/prefetch", body)
	if status != 202 {
		t.Fatalf("prefetch: %d %v", status, doc)
	}
	return waitPrefetch(t, tc, key, doc["prefetch_id"].(string))
}

func TestGuestPrefetchSteersThatGuestsCreates(t *testing.T) {
	tc := guestFixture(t)
	if v := prefetchDone(t, tc, "key1", map[string]any{"images": []string{guestImage}, "hotels": []string{"b"}}); v["state"] != "done" {
		t.Fatalf("prefetch: %v", v)
	}
	if got := guestCreates(t, tc, "key1", 20); got["b"] != 20 {
		t.Fatalf("want all 20 creates of the prefetched image on b, got %v", got)
	}
	// Another guest's prefetch steers nothing for g2: its creates still spread.
	if got := guestCreates(t, tc, "key2", 40); got["c"] == 0 {
		t.Fatalf("g2 was steered by g1's prefetch: %v", got)
	}
}

func TestGuestWarmNeverRemovesCapacity(t *testing.T) {
	tc := guestFixture(t)
	prefetchDone(t, tc, "key1", map[string]any{"images": []string{guestImage}, "hotels": []string{"b"}})
	setHotel(tc, "b", func(h *hotel) { h.slots = 0 }) // warm but full
	if got := guestCreates(t, tc, "key1", 3); got["c"] != 3 {
		t.Fatalf("want the creates on cold c while warm b is full, got %v", got)
	}
}

func TestGuestWarmOffSwitch(t *testing.T) {
	tc := guestFixture(t)
	off := false
	tc.b.mu.Lock()
	tc.b.cfg.PreferGuestWarm = &off
	tc.b.mu.Unlock()
	prefetchDone(t, tc, "key1", map[string]any{"images": []string{guestImage}, "hotels": []string{"b"}})
	if got := guestCreates(t, tc, "key1", 40); got["c"] == 0 {
		t.Fatalf("prefer_guest_warm false still steered: %v", got)
	}
}

func TestPrefetchOneRefPerHotelCall(t *testing.T) {
	tc := guestFixture(t)
	tc.hotels["b"].failRef = "ghcr.io/acme/missing:1"
	refs := []string{"alpine:3.20", "ghcr.io/acme/missing:1", guestImage}
	v := prefetchDone(t, tc, "key1", map[string]any{"images": refs, "hotels": []string{"b"}})
	if n := len(tc.hotels["b"].prefetch); n != 3 {
		t.Fatalf("want one hotel call per ref (3), got %d", n)
	}
	for _, req := range tc.hotels["b"].prefetch {
		if len(req["images"].([]any)) != 1 {
			t.Fatalf("hotel call with %d refs", len(req["images"].([]any)))
		}
	}
	hb := v["hotels"].(map[string]any)["b"].(map[string]any)
	imgs := hb["images"].([]any)
	if len(imgs) != 3 || hb["state"] != "failed" || hb["error"].(map[string]any)["code"] != "image_pull_failed" {
		t.Fatalf("hotel b: %v", hb)
	}
	want := map[string]string{"alpine:3.20": "done", "ghcr.io/acme/missing:1": "failed", guestImage: "done"}
	for i, x := range imgs {
		m := x.(map[string]any)
		if m["ref"] != refs[i] || m["state"] != want[refs[i]] {
			t.Fatalf("image %d: %v", i, m)
		}
	}
	// The good refs are warm for the guest; the failed one is not.
	tc.b.mu.Lock()
	h := tc.b.hotelByID("b")
	ok := h.guestWarm["g1"][guestImage] && h.guestWarm["g1"]["alpine:3.20"] && !h.guestWarm["g1"]["ghcr.io/acme/missing:1"]
	tc.b.mu.Unlock()
	if !ok {
		t.Fatalf("warm set after prefetch: %v", h.guestWarm)
	}
}

func TestPrefetchPullsUpToFourRefsAtOnce(t *testing.T) {
	tc := guestFixture(t)
	tc.hotels["b"].pullDelay = 300 * time.Millisecond
	refs := []string{"r/a:1", "r/b:1", "r/c:1", "r/d:1", "r/e:1", "r/f:1", "r/g:1", "r/h:1"}
	t0 := time.Now()
	prefetchDone(t, tc, "key1", map[string]any{"images": refs, "hotels": []string{"b"}})
	// 8 refs, 4 at once, 300 ms each: about 600 ms; one at a time would be 2.4 s.
	if d := time.Since(t0); d > 1800*time.Millisecond {
		t.Fatalf("8 pulls took %s: not 4 in flight", d)
	}
}

func TestCompatImportPrefetchesAsTheGuest(t *testing.T) {
	tc := guestFixture(t)
	status, doc := tc.clientCall(t, "POST", "/v1/images/import", mustMarshal(map[string]any{"image": guestImage}), nil)
	if status != 200 {
		t.Fatalf("import: %d %v", status, doc)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		tc.b.mu.Lock()
		warm := tc.b.hotelByID("b").guestWarm["g1"][guestImage]
		tc.b.mu.Unlock()
		if warm || time.Now().After(deadline) {
			if !warm {
				t.Fatal("compat import did not warm hotel b for the guest")
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	f := tc.hotels["b"]
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.prefetchGuest) == 0 || f.prefetchGuest[0] != "g1" {
		t.Fatalf("import prefetch not sent as the guest: %q", f.prefetchGuest)
	}
}

func TestHotelUpReplaysGuestPrefetch(t *testing.T) {
	tc := guestFixture(t)
	prefetchDone(t, tc, "key1", map[string]any{"images": []string{guestImage}, "hotels": []string{"b"}})
	prefetchDone(t, tc, "key1", map[string]any{"images": []string{"ghcr.io/acme/private:1"}, "hotels": []string{"b"},
		"registry_auth": map[string]any{"username": "robot", "password": "s3cret"}})
	h := tc.b.hotelByID("b")
	setHotel(tc, "b", func(h *hotel) { tc.b.hotelWentDown(h) }) // a reboot wipes the scratch
	tc.b.mu.Lock()
	cold := len(h.guestWarm) == 0
	tc.b.mu.Unlock()
	if !cold {
		t.Fatal("warm set kept after the hotel went down")
	}
	tc.b.replayGuestPrefetch(h)
	f := tc.hotels["b"]
	f.mu.Lock()
	calls := len(f.prefetch)
	last := f.prefetch[calls-1]
	guest := f.prefetchGuest[calls-1]
	f.mu.Unlock()
	if calls != 3 || last["images"].([]any)[0] != guestImage || guest != "g1" {
		t.Fatalf("replay: %d calls, last %v as %q; want 3, %s as g1, and no replay of the login pull", calls, last, guest, guestImage)
	}
	if strings.Contains(mustJSON(last), "s3cret") {
		t.Fatal("replay sent a login")
	}
	tc.b.mu.Lock()
	warm := h.guestWarm["g1"][guestImage]
	tc.b.mu.Unlock()
	if !warm {
		t.Fatal("replayed ref not warm again")
	}
}

// A short outage keeps the scratch: the replay marks a cached ref warm with no pull.
func TestHotelUpAfterABlipDoesNotPullAgain(t *testing.T) {
	tc := guestFixture(t)
	prefetchDone(t, tc, "key1", map[string]any{"images": []string{guestImage}, "hotels": []string{"b"}})
	f := tc.hotels["b"]
	f.mu.Lock()
	f.cached = map[string]bool{guestImage: true}
	f.mu.Unlock()
	h := tc.b.hotelByID("b")
	setHotel(tc, "b", func(h *hotel) { tc.b.hotelWentDown(h) })
	tc.b.replayGuestPrefetch(h)
	f.mu.Lock()
	calls := len(f.prefetch)
	f.mu.Unlock()
	tc.b.mu.Lock()
	warm := h.guestWarm["g1"][guestImage]
	tc.b.mu.Unlock()
	if calls != 1 || !warm {
		t.Fatalf("after a blip: %d pulls (want 1, the first), warm %v", calls, warm)
	}
}

// AB#896: a hotel with no key installer replays at the come-up itself, as before.
func TestPlainHotelComeUpReplaysGuestPrefetch(t *testing.T) {
	tc := guestFixture(t)
	prefetchDone(t, tc, "key1", map[string]any{"images": []string{guestImage}, "hotels": []string{"b"}})
	setHotel(tc, "b", func(h *hotel) {
		h.ok = false
		tc.b.hotelWentDown(h) // a reboot wipes the scratch
	})
	syncNow(tc, "b")
	waitFor(t, "the replay at the come-up", func() bool { return callsTo(tc.hotels["b"], prefetchCall) >= 2 })
	time.Sleep(200 * time.Millisecond)
	if n := callsTo(tc.hotels["b"], prefetchCall); n != 2 {
		t.Fatalf("%d prefetch calls; want the first and one replay", n)
	}
}

func TestPrefetchSkipsHotelAtItsDiskLine(t *testing.T) {
	tc := guestFixture(t)
	pct := func(v float64) *float64 { return &v }
	setHotel(tc, "b", func(h *hotel) { h.roomDataPct = pct(85) })                                                // over diskFullPct 80
	setHotel(tc, "c", func(h *hotel) { h.roomDataPct = pct(30) })                                                // room to spare
	setHotel(tc, "a", func(h *hotel) { h.ok = true; h.roomDataPct = pct(75); h.cfg.DiskAdmitUsedPct = pct(70) }) // over its own line
	v := prefetchDone(t, tc, "key1", map[string]any{"images": []string{guestImage}, "hotels": []string{"a", "b", "c"}})
	hs := v["hotels"].(map[string]any)
	for _, id := range []string{"a", "b"} {
		st := hs[id].(map[string]any)
		if st["state"] != "failed" || st["error"].(map[string]any)["code"] != "image_store_full" || len(tc.hotels[id].prefetch) != 0 {
			t.Fatalf("hotel %s at its disk line: %v, %d pulls", id, st, len(tc.hotels[id].prefetch))
		}
	}
	if st := hs["c"].(map[string]any); st["state"] != "done" || len(tc.hotels["c"].prefetch) != 1 {
		t.Fatalf("hotel c: %v", st)
	}
}

// A hotel that reaches its disk line during a job pulls none of the refs still queued.
func TestPrefetchStopsQueuedRefsAtTheDiskLine(t *testing.T) {
	tc := guestFixture(t)
	tc.hotels["b"].pullDelay = 200 * time.Millisecond
	refs := []string{"r/a:1", "r/b:1", "r/c:1", "r/d:1", "r/e:1", "r/f:1"}
	status, doc := tc.call(t, "key1", "POST", "/v1/images/prefetch", map[string]any{"images": refs, "hotels": []string{"b"}})
	if status != 202 {
		t.Fatalf("prefetch: %d %v", status, doc)
	}
	time.Sleep(50 * time.Millisecond) // the first 4 are in flight
	full := 85.0
	setHotel(tc, "b", func(h *hotel) { h.roomDataPct = &full })
	v := waitPrefetch(t, tc, "key1", doc["prefetch_id"].(string))
	if n := len(tc.hotels["b"].prefetch); n != 4 {
		t.Fatalf("want the 4 in-flight pulls only, got %d", n)
	}
	imgs := v["hotels"].(map[string]any)["b"].(map[string]any)["images"].([]any)
	for _, i := range []int{4, 5} {
		m := imgs[i].(map[string]any)
		if m["state"] != "failed" || m["error"].(map[string]any)["code"] != "image_store_full" {
			t.Fatalf("queued ref %d: %v", i, m)
		}
	}
}
