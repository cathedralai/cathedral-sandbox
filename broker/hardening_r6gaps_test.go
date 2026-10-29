package main

// Review round 6, reader Q: tests for the broker fixes of PR #312 that the
// mutation pass (reader O) found unguarded. Each test fails on 22e7824, or,
// where the fix guards a change made in the same PR, on head with that hunk
// reverted; the proof runs are in the round 6 catalog (Q-go-gaps.md).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// hijackClose drops the connection with no answer, as a tunnel or a hotel
// restart does after the hotel has committed the work.
func hijackClose(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			conn.Close()
		}
	}
}

// ---------------------------------------------------------------- lost create answers (O5)

// A dedicated guest has one hotel. The hotel starts the room and the answer
// is lost: the create answers 502, and the room is removed before the guest
// gets that answer. Before the fix the room stayed, the sync loop adopted it
// under the guest's label, and it billed until its TTL.
func TestLostCreateAnswerOnTheOnlyHotelIsReaped(t *testing.T) {
	tc := newChain(t)
	hb := tc.b.hotelByID("b")
	upstream := hb.cfg.API
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		status, hdr, out := forwardTo(upstream, r, body)
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			hijackClose(w) // the hotel has the room; the answer never reaches the broker
			return
		}
		passThrough(w, status, hdr, out)
	}))
	t.Cleanup(proxy.Close)
	hb.cfg.API = proxy.URL

	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if status != 502 || errCode(doc) != "hotel_unreachable" {
		t.Fatalf("create with the answer lost on the only hotel: %d %v", status, doc)
	}
	// The first reap pass runs before the guest gets its answer.
	if n := callsTo(tc.hotels["b"], "DELETE /v1/sandboxes/"); n != 1 {
		t.Errorf("hotel b got %d DELETE calls after the lost answer; want 1, for the orphan room", n)
	}
	tc.b.syncHotel(context.Background(), hb) // nothing is left to adopt
	_, list := tc.call(t, "key1", "GET", "/v1/sandboxes", nil)
	_, q := tc.call(t, "key1", "GET", "/v1/quota", nil)
	running := q["guest"].(map[string]any)["running_sandboxes"]
	if list["count"] != 0.0 || running != 0.0 {
		t.Errorf("after the 502 the guest lists %v rooms (%v) and quota says %v running; want 0, or the room bills until its TTL", list["count"], list["sandboxes"], running)
	}
}

// The answer from hotel b is lost; the retry lands on hotel c, which refuses
// the request (400: the allowlist names a port the hotel does not allow). A
// 4xx ends the create with no further retry; the room b started is reaped.
func TestLostCreateAnswerIsReapedWhenTheRetryIsRefused(t *testing.T) {
	tc := newChain(t)
	hb := tc.b.hotelByID("b")
	upstream := hb.cfg.API
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			// Hotel b starts the room from a copy without the allowlist, so a
			// room exists when its answer is lost; hotel c sees the guest's
			// allowlist and refuses it.
			var req map[string]any
			_ = json.Unmarshal(body, &req)
			delete(req, "network")
			body, _ = json.Marshal(req)
			forwardTo(upstream, r, body)
			setHotel(tc, "c", func(h *hotel) { h.ok = true }) // c opens once b's answer is lost
			hijackClose(w)
			return
		}
		status, hdr, out := forwardTo(upstream, r, body)
		passThrough(w, status, hdr, out)
	}))
	t.Cleanup(proxy.Close)
	hb.cfg.API = proxy.URL
	setHotel(tc, "c", func(h *hotel) { h.ok = false }) // b is picked first
	bad := map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"},
		"network": map[string]any{"mode": "allowlist", "allow": []string{"bad.example:9"}}}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", bad)
	if status != 400 || errCode(doc) != "invalid_network_allowlist" {
		t.Fatalf("create refused by the second hotel: %d %v", status, doc)
	}
	if n := callsTo(tc.hotels["b"], "DELETE /v1/sandboxes/"); n != 1 {
		t.Errorf("hotel b got %d DELETE calls; want 1, for the room it started before its answer was lost", n)
	}
	tc.b.syncHotel(context.Background(), hb)
	_, list := tc.call(t, "key1", "GET", "/v1/sandboxes", nil)
	if list["count"] != 0.0 {
		t.Errorf("after the 400 the guest lists %v rooms (%v); want 0", list["count"], list["sandboxes"])
	}
}

// The answer from hotel b is lost; the retry waits for a create slot on hotel
// c; the guest gives up and closes its connection. The create ends with 499
// that nobody reads, and the room b started is still reaped.
func TestLostCreateAnswerIsReapedWhenTheGuestGoesAway(t *testing.T) {
	tc := newChain(t)
	hb := tc.b.hotelByID("b")
	upstream := hb.cfg.API
	created := make(chan struct{}, 1)
	deleted := make(chan struct{}, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		status, hdr, out := forwardTo(upstream, r, body)
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/sandboxes":
			setHotel(tc, "c", func(h *hotel) { h.ok = true }) // c opens once b's answer is lost
			created <- struct{}{}
			hijackClose(w)
			return
		case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/sandboxes/"):
			defer func() { deleted <- struct{}{} }()
		}
		passThrough(w, status, hdr, out)
	}))
	t.Cleanup(proxy.Close)
	hb.cfg.API = proxy.URL
	// Hotel c is down until b has the create (so b is picked first) and has
	// no free create slot: the retry waits there until the guest is gone.
	setHotel(tc, "c", func(h *hotel) {
		h.ok = false
		for i := 0; i < cap(h.sem); i++ {
			h.sem <- struct{}{}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gone := make(chan string, 1)
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "POST", tc.srv.URL+"/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20","hotels":["b","c"]}`))
		req.Header.Set("Authorization", "Bearer key1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			gone <- err.Error()
			return
		}
		resp.Body.Close()
		gone <- fmt.Sprintf("answered %d", resp.StatusCode)
	}()
	select {
	case <-created:
	case <-time.After(5 * time.Second):
		t.Fatal("the create did not reach hotel b")
	}
	cancel() // the guest gives up
	t.Logf("guest side: %s", <-gone)
	select {
	case <-deleted:
	case <-time.After(5 * time.Second):
		t.Fatal("hotel b was not asked to delete the room it started for a guest that went away")
	}
	tc.b.syncHotel(context.Background(), hb)
	_, list := tc.call(t, "key1", "GET", "/v1/sandboxes", nil)
	if list["count"] != 0.0 {
		t.Errorf("after the guest went away it still owns %v rooms (%v); want 0", list["count"], list["sandboxes"])
	}
}

// ---------------------------------------------------------------- a delete during a late list (O9)

// A guest deletes a room while the sync loop holds a room list the hotel
// built before the delete. When that list lands, the room stays deleting:
// the quota does not count it as running. Only a room the sync loop alone
// marked deleting (a list that missed a new room) goes back to running when
// the hotel lists it.
func TestGuestDeleteOutlivesALateList(t *testing.T) {
	tc := newChain(t)
	h := tc.b.hotelByID("b")
	upstream := h.cfg.API
	var delayOnce atomic.Bool
	delayOnce.Store(true)
	fetched := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	land := func() { once.Do(func() { close(release) }) }
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		status, hdr, out := forwardTo(upstream, r, body)
		if r.Method == "GET" && r.URL.Path == "/v1/sandboxes" && r.URL.RawQuery == "" && delayOnce.CompareAndSwap(true, false) {
			fetched <- struct{}{} // the hotel built the list
			<-release             // the broker reads it after the guest's delete
		}
		passThrough(w, status, hdr, out)
	}))
	t.Cleanup(proxy.Close)
	t.Cleanup(land) // a failed step must not leave the proxy parked, or Close hangs
	h.cfg.API = proxy.URL
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	done := make(chan struct{})
	go func() { tc.b.syncHotel(context.Background(), h); close(done) }()
	<-fetched
	if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+id, nil); status != 204 {
		t.Fatalf("delete: %d %v", status, doc)
	}
	if st := roomState(tc, id); st != stDeleting {
		t.Fatalf("harness: state right after the delete is %q", st)
	}
	land()
	<-done
	st := roomState(tc, id)
	_, q := tc.call(t, "key1", "GET", "/v1/quota", nil)
	running := q["guest"].(map[string]any)["running_sandboxes"]
	if st != stDeleting || running != 0.0 {
		t.Errorf("room %s after the guest's delete and a late list that still names it: state %q, quota running_sandboxes %v; want %q and 0", id, st, running, stDeleting)
	}
}

// ---------------------------------------------------------------- finished exec results (O10)

// A finished background exec keeps its result for execKeep, so a client can
// still poll it; after that the sweep in saveCompat drops it. A running exec
// is never swept. Before the fix a result of up to 32 MiB stayed for the
// life of the broker unless the room was deleted.
func TestFinishedExecResultsExpire(t *testing.T) {
	dir := t.TempDir()
	release := make(chan struct{})
	var once sync.Once
	tc := r6Chain(t, dir, func(id string, f *fakeHotel, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/exec") && r.Method == "POST" {
				body, _ := io.ReadAll(r.Body)
				var req map[string]any
				_ = json.Unmarshal(body, &req)
				if cmd, _ := req["cmd"].([]any); len(cmd) > 0 && cmd[0] == "sleep" {
					<-release // a long command
				}
				writeJSON(w, 200, map[string]any{"exit_code": 0, "stdout": "done", "stderr": "", "timed_out": false})
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	id := doc["id"].(string)
	start := func(cmd ...string) string {
		status, doc := tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/execs", mustMarshal(map[string]any{"cmd": cmd}), nil)
		if status != 202 {
			t.Fatalf("exec start: %d %v", status, doc)
		}
		return doc["exec_id"].(string)
	}
	finished := start("true")
	if status, doc := tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+finished+"?wait=5", nil, nil); doc["state"] != "exited" {
		t.Fatalf("poll: %d %v", status, doc)
	}
	running := start("sleep", "600")
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	if status, _ := tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+finished, nil, nil); status != 200 {
		t.Fatalf("a result that ended just now answers %d; want 200 for execKeep", status)
	}
	// Two hours pass.
	tc.b.compat.mu.Lock()
	tc.b.compat.execs[finished].doneAt = time.Now().Add(-2 * time.Hour)
	tc.b.compat.mu.Unlock()
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	status, doc = tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+finished, nil, nil)
	if code, _ := r6Detail(doc); status != 404 || code != "exec_not_found" {
		t.Errorf("finished exec two hours after its end: %d %v; want 404 exec_not_found, or the result stays in memory for good", status, doc)
	}
	if status, doc := tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+running, nil, nil); status != 200 || doc["state"] != "running" {
		t.Errorf("running exec after the sweep: %d %v; want 200 running", status, doc)
	}
	once.Do(func() { close(release) })
}

// ---------------------------------------------------------------- snapshot ids outside the list (O11)

// A snapshot id "<hotel>.<snap>" that names a hotel outside the guest's list
// is not found, and that hotel sees no request: it may be dedicated to
// another guest and may hang. Before the fix the guest could fork, delete and
// push snapshots there.
func TestSnapshotIDOnAHotelOutsideTheListIs404(t *testing.T) {
	tc := newChain(t)
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits = guestLimits{Hotels: []string{"b"}}
	tc.b.mu.Unlock()
	fa := tc.hotels["a"]
	fa.mu.Lock()
	// A snapshot on hotel a with g1's label, from before the list was cut.
	fa.snaps["snap_x"] = map[string]any{"snapshot_id": "snap_x", "labels": map[string]any{guestLabel: "g1"}, "size_bytes": 10}
	fa.mu.Unlock()
	before := callsTo(fa, "")
	for _, c := range []struct {
		method, path string
		body         map[string]any
	}{
		{"POST", "/v1/sandboxes", map[string]any{"snapshot_id": "a.snap_x"}},
		{"DELETE", "/v1/snapshots/a.snap_x", nil},
		{"POST", "/v1/snapshots/a.snap_x/push", map[string]any{"image": "ghcr.io/acme/x:1"}},
	} {
		status, doc := tc.call(t, "key1", c.method, c.path, c.body)
		if status != 404 || errCode(doc) != "snapshot_not_found" {
			t.Errorf("%s %s: %d %v; want 404 snapshot_not_found", c.method, c.path, status, doc)
		}
	}
	if n := callsTo(fa, "") - before; n != 0 {
		t.Errorf("hotel a, outside g1's list, received %d request(s) for a snapshot id that names it", n)
	}
}

// ---------------------------------------------------------------- creates behind execs (observed, not changed)

// Observed, not changed (a design item for the owner): creates share the
// data pool with execs. While one guest's execs hold every data connection
// to a hotel, another guest's create on that hotel waits for a connection
// until the hotel create timeout, then answers 502 hotel_unreachable and
// rests the hotel for hotelFailBackoff. The sync loop keeps the hotel up
// meanwhile (TestLongExecsDoNotStarveTheSyncLoop), so the create is placed
// there and waits instead of failing at once.
func TestCreateWaitsBehindAnotherGuestsExecs(t *testing.T) {
	tc := newChain(t)
	_, release := saturateDataPool(t, tc)
	h := tc.b.hotelByID("b")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tc.b.syncHotel(ctx, h)
	var ok bool
	setHotel(tc, "b", func(h *hotel) { ok = h.ok })
	if !ok {
		t.Fatalf("precondition: hotel b went down behind the held data connections; the sync loop must keep it up")
	}
	old := hotelCreateTimeout
	hotelCreateTimeout = time.Second // production: 12 minutes
	t.Cleanup(func() { hotelCreateTimeout = old })
	before := createsOn(tc)["b"]
	t0 := time.Now()
	status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	waited := time.Since(t0)
	var resting bool
	setHotel(tc, "b", func(h *hotel) { resting = time.Now().Before(h.backoffUntil) })
	t.Logf("other guest's create behind %d held connections: %d %s after %.2fs (create timeout %s, then the orphan reaper's first pass waits 3s on the same pool); hotel resting: %v",
		cap(h.sem)+64, status, errCode(doc), waited.Seconds(), hotelCreateTimeout, resting)
	if status != 502 || errCode(doc) != "hotel_unreachable" || waited < hotelCreateTimeout || !resting {
		t.Errorf("want 502 hotel_unreachable after at least the create timeout, with the hotel rested; got %d %s after %.2fs, resting %v", status, errCode(doc), waited.Seconds(), resting)
	}
	if after := createsOn(tc)["b"]; after != before {
		t.Errorf("the create reached the hotel (%d -> %d creates) although every data connection was held", before, after)
	}
	// Once the execs end the pool is free and the same create lands. The
	// rest is cleared by hand: it is the hotel's penalty for the lost answer.
	release()
	setHotel(tc, "b", func(h *hotel) { h.backoffUntil = time.Time{} })
	if status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}); status != 202 {
		t.Errorf("create after the execs ended: %d %v; want 202", status, doc)
	}
}

// ---------------------------------------------------------------- low: lifetime cap, missing expiry

// r6LifetimeChain is a chain whose hotels record heartbeats and answer
// GET room with the expiry expiresIn gives (no expires_at when zero).
func r6LifetimeChain(t *testing.T, expiresIn time.Duration) (*testChain, func() []float64) {
	t.Helper()
	var mu sync.Mutex
	var heartbeats []float64
	tc := r6Chain(t, "", func(id string, f *fakeHotel, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			parts := strings.Split(r.URL.Path, "/")
			switch {
			case strings.HasSuffix(r.URL.Path, "/heartbeat") && r.Method == "POST":
				body, _ := io.ReadAll(r.Body)
				var req map[string]any
				_ = json.Unmarshal(body, &req)
				ttl, _ := req["ttl_seconds"].(float64)
				mu.Lock()
				heartbeats = append(heartbeats, ttl)
				mu.Unlock()
				writeJSON(w, 200, map[string]any{"id": parts[3], "state": "running", "ttl_seconds": ttl,
					"expires_at": time.Now().Add(time.Duration(ttl) * time.Second).UTC().Format(time.RFC3339)})
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/sandboxes/") && len(parts) == 4:
				doc := map[string]any{"id": parts[3], "state": "running"}
				if expiresIn > 0 {
					doc["expires_at"] = time.Now().Add(expiresIn).UTC().Format(time.RFC3339)
				}
				writeJSON(w, 200, doc)
			default:
				next.ServeHTTP(w, r)
			}
		})
	})
	return tc, func() []float64 {
		mu.Lock()
		defer mu.Unlock()
		return append([]float64(nil), heartbeats...)
	}
}

// The lifetime route caps a room at 48 hours, absolute or extended, as the
// create does.
func TestLifetimeRouteCapsAt48Hours(t *testing.T) {
	tc, heartbeats := r6LifetimeChain(t, 47*time.Hour)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	id := doc["id"].(string)
	for _, body := range []map[string]any{
		{"lifetime_seconds": 100 * 3600}, // absolute
		{"extend_by_seconds": 5 * 3600},  // 47 h left + 5 h
	} {
		status, doc := tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/lifetime", mustMarshal(body), nil)
		if status != 200 {
			t.Fatalf("lifetime %v: %d %v", body, status, doc)
		}
		hb := heartbeats()
		if got := hb[len(hb)-1]; got != 48*3600 {
			t.Errorf("lifetime %v: hotel heartbeat ttl_seconds=%v; want the 48 h cap, %d", body, got, 48*3600)
		}
	}
}

// extend_by_seconds adds to what the room has left. When the hotel's room
// document has no expiry, the broker cannot add to it: 502, and no heartbeat
// that would set a wrong TTL.
func TestExtendWithoutAnExpiryFromTheHotelIs502(t *testing.T) {
	tc, heartbeats := r6LifetimeChain(t, 0)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	id := doc["id"].(string)
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/lifetime", mustMarshal(map[string]any{"extend_by_seconds": 600}), nil)
	code, _ := r6Detail(doc)
	if status != 502 || code != "hotel_unreachable" || len(heartbeats()) != 0 {
		t.Errorf("extend with no expiry from the hotel: %d %s, %d heartbeat(s) sent %v; want 502 hotel_unreachable and no heartbeat", status, code, len(heartbeats()), heartbeats())
	}
}

// ---------------------------------------------------------------- low: probe, caps, saved ids

// The probe starts no room on a hotel that rests after a failed create: the
// hotel is not taking rooms, and the probe room would fail or be the only
// room there.
func TestProbeSkipsARestingHotel(t *testing.T) {
	tc := newChain(t)
	tc.b.guests["g1"].cfg.Ops = true
	setHotel(tc, "b", func(h *hotel) { h.backoffUntil = time.Now().Add(time.Minute) })
	before := createsOn(tc)["b"]
	status, doc := tc.call(t, "key1", "POST", "/v1/broker/probe", nil)
	if status != 200 {
		t.Fatalf("probe: %d %v", status, doc)
	}
	res, _ := doc["hotels"].(map[string]any)["b"].(map[string]any)
	if after := createsOn(tc)["b"]; after != before || !strings.Contains(fmt.Sprint(res["error"]), "resting") {
		t.Errorf("probe on a resting hotel: %d room(s) created, result %v; want none and a skipped note", after-before, res)
	}
}

// caps.json keeps the probe results of a hotel the broker has not loaded
// (yet): a runtime hotel whose key file is missing at start, or one in the
// middle of a join. Before the fix the first save after a restart dropped it.
func TestSaveCapsKeepsHotelsNotLoaded(t *testing.T) {
	dir := t.TempDir()
	caps := map[string]any{"zz": map[string]any{"isolation": "gVisor 4.4.0", "sealed": false}}
	raw, _ := json.Marshal(caps)
	if err := os.WriteFile(filepath.Join(dir, "caps.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc := newChainState(t, dir)
	tc.b.loadCaps()
	setHotel(tc, "b", func(h *hotel) { h.caps = map[string]any{"isolation": "gVisor 4.4.0"} })
	tc.b.saveCaps()
	raw, _ = os.ReadFile(filepath.Join(dir, "caps.json"))
	var saved map[string]map[string]any
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	if saved["zz"] == nil || saved["b"] == nil {
		t.Errorf("caps.json after a save: hotels %v; want zz (not loaded) kept beside b", keysOf(func() map[string]any {
			m := map[string]any{}
			for k, v := range saved {
				m[k] = v
			}
			return m
		}()))
	}
}

// A client id read from the state file is handed to its room when the sync
// loop lists the room, and the saved entry goes. Before the fix savedUUIDs
// kept every entry for the life of the process.
func TestSavedUUIDIsConsumedWhenTheRoomIsListed(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	id := doc["id"].(string)
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	tc.start(t)
	tc.b.mu.Lock()
	saved := len(tc.b.savedUUIDs)
	tc.b.mu.Unlock()
	if saved != 1 {
		t.Fatalf("harness: %d saved client ids after the restart, want 1", saved)
	}
	for _, h := range tc.b.hotelList() {
		tc.b.syncHotel(context.Background(), h)
	}
	tc.b.mu.Lock()
	left := len(tc.b.savedUUIDs)
	tc.b.mu.Unlock()
	if status, _ := tc.clientCall(t, "GET", "/v1/sandboxes/"+id, nil, nil); status != 200 || left != 0 {
		t.Errorf("after the sync listed the room: GET by the saved id %d, %d saved id(s) still held; want 200 and 0", status, left)
	}
}
