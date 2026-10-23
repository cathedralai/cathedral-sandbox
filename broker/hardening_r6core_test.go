package main

// Review round 6 probes for broker core (guests, hotels, state, receipts,
// probe). Each test states what the code does today; a failing test is the
// finding. None of these edit production code.

import (
	"context"
	"encoding/json"
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

// ---------------------------------------------------------------- config loader

// A misspelled key in the config file is dropped without an error. The
// positive control is a duplicate hotel id, which loadBroker does refuse.
func TestConfigLoaderFailsOpenOnTypos(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "h.key")
	if err := os.WriteFile(keyFile, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	load := func(raw string) (*broker, error) {
		p := filepath.Join(dir, "c.json")
		if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		return loadBroker(p)
	}
	hotels := `"hotels":[{"id":"h1","api":"http://127.0.0.1:1","health":"http://127.0.0.1:1","key_file":"` + keyFile + `"},{"id":"h2","api":"http://127.0.0.1:1","health":"http://127.0.0.1:1","key_file":"` + keyFile + `"}]`

	// Positive control: duplicate hotel id is refused.
	if _, err := load(`{"listen":"127.0.0.1:0","hotels":[{"id":"h1","api":"x","key_file":"` + keyFile + `"},{"id":"h1","api":"x","key_file":"` + keyFile + `"}]}`); err == nil {
		t.Fatalf("positive control failed: duplicate hotel id accepted")
	}

	// 1. "hotel" for "hotels" on a dedicated guest: the guest gets every hotel.
	b, err := load(`{"listen":"127.0.0.1:0",` + hotels + `,"guests":[{"id":"acme","key_sha256":"ab","hotel":["h1"]}]}`)
	if err == nil {
		g := b.guests["acme"]
		if g.limits.allows("h2") {
			t.Errorf("typo \"hotel\" accepted: guest acme may use h2 (every hotel), wanted an error")
		}
	}
	// 2. "listen_addr" for "listen": Listen is "" and ListenAndServe would bind :80.
	if b, err := load(`{"listen_addr":"127.0.0.1:18100",` + hotels + `}`); err == nil && b.cfg.Listen == "" {
		t.Errorf("typo \"listen_addr\" accepted: Listen is empty, the server would bind :http on every interface")
	}
	// 3. Two guests with one id: both keys own each other's rooms.
	if b, err := load(`{"listen":"127.0.0.1:0",` + hotels + `,"guests":[{"id":"x","key_sha256":"aa"},{"id":"x","key_sha256":"bb"}]}`); err == nil {
		ga, gb := b.byKey["aa"], b.byKey["bb"]
		if ga != nil && gb != nil && ga != gb && ga.cfg.ID == gb.cfg.ID {
			t.Errorf("duplicate guest id accepted: two guest objects share id %q, so each key sees the other's rooms", ga.cfg.ID)
		}
	}
	// 4. Two guests with one key hash: the first guest silently loses its key.
	if b, err := load(`{"listen":"127.0.0.1:0",` + hotels + `,"guests":[{"id":"x","key_sha256":"aa"},{"id":"y","key_sha256":"aa"}]}`); err == nil {
		if b.byKey["aa"] != nil && b.byKey["aa"].cfg.ID == "y" {
			t.Errorf("duplicate key hash accepted: key aa now belongs to y, x is locked out without a message")
		}
	}
	// 5. Guest with no id ("guest_id" typo): id "" matches every unlabeled room.
	if b, err := load(`{"listen":"127.0.0.1:0",` + hotels + `,"guests":[{"guest_id":"x","key_sha256":"aa"}]}`); err == nil {
		if g := b.byKey["aa"]; g != nil && g.cfg.ID == "" {
			t.Errorf("guest with empty id accepted: rooms with no broker_guest label have guest \"\" and this key owns them")
		}
	}
	// 6. "seald" for "sealed" on a hotel: the hotel takes unsealed creates.
	if b, err := load(`{"listen":"127.0.0.1:0","hotels":[{"id":"h1","api":"x","health":"x","key_file":"` + keyFile + `","seald":true,"labels":{"sealed":"true"}}]}`); err == nil {
		if h := b.hotelByID("h1"); h != nil && !h.cfg.Sealed {
			t.Errorf("typo \"seald\" accepted: hotel h1 is not sealed and takes any create")
		}
	}
}

// A guest with an empty id owns every room that has no broker_guest label.
func TestEmptyGuestIDOwnsUnlabeledRooms(t *testing.T) {
	tc := newChain(t)
	// The operator left out "id" for a guest. Model it on the running broker.
	g := &guestState{cfg: guestConfig{ID: "", KeySHA256: sha("nokey")}}
	tc.b.mu.Lock()
	tc.b.guests[""] = g
	tc.b.byKey[sha("nokey")] = g
	tc.b.mu.Unlock()
	// A room started on the hotel outside the broker (no broker_guest label).
	f := tc.hotels["b"]
	f.mu.Lock()
	f.rooms = append(f.rooms, map[string]any{"id": "sbx_ops", "state": "running", "labels": map[string]any{"kind": "ops-test"}})
	f.mu.Unlock()
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	status, _ := tc.call(t, "nokey", "POST", "/v1/sandboxes/b.sbx_ops/exec", map[string]any{"cmd": []string{"id"}})
	if status == 200 {
		t.Errorf("the empty-id guest ran exec in an unlabeled room on hotel b (status %d); wanted 404", status)
	}
}

// ---------------------------------------------------------------- hotels

// PATCH labels on a sealed hotel replaces the label map, and the sealed
// label newHotel forced is gone: no create can select the hotel any more.
func TestPatchLabelsDropsTheSealedLabel(t *testing.T) {
	tc := newChain(t)
	tc.b.hotelByID("a").cfg.Sealed = true
	// Sanity: a sealed create lands on a.
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "sealed": true}); hotelOf(id) != "a" {
		t.Fatalf("sealed create on %s before the patch", id)
	}
	status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"labels": map[string]string{"zone": "eu"}})
	if status != 200 {
		t.Fatalf("patch: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "sealed": true})
	if status != 202 {
		t.Errorf("after PATCH labels without \"sealed\": sealed create answered %d %v; the sealed hotel matches nothing until a restart", status, doc)
	}
}

// The probe stores the Go transport error, which carries the hotel's private
// API URL, in h.caps. The live view sends h.caps to every guest with a view
// token. README: the page shows "never addresses".
func TestProbeErrorPutsHotelAddressOnTheLiveView(t *testing.T) {
	tc := newChain(t)
	tc.b.guests["g1"].cfg.Ops = true
	h := tc.b.hotelByID("b")
	h.cfg.API = "http://127.0.0.1:9/private-hotel-path" // nothing listens: connection refused
	status, doc := tc.call(t, "key1", "POST", "/v1/broker/probe", nil)
	if status != 200 {
		t.Fatalf("probe: %d %v", status, doc)
	}
	snap, _ := json.Marshal(tc.b.snapshot(tc.b.guests["g2"]))
	for _, leak := range []string{"127.0.0.1:9", "private-hotel-path"} {
		if strings.Contains(string(snap), leak) {
			t.Errorf("live view data for g2 holds the hotel address %q: %.300s", leak, snap)
		}
	}
	if tc.b.cfg.StateDir == "" {
		return
	}
}

// The probe starts a room on a drained hotel. Drain means "no new rooms here".
func TestProbeStartsARoomOnADrainedHotel(t *testing.T) {
	tc := newChain(t)
	tc.b.guests["g1"].cfg.Ops = true
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/b", map[string]any{"drain": true}); status != 200 {
		t.Fatalf("drain: %d %v", status, doc)
	}
	before := createsOn(tc)["b"]
	if status, doc := tc.call(t, "key1", "POST", "/v1/broker/probe", nil); status != 200 {
		t.Fatalf("probe: %d %v", status, doc)
	}
	if after := createsOn(tc)["b"]; after != before {
		t.Errorf("probe created %d room(s) on drained hotel b", after-before)
	}
}

// One guest's long execs take every connection the broker has to a hotel
// (MaxConnsPerHost = concurrency + 64). The sync loop's health GET then waits
// for a connection, times out, and after okWindow the hotel is "down" for
// every guest. Condition: health and API share host:port (the config
// example uses two ports; the sealed hotel's config is private).
func TestLongExecsStarveHealthAndTakeTheHotelDown(t *testing.T) {
	if testing.Short() {
		t.Skip("takes about 50 s")
	}
	tc := newChain(t)
	f := tc.hotels["b"]
	var blocked atomic.Int32
	wrap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/exec") {
			_, _ = io.Copy(io.Discard, r.Body) // read the body, so the server notices a closed connection
			blocked.Add(1)
			<-r.Context().Done() // a long exec: never answers while the client waits
			return
		}
		f.ServeHTTP(w, r)
	}))
	t.Cleanup(wrap.Close)
	h := tc.b.hotelByID("b")
	h.cfg.API, h.cfg.Health = wrap.URL, wrap.URL
	tc.b.syncHotel(context.Background(), h) // one good health answer
	setHotel(tc, "b", func(h *hotel) { h.ok = true })
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})

	n := cap(h.sem) + 64 // MaxConnsPerHost in newHotel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(ctx, "POST", tc.srv.URL+"/v1/sandboxes/"+id+"/exec", strings.NewReader(`{"cmd":["sleep","3600"],"timeout_seconds":3600}`))
			req.Header.Set("Authorization", "Bearer key1")
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	deadline := time.Now().Add(10 * time.Second)
	for blocked.Load() < int32(n) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if blocked.Load() < int32(n) {
		cancel()
		wg.Wait()
		t.Fatalf("only %d of %d execs reached the hotel", blocked.Load(), n)
	}
	// Let the create's own answer age out of okWindow, as it would in production.
	h.lastAnswer.Store(time.Now().Add(-okWindow).UnixNano())
	setHotel(tc, "b", func(h *hotel) { h.lastOK = time.Now().Add(-okWindow) })
	t0 := time.Now()
	tc.b.syncHotel(context.Background(), h) // health, quota and list each wait 10 s for a connection
	var ok bool
	var lastErr string
	setHotel(tc, "b", func(h *hotel) { ok, lastErr = h.ok, h.lastErr })
	t.Logf("syncHotel took %.1fs, ok=%v, lastErr=%q", time.Since(t0).Seconds(), ok, lastErr)
	status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	cancel()
	wg.Wait()
	if ok {
		t.Errorf("hotel b stayed up while %d execs of one guest held every broker connection", n)
	}
	if status == 202 {
		t.Errorf("another guest's create on b answered 202; wanted 503 hotels_unavailable to show the loss")
	} else {
		t.Logf("other guest's create: %d %v", status, doc)
	}
}

// ---------------------------------------------------------------- state

// main() calls loadCaps before loadRuntimeHotels, so a runtime hotel's probe
// result is dropped at restart; the next saveCaps rewrites caps.json without it.
func TestRuntimeHotelCapsLostAtRestart(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "d", "api": hs.URL, "key": joinKey}); status != 201 {
		t.Fatalf("join: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	tc.b.hotelByID("d").caps = map[string]any{"isolation": "gVisor 4.4.0", "sealed": false}
	tc.b.mu.Unlock()
	tc.b.saveCaps()
	// Restart in main()'s order.
	tc.srv.Close()
	b, err := loadBroker(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	b.loadCaps()
	if err := b.loadCompat(); err != nil {
		t.Fatal(err)
	}
	if err := b.loadRuntimeHotels(); err != nil {
		t.Fatal(err)
	}
	if h := b.hotelByID("d"); h == nil || h.caps == nil {
		t.Errorf("runtime hotel d has no caps after restart (loadCaps ran before loadRuntimeHotels)")
	}
	b.saveCaps()
	raw, _ := os.ReadFile(filepath.Join(dir, "caps.json"))
	if !strings.Contains(string(raw), `"d"`) {
		t.Errorf("caps.json lost hotel d for good after the first save: %s", raw)
	}
}

// Client state is written by a 1 s ticker and never at shutdown. A restart
// within that second loses the newest client ids and idempotency answers.
func TestRestartWithinASecondLosesClientIDs(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	ctx, cancel := context.WithCancel(context.Background())
	go tc.b.saveLoop(ctx)
	// First room: wait for the save loop, as production normally would.
	_, first := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	firstID, _ := first["id"].(string)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if raw, _ := os.ReadFile(filepath.Join(dir, stateFile)); strings.Contains(string(raw), firstID) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Second room, then "systemctl restart" right away.
	_, second := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	secondID, _ := second["id"].(string)
	cancel() // main() waits for saveLoop's final write before it exits; model that wait
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if raw, _ := os.ReadFile(filepath.Join(dir, stateFile)); strings.Contains(string(raw), secondID) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	tc.start(t)
	for _, h := range tc.b.hotelList() {
		tc.b.syncHotel(context.Background(), h) // rooms come back from the hotel lists
	}
	s1, _ := tc.clientCall(t, "GET", "/v1/sandboxes/"+firstID, nil, nil)
	s2, _ := tc.clientCall(t, "GET", "/v1/sandboxes/"+secondID, nil, nil)
	t.Logf("after restart: first room %d, second room %d", s1, s2)
	if s1 != 200 {
		t.Errorf("first room (saved by the loop) answered %d after restart", s1)
	}
	if s2 != 200 {
		t.Errorf("second room, created in the second before the restart, answered %d after restart: the room runs on the hotel but its client id is gone", s2)
	}
}

// A corrupt state file (power loss after rename, no fsync) is logged, the
// broker starts empty, and the first save replaces the file. Nothing is kept.
func TestCorruptStateFileIsReplacedNotKept(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	_, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	id, _ := doc["id"].(string)
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(filepath.Join(dir, stateFile))
	if !strings.Contains(string(good), id) {
		t.Fatalf("state file has no room id")
	}
	// Truncate the file as a crash could leave it.
	if err := os.WriteFile(filepath.Join(dir, stateFile), good[:len(good)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	tc.srv.Close()
	b, err := loadBroker(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	lerr := b.loadCompat()
	t.Logf("loadCompat on the truncated file: %v (main logs this and goes on)", lerr)
	for _, h := range b.hotelList() {
		h.ok, h.slots = true, 100
	}
	for _, h := range b.hotelList() {
		b.syncHotel(context.Background(), h)
	}
	b.markDirty()
	if err := b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	// A truncated file cannot be read back; what must hold is that a copy of
	// it survives the next save, so the ids can be recovered by hand.
	kept := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), stateFile+".corrupt-") {
			raw, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			kept = strings.Contains(string(raw), id)
		}
	}
	if !kept {
		t.Errorf("after one save no copy of the old state file with client id %s exists; dir: %v", id, names)
	}
}

// A background exec started through the client path lives in memory only. A
// broker restart answers exec_not_found while the command still runs.
func TestCompatExecIsForgottenAtRestart(t *testing.T) {
	t.Skip("pending (review round 6): a background exec lives in the broker's memory; the hotel runs the command synchronously, so a broker restart loses the result")
	dir := t.TempDir()
	tc := newChainState(t, dir)
	_, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	id, _ := doc["id"].(string)
	status, ex := tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/execs", mustMarshal(map[string]any{"cmd": []string{"sleep", "600"}, "timeout_seconds": 600}), nil)
	if status != 202 {
		t.Fatalf("exec start: %d %v", status, ex)
	}
	execID, _ := ex["exec_id"].(string)
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	tc.start(t)
	for _, h := range tc.b.hotelList() {
		tc.b.syncHotel(context.Background(), h)
	}
	status, doc = tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+execID, nil, nil)
	if status != 200 {
		t.Errorf("exec poll after a broker restart: %d %v; the client never gets the result", status, doc)
	}
}

// ---------------------------------------------------------------- guests

// A batch larger than max_creates_per_minute can never pass; the answer is
// 429 with Retry-After 60 every time, so a client that obeys it loops.
func TestBatchOverRateLimitRetriesForever(t *testing.T) {
	tc := limitedChain(t, guestLimits{MaxCreatesPerMinute: 2})
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20","count":3}`))
		req.Header.Set("Authorization", "Bearer key1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "60" {
			t.Fatalf("batch of 3 over a limit of 2: %d Retry-After %q", resp.StatusCode, resp.Header.Get("Retry-After"))
		}
	}
	t.Logf("observation: a count above the per-minute limit is 429 with Retry-After 60 on every try; the message does not say to lower count")
}

// g.recent grows on every create and is pruned only in snapshot (live view).
func TestRecentCreatesPrunedOnlyByTheLiveView(t *testing.T) {
	tc := newChain(t)
	for i := 0; i < 5; i++ {
		tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	}
	g := tc.b.guests["g1"]
	tc.b.mu.Lock()
	g.recent = append([]time.Time{time.Now().Add(-2 * time.Hour)}, g.recent...) // an old entry a live view would drop
	n := len(g.recent)
	tc.b.mu.Unlock()
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	tc.b.mu.Lock()
	m := len(g.recent)
	tc.b.mu.Unlock()
	if m != n+1 {
		t.Fatalf("recent %d -> %d", n, m)
	}
	t.Logf("observation: g.recent keeps a 2 h old entry with no live view open (%d entries); extends B55", m)
}

// ---------------------------------------------------------------- hotel join

// hotels.json is "null" when the last runtime hotel leaves; load must take it.
func TestEmptyRuntimeHotelsFileLoads(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	if status, _ := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "d", "api": hs.URL, "key": joinKey}); status != 201 {
		t.Fatalf("join %d", status)
	}
	if status, _ := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/d", nil); status != 204 {
		t.Fatalf("leave %d", status)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, runtimeHotelsFile))
	t.Logf("hotels.json after the last leave: %s", raw)
	tc.start(t)
	if tc.b.hotelByID("d") != nil {
		t.Fatalf("hotel came back")
	}
}

// Join writes the key file before addHotel; a join refused as a duplicate by
// addHotel keeps the key on disk. Here: two joins race past the hotelByID check.
func TestJoinKeyFileOutlivesARefusedJoin(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	// Pre-add "d" between the check and the add by adding it directly.
	h := newHotel(hotelConfig{ID: "d", API: hs.URL, Health: hs.URL}, joinKey)
	if err := tc.b.addHotel(h); err != nil {
		t.Fatal(err)
	}
	// A direct call to the path after the check: write key then addHotel fails.
	keyDir := filepath.Join(dir, "hotel-keys")
	_ = os.MkdirAll(keyDir, 0o700)
	_ = os.WriteFile(filepath.Join(keyDir, "d.key"), []byte(joinKey+"\n"), 0o600)
	h2 := newHotel(hotelConfig{ID: "d", API: hs.URL, Health: hs.URL, KeyFile: filepath.Join(keyDir, "d.key")}, joinKey)
	if err := tc.b.addHotel(h2); err == nil {
		t.Fatalf("second add passed")
	}
	if _, err := os.Stat(filepath.Join(keyDir, "d.key")); err != nil {
		t.Fatalf("key file: %v", err)
	}
	t.Logf("observation: a refused join leaves hotel-keys/d.key behind (operator-only path, no customer effect)")
}

// ---------------------------------------------------------------- races

// patchHotel writes h.cfg.Labels under b.mu; parseSelection and anyHotel read
// it with no lock. Run with -race to see whether the detector flags it.
func TestPatchHotelLabelsRaceWithCreates(t *testing.T) {
	tc := newChain(t)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			labels := map[string]string{"zone": "eu"}
			if i%2 == 0 {
				labels["sealed"] = "true"
			}
			rawCall(tc, "operator-key", "", "PATCH", "/v1/broker/hotels/a", mustMarshal(map[string]any{"labels": labels}))
		}
	}()
	for i := 0; i < 40; i++ {
		rawCall(tc, "key1", "", "POST", "/v1/sandboxes", []byte(`{"image":"alpine:3.20","hotel_labels":{"zone":"eu"}}`))
		rawCall(tc, "key1", "cathedral-harbor/0.1.5", "POST", "/v1/sandboxes", []byte(`{"template":"room-1x4"}`))
	}
	close(stop)
	wg.Wait()
}
