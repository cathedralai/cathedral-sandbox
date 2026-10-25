package main

// Review round 6 probes for broker/compat.go, build.go and images.go.
// Each test states the client sequence it reproduces. A failing test here is
// the evidence for a finding in the round 6 report; it is not a regression
// test for a fix. The crash probe is skipped unless REVIEW6_CRASH=1 is set,
// because it takes the whole test binary down.

import (
	"context"
	"encoding/base64"
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

// r6Chain is newChainState with a wrapper around each fake hotel, so a probe
// can answer routes the fake hotel does not have (heartbeat, GET room) or
// hold a call (build, exec) until the test releases it.
func r6Chain(t *testing.T, stateDir string, wrap func(id string, f *fakeHotel, next http.Handler) http.Handler) *testChain {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "hotel.key")
	if err := os.WriteFile(key, []byte("hotel-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	tc := &testChain{hotels: map[string]*fakeHotel{}}
	cfg := config{StateDir: stateDir, OperatorKeySHA256: sha("operator-key"), InsecureCookie: true,
		Guests: []guestConfig{{ID: "g1", KeySHA256: sha("key1"), ViewTokenSHA256: sha("view1")}, {ID: "g2", KeySHA256: sha("key2")}}}
	for _, id := range []string{"a", "b", "c"} {
		f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
		var h http.Handler = f
		if wrap != nil {
			h = wrap(id, f, f)
		}
		hs := httptest.NewServer(h)
		t.Cleanup(hs.Close)
		tc.hotels[id] = f
		hc := hotelConfig{ID: id, Name: id, API: hs.URL, Health: hs.URL, KeyFile: key, Concurrency: 4}
		if id == "a" {
			hc.Labels = map[string]string{"sealed": "true"}
		}
		cfg.Hotels = append(cfg.Hotels, hc)
	}
	raw, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.cfgPath = cfgPath
	tc.start(t)
	return tc
}

func r6LastCreate(tc *testChain) map[string]any {
	var last map[string]any
	for _, f := range tc.hotels {
		f.mu.Lock()
		if len(f.creates) > 0 {
			last = f.creates[len(f.creates)-1]
		}
		f.mu.Unlock()
	}
	return last
}

func r6Detail(doc map[string]any) (string, string) {
	d, _ := doc["detail"].(map[string]any)
	code, _ := d["error"].(string)
	msg, _ := d["message"].(string)
	return code, msg
}

// ---------------------------------------------------------------- F1: lifetime

// The cloud API defines extend_by_seconds as expires_at += N. The compat
// layer sends the hotel a heartbeat with ttl_seconds = N, and the hotel sets
// expires_at = now + N. A room with an hour left that is extended by ten
// minutes now ends in ten minutes.
func TestExtendBySecondsShortensTheRoom(t *testing.T) {
	var mu sync.Mutex
	var heartbeats []map[string]any
	tc := r6Chain(t, "", func(id string, f *fakeHotel, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			parts := strings.Split(r.URL.Path, "/")
			if strings.HasSuffix(r.URL.Path, "/heartbeat") && r.Method == "POST" {
				body, _ := io.ReadAll(r.Body)
				var req map[string]any
				_ = json.Unmarshal(body, &req)
				mu.Lock()
				heartbeats = append(heartbeats, req)
				mu.Unlock()
				ttl, _ := req["ttl_seconds"].(float64)
				writeJSON(w, 200, map[string]any{"id": parts[3], "state": "running", "ttl_seconds": ttl,
					"expires_at": time.Now().Add(time.Duration(ttl) * time.Second).UTC().Format(time.RFC3339)})
				return
			}
			if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/sandboxes/") && len(parts) == 4 {
				// The room has 3,600 s left.
				writeJSON(w, 200, map[string]any{"id": parts[3], "state": "running", "ttl_seconds": 3600,
					"expires_at": time.Now().Add(3600 * time.Second).UTC().Format(time.RFC3339)})
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "lifetime_seconds": 3600}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	id := doc["id"].(string)
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/lifetime", mustMarshal(map[string]any{"extend_by_seconds": 600}), nil)
	if status != 200 {
		t.Fatalf("lifetime: %d %v", status, doc)
	}
	mu.Lock()
	got := append([]map[string]any(nil), heartbeats...)
	mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("hotel heartbeats: %v", got)
	}
	ttl, _ := got[0]["ttl_seconds"].(float64)
	if ttl < 4100 {
		t.Errorf("extend_by_seconds=600: hotel heartbeat ttl_seconds=%v, the room now ends in %v s; the client asked for 3600 + 600 = 4200 s", ttl, ttl)
	}
	// The cloud API's other field, lifetime_seconds, is absolute from now.
	// The compat route does not read it and sends its default.
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/lifetime", mustMarshal(map[string]any{"lifetime_seconds": 7200}), nil)
	if status != 200 {
		t.Fatalf("lifetime: %d %v", status, doc)
	}
	mu.Lock()
	got = append([]map[string]any(nil), heartbeats...)
	mu.Unlock()
	if ttl, _ := got[len(got)-1]["ttl_seconds"].(float64); ttl != 7200 {
		t.Errorf("lifetime_seconds=7200: hotel heartbeat ttl_seconds=%v", ttl)
	}
}

// ---------------------------------------------------------------- F2: create fields

// The cloud API create takes env and shape. The compat create forwards both
// to the hotel: vcpus as vcpu, memory_mib rounded up to whole GiB, disk_gib
// as is. Before the fix the room started without the environment the task
// was given and at the template's size.
func TestCompatCreateForwardsEnvAndShape(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{
		"template": "room-1x4",
		"env":      map[string]string{"HF_TOKEN": "t", "TASK": "x"},
		"shape":    map[string]any{"vcpus": 2, "memory_mib": 6000, "disk_gib": 20},
	}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	created := r6LastCreate(tc)
	if env, _ := created["env"].(map[string]any); env["HF_TOKEN"] != "t" || env["TASK"] != "x" {
		t.Errorf("hotel create env=%v; the client sent HF_TOKEN and TASK", created["env"])
	}
	if res, _ := created["resources"].(map[string]any); res["vcpu"] != 2.0 || res["memory_gib"] != 6.0 || res["disk_gib"] != 20.0 {
		t.Errorf("hotel create resources=%v; the client asked for shape vcpus=2 memory_mib=6000 (6 GiB rounded up) disk_gib=20", res)
	}
}

// ---------------------------------------------------------------- F3: build after restart

// After a broker restart the build map is empty until something starts the
// builds again. The create path does not: a create from a built image
// answers 409 image_not_ready on every try until some GET /v1/images/<id>.
func TestCreateFromBuiltImageAfterRestartIs409UntilSomeoneGETs(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	body, ctype := buildForm(t, "FROM alpine:3.20\nRUN echo hi\n", []byte("ctx-bytes"))
	_, img := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	id := img["image_id"].(string)
	if view := waitImage(t, tc, id); view["state"] != "ready" {
		t.Fatalf("build: %v", view)
	}
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	builds := func() int {
		n := 0
		for _, f := range tc.hotels {
			f.mu.Lock()
			n += len(f.builds)
			f.mu.Unlock()
		}
		return n
	}
	before := builds()
	tc.start(t) // deploy stage B: a broker restart
	for _, h := range tc.b.hotelList() {
		tc.b.syncHotel(context.Background(), h)
	}
	var status int
	var doc map[string]any
	for i := 0; i < 20; i++ {
		status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": id}), nil)
		if status == 201 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if status != 201 {
		code, msg := r6Detail(doc)
		t.Errorf("create from a built image after the restart: %d %s %q on 20 tries; hotels got %d build requests meanwhile (want > 0)", status, code, msg, builds()-before)
	}
	waitImage(t, tc, id) // a GET is what starts the rebuild
	status, _ = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": id}), nil)
	t.Logf("after GET /v1/images/<id>: create answers %d", status)
}

// ---------------------------------------------------------------- F4: build map reset

// r6BuildGate holds POST /v1/images/build on one hotel until the test
// answers it.
type r6BuildGate struct {
	mu       sync.Mutex
	calls    []chan int
	released []bool
	seen     chan struct{}
}

func r6GatedBuild(hotelID string) (func(id string, f *fakeHotel, next http.Handler) http.Handler, *r6BuildGate) {
	g := &r6BuildGate{seen: make(chan struct{}, 16)}
	wrap := func(id string, f *fakeHotel, next http.Handler) http.Handler {
		if id != hotelID {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/images/build" && r.Method == "POST" {
				ch := make(chan int, 1)
				g.mu.Lock()
				g.calls = append(g.calls, ch)
				g.released = append(g.released, false)
				g.mu.Unlock()
				g.seen <- struct{}{}
				if status := <-ch; status == 200 {
					writeJSON(w, 200, map[string]any{"image": "cathedral-build-0123456789abcdef:latest", "cached": false})
				} else {
					writeErr(w, status, "image_build_failed", "docker build failed")
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	return wrap, g
}

func (g *r6BuildGate) wait(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-g.seen:
		case <-time.After(5 * time.Second):
			t.Fatalf("build call did not arrive")
		}
	}
}

func (g *r6BuildGate) release(i, status int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if i < len(g.calls) && !g.released[i] {
		g.released[i] = true
		g.calls[i] <- status
	}
}

func (g *r6BuildGate) releaseAll() {
	g.mu.Lock()
	n := len(g.calls)
	g.mu.Unlock()
	for i := 0; i < n; i++ {
		g.release(i, 200)
	}
}

// r6ShortContext puts the broker in the state B58 describes: a restart over
// a cut-short context file left a short context in memory while a build
// started from it is still in flight.
func r6ShortContext(tc *testChain, id string, short []byte) {
	tc.b.compat.mu.Lock()
	tc.b.compat.images[id].buildCtx = short
	tc.b.compat.mu.Unlock()
}

// A resubmit of the same build resets the build map (B58's fix) while a
// build goroutine is still in flight. When that goroutine returns, its
// result lands on the entry of the new build: the image shows failed while
// the only live build is still running.
func TestStaleBuildResultOverwritesTheNewBuild(t *testing.T) {
	wrap, gate := r6GatedBuild("b")
	tc := r6Chain(t, "", wrap)
	t.Cleanup(gate.releaseAll)
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits = guestLimits{Hotels: []string{"b"}}
	tc.b.mu.Unlock()
	full := []byte("full-context-bytes")
	body, ctype := buildForm(t, "FROM alpine:3.20\n", full)
	_, img := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	id := img["image_id"].(string)
	gate.wait(t, 1) // call 1 on b is in flight
	r6ShortContext(tc, id, full[:4])
	_, again := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	if again["image_id"] != id {
		t.Fatalf("id changed: %v", again)
	}
	gate.wait(t, 1)      // call 2 on b (the real build) is in flight
	gate.release(0, 502) // call 1 (the short-context build) fails late
	time.Sleep(100 * time.Millisecond)
	_, view := tc.clientCall(t, "GET", "/v1/images/"+id, nil, nil)
	if view["state"] != "pending" {
		t.Errorf("the only live build is still running, yet the image shows %v", view)
	}
	gate.release(1, 200)
	time.Sleep(100 * time.Millisecond) // let the live build's goroutine record its answer
	t.Logf("after the live build ends: %v", waitImage(t, tc, id))
}

// Same sequence, with hotel b drained between the two submits: the new map
// has no entry for b, the old goroutine dereferences nil and the broker
// process dies. REVIEW6_CRASH=1 go test -run TestBuildResetWithDrainedHotel .
func TestBuildResetWithDrainedHotelCrashesTheBroker(t *testing.T) {
	// Before the fix this probe took the whole test binary down (nil entry).
	wrap, gate := r6GatedBuild("b")
	tc := r6Chain(t, "", wrap)
	t.Cleanup(gate.releaseAll)
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits = guestLimits{Hotels: []string{"b"}}
	tc.b.mu.Unlock()
	full := []byte("full-context-bytes")
	body, ctype := buildForm(t, "FROM alpine:3.20\n", full)
	_, img := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	id := img["image_id"].(string)
	gate.wait(t, 1)
	r6ShortContext(tc, id, full[:4])
	tc.b.mu.Lock()
	tc.b.hotelByID("b").cfg.Drain = true // operator drains b for maintenance
	tc.b.mu.Unlock()
	tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	gate.release(0, 502) // the in-flight build returns; its entry must still exist
	time.Sleep(300 * time.Millisecond)
	status, view := tc.clientCall(t, "GET", "/v1/images/"+id, nil, nil)
	if status != 200 {
		t.Fatalf("the broker did not answer after the in-flight build returned: %d %v", status, view)
	}
}

// ---------------------------------------------------------------- F9: idempotency caches a retryable 409

// compatIdem drops 429 and 5xx answers so a retry runs again, but keeps a
// 409 image_not_ready, which carries Retry-After. A client that retries the
// create with the same Idempotency-Key, as the answer tells it to, gets the
// cached 409 for 48 hours, after the image is ready too.
func TestIdempotencyReplaysImageNotReadyAfterTheImageIsReady(t *testing.T) {
	wrap, gate := r6GatedBuild("b")
	tc := r6Chain(t, "", wrap)
	t.Cleanup(gate.releaseAll)
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits = guestLimits{Hotels: []string{"b"}}
	tc.b.mu.Unlock()
	body, ctype := buildForm(t, "FROM alpine:3.20\n", []byte("ctx"))
	_, img := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	id := img["image_id"].(string)
	gate.wait(t, 1) // the build is running on b
	hdr := map[string]string{"Idempotency-Key": "job-7-room-1"}
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": id}), hdr)
	code, _ := r6Detail(doc)
	if status != 409 || code != "image_not_ready" {
		t.Fatalf("create while building: %d %v", status, doc)
	}
	gate.release(0, 200)
	if view := waitImage(t, tc, id); view["state"] != "ready" {
		t.Fatalf("image: %v", view)
	}
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": id}), hdr)
	if status != 201 {
		code, msg := r6Detail(doc)
		t.Errorf("the keyed retry after the image became ready: %d %s %q; the same create without the key answers %d",
			status, code, msg, func() int {
				s, _ := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": id}), nil)
				return s
			}())
	}
}

// ---------------------------------------------------------------- F10: exec results outlive the room

// A finished background exec keeps its whole output in the broker after the
// room is gone. Nothing prunes the map (B55); this probe shows the size per
// exec and that deletion of the room does not release it.
func TestFinishedExecsKeepOutputAfterRoomDeletion(t *testing.T) {
	big := strings.Repeat("x", 1<<20)
	tc := r6Chain(t, "", func(id string, f *fakeHotel, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/exec") && r.Method == "POST" {
				writeJSON(w, 200, map[string]any{"exit_code": 0, "stdout": big, "stderr": "", "timed_out": false})
				return
			}
			if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/sandboxes/") {
				w.WriteHeader(204)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	id := doc["id"].(string)
	for i := 0; i < 3; i++ {
		status, doc = tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/execs", mustMarshal(map[string]any{"cmd": []string{"true"}}), nil)
		if status != 202 {
			t.Fatalf("exec start: %d %v", status, doc)
		}
		eid := doc["exec_id"].(string)
		if status, doc = tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+eid+"?wait=5", nil, nil); doc["state"] != "exited" {
			t.Fatalf("poll: %d %v", status, doc["state"])
		}
	}
	if status, doc = tc.clientCall(t, "DELETE", "/v1/sandboxes/"+id, nil, nil); status != 200 {
		t.Fatalf("delete: %d %v", status, doc)
	}
	tc.b.compat.mu.Lock()
	held := 0
	for _, ex := range tc.b.compat.execs {
		s, _ := ex.result["stdout"].(string)
		held += len(s)
	}
	n := len(tc.b.compat.execs)
	tc.b.compat.mu.Unlock()
	if n != 0 {
		t.Errorf("after the room was deleted the broker still holds %d finished execs with %d MiB of output", n, held>>20)
	}
}

// ---------------------------------------------------------------- F5: snapshots outside the list

// B56 scoped list, quota and usage to the guest's hotel list. The snapshot
// routes still ask every hotel: a hotel outside the list is called for the
// guest's snapshots, and a hung one holds the guest's snapshot list.
func TestSnapshotRoutesReachHotelsOutsideTheGuestList(t *testing.T) {
	tc := newChain(t)
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits = guestLimits{Hotels: []string{"b", "c"}}
	tc.b.mu.Unlock()
	before := callsTo(tc.hotels["a"], "GET /v1/snapshots")
	tc.call(t, "key1", "GET", "/v1/snapshots", nil)
	tc.call(t, "key1", "DELETE", "/v1/snapshots/nosuch", nil)
	tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": "nosuch"}) // a fork by bare name
	if n := callsTo(tc.hotels["a"], "GET /v1/snapshots") - before; n != 0 {
		t.Errorf("hotel a, outside g1's list, was asked %d times for g1's snapshots", n)
	}
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(hang.Close)
	tc.b.hotelByID("a").cfg.API = hang.URL
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest("GET", tc.srv.URL+"/v1/snapshots", nil)
	req.Header.Set("Authorization", "Bearer key1")
	t0 := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		t.Errorf("GET /v1/snapshots waited %.1fs on hotel a, which g1 may not use: %v", time.Since(t0).Seconds(), err)
		return
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if he, _ := doc["hotel_errors"].(map[string]any); he["a"] != nil {
		t.Errorf("GET /v1/snapshots names hotel a: %v", doc)
	}
}

// ---------------------------------------------------------------- F6: chain-wide free rooms

// The client catalog and quota sum free rooms over every hotel, not the
// guest's list. A guest whose only hotel is full reads available: true.
func TestCatalogAndQuotaCountRoomsOutsideTheGuestList(t *testing.T) {
	tc := newChain(t)
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits = guestLimits{Hotels: []string{"b"}}
	tc.b.hotelByID("b").slots = 0 // g1's only hotel is full
	tc.b.mu.Unlock()
	_, cat := tc.clientCall(t, "GET", "/v1/sandboxes/catalog", nil, nil)
	if cat["available"] != false || cat["free_rooms"] != 0.0 {
		t.Errorf("catalog for a guest whose only hotel is full: available=%v free_rooms=%v (a and c, outside the list, hold the 200 free rooms)", cat["available"], cat["free_rooms"])
	}
	_, q := tc.clientCall(t, "GET", "/v1/quota", nil, nil)
	if av, _ := q["available"].(map[string]any); q["admission_open"] != false || av["rooms"] != 0.0 {
		t.Errorf("quota: admission_open=%v available=%v", q["admission_open"], q["available"])
	}
}

// ---------------------------------------------------------------- F7: tar over the exec cap

// A tar larger than the exec output cap comes back as 500 tar_failed with an
// empty message. The file route answers the same case with 413 and a reason.
func TestTarOverTheExecCapIsA500WithNoMessage(t *testing.T) {
	tc := r6Chain(t, "", func(id string, f *fakeHotel, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/exec") && r.Method == "POST" {
				writeJSON(w, 200, map[string]any{"exit_code": 0, "stdout": base64.StdEncoding.EncodeToString([]byte("gzip bytes cut at 16 MiB")),
					"stderr": "", "timed_out": false, "truncated": true})
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	id := doc["id"].(string)
	status, doc = tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/tar?path=/work", nil, nil)
	code, msg := r6Detail(doc)
	if status != 413 || msg == "" {
		t.Errorf("tar over the cap: %d %s %q (the file route says 413 file_too_large with a reason)", status, code, msg)
	}
}

// ---------------------------------------------------------------- F8: background exec and restart

// Background execs live in memory. After a broker restart the poll answers
// 404 while the command runs on; the keyed retry of the start replays an
// exec_id the new process does not know. A synchronous exec in flight at
// the restart has no saved idempotency entry, so the keyed retry runs the
// command a second time while the first still runs in the room.
func TestBackgroundExecIsLostOnBrokerRestart(t *testing.T) {
	t.Skip("pending design: background execs across a broker restart")
	dir := t.TempDir()
	release := make(chan struct{})
	var once sync.Once
	var execs atomic.Int32
	tc := r6Chain(t, dir, func(id string, f *fakeHotel, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/exec") && r.Method == "POST" {
				execs.Add(1)
				<-release
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
	hdr := map[string]string{"Idempotency-Key": "exec-1"}
	cmd := mustMarshal(map[string]any{"cmd": []string{"python", "train.py"}, "timeout_seconds": 3000})
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/execs", cmd, hdr)
	if status != 202 {
		t.Fatalf("exec start: %d %v", status, doc)
	}
	eid := doc["exec_id"].(string)
	// A synchronous exec, in flight when the broker goes down. The client's
	// connection drops with the process; here its context is cancelled once
	// the hotel has the command, so the old test server can close.
	syncHdr := map[string]string{"Idempotency-Key": "exec-2", "Content-Type": "application/json"}
	syncCmd := mustMarshal(map[string]any{"cmd": []string{"python", "eval.py"}, "timeout_seconds": 3000})
	ctx, cancel := context.WithCancel(context.Background())
	syncDone := make(chan struct{})
	go func() {
		defer close(syncDone)
		req, _ := http.NewRequestWithContext(ctx, "POST", tc.srv.URL+"/v1/sandboxes/"+id+"/exec", strings.NewReader(string(syncCmd)))
		req.Header.Set("Authorization", "Bearer key1")
		req.Header.Set("User-Agent", "cathedral-harbor/0.1.5")
		for k, v := range syncHdr {
			req.Header.Set(k, v)
		}
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	for i := 0; execs.Load() < 2 && i < 100; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if execs.Load() != 2 {
		t.Fatalf("hotel exec calls before the restart: %d, want 2", execs.Load())
	}
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-syncDone
	tc.start(t) // deploy stage B
	for _, h := range tc.b.hotelList() {
		tc.b.syncHotel(context.Background(), h)
	}
	status, doc = tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+eid+"?wait=1", nil, nil)
	if status != 200 {
		code, msg := r6Detail(doc)
		t.Errorf("poll after the restart: %d %s %q; the command still runs in the room", status, code, msg)
	}
	// The keyed retry of the background start replays the saved 202.
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/execs", cmd, hdr)
	if status != 202 || doc["exec_id"] != eid {
		t.Errorf("keyed retry of the background start: %d %v", status, doc)
	}
	// The keyed retry of the synchronous exec runs the command again.
	retryDone := make(chan struct{})
	go func() {
		defer close(retryDone)
		req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes/"+id+"/exec", strings.NewReader(string(syncCmd)))
		req.Header.Set("Authorization", "Bearer key1")
		req.Header.Set("User-Agent", "cathedral-harbor/0.1.5")
		for k, v := range syncHdr {
			req.Header.Set(k, v)
		}
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	for i := 0; execs.Load() < 3 && i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if n := execs.Load(); n != 2 {
		t.Errorf("the hotel received %d exec calls for two Idempotency-Keys: the synchronous command runs twice", n)
	}
	once.Do(func() { close(release) }) // let the held hotel calls finish before the servers close
	<-retryDone
}

// Harbor and ctcli clients got the signed receipt header on network changes
// and process starts only; create, exec and delete answers dropped it.
func TestCompatClientsGetTheReceiptHeaderOnCreateExecAndDelete(t *testing.T) {
	tc := newChain(t)
	req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes", strings.NewReader(`{"template": "room-1x4"}`))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("User-Agent", "ctcli/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if resp.StatusCode != 201 || resp.Header.Get("X-Room-Receipt") != "signed-create" {
		t.Fatalf("create: %d receipt header %q", resp.StatusCode, resp.Header.Get("X-Room-Receipt"))
	}
	id, _ := doc["id"].(string)
	for _, c := range []struct{ method, path, body, want string }{
		{"POST", "/v1/sandboxes/" + id + "/exec", `{"cmd": ["true"]}`, "signed-exec"},
		{"DELETE", "/v1/sandboxes/" + id, "", "signed-delete"},
	} {
		req, _ := http.NewRequest(c.method, tc.srv.URL+c.path, strings.NewReader(c.body))
		req.Header.Set("Authorization", "Bearer key1")
		req.Header.Set("User-Agent", "ctcli/1.0")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("X-Room-Receipt"); got != c.want {
			t.Errorf("%s %s: receipt header %q, want %q (status %d)", c.method, c.path, got, c.want, resp.StatusCode)
		}
	}
}
