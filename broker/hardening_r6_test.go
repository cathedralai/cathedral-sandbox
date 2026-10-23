package main

// Review round 6 probes for broker/main.go. New file only; no existing file
// is changed. Run one at a time:
//
//	go test -count=1 -run 'Test<Name>' .
//
// TestLabelsPatchRacesWithHotelSelection needs -race.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// forwardTo replays r (with body) to upstream and returns the answer.
func forwardTo(upstream string, r *http.Request, body []byte) (int, http.Header, []byte) {
	req, err := http.NewRequest(r.Method, upstream+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return 502, http.Header{}, nil
	}
	req.Header = r.Header.Clone()
	req.Header.Del("Content-Length")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 502, http.Header{}, nil
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, out
}

func passThrough(w http.ResponseWriter, status int, hdr http.Header, out []byte) {
	for k, v := range hdr {
		if k == "Content-Length" {
			continue
		}
		w.Header()[k] = v
	}
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

func roomState(tc *testChain, bid string) byte {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	if rm := tc.b.byBID(bid); rm != nil {
		return rm.state
	}
	return 0
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// A room the hotel lists again after the broker marked it deleting never
// goes back to running. Trigger: the hotel built its room list before a
// create landed, and the broker read that list more than 5 s after the
// create's answer. The list call is allowed 10 s, so this is inside the
// broker's own expectations for a loaded hotel.
func TestRoomListedAgainStaysDeleting(t *testing.T) {
	tc := newChain(t)
	h := tc.b.hotelByID("b")
	upstream := h.cfg.API
	var delayOnce atomic.Bool
	delayOnce.Store(true)
	fetched := make(chan struct{}, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		status, hdr, out := forwardTo(upstream, r, body)
		if r.Method == "GET" && r.URL.Path == "/v1/sandboxes" && delayOnce.CompareAndSwap(true, false) {
			fetched <- struct{}{}
			time.Sleep(6 * time.Second) // the hotel built the list; the broker reads it late
		}
		passThrough(w, status, hdr, out)
	}))
	t.Cleanup(proxy.Close)
	h.cfg.API = proxy.URL

	done := make(chan struct{})
	go func() { tc.b.syncHotel(context.Background(), h); close(done) }()
	<-fetched
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	<-done
	first := roomState(tc, id)

	// Next sync: the hotel lists the room. It still answers through the broker.
	tc.b.syncHotel(context.Background(), h)
	second := roomState(tc, id)
	execStatus, _ := tc.call(t, "key1", "POST", "/v1/sandboxes/"+id+"/exec", map[string]any{"cmd": []string{"true"}})
	_, q := tc.call(t, "key1", "GET", "/v1/quota", nil)
	running := q["guest"].(map[string]any)["running_sandboxes"]
	if second != stRunning {
		t.Fatalf("room %s: state after the late list %q, after the next list %q; exec through the broker answered %d; quota running_sandboxes %v; want state %q and 1 running",
			id, first, second, execStatus, running, stRunning)
	}
}

// A create whose answer is lost after the hotel committed the room is
// retried on another hotel. The first room stays, labelled with the guest,
// and the next sync adopts it: one create, two rooms. Production triggers:
// an SSH tunnel drop, or the broker's 5 minute create timeout during a cold
// image pull (the hotel allows the pull 600 s and finishes the create).
func TestLostCreateAnswerLeavesAnOrphanRoom(t *testing.T) {
	tc := newChain(t)
	hb := tc.b.hotelByID("b")
	upstream := hb.cfg.API
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		status, hdr, out := forwardTo(upstream, r, body)
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			// The hotel has the room. The answer never reaches the broker.
			setHotel(tc, "c", func(h *hotel) { h.cfg.Drain = false })
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					conn.Close()
				}
			}
			return
		}
		passThrough(w, status, hdr, out)
	}))
	t.Cleanup(proxy.Close)
	hb.cfg.API = proxy.URL
	setHotel(tc, "c", func(h *hotel) { h.cfg.Drain = true }) // b is picked first; c opens once b's answer is lost

	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}})
	if status != 202 {
		t.Fatalf("create: %d %v", status, doc)
	}
	hb.cfg.API = upstream
	tc.b.syncHotel(context.Background(), hb)
	_, list := tc.call(t, "key1", "GET", "/v1/sandboxes", nil)
	_, q := tc.call(t, "key1", "GET", "/v1/quota", nil)
	running := q["guest"].(map[string]any)["running_sandboxes"]
	if list["count"].(float64) != 1 || running.(float64) != 1 {
		t.Fatalf("one create answered 202 with %v; the guest now lists %v rooms (%v) and quota says %v running; want 1",
			doc["id"], list["count"], list["sandboxes"], running)
	}
}

// main() logs a failed client state load and carries on. The first save then
// replaces the file: every client room id, idempotency answer and guest room
// set is gone. One record of an unexpected shape is enough, because
// json.Unmarshal reports an error for the whole file and loadCompat uses
// nothing from it.
func TestUndecodableClientStateIsReplacedByTheFirstSave(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	tc.b.mu.Lock()
	oldUUID := tc.b.byBID(id).uuid
	tc.b.mu.Unlock()
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, stateFile)
	raw, _ := os.ReadFile(path)
	var st map[string]json.RawMessage
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(st["uuids"], []byte(oldUUID)) {
		t.Fatalf("harness: uuid %s not saved", oldUUID)
	}
	st["images"] = json.RawMessage(`{"x": {"CPU": "two"}}`) // one record of another shape
	raw, _ = json.Marshal(st)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.srv.Close()

	// Restart in main's order.
	b, err := loadBroker(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	b.loadCaps()
	lerr := b.loadCompat() // main: log.Printf and carry on
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.saveLoop(ctx)
	_ = b.loadRuntimeHotels()
	for _, h := range b.hotelList() {
		h.ok, h.slots = true, 100
	}
	tc.b, tc.srv = b, httptest.NewServer(b)
	t.Cleanup(tc.srv.Close)
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}) // marks the state dirty
	time.Sleep(1500 * time.Millisecond)                                                 // saveLoop ticks every second
	raw, _ = os.ReadFile(path)
	var after savedState
	_ = json.Unmarshal(raw, &after)
	if _, kept := after.UUIDs[oldUUID]; !kept {
		t.Fatalf("loadCompat: %v; the broker started anyway and its first save kept %d client ids; the old room's id %s is gone", lerr, len(after.UUIDs), oldUUID)
	}
}

// main() restores probe results (loadCaps) before it adds the runtime hotels
// (loadRuntimeHotels), so a hotel joined with ctcli loses its capability
// chips on the live board at every broker restart.
func TestRuntimeHotelCapsAreNotRestoredInMainOrder(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "r1", "api": hs.URL, "key": strings.Repeat("k", 40), "verify": false})
	if status != 201 {
		t.Fatalf("join: %d %v", status, doc)
	}
	caps := map[string]any{"isolation": "gVisor 4.4.0", "sealed": false}
	setHotel(tc, "b", func(h *hotel) { h.caps = caps })
	setHotel(tc, "r1", func(h *hotel) { h.caps = caps })
	tc.b.saveCaps()

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
	if b.hotelByID("b").caps == nil {
		t.Fatal("harness: config hotel caps not restored")
	}
	r1 := b.hotelByID("r1")
	if r1 == nil {
		t.Fatal("harness: runtime hotel not restored")
	}
	if r1.caps == nil {
		t.Fatalf("runtime hotel r1 restored with no caps: loadCaps ran before loadRuntimeHotels")
	}
}

// A batch create parses the body once per room before any hotel is called:
// the 1 MiB body limit becomes count x 1 MiB (count up to max_rooms, 1,000
// by default) of broker memory for the life of the batch.
func TestBatchCreateMultipliesTheBodyByCount(t *testing.T) {
	var n atomic.Int64
	hotel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			time.Sleep(300 * time.Millisecond)
			writeJSON(w, 202, map[string]any{"id": fmt.Sprintf("sbx_%d", n.Add(1)), "state": "running"})
			return
		}
		writeJSON(w, 200, map[string]any{})
	}))
	t.Cleanup(hotel.Close)
	dir := t.TempDir()
	key := filepath.Join(dir, "hotel.key")
	if err := os.WriteFile(key, []byte("hotel-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config{Hotels: []hotelConfig{{ID: "x", Name: "x", API: hotel.URL, Health: hotel.URL, KeyFile: key, Concurrency: 16}},
		Guests: []guestConfig{{ID: "g1", KeySHA256: sha("key1")}}}
	raw, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := loadBroker(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range b.hotelList() {
		h.ok, h.slots = true, 2000
	}
	srv := httptest.NewServer(b)
	t.Cleanup(srv.Close)

	const count = 100
	body, _ := json.Marshal(map[string]any{"image": "alpine:3.20", "count": count, "labels": map[string]any{"note": strings.Repeat("a", 1_000_000)}})
	if len(body) >= 1<<20 {
		t.Fatalf("harness: body %d bytes is over the create limit", len(body))
	}
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapInuse
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		var s runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				runtime.ReadMemStats(&s)
				if s.HeapInuse > peak.Load() {
					peak.Store(s.HeapInuse)
				}
			}
		}
	}()
	req, _ := http.NewRequest("POST", srv.URL+"/v1/sandboxes", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	close(stop)
	wg.Wait()
	if resp.StatusCode != 202 || doc["count"].(float64) != count {
		t.Fatalf("batch: %d %v", resp.StatusCode, doc)
	}
	p := peak.Load()
	if p < base {
		p = base
	}
	grew := float64(p-base) / (1 << 20)
	t.Logf("body %.2f MiB x count %d: broker heap in use grew by %.0f MiB at the peak", float64(len(body))/(1<<20), count, grew)
	if grew > 64 {
		t.Fatalf("heap grew %.0f MiB for one %d-room batch with a %.2f MiB body; want the body parsed once (under 64 MiB)", grew, count, float64(len(body))/(1<<20))
	}
}

// saveLoop writes dirty state once a second and never on stop; main has no
// signal handling at all. A broker restart loses up to one second of client
// ids and idempotency answers.
func TestSaveLoopDoesNotFlushWhenStopped(t *testing.T) {
	dir := t.TempDir()
	b := &broker{cfg: config{StateDir: dir}, compat: newCompat(), byUUID: map[string]*room{}, guests: map[string]*guestState{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { b.saveLoop(ctx); close(done) }()
	b.markDirty()
	cancel()
	<-done
	if _, err := os.Stat(filepath.Join(dir, stateFile)); err != nil {
		t.Fatalf("saveLoop stopped with dirty state and wrote nothing: %v", err)
	}
}

// What a view token holder sees: the guest's own squares, other guests'
// rooms as "o", and chain-wide hotel counters. Covers snapshot, stream and
// seenAge, which have no other test. This probe is expected to pass; it
// records behaviour.
func TestLiveStreamShowsOtherGuestsAndChainCounters(t *testing.T) {
	tc := newChain(t)
	setHotel(tc, "b", func(h *hotel) { h.slots = 0; h.resize(100) }) // the harness sets slots without a grid
	tc.room(t, "key2", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.PostForm(tc.srv.URL+"/g1/live/sign-in", url.Values{"token": {"view1"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 || len(resp.Cookies()) != 1 {
		t.Fatalf("sign-in: %d cookies %v", resp.StatusCode, resp.Cookies())
	}
	cookie := resp.Cookies()[0]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", tc.srv.URL+"/g1/live/events", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("events: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	rd := bufio.NewReader(resp.Body)
	var data string
	for data == "" {
		line, err := rd.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "data: ") {
			data = strings.TrimSpace(strings.TrimPrefix(line, "data: "))
		}
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(data), &doc); err != nil {
		t.Fatalf("event %q: %v", data, err)
	}
	if doc["guest"] != "g1" {
		t.Fatalf("guest %v", doc["guest"])
	}
	var hb map[string]any
	for _, x := range doc["hotels"].([]any) {
		h := x.(map[string]any)
		if h["id"] == "b" {
			hb = h
		}
	}
	grid := hb["grid"].(string)
	if !strings.Contains(grid, "r") || !strings.Contains(grid, "o") {
		t.Fatalf("hotel b grid %q: want one own running square and one other-guest square", grid)
	}
	for _, k := range []string{"rooms_all", "deleting_all", "containers", "queued", "creating", "cpu", "mem_gib", "load1", "seen_age_s", "caps", "mine"} {
		if _, ok := hb[k]; !ok {
			t.Fatalf("hotel doc has no %s: %v", k, hb)
		}
	}
	if hb["seen_age_s"].(float64) != -1 {
		t.Fatalf("seen_age_s %v before any health answer; want -1", hb["seen_age_s"])
	}
	addr := strings.TrimPrefix(tc.b.hotelByID("b").cfg.API, "http://")
	if strings.Contains(data, addr) || strings.Contains(data, "hotel-key") {
		t.Fatalf("event leaks a hotel address or key: %s", data)
	}
	t.Logf("live event keys per hotel: %v", keysOf(hb))
	t.Logf("live event totals: %v", doc["totals"])
}

// handleRoom cuts a room request body at 256 MiB with io.LimitReader and
// sends the cut body to the hotel as a complete request. The hotel writes it
// and answers 200 with "written": the guest's file is short by the rest.
func TestNativeFilePutOver256MiBIsCutToTheLimit(t *testing.T) {
	tc := newChain(t)
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	h := tc.b.hotelByID("b")
	var got atomic.Int64
	files := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		got.Store(n)
		writeJSON(w, 200, map[string]any{"path": r.URL.Query().Get("path"), "written": n})
	}))
	t.Cleanup(files.Close)
	h.cfg.API = files.URL
	const size = 256<<20 + 1
	req, _ := http.NewRequest("PUT", tc.srv.URL+"/v1/sandboxes/"+id+"/files?path=/work/big", io.LimitReader(zeros{}, size))
	req.ContentLength = size
	req.Header.Set("Authorization", "Bearer key1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	resp.Body.Close()
	if resp.StatusCode == 413 && got.Load() == 0 {
		return // refused whole: nothing short was written
	}
	if resp.StatusCode != 200 || got.Load() != size {
		t.Fatalf("PUT of %d bytes: broker answered %d, hotel received %d bytes and reported written %v; want 413 or the whole file", size, resp.StatusCode, got.Load(), doc["written"])
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// Run with -race. patchHotel writes h.cfg.Labels under b.mu; parseSelection
// reads it through pl.selects without b.mu.
func TestLabelsPatchRacesWithHotelSelection(t *testing.T) {
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
			_, _, _ = rawCall(tc, "operator-key", "", "PATCH", "/v1/broker/hotels/b", []byte(fmt.Sprintf(`{"labels":{"zone":"z%d"}}`, i%2)))
		}
	}()
	for i := 0; i < 200; i++ {
		_, _, _ = rawCall(tc, "key1", "", "POST", "/v1/sandboxes", []byte(`{"image":"alpine:3.20","hotel_labels":{"zone":"z1"}}`))
	}
	close(stop)
	wg.Wait()
}
