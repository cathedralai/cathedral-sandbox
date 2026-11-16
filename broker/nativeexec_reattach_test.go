package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// AB#756: a native exec running across a broker restart is re-attached by its
// hotel handle and returns its real result.

// fakeFront is a receipts front with exec result memory: it keeps the answer
// of every exec sent with X-Room-Exec-Handle, also when the caller is gone,
// and serves GET/DELETE .../exec/result?handle=.
type fakeFront struct {
	mu        sync.Mutex
	gate      chan struct{}
	release   func()
	entries   map[string]*frontEntry // hotel|room|handle
	forget    bool                   // every result read answers exec_unknown
	transient int                    // the next result reads answer 502 with no state header
	never     bool                   // every result read answers running at once (wait ignored)
	status    int                    // status of the exec answer (0: 200)
	execs     atomic.Int64
	reads     atomic.Int64
	acks      atomic.Int64
}

type frontEntry struct {
	done   chan struct{}
	status int
	body   []byte
	hdr    http.Header
}

func frontChain(t *testing.T, dir string) (*testChain, *fakeFront) {
	t.Helper()
	ff := &fakeFront{gate: make(chan struct{}), entries: map[string]*frontEntry{}}
	var once sync.Once
	ff.release = func() { once.Do(func() { close(ff.gate) }) }
	t.Cleanup(ff.release)
	tc := r6Chain(t, dir, func(hotelID string, f *fakeHotel, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.HasSuffix(p, "/exec") && r.Method == "POST":
				ff.exec(w, r, hotelID)
			case strings.HasSuffix(p, "/exec/result"):
				ff.result(w, r, hotelID)
			default:
				next.ServeHTTP(w, r)
			}
		})
	})
	t.Cleanup(func() { tc.b.stopNativeResume(); tc.b.drainNativeExecs(5 * time.Second) })
	t.Cleanup(ff.release)
	return tc, ff
}

func frontKey(hotelID, path, handle string) string {
	room := strings.TrimSuffix(strings.TrimPrefix(path, "/v1/sandboxes/"), "/exec")
	room = strings.TrimSuffix(room, "/exec/result")
	return hotelID + "|" + room + "|" + handle
}

func (ff *fakeFront) exec(w http.ResponseWriter, r *http.Request, hotelID string) {
	raw, _ := io.ReadAll(r.Body)
	var req map[string]any
	_ = json.Unmarshal(raw, &req)
	handle := r.Header.Get(nativeExecHandleHeader)
	var e *frontEntry
	if handle != "" {
		e = &frontEntry{done: make(chan struct{})}
		ff.mu.Lock()
		ff.entries[frontKey(hotelID, r.URL.Path, handle)] = e
		ff.mu.Unlock()
	}
	// Counted once the entry is stored, so a test that waits on the count
	// also sees the entry.
	ff.execs.Add(1)
	<-ff.gate // the command runs on when the caller goes away
	cmd, _ := req["cmd"].([]any)
	name, _ := cmd[0].(string)
	ff.mu.Lock()
	status := ff.status
	ff.mu.Unlock()
	var body []byte
	hdr := http.Header{}
	if status == 0 || status == 200 {
		status = 200
		body, _ = json.Marshal(map[string]any{"exit_code": 3, "stdout": "out-" + name, "stderr": "err-" + name, "timed_out": false})
		hdr.Set("X-Room-Receipt", "signed-"+name)
	} else {
		body = []byte(`{"error":{"code":"hotel_api_no_answer","message":"the API did not answer; the request may have run"}}`)
		hdr.Set("X-Room-Receipt", "signed-lost-"+name)
	}
	if e != nil {
		e.status, e.body, e.hdr = status, body, hdr
		close(e.done)
	}
	if r.Context().Err() != nil {
		return
	}
	for k, v := range hdr {
		w.Header()[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (ff *fakeFront) result(w http.ResponseWriter, r *http.Request, hotelID string) {
	key := frontKey(hotelID, r.URL.Path, r.URL.Query().Get("handle"))
	ff.mu.Lock()
	e := ff.entries[key]
	forget, never := ff.forget, ff.never
	transient := ff.transient > 0
	if transient {
		ff.transient--
	}
	if r.Method == "DELETE" && e != nil {
		delete(ff.entries, key)
	}
	ff.mu.Unlock()
	if r.Method == "DELETE" {
		ff.acks.Add(1)
		writeJSON(w, 200, map[string]any{"dropped": e != nil})
		return
	}
	ff.reads.Add(1)
	switch {
	case transient:
		writeErr(w, 502, "bad_gateway", "transient")
		return
	case forget || e == nil:
		writeErr(w, 404, "exec_unknown", "no exec with this handle")
		return
	}
	if !never {
		wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
		select {
		case <-e.done:
		case <-time.After(time.Duration(wait) * time.Second):
		case <-r.Context().Done():
		}
	}
	select {
	case <-e.done:
	default:
		w.Header().Set(nativeExecStateHeader, "running")
		writeJSON(w, 200, map[string]any{"state": "running"})
		return
	}
	for k, v := range e.hdr {
		w.Header()[k] = v
	}
	w.Header().Set(nativeExecStateHeader, "done")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.status)
	_, _ = w.Write(e.body)
}

// crashRestart starts a new broker on a copy of the state directory, as a
// broker that died would leave it, and kills the old one's hotel calls and
// re-attach loops. The old broker can then write only to its own directory.
func crashRestart(t *testing.T, tc *testChain) {
	t.Helper()
	old := tc.b
	old.stopNativeResume()
	newDir := t.TempDir()
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(raw, &cfg)
	oldDir, _ := cfg["state_dir"].(string)
	entries, _ := os.ReadDir(oldDir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(oldDir, e.Name()))
		if err == nil {
			_ = os.WriteFile(filepath.Join(newDir, e.Name()), data, 0o600)
		}
	}
	cfg["state_dir"] = newDir
	raw, _ = json.Marshal(cfg)
	if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	old.nexec.mu.Lock()
	for _, e := range old.nexec.execs {
		if e.State == "running" && e.cancel != nil {
			e.cancel() // the dead process's hotel calls end
		}
	}
	old.nexec.mu.Unlock()
	old.drainNativeExecs(5 * time.Second)
	tc.restart(t)
}

// startBGToken starts a background exec and returns once the front holds it.
// A 202 only means the broker saved its entry; the hotel call runs on in a
// goroutine. A restart before that call arrives is a real outcome (the hotel
// never got the command, so re-attach reports hotel_lost_exec), but the
// tests here measure a command already running in the hotel.
func startBGToken(t *testing.T, tc *testChain, ff *fakeFront, bid, cmd, token string, timeout int) string {
	t.Helper()
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/execs", map[string]any{"cmd": []string{cmd}, "timeout_seconds": timeout, "spill_token": token})
	if status != 202 || doc["state"] != "running" {
		t.Fatalf("start: %d %v", status, doc)
	}
	eid := doc["exec_id"].(string)
	tc.b.nexec.mu.Lock()
	handle := tc.b.nexec.execs[eid].Handle
	tc.b.nexec.mu.Unlock()
	waitFor(t, "the front to hold exec "+cmd, func() bool { return ff.holds(handle) })
	return eid
}

// holds reports whether the front has an entry for this handle.
func (ff *fakeFront) holds(handle string) bool {
	ff.mu.Lock()
	defer ff.mu.Unlock()
	for k := range ff.entries {
		if strings.HasSuffix(k, "|"+handle) {
			return true
		}
	}
	return false
}

func tokenN(i int) string { return fmt.Sprintf("%032x", i+1) }

func fastResume(t *testing.T) {
	t.Helper()
	first, back, gap, grace := nativeExecResumeFirst, nativeExecResumeBack, nativeExecResumeGap, nativeExecResumeGrace
	nativeExecResumeFirst, nativeExecResumeBack, nativeExecResumeGap = 10*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() {
		nativeExecResumeFirst, nativeExecResumeBack, nativeExecResumeGap, nativeExecResumeGrace = first, back, gap, grace
	})
}

func TestNativeExecReattachAfterRestartReturnsRealResult(t *testing.T) {
	fastResume(t)
	tc, ff := frontChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBGToken(t, tc, ff, bid, "job", tokenN(0), 600)
	path := "/v1/sandboxes/" + bid + "/execs/" + eid
	crashRestart(t, tc)
	if status, _, doc := tc.rawCall(t, "key1", "GET", path+"?wait=1", nil); status != 200 || doc["state"] != "running" {
		t.Fatalf("re-attached while running: %d %v", status, doc)
	}
	ff.release()
	status, hdr, doc := tc.rawCall(t, "key1", "GET", path+"?wait=10", nil)
	if status != 200 || doc["state"] != "exited" || doc["exit_code"] != float64(3) || doc["stdout"] != "out-job" || doc["stderr"] != "err-job" {
		t.Fatalf("after re-attach: %d %v", status, doc)
	}
	if hdr.Get("X-Room-Receipt") != "signed-job" {
		t.Errorf("receipt %q, want the original exec's", hdr.Get("X-Room-Receipt"))
	}
	if hdr.Get(nativeExecStateHeader) != "" {
		t.Errorf("the front's state header leaked into the result: %q", hdr.Get(nativeExecStateHeader))
	}
	if n := ff.execs.Load(); n != 1 {
		t.Errorf("hotel execs: %d, want 1 (re-attach never runs the command again)", n)
	}
	waitFor(t, "the front's copy to be dropped", func() bool { return ff.acks.Load() == 1 })
	// The result is on disk: one more restart reads it without the hotel.
	reads := ff.reads.Load()
	crashRestart(t, tc)
	if status, _, doc := tc.rawCall(t, "key1", "GET", path, nil); status != 200 || doc["state"] != "exited" || doc["stdout"] != "out-job" {
		t.Fatalf("after a second restart: %d %v", status, doc)
	}
	if ff.reads.Load() != reads {
		t.Error("a finished exec was read from the hotel again")
	}
}

func TestNativeExecReattachHotelLostExecIsLost(t *testing.T) {
	fastResume(t)
	tc, ff := frontChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBGToken(t, tc, ff, bid, "job", tokenN(0), 600)
	ff.mu.Lock()
	ff.forget = true // the front restarted: its memory is gone
	ff.mu.Unlock()
	crashRestart(t, tc)
	status, _, doc := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/"+eid+"?wait=10", nil)
	if status != 200 || doc["state"] != "lost" || doc["reason"] != "hotel_lost_exec" {
		t.Fatalf("after restart: %d %v", status, doc)
	}
	if ff.acks.Load() != 0 {
		t.Error("a lost exec was acknowledged to the front")
	}
}

func TestNativeExecRestartDuringReattach(t *testing.T) {
	fastResume(t)
	tc, ff := frontChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBGToken(t, tc, ff, bid, "job", tokenN(0), 600)
	path := "/v1/sandboxes/" + bid + "/execs/" + eid
	crashRestart(t, tc)
	waitFor(t, "the second broker to read the hotel", func() bool { return ff.reads.Load() >= 1 })
	crashRestart(t, tc) // dies mid re-attach
	ff.release()
	status, hdr, doc := tc.rawCall(t, "key1", "GET", path+"?wait=10", nil)
	if status != 200 || doc["state"] != "exited" || doc["exit_code"] != float64(3) || doc["stdout"] != "out-job" || hdr.Get("X-Room-Receipt") != "signed-job" {
		t.Fatalf("third broker: %d %v %v", status, doc, hdr)
	}
	if n := ff.execs.Load(); n != 1 {
		t.Errorf("hotel execs: %d, want 1", n)
	}
	waitFor(t, "the ack", func() bool { return ff.acks.Load() == 1 })
	crashRestart(t, tc)
	if status, _, doc := tc.rawCall(t, "key1", "GET", path, nil); status != 200 || doc["state"] != "exited" || doc["stdout"] != "out-job" {
		t.Fatalf("after one more restart: %d %v", status, doc)
	}
}

func TestNativeExecReattachSameSpillTokenKeepsEachResult(t *testing.T) {
	fastResume(t)
	tc, ff := frontChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	tok := tokenN(7)
	a := startBGToken(t, tc, ff, bid, "alpha", tok, 600)
	b := startBGToken(t, tc, ff, bid, "beta", tok, 600)
	crashRestart(t, tc)
	ff.release()
	for id, name := range map[string]string{a: "alpha", b: "beta"} {
		status, hdr, doc := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/"+id+"?wait=10", nil)
		if status != 200 || doc["stdout"] != "out-"+name || hdr.Get("X-Room-Receipt") != "signed-"+name {
			t.Errorf("%s: %d %v %v", name, status, doc, hdr)
		}
	}
}

func TestNativeExecReattachDoneReplayOf502IsHotelError(t *testing.T) {
	fastResume(t)
	tc, ff := frontChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBGToken(t, tc, ff, bid, "job", tokenN(0), 600)
	ff.mu.Lock()
	ff.status = 502 // the room API did not answer the exec itself
	ff.mu.Unlock()
	crashRestart(t, tc)
	ff.release()
	start := time.Now()
	status, _, doc := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/"+eid+"?wait=10", nil)
	if status != 200 || doc["state"] != "lost" || doc["reason"] != "hotel_error" {
		t.Fatalf("a done replay of a 502: %d %v", status, doc)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("a done replay was retried as a transient error")
	}
}

func TestNativeExecReattachTransientErrorsKeepItRunning(t *testing.T) {
	fastResume(t)
	tc, ff := frontChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBGToken(t, tc, ff, bid, "job", tokenN(0), 600)
	ff.mu.Lock()
	ff.transient = 3
	ff.mu.Unlock()
	crashRestart(t, tc)
	waitFor(t, "three transient reads", func() bool { return ff.reads.Load() >= 4 })
	if _, _, doc := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/"+eid, nil); doc["state"] != "running" {
		t.Fatalf("after transient errors: %v", doc)
	}
	ff.release()
	if _, _, doc := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/"+eid+"?wait=10", nil); doc["state"] != "exited" {
		t.Fatalf("after the hotel came back: %v", doc)
	}
}

func TestNativeExecReattachDeadlineEndsAnUnreachableHotel(t *testing.T) {
	fastResume(t)
	nativeExecResumeGrace = 300 * time.Millisecond
	tc, ff := frontChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBGToken(t, tc, ff, bid, "job", tokenN(0), 1)
	ff.mu.Lock()
	ff.transient = 1 << 30
	ff.mu.Unlock()
	crashRestart(t, tc)
	status, _, doc := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/"+eid+"?wait=10", nil)
	if status != 200 || doc["state"] != "lost" || doc["reason"] != "hotel_unreachable" {
		t.Fatalf("past the deadline: %d %v", status, doc)
	}
}

func TestNativeExecReattachRunningAnswersStopAtTheDeadlineAndAreSpaced(t *testing.T) {
	fastResume(t)
	nativeExecResumeGrace = 500 * time.Millisecond
	nativeExecResumeGap = 200 * time.Millisecond
	tc, ff := frontChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBGToken(t, tc, ff, bid, "job", tokenN(0), 1)
	ff.mu.Lock()
	ff.never = true // a front that answers running at once, whatever the wait
	ff.mu.Unlock()
	crashRestart(t, tc)
	status, _, doc := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/"+eid+"?wait=10", nil)
	if status != 200 || doc["state"] != "lost" || doc["reason"] != "hotel_unreachable" {
		t.Fatalf("running past the deadline: %d %v", status, doc)
	}
	// About 1.5 s of deadline at one read per 200 ms: never a hot loop.
	if n := ff.reads.Load(); n < 1 || n > 15 {
		t.Errorf("result reads: %d, want a handful", n)
	}
}

func TestNativeExecReattachOldFileWithoutHandleIsLost(t *testing.T) {
	dir := t.TempDir()
	tc, ff := frontChain(t, dir)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	old := []map[string]any{{"id": "old-1", "guest": "g1", "room": bid, "state": "running", "started": time.Now().Add(-time.Minute)}}
	raw, _ := json.Marshal(old)
	if err := os.WriteFile(filepath.Join(dir, nativeExecFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	if status, _, doc := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/old-1", nil); status != 200 || doc["state"] != "lost" || doc["reason"] != "broker_restarted" {
		t.Fatalf("old entry: %d %v", status, doc)
	}
	if ff.reads.Load() != 0 {
		t.Error("an entry with no handle was looked up on the hotel")
	}
}

func TestNativeExecReattachDeleteDuringResumeIsKilled(t *testing.T) {
	fastResume(t)
	tc, ff := frontChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBGToken(t, tc, ff, bid, "job", tokenN(0), 600)
	path := "/v1/sandboxes/" + bid + "/execs/" + eid
	crashRestart(t, tc)
	waitFor(t, "a resume read", func() bool { return ff.reads.Load() >= 1 })
	if status, _, doc := tc.rawCall(t, "key1", "DELETE", path, nil); status != 200 || doc["state"] != "killed" {
		t.Fatalf("delete: %d %v", status, doc)
	}
	ff.release()
	if _, _, doc := tc.rawCall(t, "key1", "GET", path+"?wait=2", nil); doc["state"] != "killed" {
		t.Fatalf("after the hotel answered: %v", doc)
	}
}

func TestNativeExecStopEndsResumeAtOnceAndKeepsItRunning(t *testing.T) {
	fastResume(t)
	tc, ff := frontChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBGToken(t, tc, ff, bid, "job", tokenN(0), 600)
	crashRestart(t, tc)
	waitFor(t, "a resume read", func() bool { return ff.reads.Load() >= 1 })
	start := time.Now()
	tc.b.stopNativeResume()
	tc.b.drainNativeExecs(10 * time.Second)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("stop waited %v on a re-attach", d)
	}
	raw, _ := os.ReadFile(filepath.Join(tc.b.cfg.StateDir, nativeExecFile))
	var saved []map[string]any
	_ = json.Unmarshal(raw, &saved)
	found := false
	for _, e := range saved {
		if e["id"] == eid {
			found = e["state"] == "running" && e["hotel_handle"] != "" && e["hotel_handle"] != nil
		}
	}
	if !found {
		t.Fatalf("after stop the exec is not saved running with its handle: %s", raw)
	}
}

func TestNativeExecStartSendsAMintedHandle(t *testing.T) {
	tc, ff := frontChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/execs", map[string]any{"cmd": []string{"job"}, "timeout_seconds": 60})
	if status != 202 {
		t.Fatalf("start: %d %v", status, doc)
	}
	waitFor(t, "the hotel exec", func() bool { return ff.execs.Load() == 1 })
	ff.mu.Lock()
	var handles []string
	for k := range ff.entries {
		handles = append(handles, k[strings.LastIndex(k, "|")+1:])
	}
	ff.mu.Unlock()
	if len(handles) != 1 || len(handles[0]) != 32 || strings.Trim(handles[0], "0123456789abcdef") != "" {
		t.Fatalf("handles sent: %v", handles)
	}
	tc.b.nexec.mu.Lock()
	ex := tc.b.nexec.execs[doc["exec_id"].(string)]
	h, timeout := ex.Handle, ex.Timeout
	tc.b.nexec.mu.Unlock()
	if h != handles[0] || timeout != 60 {
		t.Errorf("saved handle %q timeout %d, sent %q", h, timeout, handles[0])
	}
	// A normal finish drops the front's copy once the result is saved.
	ff.release()
	waitFor(t, "the ack", func() bool { return ff.acks.Load() == 1 })
}
