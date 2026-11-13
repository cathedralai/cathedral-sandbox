package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// AB#553: background execs on the native room-id route.

// nativeHotelExecs counts hotel /exec calls that reach an execChain hotel.
var nativeHotelExecs atomic.Int64

// execChain holds every hotel exec until release is closed, then answers stdout "out-<cmd0>".
func execChain(t *testing.T, dir string) (*testChain, func()) {
	t.Helper()
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	tc := r6Chain(t, dir, func(id string, f *fakeHotel, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/exec") && r.Method == "POST" {
				nativeHotelExecs.Add(1)
				raw, _ := io.ReadAll(r.Body)
				var req map[string]any
				_ = json.Unmarshal(raw, &req)
				select {
				case <-gate:
				case <-r.Context().Done():
					return
				}
				cmd, _ := req["cmd"].([]any)
				w.Header().Set("X-Room-Receipt", "signed-bg")
				writeJSON(w, 200, map[string]any{"exit_code": 0, "stdout": "out-" + cmd[0].(string), "stderr": "", "timed_out": false, "got_spill": req["spill_token"]})
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	// Last broker's background execs end and save before TempDir cleanup.
	t.Cleanup(func() { tc.b.drainNativeExecs(5 * time.Second) })
	t.Cleanup(release) // runs before the hotel servers close, which wait for held calls
	return tc, release
}

// restart is tc.start plus one hotel sync, so the new broker knows the rooms again.
func (tc *testChain) restart(t *testing.T) {
	t.Helper()
	tc.start(t)
	for _, h := range tc.b.hotelList() {
		tc.b.syncHotel(context.Background(), h)
	}
}

func (tc *testChain) rawCall(t *testing.T, key, method, path string, body any) (int, http.Header, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, tc.srv.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, resp.Header, doc
}

func startBG(t *testing.T, tc *testChain, key, bid, cmd string) string {
	t.Helper()
	status, doc := tc.call(t, key, "POST", "/v1/sandboxes/"+bid+"/execs", map[string]any{"cmd": []string{cmd}, "timeout_seconds": 600, "spill_token": strings.Repeat("ab", 16)})
	if status != 202 || doc["state"] != "running" {
		t.Fatalf("start: %d %v", status, doc)
	}
	return doc["exec_id"].(string)
}

func TestNativeBackgroundExecStartsAndPollsToResult(t *testing.T) {
	tc, release := execChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBG(t, tc, "key1", bid, "job")
	path := "/v1/sandboxes/" + bid + "/execs/" + eid
	status, _, doc := tc.rawCall(t, "key1", "GET", path, nil)
	if status != 200 || doc["state"] != "running" {
		t.Fatalf("poll while running: %d %v", status, doc)
	}
	release()
	status, hdr, doc := tc.rawCall(t, "key1", "GET", path+"?wait=10", nil)
	if status != 200 || doc["state"] != "exited" || doc["stdout"] != "out-job" || doc["exit_code"] != float64(0) {
		t.Fatalf("poll after finish: %d %v", status, doc)
	}
	if doc["got_spill"] != strings.Repeat("ab", 16) {
		t.Errorf("spill_token did not reach the hotel: %v", doc["got_spill"])
	}
	if hdr.Get("X-Room-Receipt") != "signed-bg" {
		t.Errorf("receipt header missing: %q", hdr.Get("X-Room-Receipt"))
	}
}

func TestNativeBackgroundExecScopedToOwnerAndRoom(t *testing.T) {
	tc, release := execChain(t, t.TempDir())
	release()
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	other := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBG(t, tc, "key1", bid, "job")
	if status, _, _ := tc.rawCall(t, "key2", "GET", "/v1/sandboxes/"+bid+"/execs/"+eid, nil); status != 404 {
		t.Errorf("other guest, same room id: %d, want 404", status)
	}
	if status, _, _ := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+other+"/execs/"+eid, nil); status != 404 {
		t.Errorf("same guest, other room: %d, want 404", status)
	}
	if status, _ := tc.call(t, "key2", "POST", "/v1/sandboxes/"+bid+"/execs", map[string]any{"cmd": []string{"x"}}); status != 404 {
		t.Errorf("other guest starts on a room it does not own: %d, want 404", status)
	}
	if status, _, _ := tc.rawCall(t, "nokey", "GET", "/v1/sandboxes/"+bid+"/execs/"+eid, nil); status != 401 && status != 403 {
		t.Errorf("no key: %d", status)
	}
}

func TestNativeBackgroundExecRejectsBadBody(t *testing.T) {
	tc, release := execChain(t, t.TempDir())
	release()
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	for name, body := range map[string]map[string]any{
		"string cmd": {"cmd": "echo hi"},
		"bad spill":  {"cmd": []string{"x"}, "spill_token": "nothex"},
	} {
		if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/execs", body); status != 400 || errCode(doc) != "invalid_exec" {
			t.Errorf("%s: %d %v", name, status, doc)
		}
	}
}

func TestNativeBackgroundExecDeleteStopsIt(t *testing.T) {
	tc, _ := execChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBG(t, tc, "key1", bid, "job")
	status, _, doc := tc.rawCall(t, "key1", "DELETE", "/v1/sandboxes/"+bid+"/execs/"+eid, nil)
	if status != 200 || doc["state"] != "killed" {
		t.Fatalf("delete: %d %v", status, doc)
	}
}

func TestNativeBackgroundExecFinishedResultSurvivesBrokerRestart(t *testing.T) {
	dir := t.TempDir()
	tc, release := execChain(t, dir)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBG(t, tc, "key1", bid, "job")
	release()
	path := "/v1/sandboxes/" + bid + "/execs/" + eid
	if _, _, doc := tc.rawCall(t, "key1", "GET", path+"?wait=10", nil); doc["state"] != "exited" {
		t.Fatalf("not finished: %v", doc)
	}
	tc.restart(t)
	status, hdr, doc := tc.rawCall(t, "key1", "GET", path, nil)
	if status != 200 || doc["state"] != "exited" || doc["stdout"] != "out-job" || hdr.Get("X-Room-Receipt") != "signed-bg" {
		t.Fatalf("after restart: %d %v %v", status, doc, hdr)
	}
	if status, _, _ := tc.rawCall(t, "key2", "GET", path, nil); status != 404 {
		t.Errorf("scoping after restart: %d", status)
	}
	if st, err := os.Stat(filepath.Join(dir, nativeExecFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("state file: %v %v", st, err)
	}
}

func TestNativeBackgroundExecRunningAtRestartIsLostWithReason(t *testing.T) {
	dir := t.TempDir()
	tc, release := execChain(t, dir)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBG(t, tc, "key1", bid, "job")
	old := tc.b
	tc.restart(t)
	status, _, doc := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/"+eid, nil)
	if status != 200 || doc["state"] != "lost" || doc["reason"] != "broker_restarted" {
		t.Fatalf("after restart: %d %v", status, doc)
	}
	// Unblock the old broker's held hotel /exec and wait for its saveNativeExecs
	// so TempDir cleanup does not race a late write (directory not empty).
	release()
	old.drainNativeExecs(5 * time.Second)
}

func TestNativeBackgroundExecDrainWaitsForRunningExecs(t *testing.T) {
	dir := t.TempDir()
	tc, release := execChain(t, dir)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBG(t, tc, "key1", bid, "job")
	go func() { time.Sleep(200 * time.Millisecond); release() }()
	start := time.Now()
	tc.b.drainNativeExecs(10 * time.Second)
	if d := time.Since(start); d < 150*time.Millisecond || d > 5*time.Second {
		t.Errorf("drain took %v", d)
	}
	tc.restart(t)
	if _, _, doc := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/"+eid, nil); doc["state"] != "exited" {
		t.Errorf("after drain and restart: %v", doc)
	}
}

func TestNativeBackgroundExecKeepIsBoundedByAgeAndCount(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	n := tc.b.nexec
	old := time.Now().Add(-nativeExecKeep - time.Minute)
	n.mu.Lock()
	n.execs["old"] = &nativeExec{ID: "old", Guest: "g1", State: "exited", Started: old, DoneAt: old}
	for i := 0; i < nativeExecMax+10; i++ {
		id := "e" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		now := time.Now().Add(time.Duration(i) * time.Second)
		n.execs[id] = &nativeExec{ID: id, Guest: "g1", State: "exited", Started: now, DoneAt: now}
	}
	n.mu.Unlock()
	tc.b.saveNativeExecs()
	raw, _ := os.ReadFile(filepath.Join(dir, nativeExecFile))
	var saved []map[string]any
	_ = json.Unmarshal(raw, &saved)
	if len(saved) != nativeExecMax {
		t.Errorf("saved %d execs, want %d", len(saved), nativeExecMax)
	}
	if bytes.Contains(raw, []byte(`"old"`)) {
		t.Error("an exec older than the keep age was saved")
	}
}

// AB#733 (#450 review): a 202 is only given once the running exec is on disk.

func hotelExecCalls(_ *testChain) int { return int(nativeHotelExecs.Load()) }

func TestNativeBackgroundExecRefusedWhenStateCannotBeSaved(t *testing.T) {
	dir := t.TempDir()
	tc, release := execChain(t, dir)
	release()
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	before := hotelExecCalls(tc)
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	tc.b.cfg.StateDir = filepath.Join(blocker, "state") // MkdirAll fails: a file is in the way
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/execs", map[string]any{"cmd": []string{"job"}})
	if status != 503 || errCode(doc) != "exec_store_unavailable" {
		t.Fatalf("start with an unwritable state_dir: %d %v", status, doc)
	}
	if got := hotelExecCalls(tc); got != before {
		t.Errorf("the hotel got %d exec calls for a refused start", got-before)
	}
	tc.b.nexec.mu.Lock()
	left := len(tc.b.nexec.execs)
	tc.b.nexec.mu.Unlock()
	if left != 0 {
		t.Errorf("a refused start left %d execs in memory", left)
	}
	tc.b.cfg.StateDir = dir
}

func TestNativeBackgroundExecRefusedWithoutStateDir(t *testing.T) {
	tc, release := execChain(t, "")
	release()
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	before := hotelExecCalls(tc)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/execs", map[string]any{"cmd": []string{"job"}})
	if status != 503 || errCode(doc) != "exec_store_unavailable" {
		t.Fatalf("start without state_dir: %d %v", status, doc)
	}
	if hotelExecCalls(tc) != before {
		t.Error("the hotel ran a command the broker could not keep")
	}
}

func TestNativeBackgroundExecAdmissionCapKeepsEveryRunningIDOnDisk(t *testing.T) {
	dir := t.TempDir()
	tc, release := execChain(t, dir)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	n := tc.b.nexec
	base := time.Now().Add(-time.Hour)
	n.mu.Lock()
	for i := 0; i < nativeExecMax-1; i++ {
		id := fmt.Sprintf("run-%03d", i)
		n.execs[id] = &nativeExec{ID: id, Guest: "g1", Room: bid, State: "running", Started: base.Add(time.Duration(i) * time.Second), done: make(chan struct{}), cancel: func() {}}
	}
	for i := 0; i < 20; i++ { // finished execs, newer than every running one
		id := fmt.Sprintf("done-%03d", i)
		at := time.Now().Add(time.Duration(i) * time.Millisecond)
		n.execs[id] = &nativeExec{ID: id, Guest: "g1", Room: bid, State: "exited", Started: at, DoneAt: at}
	}
	n.mu.Unlock()
	last := startBG(t, tc, "key1", bid, "job") // running number 256
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/execs", map[string]any{"cmd": []string{"one-too-many"}})
	if status != 429 || errCode(doc) != "too_many_execs" {
		t.Fatalf("start past the running cap: %d %v", status, doc)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, nativeExecFile))
	var saved []map[string]any
	_ = json.Unmarshal(raw, &saved)
	running := map[string]bool{}
	for _, e := range saved {
		if e["state"] == "running" {
			running[e["id"].(string)] = true
		}
	}
	if len(running) != nativeExecMax || !running["run-000"] || !running[last] {
		t.Errorf("running ids on disk: %d (oldest kept %v, newest kept %v), want %d", len(running), running["run-000"], running[last], nativeExecMax)
	}
	// Every accepted id comes back after a restart: lost, never 404.
	n.mu.Lock()
	for _, e := range n.execs {
		if e.State == "running" && e.ID != last {
			e.State, e.DoneAt = "exited", time.Now() // the fake ones end so drain does not wait on them
		}
	}
	n.mu.Unlock()
	tc.restart(t)
	if status, _, doc := tc.rawCall(t, "key1", "GET", "/v1/sandboxes/"+bid+"/execs/run-000", nil); status != 200 || doc["state"] != "lost" {
		t.Errorf("oldest running exec after restart: %d %v", status, doc)
	}
	release()
}

func TestNativeBackgroundExecKilledSurvivesPruneAndRestart(t *testing.T) {
	dir := t.TempDir()
	tc, _ := execChain(t, dir)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBG(t, tc, "key1", bid, "job")
	path := "/v1/sandboxes/" + bid + "/execs/" + eid
	if status, _, doc := tc.rawCall(t, "key1", "DELETE", path, nil); status != 200 || doc["state"] != "killed" {
		t.Fatalf("delete: %d %v", status, doc)
	}
	if status, _, doc := tc.rawCall(t, "key1", "GET", path, nil); status != 200 || doc["state"] != "killed" {
		t.Fatalf("read after delete: %d %v", status, doc)
	}
	tc.b.drainNativeExecs(5 * time.Second)
	tc.restart(t)
	if status, _, doc := tc.rawCall(t, "key1", "GET", path, nil); status != 200 || doc["state"] != "killed" {
		t.Fatalf("read after restart: %d %v", status, doc)
	}
}

func TestNativeBackgroundExecResultReadableAfterTheRoomIsGone(t *testing.T) {
	tc, release := execChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBG(t, tc, "key1", bid, "job")
	release()
	path := "/v1/sandboxes/" + bid + "/execs/" + eid
	if _, _, doc := tc.rawCall(t, "key1", "GET", path+"?wait=10", nil); doc["state"] != "exited" {
		t.Fatalf("not finished: %v", doc)
	}
	// The room leaves the broker, as a hotel sync does once the room is gone.
	hotelID, hid, _ := strings.Cut(bid, ".")
	h := tc.b.hotelByID(hotelID)
	tc.b.mu.Lock()
	tc.b.release(h, h.rooms[hid])
	tc.b.mu.Unlock()
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/execs", map[string]any{"cmd": []string{"x"}}); status != 404 || errCode(doc) != "sandbox_not_found" {
		t.Errorf("start on a room that is gone: %d %v, want 404", status, doc)
	}
	status, hdr, doc := tc.rawCall(t, "key1", "GET", path, nil)
	if status != 200 || doc["state"] != "exited" || doc["stdout"] != "out-job" || hdr.Get("X-Room-Receipt") != "signed-bg" {
		t.Fatalf("read after the room is gone: %d %v", status, doc)
	}
	if status, _, _ := tc.rawCall(t, "key2", "GET", path, nil); status != 404 {
		t.Errorf("other guest after the room is gone: %d", status)
	}
}

func TestNativeBackgroundExecTakesABodyOverOneMiB(t *testing.T) {
	tc, release := execChain(t, t.TempDir())
	release()
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	big := strings.Repeat("x", 3<<20) // a stdin the sync exec route takes
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/execs", map[string]any{"cmd": []string{"job"}, "stdin": big})
	if status != 202 || doc["state"] != "running" {
		t.Fatalf("start with a 3 MiB stdin: %d %v", status, doc)
	}
}
