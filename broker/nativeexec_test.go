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
	for i := 0; i < nativeExecMaxPerGuest+10; i++ {
		id := "e" + string(rune('A'+i%26)) + string(rune('a'+i/26))
		now := time.Now().Add(time.Duration(i) * time.Second)
		n.execs[id] = &nativeExec{ID: id, Guest: "g1", State: "exited", Started: now, DoneAt: now}
	}
	n.mu.Unlock()
	tc.b.saveNativeExecs()
	raw, _ := os.ReadFile(filepath.Join(dir, nativeExecFile))
	var saved []map[string]any
	_ = json.Unmarshal(raw, &saved)
	if len(saved) != nativeExecMaxPerGuest { // one guest: its own cap, not the whole broker's
		t.Errorf("saved %d execs, want %d", len(saved), nativeExecMaxPerGuest)
	}
	if bytes.Contains(raw, []byte(`"old"`)) {
		t.Error("an exec older than the keep age was saved")
	}
}

// AB#748: what the broker holds for finished commands is bounded in memory.

// execBounds sets small bounds for one test: 64 KiB of output per guest, 256 KiB
// for the broker, 64 KiB in the file. One "full" result below is 32 KiB.
func execBounds(t *testing.T) {
	t.Helper()
	old := []int{nativeExecMax, nativeExecMaxPerGuest, nativeExecGuestBytes, nativeExecTotalBytes, nativeExecFileBytes, nativeExecMaxRunning}
	nativeExecGuestBytes, nativeExecTotalBytes, nativeExecFileBytes = 64<<10, 256<<10, 64<<10
	t.Cleanup(func() {
		nativeExecMax, nativeExecMaxPerGuest, nativeExecGuestBytes, nativeExecTotalBytes, nativeExecFileBytes, nativeExecMaxRunning = old[0], old[1], old[2], old[3], old[4], old[5]
	})
}

// settleExecs lets every worker of this broker end before the test's bounds
// are put back, so no worker reads a bound while the cleanup writes it. A
// worker that does not end fails the test: nothing below may pass by timeout.
func settleExecs(t *testing.T, tc *testChain, release func()) {
	t.Helper()
	release()
	idle := make(chan struct{})
	go func() { tc.b.nexec.wg.Wait(); close(idle) }()
	select {
	case <-idle:
	case <-time.After(10 * time.Second):
		t.Fatal("background exec workers did not end")
	}
	tc.b.saveNativeExecs()
}

var execSeq atomic.Int64

// putExec adds a finished exec with size bytes of stdout that ended age ago.
func putExec(n *nativeExecs, guest string, size int, age time.Duration) *nativeExec {
	at := time.Now().Add(-age)
	e := &nativeExec{ID: guest + "-" + strconvI(execSeq.Add(1)), Guest: guest, Room: "a.r1", State: "exited", Started: at, DoneAt: at,
		Result:  map[string]any{"exit_code": float64(0), "stdout": strings.Repeat("x", size), "stderr": ""},
		Headers: map[string][]string{"X-Room-Receipt": {"signed"}}}
	e.done = make(chan struct{})
	close(e.done)
	e.cancel = func() {}
	n.execs[e.ID] = e
	return e
}

func strconvI(v int64) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func evicted(e *nativeExec) bool { v, _ := e.Result["evicted"].(bool); return v }

// outputOf counts a result's output without the code under test.
func outputOf(e *nativeExec) int {
	out, _ := e.Result["stdout"].(string)
	errs, _ := e.Result["stderr"].(string)
	return len(out) + len(errs)
}

// held is the output in memory per guest and in total.
func held(n *nativeExecs) (map[string]int, int) {
	per, total := map[string]int{}, 0
	for _, e := range n.execs {
		if e.State != "running" {
			per[e.Guest] += outputOf(e)
			total += outputOf(e)
		}
	}
	return per, total
}

func TestNativeExecEveryOutputByteCountsEvenASmallResult(t *testing.T) {
	execBounds(t)
	n := newNativeExecs()
	putExec(n, "g1", 32<<10, 3*time.Minute)
	putExec(n, "g1", 32<<10, 2*time.Minute)
	tiny := putExec(n, "g1", 200, time.Minute) // 64 KiB + 200 bytes: over, by a small result
	tiny.Result["stderr"] = "e"
	n.pruneLocked(time.Now())
	if per, _ := held(n); per["g1"] > nativeExecGuestBytes {
		t.Fatalf("g1 holds %d bytes, bound %d", per["g1"], nativeExecGuestBytes)
	}
	if evicted(tiny) || outputOf(tiny) != 201 {
		t.Errorf("the newest result must stay whole: evicted=%v bytes=%d", evicted(tiny), outputOf(tiny))
	}
}

func TestNativeExecOneGuestNeverHoldsMoreThanItsBoundAndNewestStaysFull(t *testing.T) {
	execBounds(t)
	n := newNativeExecs()
	var newest *nativeExec
	for i := 0; i < 20; i++ {
		newest = putExec(n, "g1", 32<<10, time.Duration(20-i)*time.Minute)
		other := putExec(n, "g2", 1<<10, time.Duration(20-i)*time.Minute)
		n.pruneLocked(time.Now())
		per, _ := held(n)
		if per["g1"] > nativeExecGuestBytes {
			t.Fatalf("after %d results g1 holds %d bytes, bound %d", i+1, per["g1"], nativeExecGuestBytes)
		}
		if evicted(newest) || evicted(other) {
			t.Fatalf("after %d results: newest evicted=%v, the other guest's evicted=%v", i+1, evicted(newest), evicted(other))
		}
	}
	if len(n.execs) != 40 {
		t.Errorf("entries: %d, want 40 (eviction keeps the entry)", len(n.execs))
	}
	if newest.Headers["X-Room-Receipt"][0] != "signed" {
		t.Error("receipt header lost")
	}
}

func TestNativeExecBrokerBoundHoldsAcrossGuestsAndNewestGoesLast(t *testing.T) {
	execBounds(t)
	n := newNativeExecs()
	newest := map[string]*nativeExec{}
	for g := 0; g < 5; g++ { // five guests at their own bound: 5 x 64 KiB > 256 KiB
		guest := "guest" + strconvI(int64(g))
		putExec(n, guest, 32<<10, time.Duration(10+g)*time.Minute)
		newest[guest] = putExec(n, guest, 32<<10, time.Duration(g)*time.Second)
	}
	n.pruneLocked(time.Now())
	if _, total := held(n); total > nativeExecTotalBytes {
		t.Fatalf("broker holds %d bytes, bound %d", total, nativeExecTotalBytes)
	}
	for guest, e := range newest {
		if evicted(e) {
			t.Errorf("%s: newest result evicted while older output was left", guest)
		}
	}
}

func TestNativeExecNineNewestResultsEvictExactlyTheOldest(t *testing.T) {
	execBounds(t)
	n := newNativeExecs()
	var all []*nativeExec
	for g := 0; g < 9; g++ { // 9 x 32 KiB = 288 KiB, every result is its guest's newest
		all = append(all, putExec(n, "guest"+strconvI(int64(g)), 32<<10, time.Duration(9-g)*time.Minute))
	}
	done := make(chan struct{})
	go func() { n.pruneLocked(time.Now()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("prune did not end")
	}
	if _, total := held(n); total > nativeExecTotalBytes {
		t.Fatalf("broker holds %d bytes, bound %d", total, nativeExecTotalBytes)
	}
	for i, e := range all {
		if evicted(e) != (i == 0) {
			t.Errorf("result %d (0 is oldest): evicted=%v", i, evicted(e))
		}
	}
}

func TestNativeExecOlderSmallOutputGoesBeforeAnyNewest(t *testing.T) {
	execBounds(t)
	n := newNativeExecs()
	var full []*nativeExec
	for g := 0; g < 8; g++ { // 256 KiB, exactly at the bound
		full = append(full, putExec(n, "guest"+strconvI(int64(g)), 32<<10, time.Duration(20-g)*time.Minute))
	}
	small := putExec(n, "ninth", 1<<10, 5*time.Minute) // older, pushes the total over
	empty := putExec(n, "ninth", 0, time.Minute)       // its newest has no output
	done := make(chan struct{})
	go func() { n.pruneLocked(time.Now()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("prune did not end: no legal victim")
	}
	if !evicted(small) || evicted(empty) {
		t.Errorf("small older evicted=%v (want true), empty newest evicted=%v (want false)", evicted(small), evicted(empty))
	}
	for i, e := range full {
		if evicted(e) {
			t.Errorf("guest %d lost its newest result", i)
		}
	}
}

func TestNativeExecCountCapsDeleteOldestAndSpareAGuestWithOneResult(t *testing.T) {
	execBounds(t)
	n := newNativeExecs()
	lone := putExec(n, "lone", 0, 23*time.Hour) // oldest of all
	var firstOfA *nativeExec
	for g := 0; g < 4; g++ {
		for i := 0; i < nativeExecMaxPerGuest+1; i++ { // one over the per-guest cap, no output
			e := putExec(n, "guest"+strconvI(int64(g)), 0, time.Duration(1000-i)*time.Second)
			if g == 0 && i == 0 {
				firstOfA = e
			}
		}
	}
	n.pruneLocked(time.Now())
	if n.execs[lone.ID] == nil {
		t.Error("the guest with one result lost it to the whole-broker count")
	}
	if n.execs[firstOfA.ID] != nil {
		t.Error("the oldest result of a guest over its count cap was kept")
	}
	if got := len(n.execs); got != nativeExecMax {
		t.Errorf("entries: %d, want %d", got, nativeExecMax)
	}
}

func TestNativeExecOrderIsByFinishTimeNotStartTime(t *testing.T) {
	execBounds(t)
	n := newNativeExecs()
	quick1 := putExec(n, "g1", 32<<10, 3*time.Minute)
	quick2 := putExec(n, "g1", 32<<10, 2*time.Minute)
	long := putExec(n, "g1", 32<<10, time.Second) // finished last ...
	long.Started = time.Now().Add(-time.Hour)     // ... but started first
	n.pruneLocked(time.Now())
	if evicted(long) || !evicted(quick1) || evicted(quick2) {
		t.Errorf("evicted: long=%v quick1=%v quick2=%v, want only quick1", evicted(long), evicted(quick1), evicted(quick2))
	}
}

func TestNativeExecEvictedEntryStillPollsWithReasonAndReceipt(t *testing.T) {
	execBounds(t)
	nativeExecGuestBytes = 400 // one ~300 byte result fits, two do not
	tc, release := execChain(t, t.TempDir())
	defer settleExecs(t, tc, release)
	release()
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	path := "/v1/sandboxes/" + bid + "/execs/"
	first := startBG(t, tc, "key1", bid, strings.Repeat("a", 300))
	if _, _, doc := tc.rawCall(t, "key1", "GET", path+first+"?wait=10", nil); doc["state"] != "exited" || doc["evicted"] != nil {
		t.Fatalf("first result should be full while it is the only one: %v", doc)
	}
	second := startBG(t, tc, "key1", bid, strings.Repeat("b", 300))
	status, _, doc := tc.rawCall(t, "key1", "GET", path+second+"?wait=10", nil)
	if status != 200 || doc["stdout"] != "out-"+strings.Repeat("b", 300) || doc["evicted"] != nil {
		t.Fatalf("newest result must be full: %d %v", status, doc)
	}
	status, hdr, doc := tc.rawCall(t, "key1", "GET", path+first, nil)
	if status != 200 || doc["state"] != "exited" || doc["evicted"] != true || doc["reason"] != "result_evicted" || doc["receipt_covers"] != "original_result" {
		t.Fatalf("evicted poll: %d %v", status, doc)
	}
	if _, has := doc["stdout"]; has {
		t.Error("evicted result still carries stdout")
	}
	if doc["exit_code"] != float64(0) || hdr.Get("X-Room-Receipt") != "signed-bg" {
		t.Errorf("exit code or receipt lost: %v %q", doc["exit_code"], hdr.Get("X-Room-Receipt"))
	}
}

func TestNativeExecRestartBringsBackOverFileBudgetResultsAsEvictedNotMissing(t *testing.T) {
	execBounds(t)
	dir := t.TempDir()
	tc := newChainState(t, dir)
	n := tc.b.nexec
	n.mu.Lock()
	oldest := putExec(n, "g1", 32<<10, 3*time.Minute) // three guests, 96 KiB: fits memory, not the 64 KiB file
	middle := putExec(n, "g2", 32<<10, 2*time.Minute)
	newest := putExec(n, "g3", 32<<10, time.Minute)
	n.mu.Unlock()
	tc.b.saveNativeExecs()
	n.mu.Lock()
	for name, e := range map[string]*nativeExec{"oldest": oldest, "middle": middle, "newest": newest} {
		if evicted(e) || outputOf(e) != 32<<10 {
			t.Errorf("%s: saving changed the live result", name)
		}
	}
	n.mu.Unlock()
	tc.restart(t)
	after := tc.b.nexec.execs
	if after[oldest.ID] == nil || !evicted(after[oldest.ID]) {
		t.Fatalf("oldest after restart: %+v, want present and evicted", after[oldest.ID])
	}
	if after[oldest.ID].Headers["X-Room-Receipt"] == nil || after[oldest.ID].State != "exited" {
		t.Error("evicted entry lost its receipt or state across the restart")
	}
	for name, e := range map[string]*nativeExec{"middle": middle, "newest": newest} {
		if got := after[e.ID]; got == nil || evicted(got) || outputOf(got) != 32<<10 {
			t.Errorf("%s after restart: not full", name)
		}
	}
}

func TestNativeExecOldStateFileLoadsAndIsPruned(t *testing.T) {
	execBounds(t)
	dir := t.TempDir()
	tc := newChainState(t, dir)
	now := time.Now()
	saved := []map[string]any{ // as a broker before AB#748 could write it
		{"id": "stopped", "guest": "g1", "room": "a.r1", "state": "killed", "started": now.Add(-time.Minute), "result": map[string]any{"message": "stopped"}},
		{"id": "big1", "guest": "g1", "room": "a.r1", "state": "exited", "started": now.Add(-9 * time.Minute), "done_at": now.Add(-9 * time.Minute), "result": map[string]any{"stdout": strings.Repeat("x", 48<<10)}},
		{"id": "big2", "guest": "g1", "room": "a.r1", "state": "exited", "started": now.Add(-8 * time.Minute), "done_at": now.Add(-8 * time.Minute), "result": map[string]any{"stdout": strings.Repeat("x", 48<<10)}},
	}
	raw, _ := json.Marshal(saved)
	if err := os.WriteFile(filepath.Join(dir, nativeExecFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	got := tc.b.nexec.execs
	if got["stopped"] == nil || got["stopped"].DoneAt.IsZero() {
		t.Errorf("a stopped exec with no finish time was dropped or left without one: %+v", got["stopped"])
	}
	if got["big1"] == nil || !evicted(got["big1"]) || got["big2"] == nil || evicted(got["big2"]) {
		t.Errorf("old file over the bound: big1=%+v big2 evicted=%v", got["big1"], got["big2"] != nil && evicted(got["big2"]))
	}
}

func TestNativeExecStopKeepsItsFinishTimeWhenTheWorkerReturnsLater(t *testing.T) {
	tc, release := execChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	eid := startBG(t, tc, "key1", bid, "job")
	n := tc.b.nexec
	// Hold the worker back: the stop sets the finish time, and only 30 ms
	// later does the hotel call end and the worker come back.
	var stoppedAt time.Time
	var keptWhilePending bool
	n.mu.Lock()
	ex := n.execs[eid]
	cancel := ex.cancel
	ex.cancel = func() {
		n.mu.Lock()
		stoppedAt = ex.DoneAt
		n.pruneLocked(time.Now()) // before AB#748 a stopped exec had no finish time and was pruned as ancient
		_, keptWhilePending = n.execs[eid]
		n.mu.Unlock()
		time.Sleep(30 * time.Millisecond)
		cancel()
	}
	n.mu.Unlock()
	path := "/v1/sandboxes/" + bid + "/execs/" + eid
	if status, _, doc := tc.rawCall(t, "key1", "DELETE", path, nil); status != 200 || doc["state"] != "killed" {
		t.Fatalf("delete: %d %v", status, doc)
	}
	settleExecs(t, tc, release) // the worker has returned, or the test fails
	n.mu.Lock()
	defer n.mu.Unlock()
	if stoppedAt.IsZero() || !keptWhilePending {
		t.Fatalf("stopped exec: finish time zero=%v, kept while the worker was pending=%v", stoppedAt.IsZero(), keptWhilePending)
	}
	if e := n.execs[eid]; e == nil || e.State != "killed" || !e.DoneAt.Equal(stoppedAt) {
		t.Errorf("after the worker returned: %+v, want killed with finish time %v", e, stoppedAt)
	}
}

func TestNativeExecPrunesWithNoStateDirectory(t *testing.T) {
	execBounds(t)
	tc := newChainState(t, "")
	n := tc.b.nexec
	n.mu.Lock()
	old := putExec(n, "g1", 1<<10, nativeExecKeep+time.Minute)
	a := putExec(n, "g1", 48<<10, 2*time.Minute)
	putExec(n, "g1", 48<<10, time.Minute)
	n.mu.Unlock()
	tc.b.saveNativeExecs()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.execs[old.ID] != nil || !evicted(a) {
		t.Errorf("no state directory: aged entry kept=%v, over-bound result evicted=%v", n.execs[old.ID] != nil, evicted(a))
	}
}

func TestNativeExecRunningCapPerGuestIsExactUnderARace(t *testing.T) {
	execBounds(t)
	nativeExecMaxRunning = 3
	tc, release := execChain(t, t.TempDir())
	defer settleExecs(t, tc, release)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	other := tc.room(t, "key2", map[string]any{"image": "alpine:3.20"})
	start := func(key, room string) (int, map[string]any) {
		return tc.call(t, key, "POST", "/v1/sandboxes/"+room+"/execs", map[string]any{"cmd": []string{"job"}, "timeout_seconds": 600})
	}
	first := startBG(t, tc, "key1", bid, "job")
	startBG(t, tc, "key1", bid, "job")
	var wg sync.WaitGroup
	codes := make([]int, 6) // six racing starts for the one place left
	for i := range codes {
		wg.Add(1)
		go func() { defer wg.Done(); codes[i], _ = start("key1", bid) }()
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == 202 {
			ok++
		} else if c != 429 {
			t.Errorf("racing start: %d", c)
		}
	}
	if ok != 1 {
		t.Fatalf("racing starts accepted: %d, want exactly 1 (%v)", ok, codes)
	}
	if status, doc := start("key1", bid); status != 429 || errCode(doc) != "exec_capacity" {
		t.Fatalf("start at the cap: %d %v", status, doc)
	}
	if status, _ := start("key2", other); status != 202 {
		t.Errorf("another guest is not affected by this guest's cap: %d", status)
	}
	if status, _, _ := tc.rawCall(t, "key1", "DELETE", "/v1/sandboxes/"+bid+"/execs/"+first, nil); status != 200 {
		t.Fatalf("stop one: %d", status)
	}
	if status, doc := start("key1", bid); status != 202 {
		t.Errorf("start after one ended: %d %v", status, doc)
	}
}

func TestNativeExecBoundHoldsWhileASaveIsBlocked(t *testing.T) {
	execBounds(t)
	nativeExecGuestBytes = 700 // two ~300 byte results fit, more do not
	tc, release := execChain(t, t.TempDir())
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	n := tc.b.nexec
	var ids []string
	for i := 0; i < 8; i++ {
		ids = append(ids, startBG(t, tc, "key1", bid, strings.Repeat(string(rune('a'+i)), 300)))
	}
	n.saveMu.Lock() // every finishing command now waits here for the file
	locked := true
	unlock := func() {
		if locked {
			locked = false
			n.saveMu.Unlock()
		}
	}
	defer settleExecs(t, tc, release) // runs after unlock, on every path out of this test
	defer unlock()
	release()
	deadline := time.Now().Add(10 * time.Second)
	for {
		n.mu.Lock()
		running := 0
		for _, id := range ids {
			if n.execs[id].State == "running" {
				running++
			}
		}
		per, _ := held(n)
		n.mu.Unlock()
		if per["g1"] > nativeExecGuestBytes {
			t.Fatalf("with the save blocked g1 holds %d bytes, bound %d", per["g1"], nativeExecGuestBytes)
		}
		if running == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("commands did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
	n.mu.Lock()
	full, gone := 0, 0
	for i, id := range ids {
		e := n.execs[id]
		switch {
		case e.State != "exited":
			t.Errorf("command %d ended as %q, want exited", i, e.State)
		case evicted(e):
			gone++
		case e.Result["stdout"] == "out-"+strings.Repeat(string(rune('a'+i)), 300):
			full++
		default:
			t.Errorf("command %d: neither evicted nor its own output", i)
		}
	}
	n.mu.Unlock()
	if full != 2 || gone != 6 {
		t.Errorf("with the save blocked: %d full and %d evicted, want 2 and 6", full, gone)
	}
}

func TestNativeExecAWaitingPollGetsAnHonestAnswerWhenLaterResultsPushItOut(t *testing.T) {
	execBounds(t)
	nativeExecGuestBytes = 700 // two ~300 byte results fit, the third pushes the oldest out
	tc, release := execChain(t, t.TempDir())
	defer settleExecs(t, tc, release)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	path := "/v1/sandboxes/" + bid + "/execs/"
	var ids []string
	for i := 0; i < 3; i++ {
		ids = append(ids, startBG(t, tc, "key1", bid, strings.Repeat(string(rune('a'+i)), 300)))
	}
	type answer struct {
		status int
		hdr    http.Header
		doc    map[string]any
		err    error
	}
	polls := make([]chan answer, 3)
	for i, id := range ids {
		polls[i] = make(chan answer, 1)
		go func() { // no t.Fatal here: every path sends exactly one answer
			var got answer
			req, _ := http.NewRequest("GET", tc.srv.URL+path+id+"?wait=20", nil)
			req.Header.Set("Authorization", "Bearer key1")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				polls[i] <- answer{err: err}
				return
			}
			defer resp.Body.Close()
			got.status, got.hdr = resp.StatusCode, resp.Header
			got.err = json.NewDecoder(resp.Body).Decode(&got.doc)
			polls[i] <- got
		}()
	}
	// The polls are most likely waiting by now. If one is not, it polls a
	// finished command instead; the answer must be honest either way.
	time.Sleep(50 * time.Millisecond)
	release() // the three finish close together, in no fixed order
	full, gone := 0, 0
	for i := range ids {
		var got answer
		select {
		case got = <-polls[i]:
		case <-time.After(30 * time.Second):
			t.Fatalf("poll %d did not answer", i)
		}
		if got.err != nil {
			t.Fatalf("poll %d: %v", i, got.err)
		}
		if got.status != 200 || got.doc["state"] != "exited" || got.hdr.Get("X-Room-Receipt") != "signed-bg" {
			t.Fatalf("poll %d: %d %v", i, got.status, got.doc)
		}
		if got.doc["evicted"] == true { // best effort, and it says so: never a silent empty answer
			if got.doc["reason"] != "result_evicted" || got.doc["stdout"] != nil {
				t.Errorf("poll %d evicted without a reason, or with output: %v", i, got.doc)
			}
			gone++
		} else if got.doc["stdout"] == "out-"+strings.Repeat(string(rune('a'+i)), 300) {
			full++
		} else {
			t.Errorf("poll %d: neither evicted nor its own output: %v", i, got.doc)
		}
	}
	if full < 2 || full+gone != 3 {
		t.Errorf("%d full and %d evicted, want at least the two newest full", full, gone)
	}
	n := tc.b.nexec
	n.mu.Lock()
	defer n.mu.Unlock()
	var newest *nativeExec
	for _, id := range ids {
		if e := n.execs[id]; newest == nil || execOlder(newest, e) {
			newest = e
		}
	}
	if evicted(newest) {
		t.Error("the newest result was evicted")
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
	for i := 0; i < nativeExecMaxRunningTotal-1; i++ {
		id := fmt.Sprintf("run-%03d", i)
		guest := "g9" // other guests, so the per-guest running cap is not what refuses
		if i == 0 {
			guest = "g1"
		}
		n.execs[id] = &nativeExec{ID: id, Guest: guest, Room: bid, State: "running", Started: base.Add(time.Duration(i) * time.Second), done: make(chan struct{}), cancel: func() {}}
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
	if len(running) != nativeExecMaxRunningTotal || !running["run-000"] || !running[last] {
		t.Errorf("running ids on disk: %d (oldest kept %v, newest kept %v), want %d", len(running), running["run-000"], running[last], nativeExecMaxRunningTotal)
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
