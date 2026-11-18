package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// AB#752: compat background exec results (/execs on a uuid room) are bounded
// as native ones are (AB#748): finished output and count per guest and for the
// broker, older evicted first. Answer reads are bounded per read and, in all,
// by the answer pool.

// compatExecChain is a broker whose hotels answer exec "sleep" when released,
// "big N" with N bytes of stdout, and anything else at once.
func compatExecChain(t *testing.T, stateDir string) (*testChain, string, func()) {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	tc := r6Chain(t, stateDir, func(id string, f *fakeHotel, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/exec") && r.Method == "POST" {
				body, _ := io.ReadAll(r.Body)
				var req map[string]any
				_ = json.Unmarshal(body, &req)
				cmd, _ := req["cmd"].([]any)
				stdout := "done"
				if len(cmd) > 0 && cmd[0] == "sleep" {
					<-release
				}
				if len(cmd) > 1 && cmd[0] == "big" {
					n, _ := strconv.Atoi(cmd[1].(string))
					stdout = strings.Repeat("x", n)
				}
				writeJSON(w, 200, map[string]any{"exit_code": 0, "stdout": stdout, "stderr": "", "timed_out": false})
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	// Release the hotel and let every exec worker end before the test's bounds
	// are put back (cleanups run last-in first-out), so no worker reads a bound
	// while a cleanup writes it.
	t.Cleanup(func() {
		free()
		tc.b.compat.mu.Lock()
		done := make([]chan struct{}, 0, len(tc.b.compat.execs))
		for _, ex := range tc.b.compat.execs {
			done = append(done, ex.done)
		}
		tc.b.compat.mu.Unlock()
		for _, d := range done {
			select {
			case <-d:
			case <-time.After(10 * time.Second):
				t.Error("an exec worker did not end")
			}
		}
	})
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	return tc, doc["id"].(string), free
}

// compatRoomOf creates a room for the guest of key and returns its id.
func compatRoomOf(t *testing.T, tc *testChain, key string) string {
	t.Helper()
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), map[string]string{"Authorization": "Bearer " + key})
	if status != 201 {
		t.Fatalf("create as %s: %d %v", key, status, doc)
	}
	return doc["id"].(string)
}

func compatPoll(t *testing.T, tc *testChain, key, id, tail string) map[string]any {
	t.Helper()
	_, doc := tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+tail, nil, map[string]string{"Authorization": "Bearer " + key})
	return doc
}

func compatEndedAs(t *testing.T, tc *testChain, key, id string, cmd ...string) string {
	t.Helper()
	auth := map[string]string{"Authorization": "Bearer " + key}
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/execs", mustMarshal(map[string]any{"cmd": cmd}), auth)
	if status != 202 {
		t.Fatalf("exec start %v as %s: %d %v", cmd, key, status, doc)
	}
	eid := doc["exec_id"].(string)
	if doc := compatPoll(t, tc, key, id, eid+"?wait=10"); doc["state"] != "exited" {
		t.Fatalf("exec %v as %s did not end: %v", cmd, key, doc)
	}
	return eid
}

func compatStart(t *testing.T, tc *testChain, id string, cmd ...string) (int, map[string]any) {
	t.Helper()
	return tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/execs", mustMarshal(map[string]any{"cmd": cmd}), nil)
}

func compatEnded(t *testing.T, tc *testChain, id string, cmd ...string) string {
	t.Helper()
	status, doc := compatStart(t, tc, id, cmd...)
	if status != 202 {
		t.Fatalf("exec start %v: %d %v", cmd, status, doc)
	}
	eid := doc["exec_id"].(string)
	if status, doc := tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+eid+"?wait=10", nil, nil); doc["state"] != "exited" {
		t.Fatalf("exec %v did not end: %d %v", cmd, status, doc)
	}
	return eid
}

func TestCompatExecOutputBoundEvictsOlderFirst(t *testing.T) {
	execBounds(t) // 64 KiB of output per guest
	tc, id, _ := compatExecChain(t, t.TempDir())
	older := compatEnded(t, tc, id, "big", strconv.Itoa(40<<10))
	newer := compatEnded(t, tc, id, "big", strconv.Itoa(40<<10))

	_, doc := tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+older, nil, nil)
	if doc["evicted"] != true || doc["reason"] != "result_evicted" || doc["stdout"] != nil || doc["state"] != "exited" || doc["exit_code"] != 0.0 {
		t.Fatalf("older result past the guest bound: %v; want evicted, state and exit code kept, no stdout", doc)
	}
	if _, ok := doc["receipt_covers"]; ok {
		t.Errorf("compat evicted result names a receipt it does not keep: %v", doc)
	}
	_, doc = tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+newer, nil, nil)
	if s, _ := doc["stdout"].(string); len(s) != 40<<10 || doc["evicted"] != nil {
		t.Fatalf("newest result: evicted=%v stdout %d bytes; want it whole", doc["evicted"], len(s))
	}
}

// The broker bound evicts when no guest passes its own: the older result of
// the guest whose older results hold the most goes first.
func TestCompatExecOutputBoundBroker(t *testing.T) {
	execBounds(t) // 64 KiB per guest
	old := nativeExecTotalBytes
	nativeExecTotalBytes = 80 << 10
	t.Cleanup(func() { nativeExecTotalBytes = old })
	tc, id, _ := compatExecChain(t, t.TempDir())
	other := compatRoomOf(t, tc, "key2")
	first := compatEnded(t, tc, id, "big", strconv.Itoa(30<<10))
	theirs := compatEndedAs(t, tc, "key2", other, "big", strconv.Itoa(30<<10))
	last := compatEnded(t, tc, id, "big", strconv.Itoa(30<<10)) // g1 60 KiB (under 64), broker 90 KiB (over 80)
	if doc := compatPoll(t, tc, "key1", id, first); doc["evicted"] != true {
		t.Fatalf("g1's older result past the broker bound: %v; want evicted", doc)
	}
	for _, c := range []struct{ key, room, eid string }{{"key2", other, theirs}, {"key1", id, last}} {
		if doc := compatPoll(t, tc, c.key, c.room, c.eid); doc["evicted"] != nil {
			t.Errorf("%s newest result evicted by the broker bound while older output was left: %v", c.key, doc["reason"])
		}
	}
}

// One guest past its own bound loses its own older output, never another guest's.
func TestCompatExecOutputBoundIsPerGuest(t *testing.T) {
	execBounds(t) // 64 KiB per guest, 256 KiB broker
	tc, id, _ := compatExecChain(t, t.TempDir())
	other := compatRoomOf(t, tc, "key2")
	theirs := compatEndedAs(t, tc, "key2", other, "big", strconv.Itoa(40<<10))
	mine := compatEnded(t, tc, id, "big", strconv.Itoa(40<<10))
	compatEnded(t, tc, id, "big", strconv.Itoa(40<<10))
	if doc := compatPoll(t, tc, "key1", id, mine); doc["evicted"] != true {
		t.Fatalf("g1's older result past its guest bound: %v; want evicted", doc)
	}
	if doc := compatPoll(t, tc, "key2", other, theirs); doc["evicted"] != nil {
		t.Fatalf("g2's result evicted by g1's output: %v", doc)
	}
}

// The count bound removes a guest's oldest finished result.
func TestCompatExecCountBound(t *testing.T) {
	old := nativeExecMaxPerGuest
	nativeExecMaxPerGuest = 2
	t.Cleanup(func() { nativeExecMaxPerGuest = old })
	tc, id, _ := compatExecChain(t, t.TempDir())
	first := compatEnded(t, tc, id, "true")
	compatEnded(t, tc, id, "true")
	compatEnded(t, tc, id, "true")
	status, doc := tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+first, nil, nil)
	if code, _ := r6Detail(doc); status != 404 || code != "exec_not_found" {
		t.Fatalf("oldest of three past a count of two: %d %v; want 404 exec_not_found", status, doc)
	}
}

// A read waits for room in the answer pool, then goes on: no failure, and no
// more answer bytes held at once than the pool allows.
func TestCompatExecAnswerWaitsForThePool(t *testing.T) {
	tc, id, _ := compatExecChain(t, t.TempDir())
	held, err := tc.b.answers.reserve(context.Background(), "g1", answerPoolGuestBytes)
	if err != nil {
		t.Fatal(err)
	}
	status, doc := compatStart(t, tc, id, "big", "100")
	if status != 202 {
		t.Fatalf("start: %d %v", status, doc)
	}
	eid := doc["exec_id"].(string)
	if doc := compatPoll(t, tc, "key1", id, eid+"?wait=1"); doc["state"] != "running" {
		t.Fatalf("exec whose answer has no room in g1's share: %v; want still running", doc)
	}
	// Another guest's share is its own.
	other := compatRoomOf(t, tc, "key2")
	compatEndedAs(t, tc, "key2", other, "true")
	held()
	if doc := compatPoll(t, tc, "key1", id, eid+"?wait=10"); doc["state"] != "exited" || doc["stdout"] != strings.Repeat("x", 100) {
		t.Fatalf("exec after the pool had room: %v; want exited with its output", doc)
	}
	tc.b.answers.mu.Lock()
	used := tc.b.answers.used
	tc.b.answers.mu.Unlock()
	if used != 0 {
		t.Errorf("answer pool holds %d bytes after every read ended; want 0", used)
	}
}

func TestAnswerPool(t *testing.T) {
	oldG, oldT := answerPoolGuestBytes, answerPoolTotalBytes
	answerPoolGuestBytes, answerPoolTotalBytes = 100, 150
	t.Cleanup(func() { answerPoolGuestBytes, answerPoolTotalBytes = oldG, oldT })
	p := newAnswerPool()
	if _, err := p.reserve(context.Background(), "a", 101); err != errAnswerTooLarge {
		t.Fatalf("a read over the guest share: %v; want errAnswerTooLarge", err)
	}
	ra, _ := p.reserve(context.Background(), "a", 100)
	rb, _ := p.reserve(context.Background(), "b", 50)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := p.reserve(ctx, "b", 10); err == nil {
		t.Fatal("a read past the broker total did not wait")
	}
	got := make(chan error, 1)
	go func() {
		release, err := p.reserve(context.Background(), "b", 50)
		if err == nil {
			release()
		}
		got <- err
	}()
	ra()
	ra() // a second release gives nothing back twice
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a waiting read was not woken by a release")
	}
	rb()
	if p.used != 0 || len(p.owner) != 0 {
		t.Fatalf("pool after every release: used %d, owners %v", p.used, p.owner)
	}
}

func TestCompatExecOversizeHotelAnswerIsNotRead(t *testing.T) {
	old := execAnswerMaxBytes
	execAnswerMaxBytes = 4 << 10
	t.Cleanup(func() { execAnswerMaxBytes = old })
	tc, id, _ := compatExecChain(t, t.TempDir())
	status, doc := compatStart(t, tc, id, "big", strconv.Itoa(8<<10))
	if status != 202 {
		t.Fatalf("start: %d %v", status, doc)
	}
	eid := doc["exec_id"].(string)
	_, doc = tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+eid+"?wait=10", nil, nil)
	if doc["state"] != "lost" || doc["stdout"] != nil {
		t.Fatalf("hotel answer over the read limit: %v; want lost with no output", doc)
	}
	// The sync compat exec reads the same way: 502, nothing half-parsed.
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/exec", mustMarshal(map[string]any{"cmd": []string{"big", strconv.Itoa(8 << 10)}}), nil)
	if code, _ := r6Detail(doc); status != 502 || code != "hotel_unreachable" {
		t.Fatalf("sync exec over the read limit: %d %v; want 502 hotel_unreachable", status, doc)
	}
}

func TestCompatExecStoresClippedOutput(t *testing.T) {
	tc, id, _ := compatExecChain(t, t.TempDir())
	eid := compatEnded(t, tc, id, "big", strconv.Itoa(execOutputCapBytes+10))
	tc.b.compat.mu.Lock()
	stdout, _ := tc.b.compat.execs[eid].result["stdout"].(string)
	truncated := tc.b.compat.execs[eid].result["truncated"]
	tc.b.compat.mu.Unlock()
	if len(stdout) != execOutputCapBytes || truncated != true {
		t.Fatalf("kept stdout %d bytes, truncated %v; want %d and true", len(stdout), truncated, execOutputCapBytes)
	}
}

// Without a state_dir saveCompat never runs; the age rule still applies on the next start.
func TestCompatExecAgePruneWithoutStateDir(t *testing.T) {
	tc, id, _ := compatExecChain(t, "")
	eid := compatEnded(t, tc, id, "true")
	tc.b.compat.mu.Lock()
	tc.b.compat.execs[eid].doneAt = time.Now().Add(-2 * time.Hour)
	tc.b.compat.mu.Unlock()
	compatEnded(t, tc, id, "true")
	status, doc := tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+eid, nil, nil)
	if code, _ := r6Detail(doc); status != 404 || code != "exec_not_found" {
		t.Fatalf("result two hours old after a later start: %d %v; want 404 exec_not_found", status, doc)
	}
}

// A stopped exec counts as finished from the stop, not as ancient.
func TestCompatExecKilledGetsAFinishTime(t *testing.T) {
	tc, id, _ := compatExecChain(t, t.TempDir())
	status, doc := compatStart(t, tc, id, "sleep", "600")
	if status != 202 {
		t.Fatalf("start: %d %v", status, doc)
	}
	eid := doc["exec_id"].(string)
	if status, doc := tc.clientCall(t, "DELETE", "/v1/sandboxes/"+id+"/execs/"+eid, nil, nil); status != 200 || doc["state"] != "killed" {
		t.Fatalf("stop: %d %v", status, doc)
	}
	compatEnded(t, tc, id, "true") // prunes
	if status, doc := tc.clientCall(t, "GET", "/v1/sandboxes/"+id+"/execs/"+eid, nil, nil); status != 200 || doc["state"] != "killed" {
		t.Fatalf("stopped exec after a prune: %d %v; want 200 killed", status, doc)
	}
}
