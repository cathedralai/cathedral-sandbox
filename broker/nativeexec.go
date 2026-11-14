package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Background execs on the native room-id route (AB#553). The API starts a
// command, stores the exec id, and polls. The broker keeps the result, and
// writes it under state_dir, so a broker restart keeps every finished result.
// A command still running at a restart has no reader left (the answer lives
// only on the broker's open hotel call), so it comes back as "lost" and the
// reason says the outcome is unknown. Results are never logged.
//
// What the broker holds for finished commands is bounded in memory, not only
// in the file (AB#748). The bound always wins: when it is passed, older
// results are evicted first and a guest's newest result last. An evicted
// entry keeps its state, exit code, timing and receipt; only its large output
// text is dropped, and it says so.

const (
	nativeExecFile = "native-execs.json"
	nativeExecKeep = 24 * time.Hour // age bound for a finished result
)

// Bounds. Variables so tests can use small values.
var (
	nativeExecMax             = 256       // finished execs kept, whole broker
	nativeExecMaxPerGuest     = 64        // finished execs kept, one guest
	nativeExecGuestBytes      = 64 << 20  // result output held in memory, one guest
	nativeExecTotalBytes      = 256 << 20 // result output held in memory, whole broker
	nativeExecFileBytes       = 64 << 20  // result output written to the saved file
	nativeExecMaxRunning      = 32        // execs one guest may have running
	nativeExecMaxRunningTotal = 256       // execs running on the whole broker
)

var errNoExecStore = errors.New("no state_dir")

// nativeExecDrain is how long a stopping broker waits for running execs.
var nativeExecDrain = 60 * time.Second

type nativeExec struct {
	ID      string              `json:"id"`
	Guest   string              `json:"guest"`
	Room    string              `json:"room"`  // broker room id (hotel.room)
	State   string              `json:"state"` // running, exited, timed_out, lost, killed
	Result  map[string]any      `json:"result,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"` // X-Room-* from the hotel (the signed receipt)
	Started time.Time           `json:"started"`
	DoneAt  time.Time           `json:"done_at,omitempty"`
	done    chan struct{}
	cancel  context.CancelFunc
}

type nativeExecs struct {
	mu    sync.Mutex
	execs map[string]*nativeExec
	wg    sync.WaitGroup
	// saveMu keeps one file write at a time, snapshot through rename.
	saveMu sync.Mutex
}

func newNativeExecs() *nativeExecs { return &nativeExecs{execs: map[string]*nativeExec{}} }

// loadNativeExecs reads the saved execs. A command that was running when the
// file was written is lost: nobody holds its answer any more.
func (b *broker) loadNativeExecs() {
	if b.cfg.StateDir == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(b.cfg.StateDir, nativeExecFile))
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("native execs: %s not read (%v); earlier exec ids will read 404", nativeExecFile, err)
		}
		return
	}
	var saved []*nativeExec
	if err := json.Unmarshal(raw, &saved); err != nil {
		log.Printf("native execs: %s does not parse (%v); earlier exec ids will read 404", nativeExecFile, err)
		return
	}
	n := b.nexec
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, e := range saved {
		if e == nil || e.ID == "" {
			continue
		}
		e.done = make(chan struct{})
		close(e.done)
		e.cancel = func() {}
		if e.State == "running" {
			e.State = "lost"
			e.Result = map[string]any{"message": "the broker restarted while the command ran; the outcome is unknown", "reason": "broker_restarted"}
			e.DoneAt = time.Now()
		}
		if e.DoneAt.IsZero() { // a file from before every end state had a finish time
			e.DoneAt = time.Now()
		}
		n.execs[e.ID] = e
	}
	n.pruneLocked(time.Now())
}

// execOutputFields are the output of a command in a hotel exec answer. They
// are the only large values in it, each clipped at execOutputCapBytes.
var execOutputFields = []string{"stdout", "stderr"}

// execOutputBytes is the size of a result's output: every byte of stdout and
// stderr. It is what the bounds count and what an eviction frees.
func execOutputBytes(e *nativeExec) int {
	size := 0
	for _, k := range execOutputFields {
		if str, ok := e.Result[k].(string); ok {
			size += len(str)
		}
	}
	return size
}

// evictedResult is the result without its output, marked as evicted. It is a
// new map: the caller decides whether it replaces the live result or only
// goes to the saved file. The receipt headers are kept by the caller; they
// sign the hotel's original answer, not this shortened one.
func evictedResult(result map[string]any) map[string]any {
	out := make(map[string]any, len(result)+4)
	for k, v := range result {
		out[k] = v
	}
	for _, k := range execOutputFields {
		delete(out, k)
	}
	out["evicted"] = true
	out["reason"] = "result_evicted"
	out["message"] = "the output of this command was dropped to stay inside the memory kept for finished commands; poll soon after a command ends"
	out["receipt_covers"] = "original_result"
	return out
}

// execOlder orders finished execs by finish time (id breaks a tie).
func execOlder(a, b *nativeExec) bool {
	if !a.DoneAt.Equal(b.DoneAt) {
		return a.DoneAt.Before(b.DoneAt)
	}
	return a.ID < b.ID
}

// pruneLocked applies every bound. The caller holds n.mu. It rescans the map
// each time (up to nativeExecMax finished entries plus the running ones), so
// there is no counter to drift. Each loop pass deletes an entry or drops
// output from a result that has some, so every loop ends.
func (n *nativeExecs) pruneLocked(now time.Time) {
	byGuest := map[string][]*nativeExec{} // finished, oldest first
	finished := 0
	for id, e := range n.execs {
		if e.State == "running" {
			continue
		}
		if now.Sub(e.DoneAt) > nativeExecKeep {
			delete(n.execs, id)
			continue
		}
		byGuest[e.Guest] = append(byGuest[e.Guest], e)
		finished++
	}
	for g, list := range byGuest {
		sort.Slice(list, func(i, j int) bool { return execOlder(list[i], list[j]) })
		for len(list) > nativeExecMaxPerGuest {
			delete(n.execs, list[0].ID)
			list = list[1:]
			finished--
		}
		byGuest[g] = list
	}
	// Whole broker count: take from the guest holding the most, so a guest
	// with one result loses it only when there are more guests than places.
	for finished > nativeExecMax {
		most, count := "", 0
		for g, list := range byGuest {
			if len(list) > count || (len(list) == count && count > 0 && g < most) {
				most, count = g, len(list)
			}
		}
		if count == 0 {
			break // no finished entry is left to take
		}
		delete(n.execs, byGuest[most][0].ID)
		byGuest[most] = byGuest[most][1:]
		finished--
	}
	// Output per guest: oldest first, so the newest goes last.
	total := 0
	for _, list := range byGuest {
		held := 0
		for _, e := range list {
			held += execOutputBytes(e)
		}
		for _, e := range list {
			if held <= nativeExecGuestBytes {
				break
			}
			if size := execOutputBytes(e); size > 0 {
				e.Result = evictedResult(e.Result)
				held -= size
			}
		}
		total += held
	}
	// Output for the whole broker. Only results that still have output are
	// candidates. First the older results of the guest whose older results
	// hold the most; a guest's newest result only when no older output is left.
	for total > nativeExecTotalBytes {
		var victim *nativeExec
		most := -1
		for _, list := range byGuest {
			older, first := 0, (*nativeExec)(nil)
			for _, e := range list[:max(len(list)-1, 0)] {
				if size := execOutputBytes(e); size > 0 {
					older += size
					if first == nil {
						first = e
					}
				}
			}
			if first != nil && (older > most || (older == most && execOlder(first, victim))) {
				most, victim = older, first
			}
		}
		if victim == nil {
			for _, list := range byGuest {
				if len(list) == 0 {
					continue
				}
				if e := list[len(list)-1]; execOutputBytes(e) > 0 && (victim == nil || execOlder(e, victim)) {
					victim = e
				}
			}
		}
		if victim == nil {
			return // nothing with output is left; cannot happen while total > 0
		}
		total -= execOutputBytes(victim)
		victim.Result = evictedResult(victim.Result)
	}
}

// saveNativeExecs prunes, then writes the file atomically. With no state
// directory it still prunes, and reports errNoExecStore. Any error means the
// file on disk is not current (AB#733).
func (b *broker) saveNativeExecs() error {
	n := b.nexec
	n.saveMu.Lock()
	defer n.saveMu.Unlock()
	n.mu.Lock()
	n.pruneLocked(time.Now())
	if b.cfg.StateDir == "" {
		n.mu.Unlock()
		return errNoExecStore
	}
	list := make([]*nativeExec, 0, len(n.execs))
	for _, e := range n.execs {
		list = append(list, e)
	}
	// Newest first: results keep their output while the file stays under its
	// bound. Past it an entry is written as an evicted copy, so after a
	// restart it reads as evicted, not as missing. The live entry is untouched.
	// A running entry is always written, so every accepted id reads its
	// result or lost after a restart, never 404.
	when := func(e *nativeExec) time.Time {
		if e.State == "running" {
			return e.Started
		}
		return e.DoneAt
	}
	sort.Slice(list, func(i, j int) bool {
		if !when(list[i]).Equal(when(list[j])) {
			return when(list[i]).After(when(list[j]))
		}
		return list[i].ID > list[j].ID
	})
	kept := make([]*nativeExec, 0, len(list))
	total := 0
	for _, e := range list {
		size := execOutputBytes(e)
		if e.State != "running" && size > 0 && total+size > nativeExecFileBytes {
			shadow := *e
			shadow.Result = evictedResult(e.Result)
			kept = append(kept, &shadow)
			continue
		}
		total += size
		kept = append(kept, e)
	}
	raw, err := json.Marshal(kept)
	n.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(b.cfg.StateDir, nativeExecFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(b.cfg.StateDir, nativeExecFile))
}

// nativeExecStart runs the command in the background on the room's hotel.
func (b *broker) nativeExecStart(w http.ResponseWriter, g *guestState, rm *room, bid string, raw []byte) {
	if err := requireExecCmdList(raw); err != nil {
		writeErr(w, 400, "invalid_exec", err.Error())
		return
	}
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	if v, ok := body["command"]; ok { // the hotel reads cmd
		if _, has := body["cmd"]; !has {
			body["cmd"] = v
		}
		delete(body, "command")
	}
	if v, ok := body["spill_token"]; ok && v != nil {
		tok, good := spillToken(v)
		if !good {
			writeErr(w, 400, "invalid_exec", "spill_token must be 32 lowercase hex characters")
			return
		}
		body["spill_token"] = tok
	}
	timeout := b.maxExec()
	if v, ok := body["timeout_seconds"].(float64); ok && v > 0 {
		timeout = int(v)
	}
	// A 202 promises a result or lost/broker_restarted after a restart, never
	// 404. So the running entry is on disk before anything goes to the hotel,
	// and a broker that cannot write it refuses (AB#733).
	if b.cfg.StateDir == "" {
		writeErr(w, 503, "exec_store_unavailable", "this broker has no state_dir, so a background exec would not survive a restart; use POST .../exec")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	ex := &nativeExec{ID: newUUID(), Guest: g.cfg.ID, Room: bid, State: "running", Started: time.Now(), done: make(chan struct{}), cancel: cancel}
	n := b.nexec
	n.mu.Lock()
	n.pruneLocked(time.Now())
	running, guestRunning := 0, 0
	for _, e := range n.execs {
		if e.State == "running" {
			running++
			if e.Guest == g.cfg.ID {
				guestRunning++
			}
		}
	}
	if guestRunning >= nativeExecMaxRunning {
		n.mu.Unlock()
		cancel()
		w.Header().Set("Retry-After", "5")
		writeErr(w, 429, "exec_capacity", fmt.Sprintf("this key may have %d background commands running at one time; wait for one to end", nativeExecMaxRunning))
		return
	}
	// Whole broker: running entries are never pruned, so cap them too.
	if running >= nativeExecMaxRunningTotal {
		n.mu.Unlock()
		cancel()
		w.Header().Set("Retry-After", "30")
		writeErr(w, 429, "too_many_execs", fmt.Sprintf("%d background execs are running on this broker; try again shortly", running))
		return
	}
	n.execs[ex.ID] = ex
	n.mu.Unlock()
	if err := b.saveNativeExecs(); err != nil {
		n.mu.Lock()
		delete(n.execs, ex.ID)
		n.mu.Unlock()
		cancel()
		writeErr(w, 503, "exec_store_unavailable", "the broker could not save the exec, so nothing was started")
		return
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		defer close(ex.done)
		status, hdr, doc, herr := b.hotelExecH(ctx, rm, body, timeout)
		n.mu.Lock()
		if ex.DoneAt.IsZero() { // a stop on request already set it; it does not move
			ex.DoneAt = time.Now()
		}
		switch {
		case ex.State == "killed":
		case herr != nil:
			ex.State, ex.Result = "lost", map[string]any{"message": "the hotel did not answer", "reason": "hotel_unreachable"}
		case status != 200:
			ex.State, ex.Result = "lost", map[string]any{"message": fmt.Sprintf("hotel answered %d", status), "reason": "hotel_error"}
		default:
			clipExecDoc(doc)
			ex.State, ex.Result = "exited", doc
			if t, _ := doc["timed_out"].(bool); t {
				ex.State = "timed_out"
			}
			ex.Headers = map[string][]string{}
			copyRoomHeaders(http.Header(ex.Headers), hdr)
		}
		// The result and the bounds in one locked step, before any file work.
		n.pruneLocked(time.Now())
		n.mu.Unlock()
		// A failed write leaves the entry running on disk: after a restart it
		// reads lost/broker_restarted, and until then the result is in memory.
		_ = b.saveNativeExecs()
	}()
	writeJSON(w, 202, map[string]any{"exec_id": ex.ID, "state": "running"})
}

// nativeExecPoll answers GET (optionally waiting up to 25 s) and DELETE.
// An exec of another guest or another room reads as not found.
func (b *broker) nativeExecPoll(w http.ResponseWriter, r *http.Request, g *guestState, bid, execID string) {
	n := b.nexec
	n.mu.Lock()
	ex := n.execs[execID]
	n.mu.Unlock()
	if ex == nil || ex.Guest != g.cfg.ID || ex.Room != bid || (r.Method != "GET" && r.Method != "DELETE") {
		writeErr(w, 404, "exec_not_found", "no command "+execID)
		return
	}
	if r.Method == "DELETE" {
		n.mu.Lock()
		killed := ex.State == "running"
		if killed {
			ex.State = "killed"
			ex.DoneAt = time.Now() // the age bound counts from here
			ex.Result = map[string]any{"message": "stopped on request; the command may run on inside the room until its timeout"}
		}
		n.mu.Unlock()
		ex.cancel()
		if killed {
			_ = b.saveNativeExecs()
		}
	} else if wait, _ := strconv.Atoi(r.URL.Query().Get("wait")); wait > 0 {
		if wait > 25 {
			wait = 25
		}
		select {
		case <-ex.done:
		case <-time.After(time.Duration(wait) * time.Second):
		case <-r.Context().Done():
		}
	}
	n.mu.Lock()
	out := map[string]any{"exec_id": ex.ID, "state": ex.State}
	for k, v := range ex.Result {
		out[k] = v
	}
	hdr := http.Header(ex.Headers)
	for k, v := range hdr {
		w.Header()[k] = v
	}
	n.mu.Unlock()
	writeJSON(w, 200, out)
}

// drainNativeExecs waits for running execs, up to d, then saves. Execs still
// running afterwards come back as lost after the restart.
func (b *broker) drainNativeExecs(d time.Duration) {
	idle := make(chan struct{})
	go func() { b.nexec.wg.Wait(); close(idle) }()
	select {
	case <-idle:
	case <-time.After(d):
	}
	_ = b.saveNativeExecs()
}

// routeNativeExec handles the exec start and poll tails; it reports whether it took the request.
func (b *broker) routeNativeExec(w http.ResponseWriter, r *http.Request, g *guestState, rm *room, bid, tail string, body []byte) bool {
	switch {
	case tail == "execs" && r.Method == "POST":
		r.Body = io.NopCloser(bytes.NewReader(body))
		b.compatIdemLimit(w, r, g, 256<<20, func(w http.ResponseWriter, raw []byte) { b.nativeExecStart(w, g, rm, bid, raw) })
		return true
	case strings.HasPrefix(tail, "execs/") && !strings.Contains(strings.TrimPrefix(tail, "execs/"), "/"):
		b.nativeExecPoll(w, r, g, bid, strings.TrimPrefix(tail, "execs/"))
		return true
	}
	return false
}
