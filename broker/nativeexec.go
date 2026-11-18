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
	"net/url"
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
// A command still running at a restart is re-attached (AB#756): the start
// sends a broker-minted exec handle in X-Room-Exec-Handle, the hotel's
// receipts front keeps that exec's answer, and a restarted broker reads it
// back by handle. It is lost only when the hotel says it no longer holds the
// exec (hotel_lost_exec), when the hotel's front cannot re-attach
// (broker_restarted, as before), or when the hotel stays unreachable past the
// command's time limit (hotel_unreachable). Results are never logged.
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

// Re-attach (AB#756). Variables so tests can use small values.
const (
	nativeExecHandleHeader = "X-Room-Exec-Handle" // request: the front keeps this exec's answer
	nativeExecStateHeader  = "X-Room-Exec-State"  // answer of the front's result route: running or done
)

var (
	nativeExecResumeGrace = 150 * time.Second // past the exec's time limit before a silent hotel means lost
	nativeExecResumeGap   = time.Second       // least time between two result reads
	nativeExecResumeFirst = time.Second       // first pause after a transient error
	nativeExecResumeBack  = 30 * time.Second  // longest pause after a transient error
	nativeExecResumeWait  = 25                // seconds the front may hold one read
)

type nativeExec struct {
	ID      string              `json:"id"`
	Guest   string              `json:"guest"`
	Room    string              `json:"room"`  // broker room id (hotel.room)
	State   string              `json:"state"` // running, exited, timed_out, lost, killed
	Result  map[string]any      `json:"result,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"` // X-Room-* from the hotel (the signed receipt)
	Started time.Time           `json:"started"`
	DoneAt  time.Time           `json:"done_at,omitempty"`
	// Handle is the broker-minted id the hotel's front keeps the answer under,
	// and Timeout the limit the hotel runs it under (AB#756).
	Handle  string `json:"hotel_handle,omitempty"`
	Timeout int    `json:"timeout_seconds,omitempty"`
	done    chan struct{}
	cancel  context.CancelFunc
	ctx     context.Context // ends on DELETE or on broker stop (resumed execs only)
}

type nativeExecs struct {
	mu    sync.Mutex
	execs map[string]*nativeExec
	wg    sync.WaitGroup
	// saveMu keeps one file write at a time, snapshot through rename.
	saveMu sync.Mutex
	// stop ends every re-attach at the start of a broker stop: the next broker
	// re-attaches, so waiting for them buys nothing.
	stop     context.Context
	stopFunc context.CancelFunc
	resume   []*nativeExec // loaded running execs, waiting for resumeNativeExecs
}

func newNativeExecs() *nativeExecs {
	stop, stopFunc := context.WithCancel(context.Background())
	return &nativeExecs{execs: map[string]*nativeExec{}, stop: stop, stopFunc: stopFunc}
}

// stopNativeResume ends the re-attach loops; their execs stay running on disk.
func (b *broker) stopNativeResume() { b.nexec.stopFunc() }

// loadNativeExecs reads the saved execs. A command that was running when the
// file was written is re-attached by resumeNativeExecs when it has a hotel
// handle; one from before handles (or with no time limit saved) is lost.
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
		if e.State == "running" && e.Handle != "" && e.Timeout > 0 {
			e.ctx, e.cancel = context.WithCancel(n.stop)
			n.execs[e.ID] = e
			n.resume = append(n.resume, e)
			continue
		}
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
	timeout = b.clampExecTimeout(timeout)
	// A 202 promises a result or lost/broker_restarted after a restart, never
	// 404. So the running entry is on disk before anything goes to the hotel,
	// and a broker that cannot write it refuses (AB#733).
	if b.cfg.StateDir == "" {
		writeErr(w, 503, "exec_store_unavailable", "this broker has no state_dir, so a background exec would not survive a restart; use POST .../exec")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	// The handle is ours, never the caller's spill_token: two execs can share a
	// token, and a minted token would turn on the hotel's spill buffer.
	ex := &nativeExec{ID: newUUID(), Guest: g.cfg.ID, Room: bid, State: "running", Started: time.Now(), done: make(chan struct{}), cancel: cancel,
		Handle: strings.ReplaceAll(newUUID(), "-", ""), Timeout: timeout}
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
		status, hdr, doc, herr := b.hotelExecKept(ctx, rm, body, timeout, http.Header{nativeExecHandleHeader: {ex.Handle}})
		b.endNativeExec(ex, herr == nil, func() { finishNativeExecLocked(ex, status, hdr, doc, herr) })
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
// running afterwards are saved running with their hotel handle, and the next
// broker re-attaches them. Re-attach loops end at stopNativeResume, before this.
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

// finishNativeExecLocked stores the hotel's answer to a running exec. A stop on
// request (killed) already ended it and wins. The caller holds n.mu.
func finishNativeExecLocked(ex *nativeExec, status int, hdr http.Header, doc map[string]any, herr error) {
	if ex.State != "running" {
		return
	}
	ex.DoneAt = time.Now()
	switch {
	case herr != nil:
		ex.State, ex.Result = "lost", map[string]any{"message": "the hotel did not answer", "reason": "hotel_unreachable"}
	case status != 200:
		ex.State, ex.Result = "lost", map[string]any{"message": fmt.Sprintf("hotel answered %d", status), "reason": "hotel_error"}
	default:
		if doc == nil {
			doc = map[string]any{}
		}
		clipExecDoc(doc)
		ex.State, ex.Result = "exited", doc
		if t, _ := doc["timed_out"].(bool); t {
			ex.State = "timed_out"
		}
		// The front's re-attach marker is not part of the result: a re-attached
		// result carries the same headers as one read on the start call.
		room := hdr.Clone()
		room.Del(nativeExecStateHeader)
		ex.Headers = map[string][]string{}
		copyRoomHeaders(http.Header(ex.Headers), room)
	}
}

// lostNativeExecLocked ends a running exec as lost. The caller holds n.mu.
func lostNativeExecLocked(ex *nativeExec, reason, message string) {
	if ex.State != "running" {
		return
	}
	ex.DoneAt = time.Now()
	ex.State, ex.Result = "lost", map[string]any{"message": message, "reason": reason}
}

// endNativeExec applies end (a locked step that may store the end), prunes,
// saves and, when the hotel answered and the file holds the end, tells the
// front to drop its copy. A failed save keeps the front's copy: the entry is
// still running on disk and the next broker reads it again.
func (b *broker) endNativeExec(ex *nativeExec, answered bool, end func()) {
	n := b.nexec
	n.mu.Lock()
	end()
	// The result and the bounds in one locked step, before any file work.
	n.pruneLocked(time.Now())
	n.mu.Unlock()
	if b.saveNativeExecs() == nil && answered && ex.Handle != "" {
		b.ackNativeExec(ex)
	}
}

// nativeExecResultPath is the front's result route for an exec, and the hotel.
func (b *broker) nativeExecResultPath(ex *nativeExec) (*hotel, string, url.Values) {
	hotelID, hid, ok := strings.Cut(ex.Room, ".")
	if !ok {
		return nil, "", nil
	}
	return b.hotelByID(hotelID), "/v1/sandboxes/" + url.PathEscape(hid) + "/exec/result", url.Values{"handle": {ex.Handle}}
}

// ackNativeExec drops the front's copy of a result the broker has saved. Best
// effort: a copy left behind ages out on the hotel.
func (b *broker) ackNativeExec(ex *nativeExec) {
	h, path, q := b.nativeExecResultPath(ex)
	if h == nil {
		return
	}
	_, _, _, _ = h.doHeaders(b.nexec.stop, h.cfg.API, "DELETE", path, q, nil, 10*time.Second, nil)
}

// resumeNativeExecs starts one re-attach loop per running exec loaded from the
// file. Call it once, after the hotels are loaded.
func (b *broker) resumeNativeExecs() {
	n := b.nexec
	n.mu.Lock()
	list := n.resume
	n.resume = nil
	n.mu.Unlock()
	for _, ex := range list {
		n.wg.Add(1)
		go b.resumeNativeExec(ex)
	}
}

// resumeNativeExec reads a running exec's answer back from the hotel's front.
// The front's X-Room-Exec-State decides first: done is the exec's own answer,
// whatever its status; running waits again. Without it, 404 exec_unknown means
// the hotel no longer holds the exec, another 4xx (not 429) means a front
// without re-attach, and anything else is transient until the deadline.
func (b *broker) resumeNativeExec(ex *nativeExec) {
	n := b.nexec
	defer n.wg.Done()
	deadline := ex.Started.Add(time.Duration(ex.Timeout)*time.Second + nativeExecResumeGrace)
	backoff := nativeExecResumeFirst
	// pause sleeps up to d, never past the deadline; false when the context ended.
	pause := func(d time.Duration) bool {
		if left := time.Until(deadline); d > left {
			d = left
		}
		if d <= 0 {
			return ex.ctx.Err() == nil
		}
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			return true
		case <-ex.ctx.Done():
			return false
		}
	}
loop:
	for {
		if ex.ctx.Err() != nil {
			break
		}
		left := time.Until(deadline)
		if left <= 0 {
			b.endNativeExec(ex, false, func() {
				lostNativeExecLocked(ex, "hotel_unreachable", "the hotel did not give the result back after the broker restarted; the outcome is unknown")
			})
			close(ex.done)
			return
		}
		h, path, q := b.nativeExecResultPath(ex)
		if h == nil { // not configured (yet): transient
			if !pause(backoff) {
				break loop
			}
			backoff = min(backoff*2, nativeExecResumeBack)
			continue
		}
		// The read, its wait and its timeout all end inside the time left.
		wait := min(nativeExecResumeWait, int((left-5*time.Second)/time.Second))
		wait = max(wait, 0)
		q.Set("wait", strconv.Itoa(wait))
		callTimeout := min(time.Duration(wait)*time.Second+15*time.Second, left)
		sent := time.Now()
		status, hdr, out, err := h.doHeaders(ex.ctx, h.cfg.API, "GET", path, q, nil, callTimeout, nil)
		if ex.ctx.Err() != nil {
			break loop
		}
		if err == nil {
			switch hdr.Get(nativeExecStateHeader) {
			case "done":
				var doc map[string]any
				_ = json.Unmarshal(out, &doc)
				b.endNativeExec(ex, true, func() { finishNativeExecLocked(ex, status, hdr, doc, nil) })
				close(ex.done)
				return
			case "running":
				backoff = nativeExecResumeFirst
				if !pause(nativeExecResumeGap - time.Since(sent)) {
					break loop
				}
				continue
			}
			code := errCodeOf(out)
			if status == 404 && code == "exec_unknown" {
				b.endNativeExec(ex, false, func() {
					lostNativeExecLocked(ex, "hotel_lost_exec", "the hotel no longer holds this command; the outcome is unknown")
				})
				close(ex.done)
				return
			}
			if status >= 400 && status < 500 && status != 429 {
				b.endNativeExec(ex, false, func() {
					lostNativeExecLocked(ex, "broker_restarted", "the broker restarted while the command ran; the outcome is unknown")
				})
				close(ex.done)
				return
			}
		}
		if !pause(backoff) {
			break loop
		}
		backoff = min(backoff*2, nativeExecResumeBack)
	}
	// The context ended: a stop on request (killed, the DELETE saved it) or a
	// broker stop (the exec stays running on disk for the next broker).
	n.mu.Lock()
	killed := ex.State != "running"
	n.mu.Unlock()
	if killed {
		close(ex.done)
	}
}
