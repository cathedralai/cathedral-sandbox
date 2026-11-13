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

const (
	nativeExecFile     = "native-execs.json"
	nativeExecKeep     = 24 * time.Hour // age bound for a finished result
	nativeExecMax      = 256            // count bound for kept execs
	nativeExecMaxBytes = 64 << 20       // size bound for the saved file's results
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
		n.execs[e.ID] = e
	}
}

// pruneNativeExecsLocked drops finished execs past the age bound and, newest
// first, past the count and size bounds. A running exec is never dropped or
// left out: start refuses past nativeExecMax running, so every accepted id is
// in the list it returns (AB#733). Call with n.mu held.
func (n *nativeExecs) pruneNativeExecsLocked(now time.Time) []*nativeExec {
	list := make([]*nativeExec, 0, len(n.execs))
	for id, e := range n.execs {
		if e.State != "running" && now.Sub(e.DoneAt) > nativeExecKeep {
			delete(n.execs, id)
			continue
		}
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Started.After(list[j].Started) })
	kept := list[:0:0]
	count, total := 0, 0
	for _, e := range list {
		if e.State == "running" {
			kept = append(kept, e)
			count++
			continue
		}
		size := 0
		for _, v := range e.Result {
			if s, ok := v.(string); ok {
				size += len(s)
			}
		}
		if count >= nativeExecMax || total+size > nativeExecMaxBytes {
			delete(n.execs, e.ID)
			continue
		}
		count++
		total += size
		kept = append(kept, e)
	}
	return kept
}

// saveNativeExecs prunes, then writes the file atomically. It prunes memory
// even without state_dir. An error means the file on disk is not current.
func (b *broker) saveNativeExecs() error {
	n := b.nexec
	n.saveMu.Lock()
	defer n.saveMu.Unlock()
	n.mu.Lock()
	kept := n.pruneNativeExecsLocked(time.Now())
	if b.cfg.StateDir == "" {
		n.mu.Unlock()
		return errNoExecStore
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
	running := 0
	for _, e := range n.execs {
		if e.State == "running" {
			running++
		}
	}
	if running >= nativeExecMax {
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
		ex.DoneAt = time.Now()
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
