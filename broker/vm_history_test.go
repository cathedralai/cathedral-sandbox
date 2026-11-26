package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests for docs/VM_EXECUTION_HISTORY.md, broker section B0 to B5 (AB#992).
// The host is the fake below: it answers `cancel <name> <G>` and
// `history <name> <G>` as the spec defines them. A crash is simulated by
// failing an append (appendHook) or a vms.json save (saveHook) at one step and
// then loading a new store from the same state dir.

const (
	histStopBase   = 1800001000 // host stop of generation g closes at base+g
	histCancelBase = 1800002000 // host cancel of an open generation g closes at base+g
	histStartedAt  = "2030-03-17T17:46:39.500000Z"
)

type histHost struct {
	mu          sync.Mutex
	closed      map[uint64]int64  // the host's close records
	histStopped map[uint64]int64  // history answers with another stopped_at (tampering)
	histExit    map[uint64]string // "open" or "unknown": exit 3 for history of g
	histRaw     map[uint64]string // a history answer sent verbatim (a member left out, a wrong type)
	down        map[string]bool   // subcommand -> the host does not answer
	refuseStop  bool              // stop answers exit 3
	deleted     bool
	deleteCalls int
	cancels     []uint64
	histCalls   int
}

func newHistHost() *histHost {
	return &histHost{closed: map[uint64]int64{}, histStopped: map[uint64]int64{}, histExit: map[uint64]string{}, histRaw: map[uint64]string{}, down: map[string]bool{}}
}

func (h *histHost) answer(args []string) ([]byte, int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.down[args[0]] {
		return nil, 0, errors.New("connection reset")
	}
	gen := func() uint64 {
		var g uint64
		fmt.Sscan(args[len(args)-1], &g)
		return g
	}
	switch args[0] {
	case "stop":
		if h.refuseStop {
			return []byte(`{"error":"stale_authorization"}`), vmExitStale, nil
		}
		g := gen()
		if _, ok := h.closed[g]; !ok {
			h.closed[g] = histStopBase + int64(g)
		}
		return []byte(fmt.Sprintf(`{"ok":true,"stopped_at":%d}`, h.closed[g]) + "\n"), 0, nil
	case "cancel":
		g := gen()
		h.cancels = append(h.cancels, g)
		if _, ok := h.closed[g]; !ok {
			h.closed[g] = histCancelBase + int64(g)
		}
		return []byte(fmt.Sprintf(`{"name":%q,"generation":%d,"stopped_at":%d,"reason":"cancelled"}`, args[1], g, h.closed[g]) + "\n"), 0, nil
	case "history":
		h.histCalls++
		g := gen()
		switch {
		case h.histExit[g] == "unknown":
			return []byte(`{"code":"history_unknown"}` + "\n"), vmExitStale, nil
		case h.histExit[g] == "open", h.closed[g] == 0:
			return []byte(`{"code":"history_open"}` + "\n"), vmExitStale, nil
		}
		if raw, ok := h.histRaw[g]; ok {
			return []byte(raw + "\n"), 0, nil
		}
		at := h.closed[g]
		if o, ok := h.histStopped[g]; ok {
			at = o
		}
		return []byte(fmt.Sprintf(`{"generation":%d,"closed":true,"started_at":%q,"started_at_error_us":1500,"stopped_at":%d,"tracked_from":1,"close_reason":"stopped","history":"v2"}`, g, histStartedAt, at) + "\n"), 0, nil
	case "delete":
		h.deleteCalls++
		existed := !h.deleted
		h.deleted = true
		return []byte(fmt.Sprintf(`{"ok":true,"existed":%v}`, existed) + "\n"), 0, nil
	case "list":
		return []byte(`{"vms":[]}`), 0, nil
	}
	return []byte(`{"ok":true}` + "\n"), 0, nil
}

func (h *histHost) set(f func(h *histHost)) {
	h.mu.Lock()
	f(h)
	h.mu.Unlock()
}

// restart loads a new broker from the same state dir, as after a crash. With
// replay it runs the start-time pass main runs.
func (tb *vmTestBroker) restart(t *testing.T, replay bool) *vmTestBroker {
	t.Helper()
	tb2 := loadVMTestBroker(t, tb.cfg)
	tb2.now = tb.now
	tb2.b.vms.now = func() time.Time { return tb2.now }
	tb2.host.answer = tb.host.answer
	if replay {
		tb2.b.vms.replay(context.Background())
	}
	return tb2
}

type histCase struct {
	tb   *vmTestBroker
	host *histHost
	id   string
	base string
}

func (c *histCase) post(t *testing.T, op string, body any) (int, map[string]any) {
	t.Helper()
	return c.tb.call(t, "operator-key", "POST", c.base+"/"+op, body)
}

func (c *histCase) must(t *testing.T, op string, body any) map[string]any {
	t.Helper()
	st, doc := c.post(t, op, body)
	if st != 200 {
		t.Fatalf("%s %v: %d %v", op, body, st, doc)
	}
	return doc
}

func (c *histCase) authorize(t *testing.T, gen int) {
	t.Helper()
	c.must(t, "authorize", map[string]any{"generation": gen, "paid_through": c.tb.now.Unix() + 300})
}

func (c *histCase) run(t *testing.T) { // authorize and start the next generation
	t.Helper()
	var doc map[string]any
	_, doc = c.tb.call(t, "operator-key", "GET", c.base, nil)
	g := int(doc["generation"].(float64)) + 1
	c.authorize(t, g)
	c.must(t, "start", map[string]any{"generation": g})
}

func newHistCase(t *testing.T) *histCase {
	t.Helper()
	tb := newVMTestBroker(t, true)
	h := newHistHost()
	tb.host.answer = h.answer
	id := tb.create(t, nil)["id"].(string)
	return &histCase{tb: tb, host: h, id: id, base: "/v1/broker/vms/" + id}
}

func (c *histCase) runs(t *testing.T) []vmRunLine { return readRunsFile(t, c.tb) }

// readRunsFile: the receipts and tombstones of vm-runs.jsonl (no intents).
func readRunsFile(t *testing.T, tb *vmTestBroker) []vmRunLine {
	t.Helper()
	var out []vmRunLine
	for _, l := range readRawRuns(t, tb) {
		if l.isReceipt() || l.isTombstone() {
			out = append(out, l)
		}
	}
	return out
}

// readRawRuns: every line of vm-runs.jsonl.
func readRawRuns(t *testing.T, tb *vmTestBroker) []vmRunLine {
	t.Helper()
	var out []vmRunLine
	raw, err := os.ReadFile(filepath.Join(tb.b.cfg.StateDir, vmRunsFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var l vmRunLine
		if err := json.Unmarshal(line, &l); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		out = append(out, l)
	}
	return out
}

func readHistFile(t *testing.T, tb *vmTestBroker) []vmHistoryLine {
	t.Helper()
	var out []vmHistoryLine
	raw, err := os.ReadFile(filepath.Join(tb.b.cfg.StateDir, vmHistoryFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var l vmHistoryLine
		if err := json.Unmarshal(line, &l); err != nil {
			t.Fatal(err)
		}
		out = append(out, l)
	}
	return out
}

// onDiskRecord reads the VM from vms.json, not from memory.
func onDiskRecord(t *testing.T, tb *vmTestBroker, id string) *vmRecord {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(tb.b.cfg.StateDir, vmsFile))
	if err != nil {
		t.Fatal(err)
	}
	var doc vmsFileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for i := range doc.VMs {
		if doc.VMs[i].ID == id {
			return &doc.VMs[i]
		}
	}
	return nil
}

func failOn(file string, n *int) func(string, []byte) error {
	return func(name string, _ []byte) error {
		if name == file {
			*n++
			return errors.New("disk full")
		}
		return nil
	}
}

// ---------------------------------------------------------------- B0

// B0: a host refusal of a stop is settled by the host's cancel; the stored
// stopped_at is the host's close record, never the broker's clock.
func TestVMHistoryRefusalStoresHostCloseNotBrokerTime(t *testing.T) {
	// stopVM: a start whose answer was lost, never confirmed running.
	c := newHistCase(t)
	c.authorize(t, 1)
	c.host.set(func(h *histHost) { h.down["start"] = true })
	if st, _ := c.post(t, "start", nil); st != 502 {
		t.Fatalf("lost start: %d", st)
	}
	c.host.set(func(h *histHost) { h.down["start"] = false; h.refuseStop = true })
	c.tb.now = c.tb.now.Add(77) // broker time moves on; it must not show up
	st, doc := c.post(t, "stop", map[string]any{"generation": 1})
	want := float64(histCancelBase + 1)
	if st != 200 || doc["stopped_at"] != want || doc["stopped_at"] == float64(c.tb.now.Unix()) {
		t.Fatalf("stop after host refusal: %d %v", st, doc)
	}
	if rs := c.runs(t); len(rs) != 1 || rs[0].StoppedAt != histCancelBase+1 || rs[0].Kind != vmReceiptCancel {
		t.Fatalf("receipts: %+v", rs)
	}

	// cancelVMRun: an authorized, unstarted next run whose stop the host refuses.
	d := newHistCase(t)
	d.run(t)
	d.must(t, "stop", map[string]any{"generation": 1})
	d.authorize(t, 2)
	d.host.set(func(h *histHost) { h.refuseStop = true })
	d.tb.now = d.tb.now.Add(99)
	st, doc = d.post(t, "stop", map[string]any{"generation": 2})
	if st != 200 || doc["stopped_at"] != float64(histCancelBase+2) || doc["generation"] != float64(2) {
		t.Fatalf("cancel after host refusal: %d %v", st, doc)
	}
	if got := d.host.cancels; len(got) != 1 || got[0] != 2 {
		t.Fatalf("host cancel calls: %v", got)
	}

	// A run that ran keeps the refusal and gets no receipt from a cancel.
	e := newHistCase(t)
	e.run(t)
	e.host.set(func(h *histHost) { h.refuseStop = true })
	if st, doc := e.post(t, "stop", map[string]any{"generation": 1}); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("ran run, host refusal: %d %v", st, doc)
	}
	if len(e.host.cancels) != 0 || len(e.runs(t)) != 0 {
		t.Fatal("a refused stop of a run that ran was settled by cancel")
	}
}

// B0: a host that cannot say the close changes nothing, and the cancel repeats.
func TestVMHistoryCancelHostDownChangesNothing(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.authorize(t, 2)
	c.host.set(func(h *histHost) { h.refuseStop = true; h.down["cancel"] = true })
	if st, doc := c.post(t, "stop", map[string]any{"generation": 2}); st != 502 {
		t.Fatalf("cancel with the host down: %d %v", st, doc)
	}
	if rec := onDiskRecord(t, c.tb, c.id); rec.Generation != 1 {
		t.Fatalf("generation moved: %+v", rec)
	}
	if len(c.runs(t)) != 1 {
		t.Fatal("a receipt for a close nobody confirmed")
	}
	c.host.set(func(h *histHost) { h.down["cancel"] = false })
	if st, doc := c.post(t, "stop", map[string]any{"generation": 2}); st != 200 || doc["stopped_at"] != float64(histCancelBase+2) {
		t.Fatalf("repeat: %d %v", st, doc)
	}
}

// ---------------------------------------------------------------- B1

// B1: the receipt is durable (file and dir fsync) before vms.json shows the
// stop and before the 200, and the stop and its receipt agree.
func TestVMHistoryReceiptWrittenBeforeStateAndAnswer(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	var order []string
	orig := durableSync
	defer func() { durableSync = orig }()
	durableSync = func(f *os.File) error {
		st, _ := f.Stat()
		kind := "file"
		if st != nil && st.IsDir() {
			kind = "dir"
		}
		order = append(order, kind+":"+filepath.Base(f.Name()))
		return orig(f)
	}
	var atReceipt *vmRecord
	c.tb.b.vms.appendHook = func(name string, _ []byte) error {
		if name == vmRunsFile {
			atReceipt = onDiskRecord(t, c.tb, c.id) // vms.json at the moment the receipt is written
		}
		return nil
	}
	st, doc := c.post(t, "stop", map[string]any{"generation": 1})
	if st != 200 || doc["stopped_at"] != float64(histStopBase+1) {
		t.Fatalf("stop: %d %v", st, doc)
	}
	if atReceipt == nil || atReceipt.StoppedAt != 0 {
		t.Fatalf("vms.json already showed the stop when the receipt was written: %+v", atReceipt)
	}
	idx := func(s string) int {
		for i, o := range order {
			if o == s {
				return i
			}
		}
		return -1
	}
	// The receipt is the second runs append (the first is the close intent).
	rf := idx("file:" + vmRunsFile)
	rf += 2 + idxFrom(order[rf+2:], "file:"+vmRunsFile)
	rd := rf + 1 + idxFrom(order[rf+1:], "dir:"+filepath.Base(c.tb.b.cfg.StateDir))
	vf := rd + 1 + idxFrom(order[rd+1:], "file:"+vmsFile+".tmp")
	if order[rf] != "file:"+vmRunsFile || rd < rf || vf < rd {
		t.Fatalf("fsync order (receipt file, dir, then vms.json) is %v", order)
	}
	rs := c.runs(t)
	if len(rs) != 1 || rs[0] != (vmRunLine{VM: c.id, Account: "acct-1", Host: onDiskRecord(t, c.tb, c.id).Host, Generation: 1, StoppedAt: histStopBase + 1, Kind: vmReceiptStop}) {
		t.Fatalf("receipt: %+v", rs)
	}
	if rec := onDiskRecord(t, c.tb, c.id); rec.StoppedAt != histStopBase+1 {
		t.Fatalf("vms.json after the stop: %+v", rec)
	}
}

// B1 crash window 1: the receipt append fails. 500 state_not_saved, vms.json
// does not show the stop, and the repeat finishes it.
func TestVMHistoryFailedReceiptAppendIs500AndLeavesState(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	before := onDiskRecord(t, c.tb, c.id)
	var fails int
	c.tb.b.vms.appendHook = failOn(vmRunsFile, &fails)
	st, doc := c.post(t, "stop", map[string]any{"generation": 1})
	if st != 500 || vmErrCode(doc) != "state_not_saved" || fails != 1 {
		t.Fatalf("stop with a failing receipt append: %d %v", st, doc)
	}
	rec := onDiskRecord(t, c.tb, c.id)
	if rec.StoppedAt != 0 || rec.Generation != before.Generation {
		t.Fatalf("vms.json shows a stop that has no receipt: %+v", rec)
	}
	if len(c.runs(t)) != 0 {
		t.Fatal("receipt on disk after a failed append")
	}
	// Restart from disk: still no closed run, the next run is refused, the repeat works.
	tb2 := c.tb.restart(t, true)
	c2 := &histCase{tb: tb2, host: c.host, id: c.id, base: c.base}
	if st, _ := c2.post(t, "authorize", map[string]any{"generation": 2, "paid_through": tb2.now.Unix() + 300}); st != 409 {
		t.Fatalf("authorize of the next run before the stop: %d", st)
	}
	if doc := c2.must(t, "stop", map[string]any{"generation": 1}); doc["stopped_at"] != float64(histStopBase+1) {
		t.Fatalf("repeat: %v", doc)
	}
	if len(c2.runs(t)) != 1 {
		t.Fatalf("receipts: %+v", c2.runs(t))
	}
}

// B1 crash window 2: the receipt is on disk, vms.json is not saved. A restart
// adopts the receipt without any host call, and the next run starts.
func TestVMHistoryCrashBetweenReceiptAndVMsJSONReplaysAtStart(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	saves := 0
	c.tb.b.vms.saveHook = func() error { // the intent save passes; the save after the receipt fails
		saves++
		if saves == 1 {
			return nil
		}
		return errors.New("crash")
	}
	if st, doc := c.post(t, "stop", map[string]any{"generation": 1}); st != 500 || vmErrCode(doc) != "state_not_saved" {
		t.Fatalf("stop: %d %v", st, doc)
	}
	if len(c.runs(t)) != 1 {
		t.Fatal("the receipt must be on disk before the save")
	}
	if rec := onDiskRecord(t, c.tb, c.id); rec.StoppedAt != 0 {
		t.Fatalf("vms.json: %+v", rec)
	}
	tb2 := c.tb.restart(t, true)
	if rec := onDiskRecord(t, tb2, c.id); rec.StoppedAt != histStopBase+1 || rec.Generation != 1 {
		t.Fatalf("vms.json after the replay: %+v", rec)
	}
	c2 := &histCase{tb: tb2, host: c.host, id: c.id, base: c.base}
	c2.authorize(t, 2)
	c2.must(t, "start", map[string]any{"generation": 2})
	if len(c2.runs(t)) != 1 {
		t.Fatalf("receipts: %+v", c2.runs(t))
	}
}

// B1: the same crash for a cancel of the next run: the replay moves the record
// to the cancelled generation.
func TestVMHistoryCrashBetweenCancelReceiptAndVMsJSON(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.authorize(t, 2)
	c.tb.b.vms.saveHook = func() error { return errors.New("crash") }
	if st, doc := c.post(t, "stop", map[string]any{"generation": 2}); st != 500 {
		t.Fatalf("cancel: %d %v", st, doc)
	}
	c.tb.b.vms.saveHook = nil
	if rec := onDiskRecord(t, c.tb, c.id); rec.Generation != 1 {
		t.Fatalf("vms.json moved before it was saved: %+v", rec)
	}
	tb2 := c.tb.restart(t, true)
	if rec := onDiskRecord(t, tb2, c.id); rec.Generation != 2 || rec.StoppedAt != histStopBase+2 {
		t.Fatalf("after the replay: %+v", rec)
	}
}

// B1: authorize and start of G+1 answer receipt_missing while G is closed on
// record without a receipt. The replay at start fills it from the host.
func TestVMHistoryReceiptMissingGateAndReplayAtStart(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.authorize(t, 2) // authorized while G had its receipt
	if err := os.Remove(filepath.Join(c.tb.b.cfg.StateDir, vmRunsFile)); err != nil {
		t.Fatal(err)
	}
	// A broker that restarted with the host not answering: the gate holds.
	c.host.set(func(h *histHost) { h.down["cancel"] = true })
	tb2 := c.tb.restart(t, true)
	c2 := &histCase{tb: tb2, host: c.host, id: c.id, base: c.base}
	if st, doc := c2.post(t, "authorize", map[string]any{"generation": 2, "paid_through": tb2.now.Unix() + 400}); st != 409 || vmErrCode(doc) != "receipt_missing" {
		t.Fatalf("authorize: %d %v", st, doc)
	}
	if st, doc := c2.post(t, "start", map[string]any{"generation": 2}); st != 409 || vmErrCode(doc) != "receipt_missing" {
		t.Fatalf("start: %d %v", st, doc)
	}
	if rec := onDiskRecord(t, tb2, c.id); rec.Generation != 1 || rec.DesiredState != vmStateStopped {
		t.Fatalf("a refused start changed the record: %+v", rec)
	}
	// The host is back: the replay calls cancel G and stores the receipt.
	c.host.set(func(h *histHost) { h.down["cancel"] = false })
	tb3 := c.tb.restart(t, true)
	c3 := &histCase{tb: tb3, host: c.host, id: c.id, base: c.base}
	if got := c.host.cancels; len(got) == 0 || got[len(got)-1] != 1 {
		t.Fatalf("host cancel calls %v, want one for generation 1", got)
	}
	if rs := c3.runs(t); len(rs) != 1 || rs[0].Generation != 1 || rs[0].StoppedAt != histStopBase+1 {
		t.Fatalf("receipts after the replay: %+v", rs)
	}
	c3.must(t, "authorize", map[string]any{"generation": 2, "paid_through": tb3.now.Unix() + 400})
	c3.must(t, "start", map[string]any{"generation": 2})
}

// B1: a repeated Stop of a run closed on record without a receipt makes it.
func TestVMHistoryRepeatedStopMakesMissingReceipt(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	os.Remove(filepath.Join(c.tb.b.cfg.StateDir, vmRunsFile))
	tb2 := c.tb.restart(t, false)
	c2 := &histCase{tb: tb2, host: c.host, id: c.id, base: c.base}
	if st, doc := c2.post(t, "stop", map[string]any{"generation": 1}); st != 200 || doc["stopped_at"] != float64(histStopBase+1) {
		t.Fatalf("repeat stop: %d %v", st, doc)
	}
	if len(c2.runs(t)) != 1 {
		t.Fatalf("receipts: %+v", c2.runs(t))
	}
}

// ---------------------------------------------------------------- B2

// B2: history is stored right after the receipt, keyed by (vm, generation),
// and never overwritten.
func TestVMHistoryStoredAfterStopAndNeverOverwritten(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	hs := readHistFile(t, c.tb)
	if len(hs) != 1 || hs[0].VM != c.id || hs[0].Generation != 1 || hs[0].StoppedAt != histStopBase+1 || hs[0].StartedAt == nil || *hs[0].StartedAt != histStartedAt || hs[0].History != "v2" {
		t.Fatalf("history: %+v", hs)
	}
	calls := c.host.histCalls
	// The route is served from the file: no second host call, and a host that
	// now says something else changes nothing.
	c.host.set(func(h *histHost) { h.histStopped[1] = 5 })
	for i := 0; i < 2; i++ {
		if st, doc := c.tb.call(t, "operator-key", "GET", c.base+"/runs/1", nil); st != 200 || doc["stopped_at"] != float64(histStopBase+1) {
			t.Fatalf("route: %d %v", st, doc)
		}
	}
	if c.host.histCalls != calls || len(readHistFile(t, c.tb)) != 1 {
		t.Fatal("stored history was fetched or written again")
	}
}

// B2 crash window: the history append fails or the host is down. Stop still
// answers 200; the next GET retries and stores it.
func TestVMHistoryFetchFailureDoesNotFailStopAndRetries(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.host.set(func(h *histHost) { h.down["history"] = true })
	c.must(t, "stop", map[string]any{"generation": 1})
	if len(readHistFile(t, c.tb)) != 0 {
		t.Fatal("history stored while the host was down")
	}
	// A history append that fails is no different.
	c.host.set(func(h *histHost) { h.down["history"] = false })
	var fails int
	c.tb.b.vms.appendHook = failOn(vmHistoryFile, &fails)
	c.tb.call(t, "operator-key", "GET", c.base, nil)
	if fails == 0 || len(readHistFile(t, c.tb)) != 0 {
		t.Fatalf("expected a failed history append, fails=%d", fails)
	}
	// Restart from disk: the receipt is there, the history is pending, a GET stores it.
	c.tb.b.vms.appendHook = nil
	tb2 := c.tb.restart(t, false)
	tb2.call(t, "operator-key", "GET", c.base, nil)
	if hs := readHistFile(t, tb2); len(hs) != 1 || hs[0].StoppedAt != histStopBase+1 {
		t.Fatalf("history after the retry: %+v", hs)
	}
}

// Spec test: a history fetch failure, then G+1 starts, then the history of G
// still matches the B1 receipt.
func TestVMHistoryFetchFailureThenNextRunThenHistoryMatchesReceipt(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.host.set(func(h *histHost) { h.down["history"] = true })
	c.must(t, "stop", map[string]any{"generation": 1})
	c.run(t) // generation 2 starts while history of 1 is pending
	c.host.set(func(h *histHost) { h.down["history"] = false })
	st, doc := c.tb.call(t, "operator-key", "GET", c.base+"/runs/1", nil)
	if st != 200 || doc["stopped_at"] != float64(histStopBase+1) || doc["generation"] != float64(1) {
		t.Fatalf("history of 1 after run 2 started: %d %v", st, doc)
	}
	if rs := c.runs(t); rs[0].StoppedAt != histStopBase+1 {
		t.Fatalf("receipt: %+v", rs)
	}
	if hs := readHistFile(t, c.tb); len(hs) != 1 || hs[0].Generation != 1 {
		t.Fatalf("history: %+v", hs)
	}
}

// B2: a history answer whose stopped_at differs from the receipt is refused.
func TestVMHistoryMismatchRefused(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.host.set(func(h *histHost) { h.histStopped[1] = histStopBase + 99 })
	c.must(t, "stop", map[string]any{"generation": 1}) // Stop still answers 200
	if len(readHistFile(t, c.tb)) != 0 {
		t.Fatal("a mismatched history was stored")
	}
	st, doc := c.tb.call(t, "operator-key", "GET", c.base+"/runs/1", nil)
	if st != 409 || vmErrCode(doc) != "vm_history_mismatch" {
		t.Fatalf("route: %d %v", st, doc)
	}
	// Delete refuses too: history cannot be stored.
	if st, doc := c.tb.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id}); st != 409 || vmErrCode(doc) != "history_not_stored" {
		t.Fatalf("delete: %d %v", st, doc)
	}
}

// ---------------------------------------------------------------- B3

// B3: delete with an authorized, unstarted G2 cancels and records G2 first.
func TestVMHistoryDeleteCancelsAuthorizedUnstartedRunFirst(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.authorize(t, 2)
	var seq []string
	c.tb.b.vms.exec = execFunc(func(args []string) ([]byte, int, error) {
		seq = append(seq, args[0])
		return c.host.answer(args)
	})
	st, doc := c.tb.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id})
	if st != 200 || doc["deleted"] != true {
		t.Fatalf("delete: %d %v", st, doc)
	}
	if got := c.host.cancels; len(got) != 1 || got[0] != 2 {
		t.Fatalf("host cancels: %v", got)
	}
	// Cancel before history before host delete.
	pos := map[string]int{}
	for i, s := range seq {
		if _, ok := pos[s]; !ok {
			pos[s] = i
		}
	}
	if !(pos["cancel"] < pos["history"] && pos["history"] < pos["delete"]) {
		t.Fatalf("call order %v", seq)
	}
	rs := c.runs(t)
	if len(rs) != 3 || rs[1].Generation != 2 || rs[1].Kind != vmReceiptCancel || !rs[2].isTombstone() || rs[2].VM != c.id {
		t.Fatalf("vm-runs.jsonl: %+v", rs)
	}
	if hs := readHistFile(t, c.tb); len(hs) != 2 {
		t.Fatalf("history: %+v", hs)
	}
	if onDiskRecord(t, c.tb, c.id) != nil {
		t.Fatal("VM still in vms.json")
	}
}

func idxFrom(order []string, want string) int {
	for i, o := range order {
		if o == want {
			return i
		}
	}
	return 1 << 20
}

type execFunc func(args []string) ([]byte, int, error)

func (f execFunc) Run(_ context.Context, _ vmHostConfig, _ []byte, args ...string) ([]byte, int, error) {
	return f(args)
}

// B3: delete of a running VM closes its run through the host first.
func TestVMHistoryDeleteOfRunningVMClosesItsRun(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	if st, doc := c.tb.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id}); st != 200 {
		t.Fatalf("delete: %d %v", st, doc)
	}
	if rs := c.runs(t); len(rs) != 2 || rs[0].Generation != 1 || rs[0].Kind != vmReceiptCancel || !rs[1].isTombstone() {
		t.Fatalf("vm-runs.jsonl: %+v", rs)
	}
}

// B3: delete refuses until every receipt has history (or the host says
// unknown), then leaves a tombstone, and only then drops the VM.
func TestVMHistoryDeleteRefusesUntilHistoryStoredThenTombstones(t *testing.T) {
	c := newHistCase(t)
	c.host.set(func(h *histHost) { h.down["history"] = true })
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	del := func() (int, map[string]any) {
		return c.tb.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id})
	}
	if st, doc := del(); st != 409 || vmErrCode(doc) != "history_not_stored" {
		t.Fatalf("delete with history pending: %d %v", st, doc)
	}
	if c.host.deleteCalls != 0 || onDiskRecord(t, c.tb, c.id) == nil || len(c.runs(t)) != 1 {
		t.Fatal("a refused delete went on to the host or dropped the VM")
	}
	c.host.set(func(h *histHost) { h.down["history"] = false; h.histExit[1] = "open" })
	if st, doc := del(); st != 409 || vmErrCode(doc) != "history_not_stored" {
		t.Fatalf("delete with history open: %d %v", st, doc)
	}
	// The host says unknown for good: that also lets the delete go.
	c.host.set(func(h *histHost) { h.histExit[1] = "unknown" })
	if st, doc := del(); st != 200 {
		t.Fatalf("delete with history unknown: %d %v", st, doc)
	}
	rs := c.runs(t)
	if len(rs) != 2 || !rs[1].isTombstone() || rs[1].Account != "acct-1" || rs[1].DeletedAt != c.tb.now.Unix() {
		t.Fatalf("tombstone: %+v", rs)
	}
}

// B3: an interrupted delete replays safely from every step.
func TestVMHistoryInterruptedDeleteReplays(t *testing.T) {
	steps := []struct {
		name   string
		break_ func(c *histCase, fails *int)
		heal   func(c *histCase)
	}{
		{"cancel receipt append", func(c *histCase, f *int) { c.tb.b.vms.appendHook = failOn(vmRunsFile, f) }, func(c *histCase) {}},
		{"cancel host down", func(c *histCase, f *int) { c.host.set(func(h *histHost) { h.down["cancel"] = true; *f++ }) }, func(c *histCase) { c.host.set(func(h *histHost) { h.down["cancel"] = false }) }},
		{"history fetch", func(c *histCase, f *int) { c.host.set(func(h *histHost) { h.down["history"] = true; *f++ }) }, func(c *histCase) { c.host.set(func(h *histHost) { h.down["history"] = false }) }},
		{"history append", func(c *histCase, f *int) { c.tb.b.vms.appendHook = failOn(vmHistoryFile, f) }, func(c *histCase) {}},
		{"host delete", func(c *histCase, f *int) { c.host.set(func(h *histHost) { h.down["delete"] = true; *f++ }) }, func(c *histCase) { c.host.set(func(h *histHost) { h.down["delete"] = false }) }},
		{"tombstone append", func(c *histCase, f *int) {
			calls := 0
			c.tb.b.vms.appendHook = func(name string, _ []byte) error {
				if name == vmRunsFile {
					calls++
					if calls == 1 { // after the receipts: the first runs line of this delete is the tombstone
						*f++
						return errors.New("disk full")
					}
				}
				return nil
			}
		}, func(c *histCase) {}},
		{"remove from vms.json", func(c *histCase, f *int) {
			c.tb.b.vms.saveHook = func() error { return errors.New("crash") }
			*f++
		}, func(c *histCase) {}},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			c := newHistCase(t)
			c.run(t)
			c.must(t, "stop", map[string]any{"generation": 1})
			c.authorize(t, 2) // an unstarted G2 for the delete to cancel
			fails := 0
			switch step.name {
			case "tombstone append", "remove from vms.json":
				// Let the receipts and history of the first attempt go through, then break the later step.
				c.must(t, "stop", map[string]any{"generation": 2})
			}
			step.break_(c, &fails)
			st, doc := c.tb.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id})
			if st == 200 || fails == 0 {
				t.Fatalf("the broken step did not stop the delete: %d %v fails=%d", st, doc, fails)
			}
			// Crash: a new store from disk, healed, and the delete is repeated.
			tb2 := c.tb.restart(t, false)
			step.heal(c)
			c2 := &histCase{tb: tb2, host: c.host, id: c.id, base: c.base}
			if st, doc := tb2.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id}); st != 200 || doc["deleted"] != true {
				t.Fatalf("replayed delete: %d %v", st, doc)
			}
			tombs, receipts := 0, map[uint64]int{}
			for _, l := range c2.runs(t) {
				if l.isTombstone() {
					tombs++
				} else {
					receipts[l.Generation]++
				}
			}
			if tombs != 1 || receipts[1] != 1 || receipts[2] != 1 {
				t.Fatalf("vm-runs.jsonl after the replay: %+v", c2.runs(t))
			}
			if len(readHistFile(t, tb2)) != 2 {
				t.Fatalf("history after the replay: %+v", readHistFile(t, tb2))
			}
			if onDiskRecord(t, tb2, c.id) != nil {
				t.Fatal("VM still in vms.json")
			}
			// Repeating once more is not an error that loses data: the VM is gone.
			if st, _ := tb2.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id}); st != 404 {
				t.Fatalf("delete of a gone VM: %d", st)
			}
		})
	}
}

// ---------------------------------------------------------------- B4

// B4: an id with a tombstone or a receipt is never handed out again.
func TestVMHistoryIDsAreNotReused(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	if st, _ := c.tb.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id}); st != 200 {
		t.Fatal("delete")
	}
	tb2 := c.tb.restart(t, false) // the tombstone is read back from disk
	other := "vm-aaaaaaaaaaaa"
	// A receipt without a tombstone (a VM that is not in vms.json) also blocks its id.
	line, _ := json.Marshal(vmRunLine{VM: other, Account: "a", Host: "vmh-a", Generation: 1, StoppedAt: 5, Kind: vmReceiptStop})
	f, err := os.OpenFile(filepath.Join(tb2.b.cfg.StateDir, vmRunsFile), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(append(line, '\n'))
	f.Close()
	tb3 := tb2.restart(t, false)
	ids := []string{c.id, other, c.id, other, "vm-bbbbbbbbbbbb"}
	n := 0
	tb3.b.vms.newID = func() string { n++; return ids[n-1] }
	got := tb3.create(t, nil)["id"]
	if got != "vm-bbbbbbbbbbbb" || n != 5 {
		t.Fatalf("created %v after %d draws", got, n)
	}
}

// ---------------------------------------------------------------- B5

func TestVMHistoryRouteServesTombstonedVMAndErrors(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	get := func(path string) (int, map[string]any) {
		return c.tb.call(t, "operator-key", "GET", path, nil)
	}
	st, doc := get(c.base + "/runs/1")
	hostID := onDiskRecord(t, c.tb, c.id).Host
	want := map[string]any{"vm": c.id, "account": "acct-1", "host": hostID, "generation": float64(1),
		"started_at": histStartedAt, "stopped_at": float64(histStopBase + 1), "close_reason": "stopped",
		"history_id": fmt.Sprintf("%s:1:%s", c.id, hostID)}
	if st != 200 || fmt.Sprint(doc) != fmt.Sprint(want) {
		t.Fatalf("route: %d %v\nwant %v", st, doc, want)
	}
	if st, _ := c.tb.call(t, "", "GET", c.base+"/runs/1", nil); st != 401 {
		t.Fatalf("no key: %d", st)
	}
	if st, _ := c.tb.call(t, "key1", "GET", c.base+"/runs/1", nil); st != 401 {
		t.Fatalf("guest key: %d", st)
	}
	// No receipt: 404, for an unknown generation, an unknown VM and a bad number.
	for _, p := range []string{c.base + "/runs/2", "/v1/broker/vms/vm-ffffffffffff/runs/1", c.base + "/runs/0", c.base + "/runs/x"} {
		if st, doc := get(p); st != 404 {
			t.Fatalf("%s: %d %v", p, st, doc)
		}
	}
	// After delete, the route still answers from vm-history.jsonl.
	if st, _ := c.tb.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id}); st != 200 {
		t.Fatal("delete")
	}
	if st, doc := get(c.base + "/runs/1"); st != 200 || fmt.Sprint(doc) != fmt.Sprint(want) {
		t.Fatalf("route after delete: %d %v", st, doc)
	}
	if st, _ := get(c.base); st != 404 {
		t.Fatalf("the VM itself after delete: %d", st)
	}
}

func TestVMHistoryRoutePendingAnswersFromHostOrErrors(t *testing.T) {
	c := newHistCase(t)
	c.host.set(func(h *histHost) { h.down["history"] = true })
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	path := c.base + "/runs/1"
	get := func() (int, map[string]any) { return c.tb.call(t, "operator-key", "GET", path, nil) }
	if st, doc := get(); st != 502 {
		t.Fatalf("host unreachable: %d %v", st, doc)
	}
	c.host.set(func(h *histHost) { h.down["history"] = false; h.histExit[1] = "open" })
	if st, doc := get(); st != 409 || vmErrCode(doc) != "history_open" {
		t.Fatalf("open: %d %v", st, doc)
	}
	c.host.set(func(h *histHost) { h.histExit[1] = "unknown" })
	if st, doc := get(); st != 409 || vmErrCode(doc) != "history_unknown" {
		t.Fatalf("unknown: %d %v", st, doc)
	}
	c.host.set(func(h *histHost) { delete(h.histExit, 1) })
	st, doc := get() // pending: answered from the host, then stored
	if st != 200 || doc["stopped_at"] != float64(histStopBase+1) || len(readHistFile(t, c.tb)) != 1 {
		t.Fatalf("pending: %d %v", st, doc)
	}
	// A run never started: started_at is null.
	d := newHistCase(t)
	d.run(t)
	d.must(t, "stop", map[string]any{"generation": 1})
	if st, doc := d.tb.call(t, "operator-key", "GET", d.base+"/runs/1", nil); st != 200 || doc["started_at"] == nil {
		t.Fatalf("started: %d %v", st, doc)
	}
}

// ---------------------------------------------------------------- files

func TestVMHistoryTornTailIgnoredAndCorruptLineRefusesStart(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	runs := filepath.Join(c.tb.b.cfg.StateDir, vmRunsFile)
	good, _ := os.ReadFile(runs)
	// A write that never finished: ignored, cut off, and the next append lands clean.
	if err := os.WriteFile(runs, append(append([]byte{}, good...), []byte(`{"vm":"vm-0000`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	tb2 := c.tb.restart(t, false)
	if got, _ := os.ReadFile(runs); !bytes.Equal(got, good) {
		t.Fatalf("torn tail kept: %q", got)
	}
	c2 := &histCase{tb: tb2, host: c.host, id: c.id, base: c.base}
	c2.run(t)
	c2.must(t, "stop", map[string]any{"generation": 2})
	if len(c2.runs(t)) != 2 {
		t.Fatalf("receipts: %+v", c2.runs(t))
	}
	// A bad complete line: the broker does not start with history forgotten.
	if err := os.WriteFile(runs, append([]byte("{not json}\n"), good...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBroker(c.tb.cfg); err == nil || !strings.Contains(err.Error(), vmRunsFile) {
		t.Fatalf("load with a corrupt line: %v", err)
	}
}

// ---------------------------------------------------------------- intents (spec r4)

// An intent line is durable before the host is asked: authorize and close.
func TestVMHistoryIntentsWrittenBeforeHostCalls(t *testing.T) {
	c := newHistCase(t)
	seen := map[string]bool{}
	c.tb.b.vms.exec = execFunc(func(args []string) ([]byte, int, error) {
		for _, l := range readRawRuns(t, c.tb) {
			switch {
			case args[0] == "authorize" && l.Intent == "authorize" && fmt.Sprint(l.Generation) == args[3]:
				seen["authorize"] = true
				if l.Account != "acct-1" || l.Host == "" || l.VM != c.id {
					t.Errorf("authorize intent: %+v", l)
				}
			case args[0] == "stop" && l.Intent == "close" && fmt.Sprint(l.Generation) == args[3]:
				seen["stop"] = true
			case args[0] == "cancel" && l.Intent == "close" && fmt.Sprint(l.Generation) == args[2]:
				seen["cancel"] = true
			}
		}
		return c.host.answer(args)
	})
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.authorize(t, 2)
	c.host.set(func(h *histHost) { h.refuseStop = true })
	c.must(t, "stop", map[string]any{"generation": 2}) // stop refused, then cancel
	for _, k := range []string{"authorize", "stop", "cancel"} {
		if !seen[k] {
			t.Errorf("no intent line was on disk when the host got %s", k)
		}
	}
	// The authorize answer resolved the intent; the receipts resolved the closes.
	raw := readRawRuns(t, c.tb)
	resolved := 0
	for _, l := range raw {
		if l.Resolved == "authorize" && l.Accepted != nil && *l.Accepted {
			resolved++
		}
	}
	if resolved != 2 {
		t.Fatalf("authorize resolutions: %d in %+v", resolved, raw)
	}
}

// A failed intent append answers 500 and the host is never asked.
func TestVMHistoryFailedIntentAppendSendsNothing(t *testing.T) {
	c := newHistCase(t)
	var fails int
	c.tb.b.vms.appendHook = failOn(vmRunsFile, &fails)
	calls := c.tb.host.count()
	st, doc := c.post(t, "authorize", map[string]any{"generation": 1, "paid_through": c.tb.now.Unix() + 300})
	if st != 500 || vmErrCode(doc) != "state_not_saved" || c.host.deleteCalls != 0 {
		t.Fatalf("authorize: %d %v", st, doc)
	}
	c.tb.b.vms.appendHook = nil
	c.run(t)
	c.tb.b.vms.appendHook = failOn(vmRunsFile, &fails)
	if st, doc := c.post(t, "stop", map[string]any{"generation": 1}); st != 500 || vmErrCode(doc) != "state_not_saved" {
		t.Fatalf("stop: %d %v", st, doc)
	}
	_ = calls
	if rec := onDiskRecord(t, c.tb, c.id); rec.DesiredState != vmStateRunning {
		t.Fatalf("a stop nobody recorded changed the state: %+v", rec)
	}
}

// A host refusal of an authorize is an answer: accepted false, no gate.
func TestVMHistoryRefusedAuthorizeIsResolvedNotAccepted(t *testing.T) {
	c := newHistCase(t)
	c.tb.b.vms.exec = execFunc(func(args []string) ([]byte, int, error) {
		if args[0] == "authorize" {
			return []byte(`{"error":"stale_authorization"}`), vmExitStale, nil
		}
		return c.host.answer(args)
	})
	if st, _ := c.post(t, "authorize", map[string]any{"generation": 1, "paid_through": c.tb.now.Unix() + 300}); st != 409 {
		t.Fatal("authorize")
	}
	raw := readRawRuns(t, c.tb)
	if len(raw) != 2 || raw[1].Resolved != "authorize" || raw[1].Accepted == nil || *raw[1].Accepted {
		t.Fatalf("lines: %+v", raw)
	}
	c.tb.b.vms.exec = c.tb.host
	c.run(t) // not gated
	// And delete does not cancel a refused generation that was never the VM's.
	tb2 := c.tb.restart(t, true)
	if len(c.host.cancels) != 0 {
		t.Fatalf("replay fenced a refused authorize: %v", c.host.cancels)
	}
	_ = tb2
}

// Gate: ANY unresolved intent for the VM refuses authorize and start with
// receipt_missing, until the replay settles it.
func TestVMHistoryOpenIntentGatesAuthorizeAndStart(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.authorize(t, 2)
	// A lost authorize reply for generation 3 cannot exist before 2 is closed; use a lost cancel of 2.
	c.host.set(func(h *histHost) { h.down["stop"] = true; h.down["cancel"] = true })
	if st, _ := c.post(t, "stop", map[string]any{"generation": 2}); st != 502 {
		t.Fatal("lost cancel")
	}
	for _, op := range []string{"authorize", "start"} {
		body := map[string]any{"generation": 2, "paid_through": c.tb.now.Unix() + 400}
		if op == "start" {
			body = map[string]any{"generation": 2}
		}
		st, doc := c.post(t, op, body)
		if st != 409 || vmErrCode(doc) != "receipt_missing" {
			t.Fatalf("%s: %d %v", op, st, doc)
		}
	}
	// Restart with the host back: the replay closes G2 through cancel.
	c.host.set(func(h *histHost) { h.down["stop"] = false; h.down["cancel"] = false })
	tb2 := c.tb.restart(t, true)
	c2 := &histCase{tb: tb2, host: c.host, id: c.id, base: c.base}
	if rs := c2.runs(t); len(rs) != 2 || rs[1].Generation != 2 || rs[1].Kind != vmReceiptCancel {
		t.Fatalf("receipts: %+v", rs)
	}
	c2.authorize(t, 3)
	c2.must(t, "start", map[string]any{"generation": 3})
}

// Spec r4 test: a cancel of an authorized G2 (G1 stopped) fails before B1.
// The close intent is on disk; the restart replays it through host cancel and
// moves vms.json to the closed G2.
func TestVMHistoryCancelFailsBeforeReceiptReplaysCloseIntent(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.authorize(t, 2)
	c.tb.b.vms.appendHook = func(name string, line []byte) error {
		if name == vmRunsFile && bytes.Contains(line, []byte(`"stopped_at"`)) {
			return errors.New("disk full") // the receipt, not the intent
		}
		return nil
	}
	if st, doc := c.post(t, "stop", map[string]any{"generation": 2}); st != 500 || vmErrCode(doc) != "state_not_saved" {
		t.Fatalf("cancel: %d %v", st, doc)
	}
	if rec := onDiskRecord(t, c.tb, c.id); rec.Generation != 1 || rec.StoppedAt != histStopBase+1 {
		t.Fatalf("vms.json changed: %+v", rec)
	}
	if len(c.runs(t)) != 1 {
		t.Fatal("a receipt for G2 on disk")
	}
	// The next run is refused while the intent is open.
	if st, doc := c.post(t, "authorize", map[string]any{"generation": 2, "paid_through": c.tb.now.Unix() + 400}); st != 409 || vmErrCode(doc) != "receipt_missing" {
		t.Fatalf("authorize while open: %d %v", st, doc)
	}
	tb2 := c.tb.restart(t, true)
	if rs := readRunsFile(t, tb2); len(rs) != 2 || rs[1].Generation != 2 || rs[1].StoppedAt != histStopBase+2 {
		t.Fatalf("receipts after the replay: %+v", rs)
	}
	if rec := onDiskRecord(t, tb2, c.id); rec.Generation != 2 || rec.StoppedAt != histStopBase+2 {
		t.Fatalf("vms.json after the replay: %+v", rec)
	}
}

// Spec r4 test: a lost authorize reply, then delete. G2 is cancelled and
// recorded before host delete, and B5 serves it.
func TestVMHistoryLostAuthorizeThenDeleteCancelsAndServesG2(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.host.set(func(h *histHost) { h.down["authorize"] = true }) // the reply is lost
	if st, _ := c.post(t, "authorize", map[string]any{"generation": 2, "paid_through": c.tb.now.Unix() + 300}); st != 502 {
		t.Fatal("lost authorize")
	}
	c.host.set(func(h *histHost) { h.down["authorize"] = false })
	if rec := onDiskRecord(t, c.tb, c.id); rec.AuthorizedGeneration != 1 {
		t.Fatalf("the broker recorded an authorize it never saw answered: %+v", rec)
	}
	var seq []string
	c.tb.b.vms.exec = execFunc(func(args []string) ([]byte, int, error) {
		seq = append(seq, args[0])
		return c.host.answer(args)
	})
	if st, doc := c.tb.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id}); st != 200 {
		t.Fatalf("delete: %d %v", st, doc)
	}
	if got := c.host.cancels; len(got) != 1 || got[0] != 2 {
		t.Fatalf("host cancels: %v", got)
	}
	cancelAt, deleteAt := -1, -1
	for i, a := range seq {
		if a == "cancel" && cancelAt < 0 {
			cancelAt = i
		}
		if a == "delete" {
			deleteAt = i
		}
	}
	if cancelAt < 0 || cancelAt > deleteAt {
		t.Fatalf("cancel must precede host delete: %v", seq)
	}
	st, doc := c.tb.call(t, "operator-key", "GET", c.base+"/runs/2", nil)
	if st != 200 || doc["generation"] != float64(2) || doc["stopped_at"] != float64(histCancelBase+2) {
		t.Fatalf("B5 for the fenced G2: %d %v", st, doc)
	}
}

// Each replay step is idempotent: a second replay changes no file and asks the
// host for nothing more.
func TestVMHistoryReplayStepsAreIdempotent(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	// Step 1 state: a receipt vms.json does not show (save failed).
	c.authorize(t, 2)
	c.tb.b.vms.saveHook = func() error { return errors.New("crash") }
	c.post(t, "stop", map[string]any{"generation": 2})
	c.tb.b.vms.saveHook = nil
	// Step 2 state: a close intent with no receipt, for G3 (authorize 3 after adopting 2).
	tb := c.tb.restart(t, true)
	c = &histCase{tb: tb, host: c.host, id: c.id, base: c.base}
	c.authorize(t, 3)
	c.host.set(func(h *histHost) { h.down["stop"], h.down["cancel"] = true, true })
	c.post(t, "stop", map[string]any{"generation": 3}) // 502: intent open
	c.host.set(func(h *histHost) { h.down["stop"], h.down["cancel"] = false, false })
	// Step 3 state: an authorize intent with a lost reply for G4 (after G3 is closed by replay 1).
	files := func(tb *vmTestBroker) string {
		var out strings.Builder
		for _, f := range []string{vmsFile, vmRunsFile, vmHistoryFile} {
			raw, _ := os.ReadFile(filepath.Join(tb.b.cfg.StateDir, f))
			out.WriteString(f + "\n" + string(raw))
		}
		return out.String()
	}
	tb1 := c.tb.restart(t, true) // closes G3 through cancel
	if rec := onDiskRecord(t, tb1, c.id); rec.Generation != 3 {
		t.Fatalf("after replay 1: %+v", rec)
	}
	c1 := &histCase{tb: tb1, host: c.host, id: c.id, base: c.base}
	c.host.set(func(h *histHost) { h.down["authorize"] = true })
	c1.post(t, "authorize", map[string]any{"generation": 4, "paid_through": tb1.now.Unix() + 300})
	c.host.set(func(h *histHost) { h.down["authorize"] = false })
	tb2 := tb1.restart(t, true) // fences G4 through cancel
	if rs := readRunsFile(t, tb2); rs[len(rs)-1].Generation != 4 {
		t.Fatalf("authorize intent not fenced: %+v", rs)
	}
	before, cancels := files(tb2), len(c.host.cancels)
	hist := c.host.histCalls
	tb3 := tb2.restart(t, true)
	tb3.b.vms.replay(context.Background())
	if after := files(tb3); after != before {
		t.Fatalf("a second replay changed the files:\n%s\n---\n%s", before, after)
	}
	if len(c.host.cancels) != cancels || c.host.histCalls != hist {
		t.Fatalf("a second replay called the host: cancels %d->%d history %d->%d", cancels, len(c.host.cancels), hist, c.host.histCalls)
	}
	if rec := onDiskRecord(t, tb3, c.id); rec.Generation != 4 || rec.StoppedAt == 0 {
		t.Fatalf("vms.json: %+v", rec)
	}
}

// A close refused by the host for a run that ran does not leave a gate behind.
func TestVMHistoryRefusedStopOfRunningRunLeavesNoOpenIntent(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.host.set(func(h *histHost) { h.refuseStop = true })
	if st, doc := c.post(t, "stop", map[string]any{"generation": 1}); st != 409 {
		t.Fatalf("stop: %d %v", st, doc)
	}
	c.tb.b.vms.mu.Lock()
	open := c.tb.b.vms.openIntentLocked(c.id)
	c.tb.b.vms.mu.Unlock()
	if open {
		t.Fatal("an answered refusal still gates the VM")
	}
	tb2 := c.tb.restart(t, true) // and a restart does not cancel the live run
	if len(c.host.cancels) != 0 {
		t.Fatalf("replay cancelled a live run: %v", c.host.cancels)
	}
	_ = tb2
}

// ---------------------------------------------------------------- Astra impl r1

// setLegacyStoppedAt rewrites vms.json as an older broker left it: a closed run
// with its own stopped_at, and no receipt or history files.
func setLegacyStoppedAt(t *testing.T, tb *vmTestBroker, id string, at int64) {
	t.Helper()
	path := filepath.Join(tb.b.cfg.StateDir, vmsFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc vmsFileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for i := range doc.VMs {
		if doc.VMs[i].ID == id {
			doc.VMs[i].StoppedAt = at
		}
	}
	raw, _ = json.Marshal(doc)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(tb.b.cfg.StateDir, vmRunsFile))
	os.Remove(filepath.Join(tb.b.cfg.StateDir, vmHistoryFile))
}

// Fix 1 (BLOCKER): G2 was accepted and its resolution is durable; the crash came
// before AuthorizedGeneration=2 was saved. A retry with a lower paid_through is
// refused. The refusal must not erase the acceptance: delete still cancels G2,
// and B5 serves it.
func TestVMHistoryRefusedRetryDoesNotEraseAcceptedGenerationFromDelete(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.tb.b.vms.saveHook = func() error { return errors.New("crash") }
	if st, _ := c.post(t, "authorize", map[string]any{"generation": 2, "paid_through": c.tb.now.Unix() + 600}); st != 500 {
		t.Fatalf("authorize with the save failing: %d", st)
	}
	c.tb.b.vms.saveHook = nil
	tb := c.tb.restart(t, false) // the crash: vms.json never got AuthorizedGeneration=2
	c = &histCase{tb: tb, host: c.host, id: c.id, base: c.base}
	if rec := onDiskRecord(t, tb, c.id); rec.AuthorizedGeneration != 1 {
		t.Fatalf("vms.json: %+v", rec)
	}
	// The retry with a lower paid_through is refused by the host.
	tb.b.vms.exec = execFunc(func(args []string) ([]byte, int, error) {
		if args[0] == "authorize" {
			return []byte(`{"error":"paid_through_lower"}`), vmExitStale, nil
		}
		return c.host.answer(args)
	})
	if st, doc := c.post(t, "authorize", map[string]any{"generation": 2, "paid_through": tb.now.Unix() + 100}); st != 409 {
		t.Fatalf("retry: %d %v", st, doc)
	}
	tb.b.vms.exec = tb.host
	tb2 := tb.restart(t, false) // and it survives another restart
	c2 := &histCase{tb: tb2, host: c.host, id: c.id, base: c.base}
	if st, doc := tb2.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id}); st != 200 {
		t.Fatalf("delete: %d %v", st, doc)
	}
	if got := c.host.cancels; len(got) != 1 || got[0] != 2 {
		t.Fatalf("host cancels: %v, want generation 2 fenced", got)
	}
	if st, doc := tb2.call(t, "operator-key", "GET", c2.base+"/runs/2", nil); st != 200 || doc["generation"] != float64(2) {
		t.Fatalf("B5 for G2: %d %v", st, doc)
	}
}

// Fix 1: the replay at start applies the same rule: an accepted generation
// vms.json never recorded is fenced, whatever a later retry was answered.
func TestVMHistoryReplayFencesAcceptedUnrecordedGeneration(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.tb.b.vms.saveHook = func() error { return errors.New("crash") }
	c.post(t, "authorize", map[string]any{"generation": 2, "paid_through": c.tb.now.Unix() + 600})
	c.tb.b.vms.saveHook = nil
	tb := c.tb.restart(t, false)
	tb.b.vms.exec = execFunc(func(args []string) ([]byte, int, error) {
		if args[0] == "authorize" {
			return []byte(`{"error":"paid_through_lower"}`), vmExitStale, nil
		}
		return c.host.answer(args)
	})
	(&histCase{tb: tb, host: c.host, id: c.id, base: c.base}).post(t, "authorize", map[string]any{"generation": 2, "paid_through": tb.now.Unix() + 100})
	tb.b.vms.exec = tb.host
	tb2 := tb.restart(t, true)
	if got := c.host.cancels; len(got) != 1 || got[0] != 2 {
		t.Fatalf("host cancels: %v", got)
	}
	if rec := onDiskRecord(t, tb2, c.id); rec.Generation != 2 || rec.StoppedAt != histCancelBase+2 {
		t.Fatalf("vms.json: %+v", rec)
	}
}

// Fix 2: a receipt for the record's current generation is applied whatever the
// prior state, at replay and on a GET; never over a newer generation.
func TestVMHistoryReceiptAppliedWhenVMsJSONStillSaysRunning(t *testing.T) {
	for _, op := range []string{"stop", "delete"} {
		for _, via := range []string{"replay", "get"} {
			t.Run(op+" "+via, func(t *testing.T) {
				c := newHistCase(t)
				c.run(t)
				vmsPath := filepath.Join(c.tb.b.cfg.StateDir, vmsFile)
				running, _ := os.ReadFile(vmsPath)
				switch op {
				case "stop":
					c.must(t, "stop", map[string]any{"generation": 1})
					if err := os.WriteFile(vmsPath, running, 0o600); err != nil { // crash: vms.json never saw the stop
						t.Fatal(err)
					}
				case "delete":
					c.tb.b.vms.saveHook = func() error { return errors.New("crash") }
					if st, _ := c.tb.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id}); st == 200 {
						t.Fatal("delete went through")
					}
					c.tb.b.vms.saveHook = nil
				}
				if rec := onDiskRecord(t, c.tb, c.id); rec.DesiredState != vmStateRunning || rec.StoppedAt != 0 {
					t.Fatalf("setup: %+v", rec)
				}
				tb2 := c.tb.restart(t, via == "replay")
				if via == "get" {
					if st, _ := tb2.call(t, "operator-key", "GET", c.base, nil); st != 200 {
						t.Fatal("get")
					}
				}
				want := readRunsFile(t, tb2)[0].StoppedAt
				if rec := onDiskRecord(t, tb2, c.id); rec.DesiredState != vmStateStopped || rec.StoppedAt != want || rec.Generation != 1 {
					t.Fatalf("vms.json after %s: %+v (receipt %d)", via, rec, want)
				}
			})
		}
	}
	// A receipt of an older generation never touches a newer run.
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.run(t)
	tb2 := c.tb.restart(t, true)
	if rec := onDiskRecord(t, tb2, c.id); rec.DesiredState != vmStateRunning || rec.Generation != 2 || rec.StoppedAt != 0 {
		t.Fatalf("a receipt of generation 1 changed run 2: %+v", rec)
	}
}

// Fix 3: a legacy stopped_at that the host's close does not match is a disputed
// run, not a wedge: the host's close is the receipt, the old time stays for
// audit, later runs go on, and B5 answers 409 for that run only.
func TestVMHistoryLegacyMismatchIsDisputedNotWedged(t *testing.T) {
	for _, via := range []string{"replay", "repeated stop"} {
		t.Run(via, func(t *testing.T) {
			c := newHistCase(t)
			c.run(t)
			c.must(t, "stop", map[string]any{"generation": 1})
			legacy := int64(histStopBase + 1 + 4000)
			setLegacyStoppedAt(t, c.tb, c.id, legacy)
			tb := c.tb.restart(t, via == "replay")
			c = &histCase{tb: tb, host: c.host, id: c.id, base: c.base}
			if via == "repeated stop" {
				if st, doc := c.post(t, "stop", map[string]any{"generation": 1}); st != 200 || doc["stopped_at"] != float64(histStopBase+1) {
					t.Fatalf("repeated stop: %d %v", st, doc)
				}
			}
			rs := c.runs(t)
			if len(rs) != 1 || !rs[0].Disputed || rs[0].StoppedAt != histStopBase+1 {
				t.Fatalf("receipt: %+v", rs)
			}
			rec := onDiskRecord(t, tb, c.id)
			if rec.LegacyStoppedAt != legacy || rec.StoppedAt != histStopBase+1 {
				t.Fatalf("record: %+v", rec)
			}
			// Later generations are allowed.
			c.authorize(t, 2)
			c.must(t, "start", map[string]any{"generation": 2})
			c.must(t, "stop", map[string]any{"generation": 2})
			// B5: 409 for the disputed run, 200 for the next.
			st, doc := tb.call(t, "operator-key", "GET", c.base+"/runs/1", nil)
			if st != 409 || vmErrCode(doc) != "vm_receipt_mismatch" {
				t.Fatalf("/runs/1: %d %v", st, doc)
			}
			if st, doc := tb.call(t, "operator-key", "GET", c.base+"/runs/2", nil); st != 200 {
				t.Fatalf("/runs/2: %d %v", st, doc)
			}
			// It stays disputed across a restart.
			tb2 := tb.restart(t, true)
			if st, doc := tb2.call(t, "operator-key", "GET", c.base+"/runs/1", nil); st != 409 || vmErrCode(doc) != "vm_receipt_mismatch" {
				t.Fatalf("/runs/1 after restart: %d %v", st, doc)
			}
		})
	}
}

// Fix 4: a dir fsync that fails after the file fsync leaves the line on disk.
// The retry must not write it again, and the answer is the same before and
// after a restart.
func TestVMHistoryDirFsyncFailureDoesNotDuplicateJournalLines(t *testing.T) {
	for _, journal := range []string{vmRunsFile, vmHistoryFile} {
		t.Run(journal, func(t *testing.T) {
			c := newHistCase(t)
			c.run(t)
			armed := false
			failed := 0
			cmd := "stop"
			if journal == vmHistoryFile {
				cmd = "history"
			}
			c.tb.b.vms.exec = execFunc(func(args []string) ([]byte, int, error) {
				if args[0] == cmd && failed == 0 {
					armed = true // the next dir fsync is the journal's own
				}
				return c.host.answer(args)
			})
			orig := durableSync
			defer func() { durableSync = orig }()
			durableSync = func(f *os.File) error {
				if st, err := f.Stat(); err == nil && st.IsDir() && armed {
					armed = false
					failed++
					return errors.New("dir fsync failed")
				}
				return orig(f)
			}
			stopAt := float64(histStopBase + 1)
			st, doc := c.post(t, "stop", map[string]any{"generation": 1})
			if journal == vmRunsFile {
				if st != 500 || failed != 1 {
					t.Fatalf("stop with a failing dir fsync: %d %v failed=%d", st, doc, failed)
				}
				if st, doc = c.post(t, "stop", map[string]any{"generation": 1}); st != 200 || doc["stopped_at"] != stopAt {
					t.Fatalf("retry: %d %v", st, doc)
				}
			} else if st != 200 || failed != 1 { // history never fails the Stop
				t.Fatalf("stop: %d %v failed=%d", st, doc, failed)
			}
			before := map[string]any{}
			_, before = c.tb.call(t, "operator-key", "GET", c.base+"/runs/1", nil)
			if before["stopped_at"] != stopAt {
				t.Fatalf("route: %v", before)
			}
			count := func(tb *vmTestBroker) (receipts, hist int) {
				return len(readRunsFile(t, tb)), len(readHistFile(t, tb))
			}
			if r, h := count(c.tb); r != 1 || h != 1 {
				t.Fatalf("lines: %d receipts, %d history (want 1 and 1)", r, h)
			}
			tb2 := c.tb.restart(t, true)
			_, after := tb2.call(t, "operator-key", "GET", c.base+"/runs/1", nil)
			if fmt.Sprint(before) != fmt.Sprint(after) {
				t.Fatalf("answer changed over a restart:\n%v\n%v", before, after)
			}
			if r, h := count(tb2); r != 1 || h != 1 {
				t.Fatalf("lines after restart: %d receipts, %d history", r, h)
			}
		})
	}
}

// P1 (SpockChaser HOLD): a history answer that leaves out started_at is not the
// same as an explicit null. It must never be stored, or served as a never-started
// run (a full refund).
func TestVMHistoryMissingMembersAreRefusedNotStoredAsNull(t *testing.T) {
	const ts = `"2030-03-17T17:46:39.500000Z"`
	body := func(members string) string {
		return `{"closed":true,"tracked_from":1,"close_reason":"stopped","history":"v2",` + members + `}`
	}
	stopped := fmt.Sprint(histStopBase + 1)
	c := newHistCase(t)
	c.run(t)
	cases := []struct {
		name, raw string
	}{
		{"started_at omitted", body(`"generation":1,"stopped_at":` + stopped + `,"started_at_error_us":1500`)},
		{"started_at boolean", body(`"generation":1,"stopped_at":` + stopped + `,"started_at":false`)},
		{"started_at_error_us omitted", body(`"generation":1,"stopped_at":` + stopped + `,"started_at":` + ts)},
		{"started_at_error_us wrong type", body(`"generation":1,"stopped_at":` + stopped + `,"started_at":` + ts + `,"started_at_error_us":"1500"`)},
		{"stopped_at omitted", body(`"generation":1,"started_at":` + ts + `,"started_at_error_us":1500`)},
		{"generation omitted", body(`"stopped_at":` + stopped + `,"started_at":` + ts + `,"started_at_error_us":1500`)},
	}
	for _, tc := range cases {
		c.host.set(func(h *histHost) { h.histRaw[1] = tc.raw })
		if tc.name == cases[0].name {
			// Through the real routes: Stop with a bad history still answers 200.
			c.must(t, "stop", map[string]any{"generation": 1})
		}
		st, doc := c.tb.call(t, "operator-key", "GET", c.base+"/runs/1", nil)
		if st != 502 || vmErrCode(doc) != "history_invalid" {
			t.Fatalf("%s: %d %v", tc.name, st, doc)
		}
		if n := len(readHistFile(t, c.tb)); n != 0 {
			t.Fatalf("%s: %d durable history rows", tc.name, n)
		}
	}
	// A valid answer after a restart: the real start time, not a cached null.
	c.host.set(func(h *histHost) { delete(h.histRaw, 1) })
	tb2 := c.tb.restart(t, true)
	st, doc := tb2.call(t, "operator-key", "GET", c.base+"/runs/1", nil)
	if st != 200 || doc["started_at"] != histStartedAt {
		t.Fatalf("after restart: %d %v", st, doc)
	}
	// Controls: an explicit null is the certified never-started case.
	d := newHistCase(t)
	d.run(t)
	d.host.set(func(h *histHost) {
		h.histRaw[1] = body(`"generation":1,"stopped_at":` + stopped + `,"started_at":null`)
	})
	d.must(t, "stop", map[string]any{"generation": 1})
	st, doc = d.tb.call(t, "operator-key", "GET", d.base+"/runs/1", nil)
	if v, present := doc["started_at"]; st != 200 || !present || v != nil {
		t.Fatalf("explicit null: %d %v", st, doc)
	}
	if n := len(readHistFile(t, d.tb)); n != 1 {
		t.Fatalf("explicit null rows: %d", n)
	}
}

// ---------------------------------------------------------------- Astra impl r2

// Fix r2-1: a receipt line that a failed append left on disk must not be
// published, or acknowledged by a repeated stop, while the re-sync still fails.
func TestVMHistoryFailedResyncDoesNotPublishUnconfirmedReceipt(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	armed, failing, fired := false, false, false
	c.tb.b.vms.exec = execFunc(func(args []string) ([]byte, int, error) {
		if args[0] == "stop" && !fired {
			fired, armed = true, true // the next dir fsync is the receipt's own
		}
		return c.host.answer(args)
	})
	orig := durableSync
	defer func() { durableSync = orig }()
	durableSync = func(f *os.File) error {
		if st, err := f.Stat(); err == nil && st.IsDir() && (armed || failing) {
			armed, failing = false, true
			return errors.New("dir fsync failed")
		}
		return orig(f)
	}
	if st, doc := c.post(t, "stop", map[string]any{"generation": 1}); st != 500 {
		t.Fatalf("stop with a failing dir fsync: %d %v", st, doc)
	}
	// GET reconciliation re-syncs, and the sync fails again.
	c.tb.call(t, "operator-key", "GET", c.base, nil)
	if _, ok := c.tb.b.vms.receipts[vmRunKey{c.id, 1}]; ok {
		t.Fatal("an unconfirmed receipt was published to memory")
	}
	if st, doc := c.post(t, "stop", map[string]any{"generation": 1}); st != 500 {
		t.Fatalf("repeated stop acknowledged an unsynced receipt: %d %v", st, doc)
	}
	failing = false
	if st, doc := c.post(t, "stop", map[string]any{"generation": 1}); st != 200 || doc["stopped_at"] != float64(histStopBase+1) {
		t.Fatalf("repeated stop once the disk works: %d %v", st, doc)
	}
	if rs := c.runs(t); len(rs) != 1 {
		t.Fatalf("receipts: %+v", rs)
	}
}

// Fix r2-2: delete closes a legacy run through the same dispute rule as a stop
// or a replay: disputed receipt, stored time kept for audit, B5 answers 409.
func TestVMHistoryDeleteDisputesLegacyStoredTime(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	legacy := int64(histStopBase + 1 + 4000)
	setLegacyStoppedAt(t, c.tb, c.id, legacy)
	c.tb = c.tb.restart(t, false) // the host was unreachable at startup
	del := func() (int, map[string]any) {
		return c.tb.call(t, "operator-key", "DELETE", c.base, map[string]any{"confirm": c.id})
	}
	c.host.set(func(h *histHost) { h.down["history"] = true })
	if st, doc := del(); st != 409 || vmErrCode(doc) != "history_not_stored" {
		t.Fatalf("delete with history pending: %d %v", st, doc)
	}
	rs := c.runs(t)
	if len(rs) != 1 || !rs[0].Disputed || rs[0].StoppedAt != histStopBase+1 {
		t.Fatalf("receipt: %+v", rs)
	}
	if rec := onDiskRecord(t, c.tb, c.id); rec.LegacyStoppedAt != legacy || rec.StoppedAt != histStopBase+1 {
		t.Fatalf("record: %+v", rec)
	}
	c.host.set(func(h *histHost) { h.down["history"] = false })
	if st, doc := del(); st != 200 {
		t.Fatalf("delete: %d %v", st, doc)
	}
	if st, doc := c.tb.call(t, "operator-key", "GET", c.base+"/runs/1", nil); st != 409 || vmErrCode(doc) != "vm_receipt_mismatch" {
		t.Fatalf("/runs/1 after delete: %d %v", st, doc)
	}
}

// Fix r2-3: a disputed receipt is on disk but the crash came before vms.json
// took the canonical time. Adoption keeps the stored time for audit, copies the
// canonical one forward, and repeats change nothing.
func TestVMHistoryDisputedReceiptRepairsInterruptedStateUpdate(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	legacy := int64(histStopBase + 1 + 4000)
	setLegacyStoppedAt(t, c.tb, c.id, legacy)
	tb := c.tb.restart(t, true) // disputed receipt written, vms.json repaired
	c = &histCase{tb: tb, host: c.host, id: c.id, base: c.base}
	// Undo the vms.json half, as a crash before its save would leave it.
	path := filepath.Join(tb.b.cfg.StateDir, vmsFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc vmsFileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for i := range doc.VMs {
		if doc.VMs[i].ID == c.id {
			doc.VMs[i].StoppedAt, doc.VMs[i].LegacyStoppedAt = legacy, 0
		}
	}
	raw, _ = json.Marshal(doc)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // the second pass must change nothing
		tb = tb.restart(t, true)
		c = &histCase{tb: tb, host: c.host, id: c.id, base: c.base}
		if rec := onDiskRecord(t, tb, c.id); rec.LegacyStoppedAt != legacy || rec.StoppedAt != histStopBase+1 {
			t.Fatalf("pass %d record: %+v", i, rec)
		}
	}
	if st, doc := c.post(t, "stop", map[string]any{"generation": 1}); st != 200 || doc["stopped_at"] != float64(histStopBase+1) {
		t.Fatalf("repeated stop: %d %v", st, doc)
	}
	if st, d := tb.call(t, "operator-key", "GET", c.base+"/runs/1", nil); st != 409 {
		t.Fatalf("/runs/1: %d %v", st, d)
	}
}

// ---------------------------------------------------------------- Bugbot r1

// Bugbot "Start ignores existing cancel receipt": a cancel of the authorized,
// unstarted G2 wrote its receipt, then the vms.json save failed and memory
// rolled back to G1 stopped with G2 authorized. vm-runs.jsonl already closes
// G2, so neither a start nor an authorize of G2 may reach the host: not in this
// process, and not after a restart before the replay copied the receipt forward.
func TestVMHistoryStartRefusesGenerationClosedInJournal(t *testing.T) {
	c := newHistCase(t)
	c.run(t)
	c.must(t, "stop", map[string]any{"generation": 1})
	c.authorize(t, 2)
	c.tb.b.vms.saveHook = func() error { return errors.New("crash") }
	if st, doc := c.post(t, "stop", map[string]any{"generation": 2}); st != 500 {
		t.Fatalf("cancel: %d %v", st, doc)
	}
	c.tb.b.vms.saveHook = nil
	if rs := c.runs(t); len(rs) != 2 || rs[1].Generation != 2 {
		t.Fatalf("receipts: %+v", rs)
	}
	refused := func(c *histCase) {
		t.Helper()
		starts := len(c.tb.host.calls)
		if st, doc := c.post(t, "start", map[string]any{"generation": 2}); st != 409 || vmErrCode(doc) != "generation_closed" {
			t.Fatalf("start of the closed G2: %d %v", st, doc)
		}
		if st, doc := c.post(t, "authorize", map[string]any{"generation": 2, "paid_through": c.tb.now.Unix() + 600}); st != 409 || vmErrCode(doc) != "generation_closed" {
			t.Fatalf("authorize of the closed G2: %d %v", st, doc)
		}
		if got := c.tb.host.calls[starts:]; len(got) != 0 {
			t.Fatalf("host calls for a closed generation: %v", got)
		}
	}
	refused(c)
	// A restart whose replay has not reached the VM yet: the same refusal.
	tb2 := c.tb.restart(t, false)
	c2 := &histCase{tb: tb2, host: c.host, id: c.id, base: c.base}
	if rec := onDiskRecord(t, tb2, c.id); rec.Generation != 1 || rec.AuthorizedGeneration != 2 {
		t.Fatalf("vms.json should still lag the journal: %+v", rec)
	}
	refused(c2)
	// The replay copies the receipt forward; the next run is G3.
	tb2.b.vms.replay(context.Background())
	if rec := onDiskRecord(t, tb2, c.id); rec.Generation != 2 || rec.StoppedAt != histStopBase+2 {
		t.Fatalf("after the replay: %+v", rec)
	}
	c2.authorize(t, 3)
	c2.must(t, "start", map[string]any{"generation": 3})
}
