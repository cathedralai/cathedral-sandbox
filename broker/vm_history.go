// Execution history of VM runs for billing settlement (AB#992,
// docs/VM_EXECUTION_HISTORY.md, broker section B0 to B5).
//
// Two append-only files in the state dir, each line fsynced together with the
// dir before anything depends on it:
//
//	vm-runs.jsonl     one receipt per closed generation
//	                  {"vm","account","host","generation","stopped_at","kind"}
//	                  and one tombstone per deleted VM
//	                  {"vm","account","host","deleted_at"}
//	                  Before the broker sends a host authorize or close of
//	                  (vm, G) it appends an intent
//	                  {"intent":"authorize"|"close","vm","account","host","generation"}.
//	                  A receipt for G resolves a close intent (and fences an
//	                  authorize intent); an authorize answer resolves an
//	                  authorize intent with
//	                  {"resolved":"authorize","vm","generation","accepted"}.
//	                  Replay at broker start closes every intent left open
//	                  through host cancel, so a lost reply never leaves an
//	                  open, unrecorded generation on the host.
//	vm-history.jsonl  the host's closed history answer, keyed by (vm, generation)
//
// The broker never makes up a stop time. A host refusal of a stop is settled
// by asking the host to cancel that generation, and the host's close record is
// the only source of stopped_at. A receipt is durable before vms.json shows
// the stop and before the 200.
//
//	GET /v1/broker/vms/{id}/runs/{generation}   the history of one closed run
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	vmRunsFile    = "vm-runs.jsonl"
	vmHistoryFile = "vm-history.jsonl"

	vmReceiptStop   = "stop"   // closed by the host's stop of a run
	vmReceiptCancel = "cancel" // closed by the host's cancel (never started, or a refused stop)

	vmHistoryCallTimeout = 15 * time.Second
	vmCancelCallTimeout  = 2 * time.Minute
)

type vmRunKey struct {
	vm  string
	gen uint64
}

// vmRunLine is one line of vm-runs.jsonl: a receipt (generation and
// stopped_at set) or a tombstone (deleted_at set).
type vmRunLine struct {
	Intent     string `json:"intent,omitempty"`   // "authorize" or "close": sent to the host next
	Resolved   string `json:"resolved,omitempty"` // "authorize": the host's answer is known
	VM         string `json:"vm"`
	Account    string `json:"account,omitempty"`
	Host       string `json:"host,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	Accepted   *bool  `json:"accepted,omitempty"`
	StoppedAt  int64  `json:"stopped_at,omitempty"`
	Kind       string `json:"kind,omitempty"`
	// Disputed: vms.json held another stopped_at for this run than the host's
	// close (an older broker's own clock). The receipt is the host's close;
	// B5 answers 409 vm_receipt_mismatch so settlement stays pending.
	Disputed  bool  `json:"disputed,omitempty"`
	DeletedAt int64 `json:"deleted_at,omitempty"`
}

func (l vmRunLine) isTombstone() bool { return l.DeletedAt != 0 }
func (l vmRunLine) isReceipt() bool {
	return l.Intent == "" && l.Resolved == "" && l.DeletedAt == 0
}

// vmHistoryLine is one line of vm-history.jsonl: the host's closed answer.
type vmHistoryLine struct {
	VM               string  `json:"vm"`
	Generation       uint64  `json:"generation"`
	StartedAt        *string `json:"started_at"` // ISO 8601 with microseconds and Z, or null: never started
	StoppedAt        int64   `json:"stopped_at"`
	StartedAtErrorUS *int64  `json:"started_at_error_us,omitempty"`
	TrackedFrom      uint64  `json:"tracked_from"`
	CloseReason      string  `json:"close_reason"`
	History          string  `json:"history"`
}

var vmStartedAtRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$`)

// ---------------------------------------------------------------- files

// appendJSONL appends one line and makes it durable: fsync of the file, then
// of the dir. Any failure after the write began marks the journal dirty: the
// line may be on disk although the caller is told it failed. The next
// settleLocked reloads the journal from disk, so a retry never writes a line
// that is already there.
func (s *vmStore) appendJSONL(name string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if s.appendHook != nil {
		if err := s.appendHook(name, raw); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(s.dir, name), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	s.dirty[name] = true // cleared once the line is known durable
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := durableSync(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := syncDir(s.dir); err != nil {
		return err
	}
	delete(s.dirty, name)
	return nil
}

// settleLocked makes a journal trustworthy again after a failed append: it is
// reloaded from disk with the startup rules (a torn tail is cut, the first
// entry wins), memory is replaced by what the file holds, and the file and the
// dir are fsynced again. Caller holds s.mu.
func (s *vmStore) settleLocked(name string) error {
	if !s.dirty[name] {
		return nil
	}
	var err error
	if name == vmRunsFile {
		err = s.loadRunsFile()
	} else {
		err = s.loadHistFile()
	}
	if err != nil {
		return err
	}
	if f, err := os.OpenFile(filepath.Join(s.dir, name), os.O_RDONLY, 0); err == nil {
		serr := durableSync(f)
		f.Close()
		if serr != nil {
			return serr
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := syncDir(s.dir); err != nil {
		return err
	}
	delete(s.dirty, name)
	return nil
}

// readJSONL calls fn for each complete line. A final line without a newline
// is a write that never finished (nothing depended on it): it is cut off. Any
// other bad line is an error, so the broker never starts with history forgotten.
func readJSONL(path string, fn func(line []byte) error) error {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if n := len(raw); n > 0 && raw[n-1] != '\n' {
		keep := bytes.LastIndexByte(raw, '\n') + 1
		log.Printf("vms: %s ends with an unfinished line; dropping it", filepath.Base(path))
		if err := os.Truncate(path, int64(keep)); err != nil {
			return err
		}
		raw = raw[:keep]
	}
	for i, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if err := fn(line); err != nil {
			return fmt.Errorf("%s line %d: %w", filepath.Base(path), i+1, err)
		}
	}
	return nil
}

func decodeVMLine(line []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		return errors.New("not one JSON object with only the known fields")
	}
	return nil
}

// loadRuns reads both files into memory. Called by loadVMs.
func (s *vmStore) loadRuns() error {
	s.dirty = map[string]bool{}
	if err := s.loadRunsFile(); err != nil {
		return err
	}
	return s.loadHistFile()
}

// loadRunsFile reads vm-runs.jsonl into memory, replacing what was there. On
// an error memory is left as it was.
func (s *vmStore) loadRunsFile() (err error) {
	oldR, oldT, oldC, oldA, oldRes, oldAcc, oldRef := s.receipts, s.tombs, s.closeIntents, s.authIntents, s.authRes, s.authAccepted, s.closeRefused
	defer func() {
		if err != nil {
			s.receipts, s.tombs, s.closeIntents, s.authIntents, s.authRes, s.authAccepted, s.closeRefused = oldR, oldT, oldC, oldA, oldRes, oldAcc, oldRef
		}
	}()
	s.receipts, s.tombs = map[vmRunKey]vmRunLine{}, map[string]vmRunLine{}
	s.closeIntents, s.authIntents = map[vmRunKey]vmRunLine{}, map[vmRunKey]vmRunLine{}
	s.authRes, s.authAccepted, s.closeRefused = map[vmRunKey]bool{}, map[vmRunKey]bool{}, map[vmRunKey]bool{}
	return readJSONL(filepath.Join(s.dir, vmRunsFile), func(line []byte) error {
		var l vmRunLine
		if err := decodeVMLine(line, &l); err != nil {
			return err
		}
		if !vmIDRE.MatchString(l.VM) {
			return fmt.Errorf("bad vm %q", l.VM)
		}
		switch {
		case l.Intent != "":
			if (l.Intent != "authorize" && l.Intent != "close") || l.Generation < 1 || l.Resolved != "" || l.Accepted != nil || l.StoppedAt != 0 || l.DeletedAt != 0 {
				return errors.New("bad intent")
			}
			k := vmRunKey{l.VM, l.Generation}
			if l.Intent == "close" {
				s.closeIntents[k] = l
				delete(s.closeRefused, k)
			} else {
				s.authIntents[k] = l
				delete(s.authRes, k) // a newer dispatch is open again
			}
			return nil
		case l.Resolved != "":
			if (l.Resolved != "authorize" && l.Resolved != "close") || l.Generation < 1 || l.Accepted == nil || l.StoppedAt != 0 || l.DeletedAt != 0 {
				return errors.New("bad resolution")
			}
			k := vmRunKey{l.VM, l.Generation}
			if l.Resolved == "close" {
				if *l.Accepted {
					return errors.New("a close is resolved by its receipt, only a refusal has a line")
				}
				s.closeRefused[k] = true
			} else {
				s.authRes[k] = *l.Accepted
				if *l.Accepted {
					s.authAccepted[k] = true // sticky: no later refusal erases it
				}
			}
			return nil
		}
		if l.isTombstone() {
			if l.Generation != 0 || l.StoppedAt != 0 {
				return errors.New("a tombstone with receipt fields")
			}
			s.tombs[l.VM] = l
			return nil
		}
		if l.Generation < 1 || l.StoppedAt <= 0 || (l.Kind != vmReceiptStop && l.Kind != vmReceiptCancel) {
			return errors.New("bad receipt")
		}
		k := vmRunKey{l.VM, l.Generation}
		if old, dup := s.receipts[k]; dup {
			if old.StoppedAt != l.StoppedAt {
				return fmt.Errorf("two stopped_at for %s generation %d", l.VM, l.Generation)
			}
			return nil // first entry wins
		}
		s.receipts[k] = l
		return nil
	})
}

// loadHistFile reads vm-history.jsonl into memory, first entry per key wins.
func (s *vmStore) loadHistFile() error {
	old := s.hist
	s.hist = map[vmRunKey]vmHistoryLine{}
	err := readJSONL(filepath.Join(s.dir, vmHistoryFile), func(line []byte) error {
		var l vmHistoryLine
		if err := decodeVMLine(line, &l); err != nil {
			return err
		}
		k := vmRunKey{l.VM, l.Generation}
		if !vmIDRE.MatchString(l.VM) || l.Generation < 1 {
			return errors.New("bad history key")
		}
		if _, dup := s.hist[k]; !dup { // first line wins, never overwritten
			s.hist[k] = l
		}
		return nil
	})
	if err != nil {
		s.hist = old
	}
	return err
}

// appendCloseIntentLocked records that the broker is about to ask the host to
// close (vm, gen). Idempotent; a receipt already resolves it. Caller holds s.mu.
func (s *vmStore) appendCloseIntentLocked(vm, account, host string, gen uint64) error {
	if err := s.settleLocked(vmRunsFile); err != nil {
		return err
	}
	k := vmRunKey{vm, gen}
	if _, ok := s.receipts[k]; ok {
		return nil
	}
	if _, ok := s.closeIntents[k]; ok && !s.closeRefused[k] {
		return nil
	}
	l := vmRunLine{Intent: "close", VM: vm, Account: account, Host: host, Generation: gen}
	if err := s.appendJSONL(vmRunsFile, l); err != nil {
		log.Printf("vms: %s: close intent of %s generation %d not written: %v", vmRunsFile, vm, gen, err)
		return err
	}
	s.closeIntents[k] = l
	delete(s.closeRefused, k)
	return nil
}

// refuseCloseLocked records that the host refused the close and the run stays
// as it was (a stop of a generation the host does not hold, for a run that
// ran). The intent is answered, so it no longer blocks the next authorize.
// This line is an addition to the spec's intent lines.
func (s *vmStore) refuseCloseLocked(vm string, gen uint64) {
	if err := s.settleLocked(vmRunsFile); err != nil {
		return
	}
	k := vmRunKey{vm, gen}
	if _, ok := s.closeIntents[k]; !ok || s.closeRefused[k] {
		return
	}
	if _, done := s.receipts[k]; done {
		return
	}
	no := false
	if err := s.appendJSONL(vmRunsFile, vmRunLine{Resolved: "close", VM: vm, Generation: gen, Accepted: &no}); err != nil {
		log.Printf("vms: %s: refused close of %s generation %d not recorded: %v", vmRunsFile, vm, gen, err)
		return // stays open: conservative
	}
	s.closeRefused[k] = true
}

// appendAuthIntentLocked records that the broker is about to send a host
// authorize of a new generation. It answers fresh=true when this call wrote
// the intent. A generation already outstanding (an open intent, or one the host
// accepted and no receipt closed yet) gets no new line: a later answer to a
// retry must never erase what an earlier attempt may have done.
func (s *vmStore) appendAuthIntentLocked(vm, account, host string, gen uint64) (fresh bool, err error) {
	if err := s.settleLocked(vmRunsFile); err != nil {
		return false, err
	}
	k := vmRunKey{vm, gen}
	if s.authOutstandingLocked(k) {
		return false, nil
	}
	l := vmRunLine{Intent: "authorize", VM: vm, Account: account, Host: host, Generation: gen}
	if err := s.appendJSONL(vmRunsFile, l); err != nil {
		log.Printf("vms: %s: authorize intent of %s generation %d not written: %v", vmRunsFile, vm, gen, err)
		return false, err
	}
	s.authIntents[k] = l
	delete(s.authRes, k)
	return true, nil
}

// resolveAuthLocked records the host's answer to an authorize. An acceptance
// is final. A refusal is written only when this call wrote the intent (fresh):
// a refused retry says nothing about an earlier attempt whose answer was lost
// or accepted, so it never erases it.
func (s *vmStore) resolveAuthLocked(vm string, gen uint64, accepted, fresh bool) error {
	if err := s.settleLocked(vmRunsFile); err != nil {
		return err
	}
	k := vmRunKey{vm, gen}
	if _, ok := s.authIntents[k]; !ok {
		return nil // a refresh of a tracked generation had no intent
	}
	if !accepted && !fresh {
		return nil
	}
	if !s.authUnresolvedLocked(k) {
		return nil
	}
	l := vmRunLine{Resolved: "authorize", VM: vm, Generation: gen, Accepted: &accepted}
	if err := s.appendJSONL(vmRunsFile, l); err != nil {
		log.Printf("vms: %s: authorize resolution of %s generation %d not written: %v", vmRunsFile, vm, gen, err)
		return err
	}
	s.authRes[k] = accepted
	if accepted {
		s.authAccepted[k] = true
	}
	return nil
}

// authOutstandingLocked: an authorize was dispatched for k and no receipt
// closes it yet, unless the host refused it on a fresh dispatch. Open intents
// and accepted ones both count: only a receipt retires them.
func (s *vmStore) authOutstandingLocked(k vmRunKey) bool {
	if _, ok := s.authIntents[k]; !ok {
		return false
	}
	if _, closed := s.receipts[k]; closed {
		return false
	}
	return s.authAccepted[k] || s.authUnresolvedLocked(k)
}

// authUnresolvedLocked: an authorize intent with no answer and no receipt (a
// receipt closes and fences the generation).
func (s *vmStore) authUnresolvedLocked(k vmRunKey) bool {
	if _, ok := s.authIntents[k]; !ok {
		return false
	}
	if _, ok := s.authRes[k]; ok {
		return false
	}
	_, closed := s.receipts[k]
	return !closed
}

// unresolvedGensLocked lists the generations of vm with an intent still open.
func (s *vmStore) unresolvedGensLocked(vm string) (closes, auths []uint64) {
	for k := range s.closeIntents {
		if _, done := s.receipts[k]; k.vm == vm && !done && !s.closeRefused[k] {
			closes = append(closes, k.gen)
		}
	}
	for k := range s.authIntents {
		if k.vm == vm && s.authUnresolvedLocked(k) {
			auths = append(auths, k.gen)
		}
	}
	sort.Slice(closes, func(i, j int) bool { return closes[i] < closes[j] })
	sort.Slice(auths, func(i, j int) bool { return auths[i] < auths[j] })
	return
}

// openIntentLocked: any intent of vm is unresolved (the receipt_missing gate).
func (s *vmStore) openIntentLocked(vm string) bool {
	_ = s.settleLocked(vmRunsFile)
	c, a := s.unresolvedGensLocked(vm)
	return len(c)+len(a) > 0
}

// idUsedLocked: the id is in vm-runs.jsonl as a receipt or a tombstone (B4).
func (s *vmStore) idUsedLocked(id string) bool {
	if _, ok := s.tombs[id]; ok {
		return true
	}
	for k := range s.receipts {
		if k.vm == id {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- receipts (B0, B1)

var errReceiptMismatch = errors.New("a receipt with another stopped_at is on record")

// appendReceiptLocked makes the B1 receipt durable. The same receipt again is
// a no-op; one with another stopped_at is refused and never overwritten.
// Caller holds s.mu.
func (s *vmStore) appendReceiptLocked(vm, account, host string, gen uint64, at int64, kind string, disputed bool) error {
	if err := s.settleLocked(vmRunsFile); err != nil {
		return err
	}
	k := vmRunKey{vm, gen}
	if old, ok := s.receipts[k]; ok {
		if old.StoppedAt == at {
			return nil
		}
		log.Printf("vms: %s generation %d: host close at %d, receipt on record at %d; refused", vm, gen, at, old.StoppedAt)
		return errReceiptMismatch
	}
	l := vmRunLine{VM: vm, Account: account, Host: host, Generation: gen, StoppedAt: at, Kind: kind, Disputed: disputed}
	if err := s.appendJSONL(vmRunsFile, l); err != nil {
		log.Printf("vms: %s not written for %s generation %d: %v", vmRunsFile, vm, gen, err)
		return err
	}
	s.receipts[k] = l
	return nil
}

// receiptErr answers a failed receipt append.
func receiptErr(w http.ResponseWriter, err error) {
	if errors.Is(err, errReceiptMismatch) {
		writeErr(w, 409, "vm_receipt_mismatch", "the host's close of this run differs from the receipt on record; not changed")
		return
	}
	writeErr(w, 500, "state_not_saved", "the host closed the run but the broker could not record the receipt; repeat the stop")
}

// hostCancel asks the host to close generation gen and answers its close
// record's stopped_at. Idempotent on the host: a repeat returns the same record.
func (s *vmStore) hostCancel(ctx context.Context, h vmHostConfig, id string, gen uint64) (int64, *vmCallErr) {
	doc, cerr := s.call(ctx, h, vmCancelCallTimeout, nil, "cancel", id, strconv.FormatUint(gen, 10))
	if cerr != nil {
		if cerr.code == "stale_authorization" { // exit 3: not a staleness question for cancel
			cerr = &vmCallErr{502, "vm_host_refused", "the VM host refused to cancel this generation", false}
		}
		return 0, cerr
	}
	if g, present := doc["generation"]; present {
		if gf, ok := g.(float64); !ok || gf != float64(gen) {
			return 0, &vmCallErr{502, "vm_host_bad_answer", "the host's cancel answer is for another generation", false}
		}
	}
	at, ok := vmUnixField(doc["stopped_at"])
	if !ok {
		return 0, &vmCallErr{502, "vm_host_bad_answer", "the host's cancel answer has no stopped_at", false}
	}
	return at, nil
}

// finishClose finishes a close the host has confirmed: B1 receipt, vms.json,
// then B2 and the 200. Caller holds s.mu and the VM's busy mark; both are
// released here. apply moves the record to its closed state; rollback undoes
// it in memory when vms.json cannot be saved (a stop keeps it: the receipt is
// on disk and a repeated stop re-saves).
func (s *vmStore) finishClose(ctx context.Context, w http.ResponseWriter, rec *vmRecord, gen uint64, at int64, kind string, disputed bool, apply func(*vmRecord), rollback bool) {
	id := rec.ID
	if err := s.appendReceiptLocked(rec.ID, rec.Account, rec.Host, gen, at, kind, disputed); err != nil {
		delete(s.busy, id)
		s.mu.Unlock()
		receiptErr(w, err)
		return
	}
	prev := *rec
	apply(rec)
	if err := s.saveLocked(); err != nil {
		if rollback {
			*rec = prev
		}
		delete(s.busy, id)
		s.mu.Unlock()
		log.Printf("vms: %s not saved after the close of %s generation %d: %v", vmsFile, id, gen, err)
		writeErr(w, 500, "state_not_saved", "the run was closed on the host but the broker could not record it; repeat the stop")
		return
	}
	v := s.view(rec)
	delete(s.busy, id)
	s.mu.Unlock()
	// B2: once, right after the receipt. A failure leaves the generation
	// pending for the next GET or reconcile pass.
	if _, cerr := s.storeHistory(ctx, id, gen); cerr != nil {
		log.Printf("vms: history of %s generation %d not stored yet: %s", id, gen, cerr.code)
	}
	writeJSON(w, 200, v)
}

// ---------------------------------------------------------------- history (B2)

// storeHistory fetches the host's closed history for a run that has a receipt
// and appends it to vm-history.jsonl, once. A stored answer is returned as is.
func (s *vmStore) storeHistory(ctx context.Context, vm string, gen uint64) (vmHistoryLine, *vmCallErr) {
	k := vmRunKey{vm, gen}
	s.mu.Lock()
	if err := s.settleLocked(vmHistoryFile); err != nil {
		s.mu.Unlock()
		return vmHistoryLine{}, &vmCallErr{500, "state_not_saved", "the history journal could not be settled", false}
	}
	if hl, ok := s.hist[k]; ok {
		s.mu.Unlock()
		return hl, nil
	}
	rc, ok := s.receipts[k]
	h, hostOK := s.hosts[rc.Host]
	s.mu.Unlock()
	if !ok {
		return vmHistoryLine{}, &vmCallErr{404, "run_not_found", "no receipt for this run", false}
	}
	if !hostOK {
		return vmHistoryLine{}, &vmCallErr{409, "vm_host_not_configured", "the VM's host is not in vm_hosts", false}
	}
	doc, cerr := s.call(ctx, h, vmHistoryCallTimeout, nil, "history", vm, strconv.FormatUint(gen, 10))
	if cerr != nil {
		return vmHistoryLine{}, cerr
	}
	hl, err := parseHostHistory(doc, vm, gen)
	if err != nil {
		log.Printf("vms: host %s: history of %s generation %d: %v", h.ID, vm, gen, err)
		return vmHistoryLine{}, &vmCallErr{502, "history_invalid", "the host's history answer is not valid; nothing stored", false}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.settleLocked(vmHistoryFile); err != nil {
		return vmHistoryLine{}, &vmCallErr{500, "state_not_saved", "the history journal could not be settled", false}
	}
	if old, ok := s.hist[k]; ok { // a concurrent fetch stored it
		return old, nil
	}
	if hl.StoppedAt != rc.StoppedAt {
		log.Printf("vms: vm_history_mismatch: %s generation %d: host history stopped_at %d, receipt %d; refused", vm, gen, hl.StoppedAt, rc.StoppedAt)
		return vmHistoryLine{}, &vmCallErr{409, "vm_history_mismatch", "the host's history stopped_at differs from the receipt; not stored", false}
	}
	if err := s.appendJSONL(vmHistoryFile, hl); err != nil {
		log.Printf("vms: %s not written for %s generation %d: %v", vmHistoryFile, vm, gen, err)
		return vmHistoryLine{}, &vmCallErr{500, "state_not_saved", "the history could not be recorded", false}
	}
	s.hist[k] = hl
	return hl, nil
}

func parseHostHistory(doc map[string]any, vm string, gen uint64) (vmHistoryLine, error) {
	hl := vmHistoryLine{VM: vm, Generation: gen}
	// Every member the reader relies on must be present: a missing member is
	// not the same as null, and is never stored as evidence.
	for _, m := range []string{"generation", "stopped_at", "started_at"} {
		if _, present := doc[m]; !present {
			return hl, fmt.Errorf("%s is missing", m)
		}
	}
	if g, ok := doc["generation"].(float64); !ok || g != float64(gen) {
		return hl, errors.New("generation does not match")
	}
	if c, _ := doc["closed"].(bool); !c {
		return hl, errors.New("not a closed answer")
	}
	if h, _ := doc["history"].(string); h != "v2" {
		return hl, errors.New("history is not v2")
	}
	at, ok := vmUnixField(doc["stopped_at"])
	if !ok {
		return hl, errors.New("no stopped_at")
	}
	hl.StoppedAt, hl.History = at, "v2"
	switch v := doc["started_at"].(type) {
	case nil:
	case string:
		if !vmStartedAtRE.MatchString(v) {
			return hl, errors.New("started_at is not ISO 8601 with microseconds and Z")
		}
		hl.StartedAt = &v
		// The lower-bound error is part of the evidence of a non-null start.
		ev, present := doc["started_at_error_us"]
		ef, isNum := ev.(float64)
		if !present || !isNum || ef < 0 || ef != float64(int64(ef)) {
			return hl, errors.New("started_at_error_us is missing or not a non-negative integer")
		}
		e := int64(ef)
		hl.StartedAtErrorUS = &e
	default:
		return hl, errors.New("started_at is not a string or null")
	}
	hl.CloseReason, _ = doc["close_reason"].(string)
	if tf, ok := doc["tracked_from"].(float64); ok && tf >= 0 {
		hl.TrackedFrom = uint64(tf)
	}
	return hl, nil
}

// pendingHistory tries the history of every receipt of vm that has none.
func (s *vmStore) pendingHistory(ctx context.Context, vm string) {
	s.mu.Lock()
	var gens []uint64
	for k := range s.receipts {
		if _, have := s.hist[k]; k.vm == vm && !have {
			gens = append(gens, k.gen)
		}
	}
	s.mu.Unlock()
	sort.Slice(gens, func(i, j int) bool { return gens[i] < gens[j] })
	for _, g := range gens {
		if _, cerr := s.storeHistory(ctx, vm, g); cerr != nil {
			log.Printf("vms: history of %s generation %d still pending: %s", vm, g, cerr.code)
		}
	}
}

// ---------------------------------------------------------------- reconcile and replay (B1)

// receiptMissingLocked: the run is closed in vms.json but has no receipt.
func (s *vmStore) receiptMissingLocked(rec *vmRecord) bool {
	_ = s.settleLocked(vmRunsFile)
	if rec.DesiredState != vmStateStopped || rec.Generation == 0 || rec.StoppedAt == 0 {
		return false
	}
	_, ok := s.receipts[vmRunKey{rec.ID, rec.Generation}]
	return !ok
}

// adoptReceiptsLocked is replay step 1: copy receipts forward into a stale
// vms.json. A receipt for the record's current generation closes it whatever
// state the record is in (running, starting or stopped without its time), and
// a receipt for the next generation (a cancel whose save was lost) moves the
// record to that closed run. It never applies a receipt over a newer
// generation: only Generation and Generation+1 are looked at. Repeats while a
// receipt applies, so a delete that closed G and G+1 is copied in full.
func (s *vmStore) adoptReceiptsLocked(rec *vmRecord) bool {
	changed := false
	for {
		g := rec.Generation
		if rc, ok := s.receipts[vmRunKey{rec.ID, g}]; ok && g > 0 && (rec.DesiredState != vmStateStopped || rec.StoppedAt == 0) {
			rec.DesiredState, rec.StoppedAt, rec.LastError = vmStateStopped, rc.StoppedAt, ""
			changed = true
			continue
		}
		if rc, ok := s.receipts[vmRunKey{rec.ID, g + 1}]; ok && rec.DesiredState == vmStateStopped {
			rec.Generation, rec.StoppedAt, rec.Ran, rec.LastError = g+1, rc.StoppedAt, false, ""
			changed = true
			continue
		}
		return changed
	}
}

// reconcileRuns settles one VM's runs, in the replay order of the spec: (1)
// copy receipts forward into vms.json, (2) every close intent without a
// receipt goes through host cancel, (3) so does every authorize intent with no
// answer (cancel fences the generation), then a closed run in vms.json that
// still has no receipt, then history still pending. Every step is idempotent.
// Best effort; a VM with a call in flight is left alone.
func (s *vmStore) reconcileRuns(ctx context.Context, id string) {
	s.mu.Lock()
	rec := s.recs[id]
	if rec == nil || s.busy[id] {
		s.mu.Unlock()
		return
	}
	s.busy[id] = true
	_ = s.settleLocked(vmRunsFile) // a failed append may have left a line on disk
	_ = s.settleLocked(vmHistoryFile)
	account, host := rec.Account, rec.Host
	h, hostOK := s.hosts[host]
	defer func() {
		s.mu.Lock()
		delete(s.busy, id)
		s.mu.Unlock()
	}()
	save := func(why string) {
		if err := s.saveLocked(); err != nil {
			log.Printf("vms: %s not saved after %s of %s: %v", vmsFile, why, id, err)
		}
	}
	if s.adoptReceiptsLocked(rec) {
		save("adopting a receipt")
	}
	closes, auths := s.unresolvedGensLocked(id)
	// An authorize whose generation is live was answered; only its line was lost.
	var fence []uint64
	for _, g := range auths {
		if rec.Generation == g && (rec.DesiredState == vmStateStarting || rec.DesiredState == vmStateRunning) {
			if err := s.resolveAuthLocked(id, g, true, false); err != nil {
				log.Printf("vms: authorize intent of %s generation %d stays open: %v", id, g, err)
			}
			continue
		}
		fence = append(fence, g)
	}
	// An authorize the host accepted whose save never reached vms.json stays
	// outstanding too (a refused retry cannot erase it): the replay fences it.
	for k := range s.authAccepted {
		if _, closed := s.receipts[k]; k.vm != id || closed || rec.Generation >= k.gen || rec.AuthorizedGeneration >= k.gen {
			continue
		}
		dup := false
		for _, g := range fence {
			dup = dup || g == k.gen
		}
		if !dup {
			fence = append(fence, k.gen)
		}
	}
	sort.Slice(fence, func(i, j int) bool { return fence[i] < fence[j] })
	s.mu.Unlock()

	cancel := func(g uint64, step string) {
		if !hostOK {
			return
		}
		at, cerr := s.hostCancel(ctx, h, id, g)
		if cerr != nil {
			log.Printf("vms: replay (%s) of %s generation %d: %s", step, id, g, cerr.code)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if cur := s.recs[id]; cur != nil && cur.Generation == g && cur.StoppedAt != 0 && cur.StoppedAt != at {
			// vms.json holds a time the host does not (a legacy broker's own
			// clock). The host's close is the receipt, marked disputed so B5 answers
			// 409 and settlement stays pending; the old time is kept for audit.
			log.Printf("vms: replay of %s generation %d: host close at %d, vms.json says %d; receipt written as disputed", id, g, at, cur.StoppedAt)
			if err := s.appendReceiptLocked(id, account, host, g, at, vmReceiptCancel, true); err != nil {
				log.Printf("vms: replay (%s) of %s generation %d: %v", step, id, g, err)
				return
			}
			cur.LegacyStoppedAt, cur.StoppedAt = cur.StoppedAt, at
			save("a disputed close")
			return
		}
		if err := s.appendReceiptLocked(id, account, host, g, at, vmReceiptCancel, false); err != nil {
			log.Printf("vms: replay (%s) of %s generation %d: %v", step, id, g, err)
		}
	}
	for _, g := range closes {
		cancel(g, "close intent")
	}
	for _, g := range fence {
		cancel(g, "authorize intent")
	}

	s.mu.Lock()
	if s.adoptReceiptsLocked(rec) {
		save("adopting a receipt")
	}
	var legacyGen uint64
	if s.receiptMissingLocked(rec) {
		legacyGen = rec.Generation
	}
	s.mu.Unlock()
	if legacyGen > 0 {
		cancel(legacyGen, "closed run")
	}
	s.pendingHistory(ctx, id)
}

// replay runs once at broker start (B1): every VM with a closed run and no
// receipt gets one through host cancel, and pending history is retried,
// tombstoned VMs included.
func (s *vmStore) replay(ctx context.Context) {
	s.mu.Lock()
	ids := make([]string, 0, len(s.recs))
	for id := range s.recs {
		ids = append(ids, id)
	}
	gone := map[string]bool{}
	for k := range s.receipts {
		if s.recs[k.vm] == nil {
			gone[k.vm] = true
		}
	}
	s.mu.Unlock()
	sort.Strings(ids)
	for _, id := range ids {
		s.reconcileRuns(ctx, id)
	}
	for vm := range gone {
		s.pendingHistory(ctx, vm)
	}
}

// ---------------------------------------------------------------- delete (B3)

// deleteSteps runs the steps of a delete in order and answers the refusal, or
// nil once the VM is gone from vms.json. Every step is idempotent, so a delete
// interrupted anywhere replays from the top. Caller holds the VM's busy mark.
func (s *vmStore) deleteSteps(ctx context.Context, id string, h vmHostConfig) *vmCallErr {
	s.mu.Lock()
	rec := s.recs[id]
	if rec == nil {
		s.mu.Unlock()
		return &vmCallErr{404, "vm_not_found", "no such VM", false}
	}
	account, host := rec.Account, rec.Host
	// 1. The outstanding set: the run, the authorized run, and any unresolved
	// start intent (state starting is the run in Generation).
	set := map[uint64]bool{}
	for _, g := range []uint64{rec.Generation, rec.AuthorizedGeneration} {
		if g > 0 {
			set[g] = true
		}
	}
	// Every authorize that was not refused (a lost reply may have been accepted)
	// and every close still open.
	_ = s.settleLocked(vmRunsFile)
	for k := range s.authIntents {
		// Dispatched and not closed by a receipt: outstanding, whatever a later
		// retry was answered. A fresh refusal is the only thing that retires it.
		if k.vm == id && s.authOutstandingLocked(k) {
			set[k.gen] = true
		}
	}
	for k := range s.closeIntents {
		if k.vm == id && !s.closeRefused[k] {
			set[k.gen] = true
		}
	}
	s.mu.Unlock()
	gens := make([]uint64, 0, len(set))
	for g := range set {
		gens = append(gens, g)
	}
	sort.Slice(gens, func(i, j int) bool { return gens[i] < gens[j] })

	// 2. Close each member through the host, with a B1 receipt.
	for _, g := range gens {
		s.mu.Lock()
		_, have := s.receipts[vmRunKey{id, g}]
		s.mu.Unlock()
		if have {
			continue
		}
		s.mu.Lock()
		err := s.appendCloseIntentLocked(id, account, host, g)
		s.mu.Unlock()
		if err != nil {
			return &vmCallErr{500, "state_not_saved", "the close could not be recorded; nothing was sent to the host", false}
		}
		at, cerr := s.hostCancel(ctx, h, id, g)
		if cerr != nil {
			if cerr.unknown {
				s.mu.Lock()
				if rec := s.recs[id]; rec != nil {
					rec.LastError = "delete: " + cerr.code
					_ = s.saveLocked()
				}
				s.mu.Unlock()
			}
			return cerr
		}
		s.mu.Lock()
		if err := s.appendReceiptLocked(id, account, host, g, at, vmReceiptCancel, false); err != nil {
			s.mu.Unlock()
			if errors.Is(err, errReceiptMismatch) {
				return &vmCallErr{409, "vm_receipt_mismatch", "the host's close differs from the receipt on record", false}
			}
			return &vmCallErr{500, "state_not_saved", "the receipt could not be recorded; repeat the delete", false}
		}
		if rec := s.recs[id]; rec != nil {
			if g > rec.Generation {
				rec.Generation, rec.Ran = g, false
			}
			if g == rec.Generation {
				rec.DesiredState, rec.StoppedAt, rec.LastError = vmStateStopped, at, ""
			}
			if err := s.saveLocked(); err != nil {
				s.mu.Unlock()
				log.Printf("vms: %s not saved after the close of %s generation %d in a delete: %v", vmsFile, id, g, err)
				return &vmCallErr{500, "state_not_saved", "the run was closed but the broker could not record it; repeat the delete", false}
			}
		}
		s.mu.Unlock()
	}

	// 3. History for every receipt, or the host's word that it is unknown.
	s.mu.Lock()
	var all []uint64
	for k := range s.receipts {
		if k.vm == id {
			all = append(all, k.gen)
		}
	}
	s.mu.Unlock()
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	for _, g := range all {
		if _, cerr := s.storeHistory(ctx, id, g); cerr != nil && cerr.code != "history_unknown" {
			return &vmCallErr{409, "history_not_stored", fmt.Sprintf("the history of generation %d is not stored (%s); repeat the delete", g, cerr.code), false}
		}
	}

	// 4. Host delete. A VM already gone answers existed:false.
	if _, cerr := s.call(ctx, h, 2*time.Minute, nil, "delete", id, "--confirm", id); cerr != nil {
		if cerr.unknown {
			s.mu.Lock()
			if rec := s.recs[id]; rec != nil {
				rec.LastError = "delete: " + cerr.code
				_ = s.saveLocked()
			}
			s.mu.Unlock()
		}
		return cerr
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// 5. Tombstone, durable before the VM leaves vms.json.
	if err := s.settleLocked(vmRunsFile); err != nil {
		return &vmCallErr{500, "state_not_saved", "the journal could not be settled; repeat the delete", false}
	}
	if _, done := s.tombs[id]; !done {
		l := vmRunLine{VM: id, Account: account, Host: host, DeletedAt: s.now().Unix()}
		if err := s.appendJSONL(vmRunsFile, l); err != nil {
			log.Printf("vms: %s not written for the tombstone of %s: %v", vmRunsFile, id, err)
			return &vmCallErr{500, "state_not_saved", "the host deleted the VM but the broker could not record it; repeat the delete", false}
		}
		s.tombs[id] = l
	}
	// 6. Only now out of vms.json.
	old := s.recs[id]
	delete(s.recs, id)
	if err := s.saveLocked(); err != nil {
		s.recs[id] = old
		log.Printf("vms: %s not saved after delete of %s: %v", vmsFile, id, err)
		return &vmCallErr{500, "state_not_saved", "the host deleted the VM but the broker could not record it; repeat the delete", false}
	}
	return nil
}

// ---------------------------------------------------------------- route (B5)

// getVMRun answers the history of one closed run from vm-history.jsonl, or
// from the host while it is still pending. It works for a deleted VM.
func (b *broker) getVMRun(w http.ResponseWriter, r *http.Request, id, genText string) {
	s := b.vms
	gen, err := strconv.ParseUint(genText, 10, 64)
	if err != nil || gen < 1 {
		writeErr(w, 404, "run_not_found", "no such run")
		return
	}
	k := vmRunKey{id, gen}
	s.mu.Lock()
	serr := s.settleLocked(vmRunsFile)
	rc, ok := s.receipts[k]
	s.mu.Unlock()
	if serr != nil {
		writeErr(w, 500, "state_not_saved", "the run journal could not be settled")
		return
	}
	if !ok {
		writeErr(w, 404, "run_not_found", "no receipt for this run")
		return
	}
	if rc.Disputed {
		writeErr(w, 409, "vm_receipt_mismatch", "an older broker recorded another stopped_at for this run than the host's close; settle it by hand")
		return
	}
	hl, cerr := s.storeHistory(r.Context(), id, gen)
	if cerr != nil {
		cerr.write(w)
		return
	}
	writeJSON(w, 200, map[string]any{
		"vm": rc.VM, "account": rc.Account, "host": rc.Host, "generation": gen,
		"started_at": hl.StartedAt, "stopped_at": rc.StoppedAt, "close_reason": hl.CloseReason,
		"history_id": fmt.Sprintf("%s:%d:%s", rc.VM, gen, rc.Host),
	})
}

// vmRefusalCode reads the code of a host exit 3 that is a history refusal.
// Only these two codes are taken from the host's answer.
func vmRefusalCode(out []byte) string {
	line := bytes.TrimSpace(out)
	if i := bytes.LastIndexByte(line, '\n'); i >= 0 {
		line = line[i+1:]
	}
	var doc map[string]any
	if json.Unmarshal(line, &doc) != nil {
		return ""
	}
	for _, key := range []string{"code", "error"} {
		if c, _ := doc[key].(string); strings.HasPrefix(c, "history_") && (c == "history_open" || c == "history_unknown") {
			return c
		}
	}
	return ""
}
