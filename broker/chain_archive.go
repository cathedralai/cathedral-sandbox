package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Chain archive (AB#386). The hotel receipt chain lives in the guest's /run
// and is gone at a restart. Each hotel page the broker reads is merged by
// offset into state_dir/chains/<binding_sha256>.json, so a chain from an
// earlier boot can still be fetched and checked against the binding archived
// by AB#381. Receipts are stored byte for byte. They hold public values only.
const (
	chainsDir         = "chains"
	chainReceiptsMax  = 100000
	chainFilesMax     = 64
	chainMaxAge       = 30 * 24 * time.Hour
	chainArchiveGuard = "chain archive"
)

// The broker reads hotel pages on customer requests, so the archive must cost
// that path only the page's own work. chainArchiveMu guards the entry map and
// the recently used list, and is never held for file work. Each archive file
// has one entry: the chain in memory with an index of its receipt hashes, so a
// page is merged in time linear in the page, not the chain. One writer
// goroutine per file writes the newest copy outside every lock; pages that
// arrive while a write runs are coalesced into the next write, so the file
// always ends at the newest merge. The chainLoadedMax most recently used
// entries stay in memory; older idle ones are dropped and read again from the
// file when next used.
var (
	chainArchiveMu sync.Mutex
	chainEntries   = map[string]*chainEntry{}
	chainRecent    []*chainEntry  // most recently used last; at most chainLoadedMax
	chainWrites    sync.WaitGroup // tests wait on it; nothing in the broker does
)

const chainLoadedMax = 8

type chainEntry struct {
	mu      sync.Mutex
	loaded  bool          // doc mirrors the file plus any merge not yet written
	exists  bool          // the file exists or a write of it is pending
	doc     archivedChain // shares receipt slices with snapshots; never mutated in place
	shas    []string      // receipt_sha256 of doc.Receipts, index for index
	held    map[string]int
	dirty   bool // doc has a merge the file does not have yet
	writing bool // a writer goroutine owns the file
	failed  bool // the last write failed: the next page retries it
}

// chainBeforeWrite runs in the writer before each file write, with no lock
// held. Tests use it to stall a write; the broker leaves it empty.
var chainBeforeWrite = func(name string) {}

// waitChainWrites blocks until every pending archive write has finished.
func waitChainWrites() { chainWrites.Wait() }

// archivedChain is the file under chains/. Head is the newest hotel head
// seen for this binding. Complete is true only when the archived receipts end
// at a head the hotel named; a prefix (say, the first page read before a
// restart) stays complete=false, so it cannot pass for the whole chain.
type archivedChain struct {
	Binding  string            `json:"binding_sha256"`
	Head     string            `json:"head,omitempty"`
	Complete bool              `json:"complete"`
	Receipts []json.RawMessage `json:"receipts"`
	// Unheld lists hotel heads seen for this binding that the receipts do not
	// reach yet. Pages can arrive late and out of order, and a head hash says
	// nothing about its position, so every unheld head keeps complete=false
	// until the receipts hold it.
	Unheld []string `json:"unheld_heads,omitempty"`
	// HeadsDropped is set once Unheld overflowed chainUnheldMax. A dropped head
	// may never be reached by the receipts we hold, and we no longer know it, so
	// the archive stays complete=false for good rather than guess.
	HeadsDropped bool `json:"unheld_heads_dropped,omitempty"`
}

// chainUnheldMax bounds Unheld. Past it the oldest are dropped and
// HeadsDropped is set, so the archive can never read complete again.
const chainUnheldMax = 16

// receiptSHACalls counts receipt parses, so a test can prove a page costs
// work in proportion to the page, not to the archived chain.
var receiptSHACalls atomic.Int64

func receiptSHA(raw json.RawMessage) string {
	receiptSHACalls.Add(1)
	var rc struct {
		SHA string `json:"receipt_sha256"`
	}
	_ = json.Unmarshal(raw, &rc)
	return rc.SHA
}

// archiveChainPage merges one hotel /room/receipts page that started at
// offset after into the archive of binding. The caller has checked that
// binding is the hotel's attested one. Receipts that would leave a gap or pass
// chainReceiptsMax are not stored (the next read from offset 0 fills a gap),
// but the head every page names is always recorded: an empty page, a gap page
// or a page past the cap still proves the hotel's chain reaches that head.
// The merge is done here; the file write runs in the background.
func (b *broker) archiveChainPage(binding string, after int, body []byte) error {
	binding = strings.ToLower(binding)
	if b.cfg.StateDir == "" || !sha256HexRE.MatchString(binding) || after < 0 {
		return nil
	}
	var page struct {
		Head     string            `json:"head"`
		Receipts []json.RawMessage `json:"receipts"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return err
	}
	dir := filepath.Join(b.cfg.StateDir, chainsDir)
	name := filepath.Join(dir, binding+".json")

	e := useChainEntry(name)
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.loaded {
		// No write is pending for this file (an entry is dropped only when idle),
		// so the file on disk is the newest state. Read once, then kept.
		e.load(name)
	}
	if !e.exists && len(page.Receipts) == 0 && page.Head == "" {
		return nil // nothing to record
	}
	changed := e.merge(binding, after, page.Head, page.Receipts)
	if !changed && e.exists && !e.failed && !e.writing {
		// An unchanged page writes nothing, unless the file is gone: prune (age
		// or file cap) or a hand removal. The chain is still read, so write it
		// back from memory rather than serve 404 and lose it at eviction.
		if _, err := os.Stat(name); err != nil {
			changed = true
		}
	}
	// A failed last write is retried by the next page, changed or not.
	if changed || e.failed || !e.exists {
		e.exists, e.dirty = true, true
		if !e.writing {
			e.writing = true
			chainWrites.Add(1)
			go e.writeLoop(dir, name)
		}
	}
	return nil
}

// useChainEntry returns the entry for an archive file, marks it most recently
// used, and drops the in-memory chain of the least recently used idle entries
// past chainLoadedMax. A busy entry is skipped, never waited on.
func useChainEntry(name string) *chainEntry {
	chainArchiveMu.Lock()
	defer chainArchiveMu.Unlock()
	e := chainEntries[name]
	if e == nil {
		e = &chainEntry{}
		chainEntries[name] = e
	}
	recent := chainRecent[:0:0]
	for _, other := range chainRecent {
		if other != e {
			recent = append(recent, other)
		}
	}
	recent = append(recent, e)
	// Drop the oldest idle chains past the bound. A busy one (locked, or with a
	// write pending or failed) is skipped and stays listed, so it is tried again
	// on a later page and never pins the idle ones behind it.
	excess := len(recent) - chainLoadedMax
	kept := recent[:0:0]
	for i, old := range recent {
		if excess > 0 && i < len(recent)-1 && old.mu.TryLock() {
			idle := !old.dirty && !old.writing && !old.failed
			if idle {
				old.unload()
			}
			old.mu.Unlock()
			if idle {
				excess--
				continue
			}
		}
		kept = append(kept, old)
	}
	chainRecent = kept
	return e
}

// unload drops the in-memory chain; the next page reads the file again.
// Caller holds e.mu.
func (e *chainEntry) unload() {
	e.loaded, e.exists, e.failed = false, false, false
	e.doc, e.shas, e.held = archivedChain{}, nil, nil
}

// load reads the archive file into e and indexes its receipt hashes. Caller
// holds e.mu.
func (e *chainEntry) load(name string) {
	e.doc, e.exists = archivedChain{}, false
	if old, err := os.ReadFile(name); err == nil {
		_ = json.Unmarshal(old, &e.doc)
		e.exists = true
	}
	e.shas = make([]string, len(e.doc.Receipts))
	e.held = make(map[string]int, len(e.doc.Receipts))
	for i, rc := range e.doc.Receipts {
		e.shas[i] = receiptSHA(rc)
		e.held[e.shas[i]]++
	}
	e.loaded = true
}

// merge folds one page into e.doc and reports whether the archive changed.
// It never mutates the old doc's slices: a snapshot being written may share
// them. Caller holds e.mu.
func (e *chainEntry) merge(binding string, after int, pageHead string, pageReceipts []json.RawMessage) bool {
	have := e.doc
	merged, shas := have.Receipts, e.shas
	receiptsChanged := false
	end := after + len(pageReceipts)
	// Store the page only if it leaves no gap, stays under the cap, and does not
	// shrink the archive (a short re-read must not drop receipts).
	if len(pageReceipts) > 0 && after <= len(have.Receipts) && end <= chainReceiptsMax && end >= len(have.Receipts) {
		same := end == len(have.Receipts)
		for i := 0; same && i < len(pageReceipts); i++ {
			same = bytes.Equal(pageReceipts[i], have.Receipts[after+i])
		}
		if !same {
			pageSHAs := make([]string, len(pageReceipts))
			for i, rc := range pageReceipts {
				pageSHAs[i] = receiptSHA(rc)
			}
			for _, s := range e.shas[after:] {
				if e.held[s]--; e.held[s] <= 0 {
					delete(e.held, s)
				}
			}
			for _, s := range pageSHAs {
				e.held[s]++
			}
			merged = append(have.Receipts[:after:after], pageReceipts...)
			shas = append(e.shas[:after:after], pageSHAs...)
			receiptsChanged = true
		}
	}
	if merged == nil {
		merged = []json.RawMessage{}
	}
	holds := func(h string) bool { return e.held[h] > 0 }
	doc := archivedChain{Binding: binding, Receipts: merged, HeadsDropped: have.HeadsDropped}
	seen := map[string]bool{}
	for _, h := range append(append(append([]string{}, have.Unheld...), have.Head), pageHead) {
		if h != "" && !seen[h] && !holds(h) {
			seen[h] = true
			doc.Unheld = append(doc.Unheld, h)
		}
	}
	if n := len(doc.Unheld); n > chainUnheldMax {
		doc.Unheld = doc.Unheld[n-chainUnheldMax:]
		doc.HeadsDropped = true
	}
	last := ""
	if len(shas) > 0 {
		last = shas[len(shas)-1]
	}
	switch {
	case seen[have.Head]:
		doc.Head = have.Head // keep the head already on record; others wait in Unheld
	case seen[pageHead]:
		doc.Head = pageHead
	case len(doc.Unheld) > 0:
		doc.Head = doc.Unheld[len(doc.Unheld)-1]
	case last != "" && (pageHead == last || have.Head == last):
		// A dropped head may lie past last, so the archive cannot claim it.
		doc.Head, doc.Complete = last, !doc.HeadsDropped
	default:
		doc.Head = have.Head // the receipts hold every head seen, but none ends them
	}
	if !receiptsChanged && have.Binding == doc.Binding && have.Head == doc.Head &&
		have.Complete == doc.Complete && have.HeadsDropped == doc.HeadsDropped && slices.Equal(have.Unheld, doc.Unheld) {
		return false
	}
	e.doc, e.shas = doc, shas
	return true
}

// writeLoop writes the newest doc until no merge is pending. It snapshots doc
// under e.mu and writes with no lock held. Only this goroutine writes the file
// while e.writing is set, so writes cannot reorder.
func (e *chainEntry) writeLoop(dir, name string) {
	defer chainWrites.Done()
	for {
		e.mu.Lock()
		if !e.dirty {
			e.writing = false
			e.mu.Unlock()
			return
		}
		snap := e.doc
		e.dirty = false
		e.mu.Unlock()

		chainBeforeWrite(name)
		out, err := marshalRaw(snap)
		if err == nil {
			err = writeBytes(dir, name, out)
		}
		e.mu.Lock()
		e.failed = err != nil
		e.mu.Unlock()
		if err != nil {
			log.Printf("%s: %s: %v", chainArchiveGuard, filepath.Base(name), err)
		}
	}
}

// writeBytes replaces the archive file atomically. Only the file's writeLoop
// calls it.
func writeBytes(dir, name string, out []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(name+".tmp", out, 0o600); err != nil {
		return err
	}
	// Writers of different files run at once. The rename and the prune share
	// one lock so a prune never deletes a file on an age it read before another
	// writer replaced that file. The large write above stays outside it.
	chainPruneMu.Lock()
	if err := os.Rename(name+".tmp", name); err != nil {
		chainPruneMu.Unlock()
		return err
	}
	pruneChains(dir)
	chainPruneMu.Unlock()
	return nil
}

var chainPruneMu sync.Mutex

// pruneChains drops chains older than chainMaxAge, then the oldest beyond
// chainFilesMax. Caller holds chainPruneMu.
func pruneChains(dir string) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	type aged struct {
		path string
		mod  time.Time
	}
	var keep []aged
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > chainMaxAge {
			os.Remove(f)
			continue
		}
		keep = append(keep, aged{f, info.ModTime()})
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].mod.After(keep[j].mod) })
	for i := chainFilesMax; i < len(keep); i++ {
		os.Remove(keep[i].path)
	}
}

// archiveHotelPage is the hook for the two places the broker reads the hotel
// chain. The archive is named by the binding the hotel passed attestation
// with (h.adm.bindingSHA), never by the binding_sha256 its body claims: a
// hotel with no current pass, or a page naming another binding, writes
// nothing, so it can neither overwrite another chain nor push one out by
// prune. It logs and moves on.
func (b *broker) archiveHotelPage(h *hotel, after int, body []byte) {
	b.mu.Lock()
	attested := ""
	if !h.adm.attestedAt.IsZero() && b.admitted(h, time.Now()) {
		attested = strings.ToLower(h.adm.bindingSHA)
	}
	b.mu.Unlock()
	if attested == "" {
		return
	}
	var claim struct {
		Binding string `json:"binding_sha256"`
	}
	_ = json.Unmarshal(body, &claim)
	if strings.ToLower(claim.Binding) != attested {
		log.Printf("hotel %s: %s: page names binding %.16s..., attested %.16s...; not archived",
			h.cfg.ID, chainArchiveGuard, claim.Binding, attested)
		return
	}
	if err := b.archiveChainPage(attested, after, body); err != nil {
		log.Printf("hotel %s: %s: %v", h.cfg.ID, chainArchiveGuard, err)
	}
}

// handleChainGet serves GET /v1/broker/bindings/<sha256>/receipts (operator key).
func (b *broker) handleChainGet(w http.ResponseWriter, sha string) {
	sha = strings.ToLower(sha)
	if !sha256HexRE.MatchString(sha) {
		writeErr(w, 400, "bad_request", "the binding id is a 64-character SHA-256 hex digest")
		return
	}
	raw, err := os.ReadFile(filepath.Join(b.cfg.StateDir, chainsDir, sha+".json"))
	if b.cfg.StateDir == "" || err != nil {
		writeErr(w, 404, "not_found", "no archived receipt chain for that binding")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}
