package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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

var chainArchiveMu sync.Mutex

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
}

// chainUnheldMax bounds Unheld. Past it the oldest are dropped; the newest
// are kept, so the archive still stays incomplete.
const chainUnheldMax = 16

func receiptSHA(raw json.RawMessage) string {
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
	chainArchiveMu.Lock()
	defer chainArchiveMu.Unlock()
	dir := filepath.Join(b.cfg.StateDir, chainsDir)
	name := filepath.Join(dir, binding+".json")
	var have archivedChain
	old, readErr := os.ReadFile(name)
	if readErr == nil {
		_ = json.Unmarshal(old, &have)
	}
	if readErr != nil && len(page.Receipts) == 0 && page.Head == "" {
		return nil // nothing to record
	}
	merged := have.Receipts
	if len(page.Receipts) > 0 && after <= len(have.Receipts) && after+len(page.Receipts) <= chainReceiptsMax {
		if m := append(have.Receipts[:after:after], page.Receipts...); len(m) >= len(have.Receipts) {
			merged = m // a short re-read must not shrink the archive
		}
	}
	if merged == nil {
		merged = []json.RawMessage{}
	}
	doc := archivedChain{Binding: binding, Receipts: merged}
	seen := map[string]bool{}
	for _, h := range append(append(append([]string{}, have.Unheld...), have.Head), page.Head) {
		if h != "" && !seen[h] && !chainHolds(merged, h) {
			seen[h] = true
			doc.Unheld = append(doc.Unheld, h)
		}
	}
	if n := len(doc.Unheld); n > chainUnheldMax {
		doc.Unheld = doc.Unheld[n-chainUnheldMax:]
	}
	last := ""
	if len(merged) > 0 {
		last = receiptSHA(merged[len(merged)-1])
	}
	switch {
	case seen[have.Head]:
		doc.Head = have.Head // keep the head already on record; others wait in Unheld
	case seen[page.Head]:
		doc.Head = page.Head
	case len(doc.Unheld) > 0:
		doc.Head = doc.Unheld[len(doc.Unheld)-1]
	case last != "" && (page.Head == last || have.Head == last):
		doc.Head, doc.Complete = last, true
	default:
		doc.Head = have.Head // the receipts hold every head seen, but none ends them
	}
	out, err := marshalRaw(doc)
	if err != nil {
		return err
	}
	if readErr == nil && string(out) == string(old) {
		return nil // nothing changed: no rewrite of a large archive per read
	}
	return writeBytes(dir, name, out)
}

// writeBytes replaces the archive file atomically. Caller holds chainArchiveMu.
func writeBytes(dir, name string, out []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(name+".tmp", out, 0o600); err != nil {
		return err
	}
	if err := os.Rename(name+".tmp", name); err != nil {
		return err
	}
	pruneChains(dir)
	return nil
}

// chainHolds reports whether a receipt in chain has the hash sha.
func chainHolds(chain []json.RawMessage, sha string) bool {
	for _, rc := range chain {
		if receiptSHA(rc) == sha {
			return true
		}
	}
	return false
}

// pruneChains drops chains older than chainMaxAge, then the oldest beyond
// chainFilesMax. Caller holds chainArchiveMu.
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
