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

// archiveChainPage merges one hotel /room/receipts page that started at
// offset after. A page that would leave a gap is skipped: the next read from
// offset 0 fills it. Failure never refuses the caller.
func (b *broker) archiveChainPage(binding string, after int, body []byte) error {
	binding = strings.ToLower(binding)
	if b.cfg.StateDir == "" || !sha256HexRE.MatchString(binding) || after < 0 {
		return nil
	}
	var page struct {
		Receipts []json.RawMessage `json:"receipts"`
	}
	if err := json.Unmarshal(body, &page); err != nil || len(page.Receipts) == 0 {
		return err
	}
	chainArchiveMu.Lock()
	defer chainArchiveMu.Unlock()
	dir := filepath.Join(b.cfg.StateDir, chainsDir)
	name := filepath.Join(dir, binding+".json")
	var have struct {
		Receipts []json.RawMessage `json:"receipts"`
	}
	if raw, err := os.ReadFile(name); err == nil {
		_ = json.Unmarshal(raw, &have)
	}
	if after > len(have.Receipts) || after+len(page.Receipts) > chainReceiptsMax {
		return nil
	}
	merged := append(have.Receipts[:after:after], page.Receipts...)
	if len(merged) < len(have.Receipts) {
		merged = have.Receipts // a short re-read must not shrink the archive
	}
	out, err := marshalRaw(map[string]any{"binding_sha256": binding, "receipts": merged})
	if err != nil {
		return err
	}
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
// chain. It logs and moves on.
func (b *broker) archiveHotelPage(h *hotel, after int, body []byte) {
	var head struct {
		Binding string `json:"binding_sha256"`
	}
	_ = json.Unmarshal(body, &head)
	if err := b.archiveChainPage(head.Binding, after, body); err != nil {
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
