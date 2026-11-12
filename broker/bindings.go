package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Binding archive (AB#381). A hotel keeps its binding in RAM and a new one
// comes with every boot, so a receipt from an earlier boot could not be
// checked. The broker keeps each attested binding in state_dir/bindings/
// <sha256>.json and serves it to the operator by that hash.
//
// The file is the binding exactly as served, so its SHA-256 is its name. The
// binding holds public values only (measurement, chip id, public receipt key,
// TLS key hash). The SNP report and every key file stay out.
const bindingsDir = "bindings"

var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// archiveBinding stores rawBinding under sha. Failure is logged by the caller
// and never refuses a hotel: the archive helps audits, admission does not
// depend on it.
func (b *broker) archiveBinding(rawBinding []byte, sha string) error {
	sha = strings.ToLower(sha)
	if b.cfg.StateDir == "" || !sha256HexRE.MatchString(sha) {
		return nil
	}
	dir := filepath.Join(b.cfg.StateDir, bindingsDir)
	name := filepath.Join(dir, sha+".json")
	if _, err := os.Stat(name); err == nil {
		return nil // one file per boot; the hotel is re-checked on a timer
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, rawBinding, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

// handleBindingGet serves GET /v1/broker/bindings/<sha256> (operator key).
func (b *broker) handleBindingGet(w http.ResponseWriter, sha string) {
	sha = strings.ToLower(sha)
	if !sha256HexRE.MatchString(sha) {
		writeErr(w, 400, "bad_request", "the binding id is a 64-character SHA-256 hex digest")
		return
	}
	raw, err := os.ReadFile(filepath.Join(b.cfg.StateDir, bindingsDir, sha+".json"))
	if b.cfg.StateDir == "" || err != nil {
		writeErr(w, 404, "not_found", "no archived binding with that hash")
		return
	}
	// A file that no longer hashes to its name is not the binding it claims.
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != sha {
		writeErr(w, 500, "internal", "the archived binding does not match its hash")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

func (b *broker) archiveAttested(h *hotel, rawBinding []byte, sha string) {
	if err := b.archiveBinding(rawBinding, sha); err != nil {
		log.Printf("hotel %s: binding archive: %v", h.cfg.ID, err)
	}
}
