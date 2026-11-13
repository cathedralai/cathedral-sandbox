package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func chainPage(binding string, from, n int) []byte {
	var recs []string
	for i := from; i < from+n; i++ {
		recs = append(recs, fmt.Sprintf(`{"statement":{"sandbox_id":"r%d"},"signature_b64":"s%d"}`, i, i))
	}
	return []byte(`{"binding_sha256":"` + binding + `","head":"hh","receipts":[` + strings.Join(recs, ",") + `]}`)
}

func readChain(t *testing.T, dir, binding string) []json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, chainsDir, binding+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Receipts []json.RawMessage `json:"receipts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Receipts
}

func TestChainPagesMergeByOffsetByteForByte(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	bind := strings.Repeat("a", 64)
	for _, p := range []struct{ after, from, n int }{{0, 0, 3}, {3, 3, 2}, {1, 1, 4}} { // last one re-reads
		if err := b.archiveChainPage(bind, p.after, chainPage(bind, p.from, p.n)); err != nil {
			t.Fatal(err)
		}
	}
	got := readChain(t, dir, bind)
	if len(got) != 5 {
		t.Fatalf("want 5 receipts, got %d", len(got))
	}
	if string(got[4]) != `{"statement":{"sandbox_id":"r4"},"signature_b64":"s4"}` {
		t.Fatalf("receipt bytes changed: %s", got[4])
	}
}

func TestChainPageWithGapIsSkipped(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	bind := strings.Repeat("b", 64)
	_ = b.archiveChainPage(bind, 0, chainPage(bind, 0, 2))
	_ = b.archiveChainPage(bind, 5, chainPage(bind, 5, 2))
	if n := len(readChain(t, dir, bind)); n != 2 {
		t.Fatalf("gap page was stored: %d", n)
	}
}

func TestChainArchiveIsBounded(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	for i := 0; i < chainFilesMax+3; i++ {
		bind := fmt.Sprintf("%064x", i)
		if err := b.archiveChainPage(bind, 0, chainPage(bind, 0, 1)); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, chainsDir, "*.json"))
	if len(files) > chainFilesMax {
		t.Fatalf("%d chain files kept, max %d", len(files), chainFilesMax)
	}
	big := strings.Repeat("c", 64)
	_ = b.archiveChainPage(big, 0, chainPage(big, 0, chainReceiptsMax))
	_ = b.archiveChainPage(big, chainReceiptsMax, chainPage(big, chainReceiptsMax, 10))
	if n := len(readChain(t, dir, big)); n > chainReceiptsMax {
		t.Fatalf("%d receipts kept, max %d", n, chainReceiptsMax)
	}
}

func TestChainRouteOperatorOnlyAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	bind := strings.Repeat("d", 64)
	if err := tc.b.archiveChainPage(bind, 0, chainPage(bind, 0, 2)); err != nil {
		t.Fatal(err)
	}
	tc.start(t) // a new broker over the same state_dir
	status, raw := tc.getRaw(t, "operator-key", "/v1/broker/bindings/"+bind+"/receipts")
	if status != 200 || !strings.Contains(string(raw), `"s1"`) {
		t.Fatalf("operator GET: %d %s", status, raw)
	}
	for _, key := range []string{"", "reader-key", "enroller-key", "key1", "wrong"} {
		if status, _ := tc.getRaw(t, key, "/v1/broker/bindings/"+bind+"/receipts"); status == 200 {
			t.Fatalf("key %q read the chain", key)
		}
	}
	if status, _ := tc.getRaw(t, "operator-key", "/v1/broker/bindings/"+strings.Repeat("0", 64)+"/receipts"); status != 404 {
		t.Fatalf("unknown binding: %d", status)
	}
}

// attestedHotel is a sealed hotel that passed admission for binding.
func attestedHotel(b *broker, binding string) *hotel {
	b.cfg.SealedMeasurements = []string{strings.Repeat("ab", 48)}
	h := &hotel{}
	h.cfg.ID, h.cfg.Sealed = "a", true
	h.adm.bindingSHA = binding
	h.adm.measurement = strings.Repeat("ab", 48)
	h.adm.attestedAt = time.Now()
	return h
}

// HOLD #464 finding 1: the archive name comes from the hotel's attested
// binding, never from the binding_sha256 its receipts body claims.
func TestHotelPageArchivesOnlyUnderAttestedBinding(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	own, victim := strings.Repeat("1", 64), strings.Repeat("2", 64)
	if err := b.archiveChainPage(victim, 0, chainPage(victim, 0, 3)); err != nil {
		t.Fatal(err)
	}
	victimPath := filepath.Join(dir, chainsDir, victim+".json")
	before, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatal(err)
	}
	h := attestedHotel(b, own)

	// An admitted hotel names another binding: no write anywhere.
	forged := []byte(strings.Replace(string(chainPage(victim, 0, 4)), `"r0"`, `"forged"`, 1))
	b.archiveHotelPage(h, 0, forged)
	if after, _ := os.ReadFile(victimPath); string(after) != string(before) {
		t.Fatalf("a hotel attested as %s rewrote the archive of %s", own[:8], victim[:8])
	}
	// Rotating names must not create files, so prune cannot evict the victim.
	for i := 0; i < chainFilesMax+2; i++ {
		other := fmt.Sprintf("%064x", 1000+i)
		b.archiveHotelPage(h, 0, chainPage(other, 0, 1))
	}
	files, _ := filepath.Glob(filepath.Join(dir, chainsDir, "*.json"))
	if len(files) != 1 {
		t.Fatalf("mismatched pages wrote %d archive files, want only the victim's", len(files))
	}
	if _, err := os.Stat(victimPath); err != nil {
		t.Fatalf("victim archive evicted: %v", err)
	}

	// The matching binding is archived under the attested name.
	b.archiveHotelPage(h, 0, chainPage(strings.ToUpper(own), 0, 2))
	if n := len(readChain(t, dir, own)); n != 2 {
		t.Fatalf("attested page: want 2 receipts, got %d", n)
	}

	// No admission (never attested, or the pass was cleared): no write.
	fresh := strings.Repeat("3", 64)
	h2 := attestedHotel(b, fresh)
	h2.adm.attestedAt = time.Time{}
	b.archiveHotelPage(h2, 0, chainPage(fresh, 0, 1))
	h3 := &hotel{}
	h3.cfg.ID = "c"
	b.archiveHotelPage(h3, 0, chainPage(fresh, 0, 1))
	if _, err := os.Stat(filepath.Join(dir, chainsDir, fresh+".json")); err == nil {
		t.Fatal("a hotel with no attested binding was archived")
	}
}

// headPage is a hotel page with real-looking receipt hashes and a head.
func headPage(binding string, from, n int, head string) []byte {
	var recs []string
	for i := from; i < from+n; i++ {
		recs = append(recs, fmt.Sprintf(`{"statement":{"sequence":%d},"receipt_sha256":"%064x","signature_b64":"s%d"}`, i+1, i+1, i))
	}
	return []byte(`{"binding_sha256":"` + binding + `","head":"` + head + `","receipts":[` + strings.Join(recs, ",") + `]}`)
}

// servedChain reads Complete as a pointer: a missing marker is not "false".
type servedChain struct {
	Binding  string            `json:"binding_sha256"`
	Head     string            `json:"head"`
	Complete *bool             `json:"complete"`
	Receipts []json.RawMessage `json:"receipts"`
}

func getArchive(t *testing.T, dir, binding string) servedChain {
	t.Helper()
	b := &broker{} // a new broker over the same state_dir: a restart
	b.cfg.StateDir = dir
	rec := httptest.NewRecorder()
	b.handleChainGet(rec, binding)
	if rec.Code != 200 {
		t.Fatalf("GET archive: %d %s", rec.Code, rec.Body)
	}
	var doc servedChain
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// HOLD #464 finding 2: a prefix read before a restart keeps the head the
// hotel named and says it is incomplete, so it cannot pass for the chain.
func TestPartialChainArchiveKeepsHeadAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	bind := strings.Repeat("e", 64)
	h5 := fmt.Sprintf("%064x", 5)
	h := attestedHotel(b, bind)

	b.archiveHotelPage(h, 0, headPage(bind, 0, 2, h5)) // first page of five, then the broker restarts
	doc := getArchive(t, dir, bind)
	if len(doc.Receipts) != 2 || doc.Head != h5 || doc.Complete == nil || *doc.Complete {
		t.Fatalf("prefix archive: receipts=%d head=%q complete=%v; want 2, the hotel head, complete=false",
			len(doc.Receipts), doc.Head, doc.Complete)
	}

	b2 := &broker{}
	b2.cfg.StateDir = dir
	h = attestedHotel(b2, bind)
	b2.archiveHotelPage(h, 2, headPage(bind, 2, 3, h5)) // the rest, after the restart
	doc = getArchive(t, dir, bind)
	if len(doc.Receipts) != 5 || doc.Head != h5 || doc.Complete == nil || !*doc.Complete {
		t.Fatalf("whole archive: receipts=%d head=%q complete=%v; want 5, the hotel head, complete=true",
			len(doc.Receipts), doc.Head, doc.Complete)
	}

	// An older page read late (head behind the archive) must not unmark it.
	b2.archiveHotelPage(h, 0, headPage(bind, 0, 2, fmt.Sprintf("%064x", 2)))
	if doc = getArchive(t, dir, bind); len(doc.Receipts) != 5 || doc.Complete == nil || !*doc.Complete || doc.Head != h5 {
		t.Fatalf("stale page: receipts=%d head=%q complete=%v", len(doc.Receipts), doc.Head, doc.Complete)
	}
	// A first-page retry may be shorter than the archive even though the
	// hotel's chain has grown. The new head must make the archive incomplete.
	h6 := fmt.Sprintf("%064x", 6)
	b2.archiveHotelPage(h, 0, headPage(bind, 0, 2, h6))
	if doc = getArchive(t, dir, bind); len(doc.Receipts) != 5 || doc.Complete == nil || *doc.Complete || doc.Head != h6 {
		t.Fatalf("grown chain on short page: receipts=%d head=%q complete=%v", len(doc.Receipts), doc.Head, doc.Complete)
	}
	// The chain grew past the archive: incomplete again, with the new head.
	h7 := fmt.Sprintf("%064x", 7)
	b2.archiveHotelPage(h, 5, headPage(bind, 5, 1, h7))
	if doc = getArchive(t, dir, bind); len(doc.Receipts) != 6 || doc.Complete == nil || *doc.Complete || doc.Head != h7 {
		t.Fatalf("grown chain: receipts=%d head=%q complete=%v", len(doc.Receipts), doc.Head, doc.Complete)
	}
}
