package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
