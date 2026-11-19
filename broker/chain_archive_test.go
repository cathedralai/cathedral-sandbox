package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	waitChainWrites()
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
	waitChainWrites()
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
	waitChainWrites()
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
	waitChainWrites()
	victimPath := filepath.Join(dir, chainsDir, victim+".json")
	before, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatal(err)
	}
	h := attestedHotel(b, own)

	// An admitted hotel names another binding: no write anywhere.
	forged := []byte(strings.Replace(string(chainPage(victim, 0, 4)), `"r0"`, `"forged"`, 1))
	b.archiveHotelPage(h, 0, forged)
	waitChainWrites()
	if after, _ := os.ReadFile(victimPath); string(after) != string(before) {
		t.Fatalf("a hotel attested as %s rewrote the archive of %s", own[:8], victim[:8])
	}
	// Rotating names must not create files, so prune cannot evict the victim.
	for i := 0; i < chainFilesMax+2; i++ {
		other := fmt.Sprintf("%064x", 1000+i)
		b.archiveHotelPage(h, 0, chainPage(other, 0, 1))
	}
	waitChainWrites()
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
	waitChainWrites()
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
	waitChainWrites()
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

// HOLD #464 at 77ea5f0e: a page past chainReceiptsMax is not stored, but the
// head it names still proves the chain grew. A complete archive at the cap must
// turn incomplete with the new head (the verifier then says NOT PROVEN, see
// tests/test_room_kit_level1_receipts.py test_incomplete_broker_archive_...).
func TestCapPageRecordsNewHeadAndDropsComplete(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	bind := strings.Repeat("f", 64)
	h := attestedHotel(b, bind)
	capHead := fmt.Sprintf("%064x", chainReceiptsMax)
	b.archiveHotelPage(h, 0, headPage(bind, 0, chainReceiptsMax, capHead))
	if doc := getArchive(t, dir, bind); len(doc.Receipts) != chainReceiptsMax || doc.Complete == nil || !*doc.Complete {
		t.Fatalf("archive at the cap: receipts=%d complete=%v; want the cap, complete=true", len(doc.Receipts), doc.Complete)
	}

	next := fmt.Sprintf("%064x", chainReceiptsMax+1)
	b.archiveHotelPage(h, chainReceiptsMax, headPage(bind, chainReceiptsMax, 1, next))
	doc := getArchive(t, dir, bind)
	if len(doc.Receipts) != chainReceiptsMax || doc.Head != next || doc.Complete == nil || *doc.Complete {
		t.Fatalf("one receipt past the cap: receipts=%d head=%q complete=%v; want the cap, the new head, complete=false",
			len(doc.Receipts), doc.Head, doc.Complete)
	}

	// A page that starts below the cap and crosses it says the same.
	b2 := &broker{}
	b2.cfg.StateDir = dir
	bind2 := strings.Repeat("9", 64)
	h2 := attestedHotel(b2, bind2)
	b2.archiveHotelPage(h2, 0, headPage(bind2, 0, chainReceiptsMax-1, fmt.Sprintf("%064x", chainReceiptsMax-1)))
	far := fmt.Sprintf("%064x", chainReceiptsMax+2)
	b2.archiveHotelPage(h2, chainReceiptsMax-1, headPage(bind2, chainReceiptsMax-1, 3, far))
	if doc := getArchive(t, dir, bind2); doc.Head != far || doc.Complete == nil || *doc.Complete {
		t.Fatalf("page crossing the cap: head=%q complete=%v; want the new head, complete=false", doc.Head, doc.Complete)
	}

	// A gap page past a complete archive is skipped too, and also reveals growth.
	bind3 := strings.Repeat("8", 64)
	h3 := attestedHotel(b2, bind3)
	h2nd := fmt.Sprintf("%064x", 2)
	b2.archiveHotelPage(h3, 0, headPage(bind3, 0, 2, h2nd))
	gapHead := fmt.Sprintf("%064x", 9)
	b2.archiveHotelPage(h3, 5, headPage(bind3, 5, 4, gapHead))
	if doc := getArchive(t, dir, bind3); len(doc.Receipts) != 2 || doc.Head != gapHead || doc.Complete == nil || *doc.Complete {
		t.Fatalf("gap page: receipts=%d head=%q complete=%v", len(doc.Receipts), doc.Head, doc.Complete)
	}
	// A stale gap page whose head the archive holds changes nothing.
	b2.archiveHotelPage(h3, 5, headPage(bind3, 5, 1, h2nd))
	if doc := getArchive(t, dir, bind3); doc.Head != gapHead {
		t.Fatalf("stale gap page moved the head back to %q", doc.Head)
	}
}

// Re-review of ce332333: an empty page, late pages out of order, and a first
// page that starts past offset 0 must all leave the newest head on record.
func TestEveryPageHeadIsRecorded(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	hx := func(i int) string { return fmt.Sprintf("%064x", i) }

	// Empty page past the end of a complete archive names a newer head.
	bind := strings.Repeat("7", 64)
	h := attestedHotel(b, bind)
	b.archiveHotelPage(h, 0, headPage(bind, 0, 5, hx(5)))
	b.archiveHotelPage(h, 6, headPage(bind, 6, 0, hx(6)))
	if doc := getArchive(t, dir, bind); len(doc.Receipts) != 5 || doc.Head != hx(6) || doc.Complete == nil || *doc.Complete {
		t.Fatalf("empty page: receipts=%d head=%q complete=%v", len(doc.Receipts), doc.Head, doc.Complete)
	}

	// Gap page names head 7; late pages from when the hotel was at 6 arrive after it.
	bind = strings.Repeat("6", 64)
	h = attestedHotel(b, bind)
	b.archiveHotelPage(h, 0, headPage(bind, 0, 5, hx(5)))
	b.archiveHotelPage(h, 6, headPage(bind, 6, 1, hx(7)))
	b.archiveHotelPage(h, 0, headPage(bind, 0, 2, hx(6)))
	b.archiveHotelPage(h, 5, headPage(bind, 5, 1, hx(6)))
	if doc := getArchive(t, dir, bind); len(doc.Receipts) != 6 || doc.Complete == nil || *doc.Complete || doc.Head != hx(7) {
		t.Fatalf("late pages: receipts=%d head=%q complete=%v; want 6, head 7, complete=false",
			len(doc.Receipts), doc.Head, doc.Complete)
	}
	// Receipt 7 arrives: now the archive holds every head it saw.
	b.archiveHotelPage(h, 6, headPage(bind, 6, 1, hx(7)))
	if doc := getArchive(t, dir, bind); len(doc.Receipts) != 7 || doc.Complete == nil || !*doc.Complete || doc.Head != hx(7) {
		t.Fatalf("caught up: receipts=%d head=%q complete=%v", len(doc.Receipts), doc.Head, doc.Complete)
	}

	// First read starts past offset 0: no receipts stored, but the head is on record.
	bind = strings.Repeat("5", 64)
	h = attestedHotel(b, bind)
	b.archiveHotelPage(h, 5, headPage(bind, 5, 1, hx(6)))
	if doc := getArchive(t, dir, bind); len(doc.Receipts) != 0 || doc.Head != hx(6) || doc.Complete == nil || *doc.Complete {
		t.Fatalf("first page past 0: receipts=%d head=%q complete=%v", len(doc.Receipts), doc.Head, doc.Complete)
	}
	// Re-reading what is already archived does not rewrite the file.
	name := filepath.Join(dir, chainsDir, strings.Repeat("6", 64)+".json")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(name, old, old); err != nil {
		t.Fatal(err)
	}
	b.archiveHotelPage(attestedHotel(b, strings.Repeat("6", 64)), 0, headPage(strings.Repeat("6", 64), 0, 3, hx(7)))
	waitChainWrites()
	if info, err := os.Stat(name); err != nil || !info.ModTime().Equal(old) {
		t.Fatalf("unchanged archive was rewritten: %v %v", info.ModTime(), err)
	}
}

// HOLD #464 at 957ce73, finding 1: with more than chainUnheldMax heads the
// oldest are dropped. A dropped head the receipts never reach must not let a
// later page mark the archive complete.
func TestDroppedHeadKeepsArchiveIncomplete(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	hx := func(i int) string { return fmt.Sprintf("%064x", i) }
	bind := strings.Repeat("4", 64)
	h := attestedHotel(b, bind)
	b.archiveHotelPage(h, 0, headPage(bind, 0, 5, hx(5)))

	// Gap pages name 7, then 1000 (a head past every receipt we will hold),
	// then 8..25: 20 unheld heads, more than chainUnheldMax.
	heads := []int{7, 1000}
	for i := 8; i <= 25; i++ {
		heads = append(heads, i)
	}
	if len(heads) <= chainUnheldMax {
		t.Fatalf("test needs more than %d heads, has %d", chainUnheldMax, len(heads))
	}
	for _, n := range heads {
		b.archiveHotelPage(h, 50, headPage(bind, 50, 1, hx(n)))
	}
	doc := getArchive(t, dir, bind)
	if doc.Complete == nil || *doc.Complete {
		t.Fatalf("archive with unheld heads reads complete")
	}

	// Receipts 6..25 arrive: they hold every head still on record, but not
	// 1000, which was dropped. The archive must stay incomplete.
	b.archiveHotelPage(h, 5, headPage(bind, 5, 20, hx(25)))
	doc = getArchive(t, dir, bind)
	if len(doc.Receipts) != 25 {
		t.Fatalf("want 25 receipts, got %d", len(doc.Receipts))
	}
	if doc.Complete == nil || *doc.Complete {
		t.Fatalf("a head was dropped, yet the archive reads complete (head %q)", doc.Head)
	}
	raw, err := os.ReadFile(filepath.Join(dir, chainsDir, bind+".json"))
	if err != nil || !strings.Contains(string(raw), `"unheld_heads_dropped":true`) {
		t.Fatalf("archive does not say heads were dropped: %v %s", err, raw[:min(len(raw), 200)])
	}
	// Later pages cannot clear it either.
	b.archiveHotelPage(h, 25, headPage(bind, 25, 1, hx(26)))
	if doc = getArchive(t, dir, bind); doc.Complete == nil || *doc.Complete || len(doc.Receipts) != 26 {
		t.Fatalf("after one more page: receipts=%d complete=%v", len(doc.Receipts), doc.Complete)
	}
}

// HOLD #464 at 957ce73, finding 2: the archive write runs outside every lock
// the receipts read path takes. A stalled write of one hotel's archive must
// block neither another hotel's page nor the next page of the same hotel, and
// pages merged while a write runs must all reach the file, in order.
func TestArchiveWriteDoesNotBlockReads(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	hx := func(i int) string { return fmt.Sprintf("%064x", i) }
	slow, other := strings.Repeat("3", 64), strings.Repeat("2", 64)
	release := make(chan struct{})
	stalled := make(chan struct{}, 1)
	chainBeforeWrite = func(name string) {
		if strings.Contains(name, slow) {
			select {
			case stalled <- struct{}{}:
			default:
			}
			<-release
		}
	}
	defer func() { chainBeforeWrite = func(string) {} }()

	hs, ho := attestedHotel(b, slow), attestedHotel(b, other)
	b.archiveHotelPage(hs, 0, headPage(slow, 0, 1000, hx(1000)))
	select {
	case <-stalled:
	case <-time.After(5 * time.Second):
		t.Fatal("the slow hotel's write never started")
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { // the same hotel keeps paging while its write is stalled
			defer wg.Done()
			for p := 1; p < 5; p++ {
				b.archiveHotelPage(hs, p*1000, headPage(slow, p*1000, 1000, hx((p+1)*1000)))
			}
		}()
		go func() { // another hotel's read is not held up either
			defer wg.Done()
			b.archiveHotelPage(ho, 0, headPage(other, 0, 3, hx(3)))
		}()
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("a page waited on another archive write")
	}
	close(release)
	waitChainWrites()

	doc := getArchive(t, dir, slow)
	if len(doc.Receipts) != 5000 || doc.Head != hx(5000) || doc.Complete == nil || !*doc.Complete {
		t.Fatalf("slow archive: receipts=%d head=%q complete=%v; want 5000, head 5000, complete",
			len(doc.Receipts), doc.Head, doc.Complete)
	}
	for i, rc := range doc.Receipts {
		if receiptSHA(rc) != hx(i+1) {
			t.Fatalf("receipt %d out of order: %s", i, receiptSHA(rc))
		}
	}
	if doc := getArchive(t, dir, other); len(doc.Receipts) != 3 || doc.Complete == nil || !*doc.Complete {
		t.Fatalf("other archive: receipts=%d complete=%v", len(doc.Receipts), doc.Complete)
	}
}

// Many hotels page at once (run with -race): every archive ends complete.
func TestConcurrentHotelArchives(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	hx := func(i int) string { return fmt.Sprintf("%064x", i) }
	hotels := map[string]*hotel{}
	for n := 0; n < 8; n++ { // set up every hotel before any read runs
		bind := fmt.Sprintf("%064x", 0xabc0+n)
		hotels[bind] = attestedHotel(b, bind)
	}
	var wg sync.WaitGroup
	for bind, h := range hotels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := 0; p < 10; p++ {
				b.archiveHotelPage(h, p*10, headPage(bind, p*10, 10, hx((p+1)*10)))
			}
		}()
	}
	wg.Wait()
	waitChainWrites()
	for n := 0; n < 8; n++ {
		doc := getArchive(t, dir, fmt.Sprintf("%064x", 0xabc0+n))
		if len(doc.Receipts) != 100 || doc.Complete == nil || !*doc.Complete || doc.Head != hx(100) {
			t.Fatalf("hotel %d: receipts=%d head=%q complete=%v", n, len(doc.Receipts), doc.Head, doc.Complete)
		}
	}
}

// Bugbot on bf6e2e0: with writers of different files running at once, a prune
// must not delete a file another writer just replaced. Many hotels past
// chainFilesMax write together; the newest write of each survivor must stay.
func TestPruneKeepsFreshArchivesUnderConcurrentWrites(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	hx := func(i int) string { return fmt.Sprintf("%064x", i) }
	hotels := map[string]*hotel{}
	for n := 0; n < chainFilesMax+8; n++ {
		bind := fmt.Sprintf("%064x", 0xbee0+n)
		hotels[bind] = attestedHotel(b, bind)
	}
	var wg sync.WaitGroup
	for bind, h := range hotels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := 0; p < 5; p++ {
				b.archiveHotelPage(h, p, headPage(bind, p, 1, hx(p+1)))
			}
		}()
	}
	wg.Wait()
	waitChainWrites()
	files, _ := filepath.Glob(filepath.Join(dir, chainsDir, "*.json"))
	if len(files) > chainFilesMax {
		t.Fatalf("%d chain files kept, max %d", len(files), chainFilesMax)
	}
	// One more write per hotel, one at a time: each must be on disk at once
	// after its own write, whatever else prune removed.
	for bind, h := range hotels {
		b.archiveHotelPage(h, 5, headPage(bind, 5, 1, hx(6)))
		waitChainWrites()
		if doc := getArchive(t, dir, bind); doc.Head != hx(6) {
			t.Fatalf("fresh archive of %.8s missing or stale: head %q", bind, doc.Head)
		}
	}
}

// HOLD #464 at bf6e2e0: a page must cost work in proportion to the page, not
// to the archived chain. A 100-page first capture parses each receipt once,
// and re-reading the whole unchanged chain parses nothing at all.
func TestArchiveMergeWorkIsLinearInThePage(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	hx := func(i int) string { return fmt.Sprintf("%064x", i) }
	bind := strings.Repeat("1a", 32)
	h := attestedHotel(b, bind)
	const pageSize, pages = 1000, 100
	head := hx(pageSize * pages)
	bodies := make([][]byte, pages)
	for p := range bodies {
		bodies[p] = headPage(bind, p*pageSize, pageSize, head)
	}

	before := receiptSHACalls.Load()
	for p, body := range bodies {
		b.archiveHotelPage(h, p*pageSize, body)
	}
	if n := receiptSHACalls.Load() - before; n > pageSize*pages {
		t.Fatalf("first capture parsed %d receipts for a %d-receipt chain", n, pageSize*pages)
	}
	waitChainWrites()

	before = receiptSHACalls.Load()
	for p, body := range bodies {
		b.archiveHotelPage(h, p*pageSize, body)
	}
	if n := receiptSHACalls.Load() - before; n != 0 {
		t.Fatalf("re-reading an unchanged chain parsed %d receipts", n)
	}
	waitChainWrites()
	if doc := getArchive(t, dir, bind); len(doc.Receipts) != pageSize*pages || doc.Complete == nil || !*doc.Complete || doc.Head != head {
		t.Fatalf("archive: receipts=%d head=%q complete=%v", len(doc.Receipts), doc.Head, doc.Complete)
	}
}

// HOLD #464 at bf6e2e0 (minor): after a failed write, the next page retries
// it even when the page itself changes nothing.
func TestFailedArchiveWriteIsRetriedByAnUnchangedPage(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	bind := strings.Repeat("2b", 32)
	h := attestedHotel(b, bind)
	blocker := filepath.Join(dir, chainsDir)
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := headPage(bind, 0, 3, fmt.Sprintf("%064x", 3))
	b.archiveHotelPage(h, 0, body)
	waitChainWrites()
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	b.archiveHotelPage(h, 0, body) // the same page: no change, but the file is missing
	waitChainWrites()
	if doc := getArchive(t, dir, bind); len(doc.Receipts) != 3 || doc.Complete == nil || !*doc.Complete {
		t.Fatalf("retried archive: receipts=%d complete=%v", len(doc.Receipts), doc.Complete)
	}
}

// Past chainLoadedMax recently used archives, idle ones leave memory and are
// read back from their file, unchanged, on the next page.
func TestIdleArchivesLeaveMemoryAndReloadIntact(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	hx := func(i int) string { return fmt.Sprintf("%064x", i) }
	first := strings.Repeat("3c", 32)
	h := attestedHotel(b, first)
	b.archiveHotelPage(h, 0, headPage(first, 0, 4, hx(4)))
	waitChainWrites()
	for n := 0; n < chainLoadedMax+2; n++ {
		other := fmt.Sprintf("%064x", 0xcafe0+n)
		b.archiveHotelPage(attestedHotel(b, other), 0, headPage(other, 0, 1, hx(1)))
		waitChainWrites()
	}
	chainArchiveMu.Lock()
	e := chainEntries[filepath.Join(dir, chainsDir, first+".json")]
	chainArchiveMu.Unlock()
	e.mu.Lock()
	loaded := e.loaded
	e.mu.Unlock()
	if loaded {
		t.Fatal("the least recently used idle archive stayed in memory")
	}
	b.archiveHotelPage(h, 4, headPage(first, 4, 1, hx(5)))
	if doc := getArchive(t, dir, first); len(doc.Receipts) != 5 || doc.Complete == nil || !*doc.Complete || doc.Head != hx(5) {
		t.Fatalf("reloaded archive: receipts=%d head=%q complete=%v", len(doc.Receipts), doc.Head, doc.Complete)
	}
}

// Bugbot on 04f01cd: a chain prune removed must not live on in memory, where
// an unchanged page would skip the write (GET 404s) and a changed one would
// write the pruned chain back. The next page starts from the disk, as before.
func TestPrunedArchiveIsForgottenInMemory(t *testing.T) {
	dir := t.TempDir()
	b := &broker{}
	b.cfg.StateDir = dir
	hx := func(i int) string { return fmt.Sprintf("%064x", i) }
	old, other := strings.Repeat("4d", 32), strings.Repeat("5e", 32)
	h := attestedHotel(b, old)
	b.archiveHotelPage(h, 0, headPage(old, 0, 5, hx(5)))
	waitChainWrites()
	name := filepath.Join(dir, chainsDir, old+".json")
	stale := time.Now().Add(-chainMaxAge - time.Hour)
	if err := os.Chtimes(name, stale, stale); err != nil {
		t.Fatal(err)
	}
	b.archiveHotelPage(attestedHotel(b, other), 0, headPage(other, 0, 1, hx(1))) // its write prunes by age
	waitChainWrites()
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatalf("aged archive not pruned: %v", err)
	}
	b.archiveHotelPage(h, 0, headPage(old, 0, 3, hx(5))) // a prefix the pruned chain held
	waitChainWrites()
	if doc := getArchive(t, dir, old); len(doc.Receipts) != 3 || doc.Complete == nil || *doc.Complete || doc.Head != hx(5) {
		t.Fatalf("after prune: receipts=%d head=%q complete=%v; want 3, head 5, incomplete",
			len(doc.Receipts), doc.Head, doc.Complete)
	}
}

// Bugbot on 04f01cd: one busy entry at the old end of the list must not keep
// every idle chain behind it in memory.
func TestBusyArchiveDoesNotPinIdleOnes(t *testing.T) {
	stuckDir, dir := t.TempDir(), t.TempDir()
	hx := func(i int) string { return fmt.Sprintf("%064x", i) }
	bs := &broker{}
	bs.cfg.StateDir = stuckDir
	if err := os.WriteFile(filepath.Join(stuckDir, chainsDir), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	stuck := strings.Repeat("6f", 32)
	bs.archiveHotelPage(attestedHotel(bs, stuck), 0, headPage(stuck, 0, 1, hx(1))) // every write fails
	waitChainWrites()
	b := &broker{}
	b.cfg.StateDir = dir
	var names []string
	for n := 0; n < chainLoadedMax+4; n++ {
		bind := fmt.Sprintf("%064x", 0xd00d0+n)
		b.archiveHotelPage(attestedHotel(b, bind), 0, headPage(bind, 0, 1, hx(1)))
		waitChainWrites()
		names = append(names, filepath.Join(dir, chainsDir, bind+".json"))
	}
	loaded := 0
	for _, name := range append(names, filepath.Join(stuckDir, chainsDir, stuck+".json")) {
		chainArchiveMu.Lock()
		e := chainEntries[name]
		chainArchiveMu.Unlock()
		e.mu.Lock()
		if e.loaded {
			loaded++
		}
		e.mu.Unlock()
	}
	if loaded > chainLoadedMax {
		t.Fatalf("%d chains in memory behind a failed one, max %d", loaded, chainLoadedMax)
	}
}
