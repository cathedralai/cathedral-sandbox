package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testClaimRec(id string) claimRecord {
	return claimRecord{Kind: "test", Body: json.RawMessage(`{"id":"` + id + `"}`)}
}

func claimIDRange(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%02d", prefix, i)
	}
	return out
}

// claimAck waits for ch as a caller does, with its own deadline.
func claimAck(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("no answer from the claim journal in 10 s")
		return nil
	}
}

func mustClaimAppend(t *testing.T, j *claimJournal, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := claimAck(t, j.append(testClaimRec(id))); err != nil {
			t.Fatalf("append %s: %v", id, err)
		}
	}
}

func openTestClaimJournal(t *testing.T, state string, o claimJournalOptions) *claimJournal {
	t.Helper()
	j, _, err := openClaimJournalWith(state, o)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = j.close() })
	return j
}

func claimIDsOf(t *testing.T, j *claimJournal) []string {
	t.Helper()
	var ids []string
	err := j.replay(func(r claimRecord) error {
		var b struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(r.Body, &b); err != nil {
			return err
		}
		ids = append(ids, b.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	return ids
}

// claimReplayIDs opens state on the real disk, requires it complete, and
// returns the ids it replays, in order.
func claimReplayIDs(t *testing.T, state string) []string {
	t.Helper()
	j := openTestClaimJournal(t, state, claimJournalOptions{})
	ids := claimIDsOf(t, j)
	_ = j.close()
	return ids
}

func claimGenDir(t *testing.T, state string) string {
	t.Helper()
	cur, err := readClaimText(filepath.Join(state, claimJournalDirName, claimCurrentName))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(state, claimJournalDirName, cur)
}

func readClaimManifestFile(t *testing.T, state string) claimManifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(claimGenDir(t, state), claimManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var m claimManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func claimSegPath(t *testing.T, state string, i int) string {
	t.Helper()
	man := readClaimManifestFile(t, state)
	if i < 0 {
		i += len(man.Segments)
	}
	return filepath.Join(claimGenDir(t, state), man.Segments[i].Name)
}

// claimLineIDs returns the ids of the test records in raw (whole lines only).
func claimLineIDs(raw []byte) []string {
	var ids []string
	for _, line := range bytes.Split(raw, []byte("\n")) {
		var l struct {
			Kind string `json:"kind"`
			Body struct {
				ID string `json:"id"`
			} `json:"body"`
		}
		if json.Unmarshal(line, &l) == nil && l.Kind == "test" {
			ids = append(ids, l.Body.ID)
		}
	}
	return ids
}

// claimFingerprint is every file under state with the sha256 of its bytes.
func claimFingerprint(t *testing.T, state string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(state, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[p] = claimSHA256(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func claimSame(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

// requireClaimTidy checks that only the live generation's own files are left.
func requireClaimTidy(t *testing.T, state string) {
	t.Helper()
	claims := filepath.Join(state, claimJournalDirName)
	gen := claimGenDir(t, state)
	if _, err := os.Stat(filepath.Join(state, claimJournalIDName+".tmp")); err == nil {
		t.Fatal("state_dir/claims.id.tmp was left behind")
	}
	tops, _ := os.ReadDir(claims)
	for _, e := range tops {
		if e.Name() != claimCurrentName && e.Name() != filepath.Base(gen) {
			t.Fatalf("claims/%s was left behind", e.Name())
		}
	}
	keep := map[string]bool{claimJournalIDInGen: true, claimManifestName: true, claimHeadNames[0]: true, claimHeadNames[1]: true}
	for _, s := range readClaimManifestFile(t, state).Segments {
		keep[s.Name] = true
	}
	entries, _ := os.ReadDir(gen)
	for _, e := range entries {
		if !keep[e.Name()] {
			t.Fatalf("%s/%s was left behind", filepath.Base(gen), e.Name())
		}
	}
}

// claimCrash stops the goroutine that reaches point for the nth time after
// it is armed, as a process kill would: nothing after that point runs, and
// the bytes already written stay in the page cache.
type claimCrash struct {
	point string
	nth   int64
	armed atomic.Bool
	seen  atomic.Int64
	hit   chan struct{}
}

func newClaimCrash(point string, nth int64) *claimCrash {
	return &claimCrash{point: point, nth: nth, hit: make(chan struct{})}
}

func (c *claimCrash) step(p string) {
	if p != c.point || !c.armed.Load() || c.seen.Add(1) < c.nth {
		return
	}
	close(c.hit)
	runtime.Goexit()
}

func (c *claimCrash) wait(t *testing.T) {
	t.Helper()
	select {
	case <-c.hit:
	case <-time.After(10 * time.Second):
		t.Fatalf("never reached %s", c.point)
	}
}

// claimDurable keeps what the disk holds after each successful fsync of a
// segment or head file, so a test can put the files back to it: a power loss.
type claimDurable struct {
	mu   sync.Mutex
	size map[string]int64  // segment path: its size after its last fsync
	head map[string][]byte // head file path: its bytes after its last fsync
}

func (d *claimDurable) wrap(disk *claimJournalDisk) {
	d.size, d.head = map[string]int64{}, map[string][]byte{}
	disk.sync = func(f *os.File) error {
		if err := f.Sync(); err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil {
			return err
		}
		d.mu.Lock()
		d.size[f.Name()] = info.Size()
		d.mu.Unlock()
		return nil
	}
	disk.syncHead = func(f *os.File) error {
		if err := f.Sync(); err != nil {
			return err
		}
		raw, err := os.ReadFile(f.Name())
		if err != nil {
			return err
		}
		d.mu.Lock()
		d.head[f.Name()] = raw
		d.mu.Unlock()
		return nil
	}
}

func (d *claimDurable) powerLoss(t *testing.T) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	for path, size := range d.size {
		if err := os.Truncate(path, size); err != nil {
			t.Fatal(err)
		}
	}
	for path, raw := range d.head {
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// 1,000 goroutines append 10 records each (10,000 appends). Both fsyncs are
// a 20 ms sleep; a record counts as acknowledged only once the segment fsync
// of its batch and then the head-file fsync have returned. No channel may
// close before that, each batch has one fsync of each, and batches group.
func TestClaimJournalAcksOnlyAfterSync(t *testing.T) {
	const goroutines, each = 1000, 10
	var (
		mu         sync.Mutex
		read       = map[string]int{} // segment: bytes the fsync hook has looked at (writer goroutine only)
		synced     []string           // ids whose segment fsync returned, head file not yet
		acked      = map[string]bool{}
		segSyncs   atomic.Int64
		headSyncs  atomic.Int64
		emptySyncs atomic.Int64
		batches    atomic.Int64
	)
	var o claimJournalOptions
	o.disk.sync = func(f *os.File) error {
		raw, err := os.ReadFile(f.Name())
		if err != nil {
			return err
		}
		ids := claimLineIDs(raw[read[f.Name()]:])
		read[f.Name()] = len(raw)
		if len(ids) == 0 {
			emptySyncs.Add(1)
		}
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		synced = append(synced, ids...)
		mu.Unlock()
		segSyncs.Add(1)
		return nil
	}
	o.disk.syncHead = func(f *os.File) error {
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		for _, id := range synced {
			acked[id] = true
		}
		synced = nil
		mu.Unlock()
		headSyncs.Add(1)
		return nil
	}
	o.observe = func(tm claimJournalTiming) {
		if !tm.Compaction && tm.Err == nil {
			batches.Add(1)
		}
	}
	state := t.TempDir()
	j := openTestClaimJournal(t, state, o)
	var early atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				id := fmt.Sprintf("g%04d-%d", g, i)
				if err := <-j.append(testClaimRec(id)); err != nil {
					t.Errorf("append %s: %v", id, err)
					return
				}
				mu.Lock()
				ok := acked[id]
				mu.Unlock()
				if !ok {
					early.Add(1)
				}
			}
		}(g)
	}
	wg.Wait()
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d appends from %d goroutines: %d batches, %d segment fsyncs, %d head-file fsyncs, %d early acknowledgements",
		goroutines*each, goroutines, batches.Load(), segSyncs.Load(), headSyncs.Load(), early.Load())
	if early.Load() != 0 {
		t.Fatalf("%d of %d appends acknowledged before their batch's head-file fsync returned", early.Load(), goroutines*each)
	}
	if len(acked) != goroutines*each {
		t.Fatalf("%d records acknowledged by the hooks, want %d", len(acked), goroutines*each)
	}
	if segSyncs.Load() != batches.Load() || headSyncs.Load() != batches.Load() || emptySyncs.Load() != 0 {
		t.Fatalf("%d batches, %d segment fsyncs (%d with no record), %d head-file fsyncs: want one of each per batch",
			batches.Load(), segSyncs.Load(), emptySyncs.Load(), headSyncs.Load())
	}
	if batches.Load() > goroutines*each/10 {
		t.Fatalf("%d batches for %d appends: records are not grouped", batches.Load(), goroutines*each)
	}
	ids := claimReplayIDs(t, state)
	seen := map[string]int{}
	for _, id := range ids {
		seen[id]++
	}
	if len(ids) != goroutines*each || len(seen) != goroutines*each {
		t.Fatalf("replay: %d records, %d distinct, want %d once each", len(ids), len(seen), goroutines*each)
	}
}

// A failed segment or head-file fsync fails every waiter of that batch. The
// caller appends those records again (new seqs), and replay yields each
// record once: the failed seqs are withdrawn even when their bytes stay.
func TestClaimJournalFailedSyncAcksNothing(t *testing.T) {
	cases := []struct {
		name      string
		failHead  bool // the head-file fsync fails (the segment fsync returned)
		cutFails  bool // the failed bytes cannot be cut off
		bytesStay bool // the failed batch's bytes stay in a segment
	}{
		{name: "segment fsync fails, its bytes cut off"},
		{name: "segment fsync fails, its bytes cannot be cut off", cutFails: true, bytesStay: true},
		{name: "head-file fsync fails after the segment fsync", failHead: true, bytesStay: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := t.TempDir()
			injected := errors.New("fsync: input/output error")
			var calls atomic.Int64
			entered, gate := make(chan struct{}), make(chan struct{})
			hook := func(f *os.File) error {
				switch calls.Add(1) {
				case 1: // a0's batch: held until the next batch is queued
					close(entered)
					<-gate
				case 2:
					return injected
				}
				return f.Sync()
			}
			var o claimJournalOptions
			if c.failHead {
				o.disk.syncHead = hook
			} else {
				o.disk.sync = hook
			}
			if c.cutFails {
				o.disk.cut = func(*os.File, int64) error { return errors.New("truncate: input/output error") }
			}
			j := openTestClaimJournal(t, state, o)
			first := j.append(testClaimRec("a0"))
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("a0's batch never reached its fsync")
			}
			ids := claimIDRange("b", 20)
			var failed []<-chan error
			for _, id := range ids {
				failed = append(failed, j.append(testClaimRec(id)))
			}
			close(gate)
			if err := claimAck(t, first); err != nil {
				t.Fatalf("a0: %v", err)
			}
			for i, ch := range failed {
				if err := claimAck(t, ch); !errors.Is(err, injected) {
					t.Fatalf("%s: got %v, want the injected fsync error", ids[i], err)
				}
			}
			mustClaimAppend(t, j, ids...) // the caller's retry, under new seqs
			mustClaimAppend(t, j, "c0")
			if err := j.close(); err != nil {
				t.Fatal(err)
			}
			var onDisk []byte
			segs, _ := filepath.Glob(filepath.Join(claimGenDir(t, state), "*.jsonl"))
			for _, s := range segs {
				raw, _ := os.ReadFile(s)
				onDisk = append(onDisk, raw...)
			}
			if copies := bytes.Count(onDisk, []byte(`"id":"b00"`)); c.bytesStay != (copies == 2) {
				t.Fatalf("b00 is %d times on disk; want the failed copy to stay: %v", copies, c.bytesStay)
			}
			want := append(append([]string{"a0"}, ids...), "c0")
			if got := claimReplayIDs(t, state); !claimSame(got, want) {
				t.Fatalf("replay %v\nwant   %v", got, want)
			}
		})
	}
}

// Crash points inside one batch: after its write (fsync not returned), after
// the segment fsync (head file not written), after the head file's write (its fsync
// not returned). A process kill keeps every byte written; a power loss keeps
// only what an fsync returned for. Either way every acknowledged record
// replays and the journal opens complete.
var claimBatchCrashPoints = []string{"batch-written", "batch-synced", "head-written"}

func TestClaimJournalPowerLossDropsOnlyUnacked(t *testing.T) {
	for _, p := range claimBatchCrashPoints {
		t.Run(p, func(t *testing.T) { runClaimBatchCrash(t, p, true) })
	}
}

func TestClaimJournalProcessKillKeepsWrittenRecords(t *testing.T) {
	for _, p := range claimBatchCrashPoints {
		t.Run(p, func(t *testing.T) { runClaimBatchCrash(t, p, false) })
	}
}

func runClaimBatchCrash(t *testing.T, point string, powerLoss bool) {
	state := t.TempDir()
	var d claimDurable
	var o claimJournalOptions
	d.wrap(&o.disk)
	segSync := o.disk.sync
	var hold atomic.Bool
	held, release := make(chan struct{}), make(chan struct{})
	o.disk.sync = func(f *os.File) error {
		if hold.CompareAndSwap(true, false) {
			close(held)
			<-release
		}
		return segSync(f)
	}
	// a09's batch is past its write when the crash is armed, not past its
	// fsync: for the later points the b batch is the second to reach them.
	nth := int64(1)
	if point != "batch-written" {
		nth = 2
	}
	crash := newClaimCrash(point, nth)
	o.disk.step = crash.step
	j, _, err := openClaimJournalWith(state, o)
	if err != nil {
		t.Fatal(err)
	}
	acked := claimIDRange("a", 10)
	mustClaimAppend(t, j, acked[:9]...)
	hold.Store(true)
	last := j.append(testClaimRec(acked[9]))
	<-held // a09's batch is in its fsync: the b records queue as one batch behind it
	crash.armed.Store(true)
	unackedIDs := claimIDRange("b", 5)
	var unacked []<-chan error
	for _, id := range unackedIDs {
		unacked = append(unacked, j.append(testClaimRec(id)))
	}
	close(release)
	if err := claimAck(t, last); err != nil {
		t.Fatal(err)
	}
	crash.wait(t)
	for i, ch := range unacked {
		select {
		case err := <-ch:
			t.Fatalf("%s answered (%v) although its batch never finished", unackedIDs[i], err)
		default:
		}
	}
	if powerLoss {
		d.powerLoss(t)
	}
	// The b records are whole in the segment unless a power loss cut them:
	// they replay although no caller was told they are durable.
	want := acked
	if !powerLoss || point != "batch-written" {
		want = append(append([]string(nil), acked...), unackedIDs...)
	}
	j2 := openTestClaimJournal(t, state, claimJournalOptions{})
	if got := claimIDsOf(t, j2); !claimSame(got, want) {
		t.Fatalf("replay %v\nwant   %v", got, want)
	}
	mustClaimAppend(t, j2, "after")
	_ = j2.close()
	if got := claimReplayIDs(t, state); !claimSame(got, append(want, "after")) {
		t.Fatalf("after the restart: %v", got)
	}
}

// Round 3 finding 3 and round 4: a power loss while a head file is written
// spoils that file only. The other file holds the previous head and the
// journal opens complete with every acknowledged record.
func TestClaimJournalPowerLossDuringHeadFileWrite(t *testing.T) {
	spoil := []struct {
		name string
		do   func(old, new []byte) []byte
	}{
		{"zeroed", func(old, new []byte) []byte { return make([]byte, len(new)) }},
		{"truncated", func(old, new []byte) []byte { return new[:claimHeadFileBytes/3] }},
		{"truncated to nothing", func(old, new []byte) []byte { return nil }},
		{"half old and half new", func(old, new []byte) []byte {
			return append(append([]byte(nil), new[:claimHeadFileBytes/2]...), old[claimHeadFileBytes/2:]...)
		}},
		{"the old bytes still there", func(old, new []byte) []byte { return old }},
	}
	for _, sp := range spoil {
		t.Run(sp.name, func(t *testing.T) {
			state := t.TempDir()
			crash := newClaimCrash("head-written", 1)
			o := claimJournalOptions{disk: claimJournalDisk{step: crash.step}}
			j, _, err := openClaimJournalWith(state, o)
			if err != nil {
				t.Fatal(err)
			}
			acked := claimIDRange("a", 6)
			mustClaimAppend(t, j, acked...)
			gen := claimGenDir(t, state)
			var before [2][]byte
			for i, name := range claimHeadNames {
				before[i], _ = os.ReadFile(filepath.Join(gen, name))
			}
			crash.armed.Store(true)
			b := j.append(testClaimRec("b00"))
			crash.wait(t)
			select {
			case <-b:
				t.Fatal("b00 answered before its head-file fsync")
			default:
			}
			written := -1
			var after []byte
			for i, name := range claimHeadNames {
				raw, _ := os.ReadFile(filepath.Join(gen, name))
				if !bytes.Equal(raw, before[i]) {
					written, after = i, raw
				}
			}
			if written < 0 {
				t.Fatal("no head file was being written")
			}
			if err := os.WriteFile(filepath.Join(gen, claimHeadNames[written]), sp.do(before[written], after), 0o600); err != nil {
				t.Fatal(err)
			}
			// The other file holds the previous batch's head: a05, seq 6.
			if h, _, err := readClaimHeads(gen); err != nil || h.Seq != 6 {
				t.Fatalf("head after the spoiled write: %+v, %v; want the previous head, seq 6", h, err)
			}
			// b00's segment fsync returned: it replays, unacknowledged.
			want := append(append([]string(nil), acked...), "b00")
			j2, heads, err := openClaimJournal(state)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if heads.Acked != 6 {
				t.Fatalf("open returned head %d, want 6", heads.Acked)
			}
			if got := claimIDsOf(t, j2); !claimSame(got, want) {
				t.Fatalf("replay %v\nwant   %v", got, want)
			}
			mustClaimAppend(t, j2, "after")
			_ = j2.close()
			if got := claimReplayIDs(t, state); !claimSame(got, append(want, "after")) {
				t.Fatalf("after the restart: %v", got)
			}
		})
	}
}

// The peer head set before a batch is the one open returns after a restart,
// with the journal's own acknowledged head; a compaction carries it.
func TestClaimJournalPeerHeadRoundTrips(t *testing.T) {
	state := t.TempDir()
	j, heads, err := openClaimJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	if heads != (claimJournalHeads{}) {
		t.Fatalf("a new journal returned %+v", heads)
	}
	j.setPeerHead(41)
	mustClaimAppend(t, j, "r00", "r01")
	j.setPeerHead(77) // set after the last batch: no head file records it
	_ = j.close()
	j, heads, err = openClaimJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	if heads != (claimJournalHeads{Acked: 2, Peer: 41}) {
		t.Fatalf("after a restart: %+v, want acked 2, peer 41", heads)
	}
	mustClaimAppend(t, j, "r02") // the peer head carries over without a new set
	j.setPeerHead(90)
	mustClaimAppend(t, j, "r03")
	_ = j.close()
	j, heads, err = openClaimJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	if heads != (claimJournalHeads{Acked: 4, Peer: 90}) {
		t.Fatalf("after a second restart: %+v, want acked 4, peer 90", heads)
	}
	j.setPeerHead(120)
	if err := claimAck(t, j.compact([]claimRecord{testClaimRec("s0")})); err != nil {
		t.Fatal(err)
	}
	_ = j.close()
	_, heads, err = openClaimJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	if heads != (claimJournalHeads{Acked: 5, Peer: 120}) {
		t.Fatalf("after a compaction: %+v, want acked 5 (the snapshot), peer 120", heads)
	}
}

// A crash after each step of initialization: the next open finds no valid
// claims.id and no record and redoes it, never incomplete. Records in a
// generation while claims.id is missing or does not parse are incomplete.
func TestClaimJournalCrashDuringInitialization(t *testing.T) {
	idPath := func(state string) string { return filepath.Join(state, claimJournalIDName) }
	steps := []struct {
		point string
		name  string
		after func(t *testing.T, state string) // what a power loss or a torn write leaves
	}{
		{point: "init-claims-dir"},
		{point: "init-gen-dir"},
		{point: "init-manifest"},
		{point: "init-ack-head-a"},
		{point: "init-ack-head-b"},
		{point: "init-journal-id"},
		{point: "init-gen-synced"},
		{point: "init-current-created"},
		{point: "init-current-synced"},
		{point: "init-current-renamed"},
		{point: "init-current-renamed", name: "a power loss takes the rename back", after: func(t *testing.T, state string) {
			_ = os.Remove(filepath.Join(state, claimJournalDirName, claimCurrentName))
		}},
		{point: "init-current-committed"},
		{point: "init-claims-id-created", name: "an empty temporary file"},
		{point: "init-claims-id-created", name: "a half-written temporary file", after: func(t *testing.T, state string) {
			_ = os.WriteFile(idPath(state)+".tmp", []byte("4f6a1c"), 0o600)
		}},
		{point: "init-claims-id-synced"},
		{point: "init-claims-id-renamed", name: "before the directory sync of its rename"},
		{point: "init-claims-id-renamed", name: "a power loss takes the rename back", after: func(t *testing.T, state string) {
			_ = os.Rename(idPath(state), idPath(state)+".tmp")
		}},
		{point: "init-claims-id-committed"},
	}
	opens := 0
	for _, s := range steps {
		name := s.point
		if s.name != "" {
			name += ", " + s.name
		}
		t.Run(name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state")
			crash := newClaimCrash(s.point, 1)
			crash.armed.Store(true)
			o := claimJournalOptions{disk: claimJournalDisk{step: crash.step}}
			go func() { _, _, _ = openClaimJournalWith(state, o) }()
			crash.wait(t)
			if s.after != nil {
				s.after(t, state)
			}
			j, _, err := openClaimJournal(state)
			if err != nil {
				t.Fatalf("open after a crash at %s: %v", s.point, err)
			}
			opens++
			if got := claimIDsOf(t, j); len(got) != 0 {
				t.Fatalf("replay %v", got)
			}
			mustClaimAppend(t, j, "first")
			_ = j.close()
			if got := claimReplayIDs(t, state); !claimSame(got, []string{"first"}) {
				t.Fatalf("after the redone initialization: %v", got)
			}
			requireClaimTidy(t, state)
		})
	}
	t.Run("a claims.id that does not parse, no record", func(t *testing.T) {
		state := t.TempDir()
		j := openTestClaimJournal(t, state, claimJournalOptions{})
		_ = j.close()
		_ = os.WriteFile(idPath(state), []byte("4f6a"), 0o600)
		if got := claimReplayIDs(t, state); len(got) != 0 {
			t.Fatalf("replay %v", got)
		}
		opens++
		if id, _ := readClaimText(idPath(state)); !claimIDRE.MatchString(id) {
			t.Fatalf("claims.id %q was not written again", id)
		}
	})
	t.Run("records while claims.id is missing", func(t *testing.T) {
		state := t.TempDir()
		j := openTestClaimJournal(t, state, claimJournalOptions{})
		mustClaimAppend(t, j, "r00")
		_ = j.close()
		_ = os.Remove(idPath(state))
		requireClaimIncomplete(t, state)
	})
	t.Run("records while claims.id does not parse", func(t *testing.T) {
		state := t.TempDir()
		j := openTestClaimJournal(t, state, claimJournalOptions{})
		mustClaimAppend(t, j, "r00")
		_ = j.close()
		_ = os.WriteFile(idPath(state), []byte("not an id\n"), 0o600)
		requireClaimIncomplete(t, state)
	})
	t.Logf("%d initialization crash points, each opened complete", opens)
}

// A revoked record that carries a request's new outcome is one line: torn,
// it is skipped whole, never half.
func TestClaimJournalTornTwoFactRecord(t *testing.T) {
	twoFacts := json.RawMessage(`{"id":"rv1","run_id":"r-1","revoked_at":1700000000000,"end_at":1700000000000,` +
		`"outcome":{"request_key":"k-1","fingerprint":"f-1","status":409,"body":"deleted_during_create"}}`)
	cases := []struct {
		name string
		cut  func(line []byte) []byte
	}{
		{"cut between the two facts", func(line []byte) []byte { return line[:bytes.Index(line, []byte(`,"outcome"`))] }},
		{"cut inside the second fact", func(line []byte) []byte { return line[:bytes.Index(line, []byte(`"status"`))] }},
		{"whole but for its newline", func(line []byte) []byte { return bytes.TrimSuffix(line, []byte("\n")) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := t.TempDir()
			j := openTestClaimJournal(t, state, claimJournalOptions{})
			if err := claimAck(t, j.append(claimRecord{Kind: "revoked", Body: json.RawMessage(`{"id":"rv0","run_id":"r-0","revoked_at":1,"end_at":1}`)})); err != nil {
				t.Fatal(err)
			}
			_ = j.close()
			seg := claimSegPath(t, state, -1)
			raw, _ := os.ReadFile(seg)
			sc := scanClaimSegment("seg", raw, 0, false)
			last := sc.lines[len(sc.lines)-1]
			line, _ := appendClaimLine(nil, last.Seq+1, last.hash, "revoked", twoFacts)
			f, err := os.OpenFile(seg, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.Write(c.cut(line))
			_ = f.Close()
			j2 := openTestClaimJournal(t, state, claimJournalOptions{})
			var kinds []string
			_ = j2.replay(func(r claimRecord) error {
				if bytes.Contains(r.Body, []byte(`"rv1"`)) {
					t.Fatalf("the torn two-fact record replayed: %s", r.Body)
				}
				kinds = append(kinds, r.Kind)
				return nil
			})
			if !claimSame(kinds, []string{"revoked"}) {
				t.Fatalf("replay %v", kinds)
			}
		})
	}
}

// buildClosedClaimJournal makes a journal of 24 records in several closed
// segments.
func buildClosedClaimJournal(t *testing.T) string {
	t.Helper()
	state := t.TempDir()
	j := openTestClaimJournal(t, state, claimJournalOptions{segmentMax: 300})
	mustClaimAppend(t, j, claimIDRange("c", 24)...)
	_ = j.close()
	j2 := openTestClaimJournal(t, state, claimJournalOptions{}) // closes the open segment as found
	_ = j2.close()
	man := readClaimManifestFile(t, state)
	if len(man.Segments) < 4 {
		t.Fatalf("%d segments; the test needs several", len(man.Segments))
	}
	for _, s := range man.Segments {
		if !s.Closed {
			t.Fatalf("segment %s is still open", s.Name)
		}
	}
	return state
}

// requireClaimIncomplete opens state: it must report incomplete, refuse
// appends and change no file.
func requireClaimIncomplete(t *testing.T, state string) {
	t.Helper()
	before := claimFingerprint(t, state)
	j, _, err := openClaimJournal(state)
	if !errors.Is(err, errClaimJournalIncomplete) {
		t.Fatalf("open: %v, want incomplete", err)
	}
	if j == nil {
		t.Fatal("an incomplete journal must come back read only")
	}
	t.Logf("reported: %v", err)
	if err := claimAck(t, j.append(testClaimRec("refused"))); !errors.Is(err, errClaimJournalIncomplete) {
		t.Fatalf("append on an incomplete journal: %v", err)
	}
	if err := claimAck(t, j.compact(nil)); !errors.Is(err, errClaimJournalIncomplete) {
		t.Fatalf("compact on an incomplete journal: %v", err)
	}
	if err := j.replay(func(claimRecord) error { return nil }); err != nil {
		t.Fatalf("replay on an incomplete journal: %v", err)
	}
	_ = j.close()
	after := claimFingerprint(t, state)
	if len(before) != len(after) {
		t.Fatalf("open changed the files: %d before, %d after", len(before), len(after))
	}
	for p, sum := range before {
		if after[p] != sum {
			t.Fatalf("open changed %s", p)
		}
	}
}

func TestClaimJournalLostSegmentIsIncomplete(t *testing.T) {
	damage := []struct {
		name string
		do   func(t *testing.T, state string)
	}{
		{"a listed segment removed", func(t *testing.T, state string) { _ = os.Remove(claimSegPath(t, state, 1)) }},
		{"a closed segment truncated", func(t *testing.T, state string) {
			p := claimSegPath(t, state, 1)
			info, _ := os.Stat(p)
			_ = os.Truncate(p, info.Size()-10)
		}},
		{"a closed segment changed, same size", func(t *testing.T, state string) {
			p := claimSegPath(t, state, 1)
			raw, _ := os.ReadFile(p)
			_ = os.WriteFile(p, bytes.Replace(raw, []byte(`"id":"c`), []byte(`"id":"x`), 1), 0o600)
		}},
	}
	for _, d := range damage {
		t.Run(d.name, func(t *testing.T) {
			state := buildClosedClaimJournal(t)
			d.do(t, state)
			requireClaimIncomplete(t, state)
		})
	}
}

func TestClaimJournalIncompleteIsDetected(t *testing.T) {
	claims := func(state string) string { return filepath.Join(state, claimJournalDirName) }
	damage := []struct {
		name string
		do   func(t *testing.T, state string)
	}{
		{"claims.id without claims/", func(t *testing.T, state string) { _ = os.RemoveAll(claims(state)) }},
		{"CURRENT missing", func(t *testing.T, state string) { _ = os.Remove(filepath.Join(claims(state), claimCurrentName)) }},
		{"CURRENT names a missing generation", func(t *testing.T, state string) {
			_ = os.WriteFile(filepath.Join(claims(state), claimCurrentName), []byte("gen-9\n"), 0o600)
		}},
		{"another journal id", func(t *testing.T, state string) {
			_ = os.WriteFile(filepath.Join(state, claimJournalIDName), []byte("00000000000000000000000000000000\n"), 0o600)
		}},
		{"the manifest deleted", func(t *testing.T, state string) {
			_ = os.Remove(filepath.Join(claimGenDir(t, state), claimManifestName))
		}},
		{"both head files unreadable", func(t *testing.T, state string) {
			for _, name := range claimHeadNames {
				_ = os.WriteFile(filepath.Join(claimGenDir(t, state), name), make([]byte, claimHeadFileBytes), 0o600)
			}
		}},
		{"both head files missing", func(t *testing.T, state string) {
			for _, name := range claimHeadNames {
				_ = os.Remove(filepath.Join(claimGenDir(t, state), name))
			}
		}},
		{"a non-empty unlisted segment", func(t *testing.T, state string) {
			line, _ := appendClaimLine(nil, 900, claimGenesis, "test", []byte(`{"id":"extra"}`))
			_ = os.WriteFile(filepath.Join(claimGenDir(t, state), claimSegmentName(900)), line, 0o600)
		}},
		{"records while claims.id is missing", func(t *testing.T, state string) { _ = os.Remove(filepath.Join(state, claimJournalIDName)) }},
	}
	for _, d := range damage {
		t.Run(d.name, func(t *testing.T) {
			state := buildClosedClaimJournal(t)
			d.do(t, state)
			requireClaimIncomplete(t, state)
		})
	}

	// Not loss: what a crash leaves is removed and the journal opens whole.
	notLoss := []struct {
		name string
		do   func(t *testing.T, state string) string // returns the path open must remove
	}{
		{"an empty unlisted segment", func(t *testing.T, state string) string {
			p := filepath.Join(claimGenDir(t, state), claimSegmentName(900))
			_ = os.WriteFile(p, nil, 0o600)
			return p
		}},
		{"a temporary claims.id", func(t *testing.T, state string) string {
			p := filepath.Join(state, claimJournalIDName+".tmp")
			_ = os.WriteFile(p, []byte("4f6a"), 0o600)
			return p
		}},
		{"a temporary manifest", func(t *testing.T, state string) string {
			p := filepath.Join(claimGenDir(t, state), claimManifestName+".tmp")
			_ = os.WriteFile(p, []byte("{"), 0o600)
			return p
		}},
		{"a temporary CURRENT", func(t *testing.T, state string) string {
			p := filepath.Join(claims(state), claimCurrentName+".tmp")
			_ = os.WriteFile(p, []byte("gen-2\n"), 0o600)
			return p
		}},
		{"an unfinished newer generation", func(t *testing.T, state string) string {
			p := filepath.Join(claims(state), claimGenName(2))
			_ = os.Mkdir(p, 0o700)
			line, _ := appendClaimLine(nil, 25, claimGenesis, "test", []byte(`{"id":"snap"}`))
			_ = os.WriteFile(filepath.Join(p, claimSegmentName(25)), line, 0o600)
			return p
		}},
	}
	for _, c := range notLoss {
		t.Run("not loss: "+c.name, func(t *testing.T) {
			state := buildClosedClaimJournal(t)
			left := c.do(t, state)
			if got := claimReplayIDs(t, state); !claimSame(got, claimIDRange("c", 24)) {
				t.Fatalf("replay %v", got)
			}
			if _, err := os.Stat(left); err == nil {
				t.Fatalf("%s is still there", left)
			}
			requireClaimTidy(t, state)
		})
	}
	t.Run("not loss: an obsolete older generation", func(t *testing.T) {
		state := buildClosedClaimJournal(t)
		j := openTestClaimJournal(t, state, claimJournalOptions{})
		if err := claimAck(t, j.compact([]claimRecord{testClaimRec("s0")})); err != nil {
			t.Fatal(err)
		}
		_ = j.close()
		old := filepath.Join(claims(state), claimGenName(1))
		_ = os.Mkdir(old, 0o700)
		_ = os.WriteFile(filepath.Join(old, claimManifestName), []byte("{}"), 0o600)
		if got := claimReplayIDs(t, state); !claimSame(got, []string{"s0"}) {
			t.Fatalf("replay %v", got)
		}
		if _, err := os.Stat(old); err == nil {
			t.Fatal("the obsolete generation is still there")
		}
	})
	t.Run("not loss: one head file missing", func(t *testing.T) {
		state := buildClosedClaimJournal(t)
		gone := filepath.Join(claimGenDir(t, state), claimHeadNames[1])
		_ = os.Remove(gone)
		j := openTestClaimJournal(t, state, claimJournalOptions{})
		if got := claimIDsOf(t, j); !claimSame(got, claimIDRange("c", 24)) {
			t.Fatalf("replay %v", got)
		}
		mustClaimAppend(t, j, "c24", "c25")
		_ = j.close()
		if _, err := os.Stat(gone); err != nil {
			t.Fatalf("the missing head file was not made again: %v", err)
		}
		if got := claimReplayIDs(t, state); !claimSame(got, claimIDRange("c", 26)) {
			t.Fatalf("after more records: %v", got)
		}
	})
	t.Run("intact", func(t *testing.T) {
		if got := claimReplayIDs(t, buildClosedClaimJournal(t)); !claimSame(got, claimIDRange("c", 24)) {
			t.Fatalf("replay %v", got)
		}
	})
}

// The open segment has no hash in the manifest; the head and the chain cover
// its acknowledged prefix. Losing or changing an acknowledged record is
// reported; cutting bytes nobody was told are durable is not.
func TestClaimJournalActiveTailLossIsIncomplete(t *testing.T) {
	// build leaves a journal as a process kill would: the open segment holds
	// a00 (one batch), a01 (one batch), b00 to b04 (one batch of five), all
	// acknowledged, then c00, written and never acknowledged.
	build := func(t *testing.T) (state, seg string, start, end map[string]int64) {
		state = t.TempDir()
		var calls atomic.Int64
		entered, gate := make(chan struct{}), make(chan struct{})
		var o claimJournalOptions
		o.disk.sync = func(f *os.File) error {
			if calls.Add(1) == 2 {
				close(entered)
				<-gate
			}
			return f.Sync()
		}
		crash := newClaimCrash("batch-written", 1)
		o.disk.step = crash.step
		j, _, err := openClaimJournalWith(state, o)
		if err != nil {
			t.Fatal(err)
		}
		mustClaimAppend(t, j, "a00")
		second := j.append(testClaimRec("a01"))
		<-entered
		var batch []<-chan error
		for _, id := range claimIDRange("b", 5) {
			batch = append(batch, j.append(testClaimRec(id)))
		}
		close(gate)
		for _, ch := range append([]<-chan error{second}, batch...) {
			if err := claimAck(t, ch); err != nil {
				t.Fatal(err)
			}
		}
		crash.armed.Store(true)
		unacked := j.append(testClaimRec("c00"))
		crash.wait(t)
		select {
		case <-unacked:
			t.Fatal("c00 was answered before its fsync")
		default:
		}
		man := readClaimManifestFile(t, state)
		if len(man.Segments) != 1 || man.Segments[0].Closed {
			t.Fatalf("want one open segment: %+v", man.Segments)
		}
		seg = claimSegPath(t, state, 0)
		raw, _ := os.ReadFile(seg)
		start, end = map[string]int64{}, map[string]int64{}
		var off int64
		for _, line := range bytes.SplitAfter(raw, []byte("\n")) {
			if ids := claimLineIDs(line); len(ids) == 1 {
				start[ids[0]], end[ids[0]] = off, off+int64(len(line))
			}
			off += int64(len(line))
		}
		if len(end) != 8 {
			t.Fatalf("lines %v", end)
		}
		return state, seg, start, end
	}
	acked := []string{"a00", "a01", "b00", "b01", "b02", "b03", "b04"}
	lost := []struct {
		name string
		do   func(seg string, start, end map[string]int64)
	}{
		{"truncated by one acknowledged record", func(seg string, _, end map[string]int64) { _ = os.Truncate(seg, end["b03"]) }},
		{"truncated by a whole batch", func(seg string, _, end map[string]int64) { _ = os.Truncate(seg, end["a01"]) }},
		{"truncated to zero", func(seg string, _, _ map[string]int64) { _ = os.Truncate(seg, 0) }},
		{"an acknowledged record cut out of the middle", func(seg string, start, end map[string]int64) {
			raw, _ := os.ReadFile(seg)
			_ = os.WriteFile(seg, append(append([]byte(nil), raw[:start["a01"]]...), raw[end["a01"]:]...), 0o600)
		}},
		{"an acknowledged byte changed", func(seg string, _, _ map[string]int64) {
			raw, _ := os.ReadFile(seg)
			_ = os.WriteFile(seg, bytes.Replace(raw, []byte(`"id":"a00"`), []byte(`"id":"a99"`), 1), 0o600)
		}},
	}
	for _, c := range lost {
		t.Run(c.name, func(t *testing.T) {
			state, seg, start, end := build(t)
			c.do(seg, start, end)
			requireClaimIncomplete(t, state)
		})
	}
	t.Run("only unacknowledged bytes cut", func(t *testing.T) {
		state, seg, _, end := build(t)
		_ = os.Truncate(seg, end["b04"])
		if got := claimReplayIDs(t, state); !claimSame(got, acked) {
			t.Fatalf("replay %v", got)
		}
	})
	t.Run("nothing cut", func(t *testing.T) {
		state, _, _, _ := build(t)
		// c00 is whole on disk: it replays although it was never acknowledged.
		if got := claimReplayIDs(t, state); !claimSame(got, append(append([]string(nil), acked...), "c00")) {
			t.Fatalf("replay %v", got)
		}
	})
}

// A crash after each step of a new segment and of a compaction: every case
// opens complete, with every acknowledged record exactly once (round 2
// finding 6), and leaves no stray file.
func TestClaimJournalCrashAtEveryCommitBoundary(t *testing.T) {
	type boundary struct {
		point    string
		nth      int64
		undo     string // a power loss takes this rename back: "manifest" or "CURRENT"
		newSet   bool   // a compaction: the snapshot is live after the crash
		describe string
	}
	roll := []boundary{
		{point: "roll-created"},
		{point: "roll-dir-synced"},
		{point: "roll-manifest-created"},
		{point: "roll-manifest-synced"},
		{point: "roll-manifest-renamed"},
		{point: "roll-manifest-renamed", undo: "manifest"},
		{point: "roll-manifest-committed"},
	}
	compaction := []boundary{
		{point: "compact-start"},
		{point: "compact-gen-dir"},
		{point: "compact-segment"},
		{point: "compact-manifest"},
		{point: "compact-ack-head-a"},
		{point: "compact-ack-head-b"},
		{point: "compact-journal-id"},
		{point: "compact-gen-synced"},
		{point: "compact-current-created"},
		{point: "compact-current-synced"},
		{point: "compact-current-renamed", newSet: true},
		{point: "compact-current-renamed", undo: "CURRENT"},
		{point: "compact-current-committed", newSet: true},
		{point: "compact-removed", nth: 1, newSet: true},
		{point: "compact-removed", nth: 2, newSet: true},
		{point: "compact-removed", nth: 5, newSet: true},
		{point: "compact-done", newSet: true},
	}
	opens := 0
	name := func(b boundary) string {
		n := b.point
		if b.nth > 1 {
			n += fmt.Sprintf(" #%d", b.nth)
		}
		if b.undo != "" {
			n += ", power loss takes the " + b.undo + " rename back"
		}
		return n
	}
	for _, b := range roll {
		t.Run("new segment: "+name(b), func(t *testing.T) {
			state := t.TempDir()
			crash := newClaimCrash(b.point, max(b.nth, 1))
			o := claimJournalOptions{segmentMax: 300, disk: claimJournalDisk{step: crash.step}}
			j, _, err := openClaimJournalWith(state, o)
			if err != nil {
				t.Fatal(err)
			}
			acked := claimIDRange("a", 6) // several segments already
			mustClaimAppend(t, j, acked...)
			crash.armed.Store(true)
			var savedMan []byte
			for i := 0; ; i++ {
				savedMan, _ = os.ReadFile(filepath.Join(claimGenDir(t, state), claimManifestName))
				ch := j.append(testClaimRec(fmt.Sprintf("x%02d", i)))
				select {
				case err := <-ch:
					if err != nil {
						t.Fatal(err)
					}
					acked = append(acked, fmt.Sprintf("x%02d", i))
					continue
				case <-crash.hit:
				case <-time.After(10 * time.Second):
					t.Fatal("no roll")
				}
				break
			}
			if b.undo == "manifest" {
				_ = os.WriteFile(filepath.Join(claimGenDir(t, state), claimManifestName), savedMan, 0o600)
			}
			if got := claimReplayIDs(t, state); !claimSame(got, acked) {
				t.Fatalf("replay %v\nwant   %v", got, acked)
			}
			opens++
			requireClaimTidy(t, state)
		})
	}
	for _, b := range compaction {
		t.Run("compaction: "+name(b), func(t *testing.T) {
			state := t.TempDir()
			crash := newClaimCrash(b.point, max(b.nth, 1))
			o := claimJournalOptions{segmentMax: 400, disk: claimJournalDisk{step: crash.step}}
			j, _, err := openClaimJournalWith(state, o)
			if err != nil {
				t.Fatal(err)
			}
			oldIDs := claimIDRange("o", 15)
			mustClaimAppend(t, j, oldIDs...)
			current := filepath.Join(state, claimJournalDirName, claimCurrentName)
			oldCurrent, _ := os.ReadFile(current)
			crash.armed.Store(true)
			done := j.compact([]claimRecord{testClaimRec("s0"), testClaimRec("s1")})
			crash.wait(t)
			select {
			case err := <-done:
				t.Fatalf("the compaction answered (%v) although its writer stopped", err)
			default:
			}
			if b.undo == "CURRENT" {
				_ = os.WriteFile(current, oldCurrent, 0o600)
			}
			want := oldIDs
			if b.newSet {
				want = []string{"s0", "s1"}
			}
			j2 := openTestClaimJournal(t, state, claimJournalOptions{})
			if got := claimIDsOf(t, j2); !claimSame(got, want) {
				t.Fatalf("replay %v\nwant   %v", got, want)
			}
			opens++
			mustClaimAppend(t, j2, "after")
			_ = j2.close()
			if got := claimReplayIDs(t, state); !claimSame(got, append(want, "after")) {
				t.Fatalf("after the restart: %v", got)
			}
			requireClaimTidy(t, state)
		})
	}
	t.Logf("%d commit boundaries, each opened complete", opens)
}

// A compaction's generation is written and fsynced whole, file by file and
// then its directory, before CURRENT names it; once committed it replays
// exactly, and a changed byte in it is loss.
func TestClaimJournalSnapshotIsCommittedWhole(t *testing.T) {
	state := t.TempDir()
	var mu sync.Mutex
	var events []string
	record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	var o claimJournalOptions
	o.disk.syncFile = func(f *os.File) error {
		record("fsync " + filepath.Base(filepath.Dir(f.Name())) + "/" + filepath.Base(f.Name()))
		return f.Sync()
	}
	o.disk.syncDir = func(d string) error { record("dirsync " + filepath.Base(d)); return claimJournalSyncDir(d) }
	o.disk.step = func(p string) {
		if p == "compact-start" || p == "compact-current-renamed" {
			record(p)
		}
	}
	j := openTestClaimJournal(t, state, o)
	mustClaimAppend(t, j, claimIDRange("o", 5)...)
	snapIDs := claimIDRange("s", 50)
	var snap []claimRecord
	for _, id := range snapIDs {
		snap = append(snap, testClaimRec(id))
	}
	if err := claimAck(t, j.compact(snap)); err != nil {
		t.Fatal(err)
	}
	_ = j.close()
	mu.Lock()
	var during []string
	in := false
	for _, e := range events {
		switch {
		case e == "compact-start":
			in = true
		case e == "compact-current-renamed":
			in = false
		case in:
			during = append(during, e)
		}
	}
	mu.Unlock()
	need := []string{"dirsync claims", "fsync gen-2/" + claimSegmentName(6), "fsync gen-2/" + claimManifestName,
		"fsync gen-2/" + claimHeadNames[0], "fsync gen-2/" + claimHeadNames[1], "fsync gen-2/" + claimJournalIDInGen, "dirsync gen-2", "fsync claims/" + claimCurrentName + ".tmp"}
	for _, n := range need {
		found := false
		for _, e := range during {
			found = found || e == n
		}
		if !found {
			t.Fatalf("%q did not happen before the CURRENT rename: %v", n, during)
		}
	}
	if got := claimReplayIDs(t, state); !claimSame(got, snapIDs) {
		t.Fatalf("replay %v", got)
	}
	p := claimSegPath(t, state, 0)
	raw, _ := os.ReadFile(p)
	_ = os.WriteFile(p, bytes.Replace(raw, []byte(`"id":"s25"`), []byte(`"id":"x25"`), 1), 0o600)
	requireClaimIncomplete(t, state)
}

// A crash in the middle of a write leaves a torn last line. Open skips and
// logs it, keeps the records before it, and never appends after it.
func TestClaimJournalTornLineSkipped(t *testing.T) {
	cases := []struct{ name, tail string }{
		{"part of a line", `{"schema":"cathedral_claim_record_v1","seq":6,"pr`},
		{"a whole record without its newline", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := t.TempDir()
			j := openTestClaimJournal(t, state, claimJournalOptions{})
			ids := claimIDRange("r", 5)
			mustClaimAppend(t, j, ids...)
			_ = j.close()
			torn := claimSegPath(t, state, -1)
			tail := []byte(c.tail)
			if c.tail == "" {
				raw, _ := os.ReadFile(torn)
				sc := scanClaimSegment("seg", raw, 0, false)
				last := sc.lines[len(sc.lines)-1]
				line, _ := appendClaimLine(nil, last.Seq+1, last.hash, "test", []byte(`{"id":"torn"}`))
				tail = bytes.TrimSuffix(line, []byte("\n"))
			}
			f, err := os.OpenFile(torn, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.Write(tail)
			_ = f.Close()

			var logs bytes.Buffer
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(os.Stderr) })
			j2 := openTestClaimJournal(t, state, claimJournalOptions{})
			log.SetOutput(os.Stderr)
			if got := claimIDsOf(t, j2); !claimSame(got, ids) {
				t.Fatalf("replay %v, want %v", got, ids)
			}
			if !strings.Contains(logs.String(), "torn last line skipped") {
				t.Fatalf("the torn line was not logged: %s", logs.String())
			}
			mustClaimAppend(t, j2, "r05")
			_ = j2.close()
			if got := claimReplayIDs(t, state); !claimSame(got, append(ids, "r05")) {
				t.Fatalf("after one more record: %v", got)
			}
			man := readClaimManifestFile(t, state)
			if len(man.Segments) != 2 || !man.Segments[0].Closed {
				t.Fatalf("the record after the torn line did not go to a new segment: %+v", man.Segments)
			}
			if raw, _ := os.ReadFile(torn); !bytes.HasSuffix(raw, tail) {
				t.Fatal("something was appended after the torn line")
			}
		})
	}
}

// A new segment takes no record until its directory has synced and the
// manifest lists it; a directory the journal makes is synced into its
// parent, top down, before any file goes into it.
func TestClaimJournalNewFileWaitsForDirSync(t *testing.T) {
	t.Run("a new segment waits for its directory", func(t *testing.T) {
		state := t.TempDir()
		gen := filepath.Join(state, claimJournalDirName, claimGenName(1))
		var failing atomic.Bool
		var o claimJournalOptions
		o.disk.syncDir = func(d string) error {
			if failing.Load() && d == gen {
				return errors.New("sync gen-1: input/output error")
			}
			return claimJournalSyncDir(d)
		}
		j := openTestClaimJournal(t, state, o)
		failing.Store(true)
		if err := claimAck(t, j.append(testClaimRec("refused"))); err == nil {
			t.Fatal("a record was acknowledged in a segment whose name is not durable")
		}
		segs, _ := filepath.Glob(filepath.Join(gen, "*.jsonl"))
		if len(segs) != 1 {
			t.Fatalf("segments %v, want the one new file", segs)
		}
		if info, _ := os.Stat(segs[0]); info.Size() != 0 {
			t.Fatalf("the new segment took %d bytes before its directory synced", info.Size())
		}
		if man := readClaimManifestFile(t, state); len(man.Segments) != 0 {
			t.Fatalf("the manifest lists a segment whose name is not durable: %+v", man.Segments)
		}
		failing.Store(false)
		mustClaimAppend(t, j, "kept")
		_ = j.close()
		if got := claimReplayIDs(t, state); !claimSame(got, []string{"kept"}) {
			t.Fatalf("replay %v", got)
		}
	})

	t.Run("a new segment is listed before it takes a record", func(t *testing.T) {
		state := t.TempDir()
		var unlisted, writes atomic.Int64
		o := claimJournalOptions{segmentMax: 300}
		o.disk.write = func(f *os.File, p []byte) error {
			raw, err := os.ReadFile(filepath.Join(filepath.Dir(f.Name()), claimManifestName))
			if err != nil {
				return err
			}
			var m claimManifest
			if err := json.Unmarshal(raw, &m); err != nil {
				return err
			}
			listed := false
			for _, s := range m.Segments {
				listed = listed || (s.Name == filepath.Base(f.Name()) && !s.Closed)
			}
			if !listed {
				unlisted.Add(1)
			}
			writes.Add(1)
			_, err = f.Write(p)
			return err
		}
		j := openTestClaimJournal(t, state, o)
		mustClaimAppend(t, j, claimIDRange("x", 20)...)
		_ = j.close()
		if n := len(readClaimManifestFile(t, state).Segments); n < 4 {
			t.Fatalf("%d segments; the test needs rolls", n)
		}
		if unlisted.Load() != 0 {
			t.Fatalf("%d of %d writes went into a segment the manifest on disk did not list", unlisted.Load(), writes.Load())
		}
	})

	t.Run("a new state_dir syncs every new ancestor top down", func(t *testing.T) {
		base := t.TempDir()
		state := filepath.Join(base, "a", "b")
		var o claimJournalOptions
		o.disk.syncDir = func(d string) error {
			if d == filepath.Join(base, "a") {
				return errors.New("sync a: input/output error")
			}
			return claimJournalSyncDir(d)
		}
		if _, _, err := openClaimJournalWith(state, o); err == nil {
			t.Fatal("opened with a new ancestor not durable")
		}
		if _, err := os.Stat(filepath.Join(state, claimJournalIDName)); err == nil {
			t.Fatal("claims.id was written although its directory is not durable")
		}
		if entries, _ := os.ReadDir(filepath.Join(state, claimJournalDirName)); len(entries) != 0 {
			t.Fatalf("files were written into claims/ although it is not durable: %v", entries)
		}

		base = t.TempDir()
		state = filepath.Join(base, "a", "b")
		var synced []string
		early := map[string]bool{} // first synced while claims/ already held a file
		o.disk.syncDir = func(d string) error {
			if _, seen := early[d]; !seen {
				entries, _ := os.ReadDir(filepath.Join(state, claimJournalDirName))
				early[d] = len(entries) != 0
			}
			synced = append(synced, d)
			return claimJournalSyncDir(d)
		}
		j := openTestClaimJournal(t, state, o)
		_ = j.close()
		at := map[string]int{}
		for i, d := range synced {
			if _, ok := at[d]; !ok {
				at[d] = i
			}
		}
		want := []string{base, filepath.Join(base, "a"), state}
		for i, d := range want {
			n, ok := at[d]
			if !ok || early[d] || (i > 0 && n < at[want[i-1]]) {
				t.Fatalf("synced %v (with a file already in claims/: %v), want %v top down before any file", synced, early, want)
			}
		}
	})
}

// compact replaces every record appended before the call with the snapshot;
// records appended after it wait for it and go into the new generation.
func TestClaimJournalCompactionKeepsLiveRecords(t *testing.T) {
	state := t.TempDir()
	var mu sync.Mutex
	var steps []string
	var armed atomic.Bool
	started, hold := make(chan struct{}), make(chan struct{})
	o := claimJournalOptions{segmentMax: 400}
	o.disk.step = func(p string) {
		if !strings.HasPrefix(p, "compact") {
			return
		}
		mu.Lock()
		steps = append(steps, p)
		mu.Unlock()
		if p == "compact-start" && armed.Load() {
			close(started)
			<-hold
		}
	}
	j := openTestClaimJournal(t, state, o)
	mustClaimAppend(t, j, claimIDRange("o", 20)...)
	before := j.append(testClaimRec("o20")) // before the call: the snapshot stands for it
	armed.Store(true)
	done := j.compact([]claimRecord{testClaimRec("s0"), testClaimRec("s1")})
	<-started
	var after []<-chan error
	for _, id := range []string{"n0", "n1", "n2"} {
		after = append(after, j.append(testClaimRec(id)))
	}
	select {
	case <-after[0]:
		t.Fatal("a record queued behind a compaction was answered before it ran")
	default:
	}
	close(hold)
	for _, ch := range append([]<-chan error{before, done}, after...) {
		if err := claimAck(t, ch); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(state, claimJournalDirName, claimGenName(1))); err == nil {
		t.Fatal("gen-1 is still there")
	}
	if gen := filepath.Base(claimGenDir(t, state)); gen != claimGenName(2) {
		t.Fatalf("CURRENT names %s", gen)
	}
	_ = j.close()
	if got := claimReplayIDs(t, state); !claimSame(got, []string{"s0", "s1", "n0", "n1", "n2"}) {
		t.Fatalf("replay %v", got)
	}
	want := []string{"compact-start", "compact-gen-dir", "compact-segment", "compact-manifest", "compact-ack-head-a", "compact-ack-head-b",
		"compact-journal-id", "compact-gen-synced", "compact-current-created", "compact-current-synced", "compact-current-renamed",
		"compact-current-committed", "compact-removed", "compact-done"}
	mu.Lock()
	defer mu.Unlock()
	var got []string
	for _, p := range steps {
		if p == "compact-removed" && len(got) > 0 && got[len(got)-1] == p {
			continue
		}
		got = append(got, p)
	}
	if !claimSame(got, want) {
		t.Fatalf("steps %v\nwant  %v", steps, want)
	}
}

// No disk I/O happens under the journal's mutex: while an fsync hangs,
// append still returns at once, and the caller's own deadline is what bounds
// its wait.
func TestClaimJournalHungDiskBlocksNoAppend(t *testing.T) {
	hang, entered := make(chan struct{}), make(chan struct{}, 1)
	var once sync.Once
	release := func() { once.Do(func() { close(hang) }) }
	var o claimJournalOptions
	o.disk.sync = func(f *os.File) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-hang
		return f.Sync()
	}
	j := openTestClaimJournal(t, t.TempDir(), o)
	t.Cleanup(release)
	first := j.append(testClaimRec("first"))
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the first batch never reached its fsync")
	}
	queued := make(chan []<-chan error, 1)
	go func() {
		var chs []<-chan error
		for _, id := range claimIDRange("q", 100) {
			chs = append(chs, j.append(testClaimRec(id)))
		}
		queued <- chs
	}()
	var chs []<-chan error
	select {
	case chs = <-queued:
	case <-time.After(2 * time.Second):
		t.Fatal("append blocked while an fsync hangs")
	}
	select {
	case err := <-first:
		t.Fatalf("answered (%v) while its fsync hangs", err)
	case <-time.After(50 * time.Millisecond): // the caller's own deadline
	}
	release()
	for _, ch := range append(chs, first) {
		if err := claimAck(t, ch); err != nil {
			t.Fatal(err)
		}
	}
}

func TestClaimJournalRefusesBadRecordsAndAfterClose(t *testing.T) {
	state := t.TempDir()
	j := openTestClaimJournal(t, state, claimJournalOptions{})
	for _, r := range []claimRecord{
		{Kind: ""},
		{Kind: "Won"},
		{Kind: "journal_void"},
		{Kind: "won", Body: json.RawMessage(`{"a":`)},
		{Kind: "won", Body: json.RawMessage(`{} {}`)},
		{Kind: "won", Body: json.RawMessage(`"` + strings.Repeat("x", claimRecordMaxBytes) + `"`)},
	} {
		if err := claimAck(t, j.append(r)); err == nil {
			t.Fatalf("accepted %q with a body of %d bytes", r.Kind, len(r.Body))
		}
	}
	// A body spread over lines is stored on one line.
	if err := claimAck(t, j.append(claimRecord{Kind: "test", Body: json.RawMessage("{\n  \"id\": \"multi\"\n}")})); err != nil {
		t.Fatal(err)
	}
	if err := claimAck(t, j.compact([]claimRecord{{Kind: "journal_x"}})); err == nil {
		t.Fatal("a snapshot with a journal kind was accepted")
	}
	_ = j.close()
	if err := claimAck(t, j.append(testClaimRec("late"))); !errors.Is(err, errClaimJournalClosed) {
		t.Fatalf("append after close: %v", err)
	}
	j2 := openTestClaimJournal(t, state, claimJournalOptions{})
	if got := claimIDsOf(t, j2); !claimSame(got, []string{"multi"}) {
		t.Fatalf("replay %v", got)
	}
	if err := j2.replay(func(claimRecord) error { return nil }); err == nil {
		t.Fatal("replay ran twice")
	}
}

func claimPercentiles(ds []time.Duration) (p50, p95, mx time.Duration) {
	if len(ds) == 0 {
		return 0, 0, 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(a, b int) bool { return s[a] < s[b] })
	at := func(p float64) time.Duration {
		i := int(math.Ceil(p*float64(len(s)))) - 1
		return s[max(0, min(i, len(s)-1))]
	}
	return at(0.50), at(0.95), s[len(s)-1]
}

// The time a batch spends in write, queue, segment fsync and head file, and a
// compaction's, on this machine's disk. A Mac number when run on a Mac (Go's
// fsync there is F_FULLFSYNC), not the production broker's disk: work order
// M3 measures that one.
func TestClaimJournalTimingOnThisDisk(t *testing.T) {
	var mu sync.Mutex
	var batches, compactions []claimJournalTiming
	o := claimJournalOptions{observe: func(tm claimJournalTiming) {
		mu.Lock()
		defer mu.Unlock()
		if tm.Compaction {
			compactions = append(compactions, tm)
		} else {
			batches = append(batches, tm)
		}
	}}
	j := openTestClaimJournal(t, t.TempDir(), o)
	body := func(id string) claimRecord {
		return claimRecord{Kind: "won", Body: json.RawMessage(`{"id":"` + id + `","pad":"` + strings.Repeat("x", 2960) + `"}`)}
	}
	label := fmt.Sprintf("%s/%s number", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "darwin" {
		label = "Mac number (darwin/" + runtime.GOARCH + ", F_FULLFSYNC)"
	}
	report := func(what string) {
		mu.Lock()
		bs := batches
		batches = nil
		mu.Unlock()
		var q, w, s, h, r, recs []time.Duration
		var bytesTotal int
		for _, b := range bs {
			if b.Err != nil {
				t.Fatalf("batch failed: %v", b.Err)
			}
			q, w, s, h, r = append(q, b.QueueMax), append(w, b.Write), append(s, b.Sync), append(h, b.Head), append(r, b.Roll)
			recs = append(recs, time.Duration(b.Records))
			bytesTotal += b.Bytes
		}
		line := func(name string, ds []time.Duration) string {
			p50, p95, mx := claimPercentiles(ds)
			return fmt.Sprintf("%s p50 %v p95 %v max %v", name, p50.Round(time.Microsecond), p95.Round(time.Microsecond), mx.Round(time.Microsecond))
		}
		r50, _, rmx := claimPercentiles(recs)
		t.Logf("claim journal timing, %s, this machine's disk, not the production broker's (M3): %s: %d batches, %d bytes, records per batch p50 %d max %d\n  %s\n  %s\n  %s\n  %s\n  %s",
			label, what, len(bs), bytesTotal, int(r50), int(rmx),
			line("queue (oldest record)", q), line("write", w), line("segment fsync", s), line("head-file write+fsync", h), line("roll", r))
	}
	for i := 0; i < 200; i++ {
		if err := claimAck(t, j.append(body(fmt.Sprintf("one%04d", i)))); err != nil {
			t.Fatal(err)
		}
	}
	report("1 in flight, 200 appends of 3 KB")
	var wg sync.WaitGroup
	for g := 0; g < 100; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if err := <-j.append(body(fmt.Sprintf("many%03d-%d", g, i))); err != nil {
					t.Error(err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	report("100 in flight, 1,000 appends of 3 KB")
	snap := make([]claimRecord, 1000)
	for i := range snap {
		snap[i] = body(fmt.Sprintf("snap%04d", i))
	}
	if err := claimAck(t, j.compact(snap)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	c := compactions[len(compactions)-1]
	mu.Unlock()
	t.Logf("claim journal timing, %s: compaction to a new generation of 1,000 records (%d bytes, replacing 1,200 records): %v",
		label, j.size(), c.Total.Round(time.Microsecond))
}

// Codex review finding 1 on #655: once CURRENT names generation N+1, no
// record is ever acknowledged in generation N. A failure at each step of
// adopting the new generation around the CURRENT rename: appends after it
// either fail or go into the generation CURRENT names, and a reopen replays
// every acknowledged record once.
func TestClaimJournalNoAckInOldGenerationAfterCommit(t *testing.T) {
	type outcome int
	const (
		oldGen  outcome = iota // CURRENT still names gen-1; appends go there
		newGen                 // CURRENT names gen-2; appends go there
		stopped                // CURRENT cannot be read back; every append fails
	)
	injected := errors.New("injected: input/output error")
	cases := []struct {
		name string
		set  func(o *claimJournalOptions, state string, armed *atomic.Bool, release <-chan struct{})
		want outcome
		// blocked: appends fail until release is closed, then go to the new generation
		blocked bool
	}{
		{name: "the new generation's ack-head-a cannot be opened", want: oldGen, set: func(o *claimJournalOptions, state string, armed *atomic.Bool, _ <-chan struct{}) {
			o.disk.open = func(path string, flag int, perm os.FileMode) (*os.File, error) {
				if armed.Load() && strings.HasSuffix(path, claimGenName(2)+"/"+claimHeadNames[0]) {
					return nil, injected
				}
				return os.OpenFile(path, flag, perm)
			}
		}},
		{name: "the new generation's ack-head-b cannot be opened", want: oldGen, set: func(o *claimJournalOptions, state string, armed *atomic.Bool, _ <-chan struct{}) {
			o.disk.open = func(path string, flag int, perm os.FileMode) (*os.File, error) {
				if armed.Load() && strings.HasSuffix(path, claimGenName(2)+"/"+claimHeadNames[1]) {
					return nil, injected
				}
				return os.OpenFile(path, flag, perm)
			}
		}},
		{name: "the CURRENT rename fails", want: oldGen, set: func(o *claimJournalOptions, state string, armed *atomic.Bool, _ <-chan struct{}) {
			o.disk.rename = func(oldpath, newpath string) error {
				if armed.Load() && filepath.Base(newpath) == claimCurrentName {
					return injected
				}
				return os.Rename(oldpath, newpath)
			}
		}},
		{name: "the CURRENT rename happens but reports an error", want: newGen, set: func(o *claimJournalOptions, state string, armed *atomic.Bool, _ <-chan struct{}) {
			o.disk.rename = func(oldpath, newpath string) error {
				if err := os.Rename(oldpath, newpath); err != nil {
					return err
				}
				if armed.Load() && filepath.Base(newpath) == claimCurrentName {
					return injected
				}
				return nil
			}
		}},
		{name: "claims/ cannot be synced once after the rename", want: newGen, set: func(o *claimJournalOptions, state string, armed *atomic.Bool, _ <-chan struct{}) {
			claims := filepath.Join(state, claimJournalDirName)
			var failedOnce atomic.Bool
			o.disk.syncDir = func(d string) error {
				if armed.Load() && d == claims && !failedOnce.Load() {
					if _, err := readClaimText(filepath.Join(claims, claimCurrentName)); err == nil {
						if cur, _ := readClaimText(filepath.Join(claims, claimCurrentName)); cur == claimGenName(2) {
							failedOnce.Store(true)
							return injected
						}
					}
				}
				return claimJournalSyncDir(d)
			}
		}},
		{name: "claims/ cannot be synced after the rename until it heals", want: newGen, blocked: true, set: func(o *claimJournalOptions, state string, armed *atomic.Bool, release <-chan struct{}) {
			claims := filepath.Join(state, claimJournalDirName)
			o.disk.syncDir = func(d string) error {
				if armed.Load() && d == claims {
					if cur, _ := readClaimText(filepath.Join(claims, claimCurrentName)); cur == claimGenName(2) {
						select {
						case <-release:
						default:
							return injected
						}
					}
				}
				return claimJournalSyncDir(d)
			}
		}},
		{name: "the rename reports an error and CURRENT cannot be read back", want: stopped, set: func(o *claimJournalOptions, state string, armed *atomic.Bool, _ <-chan struct{}) {
			o.disk.rename = func(oldpath, newpath string) error {
				if err := os.Rename(oldpath, newpath); err != nil {
					return err
				}
				if armed.Load() && filepath.Base(newpath) == claimCurrentName {
					_ = os.Chmod(newpath, 0)
					return injected
				}
				return nil
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state := t.TempDir()
			current := filepath.Join(state, claimJournalDirName, claimCurrentName)
			t.Cleanup(func() { _ = os.Chmod(current, 0o600) })
			var armed atomic.Bool
			release := make(chan struct{})
			var o claimJournalOptions
			c.set(&o, state, &armed, release)
			j, _, err := openClaimJournalWith(state, o)
			if err != nil {
				t.Fatal(err)
			}
			old := claimIDRange("o", 5)
			mustClaimAppend(t, j, old...)
			armed.Store(true)
			if err := claimAck(t, j.compact([]claimRecord{testClaimRec("s0"), testClaimRec("s1")})); err == nil {
				t.Fatal("the compaction reported success")
			}
			var acked []string
			for i := 0; i < 3; i++ {
				id := fmt.Sprintf("x%02d", i)
				err := claimAck(t, j.append(testClaimRec(id)))
				switch {
				case err == nil && (c.want == stopped || c.blocked):
					t.Fatalf("%s was acknowledged although the writer may not know the live generation", id)
				case err == nil:
					acked = append(acked, id)
				case c.want != stopped && !c.blocked:
					t.Fatalf("%s: %v", id, err)
				}
			}
			if c.blocked {
				close(release)
				mustClaimAppend(t, j, "x10")
				acked = append(acked, "x10")
			}
			_ = j.close()
			_ = os.Chmod(current, 0o600)
			cur, _ := readClaimText(current)
			var want []string
			switch c.want {
			case oldGen:
				if cur != claimGenName(1) {
					t.Fatalf("CURRENT names %s, want gen-1", cur)
				}
				want = append(append([]string(nil), old...), acked...)
			default:
				if cur != claimGenName(2) {
					t.Fatalf("CURRENT names %s, want gen-2", cur)
				}
				want = append([]string{"s0", "s1"}, acked...)
			}
			if len(acked) > 0 {
				var onDisk []byte
				segs, _ := filepath.Glob(filepath.Join(state, claimJournalDirName, cur, "*.jsonl"))
				for _, s := range segs {
					raw, _ := os.ReadFile(s)
					onDisk = append(onDisk, raw...)
				}
				for _, id := range acked {
					if !bytes.Contains(onDisk, []byte(`"id":"`+id+`"`)) {
						t.Fatalf("acknowledged %s is not in %s, the generation CURRENT names", id, cur)
					}
				}
			}
			if got := claimReplayIDs(t, state); !claimSame(got, want) {
				t.Fatalf("replay %v\nwant   %v", got, want)
			}
			requireClaimTidy(t, state)
		})
	}
}

// Codex review finding 2 on #655: an initialization whose ancestor sync
// failed leaves the directories in place; the next open must sync that
// ancestor again before it accepts a record.
func TestClaimJournalInitRetrySyncsAncestors(t *testing.T) {
	base := t.TempDir()
	a := filepath.Join(base, "a")
	state := filepath.Join(a, "b")
	o := claimJournalOptions{}
	o.disk.syncDir = func(d string) error {
		if d == a {
			return errors.New("sync a: input/output error")
		}
		return claimJournalSyncDir(d)
	}
	if _, _, err := openClaimJournalWith(state, o); err == nil {
		t.Fatal("the first open succeeded with an ancestor not durable")
	}
	if _, err := os.Stat(filepath.Join(state, claimJournalDirName)); err != nil {
		t.Fatalf("the first attempt should have left its directories: %v", err)
	}
	var mu sync.Mutex
	var synced []string
	o.disk.syncDir = func(d string) error {
		mu.Lock()
		synced = append(synced, d)
		mu.Unlock()
		return claimJournalSyncDir(d)
	}
	j, _, err := openClaimJournalWith(state, o)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	before := append([]string(nil), synced...)
	mu.Unlock()
	mustClaimAppend(t, j, "first")
	_ = j.close()
	at := func(d string) int {
		for i, s := range before {
			if s == d {
				return i
			}
		}
		return -1
	}
	if at(a) < 0 || at(base) < 0 || at(state) < 0 || !(at(base) < at(a) && at(a) < at(state)) {
		t.Fatalf("the second open synced %v before its first acknowledgement; want %s, %s, %s top down", before, base, a, state)
	}
}

// Codex review finding 3 on #655: after a compaction's CURRENT rename whose
// claims/ sync did not run, the next open must sync claims/ before it removes
// the generation the visible CURRENT makes obsolete, and before it
// acknowledges a record in the new one.
func TestClaimJournalOpenSyncsCurrentBeforeRemovingOldGeneration(t *testing.T) {
	state := t.TempDir()
	claims := filepath.Join(state, claimJournalDirName)
	crash := newClaimCrash("compact-current-renamed", 1)
	j, _, err := openClaimJournalWith(state, claimJournalOptions{disk: claimJournalDisk{step: crash.step}})
	if err != nil {
		t.Fatal(err)
	}
	mustClaimAppend(t, j, claimIDRange("o", 4)...)
	crash.armed.Store(true)
	done := j.compact([]claimRecord{testClaimRec("s0")})
	crash.wait(t) // CURRENT names gen-2 in the page cache; claims/ never synced
	select {
	case err := <-done:
		t.Fatalf("the compaction answered (%v) although its writer stopped", err)
	default:
	}
	old := filepath.Join(claims, claimGenName(1))
	var mu sync.Mutex
	firstSync, oldThen := false, false
	var o claimJournalOptions
	o.disk.syncDir = func(d string) error {
		mu.Lock()
		if d == claims && !firstSync {
			firstSync = true
			_, err := os.Stat(old)
			oldThen = err == nil
		}
		mu.Unlock()
		return claimJournalSyncDir(d)
	}
	j2 := openTestClaimJournal(t, state, o)
	mustClaimAppend(t, j2, "after")
	_ = j2.close()
	mu.Lock()
	defer mu.Unlock()
	if !firstSync || !oldThen {
		t.Fatalf("open removed gen-1 before it synced claims/ (synced: %v, gen-1 still there at that sync: %v)", firstSync, oldThen)
	}
	if _, err := os.Stat(old); err == nil {
		t.Fatal("gen-1 was not removed as obsolete")
	}
	if got := claimReplayIDs(t, state); !claimSame(got, []string{"s0", "after"}) {
		t.Fatalf("replay %v", got)
	}
}

// Codex review finding 4 on #655: an initialization whose claims.id rename
// landed but whose state_dir sync failed leaves a valid claims.id; the next
// open must sync state_dir before it acknowledges a record.
func TestClaimJournalOpenSyncsClaimsIDBeforeAcknowledging(t *testing.T) {
	state := t.TempDir()
	o := claimJournalOptions{}
	o.disk.syncDir = func(d string) error {
		if d == state {
			if _, err := os.Stat(filepath.Join(state, claimJournalIDName)); err == nil {
				return errors.New("sync state_dir: input/output error")
			}
		}
		return claimJournalSyncDir(d)
	}
	if _, _, err := openClaimJournalWith(state, o); err == nil {
		t.Fatal("the first open succeeded although claims.id's name is not durable")
	}
	if id, err := readClaimText(filepath.Join(state, claimJournalIDName)); err != nil || !claimIDRE.MatchString(id) {
		t.Fatalf("the first attempt should have left a valid claims.id: %q, %v", id, err)
	}
	var mu sync.Mutex
	syncedState := false
	o.disk.syncDir = func(d string) error {
		mu.Lock()
		if d == state {
			syncedState = true
		}
		mu.Unlock()
		return claimJournalSyncDir(d)
	}
	j, _, err := openClaimJournalWith(state, o)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	before := syncedState
	mu.Unlock()
	mustClaimAppend(t, j, "first")
	_ = j.close()
	if !before {
		t.Fatal("the second open acknowledged records without syncing state_dir, claims.id's directory")
	}
}
