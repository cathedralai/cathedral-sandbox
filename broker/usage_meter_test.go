package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// Usage meter (usage_meter.go). The meter tests drive the meter with a fake
// clock through the calls syncHotel and the create and delete hooks make;
// the chain tests check that wiring against fake hotels.

var usageMeterT0 = time.Unix(1_800_000_000, 0)

func at(sec float64) time.Time { return usageMeterT0.Add(time.Duration(sec * float64(time.Second))) }

func testUsageMeter(t *testing.T, dir string, every int64) *usageMeter {
	t.Helper()
	m, err := openUsageMeter(dir, every, usageMeterT0)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func sighting(run string) usageSighting {
	return usageSighting{run: run, guest: "g1", hotel: strings.Split(run, ".")[0], vcpu: 2, memGiB: 4, billable: true}
}

// listPass is one sync pass of hotel "h": the list shows runs listed, and
// the room map holds listed plus present.
func listPass(m *usageMeter, when time.Time, listed []string, present ...string) {
	var ss []usageSighting
	p := map[string]bool{}
	for _, run := range listed {
		ss = append(ss, sighting(run))
		p[run] = true
	}
	for _, run := range present {
		p[run] = true
	}
	m.hotelPass("h", ss, p, when, true, true, false)
}

func mustFlush(t *testing.T, m *usageMeter) {
	t.Helper()
	if err := m.flush(); err != nil {
		t.Fatal(err)
	}
}

// logReadings reads every reading in dir in file order and fails on a seq
// that repeats or goes back.
func logReadings(t *testing.T, dir string) []usageReading {
	t.Helper()
	m := &usageMeter{dir: dir}
	files, err := m.files()
	if err != nil {
		t.Fatal(err)
	}
	var out []usageReading
	for _, f := range files {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.SplitAfter(string(raw), "\n") {
			if !strings.HasSuffix(line, "\n") {
				continue // torn
			}
			var r usageReading
			if json.Unmarshal([]byte(line), &r) != nil {
				continue
			}
			if len(out) > 0 && r.Seq <= out[len(out)-1].Seq {
				t.Fatalf("seq %d after %d in %s", r.Seq, out[len(out)-1].Seq, f.path)
			}
			out = append(out, r)
		}
	}
	return out
}

func readingsOf(rs []usageReading, run string) []usageReading {
	var out []usageReading
	for _, r := range rs {
		if r.Run == run {
			out = append(out, r)
		}
	}
	return out
}

func wantSeqs(t *testing.T, rs []usageReading, n int) {
	t.Helper()
	if len(rs) != n {
		t.Fatalf("%d readings, want %d", len(rs), n)
	}
	for i, r := range rs {
		if r.Seq != int64(i+1) {
			t.Fatalf("reading %d has seq %d, want %d", i, r.Seq, i+1)
		}
	}
}

// Rooms that live 5 to 55 s, created and gone between sync passes, all get a
// first reading (seconds 0) and one ended reading with their exact observed
// seconds. Even rooms end by the broker's confirmed delete (the hook adds
// the tail since the last list); odd rooms vanish and the room map drops
// them 4 s later (only listed time counts).
func TestUsageMeterChurnMetersEveryRoom(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	type room struct {
		run           string
		created, died float64
		deleted       bool
	}
	var rooms []room
	for i := 0; i <= 50; i++ {
		c := 0.3 + 1.7*float64(i)
		rooms = append(rooms, room{run: fmt.Sprintf("h.sbx_%d", i), created: c, died: c + float64(5+i), deleted: i%2 == 0})
	}
	type event struct {
		when float64
		kind int // 0 create, 1 delete, 2 pass
		i    int
	}
	var events []event
	for i, r := range rooms {
		events = append(events, event{r.created, 0, i})
		if r.deleted {
			events = append(events, event{r.died, 1, i})
		}
	}
	for p := 0.0; p <= 200; p += 2 {
		events = append(events, event{p, 2, -1})
	}
	sort.SliceStable(events, func(a, b int) bool { return events[a].when < events[b].when })
	for _, e := range events {
		switch e.kind {
		case 0:
			m.seen(sighting(rooms[e.i].run), at(e.when))
		case 1:
			m.end(rooms[e.i].run, at(e.when), true)
		case 2:
			var listed, held []string
			for _, r := range rooms {
				if r.created <= e.when && e.when < r.died {
					listed = append(listed, r.run)
				} else if r.created <= e.when && e.when < r.died+4 {
					held = append(held, r.run)
				}
			}
			listPass(m, at(e.when), listed, held...)
		}
	}
	mustFlush(t, m)
	all := logReadings(t, dir)
	wantSeqs(t, all, 2*len(rooms))
	for _, r := range rooms {
		got := readingsOf(all, r.run)
		if len(got) != 2 || got[0].State != "running" || got[0].Seconds != 0 || got[1].State != "ended" {
			t.Fatalf("%s: readings %+v", r.run, got)
		}
		// The delete hook counts up to the delete; a vanished room counts up
		// to the last pass that listed it.
		want := int64(at(r.died).Sub(at(r.created)) / time.Second)
		if !r.deleted {
			last := r.created
			for p := 0.0; p < r.died; p += 2 {
				if p >= r.created {
					last = p
				}
			}
			want = int64(at(last).Sub(at(r.created)) / time.Second)
		}
		if got[1].Seconds != want {
			t.Fatalf("%s (deleted=%v, life %.1f s): ended seconds %d, want %d", r.run, r.deleted, r.died-r.created, got[1].Seconds, want)
		}
		if got[0].StartedAt != at(r.created).Unix() || got[1].StartedAt != got[0].StartedAt {
			t.Fatalf("%s: started_at %d, %d, want %d", r.run, got[0].StartedAt, got[1].StartedAt, at(r.created).Unix())
		}
		if got[1].Guest != "g1" || got[1].Hotel != "h" || got[1].VCPU != 2 || got[1].MemoryGiB != 4 || got[1].Schema != usageReadingSchema {
			t.Fatalf("%s: reading %+v", r.run, got[1])
		}
	}
}

// A room shorter than the 2 s sync is metered by the create and delete
// hooks alone. A delete the hotel answers 404 (room already gone) adds no
// time; a confirmed one adds the time since the create.
func TestUsageMeterSubSyncRoomViaHooks(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	m.seen(sighting("h.a"), at(10.2))
	m.end("h.a", at(11.7), true)
	m.seen(sighting("h.b"), at(10.2))
	m.end("h.b", at(11.7), false)
	m.end("h.a", at(12), true) // a second delete: no second ended reading
	mustFlush(t, m)
	all := logReadings(t, dir)
	wantSeqs(t, all, 4)
	for run, want := range map[string]int64{"h.a": 1, "h.b": 0} {
		got := readingsOf(all, run)
		if len(got) != 2 || got[0].Seconds != 0 || got[1].State != "ended" || got[1].Seconds != want {
			t.Fatalf("%s: %+v, want ended at %d s", run, got, want)
		}
	}
}

// seq starts at 1, survives a restart and never repeats; a torn last line is
// skipped, and a new broker writes a new file after it.
func TestUsageMeterSeqSurvivesRestartAndSkipsTornLine(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	m.seen(sighting("h.a"), at(0))
	m.seen(sighting("h.b"), at(0))
	for p := 2.0; p <= 60; p += 2 {
		listPass(m, at(p), []string{"h.a", "h.b"})
	}
	mustFlush(t, m)
	torn := m.fname
	f, err := os.OpenFile(torn, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"schema":"cathedral_usage_reading_v1","seq":5,"run":"h.`)
	f.Close()

	m2 := testUsageMeter(t, dir, 60)
	if m2.head != 4 || m2.nextSeq != 5 || len(m2.runs) != 2 {
		t.Fatalf("after restart: head %d next %d runs %d, want 4, 5, 2", m2.head, m2.nextSeq, len(m2.runs))
	}
	if r := m2.runs["h.a"]; r.observed != 60*time.Second || r.last.StartedAt != usageMeterT0.Unix() {
		t.Fatalf("h.a replayed as %+v", r)
	}
	m2.seen(sighting("h.c"), at(100))
	mustFlush(t, m2)
	if m2.fname == torn {
		t.Fatal("the new broker appended to the file with the torn line")
	}
	m3 := testUsageMeter(t, dir, 60)
	if m3.head != 5 || m3.nextSeq != 6 {
		t.Fatalf("second restart: head %d next %d", m3.head, m3.nextSeq)
	}
	all := logReadings(t, dir)
	wantSeqs(t, all, 5)
	if all[2].Run != "h.a" || all[2].Seconds != 60 || all[4].Run != "h.c" || all[4].Seconds != 0 {
		t.Fatalf("readings %+v", all)
	}
	p, err := m3.page(0, 10, at(200))
	if err != nil || len(p.Readings) != 5 || p.Next != 5 || p.Head != 5 {
		t.Fatalf("page %+v err %v", p, err)
	}
}

// A file named for the next seq that holds only a torn line (a crash during
// its first append) is moved aside, not appended to.
func TestUsageMeterTornOnlyFileIsSetAside(t *testing.T) {
	dir := t.TempDir()
	name := filepath.Join(dir, fmt.Sprintf("%020d.jsonl", 1))
	if err := os.WriteFile(name, []byte(`{"schema":"cathedral_usage_rea`), 0o600); err != nil {
		t.Fatal(err)
	}
	m := testUsageMeter(t, dir, 60)
	m.seen(sighting("h.a"), at(0))
	mustFlush(t, m)
	all := logReadings(t, dir)
	wantSeqs(t, all, 1)
	aside, _ := filepath.Glob(name + ".torn-*")
	if len(aside) != 1 {
		t.Fatalf("set aside: %v", aside)
	}
}

// After a restart the run keeps its logged started_at and seconds; the
// downtime adds nothing, and time counts again from the first sighting.
func TestUsageMeterRestartContinuesFromLoggedSeconds(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 10)
	m.seen(sighting("h.a"), at(0))
	for p := 2.0; p <= 40; p += 2 {
		listPass(m, at(p), []string{"h.a"})
	}
	mustFlush(t, m)
	listPass(m, at(42), []string{"h.a"}) // observed, never written: the crash loses it
	// crash: m is dropped without a flush

	m2 := testUsageMeter(t, dir, 10)
	listPass(m2, at(300), []string{"h.a"}) // first sighting after the restart
	listPass(m2, at(302), []string{"h.a"})
	m2.end("h.a", at(305), true)
	mustFlush(t, m2)
	got := readingsOf(logReadings(t, dir), "h.a")
	// first, 10, 20, 30, 40 before; 40 at the first sighting, 45 at the end.
	want := []int64{0, 10, 20, 30, 40, 40, 45}
	if len(got) != len(want) {
		t.Fatalf("readings %+v", got)
	}
	for i, r := range got {
		if r.Seconds != want[i] || r.StartedAt != usageMeterT0.Unix() {
			t.Fatalf("reading %d: seconds %d started_at %d, want %d and %d", i, r.Seconds, r.StartedAt, want[i], usageMeterT0.Unix())
		}
	}
	if got[5].At != at(300).Unix() || got[6].State != "ended" {
		t.Fatalf("after restart: %+v", got[5:])
	}
}

// The broker is down when a room ends: the run ends at its logged seconds,
// and the time the broker did not see adds nothing.
func TestUsageMeterOutageSpanningRoomEnd(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 10)
	m.seen(sighting("h.a"), at(0))
	for p := 2.0; p <= 20; p += 2 {
		listPass(m, at(p), []string{"h.a"})
	}
	mustFlush(t, m)
	// The broker dies at 21; the room ends on the hotel at 50; the broker
	// is back at 80.
	m2 := testUsageMeter(t, dir, 10)
	m2.hotelPass("h", nil, nil, at(80), false, false, false) // the list does not answer yet: nothing ends
	if len(m2.runs) != 1 {
		t.Fatal("a failed first list ended the run")
	}
	listPass(m2, at(82), nil) // the list answers without the room
	mustFlush(t, m2)
	got := readingsOf(logReadings(t, dir), "h.a")
	last := got[len(got)-1]
	if last.State != "ended" || last.Seconds != 20 || last.At != at(82).Unix() {
		t.Fatalf("ended reading %+v, want 20 s at %d", last, at(82).Unix())
	}
}

// A hotel whose list fails stops the meter; the ended reading keeps the
// seconds of the last list that showed the room.
func TestUsageMeterHotelDownStopsTheMeter(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	m.seen(sighting("h.a"), at(0))
	for p := 2.0; p <= 20; p += 2 {
		listPass(m, at(p), []string{"h.a"})
	}
	for p := 22.0; p <= 120; p += 2 {
		m.hotelPass("h", nil, map[string]bool{"h.a": true}, at(p), false, true, false) // list fails; room map unchanged
	}
	if s := int64(m.runs["h.a"].observed / time.Second); s != 20 {
		t.Fatalf("seconds grew to %d while the hotel did not answer", s)
	}
	m.mu.Lock()
	obs, _ := m.observedAtLocked(at(120))
	m.mu.Unlock()
	if obs != at(20).Unix() {
		t.Fatalf("observed_at %d, want the last answered list %d", obs, at(20).Unix())
	}
	listPass(m, at(122), nil) // the hotel answers, the room is gone
	mustFlush(t, m)
	// The first reading (0 s) and the ended one (20 s): no sighting came
	// after 20 s, so no periodic reading either.
	got := readingsOf(logReadings(t, dir), "h.a")
	if len(got) != 2 || got[0].Seconds != 0 || got[1].State != "ended" || got[1].Seconds != 20 {
		t.Fatalf("readings %+v", got)
	}
}

// A room missing from one list and back within 30 s counts the gap; back
// after 60 s, the gap counts nothing.
func TestUsageMeterGapRule(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 600)
	m.seen(sighting("h.a"), at(0))
	listPass(m, at(10), []string{"h.a"})
	listPass(m, at(12), nil, "h.a") // missing from this list, still in the room map
	listPass(m, at(14), []string{"h.a"})
	listPass(m, at(40), []string{"h.a"}) // 26 s gap: counted
	listPass(m, at(100), []string{"h.a"})
	listPass(m, at(102), []string{"h.a"}) // 60 s gap before: excluded
	m.end("h.a", at(103), true)
	mustFlush(t, m)
	got := readingsOf(logReadings(t, dir), "h.a")
	if len(got) != 2 || got[1].Seconds != 40+2+1 {
		t.Fatalf("readings %+v, want ended at 43 s", got)
	}
}

// A failed append keeps the readings queued; the retry writes each once,
// with no seq used twice. Then a failure the file cannot take back burns
// the seqs instead of reusing them.
func TestUsageMeterAppendFailureRetriesWithoutLossOrDuplicate(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	m.seen(sighting("h.a"), at(0))
	mustFlush(t, m)
	fails := 2
	m.write = func(f *os.File, p []byte) error {
		if fails > 0 {
			fails--
			_, _ = f.Write(p[:len(p)/2]) // disk full halfway
			return errors.New("no space left on device")
		}
		return appendDurable(f, p)
	}
	m.seen(sighting("h.b"), at(1))
	m.seen(sighting("h.c"), at(1))
	for i := 0; i < 2; i++ {
		if err := m.flush(); err == nil {
			t.Fatal("flush did not report the failure")
		}
	}
	if len(m.pending) != 2 || m.head != 1 || m.writeErrors != 2 {
		t.Fatalf("after failures: pending %d head %d errors %d", len(m.pending), m.head, m.writeErrors)
	}
	p, _ := m.page(0, 10, at(2))
	if p.Head != 1 || len(p.Readings) != 1 || p.WriteErrors != 2 {
		t.Fatalf("page during failure %+v", p)
	}
	mustFlush(t, m)
	all := logReadings(t, dir)
	wantSeqs(t, all, 3)
	if all[1].Run != "h.b" || all[2].Run != "h.c" {
		t.Fatalf("readings %+v", all)
	}

	// The partial lines cannot be cut off: the file is closed and the seqs
	// are not reused.
	m.write = func(f *os.File, p []byte) error {
		_, _ = f.Write(p)
		_ = f.Close() // the truncate after this fails
		return errors.New("i/o error")
	}
	m.end("h.a", at(5), false)
	if err := m.flush(); err == nil {
		t.Fatal("flush did not report the failure")
	}
	m.write = appendDurable
	mustFlush(t, m)
	all = logReadings(t, dir)
	var seqs []int64
	for _, r := range all {
		seqs = append(seqs, r.Seq)
	}
	if fmt.Sprint(seqs) != "[1 2 3 4 5]" || all[3].Run != "h.a" || all[4].Run != "h.a" || all[4].State != "ended" {
		t.Fatalf("seqs %v readings %+v", seqs, all)
	}
	// Seq 4 may be on disk but was never made durable: the route skips it;
	// its reading is seq 5.
	p, _ = m.page(0, 10, at(6))
	var served []int64
	for _, raw := range p.Readings {
		var r usageReading
		_ = json.Unmarshal(raw, &r)
		served = append(served, r.Seq)
	}
	if fmt.Sprint(served) != "[1 2 3 5]" || p.Next != 5 || p.Head != 5 {
		t.Fatalf("served %v next %d head %d", served, p.Next, p.Head)
	}
	m2 := testUsageMeter(t, dir, 60)
	if m2.head != 5 || m2.ended["h.a"] == nil || m2.runs["h.a"] != nil {
		t.Fatalf("replay: head %d", m2.head)
	}
}

// writeTestReadings writes n readings, maxLines per file.
func writeTestReadings(t *testing.T, dir string, n, maxLines int) *usageMeter {
	t.Helper()
	m := testUsageMeter(t, dir, 60)
	m.maxLines = maxLines
	for i := 0; i < n; i++ {
		m.seen(sighting(fmt.Sprintf("h.r%d", i)), at(float64(i)))
		mustFlush(t, m)
	}
	return m
}

// A page smaller than what is there never skips a reading, across files;
// next and head are right.
func TestUsageMeterCursorNeverSkips(t *testing.T) {
	dir := t.TempDir()
	m := writeTestReadings(t, dir, 25, 7)
	if files, _ := m.files(); len(files) != 4 {
		t.Fatalf("%d files, want 4 of at most 7 lines", len(files))
	}
	after := int64(0)
	var got []int64
	for i := 0; i < 10; i++ {
		p, err := m.page(after, 4, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if p.Head != 25 {
			t.Fatalf("head %d", p.Head)
		}
		for _, raw := range p.Readings {
			var r usageReading
			_ = json.Unmarshal(raw, &r)
			got = append(got, r.Seq)
		}
		if len(p.Readings) == 0 {
			if p.Next != after {
				t.Fatalf("empty page: next %d, want after %d", p.Next, after)
			}
			break
		}
		var last usageReading
		_ = json.Unmarshal(p.Readings[len(p.Readings)-1], &last)
		if p.Next != last.Seq {
			t.Fatalf("next %d, last returned %d", p.Next, last.Seq)
		}
		after = p.Next
	}
	if len(got) != 25 {
		t.Fatalf("read %v", got)
	}
	for i, s := range got {
		if s != int64(i+1) {
			t.Fatalf("read %v", got)
		}
	}
	// after beyond head: nothing, next stays after.
	if p, _ := m.page(99, 4, time.Now()); len(p.Readings) != 0 || p.Next != 99 || p.Head != 25 {
		t.Fatalf("page after head %+v", p)
	}
}

// Pruning deletes a file only when every seq in it is acknowledged and it
// is older than 7 days; the cursor survives a restart, and an open run
// whose first reading was pruned keeps its state from a later reading.
func TestUsageMeterPruneRespectsCursorAndAge(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 10)
	m.maxLines = 5
	m.seen(sighting("h.live"), at(0)) // seq 1, in the first file
	mustFlush(t, m)
	for i := 1; i <= 9; i++ {
		m.seen(sighting(fmt.Sprintf("h.r%d", i)), at(float64(i)))
		mustFlush(t, m)
	}
	for p := 2.0; p <= 10; p += 2 {
		listPass(m, at(p), []string{"h.live"}, "h.r1", "h.r2", "h.r3", "h.r4", "h.r5", "h.r6", "h.r7", "h.r8", "h.r9")
	}
	mustFlush(t, m) // seq 11: h.live at 10 s, in the third file
	files, _ := m.files()
	if len(files) != 3 || files[0].first != 1 || files[1].first != 6 || files[2].first != 11 {
		t.Fatalf("files %+v", files)
	}
	old := time.Now().Add(-8 * 24 * time.Hour)
	for _, f := range files {
		_ = os.Chtimes(f.path, old, old)
	}
	now := time.Now()
	exists := func(f usageFile) bool { _, err := os.Stat(f.path); return err == nil }

	m.page(4, 10, now) // file 1 holds 5: not all acknowledged
	if !exists(files[0]) {
		t.Fatal("a file with an unacknowledged seq was pruned")
	}
	_ = os.Chtimes(files[1].path, now, now)
	m.page(10, 10, now) // files 1 and 2 acknowledged; file 2 is new
	if exists(files[0]) || !exists(files[1]) || !exists(files[2]) {
		t.Fatalf("after ack 10: %v %v %v", exists(files[0]), exists(files[1]), exists(files[2]))
	}
	// r1 to r4 are open and their only reading was in file 1: carried
	// forward as seqs 12 to 15 before the file went. h.live's newest
	// reading (seq 11) was not in it.
	if m.head != 15 {
		t.Fatalf("head %d after the carry forward, want 15", m.head)
	}
	for i, r := range logReadings(t, dir)[len(logReadings(t, dir))-4:] {
		if r.Seq != int64(12+i) || !strings.HasPrefix(r.Run, "h.r") || r.Run == "h.r5" || r.Seconds != 0 || r.State != "running" {
			t.Fatalf("carried reading %+v", r)
		}
	}
	m.page(500, 10, now) // capped at head (15); the newest file always stays
	if !exists(files[2]) || m.acked != 15 {
		t.Fatalf("newest file gone or acked %d", m.acked)
	}

	m2 := testUsageMeter(t, dir, 10)
	if m2.acked != 15 {
		t.Fatalf("acked after restart %d", m2.acked)
	}
	r := m2.runs["h.live"]
	if r == nil || r.observed != 10*time.Second || r.last.StartedAt != usageMeterT0.Unix() {
		t.Fatalf("open run after pruning its first file: %+v", r)
	}
}

// Through the broker: the create hook writes the first reading, the sync
// pass does not repeat it, the delete hook writes the ended reading, and the
// route serves them to the operator key only.
func TestUsageMeterBrokerHooksAndRoute(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	body := map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "resources": map[string]any{"vcpu": 2, "memory_gib": 8}}
	id := tc.room(t, "key1", body)
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+id, nil); status != 204 {
		t.Fatalf("delete: %d %v", status, doc)
	}
	mustFlush(t, tc.b.usageMeter)

	for _, key := range []string{"key1", "reader-key", "enroller-key", ""} {
		if status, doc := tc.call(t, key, "GET", "/v1/broker/usage-meter", nil); status != 401 {
			t.Fatalf("key %q: %d %v", key, status, doc)
		}
	}
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/usage-meter?after=0&limit=5000", nil)
	if status != 200 {
		t.Fatalf("route: %d %v", status, doc)
	}
	rs := doc["readings"].([]any)
	if len(rs) != 2 || doc["next"].(float64) != 2 || doc["head"].(float64) != 2 || doc["write_errors"].(float64) != 0 {
		t.Fatalf("page %v", doc)
	}
	first, ended := rs[0].(map[string]any), rs[1].(map[string]any)
	if first["run"] != id || first["guest"] != "g1" || first["hotel"] != "b" || first["state"] != "running" ||
		first["seconds"].(float64) != 0 || first["vcpu"].(float64) != 2 || first["memory_gib"].(float64) != 8 || first["miner_hotkey"] != "" {
		t.Fatalf("first reading %v", first)
	}
	if ended["run"] != id || ended["state"] != "ended" || ended["seconds"].(float64) != 0 || ended["started_at"] != first["started_at"] {
		t.Fatalf("ended reading %v", ended)
	}
	if obs := int64(doc["observed_at"].(float64)); obs < time.Now().Unix()-5 {
		t.Fatalf("observed_at %d with no live room", obs)
	}
	for _, q := range []string{"?limit=0", "?limit=x", "?after=-1", "?after=x"} {
		if status, _ := tc.call(t, "operator-key", "GET", "/v1/broker/usage-meter"+q, nil); status != 400 {
			t.Fatalf("%s: %d", q, status)
		}
	}
	if status, _ := tc.call(t, "operator-key", "POST", "/v1/broker/usage-meter", nil); status != 405 {
		t.Fatalf("POST: %d", status)
	}
	// After the delete the sync pass releases the room: no second ended.
	setHotel(tc, "b", func(h *hotel) {
		for _, rm := range h.rooms {
			rm.vanished = time.Now().Add(-time.Minute)
		}
	})
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	mustFlush(t, tc.b.usageMeter)
	if tc.b.usageMeter.head != 2 {
		t.Fatalf("head %d after the release, want 2", tc.b.usageMeter.head)
	}
}

// A room the hotel started whose first reading never reached the disk (the
// broker died first) is adopted by the next broker's sync and starts at
// that first sight.
func TestUsageMeterCrashBeforeFirstAppendStartsAtFirstSight(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	restart := time.Now().Unix()
	tc.start(t) // no flush: the queued first reading is lost
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	mustFlush(t, tc.b.usageMeter)
	p, err := tc.b.usageMeter.page(0, 10, time.Now())
	if err != nil || len(p.Readings) != 1 {
		t.Fatalf("page %+v err %v", p, err)
	}
	var r usageReading
	_ = json.Unmarshal(p.Readings[0], &r)
	if r.Run != id || r.Seq != 1 || r.Seconds != 0 || r.StartedAt < restart || r.Guest != "g1" || r.State != "running" {
		t.Fatalf("adopted reading %+v (restart at %d)", r, restart)
	}
}

// The sync loop adopts a room the log knows: it keeps the logged started_at
// and seconds, and the first sighting adds nothing.
func TestUsageMeterSyncAdoptionKeepsLoggedStart(t *testing.T) {
	state := t.TempDir()
	start := time.Now().Unix() - 3600
	seed := usageReading{Schema: usageReadingSchema, Seq: 1, Run: "b.sbx_1", Guest: "g1", Hotel: "b", VCPU: 1, MemoryGiB: 4, StartedAt: start, Seconds: 1200, State: "running", At: start + 1200}
	line, _ := json.Marshal(seed)
	if err := os.MkdirAll(filepath.Join(state, usageDirName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, usageDirName, fmt.Sprintf("%020d.jsonl", 1)), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	tc := newChainState(t, state)
	tc.hotels["b"].mu.Lock()
	tc.hotels["b"].rooms = append(tc.hotels["b"].rooms, map[string]any{"id": "sbx_1", "state": "running",
		"labels": map[string]any{guestLabel: "g1"}, "resources": map[string]any{"vcpu": 1, "memory_gib": 4}})
	tc.hotels["b"].mu.Unlock()
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	mustFlush(t, tc.b.usageMeter)
	p, _ := tc.b.usageMeter.page(1, 10, time.Now())
	if len(p.Readings) != 1 {
		t.Fatalf("page %+v", p)
	}
	var r usageReading
	_ = json.Unmarshal(p.Readings[0], &r)
	if r.Seq != 2 || r.Run != "b.sbx_1" || r.StartedAt != start || r.Seconds != 1200 || r.State != "running" {
		t.Fatalf("adopted reading %+v", r)
	}
	if run := tc.b.usageMeter.runs["b.sbx_1"]; run == nil || run.observed < 1200*time.Second || run.observed > 1203*time.Second {
		t.Fatalf("run %+v", run)
	}
}

// Without state_dir the meter is off: creates, deletes and sync passes work,
// and the route answers 404 usage_meter_off to the operator, 401 to others.
func TestUsageMeterOffWithoutStateDir(t *testing.T) {
	tc := newChain(t)
	if tc.b.usageMeter != nil {
		t.Fatal("a meter without state_dir")
	}
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+id, nil); status != 204 {
		t.Fatalf("delete: %d", status)
	}
	if err := tc.b.usageMeter.flush(); err != nil {
		t.Fatal(err)
	}
	tc.b.usageMeter.checkpoint(time.Now())
	if status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/usage-meter", nil); status != 404 || errCode(doc) != "usage_meter_off" {
		t.Fatalf("operator: %d %v", status, doc)
	}
	if status, _ := tc.call(t, "key1", "GET", "/v1/broker/usage-meter", nil); status != 401 {
		t.Fatalf("guest: %d", status)
	}
}

// A clean stop writes a reading for every run whose seconds grew, so a
// restart loses no observed time.
func TestUsageMeterCheckpointAtStop(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	m.seen(sighting("h.a"), at(0))
	m.seen(sighting("h.b"), at(0))
	for p := 2.0; p <= 30; p += 2 {
		listPass(m, at(p), []string{"h.a"}, "h.b")
	}
	m.checkpoint(at(31))
	mustFlush(t, m)
	all := logReadings(t, dir)
	if len(all) != 3 || all[2].Run != "h.a" || all[2].Seconds != 30 {
		t.Fatalf("readings %+v", all)
	}
}

func TestUsageMeterConfigRejectsNegativeEvery(t *testing.T) {
	b := &broker{cfg: config{UsageMeterEverySeconds: -1}}
	if err := b.loadUsageMeter(); err == nil {
		t.Fatal("a negative usage_meter_every_seconds was accepted")
	}
}

// The route caps limit at 1,000 and next is the last seq it returned.
func TestUsageMeterRouteCapsTheLimit(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	for i := 0; i < 1003; i++ {
		tc.b.usageMeter.seen(sighting(fmt.Sprintf("b.r%d", i)), time.Now())
	}
	mustFlush(t, tc.b.usageMeter)
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/usage-meter?limit=5000", nil)
	if status != 200 || len(doc["readings"].([]any)) != usagePageMax || doc["next"].(float64) != usagePageMax || doc["head"].(float64) != 1003 {
		t.Fatalf("page: %d next %v head %v", status, doc["next"], doc["head"])
	}
	status, doc = tc.call(t, "operator-key", "GET", "/v1/broker/usage-meter?after=1000", nil)
	if status != 200 || len(doc["readings"].([]any)) != 3 || doc["next"].(float64) != 1003 {
		t.Fatalf("second page: %d %v", status, doc["next"])
	}
}

// A run on a hotel the broker no longer has (forgotten, gone at restart)
// ends at its last seconds; it has no sync pass of its own.
func TestUsageMeterRunOnGoneHotelEnds(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	m.known = func(id string) bool { return id != "gone" }
	m.seen(usageSighting{run: "gone.a", guest: "g1", hotel: "gone"}, at(0))
	m.seen(sighting("h.b"), at(0))
	listPass(m, at(2), []string{"h.b"})
	mustFlush(t, m)
	all := logReadings(t, dir)
	if len(all) != 3 || all[2].Run != "gone.a" || all[2].State != "ended" || m.runs["h.b"] == nil {
		t.Fatalf("readings %+v", all)
	}
}

// A delete adds its tail only when no answered list since the last
// sighting left the room out: the hotel answers 204 for a room it already
// lost.
func TestUsageMeterDeleteTailNeedsTheLastList(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 600)
	m.seen(sighting("h.live"), at(0))
	m.seen(sighting("h.lost"), at(0))
	listPass(m, at(2), []string{"h.live", "h.lost"})
	listPass(m, at(4), []string{"h.live"}, "h.lost") // h.lost is gone from the hotel; still in the room map
	m.end("h.live", at(5), true)
	m.end("h.lost", at(5), true)
	mustFlush(t, m)
	all := logReadings(t, dir)
	for run, want := range map[string]int64{"h.live": 5, "h.lost": 2} {
		got := readingsOf(all, run)
		if len(got) != 2 || got[1].State != "ended" || got[1].Seconds != want {
			t.Fatalf("%s: %+v, want ended at %d s", run, got, want)
		}
	}
}

// Through the broker: the hotel loses a listed room, the next list leaves
// it out, and the guest's delete gets 204 anyway. The end adds no time.
func TestUsageMeterDeleteOfAbsentRoomAnswered204AddsNothing(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	syncNow(tc, "b")
	f := tc.hotels["b"]
	f.mu.Lock()
	f.rooms, f.absentDelete204 = nil, true // the room's TTL ran out on the hotel
	f.mu.Unlock()
	syncNow(tc, "b")                    // the list leaves it out; the room is too young to be marked gone
	time.Sleep(1100 * time.Millisecond) // a tail would now count at least 1 s
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+id, nil); status != 204 {
		t.Fatalf("delete: %d", status)
	}
	mustFlush(t, tc.b.usageMeter)
	got := readingsOf(logReadings(t, filepath.Join(tc.b.cfg.StateDir, usageDirName)), id)
	if len(got) != 2 || got[1].State != "ended" || got[1].Seconds != 0 {
		t.Fatalf("readings %+v, want ended at 0 s", got)
	}
}

// A room created just after a sync and deleted by label before the next one
// ends at the bulk delete's own list, with its seconds, and only once.
func TestUsageMeterBulkDeleteEndsTheRunWithItsSeconds(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	syncNow(tc, "b")
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "labels": map[string]any{"job": "x"}})
	time.Sleep(1100 * time.Millisecond)
	if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes?label=job=x", nil); status != 200 {
		t.Fatalf("bulk delete: %d %v", status, doc)
	}
	setHotel(tc, "b", func(h *hotel) {
		for _, rm := range h.rooms {
			rm.since, rm.vanished = time.Now().Add(-time.Minute), time.Now().Add(-time.Minute)
		}
	})
	syncNow(tc, "b")
	syncNow(tc, "b")
	mustFlush(t, tc.b.usageMeter)
	got := readingsOf(logReadings(t, filepath.Join(tc.b.cfg.StateDir, usageDirName)), id)
	if len(got) != 2 || got[0].Seconds != 0 || got[1].State != "ended" || got[1].Seconds < 1 || got[1].Seconds > 10 {
		t.Fatalf("readings %+v, want one ended reading with 1 to 10 s", got)
	}
}

// usageMeterRunsOf is the readings of run in tc's log.
func usageMeterRunsOf(t *testing.T, tc *testChain, run string) []usageReading {
	t.Helper()
	mustFlush(t, tc.b.usageMeter)
	return readingsOf(logReadings(t, filepath.Join(tc.b.cfg.StateDir, usageDirName)), run)
}

// letGo makes hotel id's room map drop rooms its list no longer shows, as
// the sync loop does after its grace times.
func letGo(tc *testChain, id string) {
	for i := 0; i < 2; i++ {
		setHotel(tc, id, func(h *hotel) {
			for _, rm := range h.rooms {
				rm.since, rm.vanished = time.Now().Add(-time.Minute), time.Now().Add(-time.Minute)
			}
		})
		syncNow(tc, id)
	}
}

// A cancelled create whose room the broker reaps, with a cleanup that keeps
// failing, is metered as not billable while lists show it, and ends once.
func TestUsageMeterReapedRoomIsMeteredNotBillable(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	syncNow(tc, "b")
	f := tc.hotels["b"]
	f.mu.Lock()
	f.rooms = append(f.rooms, map[string]any{"id": "sbx_cancelled", "state": "running",
		"labels": map[string]any{guestLabel: "g1"}, "resources": map[string]any{"vcpu": 1, "memory_gib": 4}})
	f.roomDeleteFail = 500
	f.mu.Unlock()
	h := tc.b.hotelByID("b")
	rm := &room{h: h, guest: "g1", hid: "sbx_cancelled", id: "b.sbx_cancelled", slot: -1}
	done := make(chan struct{})
	go func() { tc.b.reapRoom(h, rm); close(done) }() // what createOne does for a cancelled create
	for i := 0; ; i++ {
		f.mu.Lock()
		tried := len(f.roomDeletes)
		f.mu.Unlock()
		if tried > 0 {
			break
		}
		if i > 500 {
			t.Fatal("reapRoom never tried the delete")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		syncNow(tc, "b")
		time.Sleep(20 * time.Millisecond)
	}
	got := usageMeterRunsOf(t, tc, "b.sbx_cancelled")
	if len(got) != 1 || got[0].Billable == nil || *got[0].Billable || got[0].State != "running" || got[0].Guest != "g1" {
		t.Fatalf("readings while cleanup fails %+v", got)
	}
	f.mu.Lock()
	f.roomDeleteFail = 0 // the reap's next try removes it
	f.mu.Unlock()
	<-done
	letGo(tc, "b")
	got = usageMeterRunsOf(t, tc, "b.sbx_cancelled")
	if len(got) != 2 || got[1].State != "ended" || got[1].Billable == nil || *got[1].Billable {
		t.Fatalf("readings after cleanup %+v", got)
	}
	var line map[string]any
	p, _ := tc.b.usageMeter.page(0, 10, time.Now())
	_ = json.Unmarshal(p.Readings[len(p.Readings)-1], &line)
	if line["billable"] != false {
		t.Fatalf("route line %v, want billable false", line)
	}
}

// A recorded leftover of a failed create (never in the room map) is metered
// as not billable while lists show it, and ends when they stop.
func TestUsageMeterRecordedLeftoverIsMeteredNotBillable(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	f := tc.hotels["b"]
	f.mu.Lock()
	f.rooms = append(f.rooms, map[string]any{"id": "sbx_orphan", "state": "running", "labels": map[string]any{guestLabel: "g1", batchLabel: "batch-1"}})
	f.mu.Unlock()
	h := tc.b.hotelByID("b")
	tc.b.mu.Lock()
	h.unreaped = map[string]*unreapedBatch{"batch-1": {guest: "g1", busy: true}} // its removal keeps failing
	tc.b.mu.Unlock()
	syncNow(tc, "b")
	time.Sleep(1100 * time.Millisecond)
	syncNow(tc, "b")
	tc.b.mu.Lock()
	adopted := h.rooms["sbx_orphan"] != nil
	tc.b.mu.Unlock()
	if adopted {
		t.Fatal("the leftover was adopted as the guest's room")
	}
	f.mu.Lock()
	f.rooms = nil // finally removed
	f.mu.Unlock()
	syncNow(tc, "b")
	got := usageMeterRunsOf(t, tc, "b.sbx_orphan")
	if len(got) != 2 || got[0].Billable == nil || *got[0].Billable || got[1].State != "ended" || got[1].Seconds != 1 || got[1].Billable == nil || *got[1].Billable {
		t.Fatalf("readings %+v, want first and ended (1 s), both billable false", got)
	}
	// A registered room's readings carry no billable field.
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if got := usageMeterRunsOf(t, tc, id); len(got) != 1 || got[0].Billable != nil {
		t.Fatalf("guest room readings %+v", got)
	}
}

// Pruning the file that holds an open run's only reading writes that
// reading again first: after a restart the run keeps started_at and seconds.
func TestUsageMeterPruneCarriesAnOpenRunsOnlyReading(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 10)
	m.maxLines = 3
	m.seen(sighting("h.quiet"), at(0))
	for p := 2.0; p <= 20; p += 2 {
		listPass(m, at(p), []string{"h.quiet"})
	}
	mustFlush(t, m) // seqs 1 to 3 (0, 10, 20 s): file 1 is full
	m.mu.Lock()
	m.listedAt = map[string]time.Time{} // its hotel stops answering: no reading after 20 s
	m.mu.Unlock()
	for _, run := range []string{"x.a", "x.b"} {
		m.seen(sighting(run), at(30))
		m.end(run, at(31), true)
		mustFlush(t, m)
	} // seqs 4 to 7: file 4 (4, 5, 6) and file 7 (7)
	files, _ := m.files()
	if len(files) != 3 {
		t.Fatalf("files %+v", files)
	}
	old := time.Now().Add(-8 * 24 * time.Hour)
	for _, f := range files[:2] {
		_ = os.Chtimes(f.path, old, old)
	}
	if _, err := m.page(7, 10, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(files[0].path); err == nil {
		t.Fatal("file 1 was not pruned")
	}
	all := logReadings(t, dir)
	last := all[len(all)-1]
	if last.Seq != 8 || last.Run != "h.quiet" || last.Seconds != 20 || last.StartedAt != usageMeterT0.Unix() || last.State != "running" {
		t.Fatalf("carried reading %+v", last)
	}
	m2 := testUsageMeter(t, dir, 10)
	r := m2.runs["h.quiet"]
	if r == nil || r.observed != 20*time.Second || r.last.StartedAt != usageMeterT0.Unix() || r.lastSeq != 8 {
		t.Fatalf("after restart: %+v", r)
	}
}

// A broker that dies between an append and its fsync: the route never
// served the unsynced line (head stays at the last fsynced seq), so a seq
// it served is never reissued with other content, whether the line was
// lost or kept.
func TestUsageMeterCrashBeforeFsyncReissuesNoServedSeq(t *testing.T) {
	for _, kept := range []bool{false, true} {
		t.Run(fmt.Sprintf("line kept %v", kept), func(t *testing.T) {
			dir := t.TempDir()
			m := testUsageMeter(t, dir, 60)
			m.seen(sighting("h.a"), at(0))
			mustFlush(t, m)
			served := map[int64]string{}
			p, _ := m.page(0, 10, time.Now())
			for _, raw := range p.Readings {
				var r usageReading
				_ = json.Unmarshal(raw, &r)
				served[r.Seq] = string(raw)
			}
			written := make(chan struct{})
			never := make(chan struct{})
			t.Cleanup(func() { close(never) })
			m.write = func(f *os.File, b []byte) error {
				_, _ = f.Write(b) // written, not yet synced: the broker dies here
				close(written)
				<-never
				return errors.New("dead")
			}
			m.seen(sighting("h.b"), at(1))
			go func() { _ = m.flush() }()
			<-written
			m.mu.Lock()
			head := m.head
			m.mu.Unlock()
			if head != 1 {
				t.Fatalf("head %d during the unsynced append, want 1", head)
			}
			if !kept { // the machine lost the unsynced tail
				name := filepath.Join(dir, fmt.Sprintf("%020d.jsonl", 1))
				raw, _ := os.ReadFile(name)
				lines := strings.SplitAfter(string(raw), "\n")
				_ = os.WriteFile(name, []byte(lines[0]), 0o600)
			}
			m2 := testUsageMeter(t, dir, 60)
			m2.seen(sighting("h.c"), at(2))
			mustFlush(t, m2)
			p2, _ := m2.page(0, 10, time.Now())
			for _, raw := range p2.Readings {
				var r usageReading
				_ = json.Unmarshal(raw, &r)
				if was, ok := served[r.Seq]; ok && was != string(raw) {
					t.Fatalf("seq %d served as %s, now %s", r.Seq, was, raw)
				}
			}
			want := int64(2)
			if kept {
				want = 3
			}
			if m2.head != want {
				t.Fatalf("head after restart %d, want %d", m2.head, want)
			}
		})
	}
}

// vcpu and memory_gib are whole numbers on the line; a fractional hotel
// value rounds up, and an absent one is 0.
func TestUsageMeterSizeIsWholeNumbers(t *testing.T) {
	for _, c := range []struct {
		res       any
		vcpu, mem int64
	}{
		{map[string]any{"vcpu": 2.0, "memory_gib": 8.0}, 2, 8},
		{map[string]any{"vcpu": 1.5, "memory_gib": 3.2}, 2, 4},
		{map[string]any{"vcpu": 1}, 1, 0},
		{map[string]any{"vcpu": "4", "memory_gib": -1.0}, 0, 0},
		{nil, 0, 0},
	} {
		if v, m := usageSizeOf(c.res); v != c.vcpu || m != c.mem {
			t.Fatalf("%v: %d, %d, want %d, %d", c.res, v, m, c.vcpu, c.mem)
		}
	}
	tc := newChainState(t, t.TempDir())
	f := tc.hotels["b"]
	f.mu.Lock()
	f.rooms = append(f.rooms, map[string]any{"id": "sbx_frac", "state": "running",
		"labels": map[string]any{guestLabel: "g1"}, "resources": map[string]any{"vcpu": 1.5, "memory_gib": 3.2}})
	f.mu.Unlock()
	syncNow(tc, "b")
	mustFlush(t, tc.b.usageMeter)
	p, _ := tc.b.usageMeter.page(0, 10, time.Now())
	if len(p.Readings) != 1 || !strings.Contains(string(p.Readings[0]), `"vcpu":2,"memory_gib":4,`) {
		t.Fatalf("line %s", p.Readings)
	}
}

// observed_at leaves out a hotel whose latest list failed and that takes no
// new room, and counts it in unobserved_hotels; a failing hotel that still
// takes rooms counts, a recovered one counts again, and a sync that never
// completes a list attempt still goes stale.
func TestUsageMeterObservedAtLeavesOutAnUnplaceableSilentHotel(t *testing.T) {
	m := testUsageMeter(t, t.TempDir(), 600)
	pass := func(hotel string, when float64, listOK, unplaceable bool) {
		run := hotel + ".r"
		var listed []usageSighting
		if listOK {
			listed = []usageSighting{sighting(run)}
		}
		m.hotelPass(hotel, listed, map[string]bool{run: true}, at(when), listOK, listOK, unplaceable)
	}
	obs := func(now float64) (int64, int) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.observedAtLocked(at(now))
	}
	pass("a", 10, true, false)
	pass("b", 10, true, false)
	for p := 12.0; p <= 100; p += 2 {
		pass("a", p, true, false)
		pass("b", p, false, false) // the list fails, the hotel still takes rooms
	}
	if o, n := obs(100); o != at(10).Unix() || n != 0 {
		t.Fatalf("placeable failing hotel: observed_at %d unobserved %d, want %d and 0", o, n, at(10).Unix())
	}
	pass("b", 101, false, true) // now down too: no new room goes there
	if o, n := obs(101); o != at(100).Unix() || n != 1 {
		t.Fatalf("silent hotel: observed_at %d unobserved %d, want %d and 1", o, n, at(100).Unix())
	}
	pass("a", 110, true, false)
	pass("b", 110, true, false) // recovered
	if o, n := obs(110); o != at(110).Unix() || n != 0 {
		t.Fatalf("recovered: observed_at %d unobserved %d, want %d and 0", o, n, at(110).Unix())
	}
	// The sync loop stalls: no list attempt completes on any hotel.
	if o, n := obs(400); o != at(110).Unix() || n != 0 {
		t.Fatalf("stalled sync: observed_at %d unobserved %d, want the stale %d and 0", o, n, at(110).Unix())
	}
	// With every hotel holding rooms left out, observed_at is now.
	pass("a", 401, false, true)
	pass("b", 401, false, true)
	if o, n := obs(402); o != at(402).Unix() || n != 2 {
		t.Fatalf("all left out: observed_at %d unobserved %d", o, n)
	}
}

// Through the broker: hotel c holds a room and goes silent (health, room
// calls and list fail), so placement skips it; the route's observed_at
// stays fresh from hotel b and unobserved_hotels is 1. A failed list alone
// (health answers) keeps c counted, and so does its recovery.
func TestUsageMeterSilentHotelDoesNotStaleTheMeter(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}})
	syncNow(tc, "b")
	syncNow(tc, "c")
	meterPage := func() map[string]any {
		t.Helper()
		status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/usage-meter", nil)
		if status != 200 {
			t.Fatalf("route: %d %v", status, doc)
		}
		return doc
	}
	fc := tc.hotels["c"]
	setFail := func(health, list bool) {
		fc.mu.Lock()
		fc.healthFail, fc.listFail = health, list
		fc.mu.Unlock()
	}

	setFail(false, true) // the list fails, health answers: c still takes rooms
	syncNow(tc, "c")
	if doc := meterPage(); doc["unobserved_hotels"].(float64) != 0 {
		t.Fatalf("placeable hotel left out: %v", doc)
	}

	setFail(true, true)
	setHotel(tc, "c", func(h *hotel) {
		h.lastOK = time.Now().Add(-time.Minute)
		h.lastAnswer.Store(time.Now().Add(-time.Minute).UnixNano())
	})
	syncNow(tc, "c")
	syncNow(tc, "b")
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}}); status == 202 {
		t.Fatalf("a room was placed on the silent hotel: %v", doc)
	}
	doc := meterPage()
	if obs := int64(doc["observed_at"].(float64)); obs < time.Now().Unix()-5 || doc["unobserved_hotels"].(float64) != 1 {
		t.Fatalf("silent c: observed_at %d unobserved %v, want fresh and 1", obs, doc["unobserved_hotels"])
	}

	setFail(false, false)
	syncNow(tc, "c")
	if doc := meterPage(); doc["unobserved_hotels"].(float64) != 0 {
		t.Fatalf("recovered c still left out: %v", doc)
	}
}

// A bulk delete whose answer comes late: two syncs drop the room and end
// its run first. The run still keeps the time seen at the bulk delete's own
// list, and the delete's answer writes no second ended reading.
func TestUsageMeterSlowBulkDeleteKeepsItsSighting(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	syncNow(tc, "b")
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "labels": map[string]any{"job": "x"}})
	time.Sleep(1100 * time.Millisecond)
	f := tc.hotels["b"]
	hold := make(chan struct{})
	f.mu.Lock()
	f.bulkDeleteHold = hold
	f.mu.Unlock()
	done := make(chan int, 1)
	go func() { st, _, _ := rawCall(tc, "key1", "", "DELETE", "/v1/sandboxes?label=job=x", nil); done <- st }()
	for i := 0; ; i++ {
		f.mu.Lock()
		asked := len(f.bulkDeletes)
		f.mu.Unlock()
		if asked > 0 {
			break
		}
		if i > 500 {
			t.Fatal("the bulk delete never reached hotel b")
		}
		time.Sleep(10 * time.Millisecond)
	}
	letGo(tc, "b") // two syncs release the room while the delete answer is held
	if got := usageMeterRunsOf(t, tc, id); len(got) != 2 || got[1].State != "ended" || got[1].Seconds < 1 {
		close(hold)
		t.Fatalf("readings before the delete answers %+v, want ended with at least 1 s", got)
	}
	close(hold)
	if status := <-done; status != 200 {
		t.Fatalf("bulk delete: %d", status)
	}
	got := usageMeterRunsOf(t, tc, id)
	if len(got) != 2 || got[1].State != "ended" || got[1].Seconds < 1 || got[1].Seconds > 10 {
		t.Fatalf("readings %+v, want one ended reading with 1 to 10 s", got)
	}
}

// The hotel starts a room and answers the create 500; the orphan cleanup
// removes it before any sync. The room is metered: not billable, ended.
func TestUsageMeterOrphanCleanupMetersTheRoom(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	f := tc.hotels["b"]
	f.mu.Lock()
	f.createFail, f.createFailAfterStart = 500, true
	f.mu.Unlock()
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}); status == 202 {
		t.Fatalf("create: %d %v", status, doc)
	}
	f.mu.Lock()
	deleted, left := append([]string(nil), f.roomDeletes...), len(f.rooms)
	f.mu.Unlock()
	if len(deleted) != 1 || left != 0 {
		t.Fatalf("cleanup deleted %v, %d rooms left", deleted, left)
	}
	got := usageMeterRunsOf(t, tc, "b."+deleted[0])
	if len(got) != 2 || got[1].State != "ended" {
		t.Fatalf("readings %+v, want a first and an ended reading", got)
	}
	for _, r := range got {
		if r.Billable == nil || *r.Billable || r.Guest != "g1" {
			t.Fatalf("reading %+v, want billable false for guest g1", r)
		}
	}
}

// A sync adopts the room while its create is in flight (billable readings),
// then the create fails and the cleanup removes the room: from the cleanup
// on, the run is not billable, the ended reading included.
func TestUsageMeterAdoptedRoomOfAFailedCreateEndsNotBillable(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	f := tc.hotels["b"]
	f.mu.Lock()
	f.createFail, f.createFailAfterStart, f.answerDelay = 500, true, 800*time.Millisecond
	f.mu.Unlock()
	done := make(chan int, 1)
	go func() {
		st, _, _ := rawCall(tc, "key1", "", "POST", "/v1/sandboxes", []byte(`{"image":"alpine:3.20","hotels":["b"]}`))
		done <- st
	}()
	var hid string
	for i := 0; hid == ""; i++ {
		f.mu.Lock()
		if len(f.rooms) > 0 {
			hid = f.rooms[0]["id"].(string)
		}
		f.mu.Unlock()
		if i > 500 {
			t.Fatal("the hotel never started the room")
		}
		time.Sleep(5 * time.Millisecond)
	}
	syncNow(tc, "b") // adopted as the guest's room
	time.Sleep(100 * time.Millisecond)
	syncNow(tc, "b")
	if status := <-done; status == 202 {
		t.Fatal("the create succeeded")
	}
	letGo(tc, "b")
	got := usageMeterRunsOf(t, tc, "b."+hid)
	if len(got) < 2 || got[0].Billable != nil || got[len(got)-1].State != "ended" {
		t.Fatalf("readings %+v, want a billable first reading and an ended one", got)
	}
	last := got[len(got)-1]
	if last.Billable == nil || *last.Billable || got[len(got)-2].State == "ended" {
		t.Fatalf("readings %+v, want exactly one ended reading, not billable", got)
	}
}

// The review's sequence: an old file holds acknowledged seqs 1 and 2; after
// a restart an append fails and leaves the newest file empty; a cursor read
// prunes the old file; another restart finds only the empty file. The next
// seq is 3, never one a reader has seen.
func TestUsageMeterSeqNeverRestartsAfterPruningEveryReading(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	m.seen(sighting("h.x"), at(0))
	m.end("h.x", at(1), false)
	mustFlush(t, m)
	served := map[int64]string{}
	p, _ := m.page(0, 10, time.Now())
	for _, raw := range p.Readings {
		var r usageReading
		_ = json.Unmarshal(raw, &r)
		served[r.Seq] = string(raw)
	}
	if len(served) != 2 {
		t.Fatalf("served %v", served)
	}

	m2 := testUsageMeter(t, dir, 60)
	m2.write = func(f *os.File, b []byte) error { _, _ = f.Write(b[:3]); return errors.New("no space left on device") }
	m2.seen(sighting("h.y"), at(10))
	if err := m2.flush(); err == nil {
		t.Fatal("the append did not fail")
	}
	newest := filepath.Join(dir, fmt.Sprintf("%020d.jsonl", 3))
	if st, err := os.Stat(newest); err != nil || st.Size() != 0 {
		t.Fatalf("newest file %v %v, want empty", st, err)
	}
	old := time.Now().Add(-8 * 24 * time.Hour)
	oldFile := filepath.Join(dir, fmt.Sprintf("%020d.jsonl", 1))
	_ = os.Chtimes(oldFile, old, old)
	if _, err := m2.page(2, 10, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldFile); err != nil {
		t.Fatal("pruned while a reading was still queued")
	}
	// The broker dies with h.y still queued. The next one prunes (nothing is
	// queued), then dies too; the one after finds only the empty file.
	m3 := testUsageMeter(t, dir, 60)
	if _, err := m3.page(2, 10, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldFile); err == nil {
		t.Fatal("the acknowledged old file was not pruned")
	}

	m4 := testUsageMeter(t, dir, 60)
	if m4.nextSeq != 3 || m4.head != 2 {
		t.Fatalf("after restart: next %d head %d, want 3 and 2", m4.nextSeq, m4.head)
	}
	m4.seen(sighting("h.z"), at(20))
	mustFlush(t, m4)
	p, _ = m4.page(2, 10, time.Now())
	if len(p.Readings) != 1 || p.Next != 3 || p.Head != 3 {
		t.Fatalf("page after 2: %+v", p)
	}
	for _, r := range logReadings(t, dir) {
		if was, ok := served[r.Seq]; ok && was != "" {
			t.Fatalf("seq %d issued again: %+v", r.Seq, r)
		}
	}
}

// A replayed file whose sync fails restores its runs but serves none of its
// readings and stays out of head; the failure counts in write_errors and the
// sync is retried; once it succeeds the readings are served.
func TestUsageMeterReplaySyncFailureServesNothingUntilSynced(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	m.seen(sighting("h.a"), at(0))
	m.seen(sighting("h.b"), at(0))
	mustFlush(t, m)
	failing := true
	orig := usageSyncFile
	usageSyncFile = func(f *os.File) error {
		if failing {
			return errors.New("input/output error")
		}
		return orig(f)
	}
	t.Cleanup(func() { usageSyncFile = orig })

	m2 := testUsageMeter(t, dir, 60)
	if m2.head != 0 || m2.nextSeq != 3 || len(m2.runs) != 2 || m2.writeErrors != 1 {
		t.Fatalf("replay: head %d next %d runs %d errors %d", m2.head, m2.nextSeq, len(m2.runs), m2.writeErrors)
	}
	p, _ := m2.page(0, 10, time.Now())
	if len(p.Readings) != 0 || p.Head != 0 || p.WriteErrors < 2 {
		t.Fatalf("page while unsynced %+v", p)
	}
	m2.seen(sighting("h.c"), at(5))
	mustFlush(t, m2)
	seqsOf := func(p usagePage) []int64 {
		var out []int64
		for _, raw := range p.Readings {
			var r usageReading
			_ = json.Unmarshal(raw, &r)
			out = append(out, r.Seq)
		}
		return out
	}
	// Seq 3 is durable but lies above the unsynced 1 and 2: a reader whose
	// cursor passed 3 would never get them, so nothing is served or acked.
	p, _ = m2.page(0, 10, time.Now())
	if len(p.Readings) != 0 || p.Head != 0 || p.Next != 0 || m2.acked != 0 {
		t.Fatalf("served %v head %d next %d acked %d, want nothing", seqsOf(p), p.Head, p.Next, m2.acked)
	}
	failing = false
	if p2, _ := m2.page(p.Next, 10, time.Now()); fmt.Sprint(seqsOf(p2)) != "[1 2 3]" || p2.Head != 3 || p2.Next != 3 {
		t.Fatalf("after the sync, from next %d: served %v head %d next %d", p.Next, seqsOf(p2), p2.Head, p2.Next)
	}
}

// While appends fail, pending_readings counts what is observed and not yet
// durable and write_errors grows; after recovery pending_readings is 0.
func TestUsageMeterRouteReportsPendingReadings(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	m := tc.b.usageMeter
	m.write = func(f *os.File, p []byte) error { return errors.New("no space left on device") }
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	read := func() map[string]any {
		t.Helper()
		status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/usage-meter", nil)
		if status != 200 {
			t.Fatalf("route: %d %v", status, doc)
		}
		return doc
	}
	_ = m.flush()
	first := read()
	_ = m.flush()
	second := read()
	if first["pending_readings"].(float64) != 2 || first["head"].(float64) != 0 || second["write_errors"].(float64) <= first["write_errors"].(float64) {
		t.Fatalf("while failing: %v then %v", first, second)
	}
	m.write = appendDurable
	mustFlush(t, m)
	if doc := read(); doc["pending_readings"].(float64) != 0 || doc["head"].(float64) != 2 {
		t.Fatalf("after recovery: %v", doc)
	}
}

// A sync adopts the room (billable reading), the create fails and the
// cleanup's delete fails too; the broker dies right after the hook returns,
// with no flush in between, before another whole second. The turn to not
// billable was made durable inside the hook, so replay restores the run as
// not billable and every later reading of it says so.
func TestUsageMeterNotBillableSurvivesARestart(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	f := tc.hotels["b"]
	f.mu.Lock()
	f.createFail, f.createFailAfterStart, f.answerDelay, f.roomDeleteFail = 500, true, 300*time.Millisecond, 500
	f.mu.Unlock()
	done := make(chan int, 1)
	go func() {
		st, _, _ := rawCall(tc, "key1", "", "POST", "/v1/sandboxes", []byte(`{"image":"alpine:3.20","hotels":["b"]}`))
		done <- st
	}()
	var hid string
	for i := 0; hid == ""; i++ {
		f.mu.Lock()
		if len(f.rooms) > 0 {
			hid = f.rooms[0]["id"].(string)
		}
		f.mu.Unlock()
		if i > 500 {
			t.Fatal("the hotel never started the room")
		}
		time.Sleep(5 * time.Millisecond)
	}
	syncNow(tc, "b") // adopted: a billable first reading
	mustFlush(t, tc.b.usageMeter)
	if status := <-done; status == 202 {
		t.Fatal("the create succeeded")
	}
	run := "b." + hid
	// The disk as the crash leaves it: no flush since the hook returned.
	before := readingsOf(logReadings(t, filepath.Join(tc.b.cfg.StateDir, usageDirName)), run)
	if len(before) != 2 || before[0].Billable != nil || before[1].Billable == nil || *before[1].Billable || before[1].Seconds != before[0].Seconds {
		t.Fatalf("readings on disk at the crash %+v, want billable then not billable at the same seconds", before)
	}
	tc.start(t) // crash and restart: the new broker has no record of the failed create
	r := tc.b.usageMeter.runs[run]
	if r == nil || r.last.Billable == nil || *r.last.Billable {
		t.Fatalf("replayed run %+v, want not billable", r)
	}
	syncNow(tc, "b") // re-adopted as the guest's room
	f.mu.Lock()
	f.rooms, f.roomDeleteFail = nil, 0
	f.mu.Unlock()
	letGo(tc, "b")
	got := usageMeterRunsOf(t, tc, run)
	if len(got) < 3 || got[len(got)-1].State != "ended" {
		t.Fatalf("readings %+v, want an ended reading after the restart", got)
	}
	for _, x := range got[1:] {
		if x.Billable == nil || *x.Billable {
			t.Fatalf("reading %+v after the turn is billable", x)
		}
	}
}

// A run's last durable state is in an old acknowledged file and its ended
// reading is still queued when a cursor read prunes: the prune writes the
// queue first, so after a crash the ended reading is there.
func TestUsageMeterPruneWritesAQueuedEndFirst(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	m.maxLines = 2
	m.seen(sighting("h.quiet"), at(0)) // seq 1: file 1
	m.seen(sighting("h.x"), at(1))     // seq 2: file 1
	mustFlush(t, m)
	m.seen(sighting("h.y"), at(2)) // seq 3: file 3
	mustFlush(t, m)
	old := time.Now().Add(-8 * 24 * time.Hour)
	_ = os.Chtimes(filepath.Join(dir, fmt.Sprintf("%020d.jsonl", 1)), old, old)
	m.end("h.quiet", at(5), false) // queued, not flushed: the run is out of the open-run map
	if _, err := m.page(3, 10, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("%020d.jsonl", 1))); err == nil {
		t.Fatal("file 1 was not pruned")
	}
	// crash: m is dropped
	m2 := testUsageMeter(t, dir, 60)
	if m2.ended["h.quiet"] == nil || m2.runs["h.quiet"] != nil {
		t.Fatal("after the crash h.quiet is neither ended nor known")
	}
	got := readingsOf(logReadings(t, dir), "h.quiet")
	if len(got) == 0 || got[len(got)-1].State != "ended" || got[len(got)-1].StartedAt != usageMeterT0.Unix() {
		t.Fatalf("h.quiet readings %+v", got)
	}
}

// A new log file whose directory does not sync (open or sync failure) gets
// no reading, so nothing is served from a file a crash could lose; a later
// pass retries. A cursor read whose acked.json rename cannot be made
// durable prunes nothing. Every failure counts in write_errors.
func TestUsageMeterDirectorySyncFailureServesAndPrunesNothing(t *testing.T) {
	for name, failure := range map[string]error{
		"open": &fs.PathError{Op: "open", Path: "usage", Err: fs.ErrPermission},
		"sync": errors.New("sync usage: input/output error"),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			orig := usageSyncDir
			failing := true
			usageSyncDir = func(d string) error {
				if failing {
					return failure
				}
				return orig(d)
			}
			t.Cleanup(func() { usageSyncDir = orig })

			m := testUsageMeter(t, dir, 60)
			m.seen(sighting("h.a"), at(0))
			if err := m.flush(); err == nil {
				t.Fatal("flush succeeded with the directory not synced")
			}
			p, _ := m.page(0, 10, time.Now())
			if len(p.Readings) != 0 || p.Head != 0 || p.PendingReadings != 1 || p.WriteErrors < 1 {
				t.Fatalf("while the name is not durable: %+v", p)
			}
			if raw, _ := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%020d.jsonl", 1))); len(raw) != 0 {
				t.Fatalf("a reading went into a file whose name is not durable: %q", raw)
			}
			failing = false
			mustFlush(t, m) // seq 1 in file 1
			m.maxLines = 1
			m.end("h.a", at(1), false)
			mustFlush(t, m) // seq 2 in file 2; no run is open, so a prune carries nothing
			m.maxLines = 10
			old := time.Now().Add(-8 * 24 * time.Hour)
			file1 := filepath.Join(dir, fmt.Sprintf("%020d.jsonl", 1))
			_ = os.Chtimes(file1, old, old)

			failing = true
			errs := m.writeErrors
			if _, err := m.page(1, 10, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(file1); err != nil {
				t.Fatal("pruned with acked.json not durable")
			}
			if m.writeErrors <= errs {
				t.Fatalf("write_errors %d, want above %d", m.writeErrors, errs)
			}
			failing = false
			if _, err := m.page(1, 10, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(file1); err == nil {
				t.Fatal("not pruned once the directory syncs")
			}
		})
	}
}

// A replayed file whose sync fails may hold a run's newer running reading
// or its end. A cursor read must not prune the older file with the run's
// durable state on the strength of it: after another crash loses the
// unsynced file, the run is still known with its start.
func TestUsageMeterNoPruneWhileAReplayedRangeIsUnsynced(t *testing.T) {
	for name, newer := range map[string]func(m *usageMeter){
		"newer running reading": func(m *usageMeter) {
			for p := 2.0; p <= 10; p += 2 {
				listPass(m, at(p), []string{"h.L"}, "h.x")
			}
		},
		"end": func(m *usageMeter) { m.end("h.L", at(5), false) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			m := testUsageMeter(t, dir, 10)
			m.maxLines = 2
			m.seen(sighting("h.L"), at(0))
			m.seen(sighting("h.x"), at(0))
			mustFlush(t, m) // seqs 1 and 2: file 1
			newer(m)
			mustFlush(t, m) // seq 3: file 3
			file1 := filepath.Join(dir, fmt.Sprintf("%020d.jsonl", 1))
			file3 := filepath.Join(dir, fmt.Sprintf("%020d.jsonl", 3))
			if _, err := os.Stat(file3); err != nil {
				t.Fatalf("no file 3: %v", err)
			}
			old := time.Now().Add(-8 * 24 * time.Hour)
			_ = os.Chtimes(file1, old, old)

			orig := usageSyncFile
			usageSyncFile = func(f *os.File) error {
				if f.Name() == file3 {
					return errors.New("input/output error")
				}
				return orig(f)
			}
			t.Cleanup(func() { usageSyncFile = orig })
			m2 := testUsageMeter(t, dir, 10) // crash and restart: file 3 does not sync
			if _, err := m2.page(2, 10, time.Now()); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(file1); err != nil {
				t.Fatal("pruned the durable state while a newer replayed range is unsynced")
			}
			// Another crash loses the unsynced file.
			_ = os.Remove(file3)
			usageSyncFile = orig
			m3 := testUsageMeter(t, dir, 10)
			if r := m3.runs["h.L"]; r == nil || r.last.StartedAt != usageMeterT0.Unix() {
				t.Fatalf("h.L after the second crash: %+v", r)
			}
		})
	}
}

// A state_dir without usage/: the broker makes it, and nothing is written
// into it (so nothing is served) until its parent directory syncs; the
// failure counts in write_errors and the next pass retries.
func TestUsageMeterNewUsageDirNeedsItsParentSynced(t *testing.T) {
	state := t.TempDir()
	dir := filepath.Join(state, usageDirName)
	orig := usageSyncDir
	failing := true
	usageSyncDir = func(d string) error {
		if failing && d == state {
			return errors.New("sync state_dir: input/output error")
		}
		return orig(d)
	}
	t.Cleanup(func() { usageSyncDir = orig })
	m := testUsageMeter(t, dir, 60)
	m.seen(sighting("h.a"), at(0))
	if err := m.flush(); err == nil {
		t.Fatal("flush succeeded with usage/ not durable")
	}
	p, _ := m.page(0, 10, time.Now())
	if len(p.Readings) != 0 || p.Head != 0 || p.PendingReadings != 1 || p.WriteErrors < 1 {
		t.Fatalf("while usage/ is not durable: %+v", p)
	}
	if files, _ := m.files(); len(files) != 0 {
		t.Fatalf("a log file was made in a usage/ that is not durable: %+v", files)
	}
	failing = false
	mustFlush(t, m)
	if p, _ := m.page(0, 10, time.Now()); len(p.Readings) != 1 || p.Head != 1 || p.PendingReadings != 0 {
		t.Fatalf("after the parent synced: %+v", p)
	}
	// A usage/ that existed at start needs no parent sync.
	failing = true
	m2 := testUsageMeter(t, dir, 60)
	m2.seen(sighting("h.b"), at(1))
	mustFlush(t, m2)
}

// A hung write never stalls the broker: a cancelled create's reap that
// turns a run not billable waits for the disk outside b.mu and only up to
// usageTurnWait; meanwhile an unrelated create and a sync pass finish, and
// a route read answers within usageReadWait.
func TestUsageMeterHungDiskStallsNothing(t *testing.T) {
	oldTurn, oldRead := usageTurnWait, usageReadWait
	usageTurnWait, usageReadWait = 300*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { usageTurnWait, usageReadWait = oldTurn, oldRead })
	tc := newChainState(t, t.TempDir())
	syncNow(tc, "b")
	mustFlush(t, tc.b.usageMeter)
	hung := make(chan struct{})
	t.Cleanup(func() { close(hung) })
	tc.b.usageMeter.write = func(f *os.File, p []byte) error { <-hung; return errors.New("disk hung") }

	f := tc.hotels["b"]
	f.mu.Lock()
	f.rooms = append(f.rooms, map[string]any{"id": "sbx_cancelled", "state": "running", "labels": map[string]any{guestLabel: "g1"}})
	f.mu.Unlock()
	h := tc.b.hotelByID("b")
	reaped := make(chan time.Duration, 1)
	go func() {
		t0 := time.Now()
		tc.b.reapRoom(h, &room{h: h, guest: "g1", hid: "sbx_cancelled", id: "b.sbx_cancelled", slot: -1})
		reaped <- time.Since(t0)
	}()
	time.Sleep(50 * time.Millisecond) // the reap's flush now holds the hung write

	t0 := time.Now()
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}})
	syncNow(tc, "c")
	if d := time.Since(t0); d > 2*time.Second {
		t.Fatalf("a create and a sync pass took %s with the disk hung", d)
	}
	t0 = time.Now()
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/usage-meter", nil)
	if d := time.Since(t0); status != 200 || d > 2*time.Second {
		t.Fatalf("route read: %d after %s: %v", status, d, doc)
	}
	if doc["pending_readings"].(float64) < 1 {
		t.Fatalf("route read with the disk hung: %v", doc)
	}
	select {
	case d := <-reaped:
		if d > 3*time.Second {
			t.Fatalf("the reap waited %s for the disk", d)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reap never carried on past the hung disk")
	}
}

// Known limit, pinned: the broker dies after learning that a create failed
// and before that turn's reading is durable. The restarted broker has no
// record of the failure: replay restores the run from its last billable
// reading, and a sync that adopts the surviving room meters it as billable
// until it leaves (at most the room's remaining lifetime; the guest sees
// the room in its own list and can delete it).
func TestUsageMeterKnownLimitCrashBeforeTheTurnIsDurable(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 10)
	m.seen(sighting("h.orphan"), at(0)) // adopted by a sync: billable
	mustFlush(t, m)
	if !m.seen(usageSighting{run: "h.orphan", guest: "g1", hotel: "h"}, at(1)) {
		t.Fatal("no turn to not billable")
	}
	// crash: the turn is queued, never written
	m2 := testUsageMeter(t, dir, 10)
	if r := m2.runs["h.orphan"]; r == nil || r.last.Billable != nil {
		t.Fatalf("replayed run %+v: the documented limit no longer holds, update the README", r)
	}
	listPass(m2, at(30), []string{"h.orphan"})
	listPass(m2, at(32), []string{"h.orphan"})
	m2.end("h.orphan", at(33), true)
	mustFlush(t, m2)
	for _, r := range readingsOf(logReadings(t, dir), "h.orphan") {
		if r.Billable != nil {
			t.Fatalf("reading %+v: the documented limit no longer holds, update the README", r)
		}
	}
}

// A served seq is never issued again: acked.json holds the highest issued
// seq before a page serves it, so losing the log file afterwards (a disk
// fault, or the operator's last resort) cannot bring a served seq back.
func TestUsageMeterServedSeqSurvivesALostLogFile(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	m.seen(sighting("h.a"), at(0))
	m.end("h.a", at(1), false)
	mustFlush(t, m)
	p, _ := m.page(0, 10, time.Now()) // served through after=0, no cursor move
	if len(p.Readings) != 2 || m.acked != 0 {
		t.Fatalf("page %+v acked %d", p, m.acked)
	}
	files, _ := m.files()
	for _, f := range files {
		_ = os.Remove(f.path)
	}
	m2 := testUsageMeter(t, dir, 60)
	if m2.nextSeq != 3 {
		t.Fatalf("next seq after losing the log %d, want 3 (above the served 2)", m2.nextSeq)
	}
	m2.seen(sighting("h.b"), at(5))
	mustFlush(t, m2)
	if p, _ := m2.page(2, 10, time.Now()); len(p.Readings) != 1 || p.Next != 3 {
		t.Fatalf("page after 2: %+v", p)
	}
}

// A state_dir the broker has to create, two levels down: every directory
// that gains a new entry syncs, top down, before any file is made, and a
// failure on the way serves nothing until a retry succeeds.
func TestUsageMeterNewStateDirSyncsEveryNewAncestor(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "a", "b")
	dir := filepath.Join(state, usageDirName)
	orig := usageSyncDir
	var synced []string
	failing := true
	usageSyncDir = func(d string) error {
		if failing && d == filepath.Join(base, "a") {
			return errors.New("sync a: input/output error")
		}
		synced = append(synced, d)
		return orig(d)
	}
	t.Cleanup(func() { usageSyncDir = orig })
	m := testUsageMeter(t, dir, 60)
	m.seen(sighting("h.a"), at(0))
	if err := m.flush(); err == nil {
		t.Fatal("flush succeeded with a new ancestor not durable")
	}
	if p, _ := m.page(0, 10, time.Now()); len(p.Readings) != 0 || p.Head != 0 || p.WriteErrors < 1 {
		t.Fatalf("while an ancestor is not durable: %+v", p)
	}
	if files, _ := m.files(); len(files) != 0 {
		t.Fatalf("a log file was made: %+v", files)
	}
	failing = false
	mustFlush(t, m)
	if p, _ := m.page(0, 10, time.Now()); len(p.Readings) != 1 {
		t.Fatalf("after the ancestors synced: %+v", p)
	}
	want := []string{base, filepath.Join(base, "a"), state}
	if len(synced) < 3 || fmt.Sprint(synced[:3]) != fmt.Sprint(want) {
		t.Fatalf("synced %v, want %v first", synced, want)
	}
}

// Main's meter key routes (#648, meter.go) and the usage meter route share
// the word meter and nothing else. After the merge the meter key gets no
// usage readings, and the operator key keeps the usage meter and gets no
// meter key route.
func TestUsageMeterRouteAndMeterKeyRoutesStayApart(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	tc.b.cfg.MeterKeySHA256 = sha("meter-key")
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	syncNow(tc, "b")
	mustFlush(t, tc.b.usageMeter)
	for _, c := range [][2]string{{"GET", "/v1/broker/usage-meter"}, {"GET", "/v1/broker/usage-meter?after=0&limit=10"}, {"POST", "/v1/broker/usage-meter"}} {
		if status, doc := tc.call(t, "meter-key", c[0], c[1], nil); status != 401 {
			t.Fatalf("meter key %s %s: %d %v, want 401", c[0], c[1], status, doc)
		}
	}
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/usage-meter?after=0", nil)
	rs, _ := doc["readings"].([]any)
	if status != 200 || len(rs) != 1 || rs[0].(map[string]any)["run"] != id {
		t.Fatalf("operator key usage meter: %d %v, want the room's first reading", status, doc)
	}
	for _, rt := range meterPaths("g1") {
		if status, doc := tc.call(t, "operator-key", rt[0], rt[1], nil); status != 401 {
			t.Fatalf("operator key %s %s: %d %v, want 401", rt[0], rt[1], status, doc)
		}
	}
	if n := len(tc.hotels["b"].freezes); n != 0 {
		t.Fatalf("hotel got %d freezes", n)
	}
	if status, doc := tc.call(t, "meter-key", "GET", "/v1/broker/guests/g1/rooms", nil); status != 200 {
		t.Fatalf("meter key on its own route: %d %v", status, doc)
	}
}

// endedReadings is how many ended readings run has in tc's log.
func endedReadings(t *testing.T, tc *testChain, run string) (n int, all []usageReading) {
	t.Helper()
	all = usageMeterRunsOf(t, tc, run)
	for _, r := range all {
		if r.State == "ended" {
			n++
		}
	}
	return n, all
}

// Every way a room leaves the broker on main (#637 records why) gives its
// run exactly one ended reading, and a later sync adds none. #637 adds no
// end path of its own: its records are written at the sync loop's release
// of a vanished room and at the miner forget, both of which end the run.
func TestUsageMeterEndsOnceOnEveryEndPathOfMain(t *testing.T) {
	for _, c := range []struct {
		name, reason string
		end          func(t *testing.T, tc *testChain, bid string)
	}{
		{"delete by id", "deleted", func(t *testing.T, tc *testChain, bid string) {
			if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+bid, nil); status != 204 {
				t.Fatalf("delete: %d %v", status, doc)
			}
			releaseGone(t, tc, "b")
		}},
		{"delete by label", "deleted", func(t *testing.T, tc *testChain, bid string) {
			if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes?label=job=x", nil); status != 200 {
				t.Fatalf("bulk delete: %d %v", status, doc)
			}
			releaseGone(t, tc, "b")
		}},
		{"listed expiry", "ttl_expired", func(t *testing.T, tc *testChain, bid string) {
			setOnHotel(tc, bid, "expires_at", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
			syncNow(tc, "b")
			vanish(t, tc, bid)
		}},
		{"hotel ended list", "idle_timeout", func(t *testing.T, tc *testChain, bid string) {
			f := tc.hotels["b"]
			f.mu.Lock()
			f.listExtra = map[string]any{"ended": []map[string]any{{"id": strings.SplitN(bid, ".", 2)[1], "end_reason": "idle_timeout"}}}
			f.mu.Unlock()
			vanish(t, tc, bid)
		}},
		{"hotel api restart", "hotel_restarted", func(t *testing.T, tc *testChain, bid string) {
			f := tc.hotels["b"]
			f.mu.Lock()
			f.listExtra = map[string]any{"api_started_at": "2026-11-21T07:00:00+00:00"}
			f.mu.Unlock()
			syncNow(tc, "b")
			f.mu.Lock()
			f.listExtra = map[string]any{"api_started_at": "2026-11-21T08:00:00+00:00"}
			f.mu.Unlock()
			vanish(t, tc, bid)
		}},
		{"vanished", "unknown", func(t *testing.T, tc *testChain, bid string) {
			vanish(t, tc, bid)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tc := newChainState(t, t.TempDir())
			bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "labels": map[string]string{"job": "x"}})
			syncNow(tc, "b")
			c.end(t, tc, bid)
			if r := goneReason(t, tc, "key1", bid); r != c.reason {
				t.Fatalf("end record reason %q, want %q", r, c.reason)
			}
			syncNow(tc, "b")
			if n, all := endedReadings(t, tc, bid); n != 1 || all[len(all)-1].State != "ended" {
				t.Fatalf("readings %+v, want exactly one ended reading, last", all)
			}
		})
	}

	t.Run("miner forget", func(t *testing.T) {
		tc := newChainState(t, t.TempDir())
		g := newRebootingGuest(t, "m1")
		_, bid, _ := readyToForget(t, tc, g)
		if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/m1?forget_rooms=true", nil); status != 204 {
			t.Fatalf("forget: %d %v", status, doc)
		}
		if r := goneReason(t, tc, "key1", bid); r != "hotel_removed" {
			t.Fatalf("end record reason %q, want hotel_removed", r)
		}
		syncNow(tc, "b") // any pass sweeps the runs of a hotel the broker no longer has
		syncNow(tc, "b")
		if n, all := endedReadings(t, tc, bid); n != 1 || all[len(all)-1].State != "ended" {
			t.Fatalf("readings %+v, want exactly one ended reading, last", all)
		}
	})

	t.Run("refused create", func(t *testing.T) {
		tc := newChainState(t, t.TempDir()) // no hotel applies tunables: the broker reaps the room
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{
			"image": "alpine:3.20", "hotels": []string{"b"}, "tunables": coldTunables()})
		if status != 409 || errCode(doc) != "tunables_unavailable" {
			t.Fatalf("create: %d %v", status, doc)
		}
		releaseGone(t, tc, "b")
		syncNow(tc, "b")
		if status, list := endedOf(t, tc, "key1", ""); status != 200 || len(list) != 0 {
			t.Fatalf("end records after a refused create: %d %v, want none", status, list)
		}
		mustFlush(t, tc.b.usageMeter)
		var runs []string
		for _, r := range logReadings(t, filepath.Join(tc.b.cfg.StateDir, usageDirName)) {
			if r.State == "ended" {
				runs = append(runs, r.Run)
			}
			if r.Billable == nil || *r.Billable {
				t.Fatalf("a refused create's reading is billable: %+v", r)
			}
		}
		if len(runs) != 1 {
			t.Fatalf("ended readings for %v, want one run", runs)
		}
	})

	// #637 drops the end record when a late list shows the room again; the
	// run stays ended (README: not metered again for 24 h).
	t.Run("late list after the end", func(t *testing.T) {
		tc := newChainState(t, t.TempDir())
		bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
		syncNow(tc, "b")
		f := tc.hotels["b"]
		f.mu.Lock()
		saved := append([]map[string]any(nil), f.rooms...)
		f.mu.Unlock()
		vanish(t, tc, bid)
		_, before := endedReadings(t, tc, bid)
		f.mu.Lock()
		f.rooms = saved
		f.mu.Unlock()
		syncNow(tc, "b")
		if status, _ := tc.call(t, "key1", "GET", "/v1/sandboxes/"+bid, nil); status != 200 {
			t.Fatalf("re-adopted room: %d, want 200", status)
		}
		n, after := endedReadings(t, tc, bid)
		if n != 1 || len(after) != len(before) {
			t.Fatalf("readings before %+v after %+v, want one ended reading and nothing new", before, after)
		}
	})
}

// Pins today's behaviour for #648's freeze, which another team must rule on
// (is a frozen room billable?). The hotel still lists a frozen room, with
// state "frozen"; the broker keeps it as a running room, and the usage meter
// counts its seconds like any listed room: readings say "running" and carry
// no billable field.
func TestUsageMeterFrozenRoomIsStillMeteredAsBillable(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	tc.b.cfg.MeterKeySHA256 = sha("meter-key")
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	syncNow(tc, "b")
	status, doc := tc.call(t, "meter-key", "POST", "/v1/broker/guests/g1/freeze-all", nil)
	if frozen, _ := doc["frozen"].([]any); status != 200 || len(frozen) != 1 || frozen[0] != bid {
		t.Fatalf("freeze-all: %d %v", status, doc)
	}
	if s := hotelRoomState(tc.hotels["b"], strings.SplitN(bid, ".", 2)[1]); s != "frozen" {
		t.Fatalf("hotel room state %v, want frozen", s)
	}
	m := tc.b.usageMeter
	for i := 0; i < 2; i++ {
		// 20 s between sightings and a reading due, without sleeping.
		m.mu.Lock()
		r := m.runs[bid]
		r.lastSeen, r.lastAt = r.lastSeen.Add(-20*time.Second), r.lastAt-61
		m.mu.Unlock()
		syncNow(tc, "b")
	}
	tc.b.mu.Lock()
	rm := tc.b.byBID(bid)
	running := rm != nil && rm.state == stRunning
	tc.b.mu.Unlock()
	if !running {
		t.Fatal("the broker no longer holds the frozen room as running")
	}
	all := usageMeterRunsOf(t, tc, bid)
	if len(all) != 3 {
		t.Fatalf("readings %+v, want the first and two more", all)
	}
	for i, r := range all {
		if r.State != "running" || r.Billable != nil || r.Seconds < int64(20*i) {
			t.Fatalf("reading %d of a frozen room: %+v", i, r)
		}
	}
}

// seedListedRoom puts a room on fake hotel f with these labels and size, as
// a hotel lists a room the broker has not seen yet.
func seedListedRoom(f *fakeHotel, id string, labels map[string]any, vcpu, gib int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rooms = append(f.rooms, map[string]any{"id": id, "state": "running", "labels": labels,
		"resources": map[string]any{"vcpu": vcpu, "memory_gib": gib, "disk_gib": 10}})
}

// unseen fails the test unless neither the room map nor the meter knows run.
func unseen(t *testing.T, tc *testChain, run string) {
	t.Helper()
	tc.b.mu.Lock()
	inMap := tc.b.byBID(run) != nil
	tc.b.mu.Unlock()
	tc.b.usageMeter.mu.Lock()
	known := tc.b.usageMeter.runs[run] != nil
	tc.b.usageMeter.mu.Unlock()
	if inMap || known {
		t.Fatalf("run %s already seen: in the room map %v, in the meter %v", run, inMap, known)
	}
}

// Codex finding on #622: a room that no sync list has shown (here no list of
// its hotel has answered since the broker started, as right after a deploy)
// and that a bulk delete removes gets its first reading from the delete's
// own list, built as the sync builds it, and its ended reading from the
// delete: once each, with the guest and size of the list.
func TestUsageMeterBulkDeleteMetersARoomNoSyncSaw(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	seedListedRoom(tc.hotels["b"], "sbx_old", map[string]any{guestLabel: "g1", "job": "x"}, 2, 8)
	run := "b.sbx_old"
	unseen(t, tc, run)
	if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes?label=job=x", nil); status != 200 {
		t.Fatalf("bulk delete: %d %v", status, doc)
	}
	syncNow(tc, "b") // the room is gone: a later sync adds nothing
	got := usageMeterRunsOf(t, tc, run)
	if len(got) != 2 {
		t.Fatalf("readings %+v, want a first and an ended reading", got)
	}
	for i, r := range got {
		want := []string{"running", "ended"}[i]
		if r.State != want || r.Guest != "g1" || r.Hotel != "b" || r.VCPU != 2 || r.MemoryGiB != 8 || r.Billable != nil || r.Seconds != 0 || r.StartedAt != got[0].StartedAt {
			t.Fatalf("reading %d: %+v, want %s for g1 with 2 vCPU, 8 GiB, billable", i, r, want)
		}
	}
}

// A hotel that ignores the bulk delete's label filter lists every room. A
// room outside the filter (another label, another guest, no guest label)
// gets no reading from that list, as before the fix.
func TestUsageMeterBulkDeleteSkipsRoomsOutsideTheFilter(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	f := tc.hotels["b"]
	f.mu.Lock()
	f.listIgnoresLabels = true
	f.mu.Unlock()
	seedListedRoom(f, "sbx_other", map[string]any{guestLabel: "g1", "job": "y"}, 1, 4)
	seedListedRoom(f, "sbx_g2", map[string]any{guestLabel: "g2", "job": "x"}, 1, 4)
	seedListedRoom(f, "sbx_nolabel", map[string]any{"job": "x"}, 1, 4)
	if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes?label=job=x", nil); status != 200 {
		t.Fatalf("bulk delete: %d %v", status, doc)
	}
	for _, run := range []string{"b.sbx_other", "b.sbx_g2", "b.sbx_nolabel"} {
		if got := usageMeterRunsOf(t, tc, run); len(got) != 0 {
			t.Fatalf("run %s outside the filter: readings %+v, want none", run, got)
		}
	}
}

// A bulk delete that fails after its list leaves the run open: the first
// reading is written and there is no ended reading; the next sync observes
// the run.
func TestUsageMeterFailedBulkDeleteLeavesTheRunOpen(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	f := tc.hotels["b"]
	seedListedRoom(f, "sbx_old", map[string]any{guestLabel: "g1", "job": "x"}, 2, 8)
	run := "b.sbx_old"
	unseen(t, tc, run)
	f.mu.Lock()
	f.bulkClaimBusy, f.bulkFailAfterBusy = 1, true // a claim refusal, then a 503
	f.mu.Unlock()
	if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes?label=job=x", nil); status == 200 {
		t.Fatalf("bulk delete succeeded: %v", doc)
	}
	got := usageMeterRunsOf(t, tc, run)
	if len(got) != 1 || got[0].State != "running" || got[0].Guest != "g1" || got[0].VCPU != 2 || got[0].MemoryGiB != 8 || got[0].Billable != nil {
		t.Fatalf("readings after a failed delete %+v, want one first reading", got)
	}
	syncNow(tc, "b")
	tc.b.usageMeter.mu.Lock()
	open := tc.b.usageMeter.runs[run] != nil
	tc.b.usageMeter.mu.Unlock()
	if !open {
		t.Fatal("the run is not open after a failed delete and a sync")
	}
	for _, r := range usageMeterRunsOf(t, tc, run) {
		if r.State == "ended" {
			t.Fatalf("ended reading after a failed delete: %+v", r)
		}
	}
}

// A recorded leftover of a failed create that the bulk delete's list shows
// first is metered by the sync's rule: not billable, then ended.
func TestUsageMeterBulkDeleteMetersALeftoverAsNotBillable(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	seedListedRoom(tc.hotels["b"], "sbx_left", map[string]any{guestLabel: "g1", batchLabel: "bt1", "job": "x"}, 1, 4)
	setHotel(tc, "b", func(h *hotel) {
		if h.unreaped == nil {
			h.unreaped = map[string]*unreapedBatch{}
		}
		h.unreaped["bt1"] = &unreapedBatch{guest: "g1", keep: map[string]bool{}}
	})
	run := "b.sbx_left"
	unseen(t, tc, run)
	if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes?label=job=x", nil); status != 200 {
		t.Fatalf("bulk delete: %d %v", status, doc)
	}
	got := usageMeterRunsOf(t, tc, run)
	if len(got) != 2 || got[0].State != "running" || got[1].State != "ended" {
		t.Fatalf("readings %+v, want a first and an ended reading", got)
	}
	for _, r := range got {
		if r.Billable == nil || *r.Billable {
			t.Fatalf("a leftover's reading is billable: %+v", r)
		}
	}
}

// The bulk delete's list and a sync that see a new room at the same time
// write one first reading between them: seenLocked keeps one run per id. In
// either order, and when both run at once.
func TestUsageMeterBulkDeleteListAndSyncWriteOneFirstReading(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	f := tc.hotels["b"]
	h := tc.b.hotelByID("b")
	q := url.Values{"label": {"job=x", guestLabel + "=g1"}}
	firsts := func(run string) int {
		n := 0
		for _, r := range usageMeterRunsOf(t, tc, run) {
			if r.State == "running" && r.Seconds == 0 {
				n++
			}
		}
		return n
	}
	seedListedRoom(f, "sbx_1", map[string]any{guestLabel: "g1", "job": "x"}, 1, 4)
	tc.b.bulkDeleteTargets(context.Background(), h, q)
	syncNow(tc, "b")
	seedListedRoom(f, "sbx_2", map[string]any{guestLabel: "g1", "job": "x"}, 1, 4)
	syncNow(tc, "b")
	tc.b.bulkDeleteTargets(context.Background(), h, q)
	for i := 3; i < 13; i++ {
		seedListedRoom(f, fmt.Sprintf("sbx_%d", i), map[string]any{guestLabel: "g1", "job": "x"}, 1, 4)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); tc.b.bulkDeleteTargets(context.Background(), h, q) }()
		go func() { defer wg.Done(); syncNow(tc, "b") }()
		wg.Wait()
	}
	for i := 1; i < 13; i++ {
		run := fmt.Sprintf("b.sbx_%d", i)
		if n := firsts(run); n != 1 {
			t.Fatalf("run %s: %d first readings, want 1: %+v", run, n, usageMeterRunsOf(t, tc, run))
		}
	}
}
