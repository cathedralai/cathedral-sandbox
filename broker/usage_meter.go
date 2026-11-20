// Usage meter: a numbered, durable log of usage readings for every room of
// every guest (usage receipts, stage 1).
//
// Any use of Cathedral compute must leave a usage record that is written
// once, can be billed and can be checked. Polling "what runs now" is not
// metering: a room that lives between two polls is never seen, and a start
// and stop pair loses money when either half is lost. So the front door
// writes cumulative readings, "run R has used N observed seconds so far". A
// reader keeps the largest reading per run and charges the increase, so a
// reading read twice, late or out of order costs nothing.
//
// One JSON line per reading, schema cathedral_usage_reading_v1:
//
//	{"schema", "seq", "run", "guest", "hotel", "miner_hotkey", "vcpu",
//	 "memory_gib", "started_at", "seconds", "state", "at"}
//
// seq starts at 1, never repeats and survives a restart. run is the broker
// room id (<hotel>.<hotel room id>). miner_hotkey is the hotel's, or "".
// vcpu and memory_gib come from the room's resources (0: unknown).
// started_at and at are unix seconds on the broker clock. state is
// "running" or "ended". guest is the room's broker_guest label ("" for a
// room no guest created through the broker).
//
// A run is sighted when the broker's own create answers, when a hotel room
// list shows it (syncHotel, every 2 s), and when the broker's own delete is
// confirmed. seconds adds the time between two sightings only when they are
// at most usageMaxGap apart. A hotel that stops answering, or a broker that
// is down, adds nothing: a customer is never billed for time nobody saw.
// After a restart a run goes on from its logged seconds and keeps its logged
// started_at; the downtime adds nothing.
//
// A reading is written at first sight (seconds 0), then on a sighting once
// usage_meter_every_seconds (default 60) have passed since the run's last
// reading, and once "ended" when the room leaves: its delete is confirmed,
// or the broker drops it from the hotel's room map (vanished, released,
// forgotten, hotel gone). An ended run is final: a later sighting of the
// same run is logged, not metered again. A clean shutdown writes a last
// reading for every run whose seconds grew since its last one.
//
// Readings queue in memory and one writer (flush) appends them to
// state_dir/usage/<first seq, 20 digits>.jsonl with one fsync per batch,
// as drain_notice.go appends its log. A file holds at most usageFileLines
// readings, and each broker start begins a new file. A failed append keeps
// the readings queued and retries on the next flush; it never stops the
// broker and never drops a reading. Replay at start restores the next seq
// and every run without an ended reading; a torn or corrupt line is skipped
// and logged.
//
// GET /v1/broker/usage-meter?after=<seq>&limit=<n> (operator key) serves the
// durable readings after seq "after" in seq order. A file is deleted only
// when every seq in it is at or below the acknowledged cursor (the highest
// "after" the route was called with, kept in state_dir/usage/acked.json)
// and it is older than 7 days. With no state_dir the meter is off and the
// route answers 404 usage_meter_off.
//
// These readings are the front door's observation, not proof: nothing here
// is signed by the guest. Guest-signed checkpoints are stage 2.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	usageReadingSchema     = "cathedral_usage_reading_v1"
	usageDirName           = "usage"
	usageAckedFile         = "acked.json"
	usageFileLines         = 100000
	usageMaxGap            = 30 * time.Second   // a longer gap between two sightings adds nothing
	usageEndedKeep         = 24 * time.Hour     // an ended run id is remembered this long, so a late sighting is not metered again
	usagePruneAge          = 7 * 24 * time.Hour // a file this old and fully acknowledged may go
	usageFlushEvery        = 5 * time.Second    // the writer retries a failed append this often without new readings
	defaultUsageMeterEvery = 60                 // seconds between readings of a running run
	usagePageDefault       = 500
	usagePageMax           = 1000
)

var usageFileRE = regexp.MustCompile(`^[0-9]{20}\.jsonl$`)

// usageReading is one line of the log. Keep the field order: seq is the
// second field, so a reader can find it at a glance.
type usageReading struct {
	Schema      string  `json:"schema"`
	Seq         int64   `json:"seq"`
	Run         string  `json:"run"`
	Guest       string  `json:"guest"`
	Hotel       string  `json:"hotel"`
	MinerHotkey string  `json:"miner_hotkey"`
	VCPU        float64 `json:"vcpu"`
	MemoryGiB   float64 `json:"memory_gib"`
	StartedAt   int64   `json:"started_at"`
	Seconds     int64   `json:"seconds"`
	State       string  `json:"state"`
	At          int64   `json:"at"`
}

// usageRun is a run without an ended reading.
type usageRun struct {
	last     usageReading  // identity, size and start; Seq, State and At are set per reading
	observed time.Duration // observed time so far
	lastSeen time.Time     // last sighting; zero: none since this broker started
	lastAt   int64         // at of the run's last queued reading
}

// observe adds the time since the last sighting when the gap is short.
func (r *usageRun) observe(at time.Time) {
	if !r.lastSeen.IsZero() {
		if gap := at.Sub(r.lastSeen); gap > 0 && gap <= usageMaxGap {
			r.observed += gap
		}
	}
	if at.After(r.lastSeen) {
		r.lastSeen = at
	}
}

// usageSighting is what the broker saw of one room.
type usageSighting struct {
	run, guest, hotel, miner string
	vcpu, memGiB             float64
}

func (r *usageRun) update(s usageSighting) {
	r.last.Guest, r.last.Hotel, r.last.MinerHotkey = s.guest, s.hotel, s.miner
	if s.vcpu > 0 {
		r.last.VCPU = s.vcpu
	}
	if s.memGiB > 0 {
		r.last.MemoryGiB = s.memGiB
	}
}

func usageSightingOf(h *hotel, rm *room, resources any) usageSighting {
	vcpu, mem := usageSizeOf(resources)
	return usageSighting{run: rm.id, guest: rm.guest, hotel: h.cfg.ID, miner: h.cfg.MinerHotkey, vcpu: vcpu, memGiB: mem}
}

// usageSizeOf reads resources.vcpu and resources.memory_gib, as diskGiBOf
// reads disk_gib. 0: absent or not a positive number.
func usageSizeOf(resources any) (vcpu, memGiB float64) {
	m, _ := resources.(map[string]any)
	num := func(k string) float64 {
		if v, ok := m[k].(float64); ok && v > 0 && !math.IsInf(v, 0) {
			return v
		}
		return 0
	}
	return num("vcpu"), num("memory_gib")
}

// createdResources is the size of a room the broker's create started: the
// hotel's answer, or the create body when the answer has none.
func createdResources(doc map[string]any, body []byte) any {
	if r, ok := doc["resources"].(map[string]any); ok {
		return r
	}
	var req struct {
		Resources map[string]any `json:"resources"`
	}
	_ = json.Unmarshal(body, &req)
	return req.Resources
}

type usageEnded struct {
	at    time.Time
	noted bool // a sighting after the end was logged
}

type usageFile struct {
	path  string
	first int64
}

type usageMeter struct {
	dir      string
	every    int64 // seconds
	maxLines int   // lines per file (usageFileLines; tests lower it)
	// write appends p to f and makes it durable. Tests replace it to fail.
	write func(f *os.File, p []byte) error
	known func(hotelID string) bool // the hotel is in the broker now; nil: every hotel
	kick  chan struct{}

	mu          sync.Mutex // guards the fields below; never held for file I/O
	runs        map[string]*usageRun
	ended       map[string]*usageEnded
	endedPruned time.Time
	pending     []usageReading // queued in order, not yet durable; Seq unset
	nextSeq     int64
	head        int64                // highest durable seq
	acked       int64                // highest "after" the route was called with, at most head
	listedAt    map[string]time.Time // hotel id -> its last room list that answered
	opened      time.Time
	writeErrors int64
	errLogged   time.Time

	ioMu      sync.Mutex // one flush or page at a time; guards the open file
	f         *os.File
	fname     string
	fileLines int
	fileSize  int64
}

// openMeter starts the usage meter in state_dir/usage. No state_dir: off.
func (b *broker) openMeter() error {
	if b.cfg.UsageMeterEverySeconds < 0 {
		return errors.New("usage_meter_every_seconds must be 0 (the default, 60) or more")
	}
	if b.cfg.StateDir == "" {
		return nil
	}
	every := int64(b.cfg.UsageMeterEverySeconds)
	if every == 0 {
		every = defaultUsageMeterEvery
	}
	m, err := openUsageMeter(filepath.Join(b.cfg.StateDir, usageDirName), every, time.Now())
	if err != nil {
		return err
	}
	m.known = func(id string) bool { return b.hotelByID(id) != nil }
	b.meter = m
	return nil
}

func openUsageMeter(dir string, every int64, now time.Time) (*usageMeter, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	m := &usageMeter{dir: dir, every: every, maxLines: usageFileLines, write: appendDurable, kick: make(chan struct{}, 1),
		runs: map[string]*usageRun{}, ended: map[string]*usageEnded{}, listedAt: map[string]time.Time{}, opened: now}
	files, err := m.files()
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		if err := m.replay(f.path); err != nil {
			return nil, err
		}
	}
	m.nextSeq = m.head + 1
	m.pruneEndedLocked(now)
	raw, err := os.ReadFile(filepath.Join(dir, usageAckedFile))
	switch {
	case err == nil:
		var a struct {
			Acked int64 `json:"acked"`
		}
		if json.Unmarshal(raw, &a) != nil || a.Acked < 0 {
			log.Printf("usage meter: %s is not a cursor; starting from 0 (nothing is pruned until the route is read)", usageAckedFile)
		} else {
			m.acked = min(a.Acked, m.head)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	log.Printf("usage meter: %d files, head %d, %d open runs", len(files), m.head, len(m.runs))
	return m, nil
}

// files lists the log files in seq order (their names are zero padded).
func (m *usageMeter) files() ([]usageFile, error) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return nil, err
	}
	var out []usageFile
	for _, e := range entries {
		if !e.Type().IsRegular() || !usageFileRE.MatchString(e.Name()) {
			continue
		}
		first, err := strconv.ParseInt(e.Name()[:20], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, usageFile{path: filepath.Join(m.dir, e.Name()), first: first})
	}
	return out, nil
}

func (m *usageMeter) replay(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	rd := bufio.NewReader(f)
	for n := 1; ; n++ {
		line, err := rd.ReadBytes('\n')
		if err == io.EOF {
			if len(line) > 0 {
				log.Printf("usage meter: %s line %d: torn last line skipped (%d bytes)", path, n, len(line))
			}
			return nil
		}
		if err != nil {
			return err
		}
		var r usageReading
		if json.Unmarshal(line, &r) != nil || r.Schema != usageReadingSchema || r.Run == "" || (r.State != "running" && r.State != "ended") {
			log.Printf("usage meter: %s line %d: not a reading, skipped", path, n)
			continue
		}
		if r.Seq <= m.head {
			log.Printf("usage meter: %s line %d: seq %d is not after %d, skipped", path, n, r.Seq, m.head)
			continue
		}
		m.head = r.Seq
		if m.ended[r.Run] != nil {
			continue // ended is final
		}
		if r.State == "ended" {
			delete(m.runs, r.Run)
			m.ended[r.Run] = &usageEnded{at: time.Unix(r.At, 0)}
			continue
		}
		run := m.runs[r.Run]
		if run == nil {
			run = &usageRun{}
			m.runs[r.Run] = run
		}
		run.last = r
		run.observed = time.Duration(r.Seconds) * time.Second
		run.lastAt = r.At
	}
}

// seen records a sighting of a run at at. The first sighting writes the
// run's first reading. Callers may hold b.mu.
func (m *usageMeter) seen(s usageSighting, at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seenLocked(s, at)
	m.kickLocked()
}

func (m *usageMeter) seenLocked(s usageSighting, at time.Time) {
	if s.run == "" {
		return
	}
	if e := m.ended[s.run]; e != nil {
		if !e.noted {
			e.noted = true
			log.Printf("usage meter: run %s seen after its ended reading; not metered again", s.run)
		}
		return
	}
	r := m.runs[s.run]
	if r == nil {
		r = &usageRun{last: usageReading{Run: s.run, StartedAt: at.Unix()}, lastSeen: at}
		r.update(s)
		m.runs[s.run] = r
		m.queueLocked(r, "running", at)
		return
	}
	r.update(s)
	r.observe(at)
	if at.Unix()-r.lastAt >= m.every {
		m.queueLocked(r, "running", at)
	}
}

// end writes the ended reading of a run. confirmed: the broker's own delete
// removed the room at at, so the time since its last sighting counts (when
// the gap is short). Callers may hold b.mu.
func (m *usageMeter) end(run string, at time.Time, confirmed bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endLocked(run, at, confirmed)
	m.kickLocked()
}

func (m *usageMeter) endLocked(run string, at time.Time, confirmed bool) {
	r := m.runs[run]
	if r == nil {
		return
	}
	if confirmed {
		r.observe(at)
	}
	m.queueLocked(r, "ended", at)
	delete(m.runs, run)
	m.ended[run] = &usageEnded{at: at}
}

func (m *usageMeter) queueLocked(r *usageRun, state string, at time.Time) {
	rd := r.last
	rd.Schema, rd.Seq, rd.State, rd.At = usageReadingSchema, 0, state, at.Unix()
	rd.Seconds = int64(r.observed / time.Second)
	r.last.Seconds = rd.Seconds
	r.lastAt = rd.At
	m.pending = append(m.pending, rd)
}

func (m *usageMeter) kickLocked() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// hotelPass applies one sync pass of a hotel: the rooms its list showed
// (listed), then, when the room map is known (endAbsent), the end of every
// run of the hotel that the broker no longer holds (present: the run ids in
// the hotel's room map). A run on a hotel the broker no longer knows ends
// too. listOK: the room list answered at at. The caller holds b.mu, so
// present and the create and delete hooks agree.
func (m *usageMeter) hotelPass(hotelID string, listed []usageSighting, present map[string]bool, at time.Time, listOK, endAbsent bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if listOK {
		m.listedAt[hotelID] = at
	}
	for _, s := range listed {
		m.seenLocked(s, at)
	}
	for id, r := range m.runs {
		if endAbsent && r.last.Hotel == hotelID && !present[id] {
			m.endLocked(id, at, false)
		}
	}
	m.sweepLocked(at)
	m.kickLocked()
}

// sweepLocked ends the runs of hotels the broker no longer has (a forgotten
// or departed hotel has no sync pass to end them) and forgets old ends.
func (m *usageMeter) sweepLocked(now time.Time) {
	if m.known != nil {
		for id, r := range m.runs {
			if !m.known(r.last.Hotel) {
				m.endLocked(id, now, false)
				delete(m.listedAt, r.last.Hotel)
			}
		}
	}
	m.pruneEndedLocked(now)
}

func (m *usageMeter) pruneEndedLocked(now time.Time) {
	if now.Sub(m.endedPruned) < time.Minute {
		return
	}
	m.endedPruned = now
	for id, e := range m.ended {
		if now.Sub(e.at) > usageEndedKeep {
			delete(m.ended, id)
		}
	}
}

// checkpoint queues a reading for every run whose seconds grew since its
// last reading, so a clean restart loses no observed time.
func (m *usageMeter) checkpoint(now time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.runs {
		if int64(r.observed/time.Second) > r.last.Seconds {
			m.queueLocked(r, "running", now)
		}
	}
}

// observedAtLocked is the oldest last answered room list among the hotels
// with runs not ended (a hotel that has not listed since start counts from
// the meter's start), or now when no run is open. A reader can tell from it
// how fresh the meter is.
func (m *usageMeter) observedAtLocked(now time.Time) int64 {
	oldest := now
	for _, r := range m.runs {
		t, ok := m.listedAt[r.last.Hotel]
		if !ok {
			t = m.opened
		}
		if t.Before(oldest) {
			oldest = t
		}
	}
	return oldest.Unix()
}

// run is the writer: it flushes when readings are queued, and on a timer so
// a failed append is retried.
func (m *usageMeter) run(ctx context.Context) {
	if m == nil {
		return
	}
	t := time.NewTicker(usageFlushEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.kick:
		case <-t.C:
			m.mu.Lock()
			m.sweepLocked(time.Now())
			m.mu.Unlock()
		}
		_ = m.flush()
	}
}

// flush appends the queued readings in seq order and makes them durable.
// On a failed append the readings stay queued for the next flush.
func (m *usageMeter) flush() error {
	if m == nil {
		return nil
	}
	m.ioMu.Lock()
	defer m.ioMu.Unlock()
	for {
		m.mu.Lock()
		batch := append([]usageReading(nil), m.pending...)
		seq := m.nextSeq
		m.mu.Unlock()
		if len(batch) == 0 {
			return nil
		}
		if m.f == nil || m.fileLines >= m.maxLines {
			if err := m.rollLocked(seq); err != nil {
				return m.failed(err)
			}
		}
		n := min(len(batch), m.maxLines-m.fileLines)
		var buf bytes.Buffer
		for i := range batch[:n] {
			batch[i].Seq = seq + int64(i)
			line, err := json.Marshal(batch[i])
			if err != nil {
				return m.failed(err)
			}
			buf.Write(line)
			buf.WriteByte('\n')
		}
		if err := m.appendLocked(buf.Bytes(), int64(n)); err != nil {
			return m.failed(err)
		}
		m.fileLines += n
		m.mu.Lock()
		m.pending = m.pending[n:]
		if len(m.pending) == 0 {
			m.pending = nil
		}
		m.nextSeq = seq + int64(n)
		m.head = m.nextSeq - 1
		m.mu.Unlock()
	}
}

// appendLocked appends n readings (p) to the open file. When the append
// fails, its partial lines are cut off so the retry can use the same seqs;
// if that fails too, the file is closed and the n seqs are never used again,
// as some of them may be on disk.
func (m *usageMeter) appendLocked(p []byte, n int64) error {
	err := m.write(m.f, p)
	if err == nil {
		m.fileSize += int64(len(p))
		return nil
	}
	if m.f.Truncate(m.fileSize) == nil && m.f.Sync() == nil {
		return err
	}
	_ = m.f.Close()
	m.f, m.fname = nil, ""
	m.mu.Lock()
	m.nextSeq += n
	m.mu.Unlock()
	return err
}

// rollLocked starts the file whose first seq is first.
func (m *usageMeter) rollLocked(first int64) error {
	if m.f != nil {
		_ = m.f.Close()
		m.f, m.fname = nil, ""
	}
	name := filepath.Join(m.dir, fmt.Sprintf("%020d.jsonl", first))
	flags := os.O_WRONLY | os.O_APPEND | os.O_CREATE | os.O_EXCL
	f, err := os.OpenFile(name, flags, 0o600)
	if errors.Is(err, fs.ErrExist) {
		// Replay found no reading at or after this seq, so this file holds
		// only a torn line from a crash. Keep it aside, out of the log.
		aside := fmt.Sprintf("%s.torn-%d", name, time.Now().UnixNano())
		if rerr := os.Rename(name, aside); rerr != nil {
			return rerr
		}
		log.Printf("usage meter: %s held no reading; moved to %s", name, filepath.Base(aside))
		f, err = os.OpenFile(name, flags, 0o600)
	}
	if err != nil {
		return err
	}
	// Best effort: the file's own fsync holds its lines; a directory that
	// cannot sync (some file systems) must not stop the meter.
	if d, derr := os.Open(m.dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	m.f, m.fname, m.fileLines, m.fileSize = f, name, 0, 0
	return nil
}

func appendDurable(f *os.File, p []byte) error {
	if _, err := f.Write(p); err != nil {
		return err
	}
	return f.Sync()
}

func (m *usageMeter) failed(err error) error {
	m.mu.Lock()
	m.writeErrors++
	queued, n := len(m.pending), m.writeErrors
	logNow := time.Since(m.errLogged) >= time.Minute
	if logNow {
		m.errLogged = time.Now()
	}
	m.mu.Unlock()
	if logNow {
		log.Printf("usage meter: append failed (%d failures so far), %d readings stay queued: %v", n, queued, err)
	}
	return err
}

// usagePage is the answer of GET /v1/broker/usage-meter.
type usagePage struct {
	Readings    []json.RawMessage `json:"readings"`
	Next        int64             `json:"next"`         // seq of the last reading here, or after when there is none
	Head        int64             `json:"head"`         // highest seq written
	ObservedAt  int64             `json:"observed_at"`  // oldest last answered list among hotels with live rooms; now if none
	WriteErrors int64             `json:"write_errors"` // failed appends since start
}

// page serves up to limit durable readings after seq after, records after
// as acknowledged, and prunes what the cursor and age allow.
func (m *usageMeter) page(after int64, limit int, now time.Time) (usagePage, error) {
	m.ioMu.Lock()
	defer m.ioMu.Unlock()
	m.mu.Lock()
	head := m.head
	p := usagePage{Readings: []json.RawMessage{}, Next: after, Head: head, ObservedAt: m.observedAtLocked(now), WriteErrors: m.writeErrors}
	acked, moved := m.acked, false
	if a := min(after, head); a > acked {
		m.acked, acked, moved = a, a, true
	}
	m.mu.Unlock()
	if moved {
		if err := m.saveAcked(acked); err != nil {
			log.Printf("usage meter: acknowledged cursor %d not saved: %v", acked, err)
		}
	}
	files, err := m.files()
	if err != nil {
		return p, err
	}
	for i, f := range files {
		if len(p.Readings) >= limit || f.first > head {
			break
		}
		if i+1 < len(files) && files[i+1].first-1 <= after {
			continue // every seq in it is at or below after
		}
		if err := readUsageFile(f.path, &p, head, limit); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return p, err
		}
	}
	m.pruneLocked(files, acked, now)
	return p, nil
}

// readUsageFile adds the readings of one file after p.Next and up to head.
// p.Next moves with every reading taken, so the page is in seq order and
// skips none. A torn last line is not served.
func readUsageFile(path string, p *usagePage, head int64, limit int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	rd := bufio.NewReader(f)
	for len(p.Readings) < limit {
		line, err := rd.ReadBytes('\n')
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var r struct {
			Schema string `json:"schema"`
			Seq    int64  `json:"seq"`
		}
		if json.Unmarshal(line, &r) != nil || r.Schema != usageReadingSchema || r.Seq <= p.Next {
			continue
		}
		if r.Seq > head {
			return nil
		}
		p.Readings = append(p.Readings, json.RawMessage(bytes.TrimRight(line, "\n")))
		p.Next = r.Seq
	}
	return nil
}

// pruneLocked deletes the files whose every seq is at or below acked and
// that are older than usagePruneAge. The newest file and the open one stay.
func (m *usageMeter) pruneLocked(files []usageFile, acked int64, now time.Time) {
	for i := 0; i+1 < len(files); i++ {
		if files[i+1].first-1 > acked {
			return // files are in seq order: no later file is acknowledged either
		}
		if files[i].path == m.fname {
			continue
		}
		st, err := os.Stat(files[i].path)
		if err != nil || now.Sub(st.ModTime()) <= usagePruneAge {
			continue
		}
		if err := os.Remove(files[i].path); err != nil {
			log.Printf("usage meter: prune %s: %v", filepath.Base(files[i].path), err)
			continue
		}
		log.Printf("usage meter: pruned %s (acknowledged through %d)", filepath.Base(files[i].path), acked)
	}
}

func (m *usageMeter) saveAcked(acked int64) error {
	raw, err := json.Marshal(map[string]int64{"acked": acked})
	if err != nil {
		return err
	}
	tmp := filepath.Join(m.dir, usageAckedFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(m.dir, usageAckedFile))
}

// meterHotel hands one sync pass of h to the meter. Until a room list has
// answered since start, the room map is empty because nobody looked, not
// because the rooms are gone: their runs do not end. Caller holds b.mu.
func (b *broker) meterHotel(h *hotel, listed []usageSighting, at time.Time, listOK bool) {
	if b.meter == nil {
		return
	}
	present := make(map[string]bool, len(h.rooms))
	for _, rm := range h.rooms {
		present[rm.id] = true
	}
	b.meter.hotelPass(h.cfg.ID, listed, present, at, listOK, !h.roomsUnchecked)
}

// handleUsageMeter serves GET /v1/broker/usage-meter (operator key).
func (b *broker) handleUsageMeter(w http.ResponseWriter, r *http.Request) {
	if !b.isOperator(r) {
		writeErr(w, 401, "unauthorized", "operator key required")
		return
	}
	if r.Method != "GET" {
		writeErr(w, 405, "method_not_allowed", "the usage meter is read with GET")
		return
	}
	if b.meter == nil {
		writeErr(w, 404, "usage_meter_off", "this broker has no state_dir, so it keeps no usage meter")
		return
	}
	q := r.URL.Query()
	after, limit := int64(0), usagePageDefault
	if v := q.Get("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			writeErr(w, 400, "invalid_after", "after must be a seq: an integer, 0 or more")
			return
		}
		after = n
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeErr(w, 400, "invalid_limit", fmt.Sprintf("limit must be an integer from 1 to %d", usagePageMax))
			return
		}
		limit = min(n, usagePageMax)
	}
	p, err := b.meter.page(after, limit, time.Now())
	if err != nil {
		log.Printf("usage meter: read: %v", err)
		writeErr(w, 500, "usage_meter_read_failed", "the usage log could not be read")
		return
	}
	writeJSON(w, 200, p)
}
