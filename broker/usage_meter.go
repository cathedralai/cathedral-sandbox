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
// room no guest created through the broker). An optional "billable": false
// marks a room the broker took back from a cancelled or failed create (its
// reap, or a recorded leftover): it used compute, so it is metered, but the
// guest does not pay for it. Absent means billable; once a run says false,
// every later reading of it does.
//
// A run is sighted when the broker's own create answers, when a hotel room
// list shows it (syncHotel, every 2 s), when a bulk delete's list shows it
// just before the delete, and when the broker's own delete removes it.
// seconds adds the time between two sightings only when they are at most
// usageMaxGap apart. A hotel that stops answering, or a broker that is down,
// adds nothing: a customer is never billed for time nobody saw. A delete
// adds its tail only when no answered list since the last sighting left the
// room out (the hotel answers 204 for a room already gone). After a restart
// a run goes on from its logged seconds and keeps its logged started_at;
// the downtime adds nothing.
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
// and it is older than 7 days; an open run whose newest reading is in it
// gets that reading written again (new seq) first, so replay never loses
// it. Before any file goes, acked.json also records the durable head and
// the highest seq issued (written, synced, renamed), and replay starts the
// next seq above all of them, so a seq is never issued twice even when
// every file that held it is gone. With no state_dir the meter is off and
// the route answers 404 usage_meter_off.
//
// The durability rule every path keeps: a seq is served (and acknowledged)
// only when its bytes and its file's name are durable and every lower
// issued seq is either durable or was never written for a reader (an append
// the file could not take back; its readings carry later seqs). So the
// route stops just below a replayed range whose sync failed, a new file gets
// no reading until its directory has synced, and a usage/ this broker made
// gets no file until its parent has synced. Pruning happens only after
// everything queued is durable, no replayed range is unsynced, and
// acked.json's new name is durable. No page goes above the highest issued
// seq acked.json holds, so a served seq is never issued again even if its
// file is lost later. A directory the broker creates (usage/, and state_dir
// and its ancestors when missing) holds no file until every directory that
// gained an entry has synced.
//
// No disk I/O happens under b.mu. A run's turn to not billable is queued
// under it and wakes the writer; the path that saw it then waits, outside
// b.mu, at most usageTurnWait for it to be durable. A route read waits at
// most usageReadWait for a write in progress, then answers what is durable
// without acknowledging. A broker that dies inside that short window loses
// the turn: see the known limits in README.md.
//
// Crash loss, accepted: a batch is fsynced before it counts, so a broker
// that dies between an append and its fsync loses at most that batch. Those
// readings were never served (head did not include them), so their seqs may
// be issued again without any reader seeing two contents. No time already
// in a durable reading is lost: readings are cumulative, and the run's next
// sighting after the restart writes its seconds again under a new seq. What
// the lost batch alone held (the observed time since the run's previous
// durable reading, at most usage_meter_every_seconds, and a delete's tail)
// is the front door death loss, in the customer's favour.
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
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
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

// Bounded waits on the disk, so a hung write never stalls the broker:
// usageTurnWait is how long a path that saw a turn to not billable waits,
// outside b.mu, for that reading to be durable before it carries on;
// usageReadWait is how long a route read waits for a write in progress
// before it answers what is durable without acknowledging. Vars for tests.
var (
	usageTurnWait = 3 * time.Second
	usageReadWait = 5 * time.Second
)

var usageFileRE = regexp.MustCompile(`^[0-9]{20}\.jsonl$`)

// usageReading is one line of the log. Keep the field order: seq is the
// second field, so a reader can find it at a glance.
type usageReading struct {
	Schema      string `json:"schema"`
	Seq         int64  `json:"seq"`
	Run         string `json:"run"`
	Guest       string `json:"guest"`
	Hotel       string `json:"hotel"`
	MinerHotkey string `json:"miner_hotkey"`
	VCPU        int64  `json:"vcpu"`
	MemoryGiB   int64  `json:"memory_gib"`
	StartedAt   int64  `json:"started_at"`
	Seconds     int64  `json:"seconds"`
	State       string `json:"state"`
	At          int64  `json:"at"`
	Billable    *bool  `json:"billable,omitempty"` // only false is written; absent: billable
}

// usageRun is a run without an ended reading.
type usageRun struct {
	last     usageReading  // identity, size and start; Seq, State and At are set per reading
	observed time.Duration // observed time so far
	lastSeen time.Time     // last sighting; zero: none since this broker started
	lastAt   int64         // at of the run's last queued reading
	lastSeq  int64         // seq of the run's newest durable reading; 0: none
	missed   bool          // an answered list since the last sighting left the room out
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
	vcpu, memGiB             int64
	billable                 bool
}

var usageNotBillable = false

// update takes the identity and size of a sighting. It reports whether the
// run just turned not billable, which must be written at once.
func (r *usageRun) update(s usageSighting) (turnedNotBillable bool) {
	r.last.Guest, r.last.Hotel, r.last.MinerHotkey = s.guest, s.hotel, s.miner
	if !s.billable && r.last.Billable == nil {
		r.last.Billable = &usageNotBillable
		turnedNotBillable = true
	}
	if s.vcpu > 0 {
		r.last.VCPU = s.vcpu
	}
	if s.memGiB > 0 {
		r.last.MemoryGiB = s.memGiB
	}
	return turnedNotBillable
}

// usageSightingOf is a sighting of a room in h's room map. A registered room
// is a guest's; one without a client id is being reaped and is not billable.
func usageSightingOf(h *hotel, rm *room, resources any) usageSighting {
	vcpu, mem := usageSizeOf(resources)
	return usageSighting{run: rm.id, guest: rm.guest, hotel: h.cfg.ID, miner: h.cfg.MinerHotkey, vcpu: vcpu, memGiB: mem, billable: rm.uuid != ""}
}

// usageSizeOf reads resources.vcpu and resources.memory_gib as whole
// numbers, as diskGiBOf reads disk_gib: a fractional value rounds up. 0:
// absent or not a positive number. The hotel's list always carries both
// (cathedral/sandbox_api.py Resources: integers, memory_gib 1 to 64).
func usageSizeOf(resources any) (vcpu, memGiB int64) {
	m, _ := resources.(map[string]any)
	num := func(k string) int64 {
		switch v := m[k].(type) {
		case float64:
			if v > 0 && v < math.MaxInt32 {
				return int64(math.Ceil(v))
			}
		case int:
			return int64(max(v, 0))
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

// usageUnsynced is a replayed file whose sync failed: its seqs lo to hi are
// not durable yet.
type usageUnsynced struct {
	path   string
	lo, hi int64
}

// usageSyncFile makes a replayed file durable. Tests replace it to fail.
var usageSyncFile = func(f *os.File) error { return f.Sync() }

// usageSyncDir makes the names in the usage directory durable: a new log
// file, or acked.json after its rename. Tests replace it to fail.
var usageSyncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// usageState is acked.json: the acknowledged cursor, and the durable head and
// highest issued seq when it was written.
type usageState struct {
	Acked  int64 `json:"acked"`
	Head   int64 `json:"head"`
	Issued int64 `json:"issued"`
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
	savedIssued int64                // highest issued seq that acked.json holds: no page serves above it
	// unobserved: hotels whose latest completed room list failed and that
	// take no new room (down, leaving or draining). Their rooms are not
	// metered now, by design, and they are left out of observed_at.
	unobserved  map[string]bool
	burned      [][2]int64      // seq ranges of appends the file could not take back: not durable, never served
	unsynced    []usageUnsynced // files whose sync failed at replay: not served until a sync succeeds
	opened      time.Time
	writeErrors int64
	errLogged   time.Time

	ioMu       sync.Mutex // one flush or page at a time; guards the open file
	f          *os.File
	fname      string
	nameSync   bool     // the open file's name is durable (its directory synced)
	dirsToSync []string // parents of directories this broker created, top down: synced before any file is made
	fileLines  int
	fileSize   int64
}

// loadUsageMeter starts the usage meter in state_dir/usage. No state_dir: off.
func (b *broker) loadUsageMeter() error {
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
	b.usageMeter = m
	return nil
}

func openUsageMeter(dir string, every int64, now time.Time) (*usageMeter, error) {
	newParents := parentsOfMissingDirs(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	m := &usageMeter{dir: dir, every: every, maxLines: usageFileLines, write: appendDurable, kick: make(chan struct{}, 1),
		runs: map[string]*usageRun{}, ended: map[string]*usageEnded{}, listedAt: map[string]time.Time{}, unobserved: map[string]bool{}, opened: now,
		// A directory made now (usage/, and state_dir and its ancestors if
		// they were missing) is durable only once the directory holding its
		// name syncs: until then nothing is written (dirDurableLocked).
		dirsToSync: newParents}
	files, err := m.files()
	if err != nil {
		return nil, err
	}
	var durable int64
	for _, f := range files {
		lo, hi, synced, err := m.replay(f.path)
		if err != nil {
			return nil, err
		}
		switch {
		case hi == 0: // no reading in it
		case synced:
			durable = max(durable, hi)
		default:
			m.unsynced = append(m.unsynced, usageUnsynced{path: f.path, lo: lo, hi: hi})
			m.writeErrors++
		}
	}
	seen := m.head // every seq replay saw, synced or not
	var st usageState
	raw, err := os.ReadFile(filepath.Join(dir, usageAckedFile))
	switch {
	case err == nil:
		if json.Unmarshal(raw, &st) != nil || st.Acked < 0 || st.Head < 0 || st.Issued < 0 {
			log.Printf("usage meter: %s is not a cursor; starting from 0 (nothing is pruned until the route is read)", usageAckedFile)
			st = usageState{}
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	// A seq is never issued twice: not one a file shows, nor one a pruned
	// file held (acked.json keeps the head and the highest issued seq).
	m.head = max(durable, st.Head)
	m.nextSeq = max(seen, st.Head, st.Issued, st.Acked) + 1
	m.savedIssued = st.Issued
	m.acked = min(st.Acked, m.head)
	m.pruneEndedLocked(now)
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

// replay reads one file into the meter and returns its lowest and highest
// seq (0 when it holds no reading) and whether it is durable. A line the last
// broker wrote but never synced may still be only in the page cache, so the
// file is synced first; when that fails its readings restore the runs but
// are not served (they stay out of head) until a later sync succeeds.
func (m *usageMeter) replay(path string) (lo, hi int64, synced bool, err error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, 0, false, err
	}
	defer f.Close()
	synced = true
	if serr := usageSyncFile(f); serr != nil {
		synced = false
		log.Printf("usage meter: %s: sync before replay failed, its readings are not served until a sync succeeds: %v", path, serr)
	}
	rd := bufio.NewReader(f)
	for n := 1; ; n++ {
		line, rerr := rd.ReadBytes('\n')
		if rerr == io.EOF {
			if len(line) > 0 {
				log.Printf("usage meter: %s line %d: torn last line skipped (%d bytes)", path, n, len(line))
			}
			return lo, hi, synced, nil
		}
		if rerr != nil {
			return 0, 0, false, rerr
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
		if lo == 0 {
			lo = r.Seq
		}
		hi = r.Seq
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
		run.lastAt, run.lastSeq = r.At, r.Seq
	}
}

// seen records a sighting of a run at at. The first sighting writes the
// run's first reading. Callers may hold b.mu.
// seen reports whether the run turned not billable: the caller then calls
// awaitDurable once it has released b.mu. It never touches the disk itself.
func (m *usageMeter) seen(s usageSighting, at time.Time) (turnedNotBillable bool) {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	turned := m.seenLocked(s, at)
	m.kickLocked() // the writer flushes at once, not on its timer
	return turned
}

// awaitDurable flushes what is queued and waits for it at most d. A caller
// that saw a run turn not billable calls it after releasing b.mu, so a
// broker that dies right after has the turn on disk and does not bill a
// failed create's room again; a hung disk costs this caller d, nobody else.
// The flush goes on after a timeout and the reading stays queued.
func (m *usageMeter) awaitDurable(d time.Duration) {
	if m == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_ = m.flush()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		log.Printf("usage meter: queued readings not durable after %s; the write goes on", d)
	}
}

// seenLocked reports whether the run turned not billable (a new run that
// is not billable included): the caller makes that reading durable once it
// has released b.mu (awaitDurable).
func (m *usageMeter) seenLocked(s usageSighting, at time.Time) (turnedNotBillable bool) {
	if s.run == "" {
		return false
	}
	if e := m.ended[s.run]; e != nil {
		if !e.noted {
			e.noted = true
			log.Printf("usage meter: run %s seen after its ended reading; not metered again", s.run)
		}
		return false
	}
	r := m.runs[s.run]
	if r == nil {
		r = &usageRun{last: usageReading{Run: s.run, StartedAt: at.Unix()}, lastSeen: at}
		r.update(s)
		m.runs[s.run] = r
		m.queueLocked(r, "running", at)
		return !s.billable
	}
	turned := r.update(s)
	r.observe(at)
	r.missed = false
	// A run that turns not billable gets a reading now, whatever the
	// interval: replay must restore it as not billable.
	if turned || at.Unix()-r.lastAt >= m.every {
		m.queueLocked(r, "running", at)
	}
	return turned
}

// end writes the ended reading of a run. confirmed: the broker's own delete
// removed the room at at, so the time since its last sighting counts, when
// the gap is short and no answered list since that sighting left the room
// out (a 204 for a room already gone proves nothing). Callers may hold b.mu.
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
	if confirmed && !r.missed {
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
// too. listOK: the room list answered at at. unplaceable: the broker places
// no new room on the hotel now. The caller holds b.mu, so present and the
// create and delete hooks agree.
func (m *usageMeter) hotelPass(hotelID string, listed []usageSighting, present map[string]bool, at time.Time, listOK, endAbsent, unplaceable bool) (turned bool) {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	shown := make(map[string]bool, len(listed))
	for _, s := range listed {
		if m.seenLocked(s, at) {
			turned = true
		}
		shown[s.run] = true
	}
	if listOK || !unplaceable {
		delete(m.unobserved, hotelID)
	} else {
		m.unobserved[hotelID] = true
	}
	if listOK {
		m.listedAt[hotelID] = at
		for id, r := range m.runs {
			if r.last.Hotel == hotelID && !shown[id] && r.lastSeen.Before(at) {
				r.missed = true
			}
		}
	}
	for id, r := range m.runs {
		if endAbsent && r.last.Hotel == hotelID && !present[id] {
			m.endLocked(id, at, false)
		}
	}
	m.sweepLocked(at)
	m.kickLocked()
	return turned
}

// sweepLocked ends the runs of hotels the broker no longer has (a forgotten
// or departed hotel has no sync pass to end them) and forgets old ends.
func (m *usageMeter) sweepLocked(now time.Time) {
	if m.known != nil {
		for id, r := range m.runs {
			if !m.known(r.last.Hotel) {
				m.endLocked(id, now, false)
				delete(m.listedAt, r.last.Hotel)
				delete(m.unobserved, r.last.Hotel)
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
// the meter's start), or now when none counts. A reader can tell from it
// whether the broker's own sync has stalled. A hotel whose latest completed
// list failed and that takes no new room is left out and counted in
// unobserved instead: one dead miner hotel must not make the whole meter
// look stale, and its rooms are not metered anyway. A hotel that still takes
// rooms always counts, and so does one whose list attempt never completes.
func (m *usageMeter) observedAtLocked(now time.Time) (observedAt int64, unobserved int) {
	oldest := now
	left := map[string]bool{}
	for _, r := range m.runs {
		if m.unobserved[r.last.Hotel] {
			left[r.last.Hotel] = true
			continue
		}
		t, ok := m.listedAt[r.last.Hotel]
		if !ok {
			t = m.opened
		}
		if t.Before(oldest) {
			oldest = t
		}
	}
	return oldest.Unix(), len(left)
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
	return m.flushLocked()
}

// flushLocked is flush for a caller that holds ioMu.
func (m *usageMeter) flushLocked() error {
	m.retryUnsyncedLocked()
	for {
		m.mu.Lock()
		batch := append([]usageReading(nil), m.pending...)
		seq := m.nextSeq
		m.mu.Unlock()
		if len(batch) == 0 {
			return nil
		}
		if err := m.dirDurableLocked(); err != nil { // no log file in a usage/ a crash can lose
			return m.failed(err)
		}
		if m.f == nil || m.fileLines >= m.maxLines {
			if err := m.rollLocked(seq); err != nil {
				return m.failed(err)
			}
		}
		// A file fsync keeps the lines, not the file's name: a reading in a
		// file whose name a crash can lose is not durable. Nothing goes into
		// a new file until its directory has synced; retried every flush.
		if !m.nameSync {
			if err := usageSyncDir(m.dir); err != nil {
				return m.failed(fmt.Errorf("sync of the usage directory for %s: %w", filepath.Base(m.fname), err))
			}
			m.nameSync = true
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
		for i := range batch[:n] {
			if r := m.runs[batch[i].Run]; r != nil {
				r.lastSeq = batch[i].Seq
			}
		}
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
	m.burned = append(m.burned, [2]int64{m.nextSeq, m.nextSeq + n - 1})
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
	// Its name is durable only once the directory syncs (flushLocked):
	// nothing is appended to it before that.
	m.f, m.fname, m.fileLines, m.fileSize, m.nameSync = f, name, 0, 0, false
	return nil
}

// retryUnsyncedLocked syncs again the replayed files whose sync failed; a
// file that syncs is served from then on. Caller holds ioMu.
func (m *usageMeter) retryUnsyncedLocked() {
	m.mu.Lock()
	list := append([]usageUnsynced(nil), m.unsynced...)
	m.mu.Unlock()
	if len(list) == 0 {
		return
	}
	var still []usageUnsynced
	var gained, failures int64
	for _, u := range list {
		f, err := os.OpenFile(u.path, os.O_RDWR, 0)
		// A missing file (moved aside while the broker ran) is not synced
		// either: the runs replayed from it stay as they are until a restart
		// replays without it (README, usage meter).
		if err == nil {
			err = usageSyncFile(f)
			_ = f.Close()
		}
		if err != nil {
			still = append(still, u)
			failures++
			continue
		}
		gained = max(gained, u.hi)
		log.Printf("usage meter: %s synced; seqs %d to %d are served now", filepath.Base(u.path), u.lo, u.hi)
	}
	m.mu.Lock()
	m.unsynced = still
	m.head = max(m.head, gained)
	m.writeErrors += failures
	m.mu.Unlock()
}

// dirDurableLocked syncs, top down and once each, the directories that
// gained a new directory when this broker made usage/ (and state_dir and its
// ancestors, if they were missing): a log file in a directory whose own name
// a crash can lose is not durable. Caller holds ioMu.
func (m *usageMeter) dirDurableLocked() error {
	for len(m.dirsToSync) > 0 {
		d := m.dirsToSync[0]
		if err := usageSyncDir(d); err != nil {
			return fmt.Errorf("sync of %s after creating a directory in it: %w", d, err)
		}
		m.dirsToSync = m.dirsToSync[1:]
	}
	return nil
}

// parentsOfMissingDirs is, top down, the parent of every directory from dir
// up to the first that exists: the directories whose entries MkdirAll adds.
func parentsOfMissingDirs(dir string) []string {
	var out []string
	for d := filepath.Clean(dir); ; {
		if _, err := os.Stat(d); err == nil {
			return out
		}
		p := filepath.Dir(d)
		if p == d {
			return out
		}
		out = append([]string{p}, out...)
		d = p
	}
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
	Head        int64             `json:"head"`         // highest durable seq
	ObservedAt  int64             `json:"observed_at"`  // oldest last answered list among counted hotels with live rooms; now if none
	WriteErrors int64             `json:"write_errors"` // failed appends since start
	// UnobservedHotels: hotels holding live rooms left out of observed_at
	// (latest list failed, no new room placed there).
	UnobservedHotels int `json:"unobserved_hotels"`
	// PendingReadings: readings observed but not durable yet (queued for a
	// retried append, or in a replayed file whose sync failed). 0 when all
	// is durable. head stops while the disk refuses writes; this grows.
	PendingReadings int64 `json:"pending_readings"`
}

// page serves up to limit durable readings after seq after, records after
// as acknowledged, and prunes what the cursor and age allow.
func (m *usageMeter) page(after int64, limit int, now time.Time) (usagePage, error) {
	// A hung write holds ioMu: wait at most usageReadWait, then answer what
	// is durable and already saved, with no acknowledgement and no prune.
	locked := m.lockIOWithin(usageReadWait)
	if locked {
		defer m.ioMu.Unlock()
		m.retryUnsyncedLocked()
	}
	m.mu.Lock()
	// Never serve or acknowledge a seq above a range that is not durable yet:
	// a reader whose cursor passed it would never get it once it syncs.
	head := m.head
	for _, u := range m.unsynced {
		head = min(head, u.lo-1)
	}
	// A served seq must never be issued again, even if its file is lost
	// later: acked.json holds the highest issued seq before any page goes
	// above the one it held.
	if locked && head > m.savedIssued {
		m.mu.Unlock()
		if err := m.saveState(); err != nil {
			log.Printf("usage meter: highest issued seq not saved, nothing above %d served: %v", m.savedIssuedNow(), err)
		}
		m.mu.Lock()
	}
	head = min(head, m.savedIssued)
	p := usagePage{Readings: []json.RawMessage{}, Next: after, Head: head, WriteErrors: m.writeErrors}
	p.ObservedAt, p.UnobservedHotels = m.observedAtLocked(now)
	acked, moved := m.acked, false
	if a := min(after, head); locked && a > acked {
		m.acked, acked, moved = a, a, true
	}
	skip := append([][2]int64(nil), m.burned...) // never written as far as a reader goes: their readings have later seqs
	p.PendingReadings = int64(len(m.pending))
	for _, u := range m.unsynced {
		p.PendingReadings += u.hi - u.lo + 1
	}
	m.mu.Unlock()
	if moved {
		if err := m.saveState(); err != nil {
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
		if err := readUsageFile(f.path, &p, head, limit, skip); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return p, err
		}
	}
	if locked {
		m.pruneLocked(files, acked, now)
	}
	return p, nil
}

// lockIOWithin takes ioMu if it comes free within d.
func (m *usageMeter) lockIOWithin(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if m.ioMu.TryLock() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (m *usageMeter) savedIssuedNow() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.savedIssued
}

// readUsageFile adds the readings of one file after p.Next and up to head.
// p.Next moves with every reading taken, so the page is in seq order and
// skips none. A torn last line is not served, nor a seq in burned (an
// append that failed and could not be taken back: those readings were
// queued again under new seqs).
func readUsageFile(path string, p *usagePage, head int64, limit int, burned [][2]int64) error {
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
		if inUsageRanges(r.Seq, burned) {
			continue
		}
		p.Readings = append(p.Readings, json.RawMessage(bytes.TrimRight(line, "\n")))
		p.Next = r.Seq
	}
	return nil
}

func inUsageRanges(seq int64, ranges [][2]int64) bool {
	for _, r := range ranges {
		if seq >= r[0] && seq <= r[1] {
			return true
		}
	}
	return false
}

// pruneLocked deletes the files whose every seq is at or below acked and
// that are older than usagePruneAge. The newest file and the open one stay.
// Caller holds ioMu.
func (m *usageMeter) pruneLocked(files []usageFile, acked int64, now time.Time) {
	// A replayed reading that is not synced yet may be a run's only newer
	// state (lastSeq) or its end (no longer an open run). It is no
	// replacement for the durable state in an older file: prune nothing
	// until every replayed range has synced.
	m.mu.Lock()
	unsynced := len(m.unsynced)
	m.mu.Unlock()
	if unsynced > 0 {
		return
	}
	for i := 0; i+1 < len(files); i++ {
		last := files[i+1].first - 1
		if last > acked {
			return // files are in seq order: no later file is acknowledged either
		}
		if files[i].path == m.fname {
			continue
		}
		st, err := os.Stat(files[i].path)
		if err != nil || now.Sub(st.ModTime()) <= usagePruneAge {
			continue
		}
		if err := m.carryForwardLocked(files[i].first, last, now); err != nil {
			log.Printf("usage meter: %s kept: open runs not carried forward: %v", filepath.Base(files[i].path), err)
			continue
		}
		// The seqs this file held must stay issued after it is gone, and the
		// carry forward may have issued more: save after every carry.
		if err := m.saveState(); err != nil {
			log.Printf("usage meter: nothing more pruned: %s not saved: %v", usageAckedFile, err)
			return
		}
		if err := os.Remove(files[i].path); err != nil {
			log.Printf("usage meter: prune %s: %v", filepath.Base(files[i].path), err)
			continue
		}
		log.Printf("usage meter: pruned %s (acknowledged through %d)", filepath.Base(files[i].path), acked)
	}
}

// carryForwardLocked writes again, under new seqs, the newest reading of
// every open run whose newest durable reading has a seq in [first, last], so
// deleting the file that holds it loses no run's start or seconds. The
// reading's seconds are the run's own; only seq and at are new. It then
// flushes every queued reading, carried or not: an ended reading queued for
// a run whose last durable state is in that file must be durable before the
// file goes. Caller holds ioMu.
func (m *usageMeter) carryForwardLocked(first, last int64, now time.Time) error {
	m.mu.Lock()
	for _, r := range m.runs {
		if r.lastSeq >= first && r.lastSeq <= last {
			m.queueLocked(r, "running", now)
		}
	}
	m.mu.Unlock()
	if err := m.flushLocked(); err != nil {
		return err
	}
	m.mu.Lock()
	queued := len(m.pending)
	m.mu.Unlock()
	if queued > 0 {
		return fmt.Errorf("%d readings still queued", queued)
	}
	return nil
}

// saveState writes acked.json (cursor, durable head, highest issued seq):
// temporary file, sync, rename, directory sync. A failure counts in
// write_errors; nothing is pruned on it. Caller holds ioMu.
func (m *usageMeter) saveState() error {
	issued, err := m.writeState()
	m.mu.Lock()
	if err != nil {
		m.writeErrors++
	} else {
		m.savedIssued = max(m.savedIssued, issued)
	}
	m.mu.Unlock()
	return err
}

func (m *usageMeter) writeState() (issued int64, err error) {
	if err := m.dirDurableLocked(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	st := usageState{Acked: m.acked, Head: m.head, Issued: m.nextSeq - 1}
	m.mu.Unlock()
	raw, err := json.Marshal(st)
	if err != nil {
		return 0, err
	}
	tmp := filepath.Join(m.dir, usageAckedFile+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return 0, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, filepath.Join(m.dir, usageAckedFile)); err != nil {
		return 0, err
	}
	// The new name must be durable before a prune or a page trusts it.
	if err := usageSyncDir(m.dir); err != nil {
		return 0, fmt.Errorf("sync of the usage directory after %s: %w", usageAckedFile, err)
	}
	return st.Issued, nil
}

// usageMeterHotel hands one sync pass of h to the meter: a run is present while
// h's room map holds it or this list showed it (a recorded leftover is never
// in the room map). Runs end only on a pass whose list answered, and not
// before a room list has answered since start: until then the room map is
// empty because nobody looked, not because the rooms are gone. Caller holds
// b.mu.
func (b *broker) usageMeterHotel(h *hotel, listed []usageSighting, at time.Time, listOK bool) (turned bool) {
	if b.usageMeter == nil {
		return false
	}
	present := make(map[string]bool, len(h.rooms)+len(listed))
	for _, rm := range h.rooms {
		present[rm.id] = true
	}
	for _, s := range listed {
		present[s.run] = true
	}
	// The broker places no new room on a hotel that is down, leaving or
	// draining (admissibleFreeIn, capacity.go). A failed list alone does not
	// stop placement: h.ok comes from health and room calls.
	unplaceable := !h.ok || h.leaving || h.drain()
	return b.usageMeter.hotelPass(h.cfg.ID, listed, present, at, listOK, listOK && !h.roomsUnchecked, unplaceable)
}

// usageListSighting is a listed room that is not in h's room map: a
// recorded leftover of a failed create. It used compute; the guest does not
// pay for it.
func usageListSighting(h *hotel, id string, labels map[string]string, resources any) usageSighting {
	vcpu, mem := usageSizeOf(resources)
	return usageSighting{run: h.cfg.ID + "." + id, guest: labels[guestLabel], hotel: h.cfg.ID, miner: h.cfg.MinerHotkey, vcpu: vcpu, memGiB: mem}
}

// bulkDeleteTargets lists the rooms of h that a bulk delete with q will
// remove (a bulk delete answers no ids) and applies that list as a sighting
// of their runs at once: a sync may drop the rooms from the room map, and end
// their runs, before the delete answers. It returns the run ids, which
// meterBulkDeleted ends when the delete succeeds; whichever of the two comes
// first writes the one ended reading. Nil when the meter is off or the list
// fails: those runs then end at their last sync list.
func (b *broker) bulkDeleteTargets(ctx context.Context, h *hotel, q url.Values) []string {
	if b.usageMeter == nil {
		return nil
	}
	var list struct {
		Sandboxes []struct {
			ID     string            `json:"id"`
			Labels map[string]string `json:"labels"`
		} `json:"sandboxes"`
	}
	if err := h.getJSON(ctx, h.cfg.API, "/v1/sandboxes", q, &list); err != nil {
		return nil
	}
	at := time.Now()
	var runs []string
	for _, s := range list.Sandboxes {
		match := true
		for _, want := range q["label"] { // a hotel that ignores the filter must not end other runs
			k, v, _ := strings.Cut(want, "=")
			match = match && s.Labels[k] == v
		}
		if match {
			runs = append(runs, h.cfg.ID+"."+s.ID)
		}
	}
	b.usageMeter.sightRuns(runs, at)
	return runs
}

// usageMeterBulkDeleted ends the runs a successful bulk delete removed. Their last
// sighting is the list just before the delete, never the time the delete
// took: it may take minutes.
func (b *broker) usageMeterBulkDeleted(runs []string) {
	for _, run := range runs {
		b.usageMeter.end(run, time.Now(), false)
	}
}

// sightRuns applies a sighting at at to open runs known by id.
func (m *usageMeter) sightRuns(runs []string, at time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range runs {
		if r := m.runs[id]; r != nil {
			r.observe(at)
			r.missed = false
		}
	}
}

// usageMeterOrphan records a room of a failed create that the orphan cleanup
// listed at at: it used compute and the guest does not pay for it, so its
// run is not billable from this reading on, also when a sync adopted it as
// the guest's room before the create failed. removed: the cleanup deleted
// it, so the run ends. Caller holds b.mu.
func (b *broker) usageMeterOrphan(h *hotel, id, guest string, at time.Time, removed bool) (turned bool) {
	run := h.cfg.ID + "." + id
	turned = b.usageMeter.seen(usageSighting{run: run, guest: guest, hotel: h.cfg.ID, miner: h.cfg.MinerHotkey}, at)
	if removed {
		b.usageMeter.end(run, at, false)
	}
	return turned
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
	if b.usageMeter == nil {
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
	p, err := b.usageMeter.page(after, limit, time.Now())
	if err != nil {
		log.Printf("usage meter: read: %v", err)
		writeErr(w, 500, "usage_meter_read_failed", "the usage log could not be read")
		return
	}
	writeJSON(w, 200, p)
}
