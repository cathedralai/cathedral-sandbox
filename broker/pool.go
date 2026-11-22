// Ready rooms, lifecycle (AB#894, phase 2 PR 2; design 2.6, 6.4, 6.5, 8.2,
// 9.6): the pool manager makes rooms ahead of time on operator sealed hotels,
// proves them, retires them and never deletes one it cannot prove unclaimed.
// Settings and the pool guest: pool_settings.go. Proof: pool_receipts.go.
//
// Nothing hands a pool room to a customer in this pull request: there is no
// claim path and no mapping yet. With every target 0 (the default) the
// manager makes nothing, and a broker without ready_rooms runs none of this.
//
// Where pool rooms are made. A hotel takes pool creates only when it is an
// operator hotel (no miner hotkey), shared (not reserved for a guest),
// admitted with a verified SEV-SNP attestation whose AMD chain passed and
// whose binding names a receipt key (every hotel is sealed, AB#776), and it
// would place a room now (admissibleFree, diskFits); and a key's rooms go
// only where that key's image is warm (the catalog pre-pull, prewarm.go).
// A create slot is taken without waiting, so a customer create never waits
// for a pool create.
//
// Refill (design 6.3, PR 3): per hotel at most refill_per_second (4, the
// most allowed) pool creates a second over all keys, started evenly
// (poolCreateSpacing apart) and up to poolCreatesInFlight at once; while a
// claim is in flight on the hotel, and for 1 s after the last one ended,
// refill_during_claims (1); but the full rate again whenever a key there is
// below a quarter of its target. No pause timer: refill never drops below
// refill_during_claims, so no burst pattern stops it. Claims call
// poolClaimBegin and poolClaimEnd (PR 6 adds the claims; nothing calls them
// before it).
//
// Hotel bounds (design 6.1, PR 3): every pool room a hotel holds, in any
// state (ready and quarantined, and unverified, stale and creating too), is
// at most 20% of its slots and 5% of its memory, counted at an idle room's
// footprint (poolIdleRoomMiB, design 6.1 and 11.4), whichever is smaller. No
// pool create while the hotel's free slots are under 10% or its room disk is
// 80% full or more. Under 5% free slots the pool gives slots back to
// customers: ready rooms are deleted, oldest first, until 5% is free again;
// quarantined rooms never.
//
// Body of a pool create, exactly: image, resources, network (deny_all, empty
// allow), labels (cathedral_pool "1" and the broker guest label of
// cathedral-pool) and ttl_seconds 14,400; no Idempotency-Key header. The
// front signs such a create "pool": true (room_receipts.py pool_create_check).
//
// States of a pool room (per hotel, in memory):
//
//	ready        receipt 1 verified under the current binding (design 6.5)
//	stale        proven never claimed and leaving: its binding changed, it is
//	             retired (20 min left), over target, or its create had no
//	             verified pool receipt. Never ready again; deleted.
//	unverified   a pool-labelled room this process did not make or prove (a
//	             broker restart, a lost create answer): its receipts are read
//	             through the front, at most 20 a second per hotel and at most
//	             10 s per read; a read with no answer is retried later.
//	quarantined  the read did not show exactly one receipt, a verified pool
//	             receipt 1: kept, never handed out, never deleted, alarmed,
//	             and counted in the hotel's pool bound. It ends at its hotel
//	             lifetime.
//
// What may be deleted (design 6.5, 9.6): only a room the manager proved
// never claimed, one it made in this process or one whose receipts read
// showed exactly one receipt, the pool create. Retirement, stale cleanup,
// over-target trimming and the rollback to targets 0 follow that rule.
//
// Quarantine at or over the hotel's bound stops refill on that hotel and
// raises an alarm; it never causes a deletion.
//
// Start order (design 9.2): the manager acts on a hotel only after that
// hotel's room list has answered once since start, and makes and deletes
// rooms only while the claim journal is open and complete. On an incomplete
// journal, or when it could not be opened, it creates and deletes nothing;
// it still reads receipts and quarantines, which changes no room.
//
// Readings: a pool room is metered under the pool guest and never billable,
// from its first reading (usageSightingOf).
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	poolLabel        = "cathedral_pool"
	poolTTLSeconds   = 14400
	poolRetireLeft   = 20 * time.Minute
	poolTick         = 50 * time.Millisecond
	poolReadTimeout  = 10 * time.Second // design 2.6 step 7
	poolReadsPerStep = 20
	poolRetryFirst   = 5 * time.Second
	poolRetryMax     = time.Minute
	// poolProofAlarmAfter is the receipt-1 proof failures in a row on one
	// hotel that raise the ready_rooms alert: its front does not prove pool
	// rooms (an older room-kit, or a tag vs digest image), so refill there is
	// churn until someone looks.
	poolProofAlarmAfter = 3
)

// Refill and bounds (design 6.1, 6.3).
const (
	poolRefillCap       = 4    // pool creates a second per hotel, over all keys, at most
	poolCreatesInFlight = 4    // pool creates in flight per hotel, at most
	poolBelowQuarter    = 0.25 // a key under this share of its target refills at the full rate, claims or not
	poolSlotShare       = 0.20 // every pool room of a hotel: at most this share of its slots
	poolMemShare        = 0.05 // and this share of its memory, at an idle room's footprint
	poolIdleRoomMiB     = 35   // an idle pool room [M 11 Nov: 3,100 idle rooms in about 108 GiB; design 6.1]
	poolMinFreeShare    = 0.10 // no pool create while free slots are under this share
	poolYieldFreeShare  = 0.05 // under this share of free slots, ready rooms go, oldest first
	poolDiskFullPct     = 80.0 // no pool create at this room disk use or more (diskFullPct)
	poolClaimTail       = time.Second
)

// Vars for tests.
var (
	poolSpacingFactor = 1.05                  // creates start (1 / rate) x this apart: under the rate at the hotel even with jitter
	poolReadEvery     = 60 * time.Millisecond // receipts reads: under 20 a second per hotel, with room for timer jitter
	poolCreateTimeout = 2 * time.Minute       // a warm image: no pull
	poolDeleteTimeout = 30 * time.Second
)

type poolRoomState string

const (
	poolReady       poolRoomState = "ready"
	poolStale       poolRoomState = "stale"
	poolUnverified  poolRoomState = "unverified"
	poolQuarantined poolRoomState = "quarantined"
)

// poolRoom is one pool room of a hotel. Guarded by b.mu.
type poolRoom struct {
	hid   string
	key   string // the pool key; "" until a receipt names its image
	state poolRoomState
	why   string
	// proven: made in this process, or its receipts read showed exactly one
	// receipt, the pool create. Only a proven room is ever deleted.
	proven    bool
	att       poolAttest // the attestation it was proven under
	receipt1  string     // receipt_sha256 of its receipt 1 (the claim's pooled_from)
	since     time.Time  // made or proven
	expiresAt time.Time
	retryAt   time.Time // unverified: next read; stale: next delete
	tries     int
}

// poolHotel is the manager's state for one hotel. Guarded by b.mu.
type poolHotel struct {
	rooms      map[string]*poolRoom // by hotel room id
	listed     bool                 // a room list answered since start
	busy       bool                 // a step runs
	creating   map[string]int       // creates in flight, by key
	started    map[*room]time.Time  // creates in flight: when each started
	memMiB     float64              // the largest memory its health answers gave since start
	lastCreate time.Time            // the last pool create's start
	backoff    time.Time            // a create failed: none before this
	proofFails int                  // creates in a row whose receipt 1 did not prove a ready room
	claims     int                  // claims in flight (poolClaimBegin)
	claimEnd   time.Time            // when the last claim ended
	inflight   sync.WaitGroup       // creates started by steps, for tests
	nextRead   time.Time            // receipts reads start at least poolReadEvery apart
	// level1 is the binding a level-1 front served (ready_rooms_unsealed_for_tests).
	level1   *poolAttest
	level1At time.Time
	reattest bool // a receipt named another binding: attest again now
	alarm    string
	alarmQ   int
	alarmAt  time.Time
	full     bool
}

type readyRooms struct {
	keys     []poolKey
	guest    *guestState
	saveMu   sync.Mutex // one settings write at a time
	stateDir string
	// Guarded by b.mu once the broker serves (the retry writes them).
	// journalState is "complete", "incomplete" or "unavailable".
	journal                  *claimJournal
	journalState, journalWhy string
	journalTries             int       // opens tried
	journalNextTry           time.Time // unavailable: when the open is tried again
	journalLoggedAt          time.Time // last log line of a failed retry
	settings                 readyRoomsSettings
	hotels                   map[string]*poolHotel
	// The open retry's lifetime (retryJournal). Guarded by retryMu.
	retryMu   sync.Mutex
	retryStop chan struct{} // closed by close(): the retry ends
	retryDone chan struct{} // closed when the retry has ended
	closed    bool
}

// poolOpenJournal opens the claim journal; a variable so a test can make an
// open fail. poolJournalRetry: how often an open that failed is tried again.
var (
	poolOpenJournal  = openClaimJournal
	poolJournalRetry = 5 * time.Second
)

// openJournal opens the claim journal at load. The manager creates and
// deletes rooms only while it is open and complete. An incomplete journal
// stays so: a person looks. Any other failed open (a head file that cannot
// be read, a lock another broker on the same state_dir still holds) leaves
// the pool "unavailable" and is tried again every poolJournalRetry by
// retryJournal, which runPool starts.
func (p *readyRooms) openJournal(stateDir string) {
	p.stateDir = stateDir
	j, _, err := poolOpenJournal(stateDir)
	p.journal = j
	p.journalTries = 1
	switch {
	case err == nil:
		p.journalState = "complete"
	case errors.Is(err, errClaimJournalIncomplete):
		p.journalState, p.journalWhy = "incomplete", err.Error()
		log.Printf("ready rooms: %v; the pool manager creates and deletes nothing until a person looks", err)
	default:
		p.journalState, p.journalWhy = "unavailable", err.Error()
		p.journalNextTry, p.journalLoggedAt = time.Now().Add(poolJournalRetry), time.Now()
		log.Printf("ready rooms: claim journal not opened: %v; the pool manager creates and deletes nothing; tried again every %s", err, poolJournalRetry)
	}
}

// startJournalRetry starts retryJournal once, when the journal is
// unavailable and the pool is not closed.
func (b *broker) startJournalRetry(ctx context.Context) {
	p := b.pool
	b.mu.Lock()
	unavailable := p.journalState == "unavailable"
	b.mu.Unlock()
	p.retryMu.Lock()
	defer p.retryMu.Unlock()
	if !unavailable || p.closed || p.retryDone != nil {
		return
	}
	p.retryStop, p.retryDone = make(chan struct{}), make(chan struct{})
	go b.retryJournal(ctx, p.retryStop, p.retryDone)
}

// retryJournal tries the journal open again every poolJournalRetry until it
// opens, turns out incomplete, or the broker stops. A journal it opened
// after the stop is closed again, so nothing stays open. Once the journal is
// complete the manager starts as after a load: each hotel's pool rooms are
// unverified until their receipts are read, and no pool create comes before
// those reads (poolPlan).
func (b *broker) retryJournal(ctx context.Context, stop, done chan struct{}) {
	p := b.pool
	defer close(done)
	t := time.NewTimer(poolJournalRetry)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-t.C:
		}
		j, _, err := poolOpenJournal(p.stateDir)
		select {
		case <-ctx.Done():
		case <-stop:
		default:
			if b.noteJournalOpen(j, err) {
				return
			}
			t.Reset(poolJournalRetry)
			continue
		}
		if j != nil {
			_ = j.close() // stopped while it opened: leave no journal open
		}
		return
	}
}

// noteJournalOpen records a retried open and reports whether the retry
// ends.
func (b *broker) noteJournalOpen(j *claimJournal, err error) bool {
	p := b.pool
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	p.journalTries++
	switch {
	case err == nil:
		p.journal, p.journalState, p.journalWhy, p.journalNextTry = j, "complete", "", time.Time{}
		log.Printf("ready rooms: claim journal opened on try %d; the pool starts on each hotel after its receipts reads", p.journalTries)
		return true
	case errors.Is(err, errClaimJournalIncomplete):
		p.journal, p.journalState, p.journalWhy, p.journalNextTry = j, "incomplete", err.Error(), time.Time{}
		log.Printf("ready rooms: %v; the pool manager creates and deletes nothing until a person looks", err)
		return true
	}
	changed := err.Error() != p.journalWhy
	p.journalWhy, p.journalNextTry = err.Error(), now.Add(poolJournalRetry)
	if changed || now.Sub(p.journalLoggedAt) >= time.Minute {
		p.journalLoggedAt = now
		log.Printf("ready rooms: claim journal still not opened after %d tries: %v; tried again every %s", p.journalTries, err, poolJournalRetry)
	}
	return false
}

// close stops the open retry, waits for it, then stops the journal's writer.
// Safe on nil and more than once.
func (p *readyRooms) close() {
	if p == nil {
		return
	}
	p.retryMu.Lock()
	first := !p.closed
	p.closed = true
	stop, done := p.retryStop, p.retryDone
	p.retryMu.Unlock()
	if done != nil {
		if first {
			close(stop)
		}
		<-done
	}
	if p.journal != nil {
		_ = p.journal.close()
	}
}

func (p *readyRooms) journalOK() bool { return p.journalState == "complete" }

// hotel is the state of hotel id, made on first use. Caller holds b.mu.
func (p *readyRooms) hotel(id string) *poolHotel {
	ph := p.hotels[id]
	if ph == nil {
		ph = &poolHotel{rooms: map[string]*poolRoom{}, creating: map[string]int{}, started: map[*room]time.Time{}}
		p.hotels[id] = ph
	}
	return ph
}

// poolBounds is a hotel's pool bound (design 6.1): the smaller of 20% of its
// slots and 5% of its memory at an idle room's footprint. byMemory is -1
// when the hotel reports no memory: the slot bound alone applies.
type poolBounds struct{ bound, bySlots, byMemory int }

// poolBoundsLocked is h's bound now. Caller holds b.mu.
func (b *broker) poolBoundsLocked(h *hotel) poolBounds {
	bs := poolBounds{bySlots: int(math.Floor(poolSlotShare * float64(max(h.slots, 0)))), byMemory: -1}
	bs.bound = bs.bySlots
	if mib := poolHotelMemMiB(h, b.pool.hotel(h.cfg.ID)); mib > 0 {
		bs.byMemory = int(math.Floor(poolMemShare * mib / poolIdleRoomMiB))
		bs.bound = min(bs.bound, bs.byMemory)
	}
	return bs
}

// poolHotelMemMiB is h's memory: its config ram_gib, else the largest its
// health answers gave since start (used GiB over used percent), else 0
// (unknown). The hotel rounds both numbers to 0.1 (room_health.py), so one
// answer to the next moves the ratio by a few percent; the largest seen holds
// the bound still, where a trim to a lower one is never undone. Caller holds
// b.mu.
func poolHotelMemMiB(h *hotel, ph *poolHotel) float64 {
	if h.cfg.RAMGiB > 0 {
		return float64(h.cfg.RAMGiB) * 1024
	}
	if h.memPct > 0 && h.memGiB > 0 {
		ph.memMiB = max(ph.memMiB, h.memGiB*100/h.memPct*1024)
	}
	return ph.memMiB
}

// oldestCreate is when ph's oldest pool create in flight started; zero when
// none is in flight. Caller holds b.mu.
func (ph *poolHotel) oldestCreate() time.Time {
	var t time.Time
	for _, at := range ph.started {
		if t.IsZero() || at.Before(t) {
			t = at
		}
	}
	return t
}

// poolMaybeInFlight reports whether rm, a listed pool room the manager does
// not hold, may be the room of a pool create still in flight on its hotel.
// The hotel lists a room from the start of its create, before the create
// answers (sandbox_guest.py records the room, then starts its guest), and
// the sync loop takes in every listed room it does not know (syncHotel), so
// such a room is in the room map before its create's answer names it. It
// counts already, through ph.creating: taken in as unverified too, it would
// count twice (at the bound the trim deletes a ready room for it) and have
// its receipts read before its receipt 1 exists (quarantined). A room the
// sync first saw before the oldest create in flight started is no such
// room: rm.born is the time of that sync, taken after its list answered.
func poolMaybeInFlight(rm *room, oldest time.Time) bool {
	return !oldest.IsZero() && !rm.born.Before(oldest)
}

// poolFreeSlots is h's free slots, pool rooms counted as used. Caller holds
// b.mu.
func poolFreeSlots(h *hotel) int { return h.slots - h.used() }

// poolLeavingLocked is the pool rooms of h that hold a slot but are on their
// way out: stale (to be deleted) or deleted and not yet gone from the room
// map. The give-back counts them as free already, so it never deletes more
// ready rooms than it needs. Caller holds b.mu.
func poolLeavingLocked(h *hotel, ph *poolHotel) int {
	n := 0
	for _, pr := range ph.rooms {
		if pr.state == poolStale && pr.proven {
			n++
		}
	}
	for hid, rm := range h.rooms {
		if rm.guest == poolGuestID && rm.state == stDeleting && rm.deleteSent && ph.rooms[hid] == nil {
			n++
		}
	}
	return n
}

// poolRateLocked is h's pool create rate now, a second (design 6.3).
// Caller holds b.mu.
func (b *broker) poolRateLocked(h *hotel, ph *poolHotel, now time.Time) float64 {
	p := b.pool
	fast := min(p.settings.RefillPerSecond, poolRefillCap)
	if ph.claims == 0 && (ph.claimEnd.IsZero() || now.Sub(ph.claimEnd) >= poolClaimTail) {
		return fast
	}
	for i := range p.keys {
		k := &p.keys[i]
		// A key below a quarter of its target refills at the full rate, claims
		// or not; a key whose image is cold here gets no create here, so it
		// does not count.
		if t := p.settings.target(k.name); t > 0 && h.warm[k.image] && float64(p.readyOfLocked(ph, k.name)) < poolBelowQuarter*float64(t) {
			return fast
		}
	}
	return min(p.settings.RefillDuringClaims, fast)
}

// readyOfLocked is ph's ready rooms of key name. Caller holds b.mu.
func (p *readyRooms) readyOfLocked(ph *poolHotel, name string) int {
	n := 0
	for _, pr := range ph.rooms {
		if pr.state == poolReady && pr.key == name {
			n++
		}
	}
	return n
}

// poolCreateSpacing is how far apart pool creates start at rate.
func poolCreateSpacing(rate float64) time.Duration {
	if rate <= 0 {
		return 0
	}
	return time.Duration(float64(time.Second) / rate * poolSpacingFactor)
}

// poolClaimBegin and poolClaimEnd bracket a claim on h (PR 6 calls them
// around each claim attempt). While one is in flight, and for 1 s after the
// last ends, refill on h runs at refill_during_claims.
func (b *broker) poolClaimBegin(h *hotel) {
	if b.pool == nil {
		return
	}
	b.mu.Lock()
	b.pool.hotel(h.cfg.ID).claims++
	b.mu.Unlock()
}

func (b *broker) poolClaimEnd(h *hotel) {
	if b.pool == nil {
		return
	}
	b.mu.Lock()
	ph := b.pool.hotel(h.cfg.ID)
	ph.claims = max(ph.claims-1, 0)
	ph.claimEnd = time.Now()
	b.mu.Unlock()
}

type poolCounts struct{ ready, stale, unverified, quarantined, creating, held int }

func (p *readyRooms) countsLocked(id string) poolCounts {
	ph := p.hotel(id)
	var c poolCounts
	for _, pr := range ph.rooms {
		switch pr.state {
		case poolReady:
			c.ready++
		case poolStale:
			c.stale++
		case poolUnverified:
			c.unverified++
		case poolQuarantined:
			c.quarantined++
		}
	}
	for _, n := range ph.creating {
		c.creating += n
	}
	c.held = len(ph.rooms) + c.creating
	return c
}

// runPool steps every hotel's pool every poolTick, one step per hotel at a
// time, until ctx ends. Safe on a broker without ready_rooms.
func (b *broker) runPool(ctx context.Context) {
	p := b.pool
	if p == nil {
		return
	}
	b.startJournalRetry(ctx)
	t := time.NewTicker(poolTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		hotels := b.hotelList()
		known := make(map[string]bool, len(hotels))
		b.mu.Lock()
		var due []*hotel
		for _, h := range hotels {
			known[h.cfg.ID] = true
			if ph := p.hotel(h.cfg.ID); !ph.busy {
				ph.busy = true
				due = append(due, h)
			}
		}
		for id, ph := range p.hotels {
			if !known[id] && !ph.busy {
				delete(p.hotels, id) // the hotel left
			}
		}
		b.mu.Unlock()
		for _, h := range due {
			go func(h *hotel) {
				defer func() {
					b.mu.Lock()
					p.hotel(h.cfg.ID).busy = false
					b.mu.Unlock()
				}()
				b.poolStep(ctx, h)
			}(h)
		}
	}
}

// poolAttestLocked is what h's pool rooms are proven under now, or false
// when the hotel has no verified attestation the pool may use. Caller holds
// b.mu.
func (b *broker) poolAttestLocked(h *hotel, ph *poolHotel, now time.Time) (poolAttest, bool) {
	if b.cfg.ReadyRoomsUnsealedForTests && admissionOff(h) && loopbackURL(h.cfg.API) && loopbackURL(h.cfg.Health) {
		if ph.level1 == nil || !h.ok {
			return poolAttest{}, false
		}
		return *ph.level1, true
	}
	if !strictAttestation(h) || !b.admitted(h, now) || h.adm.attestedAt.IsZero() {
		return poolAttest{}, false
	}
	if len(h.adm.receiptKey) != ed25519.PublicKeySize || h.adm.bindingSHA == "" || h.adm.amd == nil || h.adm.amdBinding != h.adm.bindingSHA {
		return poolAttest{}, false
	}
	return poolAttest{binding: h.adm.bindingSHA, key: append(ed25519.PublicKey(nil), h.adm.receiptKey...), schema: sealedReceiptSchema}, true
}

// poolCreateRefusalLocked is why h takes no pool create now, or "" when it
// does. Caller holds b.mu.
func (b *broker) poolCreateRefusalLocked(h *hotel, ph *poolHotel, now time.Time) string {
	p := b.pool
	switch {
	case !p.journalOK():
		return "claim journal " + p.journalState
	case !ph.listed:
		return "no room list since start"
	case h.cfg.MinerHotkey != "":
		return "miner hotel"
	case h.reservedFor() != "":
		return "reserved for a guest"
	}
	if _, ok := b.poolAttestLocked(h, ph, now); !ok {
		return "no verified attestation with a receipt key"
	}
	if b.admissibleFree(h, now) <= 0 {
		return "takes no room now"
	}
	if free := poolFreeSlots(h); float64(free) < poolMinFreeShare*float64(h.slots) {
		return fmt.Sprintf("%d free slots of %d: under 10%%, kept for customers", free, h.slots)
	}
	if h.roomDataPct != nil && *h.roomDataPct >= poolDiskFullPct {
		return fmt.Sprintf("room disk %.1f%% used: 80%% or more", *h.roomDataPct)
	}
	return ""
}

// poolColdKeysLocked is the keys with a target whose image is not warm on h:
// they get no pool create there; the other keys do. Caller holds b.mu.
func (b *broker) poolColdKeysLocked(h *hotel) []string {
	var cold []string
	for _, k := range b.pool.keys {
		if b.pool.settings.target(k.name) > 0 && !h.warm[k.image] {
			cold = append(cold, k.name)
		}
	}
	return cold
}

// poolWork is what one step does outside b.mu.
type poolWork struct {
	att      poolAttest
	attOK    bool
	reads    []string
	deletes  []string
	create   *poolKey
	createAt time.Time // when the create may start (its slot in the spacing)
}

// poolStep is one step of h's pool: receipts reads, deletes, then at most
// one create, started on its own (creates run alongside the next steps).
func (b *broker) poolStep(ctx context.Context, h *hotel) {
	b.poolLevel1(ctx, h)
	w := b.poolPlan(h)
	if w == nil {
		return
	}
	for _, hid := range w.reads {
		b.poolReadSlot(h)
		b.poolRead(ctx, h, hid, w.att)
	}
	for _, hid := range w.deletes {
		b.poolDelete(ctx, h, hid)
	}
	if w.create != nil {
		time.Sleep(time.Until(w.createAt)) // under one tick: the create starts on its slot
		b.mu.Lock()
		ph := b.pool.hotel(h.cfg.ID)
		// The spacing counts from when a create really starts: the step's
		// reads and deletes ran since the plan, and the rate may have moved.
		now := time.Now()
		if rate := b.poolRateLocked(h, ph, now); rate <= 0 || now.Before(ph.lastCreate.Add(poolCreateSpacing(rate))) {
			b.mu.Unlock()
			return
		}
		ph.lastCreate = now
		ph.inflight.Add(1)
		b.mu.Unlock()
		k, att := *w.create, w.att
		// A create still in flight when its hotel leaves the config ends into
		// a poolHotel nobody reads any more: harmless.
		go func() {
			defer ph.inflight.Done()
			b.poolCreate(ctx, h, k, att)
		}()
	}
}

// poolReadSlot waits for h's next receipts read slot: reads start at least
// poolReadEvery apart, across steps, so a hotel never gets more than 20 in
// a second.
func (b *broker) poolReadSlot(h *hotel) {
	b.mu.Lock()
	ph := b.pool.hotel(h.cfg.ID)
	at := time.Now()
	if ph.nextRead.After(at) {
		at = ph.nextRead
	}
	ph.nextRead = at.Add(poolReadEvery)
	b.mu.Unlock()
	time.Sleep(time.Until(at))
}

// poolPlan takes stock of h under b.mu and decides the step's work.
func (b *broker) poolPlan(h *hotel) *poolWork {
	p := b.pool
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	ph := p.hotel(h.cfg.ID)
	if !ph.listed {
		if !h.listOK {
			return nil // the room map is empty because nobody looked
		}
		ph.listed = true
	}
	// Rooms the hotel no longer holds are gone; pool-labelled rooms the
	// manager does not hold are unverified, once they cannot be the room of
	// a create in flight (poolMaybeInFlight). A create whose answer was lost
	// leaves its room to this: taken in when no create that could be its own
	// is in flight, and decided by its receipts.
	for hid := range ph.rooms {
		if h.rooms[hid] == nil {
			delete(ph.rooms, hid)
		}
	}
	oldest := ph.oldestCreate()
	for hid, rm := range h.rooms {
		if rm.guest == poolGuestID && rm.state == stRunning && ph.rooms[hid] == nil && !poolMaybeInFlight(rm, oldest) {
			ph.rooms[hid] = &poolRoom{hid: hid, state: poolUnverified, why: "not made or proven by this process"}
		}
	}
	w := &poolWork{}
	w.att, w.attOK = b.poolAttestLocked(h, ph, now)
	if w.attOK {
		for _, pr := range ph.rooms {
			if pr.state == poolReady && !pr.att.same(w.att) {
				pr.state, pr.why = poolStale, "the hotel's binding or receipt key changed"
			}
		}
	}
	b.poolAlarmLocked(h, ph, now)
	if w.attOK {
		for _, pr := range sortedPoolRooms(ph) {
			if pr.state == poolUnverified && !now.Before(pr.retryAt) && len(w.reads) < poolReadsPerStep {
				w.reads = append(w.reads, pr.hid)
			}
		}
	}
	if !p.journalOK() {
		return w // reads only: no create, no delete
	}
	ready := map[string][]*poolRoom{}
	for _, pr := range sortedPoolRooms(ph) {
		if pr.state != poolReady {
			continue
		}
		if !pr.expiresAt.IsZero() && pr.expiresAt.Sub(now) <= poolRetireLeft {
			pr.state, pr.why = poolStale, "retired: 20 minutes left"
			continue
		}
		ready[pr.key] = append(ready[pr.key], pr)
	}
	for name, list := range ready {
		// Oldest first: they retire first anyway.
		for i := 0; i < len(list)-p.settings.target(name); i++ {
			list[i].state, list[i].why = poolStale, "over target"
		}
	}
	// Above the hotel's bound (fewer slots or less memory reported, or a pool
	// made under an older bound): the oldest ready rooms go until it holds no
	// more than the bound, its stale rooms (being deleted) counted as gone.
	// Rooms deleted already are not in its count. Quarantined rooms never.
	if bs := b.poolBoundsLocked(h); h.slots > 0 {
		c := p.countsLocked(h.cfg.ID)
		excess := c.held - c.stale - bs.bound
		for _, pr := range sortedPoolRooms(ph) {
			if excess <= 0 {
				break
			}
			if pr.state == poolReady {
				pr.state, pr.why = poolStale, fmt.Sprintf("over the hotel's pool bound of %d", bs.bound)
				excess--
			}
		}
	}
	// Under 5% free slots the pool gives slots back to customers: ready
	// rooms, oldest first, until 5% is free again. Quarantined rooms never go.
	if want := int(math.Ceil(poolYieldFreeShare * float64(h.slots))); h.slots > 0 && poolFreeSlots(h)+poolLeavingLocked(h, ph) < want {
		give := want - poolFreeSlots(h) - poolLeavingLocked(h, ph)
		for _, pr := range sortedPoolRooms(ph) {
			if give == 0 {
				break
			}
			if pr.state == poolReady {
				pr.state, pr.why = poolStale, "slots given back to customers: under 5% free"
				give--
			}
		}
	}
	if h.ok {
		for _, pr := range sortedPoolRooms(ph) {
			if pr.state == poolStale && pr.proven && !now.Before(pr.retryAt) {
				w.deletes = append(w.deletes, pr.hid)
			}
		}
	}
	if b.poolCreateRefusalLocked(h, ph, now) != "" || now.Before(ph.backoff) || ph.full {
		return w
	}
	inflight := 0
	for _, n := range ph.creating {
		inflight += n
	}
	rate := b.poolRateLocked(h, ph, now)
	if rate <= 0 || inflight >= poolCreatesInFlight {
		return w
	}
	at := ph.lastCreate.Add(poolCreateSpacing(rate))
	if at.Sub(now) >= poolTick {
		return w // the next tick's step decides
	}
	for _, pr := range ph.rooms {
		if pr.state == poolUnverified && pr.tries == 0 {
			return w // the receipts reads come first, after a restart or a late journal open
		}
	}
	for _, k := range b.poolKeysByNeedLocked(ph) {
		if b.poolNeedsLocked(h, ph, k) && h.warm[k.image] && b.diskFits(h, k.diskGiB) {
			if at.Before(now) {
				at = now
			}
			w.create, w.createAt = k, at
			break
		}
	}
	return w
}

// poolNeedsLocked reports whether h's pool needs one more room of key k
// now: every pool room the hotel holds and its creates in flight are under
// the hotel's bound (design 6.1), and the key's ready rooms and creates in
// flight are under its target. Caller holds b.mu.
func (b *broker) poolNeedsLocked(h *hotel, ph *poolHotel, k *poolKey) bool {
	p := b.pool
	if p.countsLocked(h.cfg.ID).held >= b.poolBoundsLocked(h).bound {
		return false
	}
	return ph.creating[k.name]+p.readyOfLocked(ph, k.name) < p.settings.target(k.name)
}

// anyTargetLocked reports whether some key has a target above 0. Caller
// holds b.mu.
func (p *readyRooms) anyTargetLocked() bool {
	for _, k := range p.keys {
		if p.settings.target(k.name) > 0 {
			return true
		}
	}
	return false
}

// poolKeysByNeedLocked is the keys, the one furthest below its target (as a
// share of it) first: a key below a quarter is the one the full rate during
// claims is for. Caller holds b.mu.
func (b *broker) poolKeysByNeedLocked(ph *poolHotel) []*poolKey {
	p := b.pool
	out := make([]*poolKey, 0, len(p.keys))
	share := map[string]float64{}
	for i := range p.keys {
		k := &p.keys[i]
		out = append(out, k)
		if t := p.settings.target(k.name); t > 0 {
			share[k.name] = float64(p.readyOfLocked(ph, k.name)+ph.creating[k.name]) / float64(t)
		} else {
			share[k.name] = math.Inf(1)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return share[out[i].name] < share[out[j].name] })
	return out
}

// sortedPoolRooms is ph's rooms, oldest first. Caller holds b.mu.
func sortedPoolRooms(ph *poolHotel) []*poolRoom {
	out := make([]*poolRoom, 0, len(ph.rooms))
	for _, pr := range ph.rooms {
		out = append(out, pr)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].since.Equal(out[j].since) {
			return out[i].since.Before(out[j].since)
		}
		return out[i].hid < out[j].hid
	})
	return out
}

// poolAlarmLocked raises the quarantine alarm: when a hotel's quarantine
// grows (at most once per alertCooldown), and when it fills the pool bound,
// which stops refill there. Caller holds b.mu.
func (b *broker) poolAlarmLocked(h *hotel, ph *poolHotel, now time.Time) {
	c := b.pool.countsLocked(h.cfg.ID)
	bound := b.poolBoundsLocked(h).bound
	full := b.pool.anyTargetLocked() && c.quarantined >= bound
	switch {
	case c.quarantined == 0:
		ph.alarm, ph.alarmQ, ph.full = poolProofAlarm(h, ph), 0, false
		return
	case full && !ph.full:
	case c.quarantined > ph.alarmQ && now.Sub(ph.alarmAt) >= alertCooldown:
	default:
		ph.full = full
		return
	}
	ph.full = full
	ph.alarmQ, ph.alarmAt = c.quarantined, now
	ph.alarm = fmt.Sprintf("%s: %d pool rooms quarantined (kept, never handed out, never deleted; they end at their hotel lifetime); pool bound %d", hotelAlertName(h), c.quarantined, bound)
	if full {
		ph.alarm += "; quarantine fills the bound: no pool refill on this hotel"
	}
	b.alerts.send("ready_rooms", b.alerts.opsChat, ph.alarm, nil, nil)
}

// poolProofAlarm is the alarm text for a hotel whose last
// poolProofAlarmAfter or more creates failed their receipt-1 proof, else "".
// Caller holds b.mu.
func poolProofAlarm(h *hotel, ph *poolHotel) string {
	if ph.proofFails < poolProofAlarmAfter {
		return ""
	}
	return fmt.Sprintf("%s: %d pool creates in a row failed their receipt 1 proof (each deleted); pool creates back off to one a minute", hotelAlertName(h), ph.proofFails)
}

// poolLevel1 reads the level-1 binding of a rig front
// (ready_rooms_unsealed_for_tests) when it is due: first, every
// attest_every_seconds, after the hotel was down, and at once when a receipt
// named another binding.
func (b *broker) poolLevel1(ctx context.Context, h *hotel) {
	if !b.cfg.ReadyRoomsUnsealedForTests {
		return
	}
	now := time.Now()
	b.mu.Lock()
	ph := b.pool.hotel(h.cfg.ID)
	if !h.ok {
		ph.level1 = nil // a hotel that comes back may have a new front
	}
	due := admissionOff(h) && loopbackURL(h.cfg.API) && loopbackURL(h.cfg.Health) && h.ok &&
		(ph.level1 == nil || ph.reattest || now.Sub(ph.level1At) >= b.attestEvery())
	b.mu.Unlock()
	if !due {
		return
	}
	var doc struct {
		Binding    json.RawMessage `json:"binding"`
		BindingSHA string          `json:"binding_sha256"`
	}
	status, _, raw, err := h.doBase(ctx, h.cfg.Health, "GET", "/room/attestation", nil, nil, poolReadTimeout)
	var att *poolAttest
	if err == nil && status == 200 && json.Unmarshal(raw, &doc) == nil && len(doc.Binding) > 0 {
		var bd struct {
			Schema     string `json:"schema"`
			Level      string `json:"level"`
			ReceiptKey string `json:"receipt_key_ed25519_b64"`
		}
		sum := sha256.Sum256(doc.Binding)
		perr := json.Unmarshal(doc.Binding, &bd)
		key, kerr := base64.StdEncoding.DecodeString(bd.ReceiptKey)
		if perr == nil && hex.EncodeToString(sum[:]) == doc.BindingSHA && bd.Level == "hotel" && bd.Schema == hotelBindingSchema && kerr == nil && len(key) == ed25519.PublicKeySize {
			att = &poolAttest{binding: doc.BindingSHA, key: key, schema: hotelReceiptSchema}
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if att == nil {
		if ph.level1 != nil {
			log.Printf("ready rooms: hotel %s: level-1 binding not read (status %d, %v); its pool waits", h.cfg.ID, status, err)
		}
		ph.level1 = nil
		return
	}
	if ph.level1 == nil || !ph.level1.same(*att) {
		log.Printf("ready rooms: hotel %s: level-1 binding %s... (test rig)", h.cfg.ID, att.binding[:16])
	}
	ph.level1, ph.level1At, ph.reattest = att, now, false
}

// poolBindingMovedLocked handles a receipt that names another binding than
// the attested one: the front restarted or the attestation is old. Every
// ready room of the hotel turns stale (design 6.5) and the hotel is attested
// again at once. Caller holds b.mu.
func (b *broker) poolBindingMovedLocked(h *hotel, ph *poolHotel) {
	for _, pr := range ph.rooms {
		if pr.state == poolReady {
			pr.state, pr.why = poolStale, "a receipt of this hotel names another binding"
		}
	}
	ph.reattest = true
	if strictAttestation(h) {
		h.adm.checkedAt = time.Time{} // the sync loop attests again on its next pass
	}
}

// poolRead reads one unverified room's receipts through the front.
func (b *broker) poolRead(ctx context.Context, h *hotel, hid string, att poolAttest) {
	status, _, out, err := h.do(ctx, "GET", "/v1/sandboxes/"+url.PathEscape(hid)+"/receipts", nil, nil, poolReadTimeout)
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	ph := b.pool.hotel(h.cfg.ID)
	pr := ph.rooms[hid]
	if pr == nil || pr.state != poolUnverified {
		return
	}
	if err != nil || status != 200 {
		// No answer proves nothing: the room stays set aside and is read again.
		pr.tries++
		pr.retryAt = now.Add(poolRetry(pr.tries))
		pr.why = fmt.Sprintf("receipts not read (status %d)", status)
		if err != nil {
			pr.why = "receipts not read: " + err.Error()
		}
		return
	}
	sha, image, verr := verifyPoolReceiptsPage(out, att, hid)
	k := b.pool.keyByImage(image)
	switch {
	case errors.Is(verr, errPoolReceiptBinding):
		// The front's chain is another than the attested one: attest again,
		// and read again under the binding that comes back. Until then the
		// room stays set aside.
		b.poolBindingMovedLocked(h, ph)
		pr.tries++
		pr.retryAt = now.Add(poolRetry(pr.tries))
		pr.why = "receipts read: " + verr.Error()
		return
	case verr != nil:
		pr.state, pr.why = poolQuarantined, "receipts read: "+verr.Error()
	case k == nil:
		// Proven never claimed, but of no key: deleted, as an over-target room.
		pr.state, pr.why, pr.proven, pr.att, pr.since = poolStale, "receipts read: its image is not a ready_rooms key", true, att, now
		return
	default:
		pr.state, pr.why, pr.proven, pr.key, pr.att, pr.receipt1, pr.since = poolReady, "", true, k.name, att, sha, now
		pr.expiresAt = poolExpiry(h.rooms[hid], now)
		return
	}
	log.Printf("ready rooms: hotel %s room %s quarantined: %s", h.cfg.ID, hid, pr.why)
}

// poolExpiry is when a pool room's hotel lifetime ends: the listed
// expires_at, else 4 h from now (a proven room lives at most that long).
func poolExpiry(rm *room, now time.Time) time.Time {
	if rm != nil && !rm.expiresAt.IsZero() {
		return rm.expiresAt
	}
	return now.Add(poolTTLSeconds * time.Second)
}

// poolRetry is the wait before the next try of a failed read or delete.
func poolRetry(tries int) time.Duration {
	d := poolRetryFirst << min(tries-1, 4)
	return min(d, poolRetryMax)
}

// poolDelete deletes one stale room the manager proved never claimed.
func (b *broker) poolDelete(ctx context.Context, h *hotel, hid string) {
	b.mu.Lock()
	ph := b.pool.hotel(h.cfg.ID)
	pr := ph.rooms[hid]
	ok := pr != nil && pr.state == poolStale && pr.proven && b.pool.journalOK()
	b.mu.Unlock()
	if !ok {
		return
	}
	status, _, _, err := h.do(waitForConnUntilDeadline(ctx), "DELETE", "/v1/sandboxes/"+url.PathEscape(hid), nil, nil, poolDeleteTimeout)
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if ph.rooms[hid] != pr {
		return
	}
	if err == nil && (status == 204 || status == 200 || status == 404) {
		if rm := h.rooms[hid]; rm != nil {
			live := rm.state == stRunning
			if live {
				rm.state, rm.vanished = stDeleting, now
			}
			rm.deleteSent = true
			b.usageMeter.end(rm.id, now, status == 204 && live) // the run's ended reading, never billable
		}
		delete(ph.rooms, hid)
		return
	}
	pr.tries++
	pr.retryAt = time.Now().Add(poolRetry(pr.tries))
	log.Printf("ready rooms: hotel %s: delete of stale pool room %s: status %d err %v; tried again later", h.cfg.ID, hid, status, err)
}

// poolCreateBody is a pool create, exactly the five keys the front accepts.
func poolCreateBody(k poolKey) []byte {
	body, _ := json.Marshal(map[string]any{
		"image":       k.image,
		"resources":   k.resources,
		"network":     map[string]any{"mode": "deny_all", "allow": []string{}},
		"labels":      map[string]string{poolLabel: "1", guestLabel: poolGuestID},
		"ttl_seconds": poolTTLSeconds,
	})
	return body
}

// poolCreate makes one pool room of key k on h and proves it by its receipt
// 1, or deletes it (made in this process and never handed out).
func (b *broker) poolCreate(ctx context.Context, h *hotel, k poolKey, att poolAttest) {
	select {
	case h.sem <- struct{}{}:
	default:
		return // every create slot is busy: a customer create never waits for the pool
	}
	p := b.pool
	body := poolCreateBody(k)
	pl := placement{diskGiB: k.diskGiB}
	b.mu.Lock()
	ph := p.hotel(h.cfg.ID)
	// Read again at dispatch: the step's reads and deletes ran since the plan.
	if why := b.poolCreateRefusalLocked(h, ph, time.Now()); why != "" || !b.poolNeedsLocked(h, ph, &k) || !h.warm[k.image] || !b.diskFits(h, k.diskGiB) {
		b.mu.Unlock()
		<-h.sem
		return
	}
	rm := &room{h: h, guest: poolGuestID, state: stCreating, since: time.Now(), diskGiB: k.diskGiB}
	h.creating++
	h.holdDisk(pl, 1)
	h.place(rm)
	ph.creating[k.name]++
	ph.started[rm] = time.Now() // before the POST is sent: no listing of its room can come earlier
	b.mu.Unlock()

	status, hdr, out, err := h.doHeaders(noConnWait(context.WithoutCancel(ctx)), h.cfg.API, "POST", "/v1/sandboxes", nil, body, poolCreateTimeout, nil)
	<-h.sem
	tDone := time.Now()

	b.mu.Lock()
	h.creating--
	h.holdDisk(pl, -1)
	ph.creating[k.name]--
	delete(ph.started, rm)
	if errors.Is(err, errHotelBusy) {
		// Not sent: customer calls hold every data connection. No backoff:
		// the next create slot in the spacing tries again.
		h.release(rm)
		b.mu.Unlock()
		return
	}
	var doc map[string]any
	if err == nil {
		_ = json.Unmarshal(out, &doc)
	}
	hid, _ := doc["id"].(string)
	if err != nil || (status != 200 && status != 201 && status != 202) || hid == "" {
		ph.backoff = time.Now().Add(poolRetryFirst) // a failing hotel is not asked again for 5 s
		h.release(rm)
		b.mu.Unlock()
		// A lost answer may have started a room: its pool label brings it
		// back through the room list, unverified, and its receipts decide.
		log.Printf("ready rooms: hotel %s: pool create failed: status %d err %v", h.cfg.ID, status, err)
		return
	}
	rm.hid, rm.id, rm.state, rm.since, rm.born = hid, h.cfg.ID+"."+hid, stRunning, tDone, tDone
	rm.labels = map[string]string{poolLabel: "1", guestLabel: poolGuestID}
	if old := h.rooms[hid]; old != nil && old != rm { // the sync loop saw it first
		b.release(h, old)
	}
	h.rooms[hid] = rm
	b.register(rm)
	b.usageMeter.seen(usageSightingOf(h, rm, createdResources(doc, body)), tDone) // first reading, not billable
	pr := &poolRoom{hid: hid, key: k.name, proven: true, since: time.Now(), att: att}
	pr.expiresAt = time.Now().Add(poolTTLSeconds * time.Second)
	if s, _ := doc["expires_at"].(string); s != "" {
		if t, perr := time.Parse(time.RFC3339, s); perr == nil {
			pr.expiresAt = t
		}
	}
	raw, derr := decodeReceiptHeader(hdr.Get("X-Room-Receipt"))
	sha, image := "", ""
	if derr == nil {
		sha, image, derr = verifyPoolReceipt1(raw, att, hid)
	}
	switch {
	case derr == nil && image == k.image:
		pr.state, pr.receipt1 = poolReady, sha
		ph.proofFails = 0
	case derr == nil:
		pr.state, pr.why = poolStale, "its receipt 1 names image "+strconv.Quote(image)
	default:
		pr.state, pr.why = poolStale, "no verified pool receipt: "+derr.Error()
		if errors.Is(derr, errPoolReceiptBinding) {
			b.poolBindingMovedLocked(h, ph)
		}
	}
	ph.rooms[hid] = pr
	if pr.state == poolStale && !errors.Is(derr, errPoolReceiptBinding) {
		// A front that never proves pool rooms would otherwise see a create
		// and a delete at the full refill rate, forever: back off 5 s,
		// doubling to 1 min, and tell ops once the failures run on. A moved
		// binding is not counted: the hotel is attested again at once.
		ph.proofFails++
		ph.backoff = tDone.Add(poolRetry(ph.proofFails))
		if ph.proofFails == poolProofAlarmAfter {
			ph.alarm = poolProofAlarm(h, ph)
			b.alerts.send("ready_rooms", b.alerts.opsChat, ph.alarm, nil, nil)
		}
	}
	b.mu.Unlock()
	if pr.state == poolStale {
		log.Printf("ready rooms: hotel %s: pool room %s not ready (%s); deleted", h.cfg.ID, hid, pr.why)
		b.poolDelete(ctx, h, hid)
	}
}

// poolDebugString is one line per pool room of hotel id, for tests and logs.
// Caller holds b.mu.
func (p *readyRooms) poolDebugString(id string) string {
	var buf bytes.Buffer
	for _, pr := range sortedPoolRooms(p.hotel(id)) {
		fmt.Fprintf(&buf, "%s %s %s proven=%v %s\n", pr.hid, pr.key, pr.state, pr.proven, pr.why)
	}
	return buf.String()
}
