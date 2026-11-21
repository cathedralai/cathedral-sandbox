// Metered guests: the ledger's allowance at the front door.
//
// A guest is metered when its config says "metered": true (the config, not
// state_dir, decides it, so a lost file never opens a guest). A metered guest
// is admitted only on the ledger's word, and it starts closed: cap 0 and no
// lease, so every create is refused until the ledger sends an allowance. A
// guest that is not metered behaves as before.
//
// The ledger sends and reads the allowance with the operator key:
//
//	PUT /v1/broker/guests/<id>/allowance  {"issue", "cap", "lease_seconds", "max_ttl_seconds", "max_memory_gib"}
//	GET /v1/broker/guests/<id>/allowance  the allowance, live rooms and the lease seconds left
//
// A PUT for a guest that is not metered answers 409 guest_not_metered. A PUT
// stamps ledger_seen_at with the broker's clock and keeps the allowance in
// state_dir/guest-allowances.json (a temporary file, synced, renamed, then
// the directory synced; mode 0600) before it applies. A write that fails at
// any step answers 500 state_write_failed and closes the guest until a later
// PUT is saved. Each PUT carries an issue above the stored one; an issue at
// or below it is stale: 409 stale_allowance, and nothing changes.
//
// After a restart the file is read again: a cap of 0 stays 0, the issue is
// kept, and a lease keeps its ledger_seen_at, so it can expire across the
// restart. A missing file leaves every metered guest closed. A file that does
// not parse is kept aside and closes every metered guest; its issues are
// lost, so the next issue must be above the broker's clock in unix
// milliseconds at start. A stored entry that cannot open admission closes
// that guest and keeps its issue (or that clock value when the issue itself
// is not usable). Either way the closed state is written to a fresh file at
// once, so a later start keeps it; a broker that cannot write it does not
// start. After a failed save the file holds the allowance just sent or the
// previous one, each with its own ledger_seen_at, so a restart admits for at
// most one lease of an allowance the ledger sent.
//
// A metered create, and each lifetime extension of a metered room, is refused:
//   - 503 allowance_recount with Retry-After until every hotel the guest may
//     use (or has had rooms on) has answered one room list since the broker
//     started: until then its rooms there are not counted;
//   - 402 allowance_lease_expired when the lease is older than lease_seconds,
//     or there is none;
//   - 402 allowance_exhausted when the live rooms plus the new ones would pass
//     the cap (an extension: when the live rooms pass the cap).
//
// Live rooms of a metered guest are its creates in flight, every room the
// broker still holds for it (rooms being removed included, until the sync
// loop lets them go), and every create attempt whose answer was lost: until
// the hotel has listed its room and the broker has removed it, or a hold of
// uncertain_create_hold_seconds (default and minimum: the create timeout,
// hotelCreateTimeout) has passed, in case the hotel still starts it; a room
// it lists in that time is reaped as an orphan. A cleanup that finds no
// room, at once or after failed tries, does not end the hold; only a list
// asked for after the deadline does; in a batch each attempt counts on its
// own; and a hold still counts after its hotel leaves, until its deadline.
// Holds live in memory: a restart forgets them (README, known limits). Every retry of a metered create on
// another hotel is a new admission: lease and cap with the room the failed
// attempt may hold, and the create's ttl and memory against the allowance of
// that moment; a retry that does not fit is not sent. Size, lifetime, lease
// and cap are checked against one allowance, under the lock that reserves the
// rooms.
//
// A metered create always sends ttl_seconds of at most max_ttl_seconds (the
// maximum when absent) and resources.memory_gib (4, the hotel default, when
// absent); a create that asks for more memory than max_memory_gib is refused
// 400 memory_limit before any hotel call. Each route that resets a room's
// deadline at the hotel (PATCH on the room, POST heartbeat, POST and PATCH
// lifetime, the client lifetime route) is a new admission, checked after the
// body is read and any hotel lookup is done, right before the hotel call: it
// sends ttl_seconds of at most max_ttl_seconds, and a refused one sends
// nothing, so the room keeps the deadline it has. A room claim (room kit) is
// refused for a metered guest: it sets a lifetime this gate does not see.
//
// Nothing here stops or deletes a running room.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	allowancesFile = "guest-allowances.json"
	// allowanceLeaseRetry is the Retry-After of allowance_lease_expired: the
	// ledger renews about once a minute.
	allowanceLeaseRetry = 30
	// allowanceRecountRetry is the Retry-After of allowance_recount: hotels
	// list their rooms every 2 s.
	allowanceRecountRetry = 5
	// maxAllowanceTTLSeconds is the longest ttl_seconds a hotel takes.
	maxAllowanceTTLSeconds = 48 * 3600
	// hotelDefaultMemoryGiB is the memory_gib a hotel gives a create that
	// names none (cathedral/sandbox_api.py Resources).
	hotelDefaultMemoryGiB = 4
	// allowanceZeroMessage is the allowance_exhausted wording at cap 0.
	allowanceZeroMessage = "this key's allowance is 0 rooms right now; check the account's balance and status, then try again"
)

// guestAllowance is what the ledger last sent for one guest. A stored value
// is never changed in place: a PUT stores a new one.
type guestAllowance struct {
	Issue         int64     `json:"issue"`
	Cap           int       `json:"cap"`
	LeaseSeconds  int       `json:"lease_seconds"`
	MaxTTLSeconds int       `json:"max_ttl_seconds"`
	MaxMemoryGiB  int       `json:"max_memory_gib"`
	LedgerSeenAt  time.Time `json:"ledger_seen_at"` // broker clock at the PUT
}

// fresh reports whether the lease holds at now. A ledger_seen_at after now
// (the clock went back across a restart) is not fresh.
func (a *guestAllowance) fresh(now time.Time) bool {
	if a == nil || a.LeaseSeconds <= 0 || a.LedgerSeenAt.IsZero() {
		return false
	}
	age := now.Sub(a.LedgerSeenAt)
	return age >= 0 && age <= time.Duration(a.LeaseSeconds)*time.Second
}

// usable reports whether a stored allowance may open admission: a lease
// needs an issue and positive limits. The closed form (all zero) is valid
// too; it never opens anything.
func (a *guestAllowance) usable() bool {
	if a.Issue < 0 || a.Cap < 0 || a.LeaseSeconds < 0 || a.MaxTTLSeconds < 0 || a.MaxTTLSeconds > maxAllowanceTTLSeconds || a.MaxMemoryGiB < 0 {
		return false
	}
	return a.LeaseSeconds == 0 || (a.Issue >= 1 && a.MaxTTLSeconds >= 1 && a.MaxMemoryGiB >= 1)
}

type allowanceFile struct {
	Version int                       `json:"version"`
	Guests  map[string]guestAllowance `json:"guests"`
}

// allowances is the metered guest state of a broker.
type allowances struct {
	saveMu sync.Mutex // one PUT at a time, from the stale check through the rename
	// byGuest is guest id -> allowance, for every guest in the file, also
	// guests not in the config now (kept for when they come back). Guarded
	// by broker.mu; a PUT replaces the whole map.
	byGuest map[string]*guestAllowance
	// uncertain is guest id -> create attempts whose answer was lost (the
	// hotel may have started a room) and whose create request has not yet
	// finished its reap pass. Guarded by broker.mu.
	uncertain map[string]int
	// attempts is orphanKey(hotel, batch) -> the lost attempts of a metered
	// create request on one hotel, while the hotel's unreaped record of the
	// request lasts. Guarded by broker.mu.
	attempts map[string]int
	// removed is orphanKey(hotel, batch) -> the ids of orphan rooms of the
	// request that a reap pass deleted on that hotel; a room deleted twice
	// counts once. attempts - len(removed) is what the record still counts.
	// Guarded by broker.mu.
	removed map[string]map[string]bool
	// listedAt is orphanKey(hotel, batch) -> when the last successful
	// cleanup list of the request was asked for: a hold ends only on a
	// list asked for after its deadline. Guarded by broker.mu.
	listedAt map[string]time.Time
	// held is orphanKey(hotel, batch) -> a metered guest's hold, kept apart
	// from the hotel, so it still counts until its deadline when the hotel
	// leaves. Guarded by broker.mu.
	held map[string]*heldAttempts
	// unlisted holds hotels joined at runtime that have not answered a room
	// list yet (metered recount only; roomsUnchecked covers hotels loaded at
	// start). Guarded by broker.mu.
	unlisted map[*hotel]bool
	// hold is how long a lost create attempt whose reap found no room still
	// counts (uncertain_create_hold_seconds).
	hold time.Duration
}

func orphanKey(hotelID, batchID string) string { return hotelID + "\x00" + batchID }

// heldAttempts is one hold of a metered guest's lost create attempts on one
// hotel.
type heldAttempts struct {
	h     *hotel
	guest string
	n     int // lost attempts held
	until time.Time
}

// meteredLocked reports whether g is metered (its config says so), and its
// allowance (nil: none yet, which is closed). Caller holds b.mu.
func (b *broker) meteredLocked(g *guestState) (bool, *guestAllowance) {
	return g.limits.Metered, b.allow.byGuest[g.cfg.ID]
}

// meteredLiveLocked counts the rooms a metered guest may hold: creates
// admitted and not yet placed or failed, every room the broker still has for
// it (rooms being removed included, until the sync loop lets them go), create
// attempts whose answer was lost, and the orphans of those attempts that a
// reap pass has not confirmed gone (h.unreaped). Between a create losing its
// answer and its attempt being resolved, the attempt is counted exactly once:
// in uncertain before settleUncertain, through its unreaped record after it,
// and the move is one b.mu step. Caller holds b.mu.
func (b *broker) meteredLiveLocked(g *guestState) int {
	n := g.pending + b.allow.uncertain[g.cfg.ID]
	for _, h := range b.hotelList() {
		for _, rm := range h.rooms {
			if rm.guest == g.cfg.ID {
				n++
			}
		}
		for batchID, ub := range h.unreaped {
			if ub.guest == g.cfg.ID {
				n += b.unresolvedLocked(h, batchID)
			}
		}
	}
	now := time.Now()
	for key, ha := range b.allow.held {
		if b.hotelByID(ha.h.cfg.ID) == ha.h { // counted through the hotel's record
			if _, bid, _ := strings.Cut(key, "\x00"); ha.h.unreaped[bid] == nil {
				b.dropHoldLocked(key) // released
			}
			continue
		}
		// A hold on a hotel that left (or was replaced under its id) counts
		// until its deadline: no list of that hotel can resolve it now.
		if !now.Before(ha.until) {
			b.dropHoldLocked(key)
			continue
		}
		if ha.guest == g.cfg.ID {
			n += max(0, ha.n-len(b.allow.removed[key]))
		}
	}
	return n
}

// dropHoldLocked forgets a hold and its counts. Caller holds b.mu.
func (b *broker) dropHoldLocked(key string) {
	delete(b.allow.held, key)
	delete(b.allow.attempts, key)
	delete(b.allow.removed, key)
	delete(b.allow.listedAt, key)
}

// recountPendingLocked reports whether a hotel that g may use, or has had
// rooms on, has not answered a room list since the broker started or since
// it joined: the guest's rooms there are not counted yet. "May use" is what
// placement reaches (guestReaches), so a miner hotel an own-hosts-only guest
// can never be placed on does not hold its admission. Caller holds b.mu.
func (b *broker) recountPendingLocked(g *guestState) bool {
	for _, h := range b.hotelList() {
		if (h.roomsUnchecked || b.allow.unlisted[h]) && (g.guestReaches(h) || len(b.guestRooms[g.cfg.ID][h.cfg.ID]) > 0) {
			return true
		}
	}
	return false
}

// unmarkUnlisted forgets a hotel whose join failed.
func (b *broker) unmarkUnlisted(h *hotel) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.allow.unlisted, h)
}

// markUnlisted records a hotel that joins at runtime as not yet listed, for
// the metered recount only. Called before the hotel is in the set; a join
// that fails calls unmarkUnlisted.
func (b *broker) markUnlisted(h *hotel) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.allow.unlisted == nil {
		b.allow.unlisted = map[*hotel]bool{}
	}
	b.allow.unlisted[h] = true
}

// allowanceRefusalLocked says why metered guest g may not add n rooms now
// (n = 0: extend a room it has), with the Retry-After seconds. nil: g is not
// metered, or it is within its allowance. Caller holds b.mu.
func (b *broker) allowanceRefusalLocked(g *guestState, n int, now time.Time) (*apiErr, int) {
	metered, a := b.meteredLocked(g)
	if !metered {
		return nil, 0
	}
	if b.recountPendingLocked(g) {
		return &apiErr{503, "allowance_recount", "this key is sold out right now while the broker counts its rooms after a restart; try again shortly"}, allowanceRecountRetry
	}
	if !a.fresh(now) {
		return &apiErr{402, "allowance_lease_expired", "this key is sold out right now; try again shortly"}, allowanceLeaseRetry
	}
	if live := b.meteredLiveLocked(g); live+n > a.Cap {
		if a.Cap == 0 {
			// The ledger sends cap 0 for no credit, a disabled key, a debt or
			// too many unreadable readings, and the PUT carries no reason, so
			// the wording names none of them.
			return &apiErr{402, "allowance_exhausted", allowanceZeroMessage}, 0
		}
		return &apiErr{402, "allowance_exhausted", fmt.Sprintf("this key's allowance is %d rooms at one time and %d are running, starting or being removed; delete rooms or add credit to the account", a.Cap, live)}, 0
	}
	return nil, 0
}

// compatCountOf is the count a compat create asks for, for its early metered
// checks: 1 unless a whole number from 1 to compatMaxCount (the create
// validates count again and refuses a bad one).
func compatCountOf(req map[string]any) int {
	f, ok := req["count"].(float64)
	if !ok || f != math.Trunc(f) || f < 1 || f > compatMaxCount {
		return 1
	}
	return int(f)
}

// meteredRefusal is allowanceRefusalLocked under b.mu: an early refusal,
// before any hotel or build call. admitCreate decides.
func (b *broker) meteredRefusal(g *guestState, n int) (*apiErr, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.allowanceRefusalLocked(g, n, time.Now())
}

// meteredCreate checks a metered guest's create of n rooms before any hotel
// call and applies its size and lifetime limits to payload, the body the
// hotel receives. admitCreate checks again against the allowance of the
// moment, under the lock that reserves the rooms. A guest that is not
// metered: no change.
func (b *broker) meteredCreate(g *guestState, payload map[string]any, n int) (*apiErr, int) {
	b.mu.Lock()
	metered, a := b.meteredLocked(g)
	e, retry := b.allowanceRefusalLocked(g, n, time.Now())
	b.mu.Unlock()
	if !metered {
		return nil, 0
	}
	if e != nil {
		return e, retry
	}
	// A fresh lease means a stored allowance: a is not nil here.
	if e := limitCreateMemory(payload, a.MaxMemoryGiB); e != nil {
		return e, 0
	}
	if e := limitCreateTTL(payload, a.MaxTTLSeconds); e != nil {
		return e, 0
	}
	afterMeteredCheck()
	return nil, 0
}

// afterCleanupPass, when set, runs when a sync loop cleanup pass has
// returned, before its record is updated (busy is still set). Tests hold a
// pass there. Atomic: cleanup workers of earlier tests may still read it.
var afterCleanupPass atomic.Pointer[func(h *hotel, batchID string)]

func runAfterCleanupPass(h *hotel, batchID string) {
	if fn := afterCleanupPass.Load(); fn != nil {
		(*fn)(h, batchID)
	}
}

// afterMeteredCheck runs between a metered create's early check and its
// reservation in admitCreate. Tests hold creates there to prove the
// reservation alone keeps the cap and the limits.
var afterMeteredCheck = func() {}

// admitCreate is admit for a create of n rooms with body payload: for a
// metered guest, the lease, the cap, the size and the lifetime are checked
// against one allowance, under the lock that reserves the rooms.
func (b *broker) admitCreate(g *guestState, n int, payload map[string]any) (*apiErr, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if metered, a := b.meteredLocked(g); metered {
		if e, retry := b.allowanceRefusalLocked(g, n, time.Now()); e != nil {
			return e, retry
		}
		if e := limitCreateMemory(payload, a.MaxMemoryGiB); e != nil {
			return e, 0
		}
		if e := limitCreateTTL(payload, a.MaxTTLSeconds); e != nil {
			return e, 0
		}
	}
	return b.admitLocked(g, n)
}

// noteUncertainLocked counts one create attempt of g whose answer was lost:
// the hotel may hold a room. createMany settles it after its reap pass.
// Caller holds b.mu.
func (b *broker) noteUncertainLocked(g *guestState) {
	if b.allow.uncertain == nil {
		b.allow.uncertain = map[string]int{}
	}
	b.allow.uncertain[g.cfg.ID]++
}

// createSize is the ttl_seconds and resources.memory_gib of a create body
// as the hotel receives it (0: absent).
type createSize struct{ ttl, memGiB float64 }

func createSizeOf(body []byte) createSize {
	var doc struct {
		TTL       any `json:"ttl_seconds"`
		Resources struct {
			MemoryGiB any `json:"memory_gib"`
		} `json:"resources"`
	}
	_ = json.Unmarshal(body, &doc)
	ttl, _ := numberOf(doc.TTL)
	mem, _ := numberOf(doc.Resources.MemoryGiB)
	return createSize{ttl, mem}
}

// retryRefusalLocked says why a create of metered guest g may not try
// another hotel now: a retry is a new admission. The lease must be fresh,
// the cap must hold the live rooms (the reservation of this create and any
// room a failed attempt may hold are in them), and the body, sent unchanged,
// must fit the allowance of this moment. nil: g is not metered, or the retry
// fits. Caller holds b.mu.
func (b *broker) retryRefusalLocked(g *guestState, size createSize) (*apiErr, int) {
	metered, a := b.meteredLocked(g)
	if !metered {
		return nil, 0
	}
	if e, retry := b.allowanceRefusalLocked(g, 0, time.Now()); e != nil {
		return e, retry
	}
	if size.memGiB > float64(a.MaxMemoryGiB) || size.ttl > float64(a.MaxTTLSeconds) || size.ttl == 0 {
		return &apiErr{409, "allowance_changed", "this key's allowance changed while the create was placed; the room it asked for no longer fits, so it was not tried on another hotel"}, 0
	}
	return nil, 0
}

// refusedRetry is the answer of a create whose retry was refused: the
// failure of its last attempt, or the refusal when no attempt answered.
func refusedRetry(last createResult, e *apiErr, retry int) createResult {
	if last.status != 0 {
		return last
	}
	r := createResult{status: e.status, doc: errDoc(e.code, e.msg)}
	if retry > 0 {
		r.header = http.Header{"Retry-After": {strconv.Itoa(retry)}}
	}
	return r
}

// noteOrphanRemovedLocked records orphan room roomID of a create request as
// deleted on h by a reap pass. Two passes that delete one room count it
// once. Caller holds b.mu.
func (b *broker) noteOrphanRemovedLocked(h *hotel, batchID, roomID string) {
	if b.allow.removed == nil {
		b.allow.removed = map[string]map[string]bool{}
	}
	key := orphanKey(h.cfg.ID, batchID)
	if b.allow.removed[key] == nil {
		b.allow.removed[key] = map[string]bool{}
	}
	b.allow.removed[key][roomID] = true
}

// unresolvedLocked is what h's unreaped record of a create request counts
// against its metered guest: lost attempts whose rooms have not been listed
// and removed. Between a create losing its answer and its attempt being
// resolved, the attempt is counted exactly once: in uncertain before
// settleUncertain (the record, unsettled, counts 0), through this record
// after it, and the move is one b.mu step. A settled record with no attempts
// entry still counts 1. Caller holds b.mu.
func (b *broker) unresolvedLocked(h *hotel, batchID string) int {
	key := orphanKey(h.cfg.ID, batchID)
	n, known := b.allow.attempts[key]
	if !known {
		if ub := h.unreaped[batchID]; ub != nil && ub.unsettled {
			return 0 // its lost attempts count in uncertain until the settle
		}
		return 1
	}
	return max(0, n-len(b.allow.removed[key]))
}

// holdsLocked reports whether h's unreaped record of a create request must
// stay after a list that found none of its rooms: a metered guest's lost
// attempts are not all resolved and the list was asked for before the hold
// passed (asked is when the list request started, not when its answer came:
// a room that started before the deadline may be missing from an older
// answer). A record without a hold (a guest that is not metered) never
// stays. Caller holds b.mu.
func (b *broker) holdsLocked(h *hotel, batchID string, ub *unreapedBatch, asked time.Time) bool {
	return asked.Before(ub.holdUntil) && b.unresolvedLocked(h, batchID) > 0
}

// noteCleanupListLocked records when a successful cleanup list of a create
// request on h was asked for, for a metered request already held (the first
// pass, before settleUncertain, needs none: the hold starts after it).
// Caller holds b.mu.
func (b *broker) noteCleanupListLocked(h *hotel, batchID string, asked time.Time) {
	key := orphanKey(h.cfg.ID, batchID)
	if _, held := b.allow.attempts[key]; !held {
		return
	}
	if b.allow.listedAt == nil {
		b.allow.listedAt = map[string]time.Time{}
	}
	b.allow.listedAt[key] = asked
}

// cleanupListedAtLocked is when the last successful cleanup list of a create
// request on h was asked for; zero (before any deadline) when none is known.
// Caller holds b.mu.
func (b *broker) cleanupListedAtLocked(h *hotel, batchID string) time.Time {
	return b.allow.listedAt[orphanKey(h.cfg.ID, batchID)]
}

// listedLocked notes the first successful room list of a hotel since it
// joined (the metered recount). Called from the sync loop. Caller holds b.mu.
func (b *broker) listedLocked(h *hotel) {
	delete(b.allow.unlisted, h)
}

// settleUncertain ends the in-flight count of one create request's lost
// attempts once its first reap pass ran. For a metered guest, each attempt
// whose room has not been listed and removed goes on counting through the
// hotel's unreaped record of the request, which is held until every such
// room has been listed and removed, or the hold has passed: the hotel may
// still start a room after its answer was lost (a proxy timed out, the
// hotel went on), and a reap pass that fails, then finds nothing, proves no
// more than one that finds nothing at once. keep holds the rooms the
// request did receive, by hotel.
func (b *broker) settleUncertain(g *guestState, batchID string, results []createResult, keep map[*hotel]map[string]bool) {
	lostOn := map[*hotel]int{}
	total := 0
	for _, res := range results {
		for _, h := range res.lost {
			lostOn[h]++
			total++
		}
	}
	if total == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.allow.attempts == nil {
		b.allow.attempts = map[string]int{}
	}
	if b.allow.removed == nil {
		b.allow.removed = map[string]map[string]bool{}
	}
	if b.allow.held == nil {
		b.allow.held = map[string]*heldAttempts{}
	}
	now := time.Now()
	for k, ha := range b.allow.held { // holds released, or past their deadline on a hotel that left
		_, bid, _ := strings.Cut(k, "\x00")
		present := b.hotelByID(ha.h.cfg.ID) == ha.h
		if (present && ha.h.unreaped[bid] == nil) || (!present && !now.Before(ha.until)) {
			delete(b.allow.held, k)
		}
	}
	for k := range b.allow.attempts { // settled records released since
		hotelID, bid, _ := strings.Cut(k, "\x00")
		if h := b.hotelByID(hotelID); b.allow.held[k] == nil && (h == nil || h.unreaped[bid] == nil) {
			delete(b.allow.attempts, k)
			delete(b.allow.removed, k)
			delete(b.allow.listedAt, k)
		}
	}
	metered, _ := b.meteredLocked(g)
	until := time.Now().Add(b.allow.hold)
	for h, n := range lostOn {
		key := orphanKey(h.cfg.ID, batchID)
		ub := h.unreaped[batchID]
		if ub != nil {
			ub.unsettled = false // uncertain gives these attempts up below, in this b.mu step
		}
		if !metered || len(b.allow.removed[key]) >= n {
			// Not metered: as before. Metered and every attempt's room listed
			// and removed: nothing is left to count.
			if ub == nil {
				delete(b.allow.attempts, key)
				delete(b.allow.removed, key)
			}
			continue
		}
		b.allow.attempts[key] = n
		if ub == nil { // the reap pass found no room: the hotel may still start it
			if h.unreaped == nil {
				h.unreaped = map[string]*unreapedBatch{}
			}
			ub = &unreapedBatch{guest: g.cfg.ID, keep: keep[h]}
			h.unreaped[batchID] = ub
		}
		ub.holdUntil = until
		b.allow.held[key] = &heldAttempts{h: h, guest: g.cfg.ID, n: n, until: until}
	}
	if b.allow.uncertain[g.cfg.ID] -= total; b.allow.uncertain[g.cfg.ID] <= 0 {
		delete(b.allow.uncertain, g.cfg.ID)
	}
}

// numberOf is v as a number: a JSON number decoded by encoding/json, or an
// int the broker set itself (compat.go).
func numberOf(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// limitCreateMemory makes resources.memory_gib explicit (the hotel default
// when absent) and refuses more than limit GiB.
func limitCreateMemory(payload map[string]any, limit int) *apiErr {
	if payload["resources"] == nil {
		payload["resources"] = map[string]any{}
	}
	res, ok := payload["resources"].(map[string]any)
	if !ok {
		return &apiErr{400, "invalid_resources", "resources must be an object"}
	}
	if res["memory_gib"] == nil {
		res["memory_gib"] = hotelDefaultMemoryGiB
	}
	gib, ok := numberOf(res["memory_gib"])
	if !ok {
		return &apiErr{400, "invalid_resources", "resources.memory_gib must be a number"}
	}
	if gib > float64(limit) {
		return &apiErr{400, "memory_limit", fmt.Sprintf("this key may ask for at most %d GiB of memory per room; this create asks for %v (resources.memory_gib, %d when absent)", limit, res["memory_gib"], hotelDefaultMemoryGiB)}
	}
	return nil
}

// limitCreateTTL sets ttl_seconds to at most limit: limit when absent or
// more. A value that is not a number of seconds is refused.
func limitCreateTTL(payload map[string]any, limit int) *apiErr {
	if payload["ttl_seconds"] == nil {
		payload["ttl_seconds"] = limit
		return nil
	}
	ttl, ok := numberOf(payload["ttl_seconds"])
	if !ok || ttl < 1 {
		return &apiErr{400, "invalid_ttl", "ttl_seconds must be a number of seconds, 1 or more"}
	}
	if ttl > float64(limit) {
		payload["ttl_seconds"] = limit
	}
	return nil
}

// meteredExtension checks one lifetime extension of metered guest g. It
// returns the largest ttl_seconds the extension may send (0: g is not
// metered, no limit here), or why it is refused.
func (b *broker) meteredExtension(g *guestState) (int, *apiErr, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	metered, a := b.meteredLocked(g)
	if !metered {
		return 0, nil, 0
	}
	if e, retry := b.allowanceRefusalLocked(g, 0, time.Now()); e != nil {
		return 0, e, retry
	}
	return a.MaxTTLSeconds, nil, 0
}

// lifetimeRoute reports whether a room request (tail after the room id, gate
// its first segment without ";params") resets the room's deadline at the
// hotel: PATCH on the room, POST heartbeat, POST and PATCH lifetime
// (cathedral/sandbox_server.py, all the provider's heartbeat). The hotel
// matches methods in any case and drops ";params" from the last segment, so
// this does too. Other writing methods on these paths count as well: the
// hotel has no other route there.
func lifetimeRoute(method, gate, tail string) bool {
	if strings.Contains(tail, "/") {
		return false
	}
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "DELETE":
		return false
	}
	return gate == "" || gate == "heartbeat" || gate == "lifetime"
}

// meteredRoomRoute gates the room routes of a metered guest that set a
// room's lifetime. It returns the body to send to the hotel (the request
// body unless it is changed here) and false when it has written the answer
// and nothing may go to the hotel. A guest that is not metered, or a route
// that sets no lifetime, passes unchanged.
func (b *broker) meteredRoomRoute(w http.ResponseWriter, r *http.Request, g *guestState, h *hotel, hid, gate, tail string, body []byte) ([]byte, bool) {
	isClaim := gate == "claim" && !strings.Contains(tail, "/")
	if !isClaim && !lifetimeRoute(r.Method, gate, tail) {
		return body, true
	}
	b.mu.Lock()
	metered, _ := b.meteredLocked(g)
	b.mu.Unlock()
	if !metered {
		return body, true
	}
	if isClaim {
		writeErr(w, 403, "claim_refused_metered", "a room claim sets a lifetime outside this key's allowance; it is refused for a metered key")
		return nil, false
	}
	// The body is read (handleRoom) and checked, and any hotel lookup done,
	// before the admission below: a body held back past a lease or a cap
	// change meets the allowance of the moment it goes to the hotel.
	doc := map[string]any{}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &doc); err != nil || doc == nil {
			writeErr(w, 400, "invalid_json", "a lifetime request body must be a JSON object")
			return nil, false
		}
	}
	ask := 0.0
	if v := doc["ttl_seconds"]; v != nil {
		n, ok := numberOf(v)
		if !ok || n < 1 {
			writeErr(w, 400, "invalid_ttl", "ttl_seconds must be a number of seconds, 1 or more")
			return nil, false
		}
		ask = n
	} else {
		// No ttl_seconds: the hotel would reuse the room's own. Send that
		// explicitly, so the room never gets more than it asked for.
		own, ok := roomTTLSeconds(r, h, hid)
		if !ok {
			writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not say the room's ttl_seconds; send ttl_seconds")
			return nil, false
		}
		ask = own
	}
	maxTTL, e, retry := b.meteredExtension(g)
	if e != nil {
		writeLimitErr(w, e, retry)
		return nil, false
	}
	doc["ttl_seconds"] = int(math.Min(math.Floor(ask), float64(maxTTL)))
	out, _ := json.Marshal(doc)
	return out, true
}

// roomTTLSeconds reads ttl_seconds from the hotel's room document.
func roomTTLSeconds(r *http.Request, h *hotel, hid string) (float64, bool) {
	status, _, out, err := h.do(r.Context(), "GET", "/v1/sandboxes/"+url.PathEscape(hid), nil, nil, 30*time.Second)
	if err != nil || status != 200 {
		return 0, false
	}
	var doc struct {
		TTL *float64 `json:"ttl_seconds"`
	}
	if json.Unmarshal(out, &doc) != nil || doc.TTL == nil || *doc.TTL < 1 {
		return 0, false
	}
	return *doc.TTL, true
}

// ---------------------------------------------------------------- operator routes

// allowancePath is the guest id of an operator path "<id>/allowance" under
// /v1/broker/guests/.
func allowancePath(rest string) (string, bool) {
	id, ok := strings.CutSuffix(rest, "/allowance")
	if !ok || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

// handleAllowance serves GET and PUT /v1/broker/guests/<id>/allowance. The
// caller has checked the operator key.
func (b *broker) handleAllowance(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case "GET":
		b.mu.Lock()
		defer b.mu.Unlock()
		g := b.guests[id]
		if g == nil {
			writeErr(w, 404, "guest_not_found", "no guest "+id)
			return
		}
		writeJSON(w, 200, b.allowanceViewLocked(g, time.Now()))
	case "PUT":
		b.putAllowance(w, r, id)
	default:
		writeErr(w, 404, "route_not_found", "no such guest route")
	}
}

func (b *broker) putAllowance(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Issue         *int64 `json:"issue"`
		Cap           *int   `json:"cap"`
		LeaseSeconds  *int   `json:"lease_seconds"`
		MaxTTLSeconds *int   `json:"max_ttl_seconds"`
		MaxMemoryGiB  *int   `json:"max_memory_gib"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		writeErr(w, 400, "invalid_json", "body must be one JSON object with issue, cap, lease_seconds, max_ttl_seconds and max_memory_gib, all whole numbers")
		return
	}
	bad := ""
	switch {
	case req.Issue == nil || req.Cap == nil || req.LeaseSeconds == nil || req.MaxTTLSeconds == nil || req.MaxMemoryGiB == nil:
		bad = "issue, cap, lease_seconds, max_ttl_seconds and max_memory_gib are all required"
	case *req.Issue < 1:
		bad = "issue must be 1 or more"
	case *req.Cap < 0:
		bad = "cap must be 0 or more"
	case *req.LeaseSeconds < 1:
		bad = "lease_seconds must be 1 or more"
	case *req.MaxTTLSeconds < 1 || *req.MaxTTLSeconds > maxAllowanceTTLSeconds:
		bad = fmt.Sprintf("max_ttl_seconds must be between 1 and %d", maxAllowanceTTLSeconds)
	case *req.MaxMemoryGiB < 1:
		bad = "max_memory_gib must be 1 or more"
	}
	if bad != "" {
		writeErr(w, 400, "invalid_allowance", bad)
		return
	}
	b.allow.saveMu.Lock()
	defer b.allow.saveMu.Unlock()
	b.mu.Lock()
	g := b.guests[id]
	if g == nil {
		b.mu.Unlock()
		writeErr(w, 404, "guest_not_found", "no guest "+id)
		return
	}
	if !g.limits.Metered {
		b.mu.Unlock()
		writeErr(w, 409, "guest_not_metered", "guest "+id+" is not metered: mark it \"metered\": true in the broker config first; nothing changed")
		return
	}
	if b.cfg.StateDir == "" { // a metered guest needs state_dir (loadAllowances); kept as a guard
		b.mu.Unlock()
		writeErr(w, 409, "no_state_dir", "the broker has no state_dir, so it cannot keep an allowance")
		return
	}
	if old := b.allow.byGuest[id]; old != nil && *req.Issue <= old.Issue {
		b.mu.Unlock()
		writeErr(w, 409, "stale_allowance", fmt.Sprintf("issue %d is not above the stored issue %d; nothing changed", *req.Issue, old.Issue))
		return
	}
	a := &guestAllowance{Issue: *req.Issue, Cap: *req.Cap, LeaseSeconds: *req.LeaseSeconds,
		MaxTTLSeconds: *req.MaxTTLSeconds, MaxMemoryGiB: *req.MaxMemoryGiB, LedgerSeenAt: time.Now()}
	next := make(map[string]*guestAllowance, len(b.allow.byGuest)+1)
	for k, v := range b.allow.byGuest {
		next[k] = v
	}
	next[id] = a
	b.mu.Unlock()
	// Written before it applies. A write that fails at any step may or may
	// not have reached the disk, so the guest is closed (cap 0, no lease) and
	// keeps this issue, until a later PUT is saved.
	if err := b.saveAllowances(next); err != nil {
		log.Printf("guest allowance for %s not written: %v; the guest is closed until an allowance is saved", id, err)
		b.mu.Lock()
		closed := make(map[string]*guestAllowance, len(b.allow.byGuest)+1)
		for k, v := range b.allow.byGuest {
			closed[k] = v
		}
		closed[id] = &guestAllowance{Issue: a.Issue}
		b.allow.byGuest = closed
		b.mu.Unlock()
		writeErr(w, 500, "state_write_failed", "could not write "+allowancesFile+"; the key is closed until an allowance is saved")
		return
	}
	b.mu.Lock()
	b.allow.byGuest = next
	view := b.allowanceViewLocked(g, time.Now())
	b.mu.Unlock()
	writeJSON(w, 200, view)
}

// allowanceViewLocked is the operator view of g's allowance. Caller holds b.mu.
func (b *broker) allowanceViewLocked(g *guestState, now time.Time) map[string]any {
	metered, a := b.meteredLocked(g)
	if !metered {
		return map[string]any{"guest": g.cfg.ID, "metered": false, "live_rooms": b.activeRooms(g)}
	}
	if a == nil {
		a = &guestAllowance{} // closed: cap 0, no lease
	}
	var seen any // null: the ledger has sent nothing
	if !a.LedgerSeenAt.IsZero() {
		seen = a.LedgerSeenAt.UTC().Format(time.RFC3339Nano)
	}
	left := 0
	if a.fresh(now) {
		left = int((time.Duration(a.LeaseSeconds)*time.Second - now.Sub(a.LedgerSeenAt)).Seconds())
	}
	return map[string]any{
		"guest": g.cfg.ID, "metered": true, "issue": a.Issue, "cap": a.Cap, "lease_seconds": a.LeaseSeconds,
		"max_ttl_seconds": a.MaxTTLSeconds, "max_memory_gib": a.MaxMemoryGiB, "ledger_seen_at": seen,
		"live_rooms": b.meteredLiveLocked(g), "lease_fresh": a.fresh(now), "lease_seconds_left": left,
		"recount_pending": b.recountPendingLocked(g),
	}
}

// ---------------------------------------------------------------- state_dir

// saveAllowances writes m to state_dir: a temporary file, synced, renamed
// over the old one, then the directory synced. Caller holds b.allow.saveMu.
func (b *broker) saveAllowances(m map[string]*guestAllowance) error {
	out := allowanceFile{Version: 1, Guests: make(map[string]guestAllowance, len(m))}
	for id, a := range m {
		c := *a
		if !c.LedgerSeenAt.IsZero() {
			c.LedgerSeenAt = c.LedgerSeenAt.UTC()
		}
		out.Guests[id] = c
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return err
	}
	final := filepath.Join(b.cfg.StateDir, allowancesFile)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil { // a leftover tmp file keeps its old mode
		f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	return syncAllowanceDir(b.cfg.StateDir) // the rename is durable only once the directory is
}

// syncAllowanceDir syncs dir. A variable, so a test can make it fail.
var syncAllowanceDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// loadAllowances reads state_dir/guest-allowances.json at start. A metered
// guest needs state_dir. A missing file leaves every metered guest closed. A
// file that does not parse is moved aside and closes every metered guest,
// with an issue watermark of the clock in unix milliseconds: the issues it
// held are unknown, so only a later one may open the guest. An entry that
// cannot open admission closes that guest and keeps its issue, or that clock
// value when the issue is not usable. A file that cannot be read stops the
// broker.
func (b *broker) loadAllowances() error {
	b.allow.byGuest = map[string]*guestAllowance{}
	b.allow.uncertain = map[string]int{}
	b.allow.attempts = map[string]int{}
	b.allow.removed = map[string]map[string]bool{}
	b.allow.listedAt = map[string]time.Time{}
	b.allow.held = map[string]*heldAttempts{}
	b.allow.unlisted = map[*hotel]bool{}
	switch hold := b.cfg.UncertainCreateHoldSeconds; {
	case hold == 0:
		b.allow.hold = hotelCreateTimeout
	case time.Duration(hold)*time.Second < hotelCreateTimeout:
		return fmt.Errorf("config: uncertain_create_hold_seconds must be at least the create timeout to a hotel (%d s): a create the broker gave up on can still start a room until then", int(hotelCreateTimeout.Seconds()))
	default:
		b.allow.hold = time.Duration(hold) * time.Second
	}
	startMs := time.Now().UnixMilli()
	for id, g := range b.guests {
		if g.limits.Metered && b.cfg.StateDir == "" {
			return fmt.Errorf("config: guest %q is metered, which needs state_dir to keep its allowance", id)
		}
	}
	if b.cfg.StateDir == "" {
		return nil
	}
	path := filepath.Join(b.cfg.StateDir, allowancesFile)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	// A file that does not parse, or holds an entry that is not usable, is
	// kept aside and replaced at once by a file holding the closed entries
	// and their issue watermarks, so a later start keeps them too.
	quarantine := func(why string) error {
		aside := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
		if werr := os.WriteFile(aside, raw, 0o600); werr != nil {
			log.Printf("%s: %s; the old file was not kept aside: %v", path, why, werr)
		} else {
			log.Printf("%s: %s; the old file is kept at %s", path, why, aside)
		}
		if err := b.saveAllowances(b.allow.byGuest); err != nil {
			return fmt.Errorf("%s: %s, and the closed state could not be written: %w", path, why, err)
		}
		return nil
	}
	var f allowanceFile
	if err := json.Unmarshal(raw, &f); err != nil || f.Version != 1 || f.Guests == nil {
		for id, g := range b.guests {
			if g.limits.Metered {
				b.allow.byGuest[id] = &guestAllowance{Issue: startMs}
			}
		}
		return quarantine(fmt.Sprintf("does not parse (%v); metered guests stay closed until the ledger sends an issue above %d", err, startMs))
	}
	closed := false
	for id, a := range f.Guests {
		switch {
		case a.Issue < 1:
			log.Printf("%s: guest %s: the stored issue is not usable; the guest stays closed until the ledger sends an issue above %d", path, id, startMs)
			a, closed = guestAllowance{Issue: startMs}, true
		case !a.usable():
			log.Printf("%s: guest %s: the stored allowance is not usable; the guest stays closed until the ledger sends an issue above %d", path, id, a.Issue)
			a, closed = guestAllowance{Issue: a.Issue}, true
		}
		b.allow.byGuest[id] = &a
	}
	if closed {
		return quarantine("an entry is not usable")
	}
	return nil
}
