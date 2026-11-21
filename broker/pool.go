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
// sealed, admitted with a verified SEV-SNP attestation whose AMD chain passed
// and whose binding names a receipt key, the key's image is warm there (the
// catalog pre-pull, prewarm.go), and it would place a room now
// (admissibleFree, diskFits). At most 1 pool create a second per hotel: a
// create starts no sooner than poolCreateEvery after the previous one's
// answer, and a create slot is taken without waiting, so a customer create
// never waits for a pool create.
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
// The pool bound of a hotel in this pull request is its target: every pool
// room the hotel holds, in any state, and the creates in flight count
// against it. Quarantine at or over the bound stops refill on that hotel and
// raises an alarm; it never causes a deletion. (PR 3 adds the slot, memory
// and disk bounds.)
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
	poolTick         = 200 * time.Millisecond
	poolReadTimeout  = 10 * time.Second // design 2.6 step 7
	poolReadsPerStep = 20
	poolRetryFirst   = 5 * time.Second
	poolRetryMax     = time.Minute
)

// Vars for tests.
var (
	poolCreateEvery   = time.Second           // design: at most 1 pool create a second per hotel (PR 2)
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
	nextCreate time.Time
	nextRead   time.Time // receipts reads start at least poolReadEvery apart
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
	keys    []poolKey
	guest   *guestState
	saveMu  sync.Mutex // one settings write at a time
	journal *claimJournal
	// journalState is "complete", "incomplete" or "unavailable".
	journalState, journalWhy string
	// Guarded by b.mu.
	settings readyRoomsSettings
	hotels   map[string]*poolHotel
}

// openJournal opens the claim journal. The manager creates and deletes
// rooms only while it is open and complete.
func (p *readyRooms) openJournal(stateDir string) {
	j, _, err := openClaimJournal(stateDir)
	p.journal = j
	switch {
	case err == nil:
		p.journalState = "complete"
	case errors.Is(err, errClaimJournalIncomplete):
		p.journalState, p.journalWhy = "incomplete", err.Error()
		log.Printf("ready rooms: %v; the pool manager creates and deletes nothing until a person looks", err)
	default:
		p.journalState, p.journalWhy = "unavailable", err.Error()
		log.Printf("ready rooms: claim journal not opened: %v; the pool manager creates and deletes nothing", err)
	}
}

// close stops the journal's writer. Safe on nil.
func (p *readyRooms) close() {
	if p != nil && p.journal != nil {
		_ = p.journal.close()
	}
}

func (p *readyRooms) journalOK() bool { return p.journalState == "complete" }

// hotel is the state of hotel id, made on first use. Caller holds b.mu.
func (p *readyRooms) hotel(id string) *poolHotel {
	ph := p.hotels[id]
	if ph == nil {
		ph = &poolHotel{rooms: map[string]*poolRoom{}, creating: map[string]int{}}
		p.hotels[id] = ph
	}
	return ph
}

// boundLocked is a hotel's pool bound: the sum of its targets. Caller
// holds b.mu.
func (p *readyRooms) boundLocked() int {
	n := 0
	for _, k := range p.keys {
		n += p.settings.target(k.name)
	}
	return n
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
	if b.cfg.ReadyRoomsUnsealedForTests && admissionOff(h) && h.cfg.Sealed && loopbackURL(h.cfg.API) && loopbackURL(h.cfg.Health) {
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
	case h.cfg.MinerHotkey != "":
		return "miner hotel"
	case h.reservedFor() != "":
		return "reserved for a guest"
	case !h.cfg.Sealed:
		return "not a sealed hotel"
	}
	if _, ok := b.poolAttestLocked(h, ph, now); !ok {
		return "no verified attestation with a receipt key"
	}
	if b.admissibleFree(h, now) <= 0 {
		return "takes no room now"
	}
	for _, k := range p.keys {
		if p.settings.target(k.name) > 0 && !h.warm[k.image] {
			return "image of " + k.name + " not warm"
		}
	}
	return ""
}

// poolWork is what one step does outside b.mu.
type poolWork struct {
	att     poolAttest
	attOK   bool
	reads   []string
	deletes []string
	create  *poolKey
}

// poolStep is one step of h's pool: receipts reads, deletes, then at most
// one create.
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
		b.poolCreate(ctx, h, *w.create, w.att)
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
	// Rooms the hotel no longer holds are gone; pool-labelled rooms the
	// manager does not hold are unverified.
	for hid := range ph.rooms {
		if h.rooms[hid] == nil {
			delete(ph.rooms, hid)
		}
	}
	for hid, rm := range h.rooms {
		if rm.guest == poolGuestID && rm.state == stRunning && ph.rooms[hid] == nil {
			ph.rooms[hid] = &poolRoom{hid: hid, state: poolUnverified, why: "not made or proven by this process"}
		}
	}
	w := &poolWork{}
	w.att, w.attOK = b.poolAttestLocked(h, ph, now)
	if w.attOK {
		for _, pr := range sortedPoolRooms(ph) {
			if pr.state == poolUnverified && !now.Before(pr.retryAt) && len(w.reads) < poolReadsPerStep {
				w.reads = append(w.reads, pr.hid)
			}
		}
	}
	ready := map[string][]*poolRoom{}
	for _, pr := range sortedPoolRooms(ph) {
		if pr.state == poolReady {
			ready[pr.key] = append(ready[pr.key], pr)
		}
	}
	if h.ok {
		for _, pr := range sortedPoolRooms(ph) {
			if pr.state == poolStale && pr.proven && !now.Before(pr.retryAt) {
				w.deletes = append(w.deletes, pr.hid)
			}
		}
	}
	if b.poolCreateRefusalLocked(h, ph, now) != "" || now.Before(ph.nextCreate) {
		return w
	}
	c := p.countsLocked(h.cfg.ID)
	if c.held >= p.boundLocked() {
		return w
	}
	for i := range p.keys {
		k := &p.keys[i]
		if ph.creating[k.name]+len(ready[k.name]) < p.settings.target(k.name) && b.diskFits(h, k.diskGiB) {
			w.create = k
			break
		}
	}
	return w
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
	due := admissionOff(h) && h.cfg.Sealed && loopbackURL(h.cfg.API) && loopbackURL(h.cfg.Health) && h.ok &&
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
		// The front's chain is another than the attested one: read again
		// later. Until then the room stays set aside.
		pr.tries++
		pr.retryAt = now.Add(poolRetry(pr.tries))
		pr.why = "receipts read: " + verr.Error()
		return
	case verr != nil:
		pr.state, pr.why = poolQuarantined, "receipts read: "+verr.Error()
	case k == nil:
		pr.state, pr.why = poolQuarantined, "receipts read: its image is not a ready_rooms key"
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
	ok := pr != nil && pr.state == poolStale && pr.proven
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
	if why := b.poolCreateRefusalLocked(h, ph, time.Now()); why != "" {
		b.mu.Unlock()
		<-h.sem
		return
	}
	rm := &room{h: h, guest: poolGuestID, state: stCreating, since: time.Now(), diskGiB: k.diskGiB}
	h.creating++
	h.holdDisk(pl, 1)
	h.place(rm)
	ph.creating[k.name]++
	b.mu.Unlock()

	status, hdr, out, err := h.doHeaders(context.WithoutCancel(ctx), h.cfg.API, "POST", "/v1/sandboxes", nil, body, poolCreateTimeout, nil)
	<-h.sem
	tDone := time.Now()

	b.mu.Lock()
	h.creating--
	h.holdDisk(pl, -1)
	ph.creating[k.name]--
	ph.nextCreate = time.Now().Add(poolCreateEvery) // from the answer: never 2 creates in one second
	var doc map[string]any
	if err == nil {
		_ = json.Unmarshal(out, &doc)
	}
	hid, _ := doc["id"].(string)
	if err != nil || (status != 200 && status != 201 && status != 202) || hid == "" {
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
	case derr == nil:
		pr.state, pr.why = poolStale, "its receipt 1 names image "+strconv.Quote(image)
	default:
		pr.state, pr.why = poolStale, "no verified pool receipt: "+derr.Error()
	}
	ph.rooms[hid] = pr
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
