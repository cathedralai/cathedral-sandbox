package main

// Room end records (AB#864).
//
// A room that leaves the broker for good leaves one record: when it went
// and, as well as the broker knows, why. Its guest reads it for endedKeep:
//   - a native call on the room answers 410 sandbox_gone with the record;
//   - a client (compat) GET answers 200 state "deleted" with end_reason;
//   - GET /v1/sandboxes/ended lists the guest's records, newest first;
//   - the live stream sends one "room_gone" event per new record.
// Another guest's id, or a wrong id, stays 404.
//
// Records are written only where a guest's room leaves for good: the sync
// loop's release of a room the hotel no longer lists, and the operator forget
// of a dead miner hotel (miner_forget.go). A refused or cancelled create
// (reapRoom) and a duplicate object never get one. A late list that shows
// the room again drops its record.
//
// Kept in client-state.json section "ended_rooms", at most endedMaxPerGuest
// per guest, oldest dropped first.

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	endedKeep = 24 * time.Hour
	// endedStreamLog: how long a record stays in the stream log. A live stream
	// reads it every second; a new one starts from the backlog window.
	endedStreamLog   = 5 * time.Minute
	endedMaxPerGuest = 50000
	endedListMax     = 1000
	endedListDefault = 100
	// The hotel reaps at expires_at plus a grace; a room gone at most this
	// long before its listed expiry ended by its TTL.
	endedTTLSlack = 10 * time.Second
	// A live stream that connects sees records this recent, no older backlog.
	endedStreamBacklog = 60 * time.Second

	endDeleted        = "deleted"
	endTTLExpired     = "ttl_expired"
	endHotelRestarted = "hotel_restarted"
	endHotelRemoved   = "hotel_removed"
	endUnknown        = "unknown"
)

// hotelEndReasons are the end_reason values a hotel may send (cathedral/
// sandbox_provider.py, AB#864 Change B). Anything else reads as unknown, so a
// hotel cannot put arbitrary text in a guest's answer.
var hotelEndReasons = map[string]bool{
	"deleted": true, "ttl_expired": true, "idle_timeout": true, "key_revoked": true,
	"oom_killed": true, "container_exited": true,
}

// containerDeathReasons are hotel reasons that say the room's container
// died. The removal that follows (TTL, idle, delete) is only cleanup.
var containerDeathReasons = map[string]bool{"oom_killed": true, "container_exited": true}

type endRecord struct {
	ID        string     `json:"id"` // broker room id <hotel>.<hotel room id>
	UUID      string     `json:"uuid,omitempty"`
	Guest     string     `json:"guest"`
	Hotel     string     `json:"hotel"`
	CreatedAt *time.Time `json:"created_at,omitempty"` // when the broker first had the room
	GoneAt    time.Time  `json:"gone_at"`
	Reason    string     `json:"reason"`
	Detail    string     `json:"detail,omitempty"`
	// Claim: a claimed room's customer labels and size, for the guest's
	// usage view after the room is gone (claims_state.go); nil otherwise.
	Claim   *endClaim `json:"claim,omitempty"`
	seq     uint64    // write order, for the live stream
	written time.Time // when the broker wrote it (streamLog trim)
}

// guestEnded is one guest's records. order is oldest first.
type guestEnded struct {
	byID   map[string]*endRecord
	byUUID map[string]*endRecord
	order  []*endRecord // by GoneAt: the list and prune
	// streamLog is the records in write (seq) order, for live streams only:
	// a stream reads what was written since its cursor, whatever the GoneAt
	// (review F3 on #637). Kept endedStreamLog long, at most endedMaxPerGuest.
	streamLog []*endRecord
}

func (r *endRecord) view() map[string]any {
	doc := map[string]any{"id": r.ID, "hotel": r.Hotel, "gone_at": r.GoneAt.UTC().Format(time.RFC3339Nano), "reason": r.Reason}
	if r.UUID != "" {
		doc["uuid"] = r.UUID
	}
	if r.CreatedAt != nil {
		doc["created_at"] = r.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	if r.Detail != "" {
		doc["detail"] = r.Detail
	}
	return doc
}

// addEnded keeps rec. Caller holds b.mu.
func (b *broker) addEnded(rec *endRecord) {
	if rec.Guest == "" {
		return
	}
	if b.ended == nil {
		b.ended = map[string]*guestEnded{}
	}
	ge := b.ended[rec.Guest]
	if ge == nil {
		ge = &guestEnded{byID: map[string]*endRecord{}, byUUID: map[string]*endRecord{}}
		b.ended[rec.Guest] = ge
	}
	if old := ge.byID[rec.ID]; old != nil {
		ge.drop(old)
	}
	b.endSeq++
	rec.seq = b.endSeq
	ge.byID[rec.ID] = rec
	if rec.UUID != "" {
		ge.byUUID[rec.UUID] = rec
	}
	// order stays sorted by GoneAt: the list, newest first, and prune rely on
	// it, and one sync tick can release rooms that vanished at different
	// times in any order (review F2 on #637).
	i := len(ge.order)
	for i > 0 && ge.order[i-1].GoneAt.After(rec.GoneAt) {
		i--
	}
	ge.order = slices.Insert(ge.order, i, rec)
	now := time.Now()
	rec.written = now
	ge.streamLog = append(ge.streamLog, rec)
	cut := 0
	for cut < len(ge.streamLog) && (now.Sub(ge.streamLog[cut].written) > endedStreamLog || len(ge.streamLog)-cut > endedMaxPerGuest) {
		cut++
	}
	if cut > 0 {
		clear(ge.streamLog[:cut])
		ge.streamLog = ge.streamLog[cut:]
	}
	ge.prune(now)
	b.markDirty()
}

func (ge *guestEnded) drop(rec *endRecord) {
	if ge.byID[rec.ID] == rec {
		delete(ge.byID, rec.ID)
	}
	if rec.UUID != "" && ge.byUUID[rec.UUID] == rec {
		delete(ge.byUUID, rec.UUID)
	}
	if i := slices.Index(ge.order, rec); i >= 0 {
		ge.order = slices.Delete(ge.order, i, i+1)
	}
	if i := slices.Index(ge.streamLog, rec); i >= 0 {
		ge.streamLog = slices.Delete(ge.streamLog, i, i+1)
	}
}

// prune drops records past endedKeep, then the oldest over the cap.
func (ge *guestEnded) prune(now time.Time) {
	cut := 0
	for cut < len(ge.order) && (now.Sub(ge.order[cut].GoneAt) > endedKeep || len(ge.order)-cut > endedMaxPerGuest) {
		rec := ge.order[cut]
		if ge.byID[rec.ID] == rec {
			delete(ge.byID, rec.ID)
		}
		if rec.UUID != "" && ge.byUUID[rec.UUID] == rec {
			delete(ge.byUUID, rec.UUID)
		}
		cut++
	}
	if cut > 0 {
		clear(ge.order[:cut]) // the backing array lets go of them
		ge.order = ge.order[cut:]
	}
}

// forgetEnded drops the record of bid: the room is back. Caller holds b.mu.
func (b *broker) forgetEnded(guest, bid string) {
	if ge := b.ended[guest]; ge != nil {
		if rec := ge.byID[bid]; rec != nil {
			ge.drop(rec)
			b.markDirty()
		}
	}
}

// endedRecord returns guest's live record for broker id bid, or nil.
func (b *broker) endedRecord(guest, bid string) *endRecord {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ge := b.ended[guest]; ge != nil {
		if rec := ge.byID[bid]; rec != nil && time.Since(rec.GoneAt) <= endedKeep {
			c := *rec
			return &c
		}
	}
	return nil
}

// endedByUUID is endedRecord by client id.
func (b *broker) endedByUUID(guest, uuid string) *endRecord {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ge := b.ended[guest]; ge != nil {
		if rec := ge.byUUID[uuid]; rec != nil && time.Since(rec.GoneAt) <= endedKeep {
			c := *rec
			return &c
		}
	}
	return nil
}

// writeGone answers 410 sandbox_gone when guest g has an end record for bid.
func (b *broker) writeGone(w http.ResponseWriter, g *guestState, bid string) bool {
	rec := b.endedRecord(g.cfg.ID, bid)
	if rec == nil {
		return false
	}
	writeJSON(w, 410, map[string]any{
		"error": map[string]string{"code": "sandbox_gone", "message": "sandbox " + bid + " is gone: " + rec.Reason},
		"sandbox": map[string]any{"id": bid, "state": "gone", "gone_at": rec.GoneAt.UTC().Format(time.RFC3339Nano),
			"reason": rec.Reason, "hotel": rec.Hotel},
	})
	return true
}

// handleEnded serves GET /v1/sandboxes/ended?since=&limit=: the guest's
// records gone at or after since, newest first.
func (b *broker) handleEnded(w http.ResponseWriter, r *http.Request, g *guestState) {
	q := r.URL.Query()
	var since time.Time
	if s := q.Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeErr(w, 400, "invalid_since", "since must be an RFC 3339 time")
			return
		}
		since = t
	}
	limit := endedListDefault
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > endedListMax {
			writeErr(w, 400, "invalid_limit", "limit must be 1 to "+strconv.Itoa(endedListMax))
			return
		}
		limit = n
	}
	out := []map[string]any{}
	b.mu.Lock()
	if ge := b.ended[g.cfg.ID]; ge != nil {
		ge.prune(time.Now())
		for i := len(ge.order) - 1; i >= 0 && len(out) < limit; i-- {
			if rec := ge.order[i]; !rec.GoneAt.Before(since) {
				out = append(out, rec.view())
			}
		}
	}
	b.mu.Unlock()
	writeJSON(w, 200, map[string]any{"ended": out, "count": len(out)})
}

// endedSince returns guest's records written after seq, oldest first, and
// the newest seq. Caller does not hold b.mu.
func (b *broker) endedSince(guest string, seq uint64) ([]map[string]any, uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	last := b.endSeq
	ge := b.ended[guest]
	if ge == nil {
		return nil, last
	}
	i := len(ge.streamLog)
	for i > 0 && ge.streamLog[i-1].seq > seq {
		i--
	}
	var out []map[string]any
	for _, rec := range ge.streamLog[i:] {
		out = append(out, rec.view())
	}
	return out, last
}

// endedStreamStart is the seq a new live stream starts after: records older
// than endedStreamBacklog are not sent.
func (b *broker) endedStreamStart(guest string, now time.Time) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	ge := b.ended[guest]
	if ge == nil {
		return b.endSeq
	}
	// The lowest seq among records gone in the backlog window: a batch can
	// write a newer room before an older one (review F3 on #637).
	start := b.endSeq
	for _, rec := range ge.streamLog {
		if now.Sub(rec.GoneAt) <= endedStreamBacklog && rec.seq-1 < start {
			start = rec.seq - 1
		}
	}
	return start
}

// endOfVanished records a room the hotel no longer lists, as the sync loop
// releases it. Caller holds b.mu.
func (b *broker) endOfVanished(h *hotel, rm *room, now time.Time) {
	if rm.guest == "" || rm.reaped {
		return
	}
	gone := now
	if !rm.vanished.IsZero() {
		gone = rm.vanished
	}
	reason, detail := endUnknown, ""
	switch {
	case containerDeathReasons[rm.hotelDeath]:
		reason = rm.hotelDeath
		if rm.hotelEnd != "" && rm.hotelEnd != rm.hotelDeath {
			detail = rm.hotelEnd
		}
	case rm.hotelEnd != "":
		reason = rm.hotelEnd
	case rm.deleteSent || b.bulkDeleted(rm):
		reason = endDeleted
	case b.minerExitLost(h, rm):
		reason = endHotelRemoved
	case !rm.expiresAt.IsZero() && !gone.Before(rm.expiresAt.Add(-endedTTLSlack)):
		reason = endTTLExpired
	case rm.hotelRestarted:
		reason = endHotelRestarted
	}
	b.addEnded(b.newEndRecord(h, rm, gone, reason, detail))
}

func (b *broker) newEndRecord(h *hotel, rm *room, gone time.Time, reason, detail string) *endRecord {
	rec := &endRecord{ID: rm.id, UUID: rm.uuid, Guest: rm.guest, Hotel: h.cfg.ID, GoneAt: gone.UTC(), Reason: reason, Detail: detail}
	if !rm.born.IsZero() {
		t := rm.born.UTC()
		rec.CreatedAt = &t
	}
	if m := rm.mapping; m != nil {
		rec.Claim = &endClaim{Labels: m.customerLabels, VCPU: m.vcpu, MemoryGiB: m.memGiB}
	}
	return rec
}

// bulkDeleted reports whether a delete by label of rm's guest, made while the
// room existed, matches its listed labels. Caller holds b.mu.
func (b *broker) bulkDeleted(rm *room) bool {
	labels := rm.viewLabels() // a claimed room: the labels its customer created it with
	if labels == nil {
		return false
	}
	for _, t := range b.tombs[rm.guest] {
		if time.Since(t.at) >= tombstoneTTL || (!rm.born.IsZero() && t.at.Before(rm.born)) {
			continue
		}
		match := true
		for k, v := range t.want {
			if got, ok := labels[k]; !ok || got != v {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// minerExitLost reports whether a miner exit record of h marks rm lost: the
// miner hotel went down and came back without it. Caller holds b.mu.
func (b *broker) minerExitLost(h *hotel, rm *room) bool {
	for _, e := range b.minerExits {
		if e.Hotel != h.cfg.ID {
			continue
		}
		for _, er := range e.Rooms {
			if er.ID == rm.id && er.Lost != nil && *er.Lost {
				return true
			}
		}
	}
	return false
}

// noteListed keeps what a hotel list says about rm for its end record.
// Caller holds b.mu.
func (rm *room) noteListed(labels map[string]string, expiresAt, endReason string) {
	rm.labels = labels
	if expiresAt != rm.expiresRaw {
		rm.expiresRaw = expiresAt
		rm.expiresAt = time.Time{}
		if t, err := time.Parse(time.RFC3339, expiresAt); err == nil {
			rm.expiresAt = t
		}
	}
	if containerDeathReasons[endReason] {
		rm.hotelDeath = endReason
	}
}

// endedSnapshot is every record, oldest first per guest. Caller holds b.mu.
func (b *broker) endedSnapshot(now time.Time) []endRecord {
	var out []endRecord
	for _, ge := range b.ended {
		ge.prune(now)
		for _, rec := range ge.order {
			out = append(out, *rec)
		}
	}
	return out
}

// restoreEnded reads saved records. Caller holds b.mu.
func (b *broker) restoreEnded(list []endRecord, now time.Time) {
	slices.SortStableFunc(list, func(x, y endRecord) int { return x.GoneAt.Compare(y.GoneAt) })
	b.ended = map[string]*guestEnded{}
	for i := range list {
		rec := list[i]
		if rec.Guest == "" || rec.ID == "" || !strings.Contains(rec.ID, ".") || now.Sub(rec.GoneAt) > endedKeep {
			continue
		}
		ge := b.ended[rec.Guest]
		if ge == nil {
			ge = &guestEnded{byID: map[string]*endRecord{}, byUUID: map[string]*endRecord{}}
			b.ended[rec.Guest] = ge
		}
		if old := ge.byID[rec.ID]; old != nil {
			ge.drop(old)
		}
		b.endSeq++
		rec.seq = b.endSeq
		ge.byID[rec.ID] = &rec
		if rec.UUID != "" {
			ge.byUUID[rec.UUID] = &rec
		}
		ge.order = append(ge.order, &rec)
	}
	for _, ge := range b.ended {
		ge.prune(now)
	}
}
