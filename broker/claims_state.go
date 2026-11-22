package main

// Claimed rooms: one mapping from the physical room to the customer's run
// (AB#894 phase 2 PR 4; design 8.1).
//
// A ready room is made by the pool guest and keeps that guest's hotel labels
// for its whole life: a claim changes only its lifetime at the hotel (design
// 5). Once a claim wins it, the broker's record is the customer's: rm.guest,
// the client id and the run are the customer's, and every path that finds
// rooms by their hotel labels or meters them by their physical id goes
// through the mapping. rm.id stays the physical <hotel>.<hotel room id>,
// because every hotel call needs it. A room with no mapping (every room until
// a person turns claims on) takes exactly the path it took before.

import (
	"context"
	"encoding/json"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"
)

// roomMapping is a claimed room's customer run. It is set once, under b.mu,
// and never changed in place: a later change replaces the pointer.
type roomMapping struct {
	run            string            // the run id: the winning attempt's id (newUUID, no ".")
	customerLabels map[string]string // the create's labels as the customer sent them
	wonAt          time.Time         // the win: the room's customer-facing creation time
	vcpu, memGiB   int64             // the run's size, from the claim
}

// runID is the run the usage meter records rm under: a claimed room's
// customer run, else its physical id, as before.
func (rm *room) runID() string {
	if rm.mapping != nil {
		return rm.mapping.run
	}
	return rm.id
}

// viewLabels is the labels rm shows its guest and is matched against label
// filters by: a claimed room's customer labels, else the hotel's.
func (rm *room) viewLabels() map[string]string {
	if rm.mapping != nil {
		return rm.mapping.customerLabels
	}
	return rm.labels
}

// labelsMatch reports whether labels hold every filter as the hotel reads
// them (cathedral/sandbox_provider.py _parse_label_filters): "k=v" wants k
// with the value v, a bare "k" wants k with the empty value.
func labelsMatch(labels map[string]string, filters []string) bool {
	for _, f := range filters {
		k, v, _ := strings.Cut(f, "=")
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// mapRoomLocked makes rm, a pool room on h, guest's room under m: the
// customer's guest, client id (the run id), creation time (the win) and run,
// recorded under the customer for receipts and attestation after the room
// leaves the room map, and out of the pool's records. The win (PR 6) and the
// restart (replayClaims) both come here. Caller holds b.mu.
func (b *broker) mapRoomLocked(h *hotel, rm *room, guest string, m roomMapping) {
	if rm.uuid != "" && b.byUUID[rm.uuid] == rm {
		delete(b.byUUID, rm.uuid)
	}
	labels := make(map[string]string, len(m.customerLabels))
	for k, v := range m.customerLabels {
		labels[k] = v
	}
	m.customerLabels = labels
	rm.guest, rm.uuid, rm.born, rm.mapping = guest, m.run, m.wonAt, &m
	delete(b.savedUUIDs, rm.id) // the journal's client id wins over client-state.json
	b.byUUID[rm.uuid] = rm
	b.markDirty()
	b.rememberGuestRoom(guest, h.cfg.ID, rm.hid)
	if b.pool != nil {
		delete(b.pool.hotel(h.cfg.ID).rooms, rm.hid)
	}
}

// claimMapping is one mapping the journal holds: a claimed room's customer
// and run, under the broker room id named in its won record.
type claimMapping struct {
	bid, guest string
	m          roomMapping
}

// claimWon is the part of a won record (design 2.1) a mapping needs. PR 5
// writes the whole record under these names.
type claimWon struct {
	Guest  string `json:"guest"`
	Winner struct {
		AttemptID string `json:"attempt_id"`
		Room      string `json:"room"` // broker room id, <hotel>.<hotel room id>
	} `json:"winner"`
	Run struct {
		RunID     string `json:"run_id"`     // the winner's attempt id
		StartedAt int64  `json:"started_at"` // the win, broker clock, ms
		VCPU      int64  `json:"vcpu"`
		MemoryGiB int64  `json:"memory_gib"`
	} `json:"run"`
	CustomerLabels map[string]string `json:"customer_labels"`
}

// replayClaims reads the journal once, after a complete open and before any
// sync (it runs inside loadBroker), and keeps the mapping of every won whose
// run has no later cancel or removed. A won that does not parse, or two runs
// naming one room, maps nothing: such a room stays the pool's and its rules
// set it aside (never billed, never handed out, never deleted). PR 5 extends
// this pass with the rest of the claim state; the journal replays only once.
func (p *readyRooms) replayClaims() {
	p.replayed = true
	if p.journal == nil {
		return
	}
	byRun := map[string]claimMapping{}
	err := p.journal.replay(func(r claimRecord) error {
		switch r.Kind {
		case "won":
			var w claimWon
			if json.Unmarshal(r.Body, &w) != nil || w.Guest == "" || w.Guest == poolGuestID || !usageClaimRun(w.Run.RunID) ||
				w.Winner.AttemptID != w.Run.RunID || !strings.Contains(w.Winner.Room, ".") || w.Run.StartedAt <= 0 {
				log.Printf("ready rooms: claim journal record %d: a won with no usable mapping; its room is not mapped", r.Seq)
				return nil
			}
			byRun[w.Run.RunID] = claimMapping{bid: w.Winner.Room, guest: w.Guest, m: roomMapping{run: w.Run.RunID,
				customerLabels: w.CustomerLabels, wonAt: time.UnixMilli(w.Run.StartedAt), vcpu: w.Run.VCPU, memGiB: w.Run.MemoryGiB}}
		case "cancel", "removed":
			var x struct {
				RunID     string `json:"run_id"`
				AttemptID string `json:"attempt_id"`
			}
			if json.Unmarshal(r.Body, &x) == nil {
				delete(byRun, x.RunID)
				delete(byRun, x.AttemptID)
			}
		}
		return nil
	})
	if err != nil {
		log.Printf("ready rooms: claim journal replay: %v; no room is mapped", err)
		return
	}
	p.mappings = map[string]claimMapping{}
	twice := map[string]bool{}
	for _, cm := range byRun {
		if _, ok := p.mappings[cm.bid]; ok {
			twice[cm.bid] = true
		}
		p.mappings[cm.bid] = cm
	}
	for bid := range twice {
		delete(p.mappings, bid)
		log.Printf("ready rooms: room %s is named by two claim runs; it is not mapped", bid)
	}
}

// adoptMappedLocked maps a pool-labelled room the sync adopts after a
// restart to the customer its journal mapping names (design 2.6 step 3). It
// maps only while the usage meter holds that run open: for a run with an
// ended reading the meter writes nothing more (usageMeter.seenLocked), and
// one it does not know would start a second record of a run already
// answered, so either way the room stays the pool's, set aside by its rules,
// and is never handed back. It reports whether it mapped rm. Caller holds
// b.mu.
func (b *broker) adoptMappedLocked(h *hotel, rm *room) bool {
	p := b.pool
	if p == nil || rm.guest != poolGuestID {
		return false
	}
	cm, ok := p.mappings[rm.id]
	if !ok {
		return false
	}
	delete(p.mappings, rm.id) // decided once
	if b.guests[cm.guest] == nil || !b.usageMeter.runOpen(cm.m.run) {
		log.Printf("ready rooms: room %s: its claim run %s is not open in the usage meter (or guest %s is gone); the room stays set aside", rm.id, cm.m.run, cm.guest)
		return false
	}
	b.mapRoomLocked(h, rm, cm.guest, cm.m)
	return true
}

// usageClaimRun reports whether run is a claim run's id rather than a room's
// physical id. A claim run is the winning attempt's id, made by newUUID: 32
// hex digits and four hyphens, never a ".". Every other run the meter knows
// is a broker room id, <hotel>.<hotel room id> (usageSightingOf), which
// always has one. TestUsageClaimRunShapes pins both shapes.
func usageClaimRun(run string) bool {
	return run != "" && !strings.Contains(run, ".")
}

// endClaim is what an end record keeps of a claimed room for the guest's
// usage view once the room is gone.
type endClaim struct {
	Labels    map[string]string `json:"labels"`
	VCPU      int64             `json:"vcpu"`
	MemoryGiB int64             `json:"memory_gib"`
}

// claimedView puts a claimed room's customer labels and win time into its
// hotel document (the hotel keeps the pool's labels and the pool room's
// creation time). A room with no mapping is left as it is. The caller does
// not hold b.mu.
func (b *broker) claimedView(doc map[string]any, rm *room) {
	b.mu.Lock()
	m := rm.mapping
	b.mu.Unlock()
	if m == nil {
		return
	}
	labels := make(map[string]any, len(m.customerLabels))
	for k, v := range m.customerLabels {
		labels[k] = v
	}
	doc["labels"] = labels
	doc["created_at"] = m.wonAt.UTC().Format(time.RFC3339Nano)
}

// customerFilters is a guest's label filters without the broker's own guest
// label filter, which every room of the guest meets by definition (a claimed
// room's customer labels do not carry it).
func customerFilters(g *guestState, q url.Values) []string {
	var out []string
	for _, f := range q["label"] {
		if f != guestLabel+"="+g.cfg.ID {
			out = append(out, f)
		}
	}
	return out
}

// claimedRoomDocs is g's claimed rooms as their hotels document them, by
// hotel id (ids are the hotel's), with the customer's labels and the win
// time put in (claimedView): one pool-guest label list per hotel that holds
// such a room, kept to g's claimed rooms whose customer labels hold every
// label filter of q; q's other fields pass to the hotel. Nothing is asked
// when g has no claimed room, so a guest without one sees exactly today's
// answers. errs: hotels whose list failed. The caller does not hold b.mu.
func (b *broker) claimedRoomDocs(ctx context.Context, g *guestState, q url.Values) (map[string][]map[string]any, map[string]string) {
	filters := customerFilters(g, q)
	want := map[*hotel]map[string]*room{}
	b.mu.Lock()
	for _, h := range b.hotelList() {
		for hid, rm := range h.rooms {
			if rm.mapping != nil && rm.guest == g.cfg.ID && labelsMatch(rm.mapping.customerLabels, filters) {
				if want[h] == nil {
					want[h] = map[string]*room{}
				}
				want[h][hid] = rm
			}
		}
	}
	b.mu.Unlock()
	if len(want) == 0 {
		return nil, nil
	}
	pq := url.Values{}
	for k, v := range q {
		if k != "label" {
			pq[k] = v
		}
	}
	pq.Set("label", guestLabel+"="+poolGuestID)
	out := map[string][]map[string]any{}
	errs := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for h, rooms := range want {
		if !g.limitsAllow(b, h.cfg.ID) {
			continue
		}
		wg.Add(1)
		go func(h *hotel, rooms map[string]*room) {
			defer wg.Done()
			status, _, body, err := h.do(ctx, "GET", "/v1/sandboxes", pq, nil, 30*time.Second)
			var doc struct {
				Sandboxes []map[string]any `json:"sandboxes"`
			}
			if err != nil || status != 200 || json.Unmarshal(body, &doc) != nil {
				mu.Lock()
				errs[h.cfg.ID] = "unavailable"
				mu.Unlock()
				return
			}
			var list []map[string]any
			for _, s := range doc.Sandboxes {
				id, _ := s["id"].(string)
				if rm := rooms[id]; rm != nil {
					b.claimedView(s, rm)
					list = append(list, s)
				}
			}
			mu.Lock()
			out[h.cfg.ID] = list
			mu.Unlock()
		}(h, rooms)
	}
	wg.Wait()
	return out, errs
}

// addClaimedUsage adds g's claimed rooms to its usage parts, by hotel. The
// hotel counts a room's hours from its own creation, which for a claimed room
// is the pool room's, so the broker counts these from the win: a room still
// in the room map up to now (or to when it was marked gone), an ended one
// from its end record while that record is kept. It is a view, not the bill:
// the usage meter is the bill. Groups follow the hotel's rule: group_by
// label.<key> (default label.job), "unlabelled" without that label. A part
// that is an error is left as it is. The caller does not hold b.mu.
func (b *broker) addClaimedUsage(parts map[string]any, g *guestState, q url.Values) {
	key := "job"
	if gb := q.Get("group_by"); gb != "" {
		if _, k, ok := strings.Cut(gb, "label."); ok {
			key = k
		} else {
			key = gb
		}
	}
	filters := customerFilters(g, q)
	type use struct {
		hotel        string
		labels       map[string]string
		vcpu, memGiB int64
		seconds      float64
	}
	var uses []use
	now := time.Now()
	live := map[string]bool{}
	b.mu.Lock()
	for _, h := range b.hotelList() {
		for _, rm := range h.rooms {
			m := rm.mapping
			if m == nil || rm.guest != g.cfg.ID {
				continue
			}
			end := now
			if !rm.vanished.IsZero() {
				end = rm.vanished
			}
			live[rm.uuid] = true
			uses = append(uses, use{h.cfg.ID, m.customerLabels, m.vcpu, m.memGiB, end.Sub(m.wonAt).Seconds()})
		}
	}
	if ge := b.ended[g.cfg.ID]; ge != nil {
		for _, rec := range ge.order {
			if rec.Claim != nil && rec.CreatedAt != nil && !live[rec.UUID] {
				uses = append(uses, use{rec.Hotel, rec.Claim.Labels, rec.Claim.VCPU, rec.Claim.MemoryGiB, rec.GoneAt.Sub(*rec.CreatedAt).Seconds()})
			}
		}
	}
	b.mu.Unlock()
	for _, u := range uses {
		part, _ := parts[u.hotel].(map[string]any)
		groups, _ := part["groups"].(map[string]any)
		if groups == nil || !labelsMatch(u.labels, filters) {
			continue
		}
		name := u.labels[key]
		if name == "" {
			name = "unlabelled"
		}
		gr, _ := groups[name].(map[string]any)
		if gr == nil {
			gr = map[string]any{}
			groups[name] = gr
		}
		hours := max(u.seconds, 0) / 3600
		for k, add := range map[string]float64{"sandbox_hours": hours, "vcpu_hours": hours * float64(u.vcpu), "gib_hours": hours * float64(u.memGiB)} {
			v, _ := gr[k].(float64)
			gr[k] = v + add
		}
	}
}

// deleteClaimedRooms deletes, one by one, g's claimed rooms whose customer
// labels hold every filter: a bulk delete by label (handleBulkDelete) never
// reaches them at the hotel, where they carry the pool's labels. Each goes
// through the single delete's rule (roomDeleteAnswered); PR 7 makes it a
// revoke. rooms: each one's hotel status, 502 when the hotel did not answer;
// stillRun: how many were not confirmed deleted and so still run and bill.
// The caller does not hold b.mu.
func (b *broker) deleteClaimedRooms(ctx context.Context, g *guestState, filters []string) (rooms map[string]int, stillRun int) {
	var targets []*room
	b.mu.Lock()
	for _, h := range b.hotelList() {
		for _, rm := range h.rooms {
			if rm.mapping != nil && rm.guest == g.cfg.ID && rm.state == stRunning && labelsMatch(rm.mapping.customerLabels, filters) {
				targets = append(targets, rm)
			}
		}
	}
	b.mu.Unlock()
	if len(targets) == 0 {
		return nil, 0
	}
	rooms = map[string]int{}
	for _, rm := range targets {
		// As the single delete: a delete that gave up would leave the room
		// running on a full hotel, so it waits for a connection.
		status, _, _, err := rm.h.do(waitForConnUntilDeadline(ctx), "DELETE", "/v1/sandboxes/"+url.PathEscape(rm.hid), nil, nil, 2*time.Minute)
		if err != nil {
			status = 502
		}
		if status == 204 || status == 404 {
			b.roomDeleteAnswered(rm, status)
		} else {
			stillRun++
		}
		rooms[rm.id] = status
	}
	return rooms, stillRun
}

// mapLateLocked maps, in place, the claimed rooms the syncs adopted as the
// pool's while the claim journal could not be read (the late open): each
// pool-labelled room in a room map that the replay names, under the same rule
// as an adoption (adoptMappedLocked: only while the meter holds its run open;
// a run held by the meter during the gap, usageMeter.holdClaimRuns, is still
// open). Rooms not adopted yet are mapped when they are. Caller holds b.mu.
func (b *broker) mapLateLocked() {
	for _, h := range b.hotelList() {
		for _, rm := range h.rooms {
			if rm.guest == poolGuestID {
				b.adoptMappedLocked(h, rm)
			}
		}
	}
}
