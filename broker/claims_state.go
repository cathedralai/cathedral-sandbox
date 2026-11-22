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
	"encoding/json"
	"log"
	"strings"
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
