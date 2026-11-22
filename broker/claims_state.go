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
