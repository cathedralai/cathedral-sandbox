package main

// Forgetting the rooms of a dead miner hotel (AB#212).
//
// A miner guest keeps its rooms in memory. When the guest dies or reboots,
// its pinned calls fail (miner_tls.go), no list releases its rooms, and a
// leave needs zero rooms, so the hotel could never leave and would keep its
// hotkey cap slot. The broker cannot decide alone that the rooms are gone: a
// new attested guest at the same origin does not prove the old one stopped,
// since a host can run both on one chip. So a person decides. With the
// operator key (never the enroll key), DELETE /v1/broker/hotels/<id>?
// forget_rooms=true forgets the rooms of a miner hotel that is drained and
// has been down for minerForgetDownFor, then leaves as usual. Each forgotten
// room is tombstoned, so its clients see "deleted" and not an unknown id.

import (
	"errors"
	"fmt"
	"log"
	"time"
)

const minerForgetDownFor = 10 * time.Minute

// forgetRefusal says why h's rooms may not be forgotten now, or nil.
// Caller holds b.mu.
func (b *broker) forgetRefusal(h *hotel, now time.Time) error {
	switch {
	case h.cfg.MinerHotkey == "":
		return errors.New("forget_rooms is only for miner hotels")
	case !h.drain():
		return errors.New("drain the hotel first")
	case h.ok || h.downSince.IsZero():
		return errors.New("the hotel answers; its rooms are not lost")
	case now.Sub(h.downSince) < minerForgetDownFor:
		return fmt.Errorf("the hotel has been down %s; wait until %s", now.Sub(h.downSince).Round(time.Second), minerForgetDownFor)
	}
	return nil
}

// forgetRooms releases every room of h and returns the client ids and broker
// ids to tombstone. Caller holds b.mu.
func (b *broker) forgetRooms(h *hotel) map[string]string {
	gone := map[string]string{}
	for _, rm := range h.rooms {
		if rm.uuid != "" {
			gone[rm.uuid] = rm.id
		}
		rm.state, rm.since = stFailed, time.Now()
		b.release(h, rm)
	}
	return gone
}

// tombstoneForgotten records forgotten rooms as deleted for their clients.
func (b *broker) tombstoneForgotten(hotelID string, gone map[string]string, n int) {
	b.compat.mu.Lock()
	for uuid, bid := range gone {
		b.compat.tombs[uuid] = compatTomb{bid: bid, at: time.Now()}
	}
	b.compat.mu.Unlock()
	b.markDirty()
	log.Printf("hotel %s: the operator forgot %d rooms of a dead miner guest", hotelID, n)
}
