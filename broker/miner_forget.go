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
// has been down for minerForgetDownFor, then leaves.
//
// It is one recoverable step, in this order:
//  1. Check and mark the hotel leaving, so nothing is placed on it.
//  2. Ask the old guest once more on its pinned key. Any answer, whatever
//     its status, means it is alive: refuse, and start the down interval
//     again. A room call it answered since it went down refuses too.
//  3. Write the rooms' tombstones to disk (client-state.json), so their
//     clients read "deleted" even after a restart.
//  4. Remove the hotel from hotels.json, as a plain leave does.
//  5. Only then release the rooms from memory.
// A failed write at 3 or 4 undoes what came before and answers 500, with
// every room and client id still in place.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
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
	case time.Unix(0, h.lastAnswer.Load()).After(h.downSince):
		return errors.New("the hotel answered a room call since it went down; its rooms are not lost")
	case now.Sub(h.downSince) < minerForgetDownFor:
		return fmt.Errorf("the hotel has been down %s; wait until %s", now.Sub(h.downSince).Round(time.Second), minerForgetDownFor)
	case h.creating+h.queued > 0:
		return errors.New("a create is still in flight on the hotel")
	}
	return nil
}

// forgetAndLeave runs steps 1 to 5 above. The caller holds hotelsMutationMu.
func (b *broker) forgetAndLeave(w http.ResponseWriter, h *hotel, id string) {
	// 1. Check and mark, in one step under b.mu.
	b.mu.Lock()
	if h.leaving {
		b.mu.Unlock()
		writeErr(w, 404, "hotel_not_found", "hotel "+id+" is leaving")
		return
	}
	if err := b.forgetRefusal(h, time.Now()); err != nil {
		b.mu.Unlock()
		writeErr(w, 409, "forget_refused", err.Error())
		return
	}
	h.leaving = true
	gone := map[string]string{} // client id -> broker room id
	for _, rm := range h.rooms {
		if rm.uuid != "" {
			gone[rm.uuid] = rm.id
		}
	}
	b.mu.Unlock()
	stillHere := func() {
		b.mu.Lock()
		h.leaving = false
		b.mu.Unlock()
	}

	// 2. Any answer on the attested key is the old guest, alive: the pinned
	// TLS handshake proves who answered, whatever the HTTP status.
	if h.answersOnPin() {
		b.mu.Lock()
		h.leaving, h.downSince = false, time.Now()
		b.mu.Unlock()
		writeErr(w, 409, "forget_refused", "the hotel answers on its attested key; its rooms are not lost")
		return
	}

	// 3. Tombstones on disk before anything is removed.
	b.setTombs(gone, true)
	if err := b.saveCompat(); err != nil {
		log.Printf("hotel %s: forget refused, client state not saved: %v", id, err)
		b.setTombs(gone, false)
		stillHere()
		writeErr(w, 500, "state_write_failed", "cannot keep the forgotten rooms' tombstones")
		return
	}

	// 4. The hotel leaves hotels.json, as in a plain leave.
	if !b.dropHotelIf(id, h) {
		b.undoTombs(id, gone)
		stillHere()
		writeErr(w, 409, "hotel_changed", "hotel changed during leave; retry")
		return
	}
	b.mu.Lock()
	err := b.saveRuntimeHotelsLocked()
	b.mu.Unlock()
	if err != nil {
		log.Printf("hotel %s: forget refused, runtime hotels not saved: %v", id, err)
		if addErr := b.addHotelRestored(h); addErr != nil {
			log.Printf("runtime hotel %s could not be restored after failed save: %v", id, addErr)
		}
		b.undoTombs(id, gone)
		stillHere()
		writeErr(w, 500, "state_write_failed", "cannot keep the runtime hotel removal")
		return
	}

	// 5. Now the rooms go from memory, with every reference to them.
	b.mu.Lock()
	n := 0
	for _, rm := range h.rooms {
		rm.state, rm.since = stFailed, time.Now()
		delete(b.savedUUIDs, rm.id)
		b.release(h, rm)
		n++
	}
	for _, byHotel := range b.guestRooms {
		delete(byHotel, id)
	}
	b.mu.Unlock()
	b.compat.mu.Lock()
	for eid, ex := range b.compat.execs { // results of a forgotten room have no reader
		if _, forgotten := gone[ex.room]; forgotten {
			delete(b.compat.execs, eid)
		}
	}
	b.compat.mu.Unlock()
	b.markDirty()
	if err := b.saveCompat(); err != nil {
		log.Printf("hotel %s: client state after forget not saved yet (tombstones are): %v", id, err)
	}
	if h.stop != nil {
		h.stop()
	}
	_ = os.Remove(h.cfg.KeyFile)
	log.Printf("hotel %s: the operator forgot %d rooms of a dead miner guest and the hotel left", id, n)
	w.WriteHeader(204)
}

// answersOnPin reports whether anything answers h's health URL on h's pinned
// connections. A refused handshake (another key, or no guest) is no answer.
func (h *hotel) answersOnPin() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", h.cfg.Health+"/room/health", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+h.key)
	resp, err := h.ctl.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}

// setTombs adds (on) or removes the deleted tombstones of gone.
func (b *broker) setTombs(gone map[string]string, on bool) {
	b.compat.mu.Lock()
	defer b.compat.mu.Unlock()
	for uuid, bid := range gone {
		if on {
			b.compat.tombs[uuid] = compatTomb{bid: bid, at: time.Now()}
		} else {
			delete(b.compat.tombs, uuid)
		}
	}
}

// undoTombs takes back tombstones already on disk after a later step failed.
func (b *broker) undoTombs(id string, gone map[string]string) {
	b.setTombs(gone, false)
	if err := b.saveCompat(); err != nil {
		b.markDirty() // the save loop retries; the rooms are still in memory
		log.Printf("hotel %s: tombstone rollback not saved yet: %v", id, err)
	}
}
