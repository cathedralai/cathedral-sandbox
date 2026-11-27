// Reservations survive a restart and carry a fencing generation (AB#982).
//
// A hotel's reserved_for (capacity.go) is now also a self-serve dedicated
// box: the API reserves a hotel for a customer's guest and names its order
// in reservation_ref. Two orders racing for the last box, or a retry whose
// first reply was lost, must end in one allocation. So every hotel has a
// reservation_generation that every change of reserved_for (or of
// reservation_ref) bumps, and a PATCH may send expect_generation: when it is
// not the current generation the PATCH is refused (409
// reservation_conflict) and nothing changes. The compare runs under the
// locks the PATCH already holds, so of two PATCHes with the same
// expect_generation exactly one wins.
//
// A joined hotel keeps reserved_for, the generation and the ref in
// state_dir/hotels.json. A config file hotel's PATCHed reserved_for used to
// live in memory only, so a restart gave a reserved box back to the file's
// value. Now it is kept in state_dir/hotel-reservations.json with the file's
// own reserved_for at the time (config_reserved_for), like drains.go: at
// start, and when a reload adds the hotel, a saved reservation applies only
// while the file still says config_reserved_for. Once someone changed the
// file, the file wins: the saved reserved_for and ref are dropped and the
// generation goes on from the saved one plus one, so it never goes back and
// an old expect_generation cannot match again.
//
// The file is written with fsync on the file and its directory before the
// PATCH answers 200 (writeFileDurable, drains.go). A lend state
// (hotel-lends.json, lend.go) still wins over reserved_for at load.
//
// A record also keeps a custom guest hold (custom_guest_hold.go). A record
// with a hold is never dropped for a changed file: it is kept whole, with an
// OPS alert, and its config_reserved_for stays the baseline, so the first
// start after the hold is cleared finds the file changed and applies it.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const reservationsFile = "hotel-reservations.json"

// maxReservationRef bounds reservation_ref: an order id, not a document.
const maxReservationRef = 256

// reservationRecord is one config file hotel's PATCHed reservation.
type reservationRecord struct {
	ReservedFor       string `json:"reserved_for"`
	Ref               string `json:"reservation_ref"`
	Generation        uint64 `json:"reservation_generation"`
	ConfigReservedFor string `json:"config_reserved_for"` // the file's reserved_for when the PATCH came
	PinOnly           bool   `json:"pin_only,omitempty"`
	// CustomGuestHold: the hold, kept so a restart or a swap keeps placement
	// off and the secret skip (custom_guest_hold.go).
	CustomGuestHold *customGuestHold `json:"custom_guest_hold,omitempty"`
}

func sameReservationRecord(a, b reservationRecord) bool {
	ah, bh := a.CustomGuestHold, b.CustomGuestHold
	a.CustomGuestHold, b.CustomGuestHold = nil, nil
	return a == b && sameHold(ah, bh)
}

// reservation is h's reservation_generation and reservation_ref.
func (h *hotel) reservation() (uint64, string) {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.cfg.ReservationGeneration, h.cfg.ReservationRef
}

// setReservation reserves h for owner ("": the pool) under ref, and bumps
// the generation when either changes. Caller holds h.cfgMu (write).
func setReservation(h *hotel, owner, ref string) {
	if h.cfg.ReservedFor != owner || h.cfg.ReservationRef != ref {
		h.cfg.ReservationGeneration++
	}
	if h.cfg.ReservedFor != owner {
		h.cfg.PinOnly = false // a new owner never inherits pin_only (pin_only.go)
	}
	h.cfg.ReservedFor, h.cfg.ReservationRef = owner, ref
}

// noteConfigReservationLocked records h's reservation after it changed and
// reports whether the record changed. The record stays even when h is back
// to the file's value: it keeps the generation. Caller holds b.mu.
func (b *broker) noteConfigReservationLocked(h *hotel) bool {
	if b.reservations == nil {
		b.reservations = map[string]reservationRecord{}
	}
	h.cfgMu.RLock()
	r := reservationRecord{ReservedFor: h.cfg.ReservedFor, Ref: h.cfg.ReservationRef, Generation: h.cfg.ReservationGeneration, ConfigReservedFor: h.fileReservedFor, PinOnly: h.cfg.PinOnly,
		CustomGuestHold: h.cfg.CustomGuestHold}
	h.cfgMu.RUnlock()
	old, ok := b.reservations[h.cfg.ID]
	if (ok && sameReservationRecord(old, r)) || (!ok && r.Generation == 0 && r.CustomGuestHold == nil) {
		return false // nothing new; a hotel never changed needs no record
	}
	b.reservations[h.cfg.ID] = r
	return true
}

// saveConfigReservationsLocked writes state_dir/hotel-reservations.json.
// Caller holds b.mu and hotelsMutationMu.
func (b *broker) saveConfigReservationsLocked() error {
	if b.cfg.StateDir == "" {
		return errors.New("no state_dir")
	}
	out := map[string]reservationRecord{}
	for id, r := range b.reservations {
		out[id] = r
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return err
	}
	return writeFileDurable(filepath.Join(b.cfg.StateDir, reservationsFile), raw)
}

// applySavedReservationLocked applies the saved record to the config file
// hotel h, whose cfg holds the file's values, and reports whether the record
// changed (the file won). Caller holds b.mu, or runs before h serves.
func (b *broker) applySavedReservationLocked(h *hotel) bool {
	h.fileReservedFor = h.cfg.ReservedFor
	r, ok := b.reservations[h.cfg.ID]
	if !ok {
		return false
	}
	if r.ConfigReservedFor != h.fileReservedFor && r.CustomGuestHold != nil {
		// Kept whole while a custom guest holds the hotel: dropping it would
		// drop the hold. The record's baseline stays, so every save during the
		// hold and the clear keep it, and the first start after the clear
		// applies the file.
		b.alerts.send("OPS-ALERT", b.alerts.opsChat, fmt.Sprintf("HOLD KEPT: hotel %s: the config file's reserved_for is %q, not %q as when the reservation was saved, but custom guest %s holds the hotel; the saved reservation and hold are kept whole. The file applies at the first start after the restore.",
			h.cfg.ID, h.fileReservedFor, r.ConfigReservedFor, r.CustomGuestHold.Launch), nil, nil)
		h.fileReservedFor = r.ConfigReservedFor
	}
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	if r.ConfigReservedFor != h.fileReservedFor {
		log.Printf("hotel %s: saved reserved_for %q (ref %q) dropped: the config file's reserved_for changed since (file wins)", h.cfg.ID, r.ReservedFor, r.Ref)
		h.cfg.ReservationGeneration = r.Generation + 1
		b.reservations[h.cfg.ID] = reservationRecord{ReservedFor: h.cfg.ReservedFor, Generation: h.cfg.ReservationGeneration, ConfigReservedFor: h.fileReservedFor, PinOnly: h.cfg.PinOnly}
		return true
	}
	h.cfg.ReservedFor, h.cfg.ReservationRef, h.cfg.ReservationGeneration = r.ReservedFor, r.Ref, r.Generation
	h.cfg.PinOnly = r.PinOnly && r.ReservedFor != ""
	h.cfg.CustomGuestHold = r.CustomGuestHold
	log.Printf("hotel %s: reserved_for %q (ref %q, generation %d) kept from before the restart (%s)", h.cfg.ID, r.ReservedFor, r.Ref, r.Generation, reservationsFile)
	if c := r.CustomGuestHold; c != nil {
		log.Printf("hotel %s: custom guest hold of %s (kit_down %v) kept from before the restart", h.cfg.ID, c.Launch, c.KitDown)
	}
	return false
}

// loadConfigReservations applies state_dir/hotel-reservations.json to the
// config file hotels at start, before the lend state (which wins). A record
// of a hotel not in the file now is kept for a hotel that comes back. A file
// that does not read keeps the config file's reserved_for and is logged and
// alerted, as drains.go does: it is never a reason not to start.
func (b *broker) loadConfigReservations() {
	b.reservations = map[string]reservationRecord{}
	for _, h := range b.hotelList() {
		if !h.runtime {
			h.fileReservedFor = h.cfg.ReservedFor
		}
	}
	if b.cfg.StateDir == "" {
		return
	}
	path := filepath.Join(b.cfg.StateDir, reservationsFile)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return
	}
	var saved map[string]reservationRecord
	if err == nil {
		err = json.Unmarshal(raw, &saved)
	}
	if err != nil {
		aside := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
		kept := "the old file was not kept aside"
		if werr := os.WriteFile(aside, raw, 0o600); werr == nil {
			kept = "the old file is kept at " + aside
		}
		b.alerts.send("OPS-ALERT", b.alerts.opsChat, fmt.Sprintf("RESERVATIONS NOT LOADED: %s: %v; config file reserved_for applies, so a hotel reserved by PATCH may be back in the pool; %s. Reserve again by PATCH.", reservationsFile, err, kept), nil, nil)
		return
	}
	b.reservations = saved
	changed := false
	for _, h := range b.hotelList() {
		if !h.runtime && b.applySavedReservationLocked(h) {
			changed = true
		}
	}
	if changed {
		if err := b.saveConfigReservationsLocked(); err != nil {
			log.Printf("%s not rewritten: %v", reservationsFile, err)
		}
	}
}
