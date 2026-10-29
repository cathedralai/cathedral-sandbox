// Lend an idle reserved sealed hotel to the pool, and reclaim it only after a
// re-seal (docs/DEDICATED_SEALED.md, review of #309).
//
// A reserved hotel (reserved_for, capacity.go) is one guest's sealed machine.
// Inside one SEV-SNP guest only the room runtime separates rooms, so a pool
// guest and the owner must never share the machine, and nothing a pool guest
// left (memory, disk, workspaces) may stay in it when the owner comes back.
//
//	PATCH /v1/broker/hotels/<id> {"lend": true}
//
// lends a sealed hotel reserved for guest X. Only when X has no rooms and no
// creates in flight there (else 409 owner_rooms_active). The broker fetches
// and checks the hotel's attestation now (the admission check, with the AMD
// chain when amd_verifier is set) and records X as lent_from and the
// report's REPORT_ID as lent_report_id. reserved_for is cleared, so pool
// guests place there by their policies. From then on X's creates never go
// there: a create naming the hotel, or one that only it would match, gets
// 403 hotel_lent; X's other hotels work as before. No workspace is created on
// a lent hotel (reclaim destroys the machine, and the workspace with it).
//
//	PATCH /v1/broker/hotels/<id> {"reserved_for": "X"}
//
// on a lent hotel is the reclaim. It succeeds only when the hotel has no
// rooms and no creates in flight (else 409 rooms_active: set drain first),
// and a fresh attestation shows a REPORT_ID other than lent_report_id (else
// 409 reseal_required): the firmware sets REPORT_ID at SNP launch, so a new
// one means the old guest VM, with everything pool guests left in it, is
// gone. reserved_for is set, lent_from and lent_report_id are cleared. Any
// guest may be named; the re-seal is what makes it safe. "reserved_for": null
// on a lent hotel is refused (409 hotel_lent): reclaim is the only way out.
//
// The lend state lives in the hotel config fields lent_from and
// lent_report_id. Like reserved_for and drain, a PATCH of a joined hotel is
// kept in state_dir/hotels.json; a PATCH of a hotel from the config file lasts
// until restart, so write the same fields in the config file to keep it.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
)

// lentFrom is the guest the hotel is lent from, or "" when it is not lent.
func (h *hotel) lentFrom() string {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.cfg.LentFrom
}

func (h *hotel) lentReportID() string {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.cfg.LentReportID
}

// lendConfigError checks the lend fields of a hotel config: both or neither,
// and a lent hotel is not reserved at the same time.
func lendConfigError(hc hotelConfig) error {
	switch {
	case (hc.LentFrom == "") != (hc.LentReportID == ""):
		return errors.New("lent_from and lent_report_id go together")
	case hc.LentFrom != "" && hc.ReservedFor != "":
		return errors.New("a lent hotel has no reserved_for until it is reclaimed")
	}
	return nil
}

// ownerBusy is what keeps a lend from starting: the owner's rooms on h, and
// every create placed on h and not yet listed (a reserved hotel takes creates
// from its owner only, so they count as the owner's). Caller holds b.mu.
func ownerBusy(h *hotel, owner string) int {
	n := h.creating + h.queued
	for _, rm := range h.rooms {
		if rm.guest == owner {
			n++
		}
	}
	return n
}

// launchReportID fetches h's attestation now and checks it as admission does
// (checkAttestation). It returns the REPORT_ID of the current SNP launch.
func (b *broker) launchReportID(ctx context.Context, h *hotel) (string, *apiErr) {
	res, err := b.checkAttestation(ctx, h)
	var fe attestFetchErr
	switch {
	case errors.As(err, &fe):
		return "", &apiErr{502, "hotel_unreachable", "the hotel did not answer GET /room/attestation"}
	case err != nil:
		return "", &apiErr{422, "attestation_failed", "the hotel's SEV-SNP attestation did not pass: " + err.Error()}
	case res.reportID == "":
		return "", &apiErr{422, "attestation_failed", "the hotel's SEV-SNP report has no REPORT_ID"}
	}
	return res.reportID, nil
}

// lendChange is a lend or a reclaim that patchHotel applies with its other
// fields, all or none.
type lendChange struct {
	lend     bool   // lend the hotel from owner
	reclaim  bool   // give a lent hotel to owner (reserved_for)
	owner    string // lend: the guest it is reserved for; reclaim: the new owner
	reportID string // the REPORT_ID fetched for this change
	lentID   string // reclaim: the lent_report_id the check compared against
	reserve  bool   // the PATCH sets reserved_for (a reclaim, or a plain change of a hotel that is not lent)
}

// prepareLend checks a lend or a reclaim before patchHotel takes its locks.
// It fetches the attestation, so it runs with no lock held. reserve is the
// PATCH reserved_for (nil: not in the request; "": null).
func (b *broker) prepareLend(ctx context.Context, h *hotel, lend bool, reserve *string) (lendChange, *apiErr) {
	lent := h.lentFrom()
	c := lendChange{reserve: reserve != nil}
	switch {
	case lend && lent != "":
		return c, &apiErr{409, "hotel_lent", "hotel " + h.cfg.ID + " is already lent from " + lent}
	case lend:
		c.lend, c.owner = true, h.reservedFor()
		if c.owner == "" {
			return c, &apiErr{409, "hotel_not_reserved", "only a hotel reserved for a guest can be lent"}
		}
		if hotelClass(h) != classSealed {
			return c, &apiErr{409, "hotel_not_sealed", "only a sealed hotel can be lent: reclaim needs a new SNP launch"}
		}
	case reserve != nil && lent != "" && *reserve == "":
		return c, &apiErr{409, "hotel_lent", "hotel " + h.cfg.ID + " is lent from " + lent +
			" and already in the pool; to give it back, drain it, re-seal it and PATCH reserved_for"}
	case reserve != nil && lent != "":
		c.reclaim, c.owner, c.lentID = true, *reserve, h.lentReportID()
	default:
		return c, nil
	}
	// Refuse a busy hotel before the attestation call; applyLend checks again.
	b.mu.Lock()
	e := c.busyErr(h)
	b.mu.Unlock()
	if e != nil {
		return c, e
	}
	id, e := b.launchReportID(ctx, h)
	if e != nil {
		return c, e
	}
	if c.reclaim && id == c.lentID {
		return c, &apiErr{409, "reseal_required", "hotel " + h.cfg.ID + " runs the SNP launch it was lent with (REPORT_ID " + short(id) +
			"); destroy and relaunch the sealed machine, then reclaim"}
	}
	c.reportID = id
	return c, nil
}

// busyErr is the refusal for rooms on h. Caller holds b.mu.
func (c lendChange) busyErr(h *hotel) *apiErr {
	switch {
	case c.lend:
		if n := ownerBusy(h, c.owner); n > 0 {
			return &apiErr{409, "owner_rooms_active", fmt.Sprintf("guest %s has %d rooms or creates on hotel %s; a hotel is lent only with none", c.owner, n, h.cfg.ID)}
		}
	case c.reclaim:
		if n := h.used(); n > 0 {
			return &apiErr{409, "rooms_active", fmt.Sprintf("hotel %s has %d rooms or creates; set drain first and wait until they are gone", h.cfg.ID, n)}
		}
	}
	return nil
}

// applyLend checks c again against the hotel as it is now and applies it.
// Caller holds b.mu and h.cfgMu (write).
func (c lendChange) applyLend(h *hotel) *apiErr {
	switch {
	case c.lend:
		if h.cfg.LentFrom != "" || h.cfg.ReservedFor != c.owner {
			return &apiErr{409, "hotel_changed", "hotel " + h.cfg.ID + " changed during the lend; try again"}
		}
	case c.reclaim:
		if h.cfg.LentFrom == "" || h.cfg.LentReportID != c.lentID {
			return &apiErr{409, "hotel_changed", "hotel " + h.cfg.ID + " changed during the reclaim; try again"}
		}
	case c.reserve && h.cfg.LentFrom != "":
		// Lent after prepareLend looked: a plain reserved_for must not skip the reclaim checks.
		return &apiErr{409, "hotel_changed", "hotel " + h.cfg.ID + " was lent meanwhile; try again"}
	default:
		return nil
	}
	if e := c.busyErr(h); e != nil {
		return e
	}
	if c.lend {
		h.cfg.LentFrom, h.cfg.LentReportID, h.cfg.ReservedFor = c.owner, c.reportID, ""
		log.Printf("hotel %s lent from %s (REPORT_ID %s)", h.cfg.ID, c.owner, short(c.reportID))
		if !h.runtime {
			log.Printf("hotel %s is in the config file: the lend lasts until restart unless the config file sets lent_from and lent_report_id", h.cfg.ID)
		}
		return nil
	}
	log.Printf("hotel %s reclaimed for %s (REPORT_ID %s, lent with %s)", h.cfg.ID, c.owner, short(c.reportID), short(c.lentID))
	h.cfg.LentFrom, h.cfg.LentReportID, h.cfg.ReservedFor = "", "", c.owner
	return nil
}

// lentAway reports whether some hotel lent from the placement's guest would
// match pl if it were not lent: the guest's create then gets hotel_lent, not
// no_matching_hotel. A probe with no guest skips the lent check; a lent hotel
// has no reservation, so nothing else changes.
func (b *broker) lentAway(pl placement) bool {
	probe := pl
	probe.guest = ""
	for _, h := range b.hotelList() {
		if pl.guest != "" && h.lentFrom() == pl.guest && probe.selects(h) {
			return true
		}
	}
	return false
}

func errHotelLent(id string) *apiErr {
	return &apiErr{403, "hotel_lent", "hotel " + id + " is lent to the pool; your rooms go to your other hotels until it is reclaimed"}
}

// short is the first 16 characters of a REPORT_ID, for messages and logs.
func short(id string) string {
	if len(id) > 16 {
		return id[:16] + "..."
	}
	return id
}
