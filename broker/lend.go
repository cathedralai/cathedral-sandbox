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
// The lend state lives in the hotel fields lent_from and lent_report_id and
// survives a restart. A joined hotel keeps them in state_dir/hotels.json with
// the rest of its PATCH state. A hotel from the config file keeps them in
// state_dir/hotel-lends.json, and that state wins over the config file's
// reserved_for at load: a restart never gives a lent machine back to its
// owner. Lending a config hotel needs state_dir (else 409 no_state_dir). The
// config file itself cannot set the lend fields.
//
// Fail closed. A sealed hotel reserved for X whose room list shows a room of
// another guest (or an unlabeled room) is not X's alone. The sync loop then
// makes it lent from X with lent_report_id "unknown" and logs it loudly:
// X's creates get hotel_lent, never a room next to a stranger's. The next
// attestation records the running launch as the baseline, so the reclaim
// still needs drain and a re-seal. After a restart, a reserved hotel takes no
// rooms until its first room list has passed this check.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// lentReportUnknown is lent_report_id of a hotel the fail-closed check made
// lent: no REPORT_ID was recorded yet. Reclaim waits for a real one.
const lentReportUnknown = "unknown"

// lendsFile keeps the lend state of hotels from the config file.
const lendsFile = "hotel-lends.json"

type lendEntry struct {
	LentFrom     string `json:"lent_from"`
	LentReportID string `json:"lent_report_id"`
}

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
		if !h.runtime && b.cfg.StateDir == "" {
			return c, &apiErr{409, "no_state_dir", "set state_dir in the config to lend a hotel from the config file: the lend must survive a restart"}
		}
	case reserve != nil && lent != "" && *reserve == "":
		return c, &apiErr{409, "hotel_lent", "hotel " + h.cfg.ID + " is lent from " + lent +
			" and already in the pool; to give it back, drain it, re-seal it and PATCH reserved_for"}
	case reserve != nil && lent != "":
		c.reclaim, c.owner, c.lentID = true, *reserve, h.lentReportID()
		if c.lentID == lentReportUnknown {
			return c, &apiErr{409, "reseal_required", "hotel " + h.cfg.ID + " was made lent by the fail-closed room check and has no REPORT_ID " +
				"yet; the broker records the running launch at its next attestation. Then drain, re-seal and reclaim"}
		}
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

// awaitsRoomCheck reports whether h is a reserved hotel whose rooms were not
// listed since start: it takes no rooms until the fail-closed check ran.
// Caller holds b.mu.
func (b *broker) awaitsRoomCheck(h *hotel) bool {
	return h.roomsUnchecked && h.reservedFor() != ""
}

// foreignRooms is the number of rooms on h that are not owner's. A room with
// no guest label counts: the broker labels every room it starts. Caller
// holds b.mu.
func foreignRooms(h *hotel, owner string) int {
	n := 0
	for _, rm := range h.rooms {
		if rm.guest != owner {
			n++
		}
	}
	return n
}

// reserveErr refuses to reserve a sealed hotel for owner while another
// guest's rooms or any create are on it. The fail-closed check below would
// make the hotel lent only at the next room list; until then the owner's
// creates would land next to those rooms and stay there. Caller holds b.mu
// and not h.cfgMu.
func reserveErr(h *hotel, owner string) *apiErr {
	if owner == "" || owner == h.reservedFor() || hotelClass(h) != classSealed {
		return nil
	}
	if n := foreignRooms(h, owner) + h.creating + h.queued; n > 0 {
		return &apiErr{409, "rooms_active", fmt.Sprintf("hotel %s has %d rooms or creates that are not %s's; "+
			"drain it and wait until they are gone, then reserve it", h.cfg.ID, n, owner)}
	}
	return nil
}

// checkReservedRooms is the fail-closed check of the sync loop, after a room
// list. A sealed hotel reserved for X with a room of another guest becomes
// lent from X (lent_report_id unknown). It reports whether it changed h.
// Caller holds b.mu.
func (b *broker) checkReservedRooms(h *hotel) bool {
	owner := h.reservedFor()
	if owner == "" || hotelClass(h) != classSealed {
		return false
	}
	n := foreignRooms(h, owner)
	if n == 0 {
		return false
	}
	h.cfgMu.Lock()
	changed := h.cfg.ReservedFor == owner && h.cfg.LentFrom == ""
	if changed {
		h.cfg.LentFrom, h.cfg.LentReportID, h.cfg.ReservedFor = owner, lentReportUnknown, ""
	}
	h.cfgMu.Unlock()
	if changed {
		log.Printf("FAIL CLOSED: hotel %s is reserved_for %s but lists %d rooms of other guests; it is now lent from %s "+
			"(%s gets 403 hotel_lent). To give it back: drain, re-seal, reclaim", h.cfg.ID, owner, n, owner, owner)
	}
	return changed
}

// fillLentBaseline records the running launch's REPORT_ID for a hotel the
// fail-closed check made lent. A launch seen after that check is the one
// pool rooms ran in, or a later one; either way reclaim needs a newer one.
func (b *broker) fillLentBaseline(ctx context.Context, h *hotel, healthOK bool) {
	if !healthOK || h.lentReportID() != lentReportUnknown {
		return
	}
	now := time.Now()
	b.mu.Lock()
	due := now.Sub(h.baselineTry) >= attestRetry
	if due {
		h.baselineTry = now
	}
	b.mu.Unlock()
	if !due {
		return
	}
	id, e := b.launchReportID(ctx, h)
	if e != nil {
		return // tried again at attestRetry; reclaim stays refused meanwhile
	}
	b.mu.Lock()
	h.cfgMu.Lock()
	set := h.cfg.LentReportID == lentReportUnknown
	if set {
		h.cfg.LentReportID = id
	}
	h.cfgMu.Unlock()
	b.mu.Unlock()
	if set {
		log.Printf("hotel %s: lent baseline REPORT_ID %s recorded", h.cfg.ID, short(id))
		b.saveLendStateLogged(h)
	}
}

// saveLendStateLocked writes the lend state of h where it survives a
// restart: state_dir/hotels.json for a joined hotel,
// state_dir/hotel-lends.json for a hotel from the config file. Callers hold
// b.mu and hotelsMutationMu, as for saveRuntimeHotelsLocked.
func (b *broker) saveLendStateLocked(h *hotel) error {
	if h.runtime {
		return b.saveRuntimeHotelsLocked()
	}
	return b.saveConfigLendsLocked()
}

// saveLendStateLogged is saveLendStateLocked for the sync loop, which holds
// no lock and has no caller to answer.
func (b *broker) saveLendStateLogged(h *hotel) {
	b.hotelsMutationMu.Lock()
	defer b.hotelsMutationMu.Unlock()
	b.mu.Lock()
	err := b.saveLendStateLocked(h)
	b.mu.Unlock()
	if err != nil {
		log.Printf("LEND STATE NOT SAVED: hotel %s: %v; a restart would lose it", h.cfg.ID, err)
	}
}

// saveConfigLendsLocked writes state_dir/hotel-lends.json: the lent hotels
// from the config file, and the entries of hotels not in the config now.
// Callers hold b.mu and hotelsMutationMu.
func (b *broker) saveConfigLendsLocked() error {
	if b.cfg.StateDir == "" {
		return errors.New("no state_dir")
	}
	out := map[string]lendEntry{}
	for id, e := range b.lendsOnDisk {
		out[id] = e
	}
	for _, h := range b.hotelList() {
		if h.runtime {
			continue
		}
		if l := h.lentFrom(); l != "" {
			out[h.cfg.ID] = lendEntry{LentFrom: l, LentReportID: h.lentReportID()}
		}
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(b.cfg.StateDir, lendsFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(b.cfg.StateDir, lendsFile))
}

// loadConfigLends applies state_dir/hotel-lends.json to the hotels from the
// config file. The state wins over reserved_for: a lent hotel stays lent. A
// file that does not parse stops the broker: starting without it could give
// a lent machine back to its owner.
func (b *broker) loadConfigLends() error {
	if b.cfg.StateDir == "" {
		return nil
	}
	path := filepath.Join(b.cfg.StateDir, lendsFile)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var entries map[string]lendEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return fmt.Errorf("%s does not parse (%v); fix or remove it only after the lent machines are re-sealed", path, err)
	}
	b.lendsOnDisk = map[string]lendEntry{}
	for id, e := range entries {
		if err := lendConfigError(hotelConfig{LentFrom: e.LentFrom, LentReportID: e.LentReportID}); err != nil || e.LentFrom == "" {
			return fmt.Errorf("%s: hotel %q: lent_from and lent_report_id must both be set", path, id)
		}
		h := b.hotelByID(id)
		if h == nil {
			b.lendsOnDisk[id] = e // kept for a hotel that comes back to the config file
			log.Printf("lend state for hotel %s kept: the hotel is not in the config file", id)
			continue
		}
		if r := h.cfg.ReservedFor; r != "" {
			log.Printf("hotel %s is lent from %s (state_dir); config reserved_for %s waits for a reclaim", id, e.LentFrom, r)
		}
		h.cfg.LentFrom, h.cfg.LentReportID, h.cfg.ReservedFor = e.LentFrom, e.LentReportID, ""
	}
	return nil
}
