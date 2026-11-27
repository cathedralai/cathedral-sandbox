// The broker hold of a dedicated custom SNP guest (AB#1008; spec r9 7.2).
//
// A customer's own SNP guest takes over the host of a dedicated hotel while
// the room kit is stopped. The API's fence route sets the hold with the
// operator key, in the PATCH that moves the reservation to the launch's
// "cg:" ref; nothing else sets it:
//
//	{"custom_guest_hold": {"launch": "cg-<12 hex>", "kit_down": false}, "expect_generation": G, ...}  H3
//	{"custom_guest_hold": {"launch": "cg-<12 hex>", "kit_down": true}, "expect_generation": G+1}      H7
//	{"custom_guest_hold": null, "drain": true, "expect_generation": G+1, ...}                       restore
//
// While a hold is set, in either state:
//   - drain() reads true, whatever the config file or a reload says, so no
//     placement path selects the hotel (capacity.go). placement.selects,
//     prewarm, the prefetch replay and the image import take no claim on it.
//   - A PATCH that does not clear the hold may not change reserved_for,
//     reservation_ref, lend or pin_only, or set drain false: 409
//     custom_guest_held.
//
// H3 is accepted only on a drained hotel whose room count is known and whose
// rooms, creates, queued creates and claims are all 0 (the B8 check of
// pin_only.go, here on any hotel). kit_down is accepted after the kit
// stopped, so it needs no room list: the generation unchanged since H3 and no
// create, queued create, claim or secret call counted. Its first attempt that
// passes those checks also closes secret admission in memory, so a stream of
// new calls to a stopped kit cannot keep the count above 0.
//
// Secret fanouts (secrets.go) decide each hotel in one b.mu hold that also
// counts the call in flight: kit_down true skips the hotel (a DELETE counts it
// as not found: the stopped kit kept its secrets in memory only); admission
// closed answers status 0 with no call, so nothing counts as done there until
// kit_down is saved.
//
// The hold is kept with the reservation in hotel-reservations.json, so a
// restart or a swap keeps it, and a config file or join cannot set it. A
// joined hotel cannot take a hold: its state is in hotels.json.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

type customGuestHold struct {
	Launch  string `json:"launch"`
	KitDown bool   `json:"kit_down"`
}

var customGuestLaunchRe = regexp.MustCompile(`^cg-[0-9a-f]{12}$`)

// customGuestHold is h's hold, or nil. The value is never changed in place,
// only replaced, so the pointer may be kept.
func (h *hotel) customGuestHold() *customGuestHold {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.cfg.CustomGuestHold
}

func (h *hotel) held() bool { return h.customGuestHold() != nil }

// reservationView is h's owner, reservation tuple, drain and hold, read in
// one h.cfgMu hold so they belong together. The operator view reads it under
// b.mu, which every writer of these fields holds through its save and any
// rollback.
type reservationView struct {
	reservedFor, ref, lentFrom, lentReportID string
	gen                                      uint64
	pinOnly, drain                           bool
	hold                                     *customGuestHold
}

func (h *hotel) reservationView() reservationView {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	c := h.cfg
	return reservationView{reservedFor: c.ReservedFor, ref: c.ReservationRef, lentFrom: c.LentFrom, lentReportID: c.LentReportID,
		gen: c.ReservationGeneration, pinOnly: c.PinOnly, drain: c.Drain || c.CustomGuestHold != nil, hold: c.CustomGuestHold}
}

// cfgDrain is the drain the config file or a PATCH set, without the hold.
func (h *hotel) cfgDrain() bool {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.cfg.Drain
}

func sameHold(a, b *customGuestHold) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// holdDoc is the operator view's custom_guest_hold: null when unset.
func holdDoc(c *customGuestHold) any {
	if c == nil {
		return nil
	}
	return map[string]any{"launch": c.Launch, "kit_down": c.KitDown}
}

// holdRequest is a PATCH's custom_guest_hold: absent, null (clear) or a hold.
type holdRequest struct {
	present bool
	hold    *customGuestHold // nil with present: clear
}

func parseHoldRequest(raw json.RawMessage) (holdRequest, error) {
	if len(raw) == 0 {
		return holdRequest{}, nil
	}
	if string(raw) == "null" {
		return holdRequest{present: true}, nil
	}
	var doc struct {
		Launch  *string `json:"launch"`
		KitDown *bool   `json:"kit_down"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Launch == nil || doc.KitDown == nil {
		return holdRequest{}, errors.New(`custom_guest_hold must be null or {"launch": "cg-<12 hex>", "kit_down": true | false}`)
	}
	if !customGuestLaunchRe.MatchString(*doc.Launch) {
		return holdRequest{}, errors.New("custom_guest_hold launch must be cg- and 12 lowercase hex digits")
	}
	return holdRequest{present: true, hold: &customGuestHold{Launch: *doc.Launch, KitDown: *doc.KitDown}}, nil
}

// holdPatch is what a PATCH asks that the hold rules judge.
type holdPatch struct {
	hr      holdRequest
	reserve *string // reserved_for; nil: absent
	ref     string  // the reservation_ref the PATCH would set with reserve
	lend    bool
	pinOnly *bool
	drain   *bool
}

// holdRefusalLocked applies the rules that need no reservation_generation:
// the refusals while a hold is set, the conflict with another launch, and
// what a PATCH that sets or clears the hold may carry. Caller holds b.mu,
// not h.cfgMu.
func (b *broker) holdRefusalLocked(h *hotel, p holdPatch) *apiErr {
	cur := h.customGuestHold()
	clearing := p.hr.present && p.hr.hold == nil
	if clearing {
		if cur != nil && (p.drain == nil || !*p.drain) {
			// A reload may have set the file's drain false while the hold
			// masked it; clearing without a drain would open placement at once.
			return &apiErr{400, "invalid_hotel", "clearing custom_guest_hold needs \"drain\": true in the same request; restore the drain after"}
		}
		return nil
	}
	sets := p.hr.present && p.hr.hold != nil
	if cur != nil {
		if sets && p.hr.hold.Launch != cur.Launch {
			return &apiErr{409, "custom_guest_hold_conflict", fmt.Sprintf("hotel %s is held for custom guest %s, not %s", h.cfg.ID, cur.Launch, p.hr.hold.Launch)}
		}
		if sets && cur.KitDown && !p.hr.hold.KitDown {
			return &apiErr{409, "custom_guest_held", fmt.Sprintf("hotel %s: the hold of %s has kit_down true; it does not go back, only the restore clears it", h.cfg.ID, cur.Launch)}
		}
		if what := heldChange(h, p); what != "" {
			return &apiErr{409, "custom_guest_held", fmt.Sprintf("hotel %s is held for custom guest %s: %s waits until the restore clears the hold", h.cfg.ID, cur.Launch, what)}
		}
		return nil
	}
	if !sets {
		return nil
	}
	// No hold yet: H3, or a lost hold set again. The reservation guest stays.
	switch {
	case h.reservedFor() == "" || (p.reserve != nil && *p.reserve != h.reservedFor()):
		return &apiErr{400, "invalid_hotel", "custom_guest_hold needs a reserved hotel and keeps its reserved_for; only reservation_ref may move with it"}
	case p.hr.hold.KitDown && p.reserve != nil && p.ref != h.cfg.ReservationRef:
		return &apiErr{400, "invalid_hotel", "kit_down keeps the reservation: send it without a reservation_ref change"}
	case p.lend || (p.pinOnly != nil && *p.pinOnly != h.pinOnly()) || (p.drain != nil && !*p.drain):
		return &apiErr{400, "invalid_hotel", "custom_guest_hold cannot be set with lend, a pin_only change or drain false"}
	}
	return nil
}

// heldChange names the first change a held hotel refuses, or "".
func heldChange(h *hotel, p holdPatch) string {
	switch {
	case p.reserve != nil && *p.reserve != h.reservedFor():
		return "a reserved_for change"
	case p.reserve != nil && p.ref != h.cfg.ReservationRef:
		return "a reservation_ref change"
	case p.lend:
		return "a lend"
	case p.pinOnly != nil && *p.pinOnly != h.pinOnly():
		return "a pin_only change"
	case p.drain != nil && !*p.drain:
		return "drain false"
	}
	return ""
}

// holdSetCheckLocked is the check of a PATCH that sets a hold, run after the
// expect_generation compare under the same b.mu and h.cfgMu (write) hold.
// From no hold with the kit up (kit_down false): the B8 check on any hotel.
// Into kit_down: the counters, the admission closure, then the in-flight
// secret calls. A request equal to the hold already set changes nothing.
func (b *broker) holdSetCheckLocked(h *hotel, want *customGuestHold) *apiErr {
	cur := h.cfg.CustomGuestHold
	if sameHold(cur, want) {
		return nil
	}
	if !want.KitDown { // cur is nil: holdRefusalLocked refused every other case
		if !h.cfg.Drain {
			return &apiErr{409, "owner_change_needs_drain", "hotel " + h.cfg.ID + ": custom_guest_hold needs the hotel drained first"}
		}
		if !h.occupancyKnown() {
			return &apiErr{409, "rooms_active", fmt.Sprintf("hotel %s: its rooms are not known (no good room list since start, or unconfirmed create cleanup); retry when the room count is known", h.cfg.ID)}
		}
		if n := len(h.rooms) + h.creating + h.queued + h.claims; n > 0 {
			return &apiErr{409, "rooms_active", fmt.Sprintf("hotel %s has %d rooms, creates or calls; custom_guest_hold waits until it is empty", h.cfg.ID, n)}
		}
		return nil
	}
	// kit_down: the kit is stopped, so no room list can answer. The record
	// (H4 empty, the generation unchanged, placement off since H3) is the
	// authorization; the broker's own counters must be 0.
	if n := h.creating + h.queued + h.claims; n > 0 {
		return &apiErr{409, "rooms_active", fmt.Sprintf("hotel %s has %d creates or calls in flight; kit_down waits until they end", h.cfg.ID, n)}
	}
	// Close admission first, whether or not the count is 0: a call admitted
	// from now on would never let it reach 0 against a kit that drops SYNs.
	h.secretClosed = want.Launch
	if h.secretCalls > 0 {
		return &apiErr{409, "secret_calls_in_flight", fmt.Sprintf("hotel %s has %d secret calls in flight; admission is closed, retry when they end", h.cfg.ID, h.secretCalls)}
	}
	return nil
}

// afterHoldPatchApplied clears the admission closure when the hold that
// closed it is gone or names another launch. Caller holds b.mu.
func afterHoldPatchApplied(h *hotel) {
	if c := h.customGuestHold(); h.secretClosed != "" && (c == nil || c.Launch != h.secretClosed) {
		h.secretClosed = ""
	}
}

type secretAdmission int

const (
	secretAdmitted secretAdmission = iota
	secretNotAllowed
	secretKitDown // the kit is stopped: skip the hotel
	secretClosed  // admission closed for kit_down: status 0, no call
)

// secretAdmit decides one hotel of a secret fanout in one b.mu hold: the
// guest's limits (limitsAllow), the hold, and when admitted the in-flight
// count, which secretCallEnded takes back.
func (b *broker) secretAdmit(g *guestState, h *hotel) secretAdmission {
	now := b.hotelByID(h.cfg.ID)
	b.mu.Lock()
	defer b.mu.Unlock()
	if now == nil {
		if !(g.limits.Policy == nil && g.limits.allows(h.cfg.ID)) {
			return secretNotAllowed
		}
	} else if !g.allowsHotel(now) {
		return secretNotAllowed
	}
	c := h.customGuestHold()
	switch {
	case c != nil && c.KitDown:
		return secretKitDown
	case h.secretClosed != "" && (c == nil || c.Launch == h.secretClosed):
		return secretClosed
	}
	h.secretCalls++
	return secretAdmitted
}

func (b *broker) secretCallEnded(h *hotel) {
	b.mu.Lock()
	h.secretCalls--
	b.mu.Unlock()
}

// afterSecretAdmit runs in a fanout goroutine right after its hotel was
// admitted and before the send; a variable so a test can pause one there.
var afterSecretAdmit = func(hotelID string) {}

// beforeHotelPatchSave runs in a PATCH after h.cfgMu is released and before
// the saves, under b.mu; a variable so a test can pause one there.
var beforeHotelPatchSave = func(hotelID string) {}
