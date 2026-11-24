// AB#683 fresh guest capability: the producer side of the API interlock in
// bigailabs/polariscomputer docs/AB683_API_CAPABILITY_INTERLOCK.md (#2069).
//
// The API reads the authenticated guest's GET /v1/quota before any fresh
// guest dispatch and refuses unless it finds:
//
//	"escape_fresh_guest": {
//	  "schema": "cathedral.escape.fresh_guest/v1",
//	  "guest": "<guest id>",
//	  "durable_single_use": true,
//	  "expected_binding": true,
//	  "attempt_bound_plant": true,
//	  "recovery": "same_request_or_refuse",
//	  "slots": ["<hotel id>", ...]
//	}
//
// The contract says these fields describe enforcement the broker and the guest
// image really have, never a configuration declaration. So two things must hold
// before the broker sends it:
//
//  1. The guest opts in, default off: "escape_fresh_guest": {"slots": [...]}
//     in its config entry. Every slot must be in the guest's explicit "hotels"
//     list (no policy, no absent list meaning "all").
//  2. The broker reports every guarantee enforced, from its config at start
//     (freshGuestEnforcementFor). Three of the four rest on the guest kit
//     (room-kit room_receipts.py: #671 #672 #676), so they hold only for a
//     hotel whose attested launch measurement is one the operator listed in
//     escape_fresh_measurements: the measurements of guest kits built with
//     that code. An empty list (the default) enforces nothing, and a live
//     broker never advertises, whatever its guest config says.
//  3. A slot is advertised only while its hotel is admitted now and its
//     AMD-verified measurement is in both escape_fresh_measurements and the
//     live sealed_measurements (freshKitAttested). The create pin
//     (escape_fresh_create.go pinFresh) refuses any other hotel unsent, and
//     createOne checks the kit and the expected binding again after the slot
//     wait, so an older kit that would ignore the fresh headers never gets a
//     fresh create.
//
// Each answer is computed from current state (runtime hotel PATCH, hotel
// labels) and sent with Cache-Control: no-store. A slot that is no longer an
// allowed, sealed, escape-labelled hotel is not advertised; if none remains,
// the extension is absent and the API refuses.
package main

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	freshGuestSchema   = "cathedral.escape.fresh_guest/v1"
	freshGuestRecovery = "same_request_or_refuse"
	freshGuestMaxSlots = 64 // the API refuses more
)

// The API's slot grammar (fresh_guests.py _SLOT_ID).
var freshGuestSlotRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type freshGuestConfig struct {
	Slots []string `json:"slots"`
}

// freshGuestGuarantees lists what this build enforces for a fresh guest
// attempt. Recovery is the recovery mode implemented ("" for none).
type freshGuestGuarantees struct {
	DurableSingleUse  bool   // a launch is consumed durably before dispatch, never reused
	ExpectedBinding   bool   // the guest refuses a create whose binding is not the expected one
	AttemptBoundPlant bool   // the secret is planted into the same attempt's guest only
	Recovery          string // freshGuestRecovery once an unknown outcome is replayed or refused exactly
}

func (f freshGuestGuarantees) complete() bool {
	return f.DurableSingleUse && f.ExpectedBinding && f.AttemptBoundPlant && f.Recovery == freshGuestRecovery
}

// freshGuestEnforcementFor is what a broker started on c enforces. The broker
// halves are code in this build: the plant forward and its strict shape
// (escape_nonce.go, #671), the create pin, header forward and same request
// replay (escape_fresh_create.go, #677). The guest halves are the kit's: the
// durable attempt and launch reservation before dispatch (#676), the expected
// launch and binding check (#676), the one plant into the attempt's own live
// room (#671 #672), and the durable refusal of a repeat after a broker
// restart (#676). They are enforced only on a hotel running a listed kit, so
// none is claimed without escape_fresh_measurements.
func freshGuestEnforcementFor(c config) freshGuestGuarantees {
	if len(c.EscapeFreshMeasurements) == 0 {
		return freshGuestGuarantees{}
	}
	return freshGuestGuarantees{
		DurableSingleUse:  true,
		ExpectedBinding:   true,
		AttemptBoundPlant: true,
		Recovery:          freshGuestRecovery,
	}
}

var errFreshMeasurements = errors.New("escape_fresh_measurements")

// measurementHexRE is a SEV-SNP launch measurement (48 bytes), lower case.
var measurementHexRE = regexp.MustCompile(`^[0-9a-f]{96}$`)

// validateFreshMeasurements checks escape_fresh_measurements in every config
// file read (start, -check-config, reload): each a lower case 96 hex launch
// measurement, no repeats.
func validateFreshMeasurements(c config) error {
	seen := map[string]bool{}
	for _, m := range c.EscapeFreshMeasurements {
		if !measurementHexRE.MatchString(m) {
			return fmt.Errorf("config: %w: %q is not a 96 character lower case hex launch measurement", errFreshMeasurements, m)
		}
		if seen[m] {
			return fmt.Errorf("config: %w: %s... appears twice", errFreshMeasurements, m[:16])
		}
		seen[m] = true
	}
	return nil
}

// checkFreshMeasurementsSealed is the start check: each fresh kit is also in
// sealed_measurements, since a kit the gate refuses is no fresh kit. Not
// applied on a reload, so a reload can still withdraw a measurement at once;
// freshKitAttested reads the live list.
func checkFreshMeasurementsSealed(c config) error {
	for _, m := range c.EscapeFreshMeasurements {
		if !inFold(c.SealedMeasurements, m) {
			return fmt.Errorf("config: %w: %s... is not in sealed_measurements", errFreshMeasurements, m[:16])
		}
	}
	return nil
}

// freshKitAttested: h runs a guest kit that enforces the fresh guarantees, as
// far as the broker can know now. h is admitted, its measurement came from an
// AMD-verified attestation of its current binding, and that measurement is in
// escape_fresh_measurements and still in the live sealed_measurements (a
// reload can drop it). Caller holds b.mu.
func (b *broker) freshKitAttested(h *hotel, now time.Time) bool {
	a := h.adm
	if a.measurement == "" || a.bindingSHA == "" || a.amd == nil || a.amdBinding != a.bindingSHA {
		return false
	}
	return b.admitted(h, now) && inFold(b.cfg.EscapeFreshMeasurements, a.measurement) && inFold(b.sealedMeasurements(), a.measurement)
}

var errFreshGuestConfig = errors.New("escape_fresh_guest")

// validateFreshGuestConfig checks a guest's opt-in at load.
func validateFreshGuestConfig(gc guestConfig) error {
	fg := gc.EscapeFreshGuest
	if fg == nil {
		return nil
	}
	bad := func(msg string) error { return fmt.Errorf("config: guest %q: %w: %s", gc.ID, errFreshGuestConfig, msg) }
	if gc.Policy != nil {
		return bad("needs an explicit hotels list, not a policy")
	}
	if len(fg.Slots) == 0 || len(fg.Slots) > freshGuestMaxSlots {
		return bad(fmt.Sprintf("slots must list 1 to %d hotel ids", freshGuestMaxSlots))
	}
	allowed := map[string]bool{}
	for _, h := range gc.Hotels {
		allowed[h] = true
	}
	seen := map[string]bool{}
	for _, s := range fg.Slots {
		if !freshGuestSlotRE.MatchString(s) {
			return bad(fmt.Sprintf("slot %q is not a hotel id of [a-z0-9-], at most 63 characters", s))
		}
		if seen[s] {
			return bad(fmt.Sprintf("slot %q appears twice", s))
		}
		seen[s] = true
		if !allowed[s] {
			return bad(fmt.Sprintf("slot %q is not in the guest's hotels", s))
		}
	}
	return nil
}

// freshGuestAdvertisement returns the /v1/quota extension for g, or nil when
// the broker must not advertise. Caller holds b.mu (lim is g.limits under it).
func (b *broker) freshGuestAdvertisement(g *guestState, lim guestLimits) map[string]any {
	fg := g.cfg.EscapeFreshGuest
	if fg == nil || !b.freshEnforcement.complete() || lim.Policy != nil {
		return nil
	}
	allowed := map[string]bool{}
	for _, h := range lim.Hotels {
		allowed[h] = true
	}
	now := time.Now()
	slots := []string{}
	for _, s := range fg.Slots {
		if !allowed[s] {
			continue // removed by a runtime PATCH
		}
		h := b.hotelByID(s)
		if h == nil || !h.cfg.Sealed || !h.isEscape() || !b.freshKitAttested(h, now) {
			continue
		}
		slots = append(slots, s)
	}
	if len(slots) == 0 {
		return nil
	}
	return map[string]any{
		"schema":              freshGuestSchema,
		"guest":               g.cfg.ID,
		"durable_single_use":  true,
		"expected_binding":    true,
		"attempt_bound_plant": true,
		"recovery":            freshGuestRecovery,
		"slots":               slots,
	}
}

// freshGuestOptedIn: the guest's config opts it into fresh creates. The
// broker refuses a fresh create from any other guest before reading further.
func freshGuestOptedIn(g *guestState) bool {
	return g.cfg.EscapeFreshGuest != nil
}

// freshGuestSlotHeld: hotelID is one of the guest's opted-in slots and is still
// in its explicit hotels (a runtime PATCH can remove it). Caller holds b.mu.
func freshGuestSlotHeld(g *guestState, lim guestLimits, hotelID string) bool {
	fg := g.cfg.EscapeFreshGuest
	if fg == nil || lim.Policy != nil {
		return false
	}
	inHotels := false
	for _, h := range lim.Hotels {
		if h == hotelID {
			inHotels = true
			break
		}
	}
	if !inHotels {
		return false
	}
	for _, s := range fg.Slots {
		if s == hotelID {
			return true
		}
	}
	return false
}
