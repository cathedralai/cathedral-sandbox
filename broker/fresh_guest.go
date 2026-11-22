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
//  2. freshGuestEnforcement reports every guarantee implemented. It is a
//     compiled-in fact of this build, not config: each field turns true only in
//     the change that implements and tests that guarantee. Today none is, so a
//     live broker never advertises, whatever its config says.
//
// Each answer is computed from current state (runtime hotel PATCH, hotel
// labels) and sent with Cache-Control: no-store. A slot that is no longer an
// allowed, sealed, escape-labelled hotel is not advertised; if none remains,
// the extension is absent and the API refuses.
package main

import (
	"errors"
	"fmt"
	"log"
	"regexp"
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

// freshGuestEnforcement is what this build implements. None of it is yet
// (AB#683: the durable dispatch and the guest kit enforcement are follow-ups).
// Do not set a field true without the code and tests that make it so. Tests
// replace this value to exercise the advertisement.
var freshGuestEnforcement = freshGuestGuarantees{}

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
	if !freshGuestEnforcement.complete() {
		log.Printf("guest %s: escape_fresh_guest configured, but this broker build does not implement fresh guest enforcement; not advertised (AB#683)", gc.ID)
	}
	return nil
}

// freshGuestAdvertisement returns the /v1/quota extension for g, or nil when
// the broker must not advertise. Caller holds b.mu (lim is g.limits under it).
func (b *broker) freshGuestAdvertisement(g *guestState, lim guestLimits) map[string]any {
	fg := g.cfg.EscapeFreshGuest
	if fg == nil || !freshGuestEnforcement.complete() || lim.Policy != nil {
		return nil
	}
	allowed := map[string]bool{}
	for _, h := range lim.Hotels {
		allowed[h] = true
	}
	slots := []string{}
	for _, s := range fg.Slots {
		if !allowed[s] {
			continue // removed by a runtime PATCH
		}
		h := b.hotelByID(s)
		if h == nil || !h.cfg.Sealed || !h.isEscape() {
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
