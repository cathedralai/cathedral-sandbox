// Allowance stop (AB#948): the ledger freezes a metered guest's running rooms
// through the allowance PUT it already sends.
//
// A PUT may carry "stop": {"reason": "account_suspended" | "abuse"}. It is
// level-triggered: the ledger sends it on every PUT while the account stays
// stopped, and the broker keeps no stop id. Each such PUT saves and answers
// the allowance at once, then runs the freeze-all pass (meter.go) in the
// background: it freezes the guest's rooms in state "running" and touches no
// other room, so a repeated stop freezes nothing new, and a room that was
// still "creating" at one stop is frozen by a later one. One pass runs per
// guest at a time; a stop that arrives while one runs starts none. The last
// pass's result shows in the allowance view (in memory, lost at restart).
//
// A stop needs cap 0 in the same PUT (else 400), so the guest can also create,
// extend or thaw nothing. It reaches only metered guests: a guest that is not
// metered gets 409 guest_not_metered before anything changes, and a postpaid
// guest can never be metered (loadAllowances). Freeze, never delete: a frozen
// room keeps its TTL and still bills to it, like an API room's hold.
package main

import (
	"context"
	"log"
	"sort"
	"strings"
	"time"
)

// stopReasons are the reasons a stop may carry.
var stopReasons = map[string]bool{"account_suspended": true, "abuse": true}

// allowanceStop is the "stop" object of an allowance PUT.
type allowanceStop struct {
	Reason string `json:"reason"`
}

// stopResult is one finished freeze pass of a stop.
type stopResult struct {
	at          time.Time
	reason      string
	frozen      int
	failed      map[string]string // room id -> why it did not freeze (freezeRoom's code), as the meter route answers
	hotelErrors []string          // hotels whose room list did not answer, sorted
}

// guestStops is the stop state of one guest. Guarded by broker.mu.
type guestStops struct {
	running bool
	last    *stopResult
}

// startStopLocked starts a freeze pass for g with reason, unless one is
// running. It reports whether it started one. Caller holds b.mu.
func (b *broker) startStopLocked(g *guestState, reason string) bool {
	if b.allow.stops == nil {
		b.allow.stops = map[string]*guestStops{}
	}
	st := b.allow.stops[g.cfg.ID]
	if st == nil {
		st = &guestStops{}
		b.allow.stops[g.cfg.ID] = st
	}
	if st.running {
		return false
	}
	st.running = true
	go b.runStop(g, st, reason)
	return true
}

// runStop is one freeze pass of a stop. It outlives the PUT that started it,
// so it does not use the request's context; every hotel call has its own
// timeout (fanout, freezeRoom).
func (b *broker) runStop(g *guestState, st *guestStops, reason string) {
	out := b.freezeAllRooms(context.Background(), g)
	res := &stopResult{at: time.Now(), reason: reason, frozen: len(out.frozen), failed: map[string]string{}, hotelErrors: []string{}}
	// Each room keeps its code (AB#948): without it a stop that froze nothing
	// cannot say whether the hotel refused, did not answer, or is out of reach.
	notFrozen := []string{}
	for id, code := range out.failed {
		res.failed[id] = code
		notFrozen = append(notFrozen, id+"="+code)
	}
	for id := range out.hotelErrors {
		res.hotelErrors = append(res.hotelErrors, id)
	}
	sort.Strings(notFrozen)
	sort.Strings(res.hotelErrors)
	if len(res.failed) > 0 || len(res.hotelErrors) > 0 {
		log.Printf("allowance stop for guest %s (%s): froze %d rooms; not frozen: [%s]; hotels not listed: [%s]; the next stop retries",
			g.cfg.ID, reason, res.frozen, strings.Join(notFrozen, " "), strings.Join(res.hotelErrors, " "))
	} else {
		log.Printf("allowance stop for guest %s (%s): froze %d rooms", g.cfg.ID, reason, res.frozen)
	}
	b.mu.Lock()
	st.last = res
	st.running = false
	b.mu.Unlock()
}

// addStopViewLocked adds stop_running and last_stop to g's allowance view,
// once a stop has been sent to g since the broker started. A guest that never
// got one keeps the view of the captured exchange case
// (exchange_cases_test.go). Caller holds b.mu.
func (b *broker) addStopViewLocked(g *guestState, view map[string]any) {
	st := b.allow.stops[g.cfg.ID]
	if st == nil {
		return
	}
	var last any // null: the first pass still runs
	if st.last != nil {
		last = map[string]any{
			"at": st.last.at.UTC().Format(time.RFC3339Nano), "reason": st.last.reason, "frozen": st.last.frozen,
			"failed": st.last.failed, "hotel_errors": st.last.hotelErrors,
		}
	}
	view["stop_running"] = st.running
	view["last_stop"] = last
}
