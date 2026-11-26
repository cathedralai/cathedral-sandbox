// pin_only: a reserved sealed hotel that takes only a create its owner marks
// for it (AB#982, Track A pin_only).
//
// The platform key books a customer's owned dedicated hotel H. H is reserved
// for the platform guest P, so every unmarked create, prefetch or workspace
// of P could reach it. With pin_only set, the broker (not the request body)
// tells the two apart: only a create that carries the header
//
//	X-Cathedral-Dedicated-Hotel: <H>;gen=<N>
//
// from H's reservation owner, with hotels [H], placement "require" and N equal
// to H's reservation_generation, may be placed on H. placement.selects holds
// that rule for every path (first pick, retry, queue move, fallback, the
// recheck after the slot wait). The header is read by the sandbox-create
// handler only and is not in the body, so owner-signed projections and
// bootstrap digests do not change.
//
// h.claims counts the prefetch, workspace create and prewarm calls that
// selected a hotel and have not ended. A switch to pin_only, and a change of
// reserved_for, wait until it is 0 (reserveErr, lend.go).
package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// lostMargin is added to the create timeout before an empty cleanup list is
// taken as proof that a create whose reply was lost is not running.
const lostMargin = 5 * time.Second

// dedicatedHotelHeader marks a create for one pin_only hotel.
const dedicatedHotelHeader = "X-Cathedral-Dedicated-Hotel"

// pinState is whether h is pin_only and its reservation_generation, read
// together so a check never mixes two states.
func (h *hotel) pinState() (bool, uint64) {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.cfg.PinOnly, h.cfg.ReservationGeneration
}

func (h *hotel) pinOnly() bool {
	pin, _ := h.pinState()
	return pin
}

// pinOnlyConfigError checks the pin_only field of a hotel config: it needs a
// reservation, a sealed hotel and a state_dir: the fence (pin_only and the
// reservation generation) must survive a restart, so it is never acknowledged
// unsaved.
func pinOnlyConfigError(hc hotelConfig, stateDir string) error {
	if !hc.PinOnly {
		return nil
	}
	switch {
	case stateDir == "":
		return errors.New("pin_only needs state_dir, so the fence survives a restart")
	case hc.ReservedFor == "":
		return errors.New("pin_only needs reserved_for")
	case !hc.Sealed:
		return errors.New("pin_only needs a sealed hotel")
	}
	return nil
}

// dedicatedMark is a validated X-Cathedral-Dedicated-Hotel header.
type dedicatedMark struct {
	hotel string
	gen   uint64
}

// parseDedicatedHeader reads "<H>;gen=<N>". ok is false when the header is
// absent; a header that does not parse is 400 invalid_dedicated_hotel.
func parseDedicatedHeader(r *http.Request) (m *dedicatedMark, present bool, e *apiErr) {
	vals := r.Header.Values(dedicatedHotelHeader)
	if len(vals) == 0 {
		return nil, false, nil
	}
	bad := &apiErr{400, "invalid_dedicated_hotel", dedicatedHotelHeader + " must be <hotel>;gen=<generation>"}
	if len(vals) != 1 {
		return nil, true, bad
	}
	id, rest, ok := strings.Cut(strings.TrimSpace(vals[0]), ";")
	n, isGen := strings.CutPrefix(strings.TrimSpace(rest), "gen=")
	if !ok || id == "" || !isGen {
		return nil, true, bad
	}
	gen, err := strconv.ParseUint(n, 10, 64)
	if err != nil {
		return nil, true, bad
	}
	return &dedicatedMark{hotel: id, gen: gen}, true, nil
}

// dedicatedStaleErr is the answer for a marker whose generation is no longer
// the hotel's.
func dedicatedStaleErr(id string) *apiErr {
	return &apiErr{409, "dedicated_generation_stale", "hotel " + id + " changed owner or settings since this create was admitted; read its reservation_generation again"}
}

// checkDedicated validates the marker against the guest, the hotel and the
// body (B2). Everything but a stale generation is 400.
func (b *broker) checkDedicated(g *guestState, m *dedicatedMark, payload map[string]any) *apiErr {
	bad := func(why string) *apiErr {
		return &apiErr{400, "invalid_dedicated_hotel", dedicatedHotelHeader + ": " + why}
	}
	h := b.hotelByID(m.hotel)
	if h == nil || !g.limitsAllow(b, m.hotel) {
		return bad("no such hotel for this guest")
	}
	pin, gen := h.pinState()
	if !pin || h.reservedFor() != g.cfg.ID {
		return bad("the hotel is not a pin_only hotel reserved for this guest")
	}
	list, _ := payload["hotels"].([]any)
	only := ""
	if len(list) == 1 {
		only, _ = list[0].(string)
	}
	if only != m.hotel {
		return bad(`the body must name hotels [` + strconv.Quote(m.hotel) + `]`)
	}
	if p, _ := payload["placement"].(string); p != "require" {
		return bad(`the body must carry "placement": "require"`)
	}
	if m.gen != gen {
		return dedicatedStaleErr(m.hotel)
	}
	return nil
}

// dedicatedStaleLocked reports whether pl is a dedicated create whose hotel no
// longer matches its marker: the generation moved, or the hotel is no longer
// pin_only or reserved for the guest. Caller holds b.mu.
func (b *broker) dedicatedStaleLocked(pl placement) bool {
	if pl.dedicated == "" {
		return false
	}
	h := b.hotelByID(pl.dedicated)
	if h == nil {
		return true
	}
	pin, gen := h.pinState()
	return !pin || gen != pl.dedicatedGen || h.reservedFor() != pl.guest
}

func dedicatedStaleResult(pl placement) createResult {
	e := dedicatedStaleErr(pl.dedicated)
	return createResult{status: e.status, doc: errDoc(e.code, e.msg)}
}

// refuseDedicatedHeader answers 400 for the header on any route but the
// native sandbox create.
func refuseDedicatedHeader(w http.ResponseWriter, r *http.Request) bool {
	if len(r.Header.Values(dedicatedHotelHeader)) == 0 {
		return false
	}
	if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" && !isCompat(r) {
		return false
	}
	writeErr(w, 400, "invalid_dedicated_hotel", dedicatedHotelHeader+" is accepted on POST /v1/sandboxes only")
	return true
}

// pinStillOpen reports whether a run that started at reservation generation
// resGen may pull on h again: h is not pin_only and its generation did not
// move (B6).
func (b *broker) pinStillOpen(h *hotel, resGen uint64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	pin, gen := h.pinState()
	return !pin && gen == resGen
}

// occupancyKnown reports whether h's room count can be trusted: a room list
// answered since start, the last one did, and no failed create's rooms are
// unconfirmed. The same test as the restart guard's count_known (restart_guard.go),
// plus unreaped and creates whose outcome is still unresolved (lostPending). Zero rooms with this false means unknown, not empty. Caller
// holds b.mu.
func (h *hotel) occupancyKnown() bool {
	return !h.roomsUnchecked && h.listOK && len(h.unreaped) == 0 && h.lostPending == 0
}

func pinUnknownMsg(h *hotel) string {
	return "hotel " + h.cfg.ID + " is pin_only and its rooms are not known (no good room list since start, a create with an unknown outcome, or unconfirmed cleanup); retry when the room count is known"
}

// claim counts a call that selected h (B5). Caller holds b.mu, and takes the
// claim in the same hold as the check that selected h.
func (h *hotel) claim() { h.claims++ }

// releaseClaim ends a claim. Callers defer it, so every exit path releases.
func (b *broker) releaseClaim(h *hotel) {
	b.mu.Lock()
	h.claims--
	b.mu.Unlock()
}
