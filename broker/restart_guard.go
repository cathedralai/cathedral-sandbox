// Restart guard for hotel restarts and rolls (AB#875).
//
//	GET /v1/broker/hotels/<id>/restart-check   operator key
//
// A hotel restart ends every room on it, so a roll may restart a hotel only
// when the hotel is drained AND the broker counts nothing on it: no room it
// holds (customer or ready pool room), no create queued or in flight (pool
// creates included), no pool claim in flight, no unreaped room, and the
// hotel's own last count of running rooms is 0. A count the broker cannot
// trust (no room list answered since start, or the last list failed) refuses
// too: an unknown count is not 0.
//
// 200 {"restart_ok": true, ...} when the restart may go; 409 restart_refused
// with every reason otherwise. The roll scripts call it right before they
// restart the hotel. The check reads; it changes nothing. The drain keeps new
// rooms off between the check and the restart.
package main

import (
	"fmt"
	"net/http"
	"strings"
)

type restartCheck struct {
	Hotel      string   `json:"hotel"`
	RestartOK  bool     `json:"restart_ok"`
	Drain      bool     `json:"drain"`
	Rooms      int      `json:"rooms"`       // rooms the broker holds on the hotel, ready pool rooms included
	Creating   int      `json:"creating"`    // creates in flight, pool creates included
	Queued     int      `json:"queued"`      // creates waiting for a slot
	PoolClaims int      `json:"pool_claims"` // pool claims in flight
	Unreaped   int      `json:"unreaped"`    // failed create batches whose rooms are not yet confirmed gone
	HotelRooms int      `json:"hotel_rooms"` // running plus frozen rooms in the hotel's last health answer
	CountKnown bool     `json:"count_known"` // a room list answered since start and the last one did
	Reasons    []string `json:"reasons"`
}

// restartCheckLocked counts h. Caller holds b.mu.
func (b *broker) restartCheckLocked(h *hotel) restartCheck {
	c := restartCheck{Hotel: h.cfg.ID, Drain: h.drain(), Rooms: len(h.rooms), Creating: h.creating,
		Queued: h.queued, Unreaped: len(h.unreaped), HotelRooms: h.apiRunning,
		CountKnown: !h.roomsUnchecked && h.listOK, Reasons: []string{}}
	if b.pool != nil {
		if ph := b.pool.hotels[h.cfg.ID]; ph != nil {
			c.PoolClaims = ph.claims
		}
	}
	if !c.Drain {
		c.Reasons = append(c.Reasons, "the hotel is not drained")
	}
	if !c.CountKnown {
		c.Reasons = append(c.Reasons, "the room count is not known (no good room list from the hotel)")
	}
	for _, n := range []struct {
		v    int
		what string
	}{{c.Rooms, "room(s) on the hotel"}, {c.Creating, "create(s) in flight"}, {c.Queued, "create(s) queued"},
		{c.PoolClaims, "pool claim(s) in flight"}, {c.Unreaped, "unreaped create batch(es)"},
		{c.HotelRooms, "room(s) running by the hotel's own count"}} {
		if n.v > 0 {
			c.Reasons = append(c.Reasons, fmt.Sprintf("%d %s", n.v, n.what))
		}
	}
	c.RestartOK = len(c.Reasons) == 0
	return c
}

func (b *broker) handleRestartCheck(w http.ResponseWriter, id string) {
	h := b.hotelByID(id)
	if h == nil {
		writeErr(w, 404, "hotel_not_found", "no hotel "+id)
		return
	}
	b.mu.Lock()
	c := b.restartCheckLocked(h)
	b.mu.Unlock()
	if c.RestartOK {
		writeJSON(w, 200, c)
		return
	}
	writeJSON(w, 409, map[string]any{"error": map[string]any{"code": "restart_refused",
		"message": "restart of hotel " + id + " refused: " + strings.Join(c.Reasons, "; ") +
			". A hotel restarts only when it is drained and holds 0 rooms; drain it and wait for rooms to leave."},
		"check": c})
}
