// Per-guest limits.
//
// Each guest in the config can have limits:
//
//	"max_rooms": 1000              rooms running or starting at one time (0 or absent: 1,000)
//	"max_creates_per_minute": 600  rooms the guest may ask for in any 60 s (0 or absent: no limit)
//	"default_sealed": true         a create with no hotel choice goes to sealed hotels only
//	"hotels": ["a", "b"]           the guest may use only these hotels (absent: all hotels)
//	"ops": true                    the guest may run the probe and reset the broker counters
//
// With "default_sealed", a create gets an unsealed room only when it says
// "sealed": false, names hotels with "hotels", or excludes sealed hotels
// with "exclude_hotel_labels". A fork goes to the hotel of its snapshot.
//
// An operator (operator key) reads and changes limits at runtime:
//
//	GET   /v1/broker/guests        every guest with its limits and room counts
//	PATCH /v1/broker/guests/<id>   {"max_rooms", "max_creates_per_minute", "default_sealed", "hotels"}
//
// A runtime change stays in memory only. A restart goes back to the config
// file, so change the config file to keep a limit.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultMaxRooms = 1000

type guestLimits struct {
	MaxRooms            int      `json:"max_rooms"`
	MaxCreatesPerMinute int      `json:"max_creates_per_minute"`
	DefaultSealed       bool     `json:"default_sealed"`
	Hotels              []string `json:"hotels"`
}

func (l guestLimits) maxRooms() int {
	if l.MaxRooms > 0 {
		return l.MaxRooms
	}
	return defaultMaxRooms
}

// allows reports whether the guest may use hotel id.
func (l guestLimits) allows(id string) bool {
	if len(l.Hotels) == 0 {
		return true
	}
	for _, x := range l.Hotels {
		if x == id {
			return true
		}
	}
	return false
}

// activeRooms counts the guest's rooms that run now plus the rooms it has
// asked for that are not placed yet. Caller holds b.mu.
func (b *broker) activeRooms(g *guestState) int {
	n := g.pending
	for _, h := range b.hotelList() {
		for _, rm := range h.rooms {
			if rm.guest == g.cfg.ID && rm.state == stRunning {
				n++
			}
		}
	}
	return n
}

// admit reserves n rooms for g against its room and rate limits. On success
// the caller calls release(g, 1) once for each room when its create ends.
func (b *broker) admit(g *guestState, n int) (*apiErr, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	lim := g.limits
	if used := b.activeRooms(g); used+n > lim.maxRooms() {
		return &apiErr{429, "room_limit", fmt.Sprintf("this key may have %d rooms at one time; %d are running or starting. Delete rooms, or ask Cathedral for a higher limit", lim.maxRooms(), used)}, 10
	}
	if lim.MaxCreatesPerMinute > 0 {
		now := time.Now()
		cut := 0
		for cut < len(g.admits) && now.Sub(g.admits[cut]) >= time.Minute {
			cut++
		}
		g.admits = g.admits[cut:]
		if len(g.admits)+n > lim.MaxCreatesPerMinute {
			wait := 60
			if len(g.admits) > 0 && n <= lim.MaxCreatesPerMinute {
				// The time until enough earlier creates leave the window.
				idx := len(g.admits) + n - lim.MaxCreatesPerMinute - 1
				wait = int(math.Ceil((time.Minute - now.Sub(g.admits[idx])).Seconds()))
				if wait < 1 {
					wait = 1
				}
			}
			return &apiErr{429, "create_rate_limit", fmt.Sprintf("this key may ask for %d rooms per minute", lim.MaxCreatesPerMinute)}, wait
		}
		for i := 0; i < n; i++ {
			g.admits = append(g.admits, now)
		}
	}
	g.pending += n
	return nil, 0
}

// unreserve gives back n rooms that admit reserved.
func (b *broker) unreserve(g *guestState, n int) {
	b.mu.Lock()
	g.pending -= n
	b.mu.Unlock()
}

func writeLimitErr(w http.ResponseWriter, e *apiErr, retryAfter int) {
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	writeErr(w, e.status, e.code, e.msg)
}

// scope applies the guest's hotel set and sealed default to pl. named: the
// create names hotels. sealedField: the create has a "sealed" field.
func (b *broker) scope(g *guestState, pl *placement, named, sealedField bool) {
	b.mu.Lock()
	lim := g.limits
	b.mu.Unlock()
	if len(lim.Hotels) > 0 {
		pl.allowed = map[string]bool{}
		for _, id := range lim.Hotels {
			pl.allowed[id] = true
		}
	}
	if lim.DefaultSealed && !named && !sealedField && pl.match["sealed"] == "" && pl.exclude["sealed"] == "" {
		if pl.match == nil {
			pl.match = map[string]string{}
		}
		pl.match["sealed"] = "true"
		pl.sealedByDefault = true
	}
}

// ---------------------------------------------------------------- operator routes

func (b *broker) guestView(g *guestState) map[string]any {
	lim := g.limits
	hotels := lim.Hotels
	if hotels == nil {
		hotels = []string{}
	}
	return map[string]any{
		"id": g.cfg.ID, "max_rooms": lim.maxRooms(), "max_creates_per_minute": lim.MaxCreatesPerMinute,
		"default_sealed": lim.DefaultSealed, "hotels": hotels, "ops": g.cfg.Ops,
		"active_rooms": b.activeRooms(g),
	}
}

func (b *broker) handleGuestAdmin(w http.ResponseWriter, r *http.Request, id string) {
	if !b.isOperator(r) {
		writeErr(w, 401, "unauthorized", "operator key required")
		return
	}
	switch {
	case id == "" && r.Method == "GET":
		b.mu.Lock()
		out := []map[string]any{}
		for _, g := range b.guests {
			out = append(out, b.guestView(g))
		}
		b.mu.Unlock()
		sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
		writeJSON(w, 200, map[string]any{"guests": out})
	case id != "" && r.Method == "PATCH":
		b.patchGuest(w, r, id)
	default:
		writeErr(w, 404, "route_not_found", "no such guest route")
	}
}

func (b *broker) patchGuest(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		MaxRooms            *int      `json:"max_rooms"`
		MaxCreatesPerMinute *int      `json:"max_creates_per_minute"`
		DefaultSealed       *bool     `json:"default_sealed"`
		Hotels              *[]string `json:"hotels"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, 400, "invalid_json", "body must be a JSON object with max_rooms, max_creates_per_minute, default_sealed or hotels")
		return
	}
	if (req.MaxRooms != nil && *req.MaxRooms < 0) || (req.MaxCreatesPerMinute != nil && *req.MaxCreatesPerMinute < 0) {
		writeErr(w, 400, "invalid_limit", "limits must be 0 or more")
		return
	}
	if req.Hotels != nil {
		for _, h := range *req.Hotels {
			if b.hotelByID(h) == nil {
				writeErr(w, 400, "unknown_hotel", fmt.Sprintf("no hotel %q", h))
				return
			}
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	g := b.guests[id]
	if g == nil {
		writeErr(w, 404, "guest_not_found", "no guest "+id)
		return
	}
	if req.MaxRooms != nil {
		g.limits.MaxRooms = *req.MaxRooms
	}
	if req.MaxCreatesPerMinute != nil {
		g.limits.MaxCreatesPerMinute = *req.MaxCreatesPerMinute
	}
	if req.DefaultSealed != nil {
		g.limits.DefaultSealed = *req.DefaultSealed
	}
	if req.Hotels != nil {
		g.limits.Hotels = append([]string(nil), (*req.Hotels)...)
	}
	writeJSON(w, 200, b.guestView(g))
}

// limitsAllow reports whether g may use hotel id.
func (g *guestState) limitsAllow(b *broker, id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return g.limits.allows(id)
}

// anyHotel reports whether some hotel matches pl, full or not.
func (b *broker) anyHotel(pl placement) bool {
	for _, h := range b.hotelList() {
		if pl.allows(h) {
			return true
		}
	}
	return false
}

func (b *broker) compatImageByID(v any) *compatImage {
	id, _ := v.(string)
	b.compat.mu.Lock()
	defer b.compat.mu.Unlock()
	return b.compat.images[id]
}
