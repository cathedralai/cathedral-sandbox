// Per-guest limits.
//
// Each guest in the config can have limits:
//
//	"max_rooms": 1000              rooms running or starting at one time (0 or absent: 1,000)
//	"max_creates_per_minute": 600  rooms the guest may ask for in any 60 s (0 or absent: no limit)
//	"default_sealed": true         kept and echoed only; it changes no placement (below)
//	"hotels": ["a", "b"]           the guest may use only these hotels (absent: all non-miner hotels)
//	"policy": {prefer, allow, deny} hotels by selector; replaces "hotels" (capacity.go)
//	"own_hosts_only": true         never a miner hotel, whatever the policy says (reserved customers)
//	"ops": true                    the guest may run the probe and reset the broker counters
//
// Every hotel is sealed (AB#776), so every room is sealed and
// "default_sealed" no longer changes where a create goes. The field stays
// because live configs set it and the loader refuses unknown fields, and
// /v1/quota and the guest views still echo it for the guards that read it.
// A fork goes to the hotel of its snapshot.
//
// An operator (operator key) reads and changes limits at runtime:
//
//	GET   /v1/broker/guests        every guest with its limits and room counts
//	PATCH /v1/broker/guests/<id>   {"max_rooms", "max_creates_per_minute", "default_sealed", "hotels", "policy", "own_hosts_only"}
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
	// Policy, when set, replaces Hotels (capacity.go). It is never changed
	// in place: a PATCH stores a new value.
	Policy *guestPolicy `json:"policy,omitempty"`
	// OwnHostsOnly keeps every room of the guest on Cathedral's own hotels:
	// placement never picks a miner hotel (isMinerHotel), even when the
	// policy opts into miner hotels. For reserved customers (const). It is
	// the guest-wide form of the create flag "own_hosts_only" (images.go).
	OwnHostsOnly bool `json:"own_hosts_only,omitempty"`
}

func (l guestLimits) maxRooms() int {
	if l.MaxRooms > 0 {
		return l.MaxRooms
	}
	return defaultMaxRooms
}

// tierOf is the policy tier of h ("prefer" or "allow"), "hotels" when the
// guest has no policy and its hotel list allows h, or "" when h is out of
// reach.
// It does not look at hotel reservations; guestState.tierOf does.
func (l guestLimits) tierOf(h *hotel) string {
	if h.cfg.MinerHotkey != "" && !l.Policy.minerOptIn(h) {
		return ""
	}
	if l.Policy != nil {
		return l.Policy.tier(h)
	}
	if l.allows(h.cfg.ID) {
		return "hotels"
	}
	return ""
}

// allows reports whether the hotel list (no policy) allows hotel id. Miner
// hotels are separately denied by tierOf without an explicit miner policy.
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
	// One call larger than a limit can never pass: say so (400), rather
	// than a 429 whose Retry-After a client obeys forever (AB#865).
	if n > lim.maxRooms() {
		return &apiErr{400, "count_over_room_limit", fmt.Sprintf("this key may have %d rooms at one time; one create asked for %d. Send at most %d in one call", lim.maxRooms(), n, lim.maxRooms())}, 0
	}
	if lim.MaxCreatesPerMinute > 0 && n > lim.MaxCreatesPerMinute {
		return &apiErr{400, "count_over_rate_limit", fmt.Sprintf("this key may ask for %d rooms per minute; one create asked for %d. Send at most %d in one call", lim.MaxCreatesPerMinute, n, lim.MaxCreatesPerMinute)}, 0
	}
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

// scope applies the guest's hotel set or policy to pl.
func (b *broker) scope(g *guestState, pl *placement) {
	b.mu.Lock()
	lim := g.limits
	b.mu.Unlock()
	pl.guest = g.cfg.ID // a hotel reserved for another guest is never a candidate
	// OR, not assign: the create may already have set the flag, and the
	// policy branch below returns early.
	pl.ownHostsOnly = pl.ownHostsOnly || lim.OwnHostsOnly
	if lim.Policy != nil {
		// The policy replaces the hotel list: it names the hotels the guest
		// may use, in order (pick).
		pl.policy = lim.Policy
		return
	}
	if len(lim.Hotels) > 0 {
		pl.allowed = map[string]bool{}
		for _, id := range lim.Hotels {
			pl.allowed[id] = true
		}
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
		"active_rooms": b.activeRooms(g), "policy": lim.Policy, "own_hosts_only": lim.OwnHostsOnly,
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
		MaxRooms            *int            `json:"max_rooms"`
		MaxCreatesPerMinute *int            `json:"max_creates_per_minute"`
		DefaultSealed       *bool           `json:"default_sealed"`
		Hotels              *[]string       `json:"hotels"`
		Policy              json.RawMessage `json:"policy"` // null clears the policy
		OwnHostsOnly        *bool           `json:"own_hosts_only"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, 400, "invalid_json", "body must be a JSON object with max_rooms, max_creates_per_minute, default_sealed, hotels, policy or own_hosts_only")
		return
	}
	if (req.MaxRooms != nil && *req.MaxRooms < 0) || (req.MaxCreatesPerMinute != nil && *req.MaxCreatesPerMinute < 0) {
		writeErr(w, 400, "invalid_limit", "limits must be 0 or more")
		return
	}
	// In config, an absent list and max_rooms 0 mean "all hotels" and 1,000
	// rooms. A PATCH that sends [] or 0 means the opposite, so refuse it.
	if req.Hotels != nil && len(*req.Hotels) == 0 {
		writeErr(w, 400, "invalid_limit", "hotels must name at least one hotel; an empty list would mean every hotel")
		return
	}
	if req.MaxRooms != nil && *req.MaxRooms == 0 {
		writeErr(w, 400, "invalid_limit", "max_rooms must be 1 or more; 0 would mean 1,000")
		return
	}
	if req.Hotels != nil {
		for _, h := range *req.Hotels {
			if b.hotelByID(h) == nil {
				writeErr(w, 409, "unknown_hotel", fmt.Sprintf("no hotel %q", h))
				return
			}
		}
	}
	var policy *guestPolicy
	clearPolicy := string(req.Policy) == "null"
	if len(req.Policy) > 0 && !clearPolicy {
		pdec := json.NewDecoder(strings.NewReader(string(req.Policy)))
		pdec.DisallowUnknownFields()
		policy = &guestPolicy{}
		if err := pdec.Decode(policy); err != nil {
			writeErr(w, 400, "invalid_policy", "policy must be an object with prefer, allow and deny lists of selectors")
			return
		}
		if err := policy.validate(); err != nil {
			writeErr(w, 400, "invalid_policy", err.Error())
			return
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
	if policy != nil || clearPolicy {
		g.limits.Policy = policy
	}
	if req.OwnHostsOnly != nil {
		g.limits.OwnHostsOnly = *req.OwnHostsOnly
	}
	writeJSON(w, 200, b.guestView(g))
}

// limitsAllow reports whether g may use hotel id. With a policy, an id that
// is not a hotel now is out of reach.
func (g *guestState) limitsAllow(b *broker, id string) bool {
	h := b.hotelByID(id)
	b.mu.Lock()
	defer b.mu.Unlock()
	if h == nil {
		return g.limits.Policy == nil && g.limits.allows(id)
	}
	return g.allowsHotel(h)
}

// allowsHotel reports whether g may use hotel h: the hotel is not reserved
// for another guest, and the policy reaches it (or, with no policy, the hotel
// list holds it).
func (g *guestState) allowsHotel(h *hotel) bool {
	return g.tierOf(h) != ""
}

// guestReaches reports whether h is one of g's hotels as placement sees them:
// allowed, and not a miner hotel for an own-hosts-only guest. Every guest view
// of hotels (capacity, /v1/broker/hotels, /v1/status) counts these and no
// others (AB#869). Caller holds b.mu.
func (g *guestState) guestReaches(h *hotel) bool {
	return g.allowsHotel(h) && !(g.limits.OwnHostsOnly && isMinerHotel(h))
}

// tierOf is guestLimits.tierOf behind the hotel reservation: a hotel
// reserved for another guest is out of reach, as if denied, and so is a
// hotel lent from this guest to the pool (lend.go). Caller holds b.mu.
func (g *guestState) tierOf(h *hotel) string {
	if r := h.reservedFor(); r != "" && r != g.cfg.ID {
		return ""
	}
	if h.lentFrom() == g.cfg.ID {
		return ""
	}
	return g.limits.tierOf(h)
}
