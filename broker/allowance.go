// Metered guests: the ledger's allowance at the front door.
//
// A guest is metered when its config says "metered": true or an operator has
// sent it an allowance. A metered guest is admitted only on the ledger's
// word, and it starts closed: cap 0 and no lease, so every create is refused
// until the ledger sends an allowance. A guest that is not metered behaves as
// before.
//
// The ledger sends and reads the allowance with the operator key:
//
//	PUT /v1/broker/guests/<id>/allowance  {"issue", "cap", "lease_seconds", "max_ttl_seconds", "max_memory_gib"}
//	GET /v1/broker/guests/<id>/allowance  the allowance, live rooms and the lease seconds left
//
// A PUT marks the guest metered, stamps ledger_seen_at with the broker's
// clock and keeps the allowance in state_dir/guest-allowances.json (a
// temporary file, synced, then renamed; mode 0600). Each PUT carries an
// issue above the stored one; an issue at or below it is stale: 409
// stale_allowance, and nothing changes. After a restart the file is read
// again: a cap of 0 stays 0, and a lease keeps its ledger_seen_at, so it can
// expire across the restart. A file that is missing or does not parse leaves
// every metered guest closed; one that does not parse is moved aside.
//
// A metered create, and each lifetime extension of a metered room, is refused:
//   - 503 allowance_recount with Retry-After until every hotel the guest may
//     use (or has had rooms on) has answered one room list since the broker
//     started: until then its rooms there are not counted;
//   - 402 allowance_lease_expired when the lease is older than lease_seconds,
//     or there is none;
//   - 402 allowance_exhausted when the live rooms plus the new ones would pass
//     the cap (an extension: when the live rooms pass the cap).
//
// Live rooms of a metered guest are its creates in flight and every room the
// broker still holds for it, rooms being removed included, until the sync
// loop lets them go.
//
// A metered create always sends ttl_seconds of at most max_ttl_seconds (the
// maximum when absent) and resources.memory_gib (4, the hotel default, when
// absent); a create that asks for more memory than max_memory_gib is refused
// 400 memory_limit before any hotel call. Each route that resets a room's
// deadline at the hotel (PATCH on the room, POST heartbeat, POST and PATCH
// lifetime, the client lifetime route) is a new admission: it sends
// ttl_seconds of at most max_ttl_seconds, and a refused one sends nothing, so
// the room keeps the deadline it has. A room claim (room kit) is refused for
// a metered guest: it sets a lifetime this gate does not see.
//
// Nothing here stops or deletes a running room.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	allowancesFile = "guest-allowances.json"
	// allowanceLeaseRetry is the Retry-After of allowance_lease_expired: the
	// ledger renews about once a minute.
	allowanceLeaseRetry = 30
	// allowanceRecountRetry is the Retry-After of allowance_recount: hotels
	// list their rooms every 2 s.
	allowanceRecountRetry = 5
	// maxAllowanceTTLSeconds is the longest ttl_seconds a hotel takes.
	maxAllowanceTTLSeconds = 48 * 3600
	// hotelDefaultMemoryGiB is the memory_gib a hotel gives a create that
	// names none (cathedral/sandbox_api.py Resources).
	hotelDefaultMemoryGiB = 4
)

// guestAllowance is what the ledger last sent for one guest. A stored value
// is never changed in place: a PUT stores a new one.
type guestAllowance struct {
	Issue         int64     `json:"issue"`
	Cap           int       `json:"cap"`
	LeaseSeconds  int       `json:"lease_seconds"`
	MaxTTLSeconds int       `json:"max_ttl_seconds"`
	MaxMemoryGiB  int       `json:"max_memory_gib"`
	LedgerSeenAt  time.Time `json:"ledger_seen_at"` // broker clock at the PUT
}

// fresh reports whether the lease holds at now. A ledger_seen_at after now
// (the clock went back across a restart) is not fresh.
func (a *guestAllowance) fresh(now time.Time) bool {
	if a == nil || a.LeaseSeconds <= 0 || a.LedgerSeenAt.IsZero() {
		return false
	}
	age := now.Sub(a.LedgerSeenAt)
	return age >= 0 && age <= time.Duration(a.LeaseSeconds)*time.Second
}

// usable reports whether a stored allowance may open admission: a lease
// needs an issue and positive limits. The closed form (all zero) is valid
// too; it never opens anything.
func (a *guestAllowance) usable() bool {
	if a.Issue < 0 || a.Cap < 0 || a.LeaseSeconds < 0 || a.MaxTTLSeconds < 0 || a.MaxTTLSeconds > maxAllowanceTTLSeconds || a.MaxMemoryGiB < 0 {
		return false
	}
	return a.LeaseSeconds == 0 || (a.Issue >= 1 && a.MaxTTLSeconds >= 1 && a.MaxMemoryGiB >= 1)
}

type allowanceFile struct {
	Version int                       `json:"version"`
	Guests  map[string]guestAllowance `json:"guests"`
}

// allowances is the metered guest state of a broker.
type allowances struct {
	saveMu sync.Mutex // one PUT at a time, from the stale check through the rename
	// byGuest is guest id -> allowance, for every guest in the file, also
	// guests not in the config now (kept for when they come back). Guarded
	// by broker.mu; a PUT replaces the whole map.
	byGuest map[string]*guestAllowance
}

// meteredLocked reports whether g is metered, and its allowance (nil: none
// yet, which is closed). Caller holds b.mu.
func (b *broker) meteredLocked(g *guestState) (bool, *guestAllowance) {
	a, stored := b.allow.byGuest[g.cfg.ID]
	return stored || g.limits.Metered, a
}

// meteredLiveLocked counts the rooms a metered guest holds: creates admitted
// and not yet placed or failed, and every room the broker still has for it,
// rooms being removed included, until the sync loop lets them go. Caller
// holds b.mu.
func (b *broker) meteredLiveLocked(g *guestState) int {
	n := g.pending
	for _, h := range b.hotelList() {
		for _, rm := range h.rooms {
			if rm.guest == g.cfg.ID {
				n++
			}
		}
	}
	return n
}

// recountPendingLocked reports whether a hotel that g may use, or has had
// rooms on, has not answered a room list since the broker started: the
// guest's rooms there are not counted yet. Caller holds b.mu.
func (b *broker) recountPendingLocked(g *guestState) bool {
	for _, h := range b.hotelList() {
		if h.roomsUnchecked && (g.allowsHotel(h) || len(b.guestRooms[g.cfg.ID][h.cfg.ID]) > 0) {
			return true
		}
	}
	return false
}

// allowanceRefusalLocked says why metered guest g may not add n rooms now
// (n = 0: extend a room it has), with the Retry-After seconds. nil: g is not
// metered, or it is within its allowance. Caller holds b.mu.
func (b *broker) allowanceRefusalLocked(g *guestState, n int, now time.Time) (*apiErr, int) {
	metered, a := b.meteredLocked(g)
	if !metered {
		return nil, 0
	}
	if b.recountPendingLocked(g) {
		return &apiErr{503, "allowance_recount", "this key is sold out right now while the broker counts its rooms after a restart; try again shortly"}, allowanceRecountRetry
	}
	if !a.fresh(now) {
		return &apiErr{402, "allowance_lease_expired", "this key is sold out right now; try again shortly"}, allowanceLeaseRetry
	}
	if live := b.meteredLiveLocked(g); live+n > a.Cap {
		if a.Cap == 0 {
			return &apiErr{402, "allowance_exhausted", "this key has no allowance for rooms right now; add credit to the account, then try again"}, 0
		}
		return &apiErr{402, "allowance_exhausted", fmt.Sprintf("this key's allowance is %d rooms at one time and %d are running, starting or being removed; delete rooms or add credit to the account", a.Cap, live)}, 0
	}
	return nil, 0
}

// meteredCreate checks a metered guest's create of n rooms before any hotel
// call and applies its size and lifetime limits to payload, the body the
// hotel receives. admit checks the allowance again, under the lock that
// reserves the rooms. A guest that is not metered: no change.
func (b *broker) meteredCreate(g *guestState, payload map[string]any, n int) (*apiErr, int) {
	b.mu.Lock()
	metered, a := b.meteredLocked(g)
	e, retry := b.allowanceRefusalLocked(g, n, time.Now())
	b.mu.Unlock()
	if !metered {
		return nil, 0
	}
	if e != nil {
		return e, retry
	}
	// A fresh lease means a stored allowance: a is not nil here.
	if e := limitCreateMemory(payload, a.MaxMemoryGiB); e != nil {
		return e, 0
	}
	if e := limitCreateTTL(payload, a.MaxTTLSeconds); e != nil {
		return e, 0
	}
	afterMeteredCheck()
	return nil, 0
}

// afterMeteredCheck runs between a metered create's early check and its
// reservation in admit. Tests hold creates there to prove the reservation
// alone keeps the cap.
var afterMeteredCheck = func() {}

// numberOf is v as a number: a JSON number decoded by encoding/json, or an
// int the broker set itself (compat.go).
func numberOf(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

// limitCreateMemory makes resources.memory_gib explicit (the hotel default
// when absent) and refuses more than limit GiB.
func limitCreateMemory(payload map[string]any, limit int) *apiErr {
	if payload["resources"] == nil {
		payload["resources"] = map[string]any{}
	}
	res, ok := payload["resources"].(map[string]any)
	if !ok {
		return &apiErr{400, "invalid_resources", "resources must be an object"}
	}
	if res["memory_gib"] == nil {
		res["memory_gib"] = hotelDefaultMemoryGiB
	}
	gib, ok := numberOf(res["memory_gib"])
	if !ok {
		return &apiErr{400, "invalid_resources", "resources.memory_gib must be a number"}
	}
	if gib > float64(limit) {
		return &apiErr{400, "memory_limit", fmt.Sprintf("this key may ask for at most %d GiB of memory per room; this create asks for %v (resources.memory_gib, %d when absent)", limit, res["memory_gib"], hotelDefaultMemoryGiB)}
	}
	return nil
}

// limitCreateTTL sets ttl_seconds to at most limit: limit when absent or
// more. A value that is not a number of seconds is refused.
func limitCreateTTL(payload map[string]any, limit int) *apiErr {
	if payload["ttl_seconds"] == nil {
		payload["ttl_seconds"] = limit
		return nil
	}
	ttl, ok := numberOf(payload["ttl_seconds"])
	if !ok || ttl < 1 {
		return &apiErr{400, "invalid_ttl", "ttl_seconds must be a number of seconds, 1 or more"}
	}
	if ttl > float64(limit) {
		payload["ttl_seconds"] = limit
	}
	return nil
}

// meteredExtension checks one lifetime extension of metered guest g. It
// returns the largest ttl_seconds the extension may send (0: g is not
// metered, no limit here), or why it is refused.
func (b *broker) meteredExtension(g *guestState) (int, *apiErr, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	metered, a := b.meteredLocked(g)
	if !metered {
		return 0, nil, 0
	}
	if e, retry := b.allowanceRefusalLocked(g, 0, time.Now()); e != nil {
		return 0, e, retry
	}
	return a.MaxTTLSeconds, nil, 0
}

// lifetimeRoute reports whether a room request (tail after the room id, gate
// its first segment without ";params") resets the room's deadline at the
// hotel: PATCH on the room, POST heartbeat, POST and PATCH lifetime
// (cathedral/sandbox_server.py, all the provider's heartbeat). The hotel
// matches methods in any case and drops ";params" from the last segment, so
// this does too. Other writing methods on these paths count as well: the
// hotel has no other route there.
func lifetimeRoute(method, gate, tail string) bool {
	if strings.Contains(tail, "/") {
		return false
	}
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "DELETE":
		return false
	}
	return gate == "" || gate == "heartbeat" || gate == "lifetime"
}

// meteredRoomRoute gates the room routes of a metered guest that set a
// room's lifetime. It returns the body to send to the hotel (the request
// body unless it is changed here) and false when it has written the answer
// and nothing may go to the hotel. A guest that is not metered, or a route
// that sets no lifetime, passes unchanged.
func (b *broker) meteredRoomRoute(w http.ResponseWriter, r *http.Request, g *guestState, h *hotel, hid, gate, tail string, body []byte) ([]byte, bool) {
	isClaim := gate == "claim" && !strings.Contains(tail, "/")
	if !isClaim && !lifetimeRoute(r.Method, gate, tail) {
		return body, true
	}
	b.mu.Lock()
	metered, _ := b.meteredLocked(g)
	b.mu.Unlock()
	if !metered {
		return body, true
	}
	if isClaim {
		writeErr(w, 403, "claim_refused_metered", "a room claim sets a lifetime outside this key's allowance; it is refused for a metered key")
		return nil, false
	}
	maxTTL, e, retry := b.meteredExtension(g)
	if e != nil {
		writeLimitErr(w, e, retry)
		return nil, false
	}
	doc := map[string]any{}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &doc); err != nil || doc == nil {
			writeErr(w, 400, "invalid_json", "a lifetime request body must be a JSON object")
			return nil, false
		}
	}
	ask := 0.0
	if v := doc["ttl_seconds"]; v != nil {
		n, ok := numberOf(v)
		if !ok || n < 1 {
			writeErr(w, 400, "invalid_ttl", "ttl_seconds must be a number of seconds, 1 or more")
			return nil, false
		}
		ask = n
	} else {
		// No ttl_seconds: the hotel would reuse the room's own. Send that
		// explicitly, so the room never gets more than it asked for.
		own, ok := roomTTLSeconds(r, h, hid)
		if !ok {
			writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not say the room's ttl_seconds; send ttl_seconds")
			return nil, false
		}
		ask = own
	}
	doc["ttl_seconds"] = int(math.Min(math.Floor(ask), float64(maxTTL)))
	out, _ := json.Marshal(doc)
	return out, true
}

// roomTTLSeconds reads ttl_seconds from the hotel's room document.
func roomTTLSeconds(r *http.Request, h *hotel, hid string) (float64, bool) {
	status, _, out, err := h.do(r.Context(), "GET", "/v1/sandboxes/"+url.PathEscape(hid), nil, nil, 30*time.Second)
	if err != nil || status != 200 {
		return 0, false
	}
	var doc struct {
		TTL *float64 `json:"ttl_seconds"`
	}
	if json.Unmarshal(out, &doc) != nil || doc.TTL == nil || *doc.TTL < 1 {
		return 0, false
	}
	return *doc.TTL, true
}

// ---------------------------------------------------------------- operator routes

// allowancePath is the guest id of an operator path "<id>/allowance" under
// /v1/broker/guests/.
func allowancePath(rest string) (string, bool) {
	id, ok := strings.CutSuffix(rest, "/allowance")
	if !ok || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

// handleAllowance serves GET and PUT /v1/broker/guests/<id>/allowance. The
// caller has checked the operator key.
func (b *broker) handleAllowance(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case "GET":
		b.mu.Lock()
		defer b.mu.Unlock()
		g := b.guests[id]
		if g == nil {
			writeErr(w, 404, "guest_not_found", "no guest "+id)
			return
		}
		writeJSON(w, 200, b.allowanceViewLocked(g, time.Now()))
	case "PUT":
		b.putAllowance(w, r, id)
	default:
		writeErr(w, 404, "route_not_found", "no such guest route")
	}
}

func (b *broker) putAllowance(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Issue         *int64 `json:"issue"`
		Cap           *int   `json:"cap"`
		LeaseSeconds  *int   `json:"lease_seconds"`
		MaxTTLSeconds *int   `json:"max_ttl_seconds"`
		MaxMemoryGiB  *int   `json:"max_memory_gib"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		writeErr(w, 400, "invalid_json", "body must be one JSON object with issue, cap, lease_seconds, max_ttl_seconds and max_memory_gib, all whole numbers")
		return
	}
	bad := ""
	switch {
	case req.Issue == nil || req.Cap == nil || req.LeaseSeconds == nil || req.MaxTTLSeconds == nil || req.MaxMemoryGiB == nil:
		bad = "issue, cap, lease_seconds, max_ttl_seconds and max_memory_gib are all required"
	case *req.Issue < 1:
		bad = "issue must be 1 or more"
	case *req.Cap < 0:
		bad = "cap must be 0 or more"
	case *req.LeaseSeconds < 1:
		bad = "lease_seconds must be 1 or more"
	case *req.MaxTTLSeconds < 1 || *req.MaxTTLSeconds > maxAllowanceTTLSeconds:
		bad = fmt.Sprintf("max_ttl_seconds must be between 1 and %d", maxAllowanceTTLSeconds)
	case *req.MaxMemoryGiB < 1:
		bad = "max_memory_gib must be 1 or more"
	}
	if bad != "" {
		writeErr(w, 400, "invalid_allowance", bad)
		return
	}
	if b.cfg.StateDir == "" {
		writeErr(w, 409, "no_state_dir", "the broker has no state_dir, so it cannot keep an allowance")
		return
	}
	b.allow.saveMu.Lock()
	defer b.allow.saveMu.Unlock()
	b.mu.Lock()
	g := b.guests[id]
	if g == nil {
		b.mu.Unlock()
		writeErr(w, 404, "guest_not_found", "no guest "+id)
		return
	}
	if old := b.allow.byGuest[id]; old != nil && *req.Issue <= old.Issue {
		b.mu.Unlock()
		writeErr(w, 409, "stale_allowance", fmt.Sprintf("issue %d is not above the stored issue %d; nothing changed", *req.Issue, old.Issue))
		return
	}
	a := &guestAllowance{Issue: *req.Issue, Cap: *req.Cap, LeaseSeconds: *req.LeaseSeconds,
		MaxTTLSeconds: *req.MaxTTLSeconds, MaxMemoryGiB: *req.MaxMemoryGiB, LedgerSeenAt: time.Now()}
	next := make(map[string]*guestAllowance, len(b.allow.byGuest)+1)
	for k, v := range b.allow.byGuest {
		next[k] = v
	}
	next[id] = a
	b.mu.Unlock()
	// Written before it applies: a write that fails changes nothing.
	if err := b.saveAllowances(next); err != nil {
		log.Printf("guest allowance for %s not written: %v", id, err)
		writeErr(w, 500, "state_write_failed", "could not write "+allowancesFile+"; nothing changed")
		return
	}
	b.mu.Lock()
	b.allow.byGuest = next
	view := b.allowanceViewLocked(g, time.Now())
	b.mu.Unlock()
	writeJSON(w, 200, view)
}

// allowanceViewLocked is the operator view of g's allowance. Caller holds b.mu.
func (b *broker) allowanceViewLocked(g *guestState, now time.Time) map[string]any {
	metered, a := b.meteredLocked(g)
	if !metered {
		return map[string]any{"guest": g.cfg.ID, "metered": false, "live_rooms": b.activeRooms(g)}
	}
	if a == nil {
		a = &guestAllowance{} // closed: cap 0, no lease
	}
	var seen any // null: the ledger has sent nothing
	if !a.LedgerSeenAt.IsZero() {
		seen = a.LedgerSeenAt.UTC().Format(time.RFC3339Nano)
	}
	left := 0
	if a.fresh(now) {
		left = int((time.Duration(a.LeaseSeconds)*time.Second - now.Sub(a.LedgerSeenAt)).Seconds())
	}
	return map[string]any{
		"guest": g.cfg.ID, "metered": true, "issue": a.Issue, "cap": a.Cap, "lease_seconds": a.LeaseSeconds,
		"max_ttl_seconds": a.MaxTTLSeconds, "max_memory_gib": a.MaxMemoryGiB, "ledger_seen_at": seen,
		"live_rooms": b.meteredLiveLocked(g), "lease_fresh": a.fresh(now), "lease_seconds_left": left,
		"recount_pending": b.recountPendingLocked(g),
	}
}

// ---------------------------------------------------------------- state_dir

// saveAllowances writes m to state_dir: a temporary file, synced, renamed
// over the old one, then the directory synced. Caller holds b.allow.saveMu.
func (b *broker) saveAllowances(m map[string]*guestAllowance) error {
	out := allowanceFile{Version: 1, Guests: make(map[string]guestAllowance, len(m))}
	for id, a := range m {
		c := *a
		if !c.LedgerSeenAt.IsZero() {
			c.LedgerSeenAt = c.LedgerSeenAt.UTC()
		}
		out.Guests[id] = c
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return err
	}
	final := filepath.Join(b.cfg.StateDir, allowancesFile)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil { // a leftover tmp file keeps its old mode
		f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	// The rename is done; a directory that cannot sync is logged only.
	if d, err := os.Open(b.cfg.StateDir); err == nil {
		if err := d.Sync(); err != nil {
			log.Printf("%s: state_dir not synced after the rename: %v", allowancesFile, err)
		}
		d.Close()
	}
	return nil
}

// loadAllowances reads state_dir/guest-allowances.json at start. A metered
// guest needs state_dir. A missing file leaves every metered guest closed. A
// file that does not parse is moved aside and leaves every metered guest
// closed, as does one entry that is not usable (that guest stays metered).
// A file that cannot be read stops the broker: starting without it could
// open a guest the file meters.
func (b *broker) loadAllowances() error {
	b.allow.byGuest = map[string]*guestAllowance{}
	for id, g := range b.guests {
		if g.limits.Metered && b.cfg.StateDir == "" {
			return fmt.Errorf("config: guest %q is metered, which needs state_dir to keep its allowance", id)
		}
	}
	if b.cfg.StateDir == "" {
		return nil
	}
	path := filepath.Join(b.cfg.StateDir, allowancesFile)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var f allowanceFile
	if err := json.Unmarshal(raw, &f); err != nil || f.Version != 1 || f.Guests == nil {
		aside := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
		if rerr := os.Rename(path, aside); rerr != nil {
			log.Printf("%s does not parse (%v) and was not moved aside: %v; metered guests stay closed until the ledger sends an allowance", path, err, rerr)
			return nil
		}
		log.Printf("%s does not parse (%v); moved to %s; metered guests stay closed until the ledger sends an allowance", path, err, aside)
		return nil
	}
	for id, a := range f.Guests {
		if !a.usable() {
			log.Printf("%s: guest %s: the stored allowance is not usable; the guest stays metered and closed until the ledger sends an allowance", path, id)
			a = guestAllowance{}
		}
		b.allow.byGuest[id] = &a
	}
	return nil
}
