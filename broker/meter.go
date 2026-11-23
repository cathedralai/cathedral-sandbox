// Meter routes (AB#890): an external meter reads one guest's rooms and
// freezes them when that guest's account runs out.
//
// The Polaris API meters const's broker-guest rooms against a Gamma hotkey
// account. It needs two things and nothing more: the guest's rooms with their
// size and state, and a way to put the guest's running rooms to sleep. The
// meter key (config meter_key_sha256) allows exactly these two routes. It is
// not the operator key, the operator read key, a miner key or a guest key, and
// none of those reach these routes. Without meter_key_sha256 both answer 404.
//
//	GET  /v1/broker/guests/{id}/rooms
//	POST /v1/broker/guests/{id}/freeze-all
//
// Both use the guest's own room list fanout (label broker_guest=<id>, only the
// hotels the guest may use). freeze-all calls the hotel route POST
// /v1/sandboxes/{room}/freeze for the guest, on rooms in state "running" only:
// it never deletes and never thaws, and a second call freezes nothing new.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	meterRoomsAction  = "rooms"
	meterFreezeAction = "freeze-all"
	// hotelStateRunning is the hotel's room state that freeze accepts.
	hotelStateRunning = "running"
	// meterFreezeParallel bounds the hotel freeze calls of one freeze-all.
	meterFreezeParallel = 8
)

// meterRoute matches /v1/broker/guests/{id}/rooms and
// /v1/broker/guests/{id}/freeze-all.
func meterRoute(p string) (id, action string, ok bool) {
	rest, found := strings.CutPrefix(p, "/v1/broker/guests/")
	if !found {
		return "", "", false
	}
	id, action, found = strings.Cut(rest, "/")
	if !found || id == "" || (action != meterRoomsAction && action != meterFreezeAction) {
		return "", "", false
	}
	return id, action, true
}

// isMeter is true for the meter key. Only handleMeter checks it.
func (b *broker) isMeter(r *http.Request) bool {
	want := strings.ToLower(b.cfg.MeterKeySHA256)
	a := r.Header.Get("Authorization")
	if want == "" || len(a) < 8 || !strings.EqualFold(a[:7], "bearer ") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sha(strings.TrimSpace(a[7:]))), []byte(want)) == 1
}

func (b *broker) handleMeter(w http.ResponseWriter, r *http.Request, id, action string) {
	if b.cfg.MeterKeySHA256 == "" {
		writeErr(w, 404, "route_not_found", "no such guest route")
		return
	}
	if !b.isMeter(r) {
		writeErr(w, 401, "unauthorized", "meter key required")
		return
	}
	b.mu.Lock()
	g := b.guestByID(id)
	b.mu.Unlock()
	// The ready-room pool guest (pool.go) is the broker's own: its rooms are
	// never a customer's, so the meter neither lists nor freezes them.
	if g == nil || id == poolGuestID {
		writeErr(w, 404, "guest_not_found", "no guest "+id)
		return
	}
	switch {
	case action == meterRoomsAction && r.Method == "GET":
		rooms, errs := b.meterRooms(r.Context(), g)
		writeJSON(w, 200, map[string]any{"rooms": rooms, "hotel_errors": errs})
	case action == meterFreezeAction && r.Method == "POST" && g.limits.Postpaid:
		// A postpaid guest is billed, never frozen for balance (guests.go).
		writeErr(w, 409, "guest_postpaid", "guest "+id+" is postpaid: its rooms are never frozen for balance; nothing changed")
	case action == meterFreezeAction && r.Method == "POST":
		b.meterFreezeAll(w, r, g)
	default:
		writeErr(w, 404, "route_not_found", "no such guest route")
	}
}

// meterRooms is the guest's rooms on every hotel it may use, in the meter's
// shape. A hotel that does not answer is named in the errors and its rooms
// are left out; the call itself does not fail.
func (b *broker) meterRooms(ctx context.Context, g *guestState) ([]map[string]any, map[string]string) {
	q := url.Values{"label": {guestLabel + "=" + g.cfg.ID}}
	rooms := []map[string]any{}
	errs := map[string]string{}
	for hid, raw := range b.fanout(ctx, g, "/v1/sandboxes", q) {
		var doc struct {
			Sandboxes []map[string]any `json:"sandboxes"`
			Error     any              `json:"error"`
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Error != nil {
			errs[hid] = "unavailable"
			continue
		}
		for _, s := range doc.Sandboxes {
			if rm := meterRoom(hid, s); rm != nil {
				rooms = append(rooms, rm)
			}
		}
	}
	sort.Slice(rooms, func(i, j int) bool { return rooms[i]["id"].(string) < rooms[j]["id"].(string) })
	return rooms, errs
}

// meterRoom maps one hotel room document (cathedral/sandbox_provider.py
// _get_doc) to the meter's fields. resources.memory_gib is already whole GiB
// on the hotel, the same number its usage() multiplies into gib_hours. A size
// the hotel did not send is null, never 0, so a meter cannot read it as free.
func meterRoom(hid string, s map[string]any) map[string]any {
	id, _ := s["id"].(string)
	if id == "" {
		return nil
	}
	res, _ := s["resources"].(map[string]any)
	return map[string]any{
		"id":         hid + "." + id,
		"hotel":      hid,
		"state":      s["state"],
		"memory_gib": wholeNumber(res["memory_gib"]),
		"vcpu":       wholeNumber(res["vcpu"]),
		"created_at": s["created_at"],
	}
}

// wholeNumber is a JSON number as an int, or nil when it is absent or not a
// non-negative whole number.
func wholeNumber(v any) any {
	f, ok := v.(float64)
	if !ok || f < 0 || f != float64(int64(f)) {
		return nil
	}
	return int64(f)
}

// meterFreezeAll freezes every running room of g. Rooms in any other state
// (frozen, creating, deleting) are not touched.
func (b *broker) meterFreezeAll(w http.ResponseWriter, r *http.Request, g *guestState) {
	rooms, errs := b.meterRooms(r.Context(), g)
	frozen := []string{}
	failed := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, meterFreezeParallel)
	for _, rm := range rooms {
		if state, _ := rm["state"].(string); state != hotelStateRunning {
			continue
		}
		bid := rm["id"].(string)
		hotelID, hid, _ := strings.Cut(bid, ".")
		h := b.hotelByID(hotelID)
		if h == nil || !g.limitsAllow(b, hotelID) {
			// Freezes already started write failed under mu; so must this one.
			mu.Lock()
			failed[bid] = "hotel_not_found"
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(h *hotel, bid, hid string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			code := freezeRoom(r.Context(), h, g, hid)
			mu.Lock()
			defer mu.Unlock()
			if code == "" {
				frozen = append(frozen, bid)
			} else {
				failed[bid] = code
			}
		}(h, bid, hid)
	}
	wg.Wait()
	sort.Strings(frozen)
	writeJSON(w, 200, map[string]any{"frozen": frozen, "failed": failed, "hotel_errors": errs})
}

// freezeRoom asks hotel h to freeze room hid for guest g. It returns "" on
// success, else the hotel's error code (or "unavailable" when the hotel did
// not answer).
func freezeRoom(ctx context.Context, h *hotel, g *guestState, hid string) string {
	status, _, body, err := h.doGuest(ctx, g, "POST", "/v1/sandboxes/"+url.PathEscape(hid)+"/freeze", nil, nil, 30*time.Second)
	if err != nil {
		return "unavailable"
	}
	if status == 200 {
		return ""
	}
	var doc struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &doc) == nil && len(doc.Error) > 0 {
		var e struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(doc.Error, &e) == nil && e.Code != "" {
			return e.Code
		}
		var s string
		if json.Unmarshal(doc.Error, &s) == nil && s != "" {
			return s
		}
	}
	return fmt.Sprintf("http_%d", status)
}
