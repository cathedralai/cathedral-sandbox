package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// newKitHotel puts a hotel with the AB#860 image routes in front of the fake
// hotel id: GET /v1/images, DELETE /v1/images/pins/<ref> and a prefetch that
// echoes "pinned". Every other call goes to the fake hotel. The calls it got
// are in the returned recorder.
type kitHotel struct {
	mu       sync.Mutex
	guests   []string // X-Cathedral-Guest of every image call
	pinMax   []string // X-Pin-Max-Bytes of every prefetch
	bodies   []map[string]any
	unpinned []string // escaped path of every unpin
	hang     time.Duration
}

func newKitHotel(t *testing.T, tc *testChain, id string) *kitHotel {
	t.Helper()
	k := &kitHotel{}
	f := tc.hotels[id]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if !strings.HasPrefix(p, "/v1/images") {
			f.ServeHTTP(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		k.mu.Lock()
		k.guests = append(k.guests, r.Header.Get(guestHeader))
		hang := k.hang
		k.mu.Unlock()
		if hang > 0 {
			time.Sleep(hang)
		}
		switch {
		case p == "/v1/images" && r.Method == "GET":
			writeJSON(w, 200, map[string]any{"images": []any{map[string]any{"ref": "alpine:3.20", "size_bytes": 7, "pinned": false}}, "count": 1})
		case p == "/v1/images/prefetch" && r.Method == "POST":
			k.mu.Lock()
			k.pinMax = append(k.pinMax, r.Header.Get("X-Pin-Max-Bytes"))
			k.bodies = append(k.bodies, req)
			k.mu.Unlock()
			res := map[string]any{"images": []any{map[string]any{"ref": "alpine:3.20", "size_bytes": 7}}}
			if req["pin"] == true {
				res["pinned"] = []any{"alpine:3.20"}
			}
			writeJSON(w, 202, map[string]any{"operation_id": "op_9", "status": "done", "result": res})
		case strings.HasPrefix(p, "/v1/images/pins/") && r.Method == "DELETE":
			k.mu.Lock()
			k.unpinned = append(k.unpinned, r.URL.EscapedPath())
			k.mu.Unlock()
			writeJSON(w, 200, map[string]any{"ref": strings.TrimPrefix(p, "/v1/images/pins/"), "pinned": false})
		default:
			writeErr(w, 404, "route_not_found", p)
		}
	}))
	t.Cleanup(srv.Close)
	tc.b.hotelByID(id).cfg.API = srv.URL
	return k
}

// The guest capacity view shows how full each hotel's data volume is and the
// admission line, and nothing else of the operator's disk budget.
func TestGuestCapacityShowsDiskUseOnly(t *testing.T) {
	tc := newChain(t)
	tc.b.mu.Lock()
	pct, line := 42.5, 75.0
	tc.b.hotelByID("b").roomDataPct = &pct
	tc.b.hotelByID("b").cfg.DiskAdmitUsedPct = &line
	tc.b.hotelByID("b").cfg.DiskExtraGiB = intp(500)
	tc.b.mu.Unlock()
	status, doc := tc.call(t, "key1", "GET", "/v1/broker/capacity", nil)
	if status != 200 {
		t.Fatalf("capacity: %d %v", status, doc)
	}
	got := map[string]map[string]any{}
	for _, x := range doc["hotels"].([]any) {
		d := x.(map[string]any)
		got[d["id"].(string)] = d
	}
	b, c := got["b"], got["c"]
	if b == nil || b["disk_used_pct"] != 42.5 || b["disk_admit_used_pct"] != 75.0 {
		t.Fatalf("hotel b: %v", b)
	}
	if v, ok := c["disk_used_pct"]; !ok || v != nil {
		t.Fatalf("hotel c with no reading: %v", c)
	}
	if v, ok := c["disk_admit_used_pct"]; !ok || v != nil {
		t.Fatalf("hotel c with no line: %v", c)
	}
	for _, d := range got {
		for _, k := range []string{"room_data_used_pct", "disk_extra_gib", "disk_extra_used_gib", "lent_from"} {
			if _, ok := d[k]; ok {
				t.Fatalf("guest sees operator field %s: %v", k, d)
			}
		}
	}
}

func TestImageListIsScopedAndCalledAsTheGuest(t *testing.T) {
	tc := newChain(t)
	ka := newKitHotel(t, tc, "a")
	newKitHotel(t, tc, "b")
	// c is an old kit: GET /v1/images answers 404.
	tc.b.mu.Lock()
	tc.b.guests["g2"].limits.Hotels = []string{"b"}
	tc.b.mu.Unlock()

	status, doc := tc.call(t, "key1", "GET", "/v1/images?hotel=a", nil)
	if status != 200 || doc["hotel"] != "a" || doc["count"] != 1.0 {
		t.Fatalf("list on a: %d %v", status, doc)
	}
	if len(ka.guests) != 1 || ka.guests[0] != "g1" {
		t.Fatalf("hotel a was not called as the guest: %v", ka.guests)
	}
	// A hotel outside g2's scope is not found, and is never called.
	if status, doc := tc.call(t, "key2", "GET", "/v1/images?hotel=a", nil); status != 404 || errCode(doc) != "hotel_not_found" {
		t.Fatalf("foreign hotel: %d %v", status, doc)
	}
	if status, _ := tc.call(t, "key1", "GET", "/v1/images?hotel=nope", nil); status != 404 {
		t.Fatalf("unknown hotel: %d", status)
	}
	if len(ka.guests) != 1 {
		t.Fatalf("out of scope call reached hotel a")
	}
	// An old kit says so.
	status, doc = tc.call(t, "key1", "GET", "/v1/images?hotel=c", nil)
	if status != 200 || doc["hotel"] != "c" || doc["images_list"] != "not_supported" {
		t.Fatalf("old kit: %d %v", status, doc)
	}

	// Fan-out: one entry per hotel in scope, sorted.
	status, doc = tc.call(t, "key1", "GET", "/v1/images", nil)
	hs, _ := doc["hotels"].([]any)
	if status != 200 || len(hs) != 3 {
		t.Fatalf("fan-out: %d %v", status, doc)
	}
	ids := []string{}
	for _, x := range hs {
		ids = append(ids, x.(map[string]any)["hotel"].(string))
	}
	if strings.Join(ids, ",") != "a,b,c" || hs[2].(map[string]any)["images_list"] != "not_supported" {
		t.Fatalf("fan-out entries: %v", hs)
	}
	status, doc = tc.call(t, "key2", "GET", "/v1/images", nil)
	if hs, _ := doc["hotels"].([]any); status != 200 || len(hs) != 1 || hs[0].(map[string]any)["hotel"] != "b" {
		t.Fatalf("g2 fan-out: %d %v", status, doc)
	}
	// A hotel that is down is not asked.
	tc.b.mu.Lock()
	tc.b.hotelByID("b").ok = false
	tc.b.mu.Unlock()
	_, doc = tc.call(t, "key1", "GET", "/v1/images", nil)
	if hs, _ := doc["hotels"].([]any); len(hs) != 2 {
		t.Fatalf("down hotel listed: %v", doc)
	}
}

// A hotel that does not answer in time gets an error entry; the others answer.
func TestImageListFanOutTimesOutPerHotel(t *testing.T) {
	old := imageListTimeout
	imageListTimeout = 200 * time.Millisecond
	t.Cleanup(func() { imageListTimeout = old })
	tc := newChain(t)
	newKitHotel(t, tc, "a")
	newKitHotel(t, tc, "b").hang = time.Second
	start := time.Now()
	status, doc := tc.call(t, "key1", "GET", "/v1/images", nil)
	if status != 200 || time.Since(start) > 900*time.Millisecond {
		t.Fatalf("fan-out: %d after %v", status, time.Since(start))
	}
	byID := map[string]map[string]any{}
	for _, x := range doc["hotels"].([]any) {
		e := x.(map[string]any)
		byID[e["hotel"].(string)] = e
	}
	if byID["a"]["count"] != 1.0 || byID["b"]["error"] == nil {
		t.Fatalf("entries: %v", doc)
	}
}

func TestPrefetchPinNeedsPinMaxGiBAndSendsTheCap(t *testing.T) {
	tc := newChain(t)
	ka := newKitHotel(t, tc, "a")
	body := map[string]any{"images": []string{"alpine:3.20"}, "hotels": []string{"a", "c"}, "pin": true}
	status, doc := tc.call(t, "key1", "POST", "/v1/images/prefetch", body)
	if status != 403 || errCode(doc) != "pins_not_enabled" {
		t.Fatalf("pin without a cap: %d %v", status, doc)
	}
	if len(ka.bodies) != 0 || len(tc.hotels["c"].prefetch) != 0 {
		t.Fatalf("a refused pin reached a hotel")
	}
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits.PinMaxGiB = 3
	tc.b.mu.Unlock()
	status, doc = tc.call(t, "key1", "POST", "/v1/images/prefetch", body)
	if status != 202 {
		t.Fatalf("pin: %d %v", status, doc)
	}
	final := waitPrefetch(t, tc, "key1", doc["prefetch_id"].(string))
	if len(ka.pinMax) != 1 || ka.pinMax[0] != "3221225472" || ka.bodies[0]["pin"] != true || ka.guests[0] != "g1" {
		t.Fatalf("hotel a got %v %v %v", ka.pinMax, ka.bodies, ka.guests)
	}
	hs := final["hotels"].(map[string]any)
	a, c := hs["a"].(map[string]any), hs["c"].(map[string]any)
	if a["state"] != "done" || a["pin"] != "pinned" || a["pinned"].([]any)[0] != "alpine:3.20" {
		t.Fatalf("hotel a view: %v", a)
	}
	// The old kit pulled but dropped the pin: say so.
	if c["state"] != "done" || c["pin"] != "not_supported" || tc.hotels["c"].prefetch[0]["pin"] != true {
		t.Fatalf("hotel c view: %v", c)
	}
	// A prefetch without pin sends neither the field nor the cap.
	status, doc = tc.call(t, "key1", "POST", "/v1/images/prefetch", map[string]any{"images": []string{"alpine:3.20"}, "hotels": []string{"a"}})
	if status != 202 {
		t.Fatalf("plain: %d %v", status, doc)
	}
	final = waitPrefetch(t, tc, "key1", doc["prefetch_id"].(string))
	if _, ok := ka.bodies[1]["pin"]; ok || ka.pinMax[1] != "" {
		t.Fatalf("plain prefetch carried a pin: %v %v", ka.bodies[1], ka.pinMax[1])
	}
	if _, ok := final["hotels"].(map[string]any)["a"].(map[string]any)["pin"]; ok {
		t.Fatalf("plain prefetch view has pin: %v", final)
	}
	// "pin" must be a boolean.
	if status, _ := tc.call(t, "key1", "POST", "/v1/images/prefetch", map[string]any{"images": []string{"alpine:3.20"}, "pin": "yes"}); status != 400 {
		t.Fatalf("pin as a string: %d", status)
	}
}

func TestUnpinIsRoutedAsTheGuestInScope(t *testing.T) {
	tc := newChain(t)
	ka := newKitHotel(t, tc, "a")
	tc.b.mu.Lock()
	tc.b.guests["g2"].limits.Hotels = []string{"b"}
	tc.b.mu.Unlock()
	status, doc := tc.call(t, "key1", "DELETE", "/v1/images/pins?ref=ghcr.io/acme/x:1&hotel=a", nil)
	if status != 200 || doc["pinned"] != false {
		t.Fatalf("unpin: %d %v", status, doc)
	}
	if len(ka.unpinned) != 1 || ka.unpinned[0] != "/v1/images/pins/ghcr.io%2Facme%2Fx:1" || ka.guests[0] != "g1" {
		t.Fatalf("hotel a got %v as %v", ka.unpinned, ka.guests)
	}
	if status, _ := tc.call(t, "key2", "DELETE", "/v1/images/pins?ref=alpine:3.20&hotel=a", nil); status != 404 {
		t.Fatalf("foreign hotel: %d", status)
	}
	for _, q := range []string{"?hotel=a", "?ref=alpine:3.20"} {
		if status, _ := tc.call(t, "key1", "DELETE", "/v1/images/pins"+q, nil); status != 400 {
			t.Fatalf("unpin %s: %d", q, status)
		}
	}
	if len(ka.unpinned) != 1 {
		t.Fatalf("refused unpins reached the hotel: %v", ka.unpinned)
	}
}

func TestPinMaxGiBIsReadFromTheConfig(t *testing.T) {
	var gc guestConfig
	if err := json.Unmarshal([]byte(`{"id":"const","pin_max_gib":400}`), &gc); err != nil || gc.PinMaxGiB != 400 {
		t.Fatalf("pin_max_gib: %v %d", err, gc.PinMaxGiB)
	}
}

// Review HOLD on #640: a ref pinned on a hotel is pinned again when the
// hotel-up replay pulls it after a reboot; after an unpin it is pulled
// without a pin.
func TestReplayAfterARebootPinsAgain(t *testing.T) {
	tc := newChain(t)
	ka := newKitHotel(t, tc, "a")
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits.PinMaxGiB = 3
	tc.b.mu.Unlock()
	status, doc := tc.call(t, "key1", "POST", "/v1/images/prefetch", map[string]any{"images": []string{"alpine:3.20"}, "hotels": []string{"a"}, "pin": true})
	if status != 202 {
		t.Fatalf("pin: %d %v", status, doc)
	}
	waitPrefetch(t, tc, "key1", doc["prefetch_id"].(string))
	h := tc.b.hotelByID("a")
	setHotel(tc, "a", func(h *hotel) { tc.b.hotelWentDown(h) }) // a reboot wipes the scratch
	tc.b.replayGuestPrefetch(h)
	n := len(ka.bodies)
	if n != 2 || ka.bodies[1]["pin"] != true || ka.pinMax[1] != "3221225472" {
		t.Fatalf("replay after reboot: %d prefetches, last %v cap %v; want a pinned replay", n, ka.bodies[n-1], ka.pinMax[n-1])
	}
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/images/pins?ref=alpine:3.20&hotel=a", nil); status != 200 {
		t.Fatalf("unpin: %d", status)
	}
	setHotel(tc, "a", func(h *hotel) { tc.b.hotelWentDown(h) })
	tc.b.replayGuestPrefetch(h)
	n = len(ka.bodies)
	if _, pinned := ka.bodies[n-1]["pin"]; n != 3 || pinned || ka.pinMax[n-1] != "" {
		t.Fatalf("replay after unpin: %d prefetches, last %v cap %q; want a plain pull", n, ka.bodies[n-1], ka.pinMax[n-1])
	}
}
