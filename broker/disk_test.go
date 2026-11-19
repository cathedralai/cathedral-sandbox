package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Disk budget of a hotel (disk.go, AB#831).

func intp(n int) *int { return &n }

// setDiskBudget sets h's budget and marks its room list as read, as the
// sync loop does on its first good list (the chain runs no sync loop).
func setDiskBudget(tc *testChain, id string, gib *int) {
	setHotel(tc, id, func(h *hotel) { h.cfg.DiskExtraGiB, h.roomsUnchecked = gib, false })
}

func diskBody(diskGiB int, more map[string]any) map[string]any {
	body := map[string]any{"image": "alpine:3.20", "resources": map[string]any{"vcpu": 1, "memory_gib": 4, "disk_gib": diskGiB}}
	for k, v := range more {
		body[k] = v
	}
	return body
}

func diskUsed(tc *testChain, id string) (used, pending int) {
	setHotel(tc, id, func(h *hotel) { used, pending = h.diskExtraUsed(), h.diskPending })
	return
}

// diskCall is tc.call with the response headers, and an optional User-Agent
// that sends the call to the compat API.
func diskCall(t *testing.T, tc *testChain, key, method, path string, body any, ua string) (int, http.Header, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, tc.srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, resp.Header, doc
}

// wantDiskRefused creates body natively and wants 429 disk_sold_out.
func wantDiskRefused(t *testing.T, tc *testChain, body map[string]any) {
	t.Helper()
	status, hdr, doc := diskCall(t, tc, "key1", "POST", "/v1/sandboxes", body, "")
	wantDiskSoldOut(t, status, hdr, doc)
}

func wantDiskSoldOut(t *testing.T, status int, hdr http.Header, doc map[string]any) {
	t.Helper()
	if status != 429 || errCode(doc) != "disk_sold_out" || hdr.Get("Retry-After") != "60" {
		t.Fatalf("want 429 disk_sold_out with Retry-After 60, got %d %q %v", status, hdr.Get("Retry-After"), doc)
	}
}

func TestDiskBudgetPlacesBigRoomOnlyWhereItFits(t *testing.T) {
	tc := newChain(t)
	setDiskBudget(tc, "a", intp(0))
	setDiskBudget(tc, "b", intp(40))
	setDiskBudget(tc, "c", intp(30))
	// 50 GiB is 40 extra: only b has it.
	for i := 0; i < 5; i++ {
		if i > 0 {
			// Undo the room, so each round is a fresh pick among the three.
			setHotel(tc, "b", func(h *hotel) {
				for hid, rm := range h.rooms {
					tc.b.release(h, rm)
					delete(h.rooms, hid)
				}
			})
		}
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", diskBody(50, nil))
		if status != 202 || doc["hotel"] != "b" {
			t.Fatalf("round %d: want the room on b, got %d %v", i, status, doc)
		}
	}
	if used, pending := diskUsed(tc, "b"); used != 40 || pending != 0 {
		t.Fatalf("b disk used %d pending %d, want 40 and 0", used, pending)
	}
	// b is now full: a 20 GiB room (10 extra) goes to c, a second 50 GiB room nowhere.
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", diskBody(20, nil))
	if status != 202 || doc["hotel"] != "c" {
		t.Fatalf("20 GiB room: want c, got %d %v", status, doc)
	}
	before := createsOn(tc)
	wantDiskRefused(t, tc, diskBody(50, nil))
	if after := createsOn(tc); after["a"]+after["b"]+after["c"] != before["a"]+before["b"]+before["c"] {
		t.Fatalf("a disk_sold_out create reached a hotel: %v -> %v", before, after)
	}
}

func TestDiskSoldOutNativeBatchAndCompat(t *testing.T) {
	tc := newChain(t)
	for _, id := range []string{"a", "b", "c"} {
		setDiskBudget(tc, id, intp(0))
	}
	status, hdr, doc := diskCall(t, tc, "key1", "POST", "/v1/sandboxes", diskBody(50, nil), "")
	wantDiskSoldOut(t, status, hdr, doc)
	msg, _ := doc["error"].(map[string]any)["message"].(string)
	if !strings.Contains(msg, "no hotel has 50 GiB of disk free") {
		t.Fatalf("message: %q", msg)
	}
	// A batch answers with its error counts, as before.
	status, hdr, doc = diskCall(t, tc, "key1", "POST", "/v1/sandboxes", diskBody(20, map[string]any{"count": 2}), "")
	if errs, _ := doc["errors"].(map[string]any); status != 429 || hdr.Get("Retry-After") != "60" || errs["429 disk_sold_out"] != 2.0 {
		t.Fatalf("batch: %d %q %v", status, hdr.Get("Retry-After"), doc)
	}

	status, hdr, doc = diskCall(t, tc, "key1", "POST", "/v1/sandboxes", diskBody(50, map[string]any{"lifetime_seconds": 600}), "cathedral-harbor/0.1.5")
	detail, _ := doc["detail"].(map[string]any)
	if status != 429 || detail["error"] != "disk_sold_out" || hdr.Get("Retry-After") != "60" {
		t.Fatalf("compat: want 429 disk_sold_out Retry-After 60, got %d %q %v", status, hdr.Get("Retry-After"), doc)
	}
	// The compat shape field (the cloud API's size) counts too.
	status, _, doc = diskCall(t, tc, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "shape": map[string]any{"disk_gib": 20}}, "cathedral-harbor/0.1.5")
	if detail, _ := doc["detail"].(map[string]any); status != 429 || detail["error"] != "disk_sold_out" {
		t.Fatalf("compat shape: %d %v", status, doc)
	}
	if on := createsOn(tc); on["a"]+on["b"]+on["c"] != 0 {
		t.Fatalf("creates reached hotels: %v", on)
	}
	for _, id := range []string{"a", "b", "c"} {
		if used, pending := diskUsed(tc, id); used != 0 || pending != 0 {
			t.Fatalf("%s: used %d pending %d after refusals", id, used, pending)
		}
	}
	// Hotels that are down are not a disk problem: the old answer stays.
	for _, id := range []string{"a", "b", "c"} {
		setHotel(tc, id, func(h *hotel) { h.ok = false })
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", diskBody(50, nil)); status != 503 || errCode(doc) != "hotels_unavailable" {
		t.Fatalf("down hotels: %d %v", status, doc)
	}
}

func TestDiskBudgetNilIsUnchanged(t *testing.T) {
	tc := newChain(t)
	for _, id := range []string{"a", "b", "c"} {
		setHotel(tc, id, func(h *hotel) { pct := 99.0; h.roomDataPct = &pct })
	}
	for i := 0; i < 6; i++ {
		tc.room(t, "key1", diskBody(100, nil))
	}
}

func TestSmallRoomsIgnoreDiskBudget(t *testing.T) {
	tc := newChain(t)
	for _, id := range []string{"a", "b", "c"} {
		setDiskBudget(tc, id, intp(0))
		setHotel(tc, id, func(h *hotel) { pct := 99.0; h.roomDataPct = &pct })
	}
	tc.room(t, "key1", diskBody(10, nil))
	tc.room(t, "key1", diskBody(5, nil))
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 3}); status != 202 || doc["count"].(float64) != 3 {
		t.Fatalf("batch: %d %v", status, doc)
	}
}

func TestDiskReservationReleasedOnFailedCreateAndDelete(t *testing.T) {
	tc := newChain(t)
	setDiskBudget(tc, "b", intp(40))
	onB := map[string]any{"hotels": []string{"b"}}
	for _, fail := range []int{409, 503} {
		tc.hotels["b"].mu.Lock()
		tc.hotels["b"].createFail = fail
		tc.hotels["b"].mu.Unlock()
		if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", diskBody(50, onB)); status != fail {
			t.Fatalf("failing hotel %d: got %d %v", fail, status, doc)
		}
		if used, pending := diskUsed(tc, "b"); used != 0 || pending != 0 {
			t.Fatalf("after a failed create (%d): used %d pending %d", fail, used, pending)
		}
		setHotel(tc, "b", func(h *hotel) { h.backoffUntil = time.Time{} })
	}
	tc.hotels["b"].mu.Lock()
	tc.hotels["b"].createFail = 0
	tc.hotels["b"].mu.Unlock()

	id := tc.room(t, "key1", diskBody(50, onB))
	if used, _ := diskUsed(tc, "b"); used != 40 {
		t.Fatalf("used %d, want 40", used)
	}
	wantDiskRefused(t, tc, diskBody(50, onB))
	if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+id, nil); status != 204 {
		t.Fatalf("delete: %d %v", status, doc)
	}
	// Deleting: the disk is still in use until the hotel lists the room gone.
	if used, _ := diskUsed(tc, "b"); used != 40 {
		t.Fatalf("deleting room: used %d, want 40", used)
	}
	setHotel(tc, "b", func(h *hotel) {
		for _, rm := range h.rooms {
			rm.vanished = time.Now().Add(-time.Minute)
		}
	})
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	if used, _ := diskUsed(tc, "b"); used != 0 {
		t.Fatalf("after delete: used %d, want 0", used)
	}
	tc.room(t, "key1", diskBody(50, onB))
}

func TestSyncLoopRelearnsRoomDiskAfterRestart(t *testing.T) {
	tc := newChain(t)
	setDiskBudget(tc, "b", intp(40))
	tc.room(t, "key1", diskBody(30, map[string]any{"hotels": []string{"b"}}))
	tc.room(t, "key1", diskBody(10, map[string]any{"hotels": []string{"b"}}))
	tc.start(t) // a new broker: it knows no room until the list answers
	setHotel(tc, "b", func(h *hotel) { h.cfg.DiskExtraGiB = intp(40) })
	onB := map[string]any{"hotels": []string{"b"}}
	// Health answers but the room list fails: the empty room map must not
	// read as a free budget. Big rooms wait; small rooms are unchanged.
	tc.hotels["b"].mu.Lock()
	tc.hotels["b"].listFail = true
	tc.hotels["b"].mu.Unlock()
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	setHotel(tc, "b", func(h *hotel) {
		if !h.roomsUnchecked || h.listOK {
			t.Fatalf("list failed but roomsUnchecked=%v listOK=%v", h.roomsUnchecked, h.listOK)
		}
		h.ok = true
	})
	wantDiskRefused(t, tc, diskBody(20, onB))
	tc.room(t, "key1", diskBody(10, onB))
	tc.hotels["b"].mu.Lock()
	tc.hotels["b"].listFail = false
	tc.hotels["b"].mu.Unlock()
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	if used, _ := diskUsed(tc, "b"); used != 20 {
		t.Fatalf("after the list: used %d, want 20", used)
	}
	wantDiskRefused(t, tc, diskBody(40, onB))
	tc.room(t, "key1", diskBody(30, onB)) // exactly fills it
}

func TestRoomDataFullSkipsBigRoomsOnly(t *testing.T) {
	tc := newChain(t)
	setDiskBudget(tc, "a", intp(0))
	setDiskBudget(tc, "b", intp(500))
	setDiskBudget(tc, "c", intp(500))
	tc.hotels["b"].healthLive = map[string]any{"room_data_used_pct": 20.5}
	tc.hotels["c"].healthLive = map[string]any{"room_data_used_pct": 80.0}
	for _, id := range []string{"b", "c"} {
		tc.b.syncHotel(context.Background(), tc.b.hotelByID(id))
	}
	for i := 0; i < 5; i++ {
		if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", diskBody(50, nil)); status != 202 || doc["hotel"] != "b" {
			t.Fatalf("big room %d: want b, got %d %v", i, status, doc)
		}
	}
	onC := map[string]any{"hotels": []string{"c"}}
	wantDiskRefused(t, tc, diskBody(20, onC))
	tc.room(t, "key1", diskBody(10, onC))

	// The operator readback shows the budget, its use and the reading.
	status, _, doc := diskCall(t, tc, "operator-key", "GET", "/v1/broker/capacity", nil, "")
	if status != 200 {
		t.Fatalf("capacity: %d %v", status, doc)
	}
	got := map[string]map[string]any{}
	for _, x := range doc["hotels"].([]any) {
		d := x.(map[string]any)
		got[d["id"].(string)] = d
	}
	if d := got["b"]; d["disk_extra_gib"] != 500.0 || d["disk_extra_used_gib"] != 200.0 || d["room_data_used_pct"] != 20.5 {
		t.Fatalf("b readback: %v", d)
	}
	if d := got["c"]; d["disk_extra_used_gib"] != 0.0 || d["room_data_used_pct"] != 80.0 {
		t.Fatalf("c readback: %v", d)
	}
	if d := got["a"]; d["disk_extra_gib"] != 0.0 || d["room_data_used_pct"] != nil {
		t.Fatalf("a readback: %v", d)
	}
	// A guest view does not carry the operator fields.
	_, _, doc = diskCall(t, tc, "key1", "GET", "/v1/broker/capacity", nil, "")
	for _, x := range doc["hotels"].([]any) {
		if _, ok := x.(map[string]any)["disk_extra_gib"]; ok {
			t.Fatalf("guest capacity view shows disk_extra_gib: %v", x)
		}
	}
}

func TestDiskExtraConfigRejectsNegative(t *testing.T) {
	if checkDiskConfig(hotelConfig{DiskExtraGiB: intp(-1)}) == nil {
		t.Fatal("negative disk_extra_gib accepted")
	}
	for _, ok := range []*int{nil, intp(0), intp(200)} {
		if err := checkDiskConfig(hotelConfig{DiskExtraGiB: ok}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestConcurrentBigCreatesCannotShareTheLastDisk(t *testing.T) {
	tc := newChain(t)
	setDiskBudget(tc, "b", intp(40))
	tc.hotels["b"].createDelay = 300 * time.Millisecond
	onB := map[string]any{"hotels": []string{"b"}}
	codes := make(chan string, 4)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", diskBody(50, onB))
			codes <- strconv.Itoa(status) + " " + errCode(doc)
		}()
	}
	wg.Wait()
	close(codes)
	got := map[string]int{}
	for c := range codes {
		got[c]++
	}
	if got["202 "] != 1 || got["429 disk_sold_out"] != 3 {
		t.Fatalf("want one room and three disk_sold_out, got %v", got)
	}
	if used, pending := diskUsed(tc, "b"); used != 40 || pending != 0 {
		t.Fatalf("used %d pending %d", used, pending)
	}
}

func TestSyncAdoptedRoomOfAnInFlightCreateCountsTwiceUntilItReturns(t *testing.T) {
	tc := newChain(t)
	setDiskBudget(tc, "b", intp(50))
	tc.hotels["b"].answerDelay = 600 * time.Millisecond
	onB := map[string]any{"hotels": []string{"b"}}
	done := make(chan int, 1)
	go func() {
		status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", diskBody(50, onB))
		done <- status
	}()
	// Wait until the hotel lists the room while its create has not answered.
	deadline := time.Now().Add(3 * time.Second)
	for {
		tc.hotels["b"].mu.Lock()
		n := len(tc.hotels["b"].rooms)
		tc.hotels["b"].mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the room never listed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	var adopted bool
	setHotel(tc, "b", func(h *hotel) { adopted = len(h.rooms) == 1 && h.creating == 1 })
	if !adopted {
		t.Fatal("the sync loop did not adopt the room while its create was in flight")
	}
	// Counted in both places while in flight: the safe direction (a short
	// false disk_sold_out, never a hotel over budget).
	if used, pending := diskUsed(tc, "b"); used != 80 || pending != 40 {
		t.Fatalf("in flight and adopted: used %d pending %d, want 80 and 40", used, pending)
	}
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", diskBody(20, onB)); status != 429 {
		t.Fatalf("a big create while the count is doubled: %d, want 429 disk_sold_out", status)
	}
	tc.hotels["b"].mu.Lock()
	tc.hotels["b"].answerDelay = 0
	tc.hotels["b"].mu.Unlock()
	if status := <-done; status != 202 {
		t.Fatalf("in-flight create: %d", status)
	}
	if used, pending := diskUsed(tc, "b"); used != 40 || pending != 0 {
		t.Fatalf("after the create returned: used %d pending %d, want 40 and 0 (counted once)", used, pending)
	}
	// Now 10 extra fits the 50 budget again.
	tc.room(t, "key1", diskBody(20, onB))
}
