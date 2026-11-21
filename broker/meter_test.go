package main

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// meterChain is newChain with the meter key "meter-key" set.
func meterChain(t *testing.T) *testChain {
	t.Helper()
	tc := newChain(t)
	tc.b.cfg.MeterKeySHA256 = sha("meter-key")
	return tc
}

// seedRoom puts a room on fake hotel f as the hotel lists it.
func seedRoom(f *fakeHotel, id, guest, state string, vcpu, gib int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	labels := map[string]any{}
	if guest != "" {
		labels[guestLabel] = guest
	}
	f.rooms = append(f.rooms, map[string]any{
		"id": id, "state": state, "labels": labels, "created_at": "2026-11-21T10:00:00+00:00",
		"resources": map[string]any{"vcpu": vcpu, "memory_gib": gib, "disk_gib": 10},
	})
}

func hotelRoomState(f *fakeHotel, id string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rm := range f.rooms {
		if rm["id"] == id {
			return rm["state"]
		}
	}
	return nil
}

func meterPaths(guest string) [][2]string {
	return [][2]string{
		{"GET", "/v1/broker/guests/" + guest + "/rooms"},
		{"POST", "/v1/broker/guests/" + guest + "/freeze-all"},
	}
}

func TestMeterRoutesOffWithoutMeterKey(t *testing.T) {
	tc := newChain(t)
	seedRoom(tc.hotels["b"], "sbx_1", "g1", "running", 1, 4)
	for _, key := range []string{"meter-key", "operator-key", "reader-key", "key1"} {
		for _, rt := range meterPaths("g1") {
			if status, doc := tc.call(t, key, rt[0], rt[1], nil); status != 404 {
				t.Fatalf("%s %s with %s and no meter key: %d %v", rt[0], rt[1], key, status, doc)
			}
		}
	}
	if n := len(tc.hotels["b"].freezes); n != 0 {
		t.Fatalf("hotel got %d freezes with the routes off", n)
	}
}

func TestMeterRoutesRefuseEveryOtherKey(t *testing.T) {
	tc := meterChain(t)
	seedRoom(tc.hotels["b"], "sbx_1", "g1", "running", 1, 4)
	for _, key := range []string{"key1", "key2", "operator-key", "reader-key", "enroller-key", "view1", "", "meter-key-x"} {
		for _, rt := range meterPaths("g1") {
			status, doc := tc.call(t, key, rt[0], rt[1], nil)
			if status != 401 {
				t.Fatalf("%s %s with %q: %d %v, want 401", rt[0], rt[1], key, status, doc)
			}
		}
	}
	if n := len(tc.hotels["b"].freezes); n != 0 {
		t.Fatalf("a refused key froze %d rooms", n)
	}
	if hotelRoomState(tc.hotels["b"], "sbx_1") != "running" {
		t.Fatal("a refused key changed the room")
	}
}

// The meter key opens the two meter routes and nothing else.
func TestMeterKeyReachesNoOtherRoute(t *testing.T) {
	tc := meterChain(t)
	for _, c := range [][2]string{
		{"GET", "/v1/broker/guests"},
		{"PATCH", "/v1/broker/guests/g1"},
		{"GET", "/v1/broker/hotels"},
		{"GET", "/v1/broker/hotels/a"},
		{"GET", "/v1/broker/capacity"},
		{"GET", "/v1/broker/miner-exits"},
		{"GET", "/v1/sandboxes"},
		{"GET", "/v1/usage"},
		{"POST", "/v1/sandboxes"},
	} {
		var body any
		if c[0] != "GET" {
			body = map[string]any{"max_rooms": 1}
		}
		if status, doc := tc.call(t, "meter-key", c[0], c[1], body); status < 400 {
			t.Fatalf("meter key %s %s: %d %v", c[0], c[1], status, doc)
		}
	}
	// A wrong method on a meter route is not a route.
	for _, c := range [][2]string{{"POST", "/v1/broker/guests/g1/rooms"}, {"GET", "/v1/broker/guests/g1/freeze-all"}, {"DELETE", "/v1/broker/guests/g1/freeze-all"}} {
		if status, _ := tc.call(t, "meter-key", c[0], c[1], nil); status != 404 {
			t.Fatalf("meter key %s %s: %d, want 404", c[0], c[1], status)
		}
	}
}

// The operator read key keeps its documented scope with the meter key set.
func TestMeterKeyLeavesOperatorReadScope(t *testing.T) {
	tc := meterChain(t)
	if status, _ := tc.call(t, "reader-key", "GET", "/v1/broker/capacity", nil); status != 200 {
		t.Fatalf("read key capacity: %d", status)
	}
	if status, _ := tc.call(t, "reader-key", "GET", "/v1/broker/miner-exits", nil); status != 200 {
		t.Fatalf("read key miner exits: %d", status)
	}
	if status, _ := tc.call(t, "reader-key", "GET", "/v1/broker/guests", nil); status != 401 {
		t.Fatalf("read key guests: %d", status)
	}
}

func TestMeterUnknownGuest(t *testing.T) {
	tc := meterChain(t)
	for _, rt := range meterPaths("nobody") {
		status, doc := tc.call(t, "meter-key", rt[0], rt[1], nil)
		if status != 404 || errCode(doc) != "guest_not_found" {
			t.Fatalf("%s %s: %d %v", rt[0], rt[1], status, doc)
		}
	}
}

func TestMeterRoomsMapsHotelFields(t *testing.T) {
	tc := meterChain(t)
	seedRoom(tc.hotels["b"], "sbx_1", "g1", "running", 2, 8)
	seedRoom(tc.hotels["b"], "sbx_2", "g1", "frozen", 1, 4)
	seedRoom(tc.hotels["b"], "sbx_3", "g2", "running", 1, 4) // another guest
	seedRoom(tc.hotels["a"], "sbx_9", "", "running", 1, 4)   // no guest label
	seedRoom(tc.hotels["a"], "sbx_4", "g1", "creating", 4, 16)
	tc.hotels["c"].listFail = true
	status, doc := tc.call(t, "meter-key", "GET", "/v1/broker/guests/g1/rooms", nil)
	if status != 200 {
		t.Fatalf("rooms: %d %v", status, doc)
	}
	want := []any{
		map[string]any{"id": "a.sbx_4", "hotel": "a", "state": "creating", "memory_gib": 16.0, "vcpu": 4.0, "created_at": "2026-11-21T10:00:00+00:00"},
		map[string]any{"id": "b.sbx_1", "hotel": "b", "state": "running", "memory_gib": 8.0, "vcpu": 2.0, "created_at": "2026-11-21T10:00:00+00:00"},
		map[string]any{"id": "b.sbx_2", "hotel": "b", "state": "frozen", "memory_gib": 4.0, "vcpu": 1.0, "created_at": "2026-11-21T10:00:00+00:00"},
	}
	if !reflect.DeepEqual(doc["rooms"], want) {
		t.Fatalf("rooms = %v\nwant %v", doc["rooms"], want)
	}
	if !reflect.DeepEqual(doc["hotel_errors"], map[string]any{"c": "unavailable"}) {
		t.Fatalf("hotel_errors = %v", doc["hotel_errors"])
	}
	// The hotel list was asked for the guest's label.
	f := tc.hotels["b"]
	f.mu.Lock()
	defer f.mu.Unlock()
	asked := false
	for _, c := range f.calls {
		if strings.HasPrefix(c, "GET /v1/sandboxes?") && strings.Contains(c, "label=broker_guest%3Dg1") {
			asked = true
		}
	}
	if !asked {
		t.Fatalf("hotel b calls: %v", f.calls)
	}
}

// A size the hotel did not send is null, not 0.
func TestMeterRoomMissingSizeIsNull(t *testing.T) {
	rm := meterRoom("b", map[string]any{"id": "sbx_1", "state": "running"})
	if rm["memory_gib"] != nil || rm["vcpu"] != nil || rm["created_at"] != nil {
		t.Fatalf("missing fields: %v", rm)
	}
	rm = meterRoom("b", map[string]any{"id": "sbx_1", "resources": map[string]any{"memory_gib": 0.5, "vcpu": -1.0}})
	if rm["memory_gib"] != nil || rm["vcpu"] != nil {
		t.Fatalf("non-whole sizes: %v", rm)
	}
}

func TestMeterRoomsRespectGuestHotels(t *testing.T) {
	tc := meterChain(t)
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits.Hotels = []string{"b"}
	tc.b.mu.Unlock()
	seedRoom(tc.hotels["b"], "sbx_1", "g1", "running", 1, 4)
	seedRoom(tc.hotels["c"], "sbx_1", "g1", "running", 1, 4)
	tc.hotels["a"].listFail = true
	status, doc := tc.call(t, "meter-key", "GET", "/v1/broker/guests/g1/rooms", nil)
	rooms, _ := doc["rooms"].([]any)
	if status != 200 || len(rooms) != 1 || rooms[0].(map[string]any)["id"] != "b.sbx_1" {
		t.Fatalf("rooms: %d %v", status, doc)
	}
	if errs, _ := doc["hotel_errors"].(map[string]any); len(errs) != 0 {
		t.Fatalf("a hotel outside the guest's list was asked: %v", errs)
	}
	status, doc = tc.call(t, "meter-key", "POST", "/v1/broker/guests/g1/freeze-all", nil)
	if status != 200 || !reflect.DeepEqual(doc["frozen"], []any{"b.sbx_1"}) {
		t.Fatalf("freeze-all: %d %v", status, doc)
	}
	if n := len(tc.hotels["c"].freezes); n != 0 || hotelRoomState(tc.hotels["c"], "sbx_1") != "running" {
		t.Fatalf("a hotel outside the guest's list got %d freezes", n)
	}
}

func TestMeterFreezeAllFreezesRunningRoomsOnly(t *testing.T) {
	tc := meterChain(t)
	seedRoom(tc.hotels["b"], "sbx_1", "g1", "running", 1, 4)
	seedRoom(tc.hotels["b"], "sbx_2", "g1", "running", 2, 8)
	seedRoom(tc.hotels["b"], "sbx_3", "g1", "frozen", 1, 4)
	seedRoom(tc.hotels["b"], "sbx_4", "g2", "running", 1, 4) // another guest
	seedRoom(tc.hotels["a"], "sbx_5", "g1", "creating", 1, 4)
	seedRoom(tc.hotels["a"], "sbx_6", "g1", "running", 1, 4)
	tc.hotels["a"].freezeFail = map[string]int{"sbx_6": 500}
	tc.hotels["c"].listFail = true

	status, doc := tc.call(t, "meter-key", "POST", "/v1/broker/guests/g1/freeze-all", nil)
	if status != 200 {
		t.Fatalf("freeze-all: %d %v", status, doc)
	}
	if !reflect.DeepEqual(doc["frozen"], []any{"b.sbx_1", "b.sbx_2"}) {
		t.Fatalf("frozen = %v", doc["frozen"])
	}
	if !reflect.DeepEqual(doc["failed"], map[string]any{"a.sbx_6": "freeze_failed"}) {
		t.Fatalf("failed = %v", doc["failed"])
	}
	if !reflect.DeepEqual(doc["hotel_errors"], map[string]any{"c": "unavailable"}) {
		t.Fatalf("hotel_errors = %v", doc["hotel_errors"])
	}
	b, a := tc.hotels["b"], tc.hotels["a"]
	if !reflect.DeepEqual(sortedCopy(b.freezes), []string{"sbx_1", "sbx_2"}) || !reflect.DeepEqual(a.freezes, []string{"sbx_6"}) {
		t.Fatalf("hotel freezes: b %v a %v", b.freezes, a.freezes)
	}
	for _, g := range append(append([]string{}, b.freezeGuest...), a.freezeGuest...) {
		if g != "g1" {
			t.Fatalf("freeze sent as guest %q", g)
		}
	}
	if hotelRoomState(b, "sbx_4") != "running" || hotelRoomState(a, "sbx_5") != "creating" {
		t.Fatal("freeze-all touched a room it must not")
	}

	// Idempotent: a second call freezes nothing new and still reports the failure.
	_, doc = tc.call(t, "meter-key", "POST", "/v1/broker/guests/g1/freeze-all", nil)
	if frozen, _ := doc["frozen"].([]any); len(frozen) != 0 || !reflect.DeepEqual(doc["failed"], map[string]any{"a.sbx_6": "freeze_failed"}) {
		t.Fatalf("second freeze-all: %v", doc)
	}
	if len(b.freezes) != 2 {
		t.Fatalf("second call froze again: %v", b.freezes)
	}
	// Never deletes, never thaws.
	for _, f := range tc.hotels {
		f.mu.Lock()
		for _, c := range f.calls {
			if strings.HasPrefix(c, "DELETE ") || strings.Contains(c, "/thaw") {
				t.Fatalf("freeze-all sent %s", c)
			}
		}
		f.mu.Unlock()
	}
}

func TestMeterFreezeAllNoRooms(t *testing.T) {
	tc := meterChain(t)
	status, doc := tc.call(t, "meter-key", "POST", "/v1/broker/guests/g2/freeze-all", nil)
	if status != 200 || !reflect.DeepEqual(doc["frozen"], []any{}) || !reflect.DeepEqual(doc["failed"], map[string]any{}) || !reflect.DeepEqual(doc["hotel_errors"], map[string]any{}) {
		t.Fatalf("freeze-all with no rooms: %d %v", status, doc)
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestMeterKeyConfigRejectsReuse(t *testing.T) {
	tc := newChain(t)
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var original config
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	original.Guests[1].NextKeySHA256 = sha("next2")
	for name, digest := range map[string]string{
		"operator":  original.OperatorKeySHA256,
		"reader":    original.OperatorReadKeySHA256,
		"enroller":  original.MinerEnrollKeySHA256,
		"guest":     original.Guests[0].KeySHA256,
		"guest2":    strings.ToUpper(original.Guests[1].KeySHA256),
		"next":      original.Guests[1].NextKeySHA256,
		"view":      original.Guests[0].ViewTokenSHA256,
		"malformed": "not-a-digest",
		"short":     sha("meter-key")[:62],
	} {
		t.Run(name, func(t *testing.T) {
			cfg := original
			cfg.MeterKeySHA256 = digest
			body, _ := json.Marshal(cfg)
			path := t.TempDir() + "/config.json"
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadBroker(path); err == nil || !strings.Contains(err.Error(), "meter") {
				t.Fatalf("reused or malformed meter key: %v", err)
			}
		})
	}
	t.Run("distinct", func(t *testing.T) {
		cfg := original
		cfg.MeterKeySHA256 = sha("meter-key")
		body, _ := json.Marshal(cfg)
		path := t.TempDir() + "/config.json"
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBroker(path); err != nil {
			t.Fatalf("distinct meter key refused: %v", err)
		}
	})
}
