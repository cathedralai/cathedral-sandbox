package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// Per-room tunables ("option 2"): the broker forwards a create's "tunables"
// to the one hotel that starts the room, unchanged, and never to another
// guest's create. A hotel that starts the room without applying them (a room
// kit older than per-room tunables) does not keep the room.

func coldTunables() map[string]any {
	return map[string]any{"schema": float64(1), "runsc": map[string]any{"directfs": false, "overlay2": "all:self"}}
}

func applyAll(tc *testChain) {
	for _, f := range tc.hotels {
		f.mu.Lock()
		f.appliesTunables = true
		f.mu.Unlock()
	}
}

func TestCreateTunablesReachTheHotelUnchanged(t *testing.T) {
	tc := newChain(t)
	applyAll(tc)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{
		"image": "alpine:3.20", "hotels": []string{"b"}, "tunables": coldTunables()})
	if status != 202 {
		t.Fatalf("create: %d %v", status, doc)
	}
	f := tc.hotels["b"]
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.creates) != 1 || !reflect.DeepEqual(f.creates[0]["tunables"], coldTunables()) {
		t.Fatalf("hotel got tunables %v, want %v", f.creates[0]["tunables"], coldTunables())
	}
	if _, ok := f.creates[0]["hotels"]; ok {
		t.Fatalf("broker field reached the hotel: %v", f.creates[0])
	}
	view, _ := doc["tunables"].(map[string]any)
	if view["status"] != "applied" || len(view["sha256"].(string)) != 64 {
		t.Fatalf("room answer lost the hotel's tunables view: %v", doc)
	}
}

func TestTunablesStayWithTheirGuestUnderConcurrency(t *testing.T) {
	tc := newChain(t)
	applyAll(tc)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		for _, key := range []string{"key1", "key2"} {
			wg.Add(1)
			go func(key string) {
				defer wg.Done()
				body := map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}
				if key == "key1" {
					body["tunables"] = coldTunables()
				}
				if status, doc := tc.call(t, key, "POST", "/v1/sandboxes", body); status != 202 {
					t.Errorf("%s create: %d %v", key, status, doc)
				}
			}(key)
		}
	}
	// One batch create of guest 2 (count 3) next to them: every room of it goes without tunables.
	if status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{
		"image": "alpine:3.20", "hotels": []string{"b"}, "count": 3}); status != 202 {
		t.Fatalf("batch: %d %v", status, doc)
	}
	wg.Wait()
	f := tc.hotels["b"]
	f.mu.Lock()
	defer f.mu.Unlock()
	with, without := 0, 0
	for _, c := range f.creates {
		labels, _ := c["labels"].(map[string]any)
		switch labels[guestLabel] {
		case "g1":
			if !reflect.DeepEqual(c["tunables"], coldTunables()) {
				t.Fatalf("g1 create without its tunables: %v", c)
			}
			with++
		case "g2":
			if _, ok := c["tunables"]; ok {
				t.Fatalf("g2 create carries tunables it never sent: %v", c)
			}
			without++
		}
	}
	if with != 6 || without != 9 {
		t.Fatalf("creates: %d with, %d without", with, without)
	}
}

func TestHotelThatIgnoresTunablesKeepsNoRoom(t *testing.T) {
	tc := newChain(t) // no hotel applies tunables: the room kit before this change
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{
		"image": "alpine:3.20", "hotels": []string{"b"}, "tunables": coldTunables()})
	if status != 409 || errCode(doc) != "tunables_unavailable" {
		t.Fatalf("create on a hotel without tunables: %d %v", status, doc)
	}
	f := tc.hotels["b"]
	f.mu.Lock()
	deleted := append([]string(nil), f.roomDeletes...)
	f.mu.Unlock()
	if len(deleted) != 1 || deleted[0] != "sbx_1" {
		t.Fatalf("the room the hotel started was not removed: %v", deleted)
	}
	// A create without tunables on the same hotel is unaffected (the hotel was not rested).
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{
		"image": "alpine:3.20", "hotels": []string{"b"}}); status != 202 {
		t.Fatalf("plain create after: %d %v", status, doc)
	}
}

func TestTunablesCreateMovesToAHotelThatAppliesThem(t *testing.T) {
	tc := newChain(t)
	tc.hotels["c"].mu.Lock()
	tc.hotels["c"].appliesTunables = true
	tc.hotels["c"].mu.Unlock()
	for i := 0; i < 4; i++ {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{
			"image": "alpine:3.20", "hotels": []string{"b", "c"}, "tunables": coldTunables()})
		if status != 202 || doc["hotel"] != "c" {
			t.Fatalf("create %d: %d %v", i, status, doc)
		}
	}
	f := tc.hotels["b"]
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.roomDeletes) != len(f.creates) {
		t.Fatalf("hotel b kept rooms it started without the tunables: %d creates, %d deletes", len(f.creates), len(f.roomDeletes))
	}
}

func TestHotelAttestRoomIsTheGuestsOwnRoom(t *testing.T) {
	tc := newChain(t)
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	hid := strings.TrimPrefix(room, "a.")
	in := `{"report_data_hex":"` + strings.Repeat("ab", 64) + `","sandbox_id":"` + room + `"}`
	resp, out := tc.postRaw(t, "key1", "/v1/hotels/a/attest", []byte(in))
	if resp.StatusCode != 200 {
		t.Fatalf("own room: %d %s", resp.StatusCode, out)
	}
	f := tc.hotels["a"]
	f.mu.Lock()
	var sent map[string]any
	_ = json.Unmarshal(f.attestIn[len(f.attestIn)-1], &sent)
	f.mu.Unlock()
	if sent["sandbox_id"] != hid || sent["report_data_hex"] != strings.Repeat("ab", 64) {
		t.Fatalf("hotel got %v, want sandbox_id %s", sent, hid)
	}
	// Another guest naming that room is a 404 and the hotel is not asked.
	resp, out = tc.postRaw(t, "key2", "/v1/hotels/a/attest", []byte(in))
	if resp.StatusCode != 404 || !strings.Contains(string(out), "room_not_found") {
		t.Fatalf("other guest's room: %d %s", resp.StatusCode, out)
	}
	f.mu.Lock()
	n := len(f.attestIn)
	f.mu.Unlock()
	if n != 1 {
		t.Fatalf("hotel asked %d times, want 1", n)
	}
}
