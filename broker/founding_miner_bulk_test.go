package main

import (
	"fmt"
	"testing"
)

// This exercises the broker side after an operator has supplied a room service
// and its key for each machine. It does not simulate the signed-roster watcher.
func TestSealedMinerHotelsReceiveDynamicCustomerWork(t *testing.T) {
	for _, count := range []int{20, 32, 256} {
		t.Run(fmt.Sprintf("miners-%d", count), func(t *testing.T) {
			tc := newChainState(t, t.TempDir())
			if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{
				"max_rooms": count,
				"policy": map[string]any{"prefer": []any{map[string]any{
					"label": map[string]string{"sealed": "true", "miner": "true"},
				}}},
			}); status != 200 {
				t.Fatalf("set sealed-only dynamic policy: %d %v", status, doc)
			}
			for i := 0; i < count; i++ {
				id := fmt.Sprintf("miner-%02d", i)
				miner, url := newMinerHotel(t, 1, snpAttestation(t, attestOpts{chip: byte(i)}))
				tc.hotels[id] = miner.fakeHotel
				status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{
					"id": id, "api": url, "key": joinKey, "sealed": true,
					"miner_hotkey": minerHotkey, "max_slots": 1,
				})
				if status != 201 {
					t.Fatalf("join %s: %d %v", id, status, doc)
				}
				syncNow(tc, id)
				if a := admissionOf(t, tc, id); a["state"] != "admitted" {
					t.Fatalf("%s admission: %v", id, a)
				}
			}
			rooms := make([]string, 0, count)
			seen := make(map[string]bool)
			for i := 0; i < count; i++ {
				status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "sealed": true})
				if status != 202 {
					t.Fatalf("create %d: %d %v", i, status, doc)
				}
				hotelID := doc["hotel"].(string)
				if seen[hotelID] || doc["placement_tier"] != "prefer" {
					t.Fatalf("create %d reused %s or left sealed tier: %v", i, hotelID, doc)
				}
				seen[hotelID] = true
				rooms = append(rooms, doc["id"].(string))
			}
			if len(seen) != count {
				t.Fatalf("used %d of %d admitted miners", len(seen), count)
			}
			if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 429 || errCode(doc) != "room_limit" {
				t.Fatalf("create past customer cap: %d %v", status, doc)
			}
			if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+rooms[0]+"/exec", map[string]any{"cmd": []string{"true"}}); status != 200 {
				t.Fatalf("exec on miner: %d %v", status, doc)
			}
			if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+rooms[0], nil); status != 204 {
				t.Fatalf("delete on miner: %d %v", status, doc)
			}
		})
	}
}
