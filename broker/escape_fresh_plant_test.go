package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// AB#683: the plant route forwards the fresh assignment and room id to the
// guest, which signs them and refuses a mismatch. The broker refuses a
// malformed one unsent.

func freshPlantHotel(t *testing.T) (*testChain, *fakeHotel) {
	t.Helper()
	tc := newChain(t)
	receiptPub, receiptPriv, plant := escapePlantKeys(t)
	h := tc.b.hotelByID("a")
	admitEscapeHotel(tc, h, receiptPub, "binding-a")
	f := tc.hotels["a"]
	f.mu.Lock()
	f.plantKeyDoc = signPlantKey(t, receiptPriv, "a", "binding-a", plant.PublicKey().Bytes())
	f.mu.Unlock()
	return tc, f
}

func freshPlantBody() map[string]any {
	return map[string]any{
		"window_id":  "win-1",
		"nonce":      "control-plane-nonce-1",
		"sandbox_id": "room-1",
		"escape_fresh": map[string]any{
			"schema":                escapeFreshSchema,
			"attempt_id":            "attempt-1",
			"report_id":             "launch-1",
			"request_sha256":        strings.Repeat("a", 64),
			"create_receipt_sha256": strings.Repeat("b", 64),
		},
	}
}

func TestEscapeNoncePlantForwardsTheFreshAssignment(t *testing.T) {
	tc, f := freshPlantHotel(t)
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce", freshPlantBody())
	if status != 200 {
		t.Fatalf("plant: %d %v", status, doc)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.plantPosts) != 1 {
		t.Fatalf("hotel posts %d", len(f.plantPosts))
	}
	var posted map[string]any
	if json.Unmarshal(f.plantPosts[0], &posted) != nil {
		t.Fatalf("hotel body: %s", f.plantPosts[0])
	}
	want := freshPlantBody()["escape_fresh"].(map[string]any)
	got, _ := posted["escape_fresh"].(map[string]any)
	if posted["sandbox_id"] != "room-1" || len(got) != len(want) {
		t.Fatalf("posted %v", posted)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("escape_fresh %s = %v, want %v", k, got[k], v)
		}
	}
	if posted["ciphertext_b64"] == nil || posted["nonce"] != nil || posted["window_id"] != "win-1" {
		t.Fatalf("expected the sealed envelope: %v", posted)
	}
}

func TestEscapeNoncePlantWithoutFreshSendsNoFreshFields(t *testing.T) {
	tc, f := freshPlantHotel(t)
	body := freshPlantBody()
	delete(body, "sandbox_id")
	delete(body, "escape_fresh")
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce", body); status != 200 {
		t.Fatalf("plant: %d %v", status, doc)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var posted map[string]any
	_ = json.Unmarshal(f.plantPosts[0], &posted)
	if _, ok := posted["sandbox_id"]; ok {
		t.Fatalf("posted %v", posted)
	}
	if _, ok := posted["escape_fresh"]; ok {
		t.Fatalf("posted %v", posted)
	}
}

func TestEscapeNoncePlantRefusesAMalformedFreshAssignment(t *testing.T) {
	fresh := func(k string, v any) func(map[string]any) {
		return func(b map[string]any) { b["escape_fresh"].(map[string]any)[k] = v }
	}
	cases := map[string]func(map[string]any){
		"no sandbox_id":     func(b map[string]any) { delete(b, "sandbox_id") },
		"no escape_fresh":   func(b map[string]any) { delete(b, "escape_fresh") },
		"bad sandbox_id":    func(b map[string]any) { b["sandbox_id"] = "../room-1" },
		"wrong schema":      fresh("schema", "cathedral.escape.fresh_evidence/v0"),
		"empty attempt":     fresh("attempt_id", ""),
		"bad report":        fresh("report_id", "a/b"),
		"short request":     fresh("request_sha256", strings.Repeat("a", 63)),
		"upper create":      fresh("create_receipt_sha256", strings.Repeat("B", 64)),
		"missing create":    func(b map[string]any) { delete(b["escape_fresh"].(map[string]any), "create_receipt_sha256") },
		"extra fresh field": fresh("owner_id", "o"),
		"extra top field":   func(b map[string]any) { b["room"] = "room-1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tc, f := freshPlantHotel(t)
			body := freshPlantBody()
			mutate(body)
			status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce", body)
			if status != 400 {
				t.Fatalf("plant: %d %v", status, doc)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if len(f.plantPosts) != 0 {
				t.Fatalf("hotel got a refused plant: %s", f.plantPosts[0])
			}
		})
	}
}

// A fresh plant receipt names its room, so it follows that room's receipts:
// the room's owner (the Escape guest) sees it, no other guest does.
func TestFreshPlantReceiptIsVisibleOnlyToTheRoomOwner(t *testing.T) {
	plant := []byte(`{"statement":{"sandbox_id":"room-1","action":"escape_nonce_plant","window_id":"win-1","nonce_sha256":"ab","escape_fresh":{"attempt_id":"attempt-1"}},"signature_b64":"sig-plant"}`)
	legacy := []byte(`{"statement":{"sandbox_id":null,"action":"escape_nonce_plant","window_id":"win-0"},"signature_b64":"sig-legacy"}`)
	body := []byte(`{"binding_sha256":"bb","head":"hh","count":2,"receipts":[` + string(plant) + `,` + string(legacy) + `]}`)
	other, err := filterHotelReceipts(body, map[string]bool{"room-2": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"escape_nonce_plant", "sig-plant", "win-1", "attempt-1", "sig-legacy"} {
		if bytes.Contains(other, []byte(leak)) {
			t.Fatalf("another guest sees the plant: %s", leak)
		}
	}
	owner, err := filterHotelReceipts(body, map[string]bool{"room-1": true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(owner, plant) || bytes.Contains(owner, []byte("sig-legacy")) {
		t.Fatalf("owner view: %s", owner)
	}
}
