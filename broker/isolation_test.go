package main

import (
	"context"
	"testing"
)

// Every room answer says what its placement isolates: the hotel's TEE (or
// none), the room runtime, and that no room is attested on its own. A guest
// reads it from the document, never from the hotel id.
func TestRoomAnswersCarryIsolation(t *testing.T) {
	tc := limitedChain(t, guestLimits{DefaultSealed: true}) // hotel a sealed

	check := func(t *testing.T, where string, doc map[string]any, wantSealed bool) {
		t.Helper()
		iso, ok := doc["isolation"].(map[string]any)
		if !ok {
			t.Fatalf("%s: no isolation block: %v", where, doc)
		}
		if iso["hotel_sealed"] != wantSealed {
			t.Fatalf("%s: hotel_sealed=%v want %v (%v)", where, iso["hotel_sealed"], wantSealed, doc)
		}
		if wantSealed && iso["hotel_tee"] != "amd_sev_snp" {
			t.Fatalf("%s: sealed hotel without tee: %v", where, iso)
		}
		if !wantSealed && iso["hotel_tee"] != nil {
			t.Fatalf("%s: unsealed hotel claims a tee: %v", where, iso)
		}
		if iso["attested_per_room"] != false {
			t.Fatalf("%s: a room must never claim its own attestation: %v", where, iso)
		}
		if _, ok := iso["room_runtime"].(string); !ok {
			t.Fatalf("%s: no room_runtime: %v", where, iso)
		}
		hotel, _ := doc["hotel"].(string)
		if iso["attestation_of_host"] != "/v1/hotels/"+hotel+"/attestation" {
			t.Fatalf("%s: attestation path %v for hotel %s", where, iso["attestation_of_host"], hotel)
		}
	}

	// Native create: sealed by default, unsealed when asked.
	status, sealedDoc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status != 202 {
		t.Fatalf("sealed create: %d %v", status, sealedDoc)
	}
	check(t, "native create sealed", sealedDoc, true)
	status, plainDoc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "sealed": false})
	if status != 202 {
		t.Fatalf("unsealed create: %d %v", status, plainDoc)
	}
	check(t, "native create unsealed", plainDoc, false)

	// Native get and list carry the same block.
	sid, _ := sealedDoc["id"].(string)
	status, got := tc.call(t, "key1", "GET", "/v1/sandboxes/"+sid, nil)
	if status != 200 {
		t.Fatalf("get: %d %v", status, got)
	}
	check(t, "native get", got, true)
	status, list := tc.call(t, "key1", "GET", "/v1/sandboxes", nil)
	if status != 200 {
		t.Fatalf("list: %d %v", status, list)
	}
	rooms, _ := list["sandboxes"].([]any)
	if len(rooms) < 2 {
		t.Fatalf("list has %d rooms", len(rooms))
	}
	for _, r := range rooms {
		d := r.(map[string]any)
		hotel, _ := d["hotel"].(string)
		check(t, "native list "+hotel, d, hotel == "a")
	}

	// Harbor (compat) create and get carry it too, with the hotel named.
	status, cdoc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image": "alpine:3.20", "sealed": false}), nil)
	if status != 201 {
		t.Fatalf("compat create: %d %v", status, cdoc)
	}
	check(t, "compat create", cdoc, false)
	cid, _ := cdoc["id"].(string)
	status, cget := tc.clientCall(t, "GET", "/v1/sandboxes/"+cid, nil, nil)
	if status != 200 {
		t.Fatalf("compat get: %d %v", status, cget)
	}
	check(t, "compat get", cget, false)
	if cget["hotel"] == nil {
		t.Fatalf("compat get names no hotel: %v", cget)
	}
}

// A Harbor create that names no network fails closed: the hotel gets
// deny_all, and the answer says so.
func TestCompatCreateWithoutNetworkIsDenyAll(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image": "alpine:3.20"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	net, _ := tc.lastCreate(t)["network"].(map[string]any)
	if net["mode"] != "deny_all" {
		t.Fatalf("hotel network for a create without a mode: %v", net)
	}
	// Asking for internet still works, in both spellings the client sends.
	for _, body := range []map[string]any{
		{"image": "alpine:3.20", "network": "internet"},
		{"image": "alpine:3.20", "network": map[string]any{"mode": "internet"}},
	} {
		status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(body), nil)
		if status != 201 {
			t.Fatalf("create %v: %d %v", body, status, doc)
		}
		if net, _ = tc.lastCreate(t)["network"].(map[string]any); net["mode"] != "internet" {
			t.Fatalf("explicit internet %v became %v", body, net)
		}
	}
}

func TestNativeCreateWithoutNetworkIsDenyAll(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status != 202 {
		t.Fatalf("create: %d %v", status, doc)
	}
	if net, _ := tc.lastCreate(t)["network"].(map[string]any); net["mode"] != "deny_all" {
		t.Fatalf("hotel network for a native create without a mode: %v", net)
	}
	// A native create that names its network keeps it.
	body := map[string]any{"image": "alpine:3.20", "network": map[string]any{"mode": "internet", "allow": []any{}}}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", body)
	if status != 202 {
		t.Fatalf("create internet: %d %v", status, doc)
	}
	if net, _ := tc.lastCreate(t)["network"].(map[string]any); net["mode"] != "internet" {
		t.Fatalf("explicit internet became %v", net)
	}
}

// room_runtime falls back to the runtime the hotel reports in /room/health,
// because the hotel's room documents carry none.
func TestRoomRuntimeFromHotelHealth(t *testing.T) {
	tc := limitedChain(t, guestLimits{DefaultSealed: true}) // hotel a sealed
	tc.hotels["a"].healthRuntime = "runsc"
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("a"))
	runtimeOf := func(t *testing.T, where string, doc map[string]any) string {
		t.Helper()
		iso, _ := doc["isolation"].(map[string]any)
		rt, _ := iso["room_runtime"].(string)
		return rt
	}
	want := func(t *testing.T, where string, doc map[string]any, rt string) {
		t.Helper()
		if got := runtimeOf(t, where, doc); got != rt {
			t.Fatalf("%s: room_runtime=%q want %q (%v)", where, got, rt, doc)
		}
	}

	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status != 202 {
		t.Fatalf("create: %d %v", status, doc)
	}
	want(t, "native create", doc, "runsc")
	sid, _ := doc["id"].(string)
	_, got := tc.call(t, "key1", "GET", "/v1/sandboxes/"+sid, nil)
	want(t, "native get", got, "runsc")
	_, list := tc.call(t, "key1", "GET", "/v1/sandboxes", nil)
	for _, r := range list["sandboxes"].([]any) {
		d := r.(map[string]any)
		if d["hotel"] == "a" {
			want(t, "native list", d, "runsc")
		}
	}
	// Compat create and get (hotel a is chosen by the sealed default).
	status, cdoc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}}), nil)
	if status != 201 {
		t.Fatalf("compat create: %d %v", status, cdoc)
	}
	want(t, "compat create", cdoc, "runsc")
	cid, _ := cdoc["id"].(string)
	_, cget := tc.clientCall(t, "GET", "/v1/sandboxes/"+cid, nil, nil)
	want(t, "compat get", cget, "runsc")

	// A hotel that reports no runtime stays unknown.
	status, plain := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "sealed": false})
	if status != 202 {
		t.Fatalf("plain create: %d %v", status, plain)
	}
	want(t, "hotel without runtime", plain, "unknown")

	// A failed health fetch keeps the last known value.
	tc.hotels["a"].mu.Lock()
	tc.hotels["a"].healthFail = true
	tc.hotels["a"].mu.Unlock()
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("a"))
	_, got = tc.call(t, "key1", "GET", "/v1/sandboxes/"+sid, nil)
	want(t, "get after failed health", got, "runsc")

	// A room document's own runtime wins.
	h := tc.b.hotelByID("a")
	if rt := isolationDoc(h, map[string]any{"runtime": "kata"})["room_runtime"]; rt != "kata" {
		t.Fatalf("room document runtime lost to health: %v", rt)
	}
}
