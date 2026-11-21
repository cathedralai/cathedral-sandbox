package main

import (
	"regexp"
	"testing"
)

// AB#894: the ComputeSDK provider (@computesdk/cathedral) in front-door mode
// talks to the broker directly. Its User-Agent must get the cloud API shape
// (UUID ids, templates, 201 running); any other agent stays native.

const computeSDKAgent = "computesdk-cathedral/0.1 (+https://www.computesdk.com)"

var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestComputeSDKAgentIsCompat(t *testing.T) {
	tc := newChain(t)
	body := mustMarshal(map[string]any{"template": "node-22", "lifetime_seconds": 600, "network": "deny_all"})

	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", body, map[string]string{"User-Agent": computeSDKAgent})
	if status != 201 {
		t.Fatalf("compat create: %d %v", status, doc)
	}
	id, _ := doc["id"].(string)
	if !uuidV4.MatchString(id) {
		t.Fatalf("compat create id %q is not a UUID: %v", id, doc)
	}
	if doc["state"] != "running" {
		t.Fatalf("compat create state: %v", doc)
	}

	// The same body from another agent is a native create: 202 and the hotel's own id.
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", body, map[string]string{"User-Agent": "node"})
	if status != 202 {
		t.Fatalf("native create: %d %v", status, doc)
	}
	if id, _ := doc["id"].(string); id == "" || uuidV4.MatchString(id) {
		t.Fatalf("native create id %q should be the hotel id, not a UUID: %v", id, doc)
	}
}

// With one sealed and one unsealed hotel, the provider's node-22 creates and
// its raw-image creates with "sealed": true all land on the sealed hotel.
func TestComputeSDKCreatesLandOnTheSealedHotelOnly(t *testing.T) {
	tc := newChain(t)
	setHotelOK(tc, "c", false) // fixture: sealed a, unsealed b
	hdr := map[string]string{"User-Agent": computeSDKAgent}
	bodies := map[string]map[string]any{
		"template":  {"template": "node-22", "lifetime_seconds": 600, "network": "deny_all"},
		"raw image": {"image": pinnedImage("node", nodeDigest), "lifetime_seconds": 600, "network": "deny_all", "sealed": true},
	}
	for name, body := range bodies {
		before := createsOn(tc)
		for i := 0; i < 20; i++ {
			setHotel(tc, "a", func(h *hotel) { h.createEWMA = 1 })
			setHotel(tc, "b", func(h *hotel) { h.createEWMA = 1 })
			status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(body), hdr)
			if status != 201 {
				t.Fatalf("%s create %d: %d %v", name, i, status, doc)
			}
		}
		after := createsOn(tc)
		if a, other := after["a"]-before["a"], after["b"]-before["b"]+after["c"]-before["c"]; a != 20 || other != 0 {
			t.Fatalf("%s: want 20 creates on sealed hotel a and none elsewhere, got a=%d other=%d", name, a, other)
		}
	}
}
