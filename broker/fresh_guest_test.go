package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// implementedForTest stands in for a future build that enforces every
// guarantee, so the advertisement shape can be tested now.
var implementedForTest = freshGuestGuarantees{DurableSingleUse: true, ExpectedBinding: true, AttemptBoundPlant: true, Recovery: freshGuestRecovery}

func withEnforcement(t *testing.T, f freshGuestGuarantees) {
	t.Helper()
	old := freshGuestEnforcement
	freshGuestEnforcement = f
	t.Cleanup(func() { freshGuestEnforcement = old })
}

// freshChain is newChain with guest g1 opted in on slots and limited to hotels,
// and hotel "a" labelled escape=true. It restarts the broker so the opt-in goes
// through the config loader.
func freshChain(t *testing.T, hotels, slots []string) *testChain {
	t.Helper()
	tc := newChain(t)
	rewriteConfig(t, tc, func(c *config) {
		c.Guests[0].Hotels = hotels
		c.Guests[0].EscapeFreshGuest = &freshGuestConfig{Slots: slots}
		for i := range c.Hotels {
			if c.Hotels[i].ID == "a" {
				c.Hotels[i].Labels = map[string]string{escapeHotelLabel: escapeHotelWant}
			}
		}
	})
	tc.start(t)
	return tc
}

func rewriteConfig(t *testing.T, tc *testChain, edit func(*config)) {
	t.Helper()
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	edit(&c)
	raw, _ = json.Marshal(c)
	if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func quotaWithHeaders(t *testing.T, tc *testChain, key string) (int, map[string]any, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("GET", tc.srv.URL+"/v1/quota", nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, doc, resp.Header
}

// The exact document the API parser accepts (polariscomputer #2069
// fresh_guests.py parse_capability).
func TestFreshGuestAdvertisedWhenOnAndImplemented(t *testing.T) {
	withEnforcement(t, implementedForTest)
	tc := freshChain(t, []string{"a", "b"}, []string{"a"})
	status, doc, hdr := quotaWithHeaders(t, tc, "key1")
	if status != 200 {
		t.Fatalf("quota: %d %v", status, doc)
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q, want no-store", hdr.Get("Cache-Control"))
	}
	want := map[string]any{
		"schema": "cathedral.escape.fresh_guest/v1", "guest": "g1",
		"durable_single_use": true, "expected_binding": true, "attempt_bound_plant": true,
		"recovery": "same_request_or_refuse", "slots": []any{"a"},
	}
	if got := doc["escape_fresh_guest"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("escape_fresh_guest = %v, want %v", got, want)
	}
	// The API also requires each slot in guest.allowed_hotels.
	guest := doc["guest"].(map[string]any)
	if guest["id"] != "g1" || !reflect.DeepEqual(guest["allowed_hotels"], []any{"a", "b"}) {
		t.Fatalf("guest = %v", guest)
	}
	// Another guest with no opt-in never sees it.
	if _, doc2, _ := quotaWithHeaders(t, tc, "key2"); doc2["escape_fresh_guest"] != nil {
		t.Fatalf("g2 got the capability: %v", doc2["escape_fresh_guest"])
	}
}

// Default off: no opt-in, no extension, even on a build that implements it.
func TestFreshGuestAbsentWhenOff(t *testing.T) {
	withEnforcement(t, implementedForTest)
	tc := newChain(t)
	for _, key := range []string{"key1", "key2"} {
		status, doc, hdr := quotaWithHeaders(t, tc, key)
		if status != 200 {
			t.Fatalf("quota %s: %d", key, status)
		}
		if _, ok := doc["escape_fresh_guest"]; ok {
			t.Fatalf("%s: advertised with no opt-in: %v", key, doc["escape_fresh_guest"])
		}
		if hdr.Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control %q", hdr.Get("Cache-Control"))
		}
	}
}

// The opt-in is not a declaration: this build enforces none of the guarantees,
// so a configured guest gets nothing. Each missing guarantee alone withholds it.
func TestFreshGuestAbsentUntilBuildImplementsIt(t *testing.T) {
	if freshGuestEnforcement.complete() {
		t.Fatal("this build claims fresh guest enforcement; AB#683 has not implemented it")
	}
	tc := freshChain(t, []string{"a"}, []string{"a"})
	if _, doc, _ := quotaWithHeaders(t, tc, "key1"); doc["escape_fresh_guest"] != nil {
		t.Fatalf("advertised by a build without enforcement: %v", doc["escape_fresh_guest"])
	}
	partial := []freshGuestGuarantees{
		{ExpectedBinding: true, AttemptBoundPlant: true, Recovery: freshGuestRecovery},
		{DurableSingleUse: true, AttemptBoundPlant: true, Recovery: freshGuestRecovery},
		{DurableSingleUse: true, ExpectedBinding: true, Recovery: freshGuestRecovery},
		{DurableSingleUse: true, ExpectedBinding: true, AttemptBoundPlant: true},
		{DurableSingleUse: true, ExpectedBinding: true, AttemptBoundPlant: true, Recovery: "retry"},
	}
	for i, p := range partial {
		freshGuestEnforcement = p
		_, doc, _ := quotaWithHeaders(t, tc, "key1")
		freshGuestEnforcement = freshGuestGuarantees{}
		if doc["escape_fresh_guest"] != nil {
			t.Fatalf("partial %d advertised: %v", i, doc["escape_fresh_guest"])
		}
	}
}

func TestFreshGuestAuthRequired(t *testing.T) {
	withEnforcement(t, implementedForTest)
	tc := freshChain(t, []string{"a"}, []string{"a"})
	for _, key := range []string{"", "wrong-key", "view1"} {
		status, doc, _ := quotaWithHeaders(t, tc, key)
		if status != 401 && status != 403 {
			t.Fatalf("key %q: status %d, want 401/403", key, status)
		}
		if doc["escape_fresh_guest"] != nil || doc["guest"] != nil {
			t.Fatalf("key %q leaked the quota: %v", key, doc)
		}
	}
}

// Every answer is computed now: removing the slot from the guest's hotels at
// runtime, or a policy, withdraws it on the next read.
func TestFreshGuestUncachedAcrossRuntimeChange(t *testing.T) {
	withEnforcement(t, implementedForTest)
	tc := freshChain(t, []string{"a", "b"}, []string{"a"})
	if _, doc, _ := quotaWithHeaders(t, tc, "key1"); doc["escape_fresh_guest"] == nil {
		t.Fatal("not advertised before the change")
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"hotels": []string{"b"}}); status != 200 {
		t.Fatalf("patch: %d %v", status, doc)
	}
	if _, doc, _ := quotaWithHeaders(t, tc, "key1"); doc["escape_fresh_guest"] != nil {
		t.Fatalf("still advertised after the slot left the guest's hotels: %v", doc["escape_fresh_guest"])
	}
	// And a downgraded build (enforcement withdrawn) stops at once.
	if status, _ := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"hotels": []string{"a", "b"}}); status != 200 {
		t.Fatal("patch back")
	}
	if _, doc, _ := quotaWithHeaders(t, tc, "key1"); doc["escape_fresh_guest"] == nil {
		t.Fatal("not advertised after the slot came back")
	}
	freshGuestEnforcement = freshGuestGuarantees{}
	if _, doc, _ := quotaWithHeaders(t, tc, "key1"); doc["escape_fresh_guest"] != nil {
		t.Fatalf("advertised after enforcement was withdrawn: %v", doc["escape_fresh_guest"])
	}
}

// A slot must be a sealed hotel labelled escape=true; "b" has no label.
func TestFreshGuestSlotMustBeEscapeHotel(t *testing.T) {
	withEnforcement(t, implementedForTest)
	tc := freshChain(t, []string{"a", "b"}, []string{"a", "b"})
	_, doc, _ := quotaWithHeaders(t, tc, "key1")
	fg, _ := doc["escape_fresh_guest"].(map[string]any)
	if fg == nil || !reflect.DeepEqual(fg["slots"], []any{"a"}) {
		t.Fatalf("slots = %v, want [a] only", fg)
	}
	tc2 := freshChain(t, []string{"b"}, []string{"b"})
	if _, doc, _ := quotaWithHeaders(t, tc2, "key1"); doc["escape_fresh_guest"] != nil {
		t.Fatalf("advertised with no escape hotel: %v", doc["escape_fresh_guest"])
	}
}

func TestFreshGuestConfigRefused(t *testing.T) {
	cases := map[string]func(*guestConfig){
		"no slots":        func(g *guestConfig) { g.EscapeFreshGuest.Slots = nil },
		"empty slot list": func(g *guestConfig) { g.EscapeFreshGuest.Slots = []string{} },
		"wildcard":        func(g *guestConfig) { g.EscapeFreshGuest.Slots = []string{"*"} },
		"path":            func(g *guestConfig) { g.EscapeFreshGuest.Slots = []string{"../a"} },
		"upper case":      func(g *guestConfig) { g.EscapeFreshGuest.Slots = []string{"A"} },
		"too long":        func(g *guestConfig) { g.EscapeFreshGuest.Slots = []string{strings.Repeat("a", 64)} },
		"duplicate":       func(g *guestConfig) { g.EscapeFreshGuest.Slots = []string{"a", "a"} },
		"not in hotels":   func(g *guestConfig) { g.EscapeFreshGuest.Slots = []string{"c"} },
		"no hotels list":  func(g *guestConfig) { g.Hotels = nil },
		"policy":          func(g *guestConfig) { g.Policy = &guestPolicy{} },
		"too many": func(g *guestConfig) {
			g.EscapeFreshGuest.Slots = nil
			for i := 0; i < 65; i++ {
				g.EscapeFreshGuest.Slots = append(g.EscapeFreshGuest.Slots, "s"+strings.Repeat("x", i%40)+string(rune('a'+i%26))+string(rune('a'+i/26)))
			}
			g.Hotels = g.EscapeFreshGuest.Slots
		},
	}
	for name, edit := range cases {
		gc := guestConfig{ID: "g1", guestLimits: guestLimits{Hotels: []string{"a", "b"}}, EscapeFreshGuest: &freshGuestConfig{Slots: []string{"a"}}}
		edit(&gc)
		if err := validateFreshGuestConfig(gc); !errors.Is(err, errFreshGuestConfig) {
			t.Errorf("%s: err %v, want refusal", name, err)
		}
	}
	ok := guestConfig{ID: "g1", guestLimits: guestLimits{Hotels: []string{"a", "b"}}, EscapeFreshGuest: &freshGuestConfig{Slots: []string{"a", "b"}}}
	if err := validateFreshGuestConfig(ok); err != nil {
		t.Fatalf("valid opt-in refused: %v", err)
	}
	if err := validateFreshGuestConfig(guestConfig{ID: "g1"}); err != nil {
		t.Fatalf("absent opt-in refused: %v", err)
	}
}

// The loader refuses a bad opt-in, so a typo cannot run.
func TestFreshGuestLoaderRefusesBadOptIn(t *testing.T) {
	tc := newChain(t)
	rewriteConfig(t, tc, func(c *config) {
		c.Guests[0].Hotels = []string{"a"}
		c.Guests[0].EscapeFreshGuest = &freshGuestConfig{Slots: []string{"c"}}
	})
	if _, err := loadBroker(tc.cfgPath); !errors.Is(err, errFreshGuestConfig) {
		t.Fatalf("load: %v, want escape_fresh_guest refusal", err)
	}
	raw, _ := os.ReadFile(tc.cfgPath)
	raw = []byte(strings.Replace(string(raw), `"escape_fresh_guest":{"slots":["c"]}`, `"escape_fresh_guest":{"slots":["a"],"enabled":true}`, 1))
	p := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(p, raw, 0o600)
	if _, err := loadBroker(p); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field under escape_fresh_guest: %v", err)
	}
}
