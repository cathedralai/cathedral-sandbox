package main

import (
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
)

// terminalRoutes are the room terminal routes, REST and WebSocket, under a
// room path.
var terminalRoutes = []struct{ method, tail string }{
	{"POST", "/terminals"},
	{"GET", "/terminals"},
	{"POST", "/terminals/t1/connect"},
	{"POST", "/terminals/t1/input"},
	{"GET", "/terminals/t1/output"},
	{"GET", "/terminals/t1/ws"},
	{"DELETE", "/terminals/t1"},
}

// withTerminalHotels writes terminal_hotels into the chain's config and
// restarts the broker over the same hotels.
func withTerminalHotels(t *testing.T, tc *testChain, ids ...string) {
	t.Helper()
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.TerminalHotels = ids
	raw, _ = json.Marshal(cfg)
	if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.start(t)
}

// terminalCalls lists the terminal requests hotel id received.
func terminalCalls(tc *testChain, id string) []string {
	f := tc.hotels[id]
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.Contains(c, "/terminals") {
			out = append(out, c)
		}
	}
	return out
}

func errMsg(doc map[string]any) string {
	e, _ := doc["error"].(map[string]any)
	s, _ := e["message"].(string)
	return s
}

// assertTerminalsRefused checks that every terminal route of room id answers
// 403 terminals_disabled with a message that contains why, and that its hotel
// saw none of them.
func assertTerminalsRefused(t *testing.T, tc *testChain, id, why string) {
	t.Helper()
	for _, c := range terminalRoutes {
		code, doc := tc.call(t, "key1", c.method, "/v1/sandboxes/"+id+c.tail, nil)
		if code != http.StatusForbidden || errCode(doc) != "terminals_disabled" || !strings.Contains(errMsg(doc), why) {
			t.Errorf("%s %s: %d %v, want 403 terminals_disabled (%s)", c.method, c.tail, code, doc, why)
		}
	}
	if got := terminalCalls(tc, hotelOf(id)); len(got) > 0 {
		t.Errorf("hotel %s received terminal calls %v", hotelOf(id), got)
	}
}

// B154: with no terminal_hotels (the default) the broker refuses every room
// terminal route on every hotel before it reaches the hotel, as before.
func TestRoomTerminalRoutesAreRefused(t *testing.T) {
	tc := newChain(t)
	if len(tc.b.cfg.TerminalHotels) != 0 {
		t.Fatalf("default terminal_hotels: %v", tc.b.cfg.TerminalHotels)
	}
	for _, h := range []string{"a", "b", "c"} {
		id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{h}})
		if hotelOf(id) != h {
			t.Fatalf("room %s, want hotel %s", id, h)
		}
		assertTerminalsRefused(t, tc, id, "allowlist")
		// exec still reaches the hotel
		if code, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+id+"/exec", map[string]any{"cmd": []string{"true"}}); code != http.StatusOK {
			t.Errorf("exec on %s: %d %v", h, code, doc)
		}
	}
	// The client path (Harbor, ctcli) goes through the same gate.
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 200 && status != 201 && status != 202 {
		t.Fatalf("client create: %d %v", status, doc)
	}
	uuid, _ := doc["id"].(string)
	tc.b.mu.Lock()
	hotelID := tc.b.byUUID[uuid].h.cfg.ID
	tc.b.mu.Unlock()
	if status, doc := tc.clientCall(t, "POST", "/v1/sandboxes/"+uuid+"/terminals", nil, nil); status != http.StatusForbidden {
		t.Errorf("client terminals: %d %v, want 403", status, doc)
	}
	if got := terminalCalls(tc, hotelID); len(got) > 0 {
		t.Errorf("hotel %s received terminal calls %v", hotelID, got)
	}
}

// A listed operator hotel gets the terminal routes; an unlisted one keeps the
// 403. Ownership and the dot-segment check still apply after the gate.
func TestTerminalHotelsOpenOnlyListedOperatorHotels(t *testing.T) {
	tc := newChain(t)
	withTerminalHotels(t, tc, "b", "not-joined-yet")
	listed := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	unlisted := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}})
	_, hid, _ := strings.Cut(listed, ".")

	for _, c := range terminalRoutes {
		code, doc := tc.call(t, "key1", c.method, "/v1/sandboxes/"+listed+c.tail, nil)
		want := c.method + " /v1/sandboxes/" + hid + c.tail
		if code != http.StatusOK || doc["terminal_route"] != want {
			t.Errorf("%s %s on listed hotel: %d %v, want the hotel answer for %q", c.method, c.tail, code, doc, want)
		}
	}
	if got := terminalCalls(tc, "b"); len(got) != len(terminalRoutes) {
		t.Errorf("listed hotel received %d terminal calls, want %d: %v", len(got), len(terminalRoutes), got)
	}

	assertTerminalsRefused(t, tc, unlisted, "allowlist")

	// Another guest's room on the listed hotel is still not found.
	before := len(terminalCalls(tc, "b"))
	if code, doc := tc.call(t, "key2", "POST", "/v1/sandboxes/"+listed+"/terminals", nil); code != http.StatusNotFound {
		t.Errorf("other guest: %d %v, want 404", code, doc)
	}
	// A dot segment after terminals is still refused before the hotel.
	if code, _, err := rawCall(tc, "key1", "", "GET", "/v1/sandboxes/"+listed+"/terminals/../../..", nil); err != nil || code != http.StatusBadRequest {
		t.Errorf("dot segment: %d %v, want 400", code, err)
	}
	if got := terminalCalls(tc, "b"); len(got) != before {
		t.Errorf("hotel b received %v", got[before:])
	}
}

// A miner hotel stays closed even when terminal_hotels names it: the broker
// cannot see which kit a miner runs. An operator hotel joined at runtime and
// listed opens like a config hotel.
func TestTerminalHotelsNeverOpenMinerHotels(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	withTerminalHotels(t, tc, "miner-1", "op-join")
	joinMiner(t, tc, "miner-1", true, 4, nil)
	if a := admissionOf(t, tc, "miner-1"); a["state"] != "admitted" {
		t.Fatalf("miner-1 admission: %v", a)
	}
	joinMiner(t, tc, "op-join", false, 4, nil) // unsealed operator hotel, no hotkey
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{
		"policy": map[string]any{"prefer": []any{
			map[string]any{"label": map[string]string{"sealed": "true", "miner": "true"}},
			map[string]any{"hotel": "op-join"},
		}},
	}); status != 200 {
		t.Fatalf("opt g1 into the miner: %d %v", status, doc)
	}

	miner := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "sealed": true, "hotels": []string{"miner-1"}})
	if hotelOf(miner) != "miner-1" {
		t.Fatalf("room %s, want miner-1", miner)
	}
	assertTerminalsRefused(t, tc, miner, "miner")
	if code, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+miner+"/exec", map[string]any{"cmd": []string{"true"}}); code != http.StatusOK {
		t.Errorf("exec on miner: %d %v", code, doc)
	}

	op := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"op-join"}})
	if code, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+op+"/terminals", nil); code != http.StatusOK || doc["terminal_route"] == nil {
		t.Errorf("listed runtime operator hotel: %d %v, want the hotel answer", code, doc)
	}
}

// The miner marks each close a listed hotel: the hotkey, the miner label, and
// the miner-<hex> id of a miner join.
func TestIsMinerHotelMarks(t *testing.T) {
	for _, c := range []struct {
		hc   hotelConfig
		want bool
	}{
		{hotelConfig{ID: "c46-sealed-2", Sealed: true}, false},
		{hotelConfig{ID: "contabo"}, false},
		{hotelConfig{ID: "x1", Sealed: true, MinerHotkey: minerHotkey}, true},
		{hotelConfig{ID: "x2", Labels: map[string]string{"miner": "true"}}, true},
		{hotelConfig{ID: "miner-5f2a", Sealed: true}, true},
	} {
		if got := isMinerHotel(newHotel(c.hc, "k")); got != c.want {
			t.Errorf("%s: isMinerHotel %v, want %v", c.hc.ID, got, c.want)
		}
	}
}

func TestTerminalHotelsConfigRejectsNonIDs(t *testing.T) {
	for _, bad := range [][]string{{""}, {"c46.sbx_1"}} {
		tc := newChain(t)
		raw, _ := os.ReadFile(tc.cfgPath)
		var cfg config
		_ = json.Unmarshal(raw, &cfg)
		cfg.TerminalHotels = bad
		raw, _ = json.Marshal(cfg)
		_ = os.WriteFile(tc.cfgPath, raw, 0o600)
		if _, err := loadBroker(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "terminal_hotels") {
			t.Errorf("terminal_hotels %q: err %v, want a terminal_hotels refusal", bad, err)
		}
	}
	tc := newChain(t)
	withTerminalHotels(t, tc, "c46", "c48", "contabo")
	if !slices.Equal(tc.b.cfg.TerminalHotels, []string{"c46", "c48", "contabo"}) {
		t.Errorf("loaded terminal_hotels %v", tc.b.cfg.TerminalHotels)
	}
}
