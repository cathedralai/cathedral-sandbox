package main

import (
	"net/http"
	"strings"
	"testing"
)

// desktopRoutes are the hotel's room desktop routes, REST and WebSocket.
var desktopRoutes = []string{"/desktop", "/desktop/ws"}

// desktopCalls lists the desktop requests hotel id received.
func desktopCalls(tc *testChain, id string) []string {
	f := tc.hotels[id]
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.Contains(c, "/desktop") {
			out = append(out, c)
		}
	}
	return out
}

// assertDesktopRefused checks that every desktop route of room id answers
// 403 desktop_disabled and that its hotel saw none of them.
func assertDesktopRefused(t *testing.T, tc *testChain, key, id string) {
	t.Helper()
	for _, tail := range desktopRoutes {
		code, doc := tc.call(t, key, "GET", "/v1/sandboxes/"+id+tail, nil)
		if code != http.StatusForbidden || errCode(doc) != "desktop_disabled" || !strings.Contains(errMsg(doc), "exec") {
			t.Errorf("GET %s on %s: %d %v, want 403 desktop_disabled", tail, id, code, doc)
		}
	}
	if got := desktopCalls(tc, hotelOf(id)); len(got) > 0 {
		t.Errorf("hotel %s received desktop calls %v", hotelOf(id), got)
	}
}

// AB#121: the desktop routes stay closed on every hotel, including one listed
// in terminal_hotels, while exec still runs and the listed hotel's ticketed
// terminal WebSocket route still reaches it.
func TestRoomDesktopRoutesAreRefusedOnEveryHotel(t *testing.T) {
	tc := newChain(t)
	withTerminalHotels(t, tc, "b")
	for _, h := range []string{"a", "b", "c"} {
		id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{h}})
		if hotelOf(id) != h {
			t.Fatalf("room %s, want hotel %s", id, h)
		}
		assertDesktopRefused(t, tc, "key1", id)
		if code, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+id+"/exec", map[string]any{"cmd": []string{"true"}}); code != http.StatusOK {
			t.Errorf("exec on %s: %d %v", h, code, doc)
		}
		code, doc := tc.call(t, "key1", "GET", "/v1/sandboxes/"+id+"/terminals/t1/ws", nil)
		if h == "b" {
			if code != http.StatusOK || doc["terminal_route"] == nil {
				t.Errorf("terminal ws on listed hotel: %d %v, want the hotel answer", code, doc)
			}
		} else if code != http.StatusForbidden || errCode(doc) != "terminals_disabled" {
			t.Errorf("terminal ws on %s: %d %v, want 403 terminals_disabled", h, code, doc)
		}
	}

	// The gate answers before the room lookup, as the terminal gate does:
	// another guest's room and a missing room get the same 403.
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	assertDesktopRefused(t, tc, "key2", id)
	assertDesktopRefused(t, tc, "key1", "a.sbx_missing")

	// The client path (Harbor, ctcli) goes through the same gate.
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 200 && status != 201 && status != 202 {
		t.Fatalf("client create: %d %v", status, doc)
	}
	uuid, _ := doc["id"].(string)
	tc.b.mu.Lock()
	hotelID := tc.b.byUUID[uuid].h.cfg.ID
	tc.b.mu.Unlock()
	for _, tail := range desktopRoutes {
		if status, doc := tc.clientCall(t, "GET", "/v1/sandboxes/"+uuid+tail, nil, nil); status != http.StatusForbidden {
			t.Errorf("client GET %s: %d %v, want 403", tail, status, doc)
		}
	}
	if got := desktopCalls(tc, hotelID); len(got) > 0 {
		t.Errorf("hotel %s received desktop calls %v", hotelID, got)
	}
}

// A miner hotel gets no desktop route either, while exec still runs there.
func TestRoomDesktopRoutesAreRefusedOnMinerHotels(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "miner-1", true, 4, nil)
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{
		"policy": map[string]any{"prefer": []any{
			map[string]any{"label": map[string]string{"sealed": "true", "miner": "true"}},
		}},
	}); status != 200 {
		t.Fatalf("opt g1 into the miner: %d %v", status, doc)
	}
	miner := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "sealed": true, "hotels": []string{"miner-1"}})
	if hotelOf(miner) != "miner-1" {
		t.Fatalf("room %s, want miner-1", miner)
	}
	assertDesktopRefused(t, tc, "key1", miner)
	if code, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+miner+"/exec", map[string]any{"cmd": []string{"true"}}); code != http.StatusOK {
		t.Errorf("exec on miner: %d %v", code, doc)
	}
}
