package main

import (
	"net/http"
	"testing"
)

// B154: the broker refuses every room terminal route, REST and WebSocket,
// before it reaches a hotel.
func TestRoomTerminalRoutesAreRefused(t *testing.T) {
	tc := newChain(t)
	code, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if code != 202 && code != 201 && code != 200 {
		t.Fatalf("create: %d %v", code, doc)
	}
	id, _ := doc["id"].(string)
	if id == "" {
		t.Fatalf("no id in %v", doc)
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/v1/sandboxes/" + id + "/terminals"},
		{"GET", "/v1/sandboxes/" + id + "/terminals"},
		{"POST", "/v1/sandboxes/" + id + "/terminals/t1/connect"},
		{"POST", "/v1/sandboxes/" + id + "/terminals/t1/input"},
		{"GET", "/v1/sandboxes/" + id + "/terminals/t1/output"},
		{"GET", "/v1/sandboxes/" + id + "/terminals/t1/ws"},
		{"DELETE", "/v1/sandboxes/" + id + "/terminals/t1"},
	} {
		code, doc := tc.call(t, "key1", c.method, c.path, nil)
		if code != http.StatusForbidden {
			t.Errorf("%s %s: %d %v, want 403", c.method, c.path, code, doc)
		}
	}
	// exec still reaches the hotel
	if code, _ := tc.call(t, "key1", "POST", "/v1/sandboxes/"+id+"/exec", map[string]any{"cmd": []string{"true"}}); code == http.StatusForbidden {
		t.Errorf("exec was refused")
	}
}
