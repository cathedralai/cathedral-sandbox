package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func (tc *testChain) lastCreate(t *testing.T) map[string]any {
	t.Helper()
	for _, f := range tc.hotels {
		if n := len(f.creates); n > 0 {
			return f.creates[n-1]
		}
	}
	t.Fatal("no create reached a hotel")
	return nil
}

func TestClientCreateMapsNetworkModes(t *testing.T) {
	cases := []struct {
		body map[string]any
		mode string
		n    int
	}{
		{map[string]any{"template": "room-1x4"}, "deny_all", 0}, // no mode named: fail closed
		{map[string]any{"template": "room-1x4", "network": ""}, "deny_all", 0},
		{map[string]any{"template": "room-1x4", "network": "internet"}, "internet", 0},
		{map[string]any{"template": "room-1x4", "network": "public"}, "internet", 0},
		{map[string]any{"template": "room-1x4", "network": "deny_all"}, "deny_all", 0},
		{map[string]any{"template": "room-1x4", "network": "none"}, "deny_all", 0},
		{map[string]any{"template": "room-1x4", "network": "allowlist", "network_allow": []string{"pypi.org", "1.2.3.0/24"}}, "allowlist", 2},
		{map[string]any{"template": "room-1x4", "network": map[string]any{"mode": "allowlist", "allow": []string{"*.example.com"}}}, "allowlist", 1},
	}
	for _, c := range cases {
		tc := newChain(t)
		status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(c.body), nil)
		if status != 201 {
			t.Fatalf("%v: create %d %v", c.body, status, doc)
		}
		net := tc.lastCreate(t)["network"].(map[string]any)
		if net["mode"] != c.mode || len(net["allow"].([]any)) != c.n {
			t.Fatalf("%v: hotel network %v", c.body, net)
		}
	}
	tc := newChain(t)
	for _, bad := range []map[string]any{
		{"template": "room-1x4", "network": "allowlist"},
		{"template": "room-1x4", "network": "open"},
		{"template": "room-1x4", "network": "allowlist", "network_allow": "pypi.org"},
	} {
		if status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(bad), nil); status != 400 {
			t.Fatalf("%v: want 400, got %d %v", bad, status, doc)
		}
	}
}

func TestClientSwitchesNetworkLive(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4", "network": "deny_all"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	id := doc["id"].(string)
	status, doc = tc.clientCall(t, "PUT", "/v1/sandboxes/"+id+"/network", mustMarshal(map[string]any{"mode": "allowlist", "allow": []string{"pypi.org"}}), nil)
	if status != 200 || doc["id"] != id {
		t.Fatalf("switch: %d %v", status, doc)
	}
	pol := doc["network"].(map[string]any)["policy"].(map[string]any)
	if pol["mode"] != "allowlist" || pol["allow"].([]any)[0] != "pypi.org" {
		t.Fatalf("policy: %v", pol)
	}
	var sent []map[string]any
	for _, f := range tc.hotels {
		sent = append(sent, f.networks...)
	}
	if len(sent) != 1 || sent[0]["mode"] != "allowlist" {
		t.Fatalf("hotel got %v", sent)
	}
	// The hotel error reaches the client in the client envelope.
	status, doc = tc.clientCall(t, "PUT", "/v1/sandboxes/"+id+"/network", mustMarshal(map[string]any{"mode": "allowlist", "allow": []string{"::1"}}), nil)
	if status != 400 || doc["detail"].(map[string]any)["error"] != "invalid_network_allowlist" {
		t.Fatalf("bad switch: %d %v", status, doc)
	}
	if status, _ := tc.clientCall(t, "PUT", "/v1/sandboxes/00000000-0000-4000-8000-000000000000/network", mustMarshal(map[string]any{"mode": "internet"}), nil); status != 404 {
		t.Fatalf("unknown room: %d", status)
	}
	_, cat := tc.clientCall(t, "GET", "/v1/sandboxes/catalog", nil, nil)
	if cat["dynamic_network_policy"] != true {
		t.Fatalf("catalog: %v", cat)
	}
	modes := cat["templates"].([]any)[0].(map[string]any)["network_modes"].([]any)
	if len(modes) != 3 || modes[2] != "allowlist" {
		t.Fatalf("modes: %v", modes)
	}
}

// A native guest switches with PUT on the broker room id; the signed receipt
// header of a sealed hotel passes through.
func TestNativeSwitchPassesThroughWithReceipt(t *testing.T) {
	tc := newChain(t)
	req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes", bytes.NewReader(mustMarshal(map[string]any{
		"image": "alpine:3.20", "network": map[string]any{"mode": "allowlist", "allow": []string{"pypi.org"}}})))
	req.Header.Set("Authorization", "Bearer key1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil || resp.StatusCode != 202 {
		t.Fatalf("create: %d %s", resp.StatusCode, raw)
	}
	bid := doc["id"].(string)
	req, _ = http.NewRequest("PUT", tc.srv.URL+"/v1/sandboxes/"+bid+"/network", bytes.NewReader(mustMarshal(map[string]any{"mode": "deny_all"})))
	req.Header.Set("Authorization", "Bearer key1")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("X-Room-Receipt") != "signed-receipt" || !bytes.Contains(raw, []byte(`"sandbox_id":"`+bid+`"`)) {
		t.Fatalf("switch: %d %v %s", resp.StatusCode, resp.Header, raw)
	}
}
