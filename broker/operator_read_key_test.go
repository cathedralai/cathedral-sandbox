package main

import (
	"encoding/json"
	"os"
	"testing"
)

// The read key is for the admin fleet feed. It must see what the operator
// sees on GET /v1/broker/capacity and nothing else.
func TestOperatorReadKeySeesOperatorCapacity(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 1, nil)
	status, doc := tc.call(t, "reader-key", "GET", "/v1/broker/capacity", nil)
	if status != 200 || !listed(doc, "a") || !listed(doc, "b") || !listed(doc, "m1") || doc["admission_policy"] == nil {
		t.Fatalf("read key capacity: %d %v", status, doc)
	}
	_, operator := tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	if len(doc["hotels"].([]any)) != len(operator["hotels"].([]any)) {
		t.Fatalf("read key view differs from operator view: %v vs %v", doc, operator)
	}
}

func TestOperatorReadKeyCannotWrite(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 1, nil)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/v1/broker/hotels", nil},
		{"GET", "/v1/broker/hotels/a", nil},
		{"POST", "/v1/broker/hotels", map[string]any{"id": "x", "api": "https://example.invalid"}},
		{"PATCH", "/v1/broker/hotels/a", map[string]any{"drain": true}},
		{"DELETE", "/v1/broker/hotels/m1", nil},
		{"GET", "/v1/broker/guests", nil},
		{"POST", "/v1/broker/guests", map[string]any{"id": "g9"}},
		{"POST", "/v1/broker/capacity", nil},
		{"GET", "/v1/sandboxes", nil},
		{"POST", "/v1/sandboxes", map[string]any{"template": "base"}},
	} {
		status, body := tc.call(t, "reader-key", c.method, c.path, c.body)
		if status < 400 {
			t.Fatalf("read key %s %s: %d %v", c.method, c.path, status, body)
		}
	}
	// Nothing changed: hotel a is not draining and m1 is still joined.
	_, doc := tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	a, ok := catalogEntry(doc, "a")
	if !ok || a["drain"] == true || !listed(doc, "m1") || listed(doc, "x") {
		t.Fatalf("read key changed the fleet: %v", doc)
	}
}

func TestOperatorReadKeyConfigRejectsReuse(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var original config
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	for name, digest := range map[string]string{
		"operator":  original.OperatorKeySHA256,
		"enroller":  original.MinerEnrollKeySHA256,
		"guest":     original.Guests[0].KeySHA256,
		"view":      original.Guests[0].ViewTokenSHA256,
		"malformed": "not-a-digest",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := original
			cfg.OperatorReadKeySHA256 = digest
			body, _ := json.Marshal(cfg)
			path := t.TempDir() + "/config.json"
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadBroker(path); err == nil {
				t.Fatal("reused or malformed operator read key was accepted")
			}
		})
	}
}
