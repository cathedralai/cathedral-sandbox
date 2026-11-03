package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func nextKeyBroker(t *testing.T, guests []guestConfig) (*broker, error) {
	t.Helper()
	dir := t.TempDir()
	cfg := config{OperatorKeySHA256: sha("operator-key"), Guests: guests}
	raw, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return loadBroker(path)
}

func keyedRequest(key string) *http.Request {
	r := httptest.NewRequest("GET", "/v1/sandboxes", nil)
	r.Header.Set("Authorization", "Bearer "+key)
	return r
}

// During a rotation both keys reach the same guest, so the client can move
// to the new key without losing sight of its rooms; the old key then goes.
func TestNextKeyReachesTheSameGuestDuringRotation(t *testing.T) {
	b, err := nextKeyBroker(t, []guestConfig{{ID: "g1", KeySHA256: sha("old-key"), NextKeySHA256: sha("new-key")}})
	if err != nil {
		t.Fatal(err)
	}
	old, next := b.guestFromKey(keyedRequest("old-key")), b.guestFromKey(keyedRequest("new-key"))
	if old == nil || next == nil || old != next || old.cfg.ID != "g1" {
		t.Fatalf("old %v next %v: both keys must reach guest g1", old, next)
	}
	if b.guestFromKey(keyedRequest("other-key")) != nil {
		t.Fatal("an unknown key reached a guest")
	}
}

func TestNextKeyConfigRefusesUnsafeValues(t *testing.T) {
	cases := map[string][]guestConfig{
		"not a digest":      {{ID: "g1", KeySHA256: sha("old-key"), NextKeySHA256: "not-hex"}},
		"no current key":    {{ID: "g1", NextKeySHA256: sha("new-key")}},
		"same as current":   {{ID: "g1", KeySHA256: sha("old-key"), NextKeySHA256: sha("old-key")}},
		"operator key":      {{ID: "g1", KeySHA256: sha("old-key"), NextKeySHA256: sha("operator-key")}},
		"another guest key": {{ID: "g1", KeySHA256: sha("old-key"), NextKeySHA256: sha("key-2")}, {ID: "g2", KeySHA256: sha("key-2")}},
		"another next key":  {{ID: "g1", KeySHA256: sha("a"), NextKeySHA256: sha("n")}, {ID: "g2", KeySHA256: sha("b"), NextKeySHA256: sha("n")}},
	}
	for name, guests := range cases {
		if _, err := nextKeyBroker(t, guests); err == nil || !strings.Contains(err.Error(), "config:") {
			t.Errorf("%s: want a config refusal, got %v", name, err)
		}
	}
}
