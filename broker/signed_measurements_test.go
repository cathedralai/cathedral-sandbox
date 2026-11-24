package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedMeasurementsLoadAndAllow(t *testing.T) {
	raw := []byte(`{
  "schema": "cathedral_sealed_hotels_v1",
  "hotels": {
    "owner-hotel": {
      "chip_id": "` + strings.Repeat("aa", 64) + `",
      "measurements": ["` + strings.Repeat("11", 48) + `", "` + strings.Repeat("22", 48) + `"]
    }
  }
}`)
	c := &signedMeasurementsCache{}
	if err := c.load(raw, "test"); err != nil {
		t.Fatal(err)
	}
	ok, _ := c.allow("owner-hotel", strings.Repeat("11", 48))
	if !ok {
		t.Fatal("expected hotel measurement allowed")
	}
	ok, why := c.allow("owner-hotel", strings.Repeat("33", 48))
	if ok || !strings.Contains(why, "not in signed list") {
		t.Fatalf("want refusal, got ok=%v why=%q", ok, why)
	}
	// Unknown hotel id: any listed measurement still matches.
	ok, _ = c.allow("other", strings.Repeat("22", 48))
	if !ok {
		t.Fatal("expected global measurement allow for unknown hotel id")
	}
	hotels := c.hotelsForChip(strings.Repeat("aa", 64))
	if len(hotels) != 1 || hotels[0] != "owner-hotel" {
		t.Fatalf("chip index: %v", hotels)
	}
}

func TestMeasurementAllowedSignedRequiredFallback(t *testing.T) {
	signedMeas = &signedMeasurementsCache{}
	local := []string{strings.Repeat("ab", 48)}
	ok, src := measurementAllowed("h1", strings.Repeat("ab", 48), local, true)
	if !ok || src != "local_fallback" {
		t.Fatalf("empty signed cache should fall back to local pin: ok=%v src=%s", ok, src)
	}
	ok, _ = measurementAllowed("h1", strings.Repeat("cd", 48), local, true)
	if ok {
		t.Fatal("unmatched local pin must refuse when signed list empty")
	}
	ok, src = measurementAllowed("h1", strings.Repeat("cd", 48), local, false)
	if ok || src != "measurement not in sealed_measurements" {
		t.Fatalf("signed off should use local only: ok=%v src=%s", ok, src)
	}
}

func TestFetchSignedMeasurementsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "release.json")
	body := `{"schema":"cathedral_sealed_hotels_v1","hotels":{"h":{"measurements":["` + strings.Repeat("ab", 48) + `"]}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := fetchSignedMeasurements(path)
	if err != nil {
		t.Fatal(err)
	}
	c := &signedMeasurementsCache{}
	if err := c.load(raw, path); err != nil {
		t.Fatal(err)
	}
	ok, _ := c.allow("h", strings.Repeat("ab", 48))
	if !ok {
		t.Fatal("file-backed list should allow")
	}
}

func signSealedHotelsDoc(t *testing.T, priv ed25519.PrivateKey, unsigned map[string]any) []byte {
	t.Helper()
	msg, err := marshalCanonical(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, msg)
	doc := map[string]any{}
	for k, v := range unsigned {
		doc[k] = v
	}
	doc["signature"] = map[string]any{
		"algorithm":    "ed25519",
		"value_base64": base64.StdEncoding.EncodeToString(sig),
	}
	raw, err := marshalCanonical(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifySignedMeasurementsEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID := "test-key-1"
	pins := map[string]signedMeasurementPin{
		keyID: {
			PublicKeyHex: hex.EncodeToString(pub),
			NotBefore:    "2020-01-01T00:00:00Z",
			NotAfter:     "2099-01-01T00:00:00Z",
		},
	}
	unsigned := map[string]any{
		"schema":       signedMeasurementsSchema,
		"release":      json.Number("1"),
		"generated_at": "2026-11-24T12:00:00Z",
		"valid_from":   "2026-11-24T00:00:00Z",
		"valid_until":  "2026-11-25T00:00:00Z",
		"key_id":       keyID,
		"hotels": map[string]any{
			"h1": map[string]any{
				"chip_id":      strings.Repeat("ab", 64),
				"measurements": []any{strings.Repeat("11", 48)},
			},
		},
	}
	raw := signSealedHotelsDoc(t, priv, unsigned)
	now, _ := time.Parse(time.RFC3339, "2026-11-24T12:00:00Z")
	if err := verifySignedMeasurements(raw, pins, now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	c := &signedMeasurementsCache{}
	if err := c.load(raw, "test"); err != nil {
		t.Fatal(err)
	}
	ok, _ := c.allow("h1", strings.Repeat("11", 48))
	if !ok {
		t.Fatal("verified list should allow")
	}

	// Tamper: change a measurement after signing.
	var tampered map[string]any
	if err := json.Unmarshal(raw, &tampered); err != nil {
		t.Fatal(err)
	}
	hotels := tampered["hotels"].(map[string]any)
	h1 := hotels["h1"].(map[string]any)
	h1["measurements"] = []any{strings.Repeat("22", 48)}
	bad, err := marshalCanonical(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySignedMeasurements(bad, pins, now); err == nil {
		t.Fatal("tampered document must fail verify")
	}

	// Wrong key pin.
	wrongPins := map[string]signedMeasurementPin{
		keyID: {
			PublicKeyHex: strings.Repeat("00", 32),
			NotBefore:    "2020-01-01T00:00:00Z",
			NotAfter:     "2099-01-01T00:00:00Z",
		},
	}
	if err := verifySignedMeasurements(raw, wrongPins, now); err == nil {
		t.Fatal("wrong pin must fail verify")
	}
}

func TestPreferChipSoftPrefer(t *testing.T) {
	match := &hotel{adm: admission{chipFull: strings.Repeat("aa", 64)}}
	other := &hotel{adm: admission{chipFull: strings.Repeat("bb", 64)}}
	hotels := []*hotel{match, other}
	weight := []float64{2, 3}
	total := preferChip(hotels, weight, 5, strings.Repeat("aa", 64))
	if total != 2 || weight[0] != 2 || weight[1] != 0 {
		t.Fatalf("soft prefer: total=%v weight=%v", total, weight)
	}
	// No match: leave weights alone.
	weight = []float64{2, 3}
	total = preferChip(hotels, weight, 5, strings.Repeat("cc", 64))
	if total != 5 || weight[1] != 3 {
		t.Fatalf("no match should keep weights: total=%v weight=%v", total, weight)
	}
}
