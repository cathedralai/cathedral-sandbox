package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
