package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Config file hotels that opt in to the attestation gate with
// "require_attestation": true (AB#207). No network: every hotel is a fake
// sealed guest in this process.

// configHotel is one sealed hotel of the broker config file.
type configHotel struct {
	id      string
	att     attestOpts // what its GET /room/attestation serves
	optIn   bool       // "require_attestation": true
	reserve string     // reserved_for
}

// newConfigHotelChain is newChainState with only the given sealed config
// hotels, guests g1 (key1) and const (key-const). tweak, if set, changes the
// config before the broker loads it.
func newConfigHotelChain(t *testing.T, hotels []configHotel, tweak func(*config)) (*testChain, map[string]*minerHotel) {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "hotel.key")
	if err := os.WriteFile(key, []byte("hotel-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	tc := &testChain{hotels: map[string]*fakeHotel{}, amdDir: fakeAMDVerifier(t)}
	cfg := config{OperatorKeySHA256: sha("operator-key"), InsecureCookie: true,
		SealedMeasurements: []string{strings.Repeat("ab", 48), strings.Repeat("22", 48)},
		Guests:             []guestConfig{{ID: "g1", KeySHA256: sha("key1")}, {ID: "const", KeySHA256: sha("key-const")}},
		AMDVerifier:        &amdVerifierConfig{Command: []string{"/bin/sh", filepath.Join(tc.amdDir, "verify.sh")}, ARKSHA256: arkPins{testARKPin}}}
	guests := map[string]*minerHotel{}
	for _, ch := range hotels {
		m, url := newOperatorHotel(t, 5, snpAttestation(t, ch.att))
		tc.hotels[ch.id], guests[ch.id] = m.fakeHotel, m
		cfg.Hotels = append(cfg.Hotels, hotelConfig{ID: ch.id, Name: ch.id, API: url, Health: url, KeyFile: key, Concurrency: 4,
			Sealed: true, RequireAttestation: ch.optIn, ReservedFor: ch.reserve})
	}
	if tweak != nil {
		tweak(&cfg)
	}
	raw, _ := json.Marshal(cfg)
	tc.cfgPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.start(t)
	return tc, guests
}

func sealedOn(id string) map[string]any {
	return map[string]any{"image": "alpine:3.20", "hotels": []string{id}, "sealed": true}
}

// attestationAsked reports whether the broker asked hotel id for its attestation.
func attestationAsked(tc *testChain, id string) bool {
	f := tc.hotels[id]
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.calls, "GET /room/attestation")
}

// recheckNow makes the attestation of id due and runs one sync step.
func recheckNow(tc *testChain, id string) {
	tc.b.mu.Lock()
	tc.b.hotelByID(id).adm.checkedAt = time.Time{}
	tc.b.mu.Unlock()
	syncNow(tc, id)
}

func TestConfigHotelOptInTakesRoomsOnlyAfterAttestation(t *testing.T) {
	tc, _ := newConfigHotelChain(t, []configHotel{{id: "s1", att: attestOpts{chip: 46}, optIn: true}}, nil)

	// Before the first check: pending, strict, no room and no free rooms.
	a := admissionOf(t, tc, "s1")
	if a["state"] != "pending" || a["attestation_required"] != true || a["amd_chain_required"] != true {
		t.Fatalf("opted-in hotel before its check: %v", a)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", sealedOn("s1")); status != 503 || errCode(doc) != "hotels_not_admitted" {
		t.Fatalf("create before admission: %d %v", status, doc)
	}
	_, cat := tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	e, _ := catalogEntry(cat, "s1")
	ca, _ := e["admission"].(map[string]any)
	if e["free_rooms"] != float64(0) || e["source"] != "broker" || ca["attestation_required"] != true || ca["amd_chain_required"] != true {
		t.Fatalf("catalog before admission: %v", e)
	}

	// One sync step: health, then the attestation with the AMD chain.
	syncNow(tc, "s1")
	a = admissionOf(t, tc, "s1")
	if a["state"] != "admitted" || a["measurement"] != strings.Repeat("ab", 48) || a["amd_chain"] == nil {
		t.Fatalf("opted-in hotel after a good attestation: %v", a)
	}
	if calls := amdCalls(tc.amdDir); len(calls) != 1 || !strings.Contains(calls[0], "--require-sealed") {
		t.Fatalf("AMD chain verifier runs: %v", calls)
	}
	if id := tc.room(t, "key1", sealedOn("s1")); !strings.HasPrefix(id, "s1.") {
		t.Fatalf("room on %s", id)
	}
	if n := creates(tc, "s1"); n != 1 {
		t.Fatalf("hotel s1 got %d creates, want 1 (none before admission)", n)
	}
	_, cat = tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	e, _ = catalogEntry(cat, "s1")
	ca, _ = e["admission"].(map[string]any)
	if ca["state"] != "admitted" || ca["attestation_required"] != true || ca["amd_chain_required"] != true {
		t.Fatalf("catalog after admission: %v", e)
	}
}

func TestConfigHotelOptInWithAnUnlistedMeasurementGetsNoRooms(t *testing.T) {
	tc, _ := newConfigHotelChain(t, []configHotel{{id: "s1", att: attestOpts{chip: 46, measurement: 0x33}, optIn: true}}, nil)
	for i := 0; i < 2; i++ {
		recheckNow(tc, "s1")
		a := admissionOf(t, tc, "s1")
		if a["state"] != "refused" || !strings.Contains(a["reason"].(string), "not in sealed_measurements") || a["attested_at"] != nil {
			t.Fatalf("unlisted measurement, check %d: %v", i, a)
		}
		if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", sealedOn("s1")); status != 503 || errCode(doc) != "hotels_not_admitted" {
			t.Fatalf("create on a refused hotel: %d %v", status, doc)
		}
	}
	if n := creates(tc, "s1"); n != 0 {
		t.Fatalf("refused hotel got %d creates", n)
	}
}

// Live, c46-sealed and c46-sealed-2 are two guests on one machine (one
// CHIP_ID), and so are nc-sealed (const), nc-sealed-2 and nc-sealed-3. Opting
// in one hotel must not refuse it, or any neighbour, for its chip.
func TestConfigHotelOptInSharesAChipWithUngatedConfigHotels(t *testing.T) {
	tc, guests := newConfigHotelChain(t, []configHotel{
		{id: "c46-sealed", att: attestOpts{chip: 46}},
		{id: "c46-sealed-2", att: attestOpts{chip: 46}, optIn: true},
		{id: "nc-sealed", att: attestOpts{chip: 47}, reserve: "const"},
		{id: "nc-sealed-2", att: attestOpts{chip: 47}},
	}, nil)
	ungated := []string{"c46-sealed", "nc-sealed", "nc-sealed-2"}
	for round := 0; round < 2; round++ {
		for _, id := range append(ungated, "c46-sealed-2") {
			recheckNow(tc, id)
		}
	}
	if a := admissionOf(t, tc, "c46-sealed-2"); a["state"] != "admitted" || a["reason"] != nil || a["chip_id"] == nil {
		t.Fatalf("opted-in hotel next to an ungated hotel on its chip: %v", a)
	}
	for _, id := range ungated {
		a := admissionOf(t, tc, id)
		if a["state"] != "admitted" || a["attestation_required"] != false || a["amd_chain_required"] != false || a["attested_at"] != nil || a["reason"] != nil {
			t.Fatalf("ungated config hotel %s: %v", id, a)
		}
		if attestationAsked(tc, id) {
			t.Fatalf("ungated config hotel %s was asked for an attestation", id)
		}
	}
	if !attestationAsked(tc, "c46-sealed-2") {
		t.Fatal("opted-in hotel was never asked for its attestation")
	}
	if n := len(amdCalls(tc.amdDir)); n != 1 {
		t.Fatalf("AMD chain ran %d times, want once (only the opted-in hotel, once per binding)", n)
	}
	for _, id := range []string{"c46-sealed", "c46-sealed-2", "nc-sealed-2"} {
		if got := tc.room(t, "key1", sealedOn(id)); !strings.HasPrefix(got, id+".") {
			t.Fatalf("room for %s on %s", id, got)
		}
	}
	if got := tc.room(t, "key-const", sealedOn("nc-sealed")); !strings.HasPrefix(got, "nc-sealed.") {
		t.Fatalf("const room on %s", got)
	}

	// The opted-in hotel loses its pass; its chip neighbour keeps taking rooms.
	guests["c46-sealed-2"].setAttestation(snpAttestation(t, attestOpts{chip: 46, measurement: 0x33}))
	recheckNow(tc, "c46-sealed-2")
	if a := admissionOf(t, tc, "c46-sealed-2"); a["state"] != "refused" {
		t.Fatalf("opted-in hotel after a bad attestation: %v", a)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", sealedOn("c46-sealed-2")); status != 503 || errCode(doc) != "hotels_not_admitted" {
		t.Fatalf("create on the refused hotel: %d %v", status, doc)
	}
	if got := tc.room(t, "key1", sealedOn("c46-sealed")); !strings.HasPrefix(got, "c46-sealed.") {
		t.Fatalf("room on the chip neighbour went to %s", got)
	}
}

// A refused or expired pass stops new rooms only: rooms already on the hotel
// keep working and the broker deletes none of them.
func TestConfigHotelOptInRefusalKeepsExistingRooms(t *testing.T) {
	tc, guests := newConfigHotelChain(t, []configHotel{{id: "s1", att: attestOpts{chip: 46}, optIn: true}}, nil)
	syncNow(tc, "s1")
	room := tc.room(t, "key1", sealedOn("s1"))
	guests["s1"].setAttestation(snpAttestation(t, attestOpts{chip: 46, debugPolicy: true}))
	recheckNow(tc, "s1")
	if a := admissionOf(t, tc, "s1"); a["state"] != "refused" || !strings.Contains(a["reason"].(string), "debug") {
		t.Fatalf("debug attestation: %v", a)
	}
	if status, doc := tc.call(t, "key1", "GET", "/v1/sandboxes/"+room, nil); status != 200 || doc["state"] != "running" {
		t.Fatalf("existing room on the refused hotel: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", sealedOn("s1")); status != 503 || errCode(doc) != "hotels_not_admitted" {
		t.Fatalf("new create on the refused hotel: %d %v", status, doc)
	}
	f := tc.hotels["s1"]
	f.mu.Lock()
	deletes := len(f.roomDeletes) + len(f.bulkDeletes)
	f.mu.Unlock()
	if deletes != 0 {
		t.Fatalf("the broker deleted rooms on a refused hotel: %d", deletes)
	}
	// A good attestation admits it again.
	guests["s1"].setAttestation(snpAttestation(t, attestOpts{chip: 46}))
	recheckNow(tc, "s1")
	if got := tc.room(t, "key1", sealedOn("s1")); !strings.HasPrefix(got, "s1.") {
		t.Fatalf("room after re-admission on %s", got)
	}
}

func TestConfigHotelOptInFailsClosed(t *testing.T) {
	refused := func(t *testing.T, tc *testChain, reason string) {
		t.Helper()
		recheckNow(tc, "s1")
		a := admissionOf(t, tc, "s1")
		if a["state"] == "admitted" || a["attestation_required"] != true || a["amd_chain_required"] != true || !strings.Contains(a["reason"].(string), reason) {
			t.Fatalf("want refused for %q: %v", reason, a)
		}
		if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", sealedOn("s1")); status != 503 || errCode(doc) != "hotels_not_admitted" {
			t.Fatalf("create: %d %v", status, doc)
		}
	}
	optIn := []configHotel{{id: "s1", att: attestOpts{chip: 46}, optIn: true}}

	t.Run("no amd_verifier", func(t *testing.T) {
		tc, _ := newConfigHotelChain(t, optIn, func(c *config) { c.AMDVerifier = nil })
		refused(t, tc, "needs the AMD chain check")
	})
	t.Run("empty sealed_measurements", func(t *testing.T) {
		tc, _ := newConfigHotelChain(t, optIn, func(c *config) { c.SealedMeasurements = nil })
		refused(t, tc, "needs a nonempty sealed_measurements")
	})
	t.Run("AMD chain fails", func(t *testing.T) {
		tc, _ := newConfigHotelChain(t, optIn, nil)
		setAMDVerdict(t, tc.amdDir, `{"verdict": "FAIL", "reason": "report signature does not verify with the VCEK"}`)
		refused(t, tc, "AMD chain: report signature")
	})
	t.Run("sealed_admission off keeps the gate", func(t *testing.T) {
		tc, _ := newConfigHotelChain(t, optIn, func(c *config) { c.SealedAdmission = "off" })
		if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", sealedOn("s1")); status != 503 || errCode(doc) != "hotels_not_admitted" {
			t.Fatalf("create before admission with sealed_admission off: %d %v", status, doc)
		}
		admitNow(t, tc, "s1")
	})
	t.Run("unsealed config hotel", func(t *testing.T) {
		tc, _ := newConfigHotelChain(t, optIn, nil)
		var c config
		raw, _ := os.ReadFile(tc.cfgPath)
		_ = json.Unmarshal(raw, &c)
		c.Hotels[0].Sealed = false
		raw, _ = json.Marshal(c)
		if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBroker(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "require_attestation needs") {
			t.Fatalf("unsealed require_attestation hotel loaded: %v", err)
		}
	})
	t.Run("unsealed join", func(t *testing.T) {
		tc := newChainState(t, t.TempDir())
		_, url := newOperatorHotel(t, 5, snpAttestation(t, attestOpts{chip: 46}))
		status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "u", "api": url, "key": joinKey, "require_attestation": true})
		if status != 400 || errCode(doc) != "invalid_hotel" || tc.b.hotelByID("u") != nil {
			t.Fatalf("unsealed join with require_attestation: %d %v", status, doc)
		}
	})
}
