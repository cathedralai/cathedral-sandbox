package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// AB#596: every sealed hotel takes the SEV-SNP, pinned measurement and AMD
// chain gate that miner hotels take, from the config file or a join. The one
// way past it is "sealed_admission": "off" on an operator hotel's config
// entry. No network: every hotel is a fake in this process.

// ungatedSealed makes h a sealed config hotel past the gate ("sealed_admission":
// "off"). The placement, lend and Escape tests that use it cover what a
// sealed hotel does once it takes rooms, not admission (this file and
// config_attest_test.go).
func ungatedSealed(h *hotel) {
	h.cfgMu.Lock()
	h.cfg.Sealed, h.cfg.SealedAdmission = true, sealedAdmissionOff
	h.cfgMu.Unlock()
}

// addPendingSealed adds a joined (runtime) operator sealed hotel that has not
// passed admission yet, as a broker restart leaves one (loadRuntimeHotels): a
// sealed join with "verify": false is refused since AB#596. att is what its
// GET /room/attestation serves (nil: no answer).
func addPendingSealed(t *testing.T, tc *testChain, id string, slots int, att []byte) *minerHotel {
	t.Helper()
	m, url := newOperatorHotel(t, slots, att)
	tc.hotels[id] = m.fakeHotel
	h := newHotel(hotelConfig{ID: id, Name: id, API: url, Health: url, Concurrency: 4, Sealed: true}, joinKey)
	h.runtime = true
	if err := tc.b.addHotel(h); err != nil {
		t.Fatal(err)
	}
	return m
}

// captureLog sends the standard logger to a buffer for the rest of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// writeConfig marshals c to a fresh config file and returns its path.
func writeConfig(t *testing.T, c config) string {
	t.Helper()
	raw, _ := json.Marshal(c)
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustNotLoad(t *testing.T, c config, want string) {
	t.Helper()
	if _, err := loadBroker(writeConfig(t, c)); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("config loaded or wrong error: %v (want %q)", err, want)
	}
}

func TestSealedConfigHotelIsGatedByDefault(t *testing.T) {
	tc, _ := newConfigHotelChain(t, []configHotel{{id: "s1", att: attestOpts{chip: 46}}}, nil)

	// From broker start to the first check: up, pending, strict, no room.
	a := admissionOf(t, tc, "s1")
	if a["state"] != "pending" || a["attestation_required"] != true || a["amd_chain_required"] != true || a["sealed_admission"] != nil {
		t.Fatalf("sealed config hotel before its check: %v", a)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", sealedOn("s1")); status != 503 || errCode(doc) != "hotels_not_admitted" {
		t.Fatalf("create before admission: %d %v", status, doc)
	}

	syncNow(tc, "s1")
	a = admissionOf(t, tc, "s1")
	if a["state"] != "admitted" || a["measurement"] != strings.Repeat("ab", 48) || a["amd_chain"] == nil || a["chip_id"] == nil {
		t.Fatalf("sealed config hotel after a good attestation: %v", a)
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
}

func TestSealedConfigHotelRefusedForEveryFailedCheck(t *testing.T) {
	cases := []struct {
		name   string
		att    attestOpts
		tweak  func(*config)
		amd    string // verifier verdict; "" passes
		reason string
	}{
		{name: "unpinned measurement", att: attestOpts{chip: 46, measurement: 0x33}, reason: "not in sealed_measurements"},
		{name: "bad AMD chain", att: attestOpts{chip: 46}, amd: `{"verdict": "FAIL", "reason": "VCEK does not chain to the pinned ARK"}`, reason: "AMD chain: VCEK does not chain"},
		{name: "verifier gives no verdict", att: attestOpts{chip: 46}, amd: "Traceback: urlopen error", reason: "no verdict"},
		{name: "debug policy", att: attestOpts{chip: 46, debugPolicy: true}, reason: "guest policy allows debug"},
		{name: "debug kernel", att: attestOpts{chip: 46, debugCmdline: true}, reason: "debug build"},
		{name: "level 1 binding", att: attestOpts{chip: 46, level1: true}, reason: "no SEV-SNP report"},
		{name: "REPORT_DATA", att: attestOpts{chip: 46, badReportData: true}, reason: "REPORT_DATA"},
		{name: "no amd_verifier", att: attestOpts{chip: 46}, tweak: func(c *config) { c.AMDVerifier = nil }, reason: "needs the AMD chain check"},
		{name: "empty sealed_measurements", att: attestOpts{chip: 46}, tweak: func(c *config) { c.SealedMeasurements = nil }, reason: "needs a nonempty sealed_measurements"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc, _ := newConfigHotelChain(t, []configHotel{{id: "s1", att: c.att}}, c.tweak)
			if c.amd != "" {
				setAMDVerdict(t, tc.amdDir, c.amd)
			}
			for i := 0; i < 2; i++ { // the 5 s retry refuses again
				recheckNow(tc, "s1")
				status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/hotels/s1", nil)
				a, _ := doc["admission"].(map[string]any)
				if status != 200 || doc["up"] != true || a["state"] != "refused" || a["attested_at"] != nil || !strings.Contains(fmt.Sprint(a["reason"]), c.reason) {
					t.Fatalf("check %d: want up and refused for %q: %d %v", i, c.reason, status, doc)
				}
				if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", sealedOn("s1")); status != 503 || errCode(doc) != "hotels_not_admitted" {
					t.Fatalf("create on a refused hotel: %d %v", status, doc)
				}
			}
			if n := creates(tc, "s1"); n != 0 {
				t.Fatalf("refused hotel got %d creates", n)
			}
		})
	}
}

// Stale and terminal states match a miner hotel: a later failed check refuses
// at once, a check with no answer keeps the pass until attest_ttl_seconds, a
// down hotel must pass again, and no room is ever deleted by admission.
func TestSealedConfigHotelLosesAdmissionLikeAMinerHotel(t *testing.T) {
	tc, guests := newConfigHotelChain(t, []configHotel{{id: "s1", att: attestOpts{chip: 46}}}, nil)
	syncNow(tc, "s1")
	room := tc.room(t, "key1", sealedOn("s1"))

	// No answer: the pass stands until its TTL runs out.
	guests["s1"].setAttestation(nil)
	recheckNow(tc, "s1")
	if a := admissionOf(t, tc, "s1"); a["state"] != "admitted" || !strings.Contains(fmt.Sprint(a["reason"]), "did not answer") {
		t.Fatalf("no answer within the TTL: %v", a)
	}
	h := tc.b.hotelByID("s1")
	tc.b.mu.Lock()
	h.adm.attestedAt = time.Now().Add(-tc.b.attestTTL() - time.Second)
	tc.b.mu.Unlock()
	if a := admissionOf(t, tc, "s1"); a["state"] == "admitted" {
		t.Fatalf("pass past its TTL still admits: %v", a)
	}

	// A good answer again, then a failed check: refused at once.
	guests["s1"].setAttestation(snpAttestation(t, attestOpts{chip: 46}))
	admitNow(t, tc, "s1")
	guests["s1"].setAttestation(snpAttestation(t, attestOpts{chip: 46, measurement: 0x33}))
	recheckNow(tc, "s1")
	if a := admissionOf(t, tc, "s1"); a["state"] != "refused" || a["attested_at"] != nil {
		t.Fatalf("failed recheck: %v", a)
	}
	if status, doc := tc.call(t, "key1", "GET", "/v1/sandboxes/"+room, nil); status != 200 || doc["state"] != "running" {
		t.Fatalf("existing room on the refused hotel: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", sealedOn("s1")); status != 503 || errCode(doc) != "hotels_not_admitted" {
		t.Fatalf("new create on the refused hotel: %d %v", status, doc)
	}

	// Down clears the pass: back up, it is pending until it passes again.
	guests["s1"].setAttestation(snpAttestation(t, attestOpts{chip: 46}))
	admitNow(t, tc, "s1")
	guests["s1"].setHealthFail(true)
	tc.b.mu.Lock()
	h.lastOK = time.Now().Add(-time.Minute)
	tc.b.mu.Unlock()
	h.lastAnswer.Store(0)
	syncNow(tc, "s1")
	guests["s1"].setHealthFail(false)
	tc.b.mu.Lock()
	h.ok = true // health is back; the attestation step has not run yet
	state := tc.b.admissionState(h, time.Now())
	tc.b.mu.Unlock()
	if state != "pending" {
		t.Fatalf("hotel back after down: %s, want pending", state)
	}
	syncNow(tc, "s1")
	if a := admissionOf(t, tc, "s1"); a["state"] != "admitted" {
		t.Fatalf("hotel back after down, checked: %v", a)
	}
	f := tc.hotels["s1"]
	f.mu.Lock()
	deletes := len(f.roomDeletes) + len(f.bulkDeletes)
	f.mu.Unlock()
	if deletes != 0 {
		t.Fatalf("admission deleted %d rooms", deletes)
	}
}

func TestSealedAdmissionOffIsHonouredForAnOperatorConfigHotel(t *testing.T) {
	logs := captureLog(t)
	tc, _ := newConfigHotelChain(t, []configHotel{{id: "s1", att: attestOpts{chip: 46, measurement: 0x33}}, {id: "s2", att: attestOpts{chip: 46}}},
		func(c *config) {
			c.Hotels[0].SealedAdmission = sealedAdmissionOff
			c.Hotels[1].SealedAdmission = sealedAdmissionGate
		})
	if !strings.Contains(logs.String(), "hotel s1: sealed_admission off: the SEV-SNP admission gate is OFF") {
		t.Fatalf("no log line for the escape: %q", logs.String())
	}
	syncNow(tc, "s1")
	syncNow(tc, "s2")
	a := admissionOf(t, tc, "s1")
	if a["state"] != "admitted" || a["attestation_required"] != false || a["amd_chain_required"] != false || a["sealed_admission"] != "off" {
		t.Fatalf("hotel with sealed_admission off: %v", a)
	}
	if attestationAsked(tc, "s1") {
		t.Fatal("the broker asked an ungated hotel for its attestation")
	}
	if id := tc.room(t, "key1", sealedOn("s1")); !strings.HasPrefix(id, "s1.") {
		t.Fatalf("room on %s", id)
	}
	// "gate" is the default spelled out: s2 is gated.
	if a := admissionOf(t, tc, "s2"); a["state"] != "admitted" || a["attestation_required"] != true || a["sealed_admission"] != nil {
		t.Fatalf("hotel with sealed_admission gate: %v", a)
	}
	if n := len(amdCalls(tc.amdDir)); n != 1 {
		t.Fatalf("AMD chain ran %d times, want once (s2 only)", n)
	}
	_, cat := tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	pol, _ := cat["admission_policy"].(map[string]any)
	if pol["sealed_admission"] != "on" || fmt.Sprint(pol["sealed_admission_off"]) != "[s1]" {
		t.Fatalf("admission policy: %v", pol)
	}
}

func TestSealedAdmissionOffIsRefusedForMinersJoinsAndContradictions(t *testing.T) {
	base := func(hc hotelConfig) config {
		key := filepath.Join(t.TempDir(), "hotel.key")
		_ = os.WriteFile(key, []byte("hotel-key"), 0o600)
		hc.API, hc.Health, hc.KeyFile = "http://127.0.0.1:1", "http://127.0.0.1:1", key
		return config{SealedMeasurements: []string{strings.Repeat("ab", 48)}, Hotels: []hotelConfig{hc}}
	}
	mustNotLoad(t, base(hotelConfig{ID: "m", Sealed: true, MinerHotkey: minerHotkey, SealedAdmission: "off"}), `sealed_admission "off" is refused for a miner hotel`)
	mustNotLoad(t, base(hotelConfig{ID: "u", SealedAdmission: "off"}), `sealed_admission "off" needs "sealed": true`)
	mustNotLoad(t, base(hotelConfig{ID: "r", Sealed: true, RequireAttestation: true, SealedAdmission: "off"}), "contradict")
	mustNotLoad(t, base(hotelConfig{ID: "t", Sealed: true, SealedAdmission: "of"}), `use "gate" (the default) or "off"`)
	top := base(hotelConfig{ID: "s", Sealed: true})
	top.SealedAdmission = "off"
	mustNotLoad(t, top, `top-level "sealed_admission": "off" is refused`)
	top.SealedAdmission = "on"
	if _, err := loadBroker(writeConfig(t, top)); err != nil {
		t.Fatalf(`top-level "on": %v`, err)
	}

	// A join cannot set "off", for an operator hotel or a miner hotel.
	tc := newChainState(t, t.TempDir())
	_, url := newOperatorHotel(t, 5, snpAttestation(t, attestOpts{chip: 46}))
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "op", "api": url, "key": joinKey, "sealed": true, "sealed_admission": "off"})
	if status != 400 || errCode(doc) != "invalid_hotel" || !strings.Contains(fmt.Sprint(doc), "joined hotel is always gated") || tc.b.hotelByID("op") != nil {
		t.Fatalf("operator join with sealed_admission off: %d %v", status, doc)
	}
	_, murl := newMinerHotel(t, 5, snpAttestation(t, attestOpts{chip: 47}))
	status, doc = tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "mi", "api": murl, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey, "sealed_admission": "off"})
	if status != 400 || errCode(doc) != "invalid_hotel" || tc.b.hotelByID("mi") != nil {
		t.Fatalf("miner join with sealed_admission off: %d %v", status, doc)
	}
	status, doc = tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "op", "api": url, "key": joinKey, "sealed": true, "sealed_admission": "Off"})
	if status != 400 || errCode(doc) != "invalid_hotel" {
		t.Fatalf("join with an unknown sealed_admission: %d %v", status, doc)
	}
	// "gate" joins, and the state file does not keep the field.
	status, doc = tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "op", "api": url, "key": joinKey, "sealed": true, "sealed_admission": "gate"})
	if a, _ := doc["admission"].(map[string]any); status != 201 || a["attested_at"] == nil || a["attestation_required"] != true {
		t.Fatalf("join with sealed_admission gate: %d %v", status, doc)
	}
	statePath := filepath.Join(tc.b.cfg.StateDir, runtimeHotelsFile)
	raw, err := os.ReadFile(statePath)
	if err != nil || bytes.Contains(raw, []byte("sealed_admission")) {
		t.Fatalf("hotels.json: %v %s", err, raw)
	}

	// A state file edited by hand to "off" does not ungate a joined hotel.
	var list []hotelConfig
	if err := json.Unmarshal(raw, &list); err != nil || len(list) != 1 {
		t.Fatalf("hotels.json: %v %s", err, raw)
	}
	list[0].SealedAdmission = sealedAdmissionOff
	raw, _ = json.Marshal(list)
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.start(t)
	h := tc.b.hotelByID("op")
	tc.b.mu.Lock()
	need, adm := tc.b.needsAttestation(h), tc.b.admitted(h, time.Now())
	tc.b.mu.Unlock()
	if !h.runtime || !need || adm {
		t.Fatalf("joined hotel with a hand-edited off: runtime=%t gated=%t admitted=%t", h.runtime, need, adm)
	}
}

func TestSealedJoinWithVerifyFalseIsRefused(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	_, url := newOperatorHotel(t, 5, snpAttestation(t, attestOpts{chip: 46}))
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "p", "api": url, "key": joinKey, "sealed": true, "verify": false})
	if status != 400 || errCode(doc) != "verify_required" || tc.b.hotelByID("p") != nil {
		t.Fatalf("sealed join with verify false: %d %v", status, doc)
	}
	if _, err := os.Stat(filepath.Join(tc.b.cfg.StateDir, "hotel-keys", "p.key")); !os.IsNotExist(err) {
		t.Fatalf("refused join kept its key: %v", err)
	}
	// A miner keeps its own refusal.
	_, murl := newMinerHotel(t, 5, snpAttestation(t, attestOpts{chip: 47}))
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "m", "api": murl, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey, "verify": false}); status != 409 || errCode(doc) != "guest_tls_required" {
		t.Fatalf("miner join with verify false: %d %v", status, doc)
	}
	// The same hotel with verify joins admitted.
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "p", "api": url, "key": joinKey, "sealed": true}); status != 201 {
		t.Fatalf("sealed join with verify: %d %v", status, doc)
	}
}

// A joined operator sealed hotel takes the miner check: the pin and the AMD
// chain are required (before AB#596 both were optional for it).
func TestJoinedOperatorSealedHotelNeedsThePinAndTheChain(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	tc.b.cfg.AMDVerifier = nil
	_, url := newOperatorHotel(t, 5, snpAttestation(t, attestOpts{chip: 46}))
	join := map[string]any{"id": "op", "api": url, "key": joinKey, "sealed": true}
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", join); status != 422 || !strings.Contains(fmt.Sprint(doc), "a sealed hotel needs the AMD chain check") {
		t.Fatalf("operator sealed join without a verifier: %d %v", status, doc)
	}
	tc = newChainState(t, t.TempDir())
	tc.b.cfg.SealedMeasurements = nil
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", join); status != 422 || !strings.Contains(fmt.Sprint(doc), "nonempty sealed_measurements") {
		t.Fatalf("operator sealed join without a pin list: %d %v", status, doc)
	}
	tc = newChainState(t, t.TempDir())
	_, url = newOperatorHotel(t, 5, snpAttestation(t, attestOpts{chip: 46, measurement: 0x33}))
	join["api"] = url
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", join); status != 422 || !strings.Contains(fmt.Sprint(doc), "not in sealed_measurements") {
		t.Fatalf("operator sealed join with an unpinned measurement: %d %v", status, doc)
	}
}

func TestUnsealedHotelsAreUnchanged(t *testing.T) {
	// No pin list and no verifier: an unsealed hotel needs neither.
	tc := newChainState(t, t.TempDir())
	tc.b.cfg.SealedMeasurements, tc.b.cfg.AMDVerifier = nil, nil
	m, url := newOperatorHotel(t, 5, nil)
	tc.hotels["u"] = m.fakeHotel
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "u", "api": url, "key": joinKey}); status != 201 {
		t.Fatalf("unsealed join: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "u2", "api": url, "key": joinKey, "verify": false}); status != 201 {
		t.Fatalf("unsealed join with verify false: %d %v", status, doc)
	}
	syncNow(tc, "u")
	for _, id := range []string{"b", "u"} { // a config hotel and a joined hotel
		a := admissionOf(t, tc, id)
		if a["state"] != "admitted" || a["attestation_required"] != false || a["amd_chain_required"] != false || a["reason"] != nil {
			t.Fatalf("unsealed hotel %s: %v", id, a)
		}
		if attestationAsked(tc, id) {
			t.Fatalf("unsealed hotel %s was asked for its attestation", id)
		}
		if got := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{id}}); !strings.HasPrefix(got, id+".") {
			t.Fatalf("room for %s on %s", id, got)
		}
	}
}

func TestRequireAttestationIsRedundantAndLoggedOnce(t *testing.T) {
	logs := captureLog(t)
	tc, _ := newConfigHotelChain(t, []configHotel{{id: "s1", att: attestOpts{chip: 46}, optIn: true}, {id: "s2", att: attestOpts{chip: 46}, optIn: true}, {id: "s3", att: attestOpts{chip: 46}}}, nil)
	for _, id := range []string{"s1", "s2", "s3"} {
		recheckNow(tc, id)
		if a := admissionOf(t, tc, id); a["state"] != "admitted" || a["attestation_required"] != true || a["amd_chain_required"] != true {
			t.Fatalf("hotel %s: %v", id, a)
		}
	}
	tc.b.cfg.StateDir = t.TempDir()
	_, url := newOperatorHotel(t, 5, snpAttestation(t, attestOpts{chip: 46}))
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "j1", "api": url, "key": joinKey, "sealed": true, "require_attestation": true}); status != 201 {
		t.Fatalf("join with require_attestation: %d %v", status, doc)
	}
	out := logs.String()
	if n := strings.Count(out, "require_attestation is deprecated"); n != 1 || !strings.Contains(out, "remove it from hotel s1, s2") {
		t.Fatalf("deprecation lines: %d in %q", n, out)
	}
}
