package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// stopLoops stops the sync loops the join handler started, so only the
// test's synthetic samples move probation (and a broker the test restarts
// does not keep writing the probation file).
func stopLoops(tc *testChain) {
	for _, h := range tc.b.hotelList() {
		if h.stop != nil {
			h.stop()
		}
	}
	time.Sleep(50 * time.Millisecond) // a tick in flight finishes
}

// setProbationConfig writes the probation fields into the test config file
// and restarts the broker on it.
func setProbationConfig(t *testing.T, tc *testChain, seconds, minPct float64) {
	t.Helper()
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.MinerProbationSeconds, c.MinerProbationMinUptimePct = seconds, minPct
	raw, _ = json.Marshal(c)
	if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	stopLoops(tc)
	tc.start(t)
}

// probationTC is a broker with miner probation on (window 100 s, 99%) and
// an existing probation file, so a joined miner starts on probation.
func probationTC(t *testing.T) *testChain {
	t.Helper()
	dir := t.TempDir()
	tc := newChainState(t, dir)
	setProbationConfig(t, tc, 100, 0)
	return tc
}

// testTrafficPolicy is the test-traffic guest: miner opt-in plus miner_probation.
var testTrafficPolicy = map[string]any{
	"prefer":          []any{map[string]any{"label": map[string]string{"miner": "true"}}},
	"allow":           []any{map[string]any{"class": "sealed"}, map[string]any{"class": "unsealed"}},
	"miner_probation": true,
}

// steps feeds samples (offset from t0, up) to h's probation and returns
// whether the last one changed the state.
func steps(tc *testChain, h *hotel, t0 time.Time, samples ...struct {
	at time.Duration
	up bool
}) bool {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	changed := false
	for _, s := range samples {
		changed = h.probationStep(t0.Add(s.at), s.up, tc.b.probationWindow(), tc.b.probationMinBP())
	}
	return changed
}

type sample = struct {
	at time.Duration
	up bool
}

func probationOf(t *testing.T, tc *testChain, id string) map[string]any {
	t.Helper()
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/hotels/"+id, nil)
	if status != 200 {
		t.Fatalf("hotel %s: %d %v", id, status, doc)
	}
	p, _ := doc["probation"].(map[string]any)
	return p
}

func TestProbationGraduatesAtExactlyTheMinimumUptime(t *testing.T) {
	tc := probationTC(t)
	joinMiner(t, tc, "m1", true, 5, nil)
	stopLoops(tc)
	h := tc.b.hotelByID("m1")
	if tc.b.probationWindow() != 100*time.Second || tc.b.probationMinBP() != 9900 || !h.inProbation() {
		t.Fatalf("config: window %s min %d on %v", tc.b.probationWindow(), tc.b.probationMinBP(), h.inProbation())
	}
	t0 := time.Now().Add(time.Hour) // after any sample the join's sync took
	tc.b.mu.Lock()
	h.prob.lastSample = time.Time{} // the next sample sets the clock
	tc.b.mu.Unlock()
	// 99 s up, then down for the last second: 99.00% of 100 s.
	if !steps(tc, h, t0, sample{0, true}, sample{99 * time.Second, true}, sample{100 * time.Second, false}) {
		t.Fatal("the window end did not change the state")
	}
	if h.inProbation() {
		t.Fatal("99.00% verified uptime did not graduate")
	}
	if p := probationOf(t, tc, "m1"); p["state"] != "graduated" || p["uptime_pct"] != float64(99) || p["graduated_at"] == nil {
		t.Fatalf("readback: %v", p)
	}
}

func TestProbationRefusesJustUnderTheMinimumAndStartsANewWindow(t *testing.T) {
	tc := probationTC(t)
	joinMiner(t, tc, "m1", true, 5, nil)
	stopLoops(tc)
	h := tc.b.hotelByID("m1")
	t0 := time.Now().Add(time.Hour)
	tc.b.mu.Lock()
	h.prob.lastSample = time.Time{}
	tc.b.mu.Unlock()
	// 98.999 s up of 100 s: one millisecond under the minimum.
	if !steps(tc, h, t0, sample{0, true}, sample{98999 * time.Millisecond, true}, sample{100 * time.Second, false}) {
		t.Fatal("the window end did not change the state")
	}
	if !h.inProbation() {
		t.Fatal("98.999% uptime graduated")
	}
	p := probationOf(t, tc, "m1")
	if p["state"] != "probation" || p["windows_failed"] != float64(1) || p["last_window_uptime_pct"] != 98.99 || p["observed_s"] != float64(0) {
		t.Fatalf("readback after a failed window: %v", p)
	}
	// Far lower uptime fails the next window too.
	steps(tc, h, t0, sample{150 * time.Second, false}, sample{200 * time.Second, true})
	if !h.inProbation() || probationOf(t, tc, "m1")["windows_failed"] != float64(2) {
		t.Fatalf("low uptime: %v", probationOf(t, tc, "m1"))
	}
	// A clean window then graduates.
	steps(tc, h, t0, sample{250 * time.Second, true}, sample{300 * time.Second, true})
	if h.inProbation() {
		t.Fatalf("clean window: %v", probationOf(t, tc, "m1"))
	}
}

func TestProbationNeedsTheWholeWindowEvenAtFullUptime(t *testing.T) {
	tc := probationTC(t)
	joinMiner(t, tc, "m1", true, 5, nil)
	stopLoops(tc)
	h := tc.b.hotelByID("m1")
	t0 := time.Now().Add(time.Hour)
	tc.b.mu.Lock()
	h.prob.lastSample = time.Time{}
	tc.b.mu.Unlock()
	if steps(tc, h, t0, sample{0, true}, sample{99999 * time.Millisecond, true}) || !h.inProbation() {
		t.Fatal("graduated before the window was observed")
	}
	// A broker gap: after a restart the first sample only sets the clock, so
	// unobserved time neither helps nor hurts.
	tc.b.mu.Lock()
	h.prob.lastSample = time.Time{}
	tc.b.mu.Unlock()
	if steps(tc, h, t0, sample{time.Hour, true}) || !h.inProbation() {
		t.Fatal("unobserved time counted")
	}
	steps(tc, h, t0, sample{time.Hour + time.Millisecond, true})
	if h.inProbation() {
		t.Fatal("did not graduate once the window was observed")
	}
}

func TestProbationMinimumComesFromConfig(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	setProbationConfig(t, tc, 0.5, 95.5)
	if tc.b.probationWindow() != 500*time.Millisecond || tc.b.probationMinBP() != 9550 {
		t.Fatalf("window %s min %d", tc.b.probationWindow(), tc.b.probationMinBP())
	}
	joinMiner(t, tc, "m1", true, 5, nil)
	stopLoops(tc)
	h := tc.b.hotelByID("m1")
	t0 := time.Now().Add(time.Hour)
	tc.b.mu.Lock()
	h.prob.lastSample = time.Time{}
	tc.b.mu.Unlock()
	steps(tc, h, t0, sample{0, true}, sample{477 * time.Millisecond, true}, sample{500 * time.Millisecond, false}) // 95.4%
	if !h.inProbation() {
		t.Fatal("95.4% graduated at a 95.5% minimum")
	}
	tc.b.mu.Lock()
	h.prob.lastSample = time.Time{}
	tc.b.mu.Unlock()
	steps(tc, h, t0, sample{2 * time.Second, true}, sample{2500 * time.Millisecond, true}) // a full clean window
	if h.inProbation() {
		t.Fatal("clean window did not graduate")
	}
}

func TestProbationHotelTakesTestTrafficOnlyUntilItGraduates(t *testing.T) {
	tc := probationTC(t)
	joinMiner(t, tc, "m1", true, 5, nil)
	stopLoops(tc)
	optInMiner(t, tc, "g1") // the shared pool: miner opt-in without miner_probation
	setPolicy(t, tc, "g2", testTrafficPolicy)
	onM1 := map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}, "sealed": true}

	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", onM1); status != 409 {
		t.Fatalf("shared-pool guest reached a miner on probation: %d %v", status, doc)
	}
	if _, cat := tc.call(t, "key1", "GET", "/v1/broker/capacity", nil); listed(cat, "m1") {
		t.Fatalf("probation miner in the shared guest's catalog: %v", cat)
	}
	// Unnamed creates of the shared guest go to the own fleet.
	for i := 0; i < 5; i++ {
		if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"}); strings.HasPrefix(id, "m1.") {
			t.Fatalf("shared create on probation miner: %s", id)
		}
	}
	// The live view hides it from the shared guest as well.
	tc.b.mu.Lock()
	reach := tc.b.guests["g1"].tierOf(tc.b.hotelByID("m1"))
	tc.b.mu.Unlock()
	if reach != "" {
		t.Fatalf("shared guest tier on probation miner: %q", reach)
	}

	// The test-traffic guest reaches it, named and unnamed.
	if _, cat := tc.call(t, "key2", "GET", "/v1/broker/capacity", nil); !listed(cat, "m1") {
		t.Fatalf("probation miner missing from the test guest's catalog: %v", cat)
	}
	if id := tc.room(t, "key2", onM1); !strings.HasPrefix(id, "m1.") {
		t.Fatalf("test traffic did not reach the probation miner: %s", id)
	}
	if id := tc.room(t, "key2", map[string]any{"image": "alpine:3.20"}); !strings.HasPrefix(id, "m1.") {
		t.Fatalf("test traffic preferred tier: %s", id)
	}

	// Graduate: a clean, fully observed window.
	h := tc.b.hotelByID("m1")
	t0 := time.Now().Add(time.Hour)
	tc.b.mu.Lock()
	h.prob.lastSample = time.Time{}
	tc.b.mu.Unlock()
	steps(tc, h, t0, sample{0, true}, sample{100 * time.Second, true})
	if h.inProbation() {
		t.Fatal("not graduated")
	}
	if id := tc.room(t, "key1", onM1); !strings.HasPrefix(id, "m1.") {
		t.Fatalf("graduated miner refused the shared pool: %s", id)
	}
	if _, cat := tc.call(t, "key1", "GET", "/v1/broker/capacity", nil); !listed(cat, "m1") {
		t.Fatalf("graduated miner missing from the shared catalog: %v", cat)
	}
}

func TestGraduatedLabelFollowsProbation(t *testing.T) {
	tc := probationTC(t)
	joinMiner(t, tc, "m1", true, 5, map[string]any{"labels": map[string]string{"graduated": "true"}})
	stopLoops(tc)
	h := tc.b.hotelByID("m1")
	if h.labels()["graduated"] != "" || h.labels()["miner"] != "true" {
		t.Fatalf("probation miner labels: %v", h.labels())
	}
	// A shared policy that selects graduated miners by label does not reach it.
	setPolicy(t, tc, "g1", map[string]any{
		"prefer": []any{map[string]any{"label": map[string]string{"miner": "true", "graduated": "true"}}},
		"allow":  []any{map[string]any{"class": "unsealed"}},
	})
	onM1 := map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}, "sealed": true}
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", onM1); status != 409 {
		t.Fatalf("graduated selector reached a probation miner: %d", status)
	}
	t0 := time.Now().Add(time.Hour)
	tc.b.mu.Lock()
	h.prob.lastSample = time.Time{}
	tc.b.mu.Unlock()
	steps(tc, h, t0, sample{0, true}, sample{100 * time.Second, true})
	if h.labels()["graduated"] != "true" {
		t.Fatalf("graduated miner labels: %v", h.labels())
	}
	if id := tc.room(t, "key1", onM1); !strings.HasPrefix(id, "m1.") {
		t.Fatalf("graduated selector did not reach the graduated miner: %s", id)
	}
	// With probation off every miner is graduated; an operator hotel never is.
	tc2 := newChainState(t, t.TempDir())
	joinMiner(t, tc2, "m1", true, 5, nil)
	if tc2.b.hotelByID("m1").labels()["graduated"] != "true" || tc2.b.hotelByID("a").labels()["graduated"] != "" {
		t.Fatal("labels with probation off")
	}
}

func TestProbationCountsDownDrainedAndUnattestedAsDown(t *testing.T) {
	tc := probationTC(t)
	joinMiner(t, tc, "m1", true, 5, nil)
	stopLoops(tc)
	h := tc.b.hotelByID("m1")
	up := func() bool {
		tc.b.mu.Lock()
		defer tc.b.mu.Unlock()
		return tc.b.probationUp(h, time.Now())
	}
	if !up() {
		t.Fatal("admitted, healthy miner is not up")
	}
	h.cfgMu.Lock()
	h.cfg.Drain = true
	h.cfgMu.Unlock()
	if up() {
		t.Fatal("a draining miner counted as up")
	}
	h.cfgMu.Lock()
	h.cfg.Drain = false
	h.cfgMu.Unlock()
	tc.b.mu.Lock()
	h.ok = false
	tc.b.mu.Unlock()
	if up() {
		t.Fatal("a down miner counted as up")
	}
	tc.b.mu.Lock()
	h.ok = true
	h.adm.attestedAt = time.Time{} // attestation refused or expired
	tc.b.mu.Unlock()
	if up() {
		t.Fatal("an unattested miner counted as up")
	}
	// The sync loop samples it: after two ticks the readback has observed time.
	syncNow(tc, "m1")
	syncNow(tc, "m1")
	if p := probationOf(t, tc, "m1"); p["state"] != "probation" || p["observed_s"] == float64(0) {
		t.Fatalf("sync loop did not sample: %v", p)
	}
}

func TestProbationSurvivesRestartAndARejoinStartsFresh(t *testing.T) {
	tc := probationTC(t)
	joinMiner(t, tc, "m1", true, 5, nil)
	stopLoops(tc)
	joinMiner(t, tc, "m2", true, 5, nil)
	stopLoops(tc)
	h := tc.b.hotelByID("m1")
	t0 := time.Now().Add(time.Hour)
	tc.b.mu.Lock()
	h.prob.lastSample = time.Time{}
	tc.b.mu.Unlock()
	steps(tc, h, t0, sample{0, true}, sample{100 * time.Second, true}) // graduation saves at once
	h2 := tc.b.hotelByID("m2")
	tc.b.mu.Lock()
	h2.prob.lastSample = time.Time{}
	tc.b.mu.Unlock()
	steps(tc, h2, t0, sample{0, true}, sample{40 * time.Second, true})
	tc.b.saveProbationLogged()

	stopLoops(tc)
	tc.start(t)
	if tc.b.hotelByID("m1").inProbation() {
		t.Fatal("graduation lost on restart")
	}
	if p := probationOf(t, tc, "m2"); !tc.b.hotelByID("m2").inProbation() || p["observed_s"] != float64(40) {
		t.Fatalf("probation progress lost on restart: %v", p)
	}

	// A leave and rejoin under the same id starts a fresh probation, also
	// after a restart.
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/m1", nil); status != 204 {
		t.Fatalf("leave: %d %v", status, doc)
	}
	joinMiner(t, tc, "m1", true, 5, nil)
	stopLoops(tc)
	if !tc.b.hotelByID("m1").inProbation() {
		t.Fatal("rejoin inherited graduation")
	}
	stopLoops(tc)
	tc.start(t)
	if !tc.b.hotelByID("m1").inProbation() {
		t.Fatal("rejoin inherited graduation after a restart")
	}
	raw, _ := os.ReadFile(filepath.Join(tc.b.cfg.StateDir, probationFile))
	var saved map[string]savedProbation
	if json.Unmarshal(raw, &saved) != nil || saved["m1"].Graduated || saved["m1"].MinerHotkey != minerHotkey {
		t.Fatalf("%s: %s", probationFile, raw)
	}
	if info, err := os.Stat(filepath.Join(tc.b.cfg.StateDir, probationFile)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode: %v %v", info, err)
	}
}

func TestProbationRestoreNeedsTheSameMachine(t *testing.T) {
	tc := probationTC(t)
	joinMiner(t, tc, "m1", true, 5, nil)
	stopLoops(tc)
	h := tc.b.hotelByID("m1")
	t0 := time.Now().Add(time.Hour)
	tc.b.mu.Lock()
	h.prob.lastSample = time.Time{}
	tc.b.mu.Unlock()
	steps(tc, h, t0, sample{0, true}, sample{100 * time.Second, true})
	tc.b.saveProbationLogged()
	// The saved entry names another TLS pin: a different machine.
	path := filepath.Join(tc.b.cfg.StateDir, probationFile)
	raw, _ := os.ReadFile(path)
	var saved map[string]savedProbation
	if err := json.Unmarshal(raw, &saved); err != nil || !saved["m1"].Graduated {
		t.Fatalf("saved: %s", raw)
	}
	e := saved["m1"]
	e.TLSSPKISHA256 = strings.Repeat("0", 64)
	saved["m1"] = e
	raw, _ = json.Marshal(saved)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	stopLoops(tc)
	tc.start(t)
	if !tc.b.hotelByID("m1").inProbation() {
		t.Fatal("a different machine inherited the graduation")
	}
}

func TestTurningProbationOnGrandfathersServingMiners(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	joinMiner(t, tc, "m1", true, 5, nil) // probation off: serving the pool
	stopLoops(tc)
	if tc.b.hotelByID("m1").inProbation() {
		t.Fatal("probation off but the miner is on probation")
	}
	optInMiner(t, tc, "g1")
	onM1 := map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}, "sealed": true}
	room := tc.room(t, "key1", onM1)

	setProbationConfig(t, tc, 100, 0) // first enable: no probation file yet
	if tc.b.hotelByID("m1").inProbation() {
		t.Fatal("a serving miner went on probation at first enable")
	}
	if p := probationOf(t, tc, "m1"); p["state"] != "graduated" || p["grandfathered"] != true {
		t.Fatalf("readback: %v", p)
	}
	admitNow(t, tc, "m1")
	syncNow(tc, "m1")
	if status, doc := tc.call(t, "key1", "GET", "/v1/sandboxes/"+room, nil); status != 200 {
		t.Fatalf("running room unreachable after enable: %d %v", status, doc)
	}
	// A miner that joins after that starts on probation.
	joinMiner(t, tc, "m2", true, 5, nil)
	stopLoops(tc)
	if !tc.b.hotelByID("m2").inProbation() {
		t.Fatal("new miner skipped probation")
	}
	stopLoops(tc)
	tc.start(t)
	if tc.b.hotelByID("m1").inProbation() || !tc.b.hotelByID("m2").inProbation() {
		t.Fatal("restart changed the grandfathered or the probation state")
	}
}

func TestProbationOffLeavesMinersInThePool(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 5, nil)
	stopLoops(tc)
	optInMiner(t, tc, "g1")
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}, "sealed": true}); !strings.HasPrefix(id, "m1.") {
		t.Fatalf("probation off: %s", id)
	}
	if p := probationOf(t, tc, "m1"); p != nil {
		t.Fatalf("probation readback while off: %v", p)
	}
	if _, err := os.Stat(filepath.Join(tc.b.cfg.StateDir, probationFile)); !os.IsNotExist(err) {
		t.Fatalf("probation file written while off: %v", err)
	}
}

func TestProbationConfigAndPolicyValidation(t *testing.T) {
	for _, c := range []config{
		{MinerProbationSeconds: -1},
		{MinerProbationMinUptimePct: -1},
		{MinerProbationMinUptimePct: 100.5},
	} {
		if validateProbationConfig(c) == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	if err := validateProbationConfig(config{MinerProbationSeconds: 7 * 86400, MinerProbationMinUptimePct: 100}); err != nil {
		t.Fatal(err)
	}
	tc := newChainState(t, t.TempDir())
	status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g2", map[string]any{"policy": map[string]any{
		"prefer": []any{map[string]any{"class": "sealed"}}, "miner_probation": true}})
	if status != 400 {
		t.Fatalf("miner_probation without a miner selector: %d %v", status, doc)
	}
	setPolicy(t, tc, "g2", testTrafficPolicy)
	_, cat := tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	ap, _ := cat["admission_policy"].(map[string]any)
	if ap["miner_probation_seconds"] != float64(0) || ap["miner_probation_min_uptime_pct"] != float64(99) {
		t.Fatalf("admission_policy: %v", ap)
	}
}
