package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fresh attestation of miner hotels before new rooms (AB#947, fresh_attest.go).

// freshMiner joins miner hotel id with a fresh pass (joinMiner's sync step
// runs the fresh check) and opts g1 in.
func freshMiner(t *testing.T, tc *testChain, id string) (*minerHotel, *hotel) {
	t.Helper()
	m := joinMiner(t, tc, id, 4, nil)
	h := tc.b.hotelByID(id)
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	if !tc.b.admitted(h, time.Now()) || !tc.b.freshAttestOK(h, time.Now()) {
		t.Fatalf("hotel %s: admitted %v, fresh %+v", id, tc.b.admitted(h, time.Now()), h.freshAtt)
	}
	return m, h
}

// freshCheckNow runs h's fresh step now, as the sync loop does when it is due.
func freshCheckNow(tc *testChain, h *hotel) {
	tc.b.mu.Lock()
	h.freshAtt.checkedAt = time.Time{}
	tc.b.mu.Unlock()
	tc.b.syncFresh(context.Background(), h, true)
}

func freshState(tc *testChain, h *hotel) (bool, freshProof, int) {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	now := time.Now()
	return tc.b.freshAttestOK(h, now), h.freshAtt, tc.b.admissibleFree(h, now)
}

func ageFresh(tc *testChain, h *hotel, by time.Duration) {
	tc.b.mu.Lock()
	h.freshAtt.passedAt = h.freshAtt.passedAt.Add(-by)
	tc.b.mu.Unlock()
}

// Spec test 1: a pass at the boot binding with no fresh check is not picked;
// with a fresh pass it is. The check goes to /room/attest under the reserved
// guest id, over the miner's TLS fixture, and runs the verifier's fresh mode.
func TestFreshMinerNotPickedWithoutAFreshCheck(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	optInMiner(t, tc, "g1")
	m, h := freshMiner(t, tc, "m1")
	if m.freshCalls.Load() != 1 {
		t.Fatalf("fresh calls after join: %d, want 1", m.freshCalls.Load())
	}
	fl, _ := os.ReadFile(filepath.Join(tc.amdDir, "fresh.log"))
	if !strings.HasPrefix(string(fl), "--fresh-report ") || !strings.Contains(string(fl), "--report-data-hex ") || !strings.Contains(string(fl), "--ark-sha256 "+testARKPin) {
		t.Fatalf("verifier fresh mode call: %q", fl)
	}
	tc.b.mu.Lock()
	h.freshAtt = freshProof{} // admitted at the boot binding, never fresh-checked
	tc.b.mu.Unlock()
	if ok, _, free := freshState(tc, h); ok || free != 0 {
		t.Fatalf("no fresh check: ok %v free %d", ok, free)
	}
	tc.b.mu.Lock()
	admitted := tc.b.admitted(h, time.Now())
	tc.b.mu.Unlock()
	if !admitted {
		t.Fatal("admission itself must not read fresh state")
	}
	onM1 := map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", onM1); status != 503 || errCode(doc) != "hotels_not_admitted" {
		t.Fatalf("create with no fresh proof: %d %v", status, doc)
	}
	syncNow(tc, "m1") // due at once: no state for the admitted binding
	if ok, _, free := freshState(tc, h); !ok || free == 0 {
		t.Fatalf("after a fresh pass: ok %v free %d", ok, free)
	}
	if id := tc.room(t, "key1", onM1); !strings.HasPrefix(id, "m1.") {
		t.Fatalf("fresh miner not picked: %s", id)
	}
}

// Spec test 2: a pass older than the window is not picked; the create lands
// on another fresh miner, and with none it is a 503.
func TestFreshStaleProofSendsTheCreateElsewhereOr503(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	optInMiner(t, tc, "g1")
	_, h1 := freshMiner(t, tc, "m1")
	_, h2 := freshMiner(t, tc, "m2")
	ageFresh(tc, h1, tc.b.minerFreshAttest()+time.Second)
	if ok, _, free := freshState(tc, h1); ok || free != 0 {
		t.Fatalf("stale: ok %v free %d", ok, free)
	}
	both := map[string]any{"image": "alpine:3.20", "hotels": []string{"m1", "m2"}}
	for i := 0; i < 3; i++ {
		if id := tc.room(t, "key1", both); !strings.HasPrefix(id, "m2.") {
			t.Fatalf("create %d went to %s, want m2", i, id)
		}
	}
	ageFresh(tc, h2, tc.b.minerFreshAttest()+time.Second)
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", both); status != 503 || errCode(doc) != "hotels_not_admitted" {
		t.Fatalf("no fresh miner: %d %v", status, doc)
	}
	_, cat := tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	mf, _ := cat["miner_fresh"].(map[string]any)
	if mf["held_out"] != float64(2) || mf["max_age_seconds"] != float64(30) {
		t.Fatalf("capacity miner_fresh: %v", cat["miner_fresh"])
	}
	for _, d := range cat["hotels"].([]any) {
		doc := d.(map[string]any)
		fr, _ := doc["admission"].(map[string]any)["fresh"].(map[string]any)
		if id := doc["id"].(string); id != "m1" && id != "m2" {
			if fr != nil {
				t.Fatalf("operator hotel %s has admission.fresh %v", id, fr)
			}
			continue
		}
		if fr == nil || fr["ok"] != false || fr["max_age_seconds"] != float64(30) || fr["at"] == nil || fr["reason"] == nil {
			t.Fatalf("hotel %v admission.fresh: %v", doc["id"], fr)
		}
	}
}

// Spec test 3 and rev 2: each wrong answer is refused with its reason and
// clears the pass. The answer's unsigned binding_sha256 is always wrong in
// the fixture (serveFresh) and is never read.
func TestFreshRefusalsClearThePassWithAReason(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	m, h := freshMiner(t, tc, "m1")
	for _, c := range []struct{ mode, verdict, reason string }{
		{mode: "replay", reason: "REPORT_DATA is not the value sent"},
		{mode: "report_id", reason: "REPORT_ID differs from the admitted launch"},
		{mode: "no_report_id", reason: "fresh report has no REPORT_ID"},
		{mode: "debug", reason: "policy differs from the admitted one"},
		{mode: "chip", reason: "chip id differs"},
		{mode: "launch_tcb", reason: "LAUNCH_TCB differs"},
		{mode: "500", reason: "answered 500"},
		{verdict: `{"verdict": "FAIL", "reason": "report signature does not verify with the VCEK"}`, reason: "AMD chain: report signature does not verify"},
	} {
		m.setFresh("")
		setFreshVerdict(t, tc, "")
		freshCheckNow(tc, h)
		if ok, _, _ := freshState(tc, h); !ok {
			t.Fatalf("%s: no pass before the case", c.mode)
		}
		m.setFresh(c.mode)
		setFreshVerdict(t, tc, c.verdict)
		freshCheckNow(tc, h)
		ok, f, free := freshState(tc, h)
		if ok || free != 0 || !f.passedAt.IsZero() || !strings.Contains(f.reason, c.reason) {
			t.Fatalf("%s: ok %v free %d passedAt %v reason %q, want %q", c.mode+c.verdict, ok, free, f.passedAt, f.reason, c.reason)
		}
	}
}

// The field checks without a hotel: the debug bit (the hotel fixture's
// "debug" mode also changes the policy, so it is refused as a policy change
// first) and a measurement no longer listed.
func TestFreshFieldChecks(t *testing.T) {
	var att struct {
		Report string `json:"report_b64"`
	}
	_ = json.Unmarshal(snpAttestation(t, attestOpts{}), &att)
	rep, _ := base64.StdEncoding.DecodeString(att.Report)
	want := bytes.Repeat([]byte{0x42}, 64)
	copy(rep[0x50:0x90], want)
	tg := freshTarget{reportID: snpReportID(rep), measurement: strings.Repeat("ab", 48), chip: hex.EncodeToString(rep[0x1A0:0x1E0]),
		launchTCB: hex.EncodeToString(rep[0x1F0:0x1F8]), policy: 0x30000 | snpPolicyDebugBit}
	rep[0x08+2] |= 0x08
	if err := checkFreshFields(rep, want, tg, []string{tg.measurement}); err == nil || !strings.Contains(err.Error(), "allows debug") {
		t.Fatalf("debug bit: %v", err)
	}
	rep[0x08+2] &^= 0x08
	tg.policy = 0x30000
	if err := checkFreshFields(rep, want, tg, []string{tg.measurement}); err != nil {
		t.Fatalf("good fields: %v", err)
	}
	if err := checkFreshFields(rep, want, tg, []string{strings.Repeat("22", 48)}); err == nil || !strings.Contains(err.Error(), "no longer in sealed_measurements") {
		t.Fatalf("measurement gone: %v", err)
	}
}

// Spec test 4: a reload that removes the measurement: the next fresh check fails.
func TestFreshCheckFailsAfterReloadRemovesTheMeasurement(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	_, h := freshMiner(t, tc, "m1")
	tc.b.mu.Lock()
	tg, due := tc.b.freshDue(h, true, time.Now().Add(time.Minute))
	h.freshAtt.running = false
	l := *tc.b.admLists()
	l.measurements = []string{strings.Repeat("22", 48)}
	tc.b.adml.Store(&l)
	tc.b.admissionListsChangedLocked(true)
	free := tc.b.admissibleFree(h, time.Now())
	tc.b.mu.Unlock()
	if !due || free != 0 {
		t.Fatalf("due %v, free after the reload %d", due, free)
	}
	err := tc.b.checkFresh(context.Background(), h, tg)
	if err == nil || !strings.Contains(err.Error(), "no longer in sealed_measurements") {
		t.Fatalf("fresh check after the reload: %v", err)
	}
}

// Spec test 5 and rev 2: a 429, a timeout or a busy verifier keeps the last
// pass until its window ends; rooms already running are untouched.
func TestFreshNoAnswerKeepsThePassUntilItsWindowEnds(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	optInMiner(t, tc, "g1")
	m, h := freshMiner(t, tc, "m1")
	onM1 := map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}}
	room := tc.room(t, "key1", onM1)
	defer func(d, w time.Duration) { freshCallTimeout, freshVerifierWait = d, w }(freshCallTimeout, freshVerifierWait)
	freshCallTimeout, freshVerifierWait = 200*time.Millisecond, 100*time.Millisecond
	busy := func() func() {
		freshSlot <- struct{}{}
		for i := 0; i < cap(amdSlots); i++ {
			amdSlots <- struct{}{}
		}
		return func() {
			<-freshSlot
			for i := 0; i < cap(amdSlots); i++ {
				<-amdSlots
			}
		}
	}
	for _, c := range []struct{ mode, reason string }{
		{"429", "429"}, {"hang", "did not answer"}, {"busy", "verifier is busy"},
	} {
		m.setFresh("")
		freshCheckNow(tc, h)
		if c.mode == "busy" {
			done := busy()
			freshCheckNow(tc, h)
			done()
		} else {
			m.setFresh(c.mode)
			freshCheckNow(tc, h)
		}
		ok, f, free := freshState(tc, h)
		if !ok || free == 0 || f.passedAt.IsZero() || !strings.Contains(f.reason, c.reason) {
			t.Fatalf("%s: ok %v free %d reason %q", c.mode, ok, free, f.reason)
		}
		ageFresh(tc, h, tc.b.minerFreshAttest())
		if ok, _, _ := freshState(tc, h); ok {
			t.Fatalf("%s: the kept pass outlived its window", c.mode)
		}
	}
	if status, doc := tc.call(t, "key1", "GET", "/v1/sandboxes/"+room, nil); status != 200 {
		t.Fatalf("running room after lapses: %d %v", status, doc)
	}
}

// Rev 2: joins holding every shared verifier slot cannot starve fresh checks.
func TestFreshCheckHasAReservedVerifierSlot(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	_, h := freshMiner(t, tc, "m1")
	for i := 0; i < cap(amdSlots); i++ {
		amdSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(amdSlots); i++ {
			<-amdSlots
		}
	}()
	ageFresh(tc, h, time.Hour)
	freshCheckNow(tc, h)
	if ok, f, _ := freshState(tc, h); !ok {
		t.Fatalf("fresh check with joins holding every shared slot: %+v", f)
	}
	// And a join waits for a shared slot: it never takes the reserved one.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := amdSlotAcquire(ctx); err != errVerifierBusy {
		t.Fatalf("join slot with every shared slot taken: %v", err)
	}
}

// Rev 2: the one-chip check and probation read admission, not fresh state.
func TestChipHolderAndProbationIgnoreFreshState(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	_, h := freshMiner(t, tc, "m1")
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	h.freshAtt = freshProof{}
	now := time.Now()
	other := &hotel{cfg: hotelConfig{ID: "m9", MinerHotkey: minerHotkey, Sealed: true}}
	if o := tc.b.chipHolder(other, h.adm.chipFull, now); o != h {
		t.Fatalf("chip holder with no fresh proof: %v", o)
	}
	if !tc.b.probationUp(h, now) {
		t.Fatal("probation counts a lapsed fresh proof as downtime")
	}
}

// Rev 2: a pass for an older binding does not count for the admitted one.
func TestFreshStateOfAnOlderBindingIsIgnored(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	_, h := freshMiner(t, tc, "m1")
	tc.b.mu.Lock()
	h.freshAtt.binding = strings.Repeat("0", 64)
	tc.b.mu.Unlock()
	if ok, _, free := freshState(tc, h); ok || free != 0 {
		t.Fatalf("old binding's pass: ok %v free %d", ok, free)
	}
	tc.b.mu.Lock()
	d := tc.b.admissionDoc(h, time.Now())["fresh"].(map[string]any)
	tc.b.mu.Unlock()
	if d["ok"] != false || d["at"] != nil || !strings.Contains(d["reason"].(string), "no fresh check of the admitted binding") {
		t.Fatalf("doc for an old binding's state: %v", d)
	}
	tc.b.mu.Lock()
	_, due := tc.b.freshDue(h, true, time.Now())
	h.freshAtt.running = false
	tc.b.mu.Unlock()
	if !due {
		t.Fatal("an old binding's state must make the check due")
	}
	syncNow(tc, "m1")
	if ok, f, _ := freshState(tc, h); !ok || f.binding != h.adm.bindingSHA {
		t.Fatalf("after a check of the admitted binding: %+v", f)
	}
	// A check that finishes after the hotel was admitted with another
	// binding is dropped.
	tc.b.mu.Lock()
	tc.b.noteFresh(h, strings.Repeat("1", 64), nil, time.Now())
	ok := tc.b.freshAttestOK(h, time.Now())
	tc.b.mu.Unlock()
	if ok {
		t.Fatal("a pass noted for another binding counts for the admitted one")
	}
}

// Rev 2: a create queued for its slot is rechecked after a lapse.
func TestQueuedCreateDoesNotStartAfterTheFreshProofLapsed(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	optInMiner(t, tc, "g1")
	m, h := freshMiner(t, tc, "m1")
	m.mu.Lock()
	m.createDelay = 500 * time.Millisecond
	m.mu.Unlock()
	setHotel(tc, "m1", func(h *hotel) { h.sem = make(chan struct{}, 1) })
	onM1 := map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			tc.b.mu.Lock()
			ok := cond()
			tc.b.mu.Unlock()
			if ok {
				return
			}
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	type answer struct {
		status int
		doc    map[string]any
	}
	first, second := make(chan answer, 1), make(chan answer, 1)
	go func() { s, d := tc.call(t, "key1", "POST", "/v1/sandboxes", onM1); first <- answer{s, d} }()
	waitFor("the first create to hold the slot", func() bool { return h.creating == 1 })
	go func() { s, d := tc.call(t, "key1", "POST", "/v1/sandboxes", onM1); second <- answer{s, d} }()
	waitFor("the second create to queue", func() bool { return h.queued == 1 })
	m.setFresh("replay")
	freshCheckNow(tc, h)
	if a := <-first; a.status != 202 {
		t.Fatalf("first create: %d %v", a.status, a.doc)
	}
	if a := <-second; a.status != 503 || errCode(a.doc) != "hotels_not_admitted" {
		t.Fatalf("queued create after the fresh proof lapsed: %d %v", a.status, a.doc)
	}
	if n := creates(tc, "m1"); n != 1 {
		t.Fatalf("hotel m1 started %d rooms, want 1", n)
	}
}

// Spec test 6: an operator hotel takes no fresh check and places as before.
func TestOperatorHotelHasNoFreshGate(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	m := joinOperatorSealed(t, tc, "op1", 4)
	syncNow(tc, "op1")
	h := tc.b.hotelByID("op1")
	tc.b.mu.Lock()
	ok, doc := tc.b.freshAttestOK(h, time.Now()), tc.b.admissionDoc(h, time.Now())
	free := tc.b.admissibleFree(h, time.Now())
	tc.b.mu.Unlock()
	if !ok || free == 0 || doc["fresh"] != nil || m.freshCalls.Load() != 0 {
		t.Fatalf("operator hotel: ok %v free %d doc %v calls %d", ok, free, doc["fresh"], m.freshCalls.Load())
	}
	if _, err := os.Stat(filepath.Join(tc.amdDir, "fresh.log")); err == nil {
		t.Fatal("the verifier ran a fresh check for an operator hotel")
	}
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"op1"}}); !strings.HasPrefix(id, "op1.") {
		t.Fatalf("operator hotel create: %s", id)
	}
	// The config file hotels (sealed_admission off) too.
	for _, id := range []string{"a", "b", "c"} {
		tc.b.mu.Lock()
		ok := tc.b.freshAttestOK(tc.b.hotelByID(id), time.Now())
		tc.b.mu.Unlock()
		if !ok {
			t.Fatalf("config hotel %s gated on a fresh proof", id)
		}
	}
}

// One log line per transition, never per check.
func TestFreshLogsOnlyTransitions(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	m, h := freshMiner(t, tc, "m1")
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	freshCheckNow(tc, h) // ok to ok
	m.setFresh("replay")
	freshCheckNow(tc, h) // ok to failed
	freshCheckNow(tc, h) // failed to failed
	m.setFresh("")
	freshCheckNow(tc, h) // failed to ok
	freshCheckNow(tc, h)
	log.SetOutput(os.Stderr)
	out := buf.String()
	if strings.Count(out, "hotel m1 held out of placement: fresh attestation") != 1 || strings.Count(out, "hotel m1 fresh attestation passed") != 1 {
		t.Fatalf("fresh log lines:\n%s", out)
	}
}

// Config: the window's bounds and the reserved guest id.
func TestFreshConfigBoundsAndReservedGuest(t *testing.T) {
	for v, ok := range map[float64]bool{0: true, 5: true, 30: true, 300: true, 4.9: false, 301: false, -1: false} {
		if err := validateMinerFreshAttest(v); (err == nil) != ok {
			t.Fatalf("miner_fresh_attest_seconds %v: %v", v, err)
		}
	}
	if err := validateTopConfig(config{MinerFreshAttestSeconds: 2}); err == nil || !strings.Contains(err.Error(), "miner_fresh_attest_seconds") {
		t.Fatalf("top config with a 2 s window: %v", err)
	}
	if _, _, err := buildGuests(config{Guests: []guestConfig{{ID: freshGuestID, KeySHA256: sha("k")}}}); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("guest %s: %v", freshGuestID, err)
	}
	b := &broker{cfg: config{MinerFreshAttestSeconds: 12}}
	if b.minerFreshAttest() != 12*time.Second || (&broker{}).minerFreshAttest() != 30*time.Second {
		t.Fatal("window from config")
	}
}

// The fresh REPORT_DATA binds the hotel, the binding and the nonce.
func TestFreshReportDataBindsHotelBindingAndNonce(t *testing.T) {
	bsha := strings.Repeat("ab", 32)
	n1, n2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	a, _ := freshReportData("m1", bsha, n1)
	for _, other := range [][]byte{
		mustRD(t, "m2", bsha, n1), mustRD(t, "m1", strings.Repeat("cd", 32), n1), mustRD(t, "m1", bsha, n2),
	} {
		if bytes.Equal(a, other) || len(other) != 64 {
			t.Fatal("REPORT_DATA does not bind every input")
		}
	}
	if _, err := freshReportData("m1", "", n1); err == nil {
		t.Fatal("an empty binding must not make a REPORT_DATA")
	}
}

func mustRD(t *testing.T, id, bsha string, nonce []byte) []byte {
	t.Helper()
	rd, err := freshReportData(id, bsha, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return rd
}

func setFreshVerdict(t *testing.T, tc *testChain, verdict string) {
	t.Helper()
	p := filepath.Join(tc.amdDir, "fresh_verdict.json")
	if verdict == "" {
		_ = os.Remove(p)
		return
	}
	if err := os.WriteFile(p, []byte(verdict), 0o600); err != nil {
		t.Fatal(err)
	}
}

// freshPass gives a miner hotel built by hand a fresh pass for its binding
// (one is made up when it has none). Caller holds b.mu or owns h.
func freshPass(h *hotel) {
	if h.adm.bindingSHA == "" {
		h.adm.bindingSHA = strings.Repeat("5e", 32)
	}
	h.freshAtt = freshProof{binding: h.adm.bindingSHA, passedAt: time.Now(), checkedAt: time.Now(), shownOK: true}
}

// freshSettled runs h's fresh step as the sync step does after admission,
// and waits for a check a still-running sync loop has in flight.
func freshSettled(tc *testChain, h *hotel) {
	tc.b.syncFresh(context.Background(), h, true)
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		tc.b.mu.Lock()
		running := h.freshAtt.running
		tc.b.mu.Unlock()
		if !running {
			return
		}
	}
}
