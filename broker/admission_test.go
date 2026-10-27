package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Capacity plane slice 2: joined (miner) hotels in the broker catalog,
// admission (health and SEV-SNP attestation), class spill, isolation and the
// per-class catalog. No network: every hotel is a fake in this process.

const minerHotkey = "5F3sa2TJAWMqDhXG6jhV4N8ko9SxwGy8TpaNS1repo5EYjQX"

type attestOpts struct {
	debugPolicy   bool   // guest policy bit 19 set
	debugCmdline  bool   // cathedral.debug=1 on the kernel command line
	level1        bool   // a hotel (level 1) binding with no report
	badReportData bool   // REPORT_DATA does not commit to the binding
	badSHA        bool   // binding_sha256 is not the hash of the binding
	measurement   byte   // fill byte of the measurement (default 0xab)
	chip          byte   // CHIP_ID seed: hotels with one seed are one machine
	receiptKey    []byte // 32-byte Ed25519 public key; default is the placeholder "AAAA"
}

// snpAttestation builds a GET /room/attestation body the way room_receipts.py
// serves it: canonical JSON (sorted keys, no spaces) with a binding, its
// SHA-256 and a 1184-byte SNP report whose fields agree with the binding.
func snpAttestation(t testing.TB, o attestOpts) []byte {
	t.Helper()
	m := o.measurement
	if m == 0 {
		m = 0xab
	}
	rep := make([]byte, 0x4A0)
	binary.LittleEndian.PutUint32(rep[0:4], 3)
	policy := uint64(0x30000)
	if o.debugPolicy {
		policy |= 1 << 19
	}
	binary.LittleEndian.PutUint64(rep[0x08:0x10], policy)
	for i := 0x90; i < 0xC0; i++ {
		rep[i] = m
	}
	for i := 0xC0; i < 0xE0; i++ {
		rep[i] = 0x55
	}
	for i := 0x180; i < 0x188; i++ {
		rep[i] = 0x07
	}
	for i := 0x1A0; i < 0x1E0; i++ {
		rep[i] = byte(i) + o.chip
	}
	cmdline := "console=ttyS0 root=/dev/vda"
	if o.debugCmdline {
		cmdline += " cathedral.debug=1"
	}
	receiptKeyB64 := "AAAA"
	if len(o.receiptKey) == 32 {
		receiptKeyB64 = base64.StdEncoding.EncodeToString(o.receiptKey)
	}
	binding := map[string]any{
		"schema": "cathedral.room-binding.v1", "hotel": "miner", "boot_id": "b-1", "created_at": 1,
		"receipt_key_ed25519_b64": receiptKeyB64, "measurement": hex.EncodeToString(rep[0x90:0xC0]),
		"chip_id": hex.EncodeToString(rep[0x1A0:0x1E0]), "reported_tcb": hex.EncodeToString(rep[0x180:0x188]),
		"policy": "0x30000", "host_data": hex.EncodeToString(rep[0xC0:0xE0]), "kernel_cmdline": cmdline,
		"kernel_release": "6.8.0", "software": map[string]any{"room_kit": "abc", "cathedral": "def"},
	}
	if o.debugPolicy {
		binding["policy"] = "0xb0000"
	}
	if o.level1 {
		binding = map[string]any{"schema": "cathedral.hotel-binding.v1", "level": "hotel", "hotel": "miner"}
	}
	raw, _ := json.Marshal(binding) // sorted keys, compact: the canonical form
	sum := sha256.Sum256(raw)
	if !o.badReportData {
		copy(rep[0x50:0x70], sum[:])
	}
	doc := map[string]any{"binding": json.RawMessage(raw), "binding_sha256": hex.EncodeToString(sum[:])}
	if o.badSHA {
		doc["binding_sha256"] = strings.Repeat("0", 64)
	}
	if !o.level1 {
		doc["report_b64"] = base64.StdEncoding.EncodeToString(rep)
	}
	out, _ := json.Marshal(doc)
	return out
}

// minerHotel is a fake hotel whose health reports slots, like room_health.py.
type minerHotel struct {
	*fakeHotel
	slots atomic.Int64
}

func (m *minerHotel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/room/health" {
		m.mu.Lock()
		fail := m.healthFail
		m.mu.Unlock()
		if !fail {
			writeJSON(w, 200, map[string]any{"slots": m.slots.Load(), "live": map[string]any{"host_cpu_pct": 10.0}})
			return
		}
	}
	m.fakeHotel.ServeHTTP(w, r)
}

func (m *minerHotel) setAttestation(b []byte) {
	m.mu.Lock()
	m.attestation = b
	m.mu.Unlock()
}

func (m *minerHotel) setHealthFail(v bool) {
	m.mu.Lock()
	m.healthFail = v
	m.mu.Unlock()
}

func newMinerHotel(t *testing.T, slots int, att []byte) (*minerHotel, string) {
	t.Helper()
	m := &minerHotel{fakeHotel: &fakeHotel{t: t, snaps: map[string]map[string]any{}, attestation: att}}
	m.slots.Store(int64(slots))
	hs := httptest.NewServer(m)
	t.Cleanup(hs.Close)
	return m, hs.URL
}

// chipOf is a CHIP_ID seed per hotel id: each test hotel is its own machine.
func chipOf(id string) byte {
	var s byte
	for _, c := range []byte(id) {
		s = s*31 + c
	}
	return s
}

// joinMiner joins a miner hotel through the operator route and runs one sync
// step, as the sync loop would: health, then the attestation check.
func joinMiner(t *testing.T, tc *testChain, id string, sealed bool, slots int, extra map[string]any) *minerHotel {
	t.Helper()
	var att []byte
	if sealed {
		att = snpAttestation(t, attestOpts{chip: chipOf(id)})
	}
	m, url := newMinerHotel(t, slots, att)
	tc.hotels[id] = m.fakeHotel
	body := map[string]any{"id": id, "api": url, "key": joinKey, "sealed": sealed, "miner_hotkey": minerHotkey}
	for k, v := range extra {
		body[k] = v
	}
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", body); status != 201 {
		t.Fatalf("join %s: %d %v", id, status, doc)
	}
	syncNow(tc, id)
	return m
}

// syncNow runs one sync step of hotel id now, if it is still in the set (a
// concurrent leave may have removed it).
func syncNow(tc *testChain, id string) {
	if h := tc.b.hotelByID(id); h != nil {
		tc.b.syncHotel(context.Background(), h)
	}
}

// admitNow runs the sync loop's attestation step for id and fails the test
// when the hotel is not admitted after it.
func admitNow(t *testing.T, tc *testChain, id string) {
	t.Helper()
	h := tc.b.hotelByID(id)
	tc.b.mu.Lock()
	h.adm.checkedAt = time.Time{} // due now
	tc.b.mu.Unlock()
	tc.b.syncAdmission(context.Background(), h, true)
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	if !tc.b.admitted(h, time.Now()) {
		t.Fatalf("hotel %s not admitted: %s", id, h.adm.reason)
	}
}

func setPolicy(t *testing.T, tc *testChain, guest string, policy map[string]any) {
	t.Helper()
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/"+guest, map[string]any{"policy": policy}); status != 200 {
		t.Fatalf("policy %s: %d %v", guest, status, doc)
	}
}

func reasonOf(doc map[string]any) map[string]any {
	r, _ := doc["reason"].(map[string]any)
	return r
}

func admissionOf(t *testing.T, tc *testChain, id string) map[string]any {
	t.Helper()
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/hotels/"+id, nil)
	if status != 200 {
		t.Fatalf("hotel %s: %d %v", id, status, doc)
	}
	a, _ := doc["admission"].(map[string]any)
	return a
}

// ---------------------------------------------------------------- registration

func TestJoinedMinerHotelPersistsAcrossRestartAndMustPassAgain(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	joinMiner(t, tc, "m1", true, 5, map[string]any{"max_slots": 3, "reserved_for": "g1"})
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/hotels/m1", nil)
	labels, _ := doc["labels"].(map[string]any)
	if status != 200 || doc["class"] != "sealed" || labels["miner"] != "true" || labels["miner_hotkey"] != minerHotkey || doc["slots"] != float64(3) {
		t.Fatalf("joined hotel: %d %v", status, doc)
	}
	if a := admissionOf(t, tc, "m1"); a["state"] != "admitted" || a["attestation_required"] != true {
		t.Fatalf("admission after join: %v", a)
	}
	// Update: a lower cap applies at once; the miner and sealed labels stay.
	status, doc = tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"max_slots": 2, "labels": map[string]string{"zone": "eu"}})
	labels, _ = doc["labels"].(map[string]any)
	if status != 200 || doc["slots"] != float64(2) || labels["miner"] != "true" || labels["sealed"] != "true" || labels["zone"] != "eu" {
		t.Fatalf("patch: %d %v", status, doc)
	}

	tc.start(t) // restart: same config, same state_dir
	h := tc.b.hotelByID("m1")
	if h == nil || h.cfg.MinerHotkey != minerHotkey || h.cfg.MaxSlots != 2 || h.reservedFor() != "g1" || h.labels()["zone"] != "eu" || h.labels()["miner"] != "true" {
		t.Fatalf("hotel after restart: %+v", h)
	}
	// Restored, but not admitted: the attestation must pass again.
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}, "sealed": true})
	if status != 503 || errCode(doc) != "hotels_not_admitted" || reasonOf(doc)["pending_admission"] != float64(1) {
		t.Fatalf("create before admission: %d %v", status, doc)
	}
	admitNow(t, tc, "m1")
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}, "sealed": true}); !strings.HasPrefix(id, "m1.") {
		t.Fatalf("room on %s", id)
	}
	// Config hotels keep working and are not gated.
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}); !strings.HasPrefix(id, "b.") {
		t.Fatalf("config hotel: %s", id)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, runtimeHotelsFile))
	if strings.Contains(string(raw), joinKey) || !strings.Contains(string(raw), minerHotkey) {
		t.Fatalf("hotels.json: %s", raw)
	}
}

func TestJoinRefusesABadMinerHotkeyAndCap(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	_, url := newMinerHotel(t, 5, nil)
	for _, body := range []map[string]any{
		{"id": "x", "api": url, "key": joinKey, "miner_hotkey": "not-a-hotkey"},
		{"id": "x", "api": url, "key": joinKey, "max_slots": -1},
	} {
		if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", body); status != 400 || errCode(doc) != "invalid_hotel" {
			t.Fatalf("%v: %d %v", body, status, doc)
		}
	}
}

// ---------------------------------------------------------------- admission

func TestSealedJoinPassesAttestationBeforePlacement(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	bad := map[string]attestOpts{
		"debug policy":  {debugPolicy: true},
		"debug cmdline": {debugCmdline: true},
		"level 1":       {level1: true},
		"report data":   {badReportData: true},
		"binding hash":  {badSHA: true},
	}
	for name, o := range bad {
		_, url := newMinerHotel(t, 5, snpAttestation(t, o))
		status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "bad", "api": url, "key": joinKey, "sealed": true})
		if status != 422 || errCode(doc) != "attestation_failed" {
			t.Fatalf("%s: %d %v", name, status, doc)
		}
		if tc.b.hotelByID("bad") != nil {
			t.Fatalf("%s: refused hotel was added", name)
		}
	}
	// No attestation endpoint at all: refused too.
	_, url := newMinerHotel(t, 5, nil)
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "bad", "api": url, "key": joinKey, "sealed": true}); status != 422 {
		t.Fatalf("no attestation: %d %v", status, doc)
	}

	// verify false: the hotel joins pending and takes no room until it passes.
	m, url := newMinerHotel(t, 5, nil)
	tc.hotels["p"] = m.fakeHotel
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "p", "api": url, "key": joinKey, "sealed": true, "verify": false}); status != 201 {
		t.Fatalf("join pending: %d %v", status, doc)
	}
	syncNow(tc, "p") // health passes, attestation does not answer
	sealedOnP := map[string]any{"image": "alpine:3.20", "hotels": []string{"p"}}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", sealedOnP)
	if status != 503 || errCode(doc) != "hotels_not_admitted" {
		t.Fatalf("create on pending hotel: %d %v", status, doc)
	}
	if a := admissionOf(t, tc, "p"); a["state"] == "admitted" {
		t.Fatalf("pending hotel shows admitted: %v", a)
	}
	_, cat := tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	if e, _ := catalogEntry(cat, "p"); e["free_rooms"] != float64(0) || e["source"] != "join" {
		t.Fatalf("catalog of pending hotel: %v", e)
	}
	// A bad attestation is refused with its reason; a good one admits.
	m.setAttestation(snpAttestation(t, attestOpts{debugPolicy: true}))
	tc.b.mu.Lock()
	tc.b.hotelByID("p").adm.checkedAt = time.Time{}
	tc.b.mu.Unlock()
	syncNow(tc, "p")
	if a := admissionOf(t, tc, "p"); a["state"] != "refused" || !strings.Contains(a["reason"].(string), "debug") {
		t.Fatalf("debug attestation: %v", a)
	}
	m.setAttestation(snpAttestation(t, attestOpts{}))
	admitNow(t, tc, "p")
	if id := tc.room(t, "key1", sealedOnP); !strings.HasPrefix(id, "p.") {
		t.Fatalf("room on %s", id)
	}
	if n := creates(tc, "p"); n != 1 {
		t.Fatalf("hotel p got %d creates, want 1 (none before admission)", n)
	}
}

func TestVerifyAttestationAllowlists(t *testing.T) {
	var att struct {
		Binding    json.RawMessage `json:"binding"`
		BindingSHA string          `json:"binding_sha256"`
		Report     string          `json:"report_b64"`
	}
	_ = json.Unmarshal(snpAttestation(t, attestOpts{measurement: 0x11}), &att)
	want := strings.Repeat("11", 48)
	host := strings.Repeat("55", 32)
	if res, err := verifyAttestation(att.Binding, att.BindingSHA, att.Report, nil, nil); err != nil || res.measurement != want {
		t.Fatalf("no allowlist: %v %v", res, err)
	}
	if _, err := verifyAttestation(att.Binding, att.BindingSHA, att.Report, []string{strings.Repeat("22", 48)}, nil); err == nil || !strings.Contains(err.Error(), "sealed_measurements") {
		t.Fatalf("measurement outside the list passed: %v", err)
	}
	if _, err := verifyAttestation(att.Binding, att.BindingSHA, att.Report, []string{strings.ToUpper(want)}, []string{host}); err != nil {
		t.Fatalf("listed measurement and host data: %v", err)
	}
	if _, err := verifyAttestation(att.Binding, att.BindingSHA, att.Report, nil, []string{strings.Repeat("66", 32)}); err == nil || !strings.Contains(err.Error(), "sealed_host_data") {
		t.Fatalf("host data outside the list passed: %v", err)
	}
	// One changed byte in the served binding breaks the hash.
	tampered := []byte(strings.Replace(string(att.Binding), `"miner"`, `"minor"`, 1))
	if _, err := verifyAttestation(tampered, att.BindingSHA, att.Report, nil, nil); err == nil {
		t.Fatalf("tampered binding passed")
	}
}

func TestVerifyAttestationKeepsTheReceiptKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var att struct {
		Binding    json.RawMessage `json:"binding"`
		BindingSHA string          `json:"binding_sha256"`
		Report     string          `json:"report_b64"`
	}
	_ = json.Unmarshal(snpAttestation(t, attestOpts{receiptKey: pub}), &att)
	res, err := verifyAttestation(att.Binding, att.BindingSHA, att.Report, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.receiptKey, pub) {
		t.Fatalf("receipt key %x, want %x", res.receiptKey, pub)
	}
	_ = json.Unmarshal(snpAttestation(t, attestOpts{}), &att)
	empty, err := verifyAttestation(att.Binding, att.BindingSHA, att.Report, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.receiptKey) != 0 {
		t.Fatalf("placeholder receipt key was kept: %x", empty.receiptKey)
	}
}

func TestUnhealthyOrExpiredHotelLeavesPlacementAndComesBack(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	m := joinMiner(t, tc, "m1", true, 5, nil)
	onM1 := map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}}
	tc.room(t, "key1", onM1)
	h := tc.b.hotelByID("m1")
	goDown := func() {
		m.setHealthFail(true)
		tc.b.mu.Lock()
		h.lastOK = time.Now().Add(-time.Minute)
		tc.b.mu.Unlock()
		h.lastAnswer.Store(0)
		syncNow(tc, "m1")
	}

	// Health fails: out of placement, attestation cleared.
	goDown()
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", onM1)
	if status != 503 || errCode(doc) != "hotels_unavailable" || reasonOf(doc)["down"] != float64(1) {
		t.Fatalf("create on down hotel: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	cleared := h.adm.attestedAt.IsZero()
	tc.b.mu.Unlock()
	if !cleared {
		t.Fatalf("a down hotel kept its attestation pass")
	}
	// Health back: one sync step checks attestation again and admits.
	m.setHealthFail(false)
	syncNow(tc, "m1")
	if id := tc.room(t, "key1", onM1); !strings.HasPrefix(id, "m1.") {
		t.Fatalf("after return: %s", id)
	}

	// The pass runs out: out of placement until a check passes again.
	tc.b.mu.Lock()
	h.adm.attestedAt = time.Now().Add(-tc.b.attestTTL() - time.Second)
	tc.b.mu.Unlock()
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", onM1); status != 503 || errCode(doc) != "hotels_not_admitted" {
		t.Fatalf("expired: %d %v", status, doc)
	}
	// The hotel rebooted into a debug build: the check refuses it.
	m.setAttestation(snpAttestation(t, attestOpts{debugCmdline: true}))
	tc.b.mu.Lock()
	h.adm.checkedAt = time.Time{}
	tc.b.mu.Unlock()
	syncNow(tc, "m1")
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", onM1); status != 503 {
		t.Fatalf("refused hotel took a room: %d", status)
	}
	m.setAttestation(snpAttestation(t, attestOpts{}))
	admitNow(t, tc, "m1")
	if id := tc.room(t, "key1", onM1); !strings.HasPrefix(id, "m1.") {
		t.Fatalf("after a new pass: %s", id)
	}

	// An unsealed joined hotel needs health only, and leaves and returns with it.
	u := joinMiner(t, tc, "u1", false, 5, nil)
	onU1 := map[string]any{"image": "alpine:3.20", "hotels": []string{"u1"}}
	tc.room(t, "key1", onU1)
	u.setHealthFail(true)
	hu := tc.b.hotelByID("u1")
	tc.b.mu.Lock()
	hu.lastOK = time.Now().Add(-time.Minute)
	tc.b.mu.Unlock()
	hu.lastAnswer.Store(0)
	syncNow(tc, "u1")
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", onU1); status != 503 {
		t.Fatalf("down unsealed hotel took a room: %d", status)
	}
	u.setHealthFail(false)
	syncNow(tc, "u1")
	if id := tc.room(t, "key1", onU1); !strings.HasPrefix(id, "u1.") {
		t.Fatalf("unsealed after return: %s", id)
	}
}

// ---------------------------------------------------------------- spill and reasons

var sealedFirst = map[string]any{
	"prefer": []any{map[string]any{"class": "sealed"}},
	"allow":  []any{map[string]any{"class": "unsealed"}},
}

func TestSpillFromJoinedSealedToUnsealedAndClearReasons(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	setPolicy(t, tc, "g1", sealedFirst)
	setHotel(tc, "a", func(h *hotel) { h.slots = 1 }) // config sealed (label)
	setHotel(tc, "b", func(h *hotel) { h.slots = 1 })
	setHotel(tc, "c", func(h *hotel) { h.slots = 1 })
	joinMiner(t, tc, "m1", true, 1, nil)
	joinMiner(t, tc, "m2", true, 1, nil)
	// A sealed miner hotel that has not passed admission: never a candidate.
	pm, url := newMinerHotel(t, 10, nil)
	tc.hotels["m3"] = pm.fakeHotel
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "m3", "api": url, "key": joinKey, "sealed": true, "verify": false}); status != 201 {
		t.Fatalf("join m3: %d %v", status, doc)
	}
	syncNow(tc, "m3")

	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		h, tier, _ := createdOn(t, tc, plain)
		if tier != "prefer" || seen[h] || (h != "a" && h != "m1" && h != "m2") {
			t.Fatalf("sealed create %d: %s %s", i, h, tier)
		}
		seen[h] = true
	}
	// Every sealed room is taken: spill to the allowed class.
	for i := 0; i < 2; i++ {
		h, tier, _ := createdOn(t, tc, plain)
		if tier != "allow" || (h != "b" && h != "c") {
			t.Fatalf("spill create %d: %s %s", i, h, tier)
		}
	}
	if n := creates(tc, "m3"); n != 0 {
		t.Fatalf("pending hotel got %d creates", n)
	}
	// Nothing fits: 503 with the count of each state (5 full, 1 not admitted).
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", plain)
	r := reasonOf(doc)
	if status != 503 || errCode(doc) != "hotels_unavailable" || r["full"] != float64(5) || r["pending_admission"] != float64(1) || r["matching"] != float64(6) {
		t.Fatalf("full and pending: %d %v", status, doc)
	}
	// The pending hotel leaves: only full hotels match, which stays the
	// retryable 429 it was before slice 2.
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/m3", nil); status != 204 {
		t.Fatalf("leave m3: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", plain)
	if r := reasonOf(doc); status != 429 || errCode(doc) != "no_free_rooms" || r["full"] != float64(5) || r["matching"] != float64(5) {
		t.Fatalf("all full: %d %v", status, doc)
	}
	// Every hotel down: 503 with the reason.
	for _, id := range []string{"a", "b", "c", "m1", "m2"} {
		setHotel(tc, id, func(h *hotel) { h.ok = false })
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", plain)
	if status != 503 || errCode(doc) != "hotels_unavailable" || reasonOf(doc)["down"] != float64(5) {
		t.Fatalf("all down: %d %v", status, doc)
	}
}

// ---------------------------------------------------------------- isolation

func TestMinerHotelIsolationDenyAndReserve(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 10, nil)
	joinMiner(t, tc, "m2", false, 10, nil)
	// g2 denies miner hotels. Its only other hotels are draining: a miner
	// hotel is the only free room, and it must still not get g2's create.
	setPolicy(t, tc, "g2", map[string]any{
		"prefer": []any{map[string]any{"class": "sealed"}},
		"allow":  []any{map[string]any{"class": "unsealed"}},
		"deny":   []any{map[string]any{"label": map[string]string{"miner": "true"}}},
	})
	for _, id := range []string{"a", "b", "c"} {
		if status, _ := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/"+id, map[string]any{"drain": true}); status != 200 {
			t.Fatalf("drain %s", id)
		}
	}
	for i := 0; i < 5; i++ {
		if status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", plain); status != 503 {
			t.Fatalf("g2 create with only miner hotels free: %d %v", status, doc)
		}
	}
	if status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}}); status != 409 {
		t.Fatalf("g2 named a denied miner hotel: %d %v", status, doc)
	}
	// Relabeling cannot drop the miner label.
	tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"labels": map[string]string{"zone": "x"}})
	if status, _ := tc.call(t, "key2", "POST", "/v1/sandboxes", plain); status != 503 {
		t.Fatalf("g2 reached a relabeled miner hotel: %d", status)
	}
	_, cat := tc.call(t, "key2", "GET", "/v1/broker/capacity", nil)
	if listed(cat, "m1") || listed(cat, "m2") {
		t.Fatalf("g2 catalog lists a denied miner hotel: %v", cat)
	}

	// A miner hotel reserved for g1: g2 never gets it, even with no deny.
	reserve(t, tc, "m1", "g1")
	setPolicy(t, tc, "g2", sealedFirst)
	for i := 0; i < 5; i++ {
		if h, _, _ := createdOn2(t, tc, plain); h == "m1" {
			t.Fatalf("g2 placed on a hotel reserved for g1")
		}
	}
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}}); !strings.HasPrefix(id, "m1.") {
		t.Fatalf("owner on reserved miner hotel: %s", id)
	}
	if n := creates(tc, "m1"); n != 1 {
		t.Fatalf("m1 got %d creates, want 1 (the owner's)", n)
	}

	// A guest with a fixed hotel list (const's shape) never reaches a joined hotel.
	if status, _ := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/b", map[string]any{"drain": false}); status != 200 {
		t.Fatal("undrain b")
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"policy": nil, "hotels": []string{"b"}}); status != 200 {
		t.Fatalf("g1 hotel list: %d %v", status, doc)
	}
	for i := 0; i < 5; i++ {
		if id := tc.room(t, "key1", plain); !strings.HasPrefix(id, "b.") {
			t.Fatalf("listed guest placed on %s", id)
		}
	}
	_, cat = tc.call(t, "key1", "GET", "/v1/broker/capacity", nil)
	if listed(cat, "m2") {
		t.Fatalf("listed guest sees a joined hotel")
	}
}

// createdOn2 is createdOn for guest g2; "" when the create was refused.
func createdOn2(t *testing.T, tc *testChain, body map[string]any) (string, string, int) {
	t.Helper()
	status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", body)
	if status != 202 {
		return "", "", status
	}
	h, _ := doc["hotel"].(string)
	tr, _ := doc["placement_tier"].(string)
	return h, tr, status
}

// ---------------------------------------------------------------- catalog

func TestCapacityClassTotalsIncludeJoinedHotels(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 7, nil)
	joinMiner(t, tc, "m2", false, 4, nil)
	pm, url := newMinerHotel(t, 9, nil)
	tc.hotels["m3"] = pm.fakeHotel
	tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "m3", "api": url, "key": joinKey, "sealed": true, "verify": false, "miner_hotkey": minerHotkey})
	syncNow(tc, "m3")
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	classes, _ := doc["classes"].(map[string]any)
	sealed, _ := classes["sealed"].(map[string]any)
	unsealed, _ := classes["unsealed"].(map[string]any)
	// Config: a sealed (100 slots), b and c unsealed (100 each).
	if status != 200 || sealed["hotels"] != float64(3) || sealed["joined"] != float64(2) || sealed["pending_admission"] != float64(1) ||
		sealed["placeable"] != float64(2) || sealed["free_rooms"] != float64(107) || sealed["slots"] != float64(116) {
		t.Fatalf("sealed totals: %d %v", status, sealed)
	}
	if unsealed["hotels"] != float64(3) || unsealed["joined"] != float64(1) || unsealed["free_rooms"] != float64(204) {
		t.Fatalf("unsealed totals: %v", unsealed)
	}
	if e, _ := catalogEntry(doc, "m1"); e["source"] != "join" {
		t.Fatalf("m1 source: %v", e)
	}
	if e, _ := catalogEntry(doc, "a"); e["source"] != "broker" {
		t.Fatalf("a source: %v", e)
	}
	// A guest sees totals of what it can reach only.
	setPolicy(t, tc, "g2", map[string]any{"prefer": []any{map[string]any{"class": "sealed"}}, "deny": []any{map[string]any{"label": map[string]string{"miner": "true"}}}})
	_, doc = tc.call(t, "key2", "GET", "/v1/broker/capacity", nil)
	classes, _ = doc["classes"].(map[string]any)
	sealed, _ = classes["sealed"].(map[string]any)
	unsealed, _ = classes["unsealed"].(map[string]any)
	if sealed["hotels"] != float64(1) || sealed["free_rooms"] != float64(100) || unsealed["hotels"] != float64(0) {
		t.Fatalf("guest totals: %v", classes)
	}
}

// A create that queued for a hotel's slot while the hotel was admitted must
// not start there after the hotel lost admission (Codex P1 on #340).
func TestQueuedCreateDoesNotStartOnAHotelThatLostAdmission(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	m := joinMiner(t, tc, "m1", true, 5, nil)
	m.mu.Lock()
	m.createDelay = 500 * time.Millisecond
	m.mu.Unlock()
	h := tc.b.hotelByID("m1")
	setHotel(tc, "m1", func(h *hotel) { h.sem = make(chan struct{}, 1) }) // one create at a time
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
	// The hotel's next attestation check fails while the second create waits.
	tc.b.mu.Lock()
	tc.b.noteAttestation(h, admission{}, errDebugBuild, time.Now())
	tc.b.mu.Unlock()
	if a := <-first; a.status != 202 {
		t.Fatalf("first create: %d %v", a.status, a.doc)
	}
	a := <-second
	if a.status != 503 || errCode(a.doc) != "hotels_not_admitted" {
		t.Fatalf("queued create after admission was lost: %d %v", a.status, a.doc)
	}
	if n := creates(tc, "m1"); n != 1 {
		t.Fatalf("hotel m1 started %d rooms, want 1 (none after admission was lost)", n)
	}
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	if h.queued != 0 || len(h.sem) != 0 {
		t.Fatalf("slot or queue count leaked: queued %d, slots held %d", h.queued, len(h.sem))
	}
}

var errDebugBuild = errors.New("debug build: the host can log in to this guest")

// ---------------------------------------------------------------- fake AMD chain verifier

const testARKPin = "1111111111111111111111111111111111111111111111111111111111111111"

const amdPass = `{"verdict": "PASS", "attestation": {"amd": {"product": "Genoa", "ark_sha256": "` + testARKPin + `"}}}`

// fakeAMDVerifier is a stand-in for verify_receipts.py: it prints the
// verdict in verdict.json and logs its arguments to calls.log.
func fakeAMDVerifier(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nd=$(dirname \"$0\")\necho \"$@\" >> \"$d/calls.log\"\ncat \"$d/verdict.json\"\n"
	if err := os.WriteFile(filepath.Join(dir, "verify.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	setAMDVerdict(t, dir, amdPass)
	return dir
}

func setAMDVerdict(t *testing.T, dir, verdict string) {
	t.Helper()
	tmp := filepath.Join(dir, "verdict.json.tmp")
	if err := os.WriteFile(tmp, []byte(verdict), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "verdict.json")); err != nil {
		t.Fatal(err)
	}
}

// amdCalls is the argument lines the fake verifier was run with.
func amdCalls(dir string) []string {
	raw, _ := os.ReadFile(filepath.Join(dir, "calls.log"))
	return strings.FieldsFunc(string(raw), func(r rune) bool { return r == '\n' })
}
