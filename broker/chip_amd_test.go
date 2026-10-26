package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// One hotel per chip, and the AMD chain check on sealed admission.

func bothAdmitted(tc *testChain, a, b string) bool {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	now := time.Now()
	ha, hb := tc.b.hotelByID(a), tc.b.hotelByID(b)
	return ha != nil && hb != nil && tc.b.admissibleFree(ha, now) > 0 && tc.b.admissibleFree(hb, now) > 0
}

func recheck(t *testing.T, tc *testChain, id string) {
	t.Helper()
	h := tc.b.hotelByID(id)
	tc.b.mu.Lock()
	h.adm.checkedAt = time.Time{}
	tc.b.mu.Unlock()
	tc.b.syncAdmission(context.Background(), h, true)
}

func TestOneHotelPerChip(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	sameChip := attestOpts{chip: 7}
	m1, url1 := newMinerHotel(t, 5, snpAttestation(t, sameChip))
	tc.hotels["m1"] = m1.fakeHotel
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "m1", "api": url1, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey}); status != 201 {
		t.Fatalf("join m1: %d %v", status, doc)
	}
	syncNow(tc, "m1")
	// A second hotel on the same machine: refused at join.
	m2, url2 := newMinerHotel(t, 5, snpAttestation(t, sameChip))
	tc.hotels["m2"] = m2.fakeHotel
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "m2", "api": url2, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey})
	if status != 409 || errCode(doc) != "chip_in_use" || !strings.Contains(fmt.Sprint(doc), "hotel m1") {
		t.Fatalf("second hotel on one chip: %d %v", status, doc)
	}
	if tc.b.hotelByID("m2") != nil {
		t.Fatalf("refused hotel is in the set")
	}
	// Joined without verify, it is held refused with the reason, and gets no room.
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "m2", "api": url2, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey, "verify": false}); status != 201 {
		t.Fatalf("join m2 unverified: %d %v", status, doc)
	}
	syncNow(tc, "m2")
	if a := admissionOf(t, tc, "m2"); a["state"] != "refused" || !strings.Contains(fmt.Sprint(a["reason"]), "already hotel m1") {
		t.Fatalf("m2 admission: %v", a)
	}
	onM2 := map[string]any{"image": "alpine:3.20", "hotels": []string{"m2"}}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", onM2); status != 503 || errCode(doc) != "hotels_not_admitted" {
		t.Fatalf("create on the duplicate: %d %v", status, doc)
	}
	// m1 goes down: m2 may take the chip; m1 back is then the duplicate.
	m1.setHealthFail(true)
	h1 := tc.b.hotelByID("m1")
	tc.b.mu.Lock()
	h1.lastOK = time.Now().Add(-time.Minute)
	tc.b.mu.Unlock()
	h1.lastAnswer.Store(0)
	syncNow(tc, "m1")
	recheck(t, tc, "m2")
	if id := tc.room(t, "key1", onM2); !strings.HasPrefix(id, "m2.") {
		t.Fatalf("m2 after m1 left: %s", id)
	}
	m1.setHealthFail(false)
	syncNow(tc, "m1")
	if bothAdmitted(tc, "m1", "m2") {
		t.Fatalf("two placeable hotels on one chip")
	}
	if a := admissionOf(t, tc, "m1"); a["state"] != "refused" || !strings.Contains(fmt.Sprint(a["reason"]), "already hotel m2") {
		t.Fatalf("m1 back: %v", a)
	}
	if n := creates(tc, "m1"); n != 0 {
		t.Fatalf("m1 got %d creates", n)
	}
	// Another chip is another machine.
	joinMiner(t, tc, "m3", true, 5, nil)
	if !bothAdmitted(tc, "m2", "m3") {
		t.Fatalf("hotels on two chips are not both placeable")
	}
}

func TestConcurrentJoinsOnOneChipAdmitOne(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	const n = 8
	urls := make([]string, n)
	for i := range urls {
		_, urls[i] = newMinerHotel(t, 5, snpAttestation(t, attestOpts{chip: 9}))
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status, _ := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": fmt.Sprintf("c%d", i), "api": urls[i], "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey})
			mu.Lock()
			codes[status]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if codes[201] != 1 || codes[409] != n-1 {
		t.Fatalf("joins on one chip: %v, want one 201", codes)
	}
	placeable := 0
	tc.b.mu.Lock()
	for _, h := range tc.b.hotelList() {
		if h.runtime && !h.leaving && tc.b.admitted(h, time.Now()) {
			placeable++
		}
	}
	tc.b.mu.Unlock()
	if placeable != 1 {
		t.Fatalf("%d admitted hotels on one chip", placeable)
	}
}

func TestAMDChainRequiredForMinerHotels(t *testing.T) {
	// No verifier configured (set before any sync loop runs).
	tc := newChainState(t, t.TempDir())
	tc.b.cfg.AMDVerifier = nil
	_, url := newMinerHotel(t, 5, snpAttestation(t, attestOpts{chip: 1}))
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "m1", "api": url, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey})
	if status != 422 || !strings.Contains(fmt.Sprint(doc), "amd_verifier") {
		t.Fatalf("miner hotel with no chain verifier: %d %v", status, doc)
	}
	// An operator hotel (no miner_hotkey) is not chain-checked without a verifier.
	_, url = newMinerHotel(t, 5, snpAttestation(t, attestOpts{chip: 2}))
	status, doc = tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "op1", "api": url, "key": joinKey, "sealed": true})
	if a, _ := doc["admission"].(map[string]any); status != 201 || a["attested_at"] == nil || a["amd_chain_required"] != false || a["amd_chain"] != nil {
		t.Fatalf("operator hotel: %d %v", status, doc)
	}

	// With the verifier: FAIL refuses with its reason, PASS admits.
	tc = newChainState(t, t.TempDir())
	setAMDVerdict(t, tc.amdDir, `{"verdict": "FAIL", "reason": "report signature does not verify with the VCEK"}`)
	m, url := newMinerHotel(t, 5, snpAttestation(t, attestOpts{chip: 3}))
	tc.hotels["m1"] = m.fakeHotel
	join := map[string]any{"id": "m1", "api": url, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey}
	status, doc = tc.call(t, "operator-key", "POST", "/v1/broker/hotels", join)
	if status != 422 || !strings.Contains(fmt.Sprint(doc), "report signature does not verify") {
		t.Fatalf("chain FAIL: %d %v", status, doc)
	}
	calls := amdCalls(tc.amdDir)
	if len(calls) != 1 || !strings.Contains(calls[0], "--require-sealed") || !strings.Contains(calls[0], "--ark-sha256 "+testARKPin) || !strings.Contains(calls[0], "--attestation ") {
		t.Fatalf("verifier arguments: %v", calls)
	}
	setAMDVerdict(t, tc.amdDir, amdPass)
	status, doc = tc.call(t, "operator-key", "POST", "/v1/broker/hotels", join)
	a, _ := doc["admission"].(map[string]any)
	chain, _ := a["amd_chain"].(map[string]any)
	if status != 201 || a["attested_at"] == nil || a["amd_chain_required"] != true || chain["product"] != "Genoa" {
		t.Fatalf("chain PASS: %d %v", status, doc)
	}
	syncNow(tc, "m1")
	// The chain is checked once per binding: rechecks do not run the verifier.
	before := len(amdCalls(tc.amdDir))
	for i := 0; i < 3; i++ {
		recheck(t, tc, "m1")
	}
	if n := len(amdCalls(tc.amdDir)); n != before {
		t.Fatalf("verifier ran %d more times for one binding", n-before)
	}
	// A new binding (the hotel rebooted into another build) is checked again;
	// a verifier that gives no verdict refuses it.
	setAMDVerdict(t, tc.amdDir, "Traceback: urlopen error")
	m.setAttestation(snpAttestation(t, attestOpts{chip: 3, measurement: 0x22}))
	recheck(t, tc, "m1")
	if n := len(amdCalls(tc.amdDir)); n != before+1 {
		t.Fatalf("verifier runs for a new binding: %d, want 1", n-before)
	}
	if a := admissionOf(t, tc, "m1"); a["state"] != "refused" || !strings.Contains(fmt.Sprint(a["reason"]), "no verdict") {
		t.Fatalf("no verdict: %v", a)
	}
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"m1"}}); status != 503 {
		t.Fatalf("refused hotel took a room: %d", status)
	}
	setAMDVerdict(t, tc.amdDir, amdPass)
	admitNow(t, tc, "m1")
}

func TestAMDVerifierConfigNeedsAPinnedARK(t *testing.T) {
	for _, c := range []*amdVerifierConfig{
		{Command: nil, ARKSHA256: arkPins{testARKPin}},
		{Command: []string{"python3", "v.py"}},
		{Command: []string{"python3", "v.py"}, ARKSHA256: arkPins{"abc"}},
	} {
		if c.validate() == nil {
			t.Fatalf("config %+v accepted", c)
		}
	}
}

// ---------------------------------------------------------------- the real verifier

// testPython is a Python with the cryptography package, or "" (the test skips).
func testPython(t *testing.T) string {
	if p := os.Getenv("CATHEDRAL_TEST_PYTHON"); p != "" {
		// Asked for (CI): a Python that cannot run the verifier is a failure, not a skip.
		if out, err := exec.Command(p, "-c", "import cryptography").CombinedOutput(); err != nil {
			t.Fatalf("CATHEDRAL_TEST_PYTHON=%s cannot import cryptography: %v %s", p, err, out)
		}
		return p
	}
	for _, p := range []string{"python3"} {
		if p == "" {
			continue
		}
		if exec.Command(p, "-c", "import cryptography").Run() == nil {
			return p
		}
	}
	return ""
}

func rsaPSSCert(t *testing.T, tmpl *x509.Certificate, pub any, parent *x509.Certificate, key *rsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl.SignatureAlgorithm = x509.SHA384WithRSAPSS
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func asn1Int(t *testing.T, v int) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRealVerifierChecksTheAMDChain runs room-kit/verify_receipts.py itself,
// offline: a test ARK, ASK and VCEK in its KDS cache, a report signed by the
// VCEK. It skips when no Python with cryptography is installed.
func TestRealVerifierChecksTheAMDChain(t *testing.T) {
	py := testPython(t)
	if py == "" {
		t.Skip("no python3 with the cryptography package (set CATHEDRAL_TEST_PYTHON)")
	}
	verifier, _ := filepath.Abs("../room-kit/verify_receipts.py")
	cache := t.TempDir()
	arkKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	askKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	vcekKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := time.Now()
	arkTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ARK-Genoa"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ark := rsaPSSCert(t, arkTmpl, &arkKey.PublicKey, arkTmpl, arkKey) // self-signed
	ask := rsaPSSCert(t, &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "SEV-Genoa"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, &askKey.PublicKey, ark, arkKey)

	// The report: Genoa (family 0x19, model 0x11), TCB SPLs 3/0/.../8/115.
	rep := make([]byte, 0x4A0)
	binary.LittleEndian.PutUint32(rep[0:4], 3)
	binary.LittleEndian.PutUint64(rep[0x08:0x10], 0x30000)
	binary.LittleEndian.PutUint32(rep[0x34:0x38], 1)
	for i := 0x90; i < 0xC0; i++ {
		rep[i] = 0xab
	}
	for i := 0xC0; i < 0xE0; i++ {
		rep[i] = 0x55
	}
	tcb := []byte{3, 0, 0, 0, 0, 0, 8, 115}
	copy(rep[0x180:0x188], tcb)
	rep[0x188], rep[0x189] = 0x19, 0x11
	for i := 0x1A0; i < 0x1E0; i++ {
		rep[i] = byte(i * 7)
	}
	chip := rep[0x1A0:0x1E0]
	vcek := rsaPSSCert(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "SEV-VCEK"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 4}, Value: append([]byte{}, chip...)},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 1}, Value: asn1Int(t, int(tcb[0]))},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 2}, Value: asn1Int(t, int(tcb[1]))},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 3}, Value: asn1Int(t, int(tcb[6]))},
			{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3704, 1, 3, 8}, Value: asn1Int(t, int(tcb[7]))},
		}}, &vcekKey.PublicKey, ask, askKey)
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ask.Raw}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ark.Raw})...)
	_ = os.WriteFile(filepath.Join(cache, "Genoa-cert_chain.pem"), chainPEM, 0o600)
	_ = os.WriteFile(filepath.Join(cache, "vcek-"+hex.EncodeToString(chip)[:16]+"-"+hex.EncodeToString(tcb)+".der"), vcek.Raw, 0o600)
	arkSum := sha256.Sum256(ark.Raw)

	receiptKey, _, _ := ed25519.GenerateKey(rand.Reader)
	binding := map[string]any{
		"schema": "cathedral.room-binding.v1", "hotel": "miner", "boot_id": "b-1", "created_at": 1,
		"receipt_key_ed25519_b64": base64.StdEncoding.EncodeToString(receiptKey), "measurement": hex.EncodeToString(rep[0x90:0xC0]),
		"chip_id": hex.EncodeToString(chip), "reported_tcb": hex.EncodeToString(tcb), "policy": "0x30000",
		"host_data": hex.EncodeToString(rep[0xC0:0xE0]), "kernel_cmdline": "console=ttyS0", "kernel_release": "6.8.0",
		"software": map[string]any{"room_kit": "abc", "cathedral": "def"},
	}
	rawBinding, _ := json.Marshal(binding)
	bsum := sha256.Sum256(rawBinding)
	copy(rep[0x50:0x70], bsum[:])
	sign := func(report []byte) {
		digest := sha512.Sum384(report[:0x2A0])
		r, s, err := ecdsa.Sign(rand.Reader, vcekKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		le := func(v *big.Int) []byte {
			be := v.FillBytes(make([]byte, 72))
			for i, j := 0, len(be)-1; i < j; i, j = i+1, j-1 {
				be[i], be[j] = be[j], be[i]
			}
			return be
		}
		copy(report[0x2A0:0x2E8], le(r))
		copy(report[0x2E8:0x330], le(s))
	}
	sign(rep)
	doc := func(report []byte) []byte {
		out, _ := json.Marshal(map[string]any{"binding": json.RawMessage(rawBinding), "binding_sha256": hex.EncodeToString(bsum[:]),
			"report_b64": base64.StdEncoding.EncodeToString(report)})
		return out
	}
	b := &broker{cfg: config{StateDir: t.TempDir(), AMDVerifier: &amdVerifierConfig{Command: []string{py, verifier}, ARKSHA256: arkPins{hex.EncodeToString(arkSum[:])}, KDSCache: cache}}}

	amd, err := b.verifyAMDChain(context.Background(), doc(rep))
	if err != nil || amd["product"] != "Genoa" || amd["ark_sha256"] != hex.EncodeToString(arkSum[:]) {
		t.Fatalf("good chain: %v %v", amd, err)
	}
	// A report the VCEK did not sign.
	bad := append([]byte{}, rep...)
	bad[0x2A0] ^= 1
	if _, err := b.verifyAMDChain(context.Background(), doc(bad)); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("bad signature: %v", err)
	}
	// Another ARK than the pinned one.
	b.cfg.AMDVerifier.ARKSHA256 = arkPins{strings.Repeat("0", 64)}
	if _, err := b.verifyAMDChain(context.Background(), doc(rep)); err == nil || !strings.Contains(err.Error(), "ARK") {
		t.Fatalf("wrong ARK pin: %v", err)
	}
	// A list admits the hotel whose product's ARK is any pin.
	b.cfg.AMDVerifier.ARKSHA256 = arkPins{arkMilan, hex.EncodeToString(arkSum[:]), arkTurin}
	if amd, err := b.verifyAMDChain(context.Background(), doc(rep)); err != nil || amd["ark_sha256"] != hex.EncodeToString(arkSum[:]) {
		t.Fatalf("list with the chain's ARK: %v %v", amd, err)
	}
	// The real AMD roots: the test chain's root is none of them.
	b.cfg.AMDVerifier.ARKSHA256 = arkPins{arkMilan, arkGenoa, arkTurin}
	if _, err := b.verifyAMDChain(context.Background(), doc(rep)); err == nil || !strings.Contains(err.Error(), "ARK") {
		t.Fatalf("wrong-root chain against a list: %v", err)
	}
	// A list does not hide another failure: a bad signature still fails.
	b.cfg.AMDVerifier.ARKSHA256 = arkPins{arkMilan, hex.EncodeToString(arkSum[:])}
	if _, err := b.verifyAMDChain(context.Background(), doc(bad)); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("bad signature with a list: %v", err)
	}
}
