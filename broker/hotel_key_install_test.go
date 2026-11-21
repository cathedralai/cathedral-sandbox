package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// AB#817: a "guest_tls" config hotel whose guest takes its hotel key only by
// install. The fake guest below follows room_receipts.py: the install key
// statement signed by the receipt key, POST /room/hotel-key checked field by
// field, and no keyed call answered before an install.

type installGuest struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex

	hotel   string
	signers []string // install signers the binding pins (public keys, base64)
	cert    tls.Certificate
	leaf    *x509.Certificate
	receipt ed25519.PrivateKey
	install *ecdh.PrivateKey
	att     []byte
	bsha    string

	key        string // installed hotel key; "" none
	lastIssued int64
	lastReq    string

	refuse     string // non-empty: POST /room/hotel-key answers this code
	dropAnswer bool   // install, then drop the connection before answering
	posts      int
	bearerSeen int // keyed calls before an install
}

func newInstallGuest(t *testing.T, hotel string, signers ...string) *installGuest {
	t.Helper()
	g := &installGuest{t: t, hotel: hotel, signers: signers}
	g.boot()
	g.srv = httptest.NewUnstartedServer(g)
	g.srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		g.mu.Lock()
		defer g.mu.Unlock()
		return &tls.Config{Certificates: []tls.Certificate{g.cert}}, nil
	}}
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	return g
}

// boot is a new guest boot: new TLS, receipt and install keys, no hotel key.
func (g *installGuest) boot() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		g.t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		g.t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	rpub, rpriv, _ := ed25519.GenerateKey(rand.Reader)
	inst, _ := ecdh.X25519().GenerateKey(rand.Reader)
	raw := snpAttestation(g.t, attestOpts{chip: 41, receiptKey: rpub})
	raw = testAttestationWithTLSPin(g.t, raw, leaf)
	signers := append([]string{}, g.signers...)
	raw = rebindAttestation(g.t, raw, func(b map[string]any) {
		b["hotel"] = g.hotel
		b["hotel_key_install_x25519_b64"] = base64.StdEncoding.EncodeToString(inst.PublicKey().Bytes())
		b["hotel_key_install_signers_ed25519_b64"] = signers
	})
	var doc struct {
		BindingSHA string `json:"binding_sha256"`
	}
	_ = json.Unmarshal(raw, &doc)
	g.mu.Lock()
	g.cert, g.leaf, g.receipt, g.install, g.att, g.bsha = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, leaf, rpriv, inst, raw, doc.BindingSHA
	g.key, g.lastIssued, g.lastReq = "", -1, ""
	g.mu.Unlock()
	if g.srv != nil {
		g.srv.CloseClientConnections()
	}
}

func (g *installGuest) installed() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.key
}

func (g *installGuest) refuseErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": strings.ReplaceAll(code, "_", " ")}})
}

func (g *installGuest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch r.URL.Path {
	case "/room/attestation":
		_, _ = w.Write(g.att)
		return
	case "/room/hotel-key-install-key":
		st := map[string]string{"algorithm": plantAlgorithm, "binding_sha256": g.bsha, "purpose": installPurpose,
			"x25519_public_b64": base64.StdEncoding.EncodeToString(g.install.PublicKey().Bytes())}
		msg, _ := canonicalJSON(st)
		st["signature_b64"] = base64.StdEncoding.EncodeToString(ed25519.Sign(g.receipt, msg))
		writeJSON(w, 200, st)
		return
	case "/room/hotel-key":
		g.posts++
		g.serveInstall(w, r)
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if g.key == "" || got != g.key {
		if g.key == "" && got != "" {
			g.bearerSeen++
		}
		writeJSON(w, 401, map[string]any{"error": "unauthorized"})
		return
	}
	switch r.URL.Path {
	case "/room/health":
		writeJSON(w, 200, map[string]any{"slots": 4})
	case "/v1/quota":
		writeJSON(w, 200, map[string]any{"usage": map[string]float64{}})
	case "/v1/sandboxes":
		writeJSON(w, 200, map[string]any{"sandboxes": []any{}})
	default:
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

// serveInstall is room_receipts.Ledger.install_hotel_key. Caller holds g.mu.
func (g *installGuest) serveInstall(w http.ResponseWriter, r *http.Request) {
	var doc map[string]any
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	if dec.Decode(&doc) != nil || len(doc) != 7 || doc["schema"] != installSchema {
		g.refuseErr(w, 400, "install_fields_invalid")
		return
	}
	sig, _ := base64.StdEncoding.DecodeString(doc["signature_b64"].(string))
	body := map[string]any{}
	for k, v := range doc {
		if k != "signature_b64" {
			body[k] = v
		}
	}
	msg, _ := canonicalJSON(body)
	signed := false
	for _, s := range g.signers {
		pub, _ := base64.StdEncoding.DecodeString(s)
		signed = signed || (len(sig) == 64 && ed25519.Verify(pub, msg, sig))
	}
	if !signed {
		g.refuseErr(w, 403, "install_signature_invalid")
		return
	}
	if doc["binding_sha256"] != g.bsha {
		g.refuseErr(w, 409, "install_wrong_binding")
		return
	}
	issued, err := doc["issued_at"].(json.Number).Int64()
	now := time.Now().Unix()
	if err != nil || issued < now-900 || issued > now+300 {
		g.refuseErr(w, 409, "install_not_fresh")
		return
	}
	if g.refuse != "" {
		g.refuseErr(w, 409, g.refuse)
		return
	}
	full, _ := canonicalJSON(doc)
	reqSHA := hex.EncodeToString(sha256Sum(full))
	answer := func(status string) {
		writeJSON(w, 200, map[string]any{"key_sha256": doc["key_sha256"], "hotel_id": doc["hotel_id"], "issued_at": issued, "status": status})
	}
	if reqSHA == g.lastReq {
		answer("unchanged")
		return
	}
	if issued <= g.lastIssued {
		g.refuseErr(w, 409, "install_replayed")
		return
	}
	env := map[string]string{}
	for k, v := range doc["envelope"].(map[string]any) {
		env[k], _ = v.(string)
	}
	plain, err := openInstallEnvelope(env, g.install, "hotel-key-install:"+g.bsha)
	if err != nil {
		g.refuseErr(w, 400, "install_envelope_does_not_open")
		return
	}
	if hex.EncodeToString(sha256Sum(plain)) != doc["key_sha256"] {
		g.refuseErr(w, 400, "install_key_digest_mismatch")
		return
	}
	g.key, g.lastIssued, g.lastReq = string(plain), issued, reqSHA
	if g.dropAnswer {
		g.dropAnswer = false
		if hj, ok := w.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				_ = c.Close()
				return
			}
		}
	}
	answer("installed")
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func openInstallEnvelope(env map[string]string, private *ecdh.PrivateKey, aad string) ([]byte, error) {
	rawEph, err := base64.StdEncoding.DecodeString(env["ephemeral_public_b64"])
	if err != nil {
		return nil, err
	}
	n, _ := base64.StdEncoding.DecodeString(env["nonce_b64"])
	ct, _ := base64.StdEncoding.DecodeString(env["ciphertext_b64"])
	eph, err := ecdh.X25519().NewPublicKey(rawEph)
	if err != nil {
		return nil, err
	}
	shared, err := private.ECDH(eph)
	if err != nil {
		return nil, err
	}
	info := append(append(append([]byte{}, installHKDFInfo...), rawEph...), private.PublicKey().Bytes()...)
	key := hkdfSHA256(shared, []byte(aad), info, 32)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead.Open(nil, n, ct, []byte(aad))
}

const installHotelKeyValue = "config-hotel-key-0123456789abcdefABCDEF_-"

// installSeedFile writes a signer seed file and returns its path and public key.
func installSeedFile(t *testing.T, mode os.FileMode) (string, string, string) {
	t.Helper()
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	seedB64 := base64.StdEncoding.EncodeToString(seed)
	path := filepath.Join(t.TempDir(), "install.seed")
	if err := os.WriteFile(path, []byte(seedB64+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path, installSignerPublicB64(ed25519.NewKeyFromSeed(seed)), seedB64
}

func installHotel(t *testing.T, tc *testChain, signerFile string, g *installGuest) *hotel {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "ct.key")
	if err := os.WriteFile(keyFile, []byte(installHotelKeyValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := startWithHotels(t, tc, false, hotelConfig{ID: g.hotel, Name: g.hotel, API: g.srv.URL, Health: g.srv.URL,
		KeyFile: keyFile, Sealed: true, GuestTLS: true, HotelKeyInstallSigningKeyFile: signerFile}); err != nil {
		t.Fatal(err)
	}
	h := tc.b.hotelByID(g.hotel)
	if h == nil || h.installer == nil {
		t.Fatal("config hotel with an installer not loaded")
	}
	return h
}

func captureLogs(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func isAdmitted(tc *testChain, h *hotel) bool {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	return tc.b.admitted(h, time.Now())
}

func installErr(tc *testChain, h *hotel) string {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	return h.keyInst.err
}

func TestConfigHotelKeyInstalledOnFirstPinAndAfterEachReboot(t *testing.T) {
	logs := captureLogs(t)
	signerFile, signer, seedB64 := installSeedFile(t, 0o600)
	tc := newChainState(t, t.TempDir())
	g := newInstallGuest(t, "ct", signer)
	h := installHotel(t, tc, signerFile, g)
	ctx := context.Background()
	if isAdmitted(tc, h) {
		t.Fatal("admitted before a pin and an install")
	}

	tc.b.syncHotel(ctx, h)
	if h.pinHex() == "" || g.installed() != installHotelKeyValue {
		t.Fatalf("first sync: pin %q, guest key installed %t", h.pinHex(), g.installed() == installHotelKeyValue)
	}
	tc.b.syncHotel(ctx, h) // health now answers with the installed key
	if !isAdmitted(tc, h) {
		t.Fatalf("installed hotel not admitted: %s", h.adm.reason)
	}
	if g.bearerSeen != 0 {
		t.Fatalf("%d keyed calls reached the guest before the install", g.bearerSeen)
	}
	tc.b.mu.Lock()
	doc := tc.b.admissionDoc(h, time.Now())
	tc.b.mu.Unlock()
	inst, _ := doc["hotel_key_install"].(map[string]any)
	if inst["installed"] != true || inst["signer_ed25519_b64"] != signer {
		t.Fatalf("admission doc install part: %v", inst)
	}

	// A reboot: new keys, no hotel key in the guest. The broker re-pins and installs again.
	first := h.pinHex()
	g.boot()
	expirePin(tc, h)
	tc.b.syncHotel(ctx, h)
	if h.pinHex() == first || g.installed() != installHotelKeyValue {
		t.Fatalf("after reboot: pin moved %t, key installed %t", h.pinHex() != first, g.installed() == installHotelKeyValue)
	}
	tc.b.syncHotel(ctx, h)
	if !isAdmitted(tc, h) {
		t.Fatal("re-installed hotel not admitted")
	}

	sum := sha256.Sum256([]byte(installHotelKeyValue))
	for _, secret := range []string{installHotelKeyValue, seedB64, hex.EncodeToString(sum[:])} {
		if strings.Contains(logs.String(), secret) {
			t.Fatal("a log line names the hotel key, its full digest or the signer seed")
		}
	}
	if !strings.Contains(logs.String(), "installed in the guest") {
		t.Fatalf("no install log line: %s", logs.String())
	}
}

func TestConfigHotelKeyInstallRetriesALostAnswer(t *testing.T) {
	signerFile, signer, _ := installSeedFile(t, 0o600)
	tc := newChainState(t, t.TempDir())
	g := newInstallGuest(t, "ct", signer)
	h := installHotel(t, tc, signerFile, g)
	ctx := context.Background()
	g.mu.Lock()
	g.dropAnswer = true
	g.mu.Unlock()
	tc.b.syncHotel(ctx, h)
	if g.installed() == "" {
		t.Fatal("the guest did not take the first install")
	}
	if isAdmitted(tc, h) || installErr(tc, h) == "" {
		t.Fatalf("lost answer: admitted %t, err %q", isAdmitted(tc, h), installErr(tc, h))
	}
	expirePin(tc, h)
	tc.b.syncHotel(ctx, h)
	tc.b.syncHotel(ctx, h)
	if !isAdmitted(tc, h) || installErr(tc, h) != "" || g.posts != 2 {
		t.Fatalf("retry: admitted %t, err %q, posts %d", isAdmitted(tc, h), installErr(tc, h), g.posts)
	}
}

func TestConfigHotelKeyInstallRefusalsKeepTheHotelOut(t *testing.T) {
	ctx := context.Background()

	// The guest pins another signer (a kit built for another broker host): nothing is posted.
	signerFile, _, _ := installSeedFile(t, 0o600)
	_, other, _ := installSeedFile(t, 0o600)
	tc := newChainState(t, t.TempDir())
	g := newInstallGuest(t, "ct", other)
	h := installHotel(t, tc, signerFile, g)
	tc.b.syncHotel(ctx, h)
	tc.b.syncHotel(ctx, h)
	if isAdmitted(tc, h) || installErr(tc, h) != "install_signer_not_in_binding" || g.posts != 0 || g.installed() != "" {
		t.Fatalf("other signer: admitted %t err %q posts %d", isAdmitted(tc, h), installErr(tc, h), g.posts)
	}

	// The guest refuses: the code is kept, the hotel stays out, and a later retry lands.
	signerFile, signer, _ := installSeedFile(t, 0o600)
	tc = newChainState(t, t.TempDir())
	g = newInstallGuest(t, "ct", signer)
	g.refuse = "install_not_fresh"
	h = installHotel(t, tc, signerFile, g)
	tc.b.syncHotel(ctx, h)
	if isAdmitted(tc, h) || installErr(tc, h) != "install_not_fresh" {
		t.Fatalf("refused: admitted %t err %q", isAdmitted(tc, h), installErr(tc, h))
	}
	g.mu.Lock()
	g.refuse = ""
	g.mu.Unlock()
	tc.b.syncHotel(ctx, h) // not due yet: no retry inside the recheck interval
	if g.posts != 1 {
		t.Fatalf("retried inside the recheck interval: %d posts", g.posts)
	}
	expirePin(tc, h)
	tc.b.syncHotel(ctx, h)
	tc.b.syncHotel(ctx, h)
	if !isAdmitted(tc, h) {
		t.Fatalf("retry after the refusal cleared: err %q", installErr(tc, h))
	}

	// A guest whose install key statement is not signed by its receipt key is refused before any post.
	tc = newChainState(t, t.TempDir())
	g = newInstallGuest(t, "ct", signer)
	h = installHotel(t, tc, signerFile, g)
	g.mu.Lock()
	_, g.receipt, _ = ed25519.GenerateKey(rand.Reader)
	g.mu.Unlock()
	tc.b.syncHotel(ctx, h)
	if installErr(tc, h) != "install_key_signature_invalid" || g.posts != 0 {
		t.Fatalf("forged install key: err %q posts %d", installErr(tc, h), g.posts)
	}
}

func TestConfigHotelKeyInstallLoadRules(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	keyFile := filepath.Join(t.TempDir(), "k.key")
	_ = os.WriteFile(keyFile, []byte(installHotelKeyValue), 0o600)
	good, _, _ := installSeedFile(t, 0o600)
	open, _, _ := installSeedFile(t, 0o644)
	bad := filepath.Join(t.TempDir(), "bad.seed")
	_ = os.WriteFile(bad, []byte("bm90IGEgc2VlZA==\n"), 0o600)
	for name, hc := range map[string]hotelConfig{
		"without guest_tls": {ID: "x", API: "https://127.0.0.1:1", Health: "https://127.0.0.1:1", KeyFile: keyFile, Sealed: true, HotelKeyInstallSigningKeyFile: good},
		"group readable":    {ID: "x", API: "https://127.0.0.1:1", Health: "https://127.0.0.1:1", KeyFile: keyFile, Sealed: true, GuestTLS: true, HotelKeyInstallSigningKeyFile: open},
		"not a seed":        {ID: "x", API: "https://127.0.0.1:1", Health: "https://127.0.0.1:1", KeyFile: keyFile, Sealed: true, GuestTLS: true, HotelKeyInstallSigningKeyFile: bad},
		"missing":           {ID: "x", API: "https://127.0.0.1:1", Health: "https://127.0.0.1:1", KeyFile: keyFile, Sealed: true, GuestTLS: true, HotelKeyInstallSigningKeyFile: bad + ".none"},
	} {
		if err := startWithHotels(t, tc, false, hc); err == nil || !strings.Contains(err.Error(), "hotel_key_install_signing_key_file") && !strings.Contains(err.Error(), "install signer") {
			t.Fatalf("%s: loaded (%v)", name, err)
		}
	}
}

// TestHotelKeyInstallRequestOpensInRoomKit hands a request this broker built
// to room_receipts.Ledger.install_hotel_key, the guest's own check. Skipped
// where python3 with cryptography is not installed.
func TestHotelKeyInstallRequestOpensInRoomKit(t *testing.T) {
	kit, _ := filepath.Abs("../room-kit")
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	if exec.Command("python3", "-c", "import cryptography").Run() != nil {
		t.Skip("python3 cryptography not installed")
	}
	signerFile, signer, _ := installSeedFile(t, 0o600)
	tc := newChainState(t, t.TempDir())
	g := newInstallGuest(t, "ct", signer)
	h := installHotel(t, tc, signerFile, g)
	var captured []byte
	g.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/room/hotel-key" {
			captured, _ = readAllLimit(r)
			g.refuseErr(w, 409, "install_replayed")
			return
		}
		g.ServeHTTP(w, r)
	})
	tc.b.syncHotel(context.Background(), h)
	if len(captured) == 0 {
		t.Fatal("no install request was sent")
	}
	g.mu.Lock()
	priv := base64.StdEncoding.EncodeToString(g.install.Bytes())
	bsha := g.bsha
	g.mu.Unlock()
	script := `
import base64, json, sys
sys.path.insert(0, sys.argv[1])
import room_receipts as rr
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
signer = base64.b64decode(sys.argv[2])
mh = rr.MinerHotel("ct", [signer])
mh.install_private = X25519PrivateKey.from_private_bytes(base64.b64decode(sys.argv[3]))
led = rr.Ledger.__new__(rr.Ledger)
led.miner, led.binding_sha256 = mh, sys.argv[4]
led.sign = lambda doc: doc
out, receipt = led.install_hotel_key(json.loads(sys.stdin.read()))
assert out["status"] == "installed", out
assert mh.key == sys.argv[5].encode(), "installed key differs"
print("ok")
`
	cmd := exec.Command("python3", "-I", "-c", script, kit, signer, priv, bsha, installHotelKeyValue)
	cmd.Stdin = bytes.NewReader(captured)
	out, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("room_receipts refused the broker's install request: %v\n%s", err, out)
	}
}

func readAllLimit(r *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(http.MaxBytesReader(nil, r.Body, 64<<10))
	return buf.Bytes(), err
}

func TestHotelDocCountsRoomsInUse(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	h := tc.b.hotelByID("a")
	tc.b.mu.Lock()
	h.queued, h.creating = 2, 1
	tc.b.mu.Unlock()
	if n, _ := tc.b.hotelDoc(h)["rooms_in_use"].(int); n != 3 {
		t.Fatalf("rooms_in_use %v, want 3", tc.b.hotelDoc(h)["rooms_in_use"])
	}
}
