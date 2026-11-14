package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// AB#378: a config sealed hotel with "guest_tls": true is reached only over
// the TLS key its guest names in the attested binding, as a miner hotel is,
// and the broker re-pins it after a reboot only after the full check.

// guestTLSServer is a sealed guest on guest TLS: its certificate can change
// (a reboot makes a new key), it serves its attestation without a key, and it
// records which certificate was showing whenever a request carried a bearer.
type guestTLSServer struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	cert   tls.Certificate
	leaf   *x509.Certificate
	att    []byte
	keyed  map[string]int // SPKI hex of the showing certificate -> keyed requests
	apiKey string
}

func newGuestTLSServer(t *testing.T, apiKey string) *guestTLSServer {
	t.Helper()
	g := &guestTLSServer{t: t, keyed: map[string]int{}, apiKey: apiKey}
	g.rotate()
	g.srv = httptest.NewUnstartedServer(g)
	// GetConfigForClient runs on every handshake (httptest fills Certificates,
	// which GetCertificate alone would not override for an IP address).
	g.srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		g.mu.Lock()
		defer g.mu.Unlock()
		return &tls.Config{Certificates: []tls.Certificate{g.cert}}, nil
	}}
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	return g
}

// rotate makes a new guest TLS key, as a reboot does.
func (g *guestTLSServer) rotate() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		g.t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		g.t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	g.mu.Lock()
	g.cert, g.leaf = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, leaf
	g.mu.Unlock()
	if g.srv != nil {
		// A reboot ends every connection, so a keyed request after this one
		// came over a handshake with the new key.
		g.srv.CloseClientConnections()
	}
}

func (g *guestTLSServer) spki() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	sum := sha256.Sum256(g.leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// attest serves an attestation of o for hotel name, bound to the showing key.
func (g *guestTLSServer) attest(name string, o attestOpts) {
	g.mu.Lock()
	leaf := g.leaf
	g.mu.Unlock()
	raw := rebindAttestation(g.t, snpAttestation(g.t, o), func(b map[string]any) { b["hotel"] = name })
	raw = testAttestationWithTLSPin(g.t, raw, leaf)
	g.mu.Lock()
	g.att = raw
	g.mu.Unlock()
}

func (g *guestTLSServer) keyedOn(spki string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.keyed[spki]
}

func (g *guestTLSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" {
		g.mu.Lock()
		own := sha256.Sum256(g.leaf.RawSubjectPublicKeyInfo)
		g.keyed[hex.EncodeToString(own[:])]++
		g.mu.Unlock()
	}
	if r.URL.Path == "/room/attestation" {
		g.mu.Lock()
		att := g.att
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(att)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+g.apiKey {
		writeJSON(w, 401, map[string]any{"error": "no installed hotel key"})
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

// rebindAttestation changes the binding of an attestation body and keeps
// binding_sha256 and REPORT_DATA consistent with it.
func rebindAttestation(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var doc struct {
		Binding    json.RawMessage `json:"binding"`
		BindingSHA string          `json:"binding_sha256"`
		Report     string          `json:"report_b64"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var binding map[string]any
	if err := json.Unmarshal(doc.Binding, &binding); err != nil {
		t.Fatal(err)
	}
	mutate(binding)
	nb, _ := json.Marshal(binding)
	sum := sha256.Sum256(nb)
	rep, err := base64.StdEncoding.DecodeString(doc.Report)
	if err != nil {
		t.Fatal(err)
	}
	copy(rep[0x50:0x70], sum[:])
	out, _ := json.Marshal(map[string]any{"binding": json.RawMessage(nb), "binding_sha256": hex.EncodeToString(sum[:]),
		"report_b64": base64.StdEncoding.EncodeToString(rep)})
	return out
}

// startWithHotels restarts tc's broker with extra config hotels and top-level
// require_sealed_guest_tls.
func startWithHotels(t *testing.T, tc *testChain, require bool, extra ...hotelConfig) error {
	t.Helper()
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Hotels = append(cfg.Hotels, extra...)
	cfg.RequireSealedGuestTLS = require
	raw, _ = json.Marshal(cfg)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBroker(path); err != nil {
		return err
	}
	tc.cfgPath = path
	tc.start(t)
	return nil
}

const guestTLSKey = "installed-hotel-key-0123456789abcdef"

func guestTLSHotel(t *testing.T, tc *testChain) (*guestTLSServer, *hotel) {
	t.Helper()
	g := newGuestTLSServer(t, guestTLSKey)
	g.attest("gt", attestOpts{chip: 41})
	keyFile := filepath.Join(t.TempDir(), "gt.key")
	if err := os.WriteFile(keyFile, []byte(guestTLSKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := startWithHotels(t, tc, false, hotelConfig{ID: "gt", Name: "gt", API: g.srv.URL, Health: g.srv.URL,
		KeyFile: keyFile, Sealed: true, GuestTLS: true}); err != nil {
		t.Fatal(err)
	}
	h := tc.b.hotelByID("gt")
	if h == nil {
		t.Fatal("guest_tls hotel not loaded")
	}
	return g, h
}

// expire makes the next sync check the guest TLS key again at once.
func expirePin(tc *testChain, h *hotel) {
	tc.b.mu.Lock()
	h.pinCheckedAt, h.lastOK = time.Time{}, time.Time{}
	tc.b.mu.Unlock()
}

func TestConfigGuestTLSHotelSendsNoKeyBeforeItsAttestedPin(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g, h := guestTLSHotel(t, tc)
	ctx := context.Background()
	if h.pinHex() != "" {
		t.Fatal("a config guest_tls hotel started with a pin")
	}
	if _, _, _, err := h.do(ctx, "GET", "/v1/status", nil, nil, time.Second); !errors.Is(err, errGuestPinPending) {
		t.Fatalf("keyed call before the pin: %v", err)
	}
	tc.b.mu.Lock()
	admitted := tc.b.admitted(h, time.Now())
	tc.b.mu.Unlock()
	if admitted || g.keyedOn(g.spki()) != 0 {
		t.Fatalf("unpinned hotel admitted=%t or saw the key %d times", admitted, g.keyedOn(g.spki()))
	}

	tc.b.syncHotel(ctx, h)
	if h.pinHex() != g.spki() {
		t.Fatalf("pin %q, want the attested guest key %q", h.pinHex(), g.spki())
	}
	tc.b.mu.Lock()
	admitted = tc.b.admitted(h, time.Now())
	reason := h.adm.reason
	tc.b.mu.Unlock()
	if !admitted {
		t.Fatalf("pinned guest_tls hotel not admitted: %s", reason)
	}
	if g.keyedOn(g.spki()) == 0 {
		t.Fatal("pinned hotel was never called with its key")
	}

	// Another TLS key at another address, serving the same attestation, never
	// receives the hotel key.
	var impostorSawKey bool
	var imu sync.Mutex
	impostor := newDistinctTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			imu.Lock()
			impostorSawKey = true
			imu.Unlock()
		}
		g.mu.Lock()
		att := g.att
		g.mu.Unlock()
		_, _ = w.Write(att)
	}))
	defer impostor.Close()
	if _, _, _, err := h.doBase(ctx, impostor.URL, "GET", "/v1/status", nil, nil, time.Second); err == nil {
		t.Fatal("data client accepted another TLS key")
	}
	var doc map[string]any
	if err := h.getJSON(ctx, impostor.URL, "/v1/status", nil, &doc); err == nil {
		t.Fatal("control client accepted another TLS key")
	}
	if _, _, _, err := h.doBase(ctx, "http://127.0.0.1:1", "GET", "/v1/status", nil, nil, time.Second); err == nil ||
		!strings.Contains(err.Error(), "attested HTTPS") {
		t.Fatalf("plain HTTP call on a guest_tls hotel: %v", err)
	}
	imu.Lock()
	defer imu.Unlock()
	if impostorSawKey {
		t.Fatal("impostor received the hotel key")
	}
}

func TestConfigGuestTLSHotelRepinsOnlyAVerifiedGuestOfItsOwn(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g, h := guestTLSHotel(t, tc)
	ctx := context.Background()
	tc.b.syncHotel(ctx, h)
	first := h.pinHex()
	if first == "" {
		t.Fatal("no first pin")
	}

	// A reboot: a new guest key. Each bad attestation of it is refused, the
	// pin stays, and the new key never sees the hotel key.
	g.rotate()
	second := g.spki()
	for name, set := range map[string]func(){
		"measurement not allowed": func() { g.attest("gt", attestOpts{chip: 41, measurement: 0x33}) },
		"another hotel's guest":   func() { g.attest("other", attestOpts{chip: 41}) },
		"another chip":            func() { g.attest("gt", attestOpts{chip: 42}) },
		"key from the host": func() {
			g.attest("gt", attestOpts{chip: 41})
			g.mu.Lock()
			g.att = rebindAttestation(t, g.att, func(b map[string]any) { b["hotel_key_source"] = "fw_cfg" })
			g.mu.Unlock()
		},
	} {
		set()
		expirePin(tc, h)
		tc.b.syncHotel(ctx, h)
		if h.pinHex() != first {
			t.Fatalf("%s: pin moved to %q", name, h.pinHex())
		}
		if n := g.keyedOn(second); n != 0 {
			t.Fatalf("%s: the unverified key received the hotel key %d times", name, n)
		}
		tc.b.mu.Lock()
		pinErr := h.pinErr
		tc.b.mu.Unlock()
		if pinErr == "" {
			t.Fatalf("%s: no reason recorded", name)
		}
	}

	// The same hotel's guest, on its chip, with an allowed measurement.
	g.attest("gt", attestOpts{chip: 41})
	expirePin(tc, h)
	tc.b.syncHotel(ctx, h)
	if h.pinHex() != second {
		t.Fatalf("verified new key not pinned: %q", h.pinHex())
	}
	tc.b.mu.Lock()
	admitted := tc.b.admitted(h, time.Now())
	reason := h.adm.reason
	tc.b.mu.Unlock()
	if !admitted || g.keyedOn(second) == 0 {
		t.Fatalf("re-pinned hotel admitted=%t (%s) keyed=%d", admitted, reason, g.keyedOn(second))
	}
}

func TestGuestTLSConfigLoadRules(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	keyFile := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(keyFile, []byte(guestTLSKey), 0o600); err != nil {
		t.Fatal(err)
	}
	ok := hotelConfig{ID: "gt", API: "https://10.0.0.1:18443", Health: "https://10.0.0.1:18443", KeyFile: keyFile, Sealed: true, GuestTLS: true}
	for name, c := range map[string]struct {
		mutate  func(*hotelConfig)
		require bool
		want    string
	}{
		"unsealed":         {func(h *hotelConfig) { h.Sealed = false }, false, `guest_tls needs "sealed": true`},
		"plain api":        {func(h *hotelConfig) { h.API = "http://10.0.0.1:18090" }, false, "https:// api and health"},
		"plain health":     {func(h *hotelConfig) { h.Health = "http://10.0.0.1:18091" }, false, "https:// api and health"},
		"typed pin":        {func(h *hotelConfig) { h.TLSSPKISHA256 = strings.Repeat("ab", 32) }, false, "derived from the hotel's attestation"},
		"admission off":    {func(h *hotelConfig) { h.SealedAdmission = sealedAdmissionOff }, false, "needs the admission gate"},
		"required, no tls": {func(h *hotelConfig) { h.GuestTLS = false; h.API, h.Health = "http://x:1", "http://x:1" }, true, "require_sealed_guest_tls is on"},
	} {
		hc := ok
		c.mutate(&hc)
		if err := startWithHotels(t, tc, c.require, hc); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v, want %q", name, err, c.want)
		}
	}
	if err := startWithHotels(t, tc, true, ok); err != nil {
		t.Fatalf("a guest_tls sealed hotel under require_sealed_guest_tls: %v", err)
	}
}

func TestSealedJoinTakesTheGuestTLSBootstrapWhenRequired(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	tc.b.cfg.RequireSealedGuestTLS = true
	_, plain := newOperatorHotel(t, 1, snpAttestation(t, attestOpts{chip: 50}))
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "plain", "api": plain, "key": guestTLSKey, "sealed": true,
	}); status != 409 || errCode(doc) != "guest_tls_required" {
		t.Fatalf("plain sealed join under require_sealed_guest_tls: %d %v", status, doc)
	}
	g := newGuestTLSServer(t, guestTLSKey)
	g.attest("joined", attestOpts{chip: 51})
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "joined", "api": g.srv.URL, "key": guestTLSKey, "sealed": true,
	}); status != 201 {
		t.Fatalf("guest TLS sealed join: %d %v", status, doc)
	}
	h := tc.b.hotelByID("joined")
	if h == nil || !h.cfg.GuestTLS || h.pinHex() != g.spki() {
		t.Fatalf("joined sealed hotel not on guest TLS: %+v", h)
	}
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "typed", "api": g.srv.URL, "key": guestTLSKey, "sealed": true, "guest_tls": true,
		"tls_spki_sha256": g.spki(),
	}); status != 409 || errCode(doc) != "guest_tls_required" {
		t.Fatalf("typed pin at join: %d %v", status, doc)
	}
}
