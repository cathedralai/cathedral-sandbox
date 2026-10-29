package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const joinKey = "hotel-d-key-0123456789abcdefghijklmnop"

func TestRuntimeMinerHotelsSurviveTightenedCaps(t *testing.T) {
	stateDir := t.TempDir()
	tc := newChainState(t, stateDir)
	for _, id := range []string{"m1", "m2", "m3"} {
		joinMiner(t, tc, id, true, 1, nil)
	}

	setCaps := func(perHotkey, global int) {
		t.Helper()
		raw, err := os.ReadFile(tc.cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		var cfg config
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatal(err)
		}
		if perHotkey == 0 {
			delete(cfg.MinerHotkeyCaps, minerHotkey)
		} else {
			cfg.MinerHotkeyCaps[minerHotkey] = perHotkey
		}
		cfg.MinerMaxHotels = global
		raw, err = json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		tc.start(t)
	}
	checkRetained := func(wantDrain map[string]bool) {
		t.Helper()
		for id, drained := range wantDrain {
			h := tc.b.hotelByID(id)
			if h == nil || h.drain() != drained || h.cfg.TLSSPKISHA256 == "" {
				t.Fatalf("restored %s: hotel=%+v want drain=%t", id, h, drained)
			}
			if _, err := os.Stat(h.cfg.KeyFile); err != nil {
				t.Fatalf("restored %s key: %v", id, err)
			}
		}
		tc.b.mu.Lock()
		err := tc.b.saveRuntimeHotelsLocked()
		tc.b.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(stateDir, runtimeHotelsFile))
		if err != nil {
			t.Fatal(err)
		}
		var saved []hotelConfig
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		if len(saved) != 3 {
			t.Fatalf("state save lost restored miner hotels: %v", saved)
		}
	}

	setCaps(1, 2)
	checkRetained(map[string]bool{"m1": false, "m2": true, "m3": true})
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/m2", map[string]any{"drain": false}); status != 409 || errCode(doc) != "miner_cap_reached" {
		t.Fatalf("over-cap miner undrained: %d %v", status, doc)
	}
	setCaps(0, 0)
	checkRetained(map[string]bool{"m1": true, "m2": true, "m3": true})
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": false}); status != 409 || errCode(doc) != "miner_cap_reached" {
		t.Fatalf("unapproved miner undrained: %d %v", status, doc)
	}
	_, url := newMinerHotel(t, 1, snpAttestation(t, attestOpts{chip: chipOf("m4")}))
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "m4", "api": url, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey,
	}); status != 403 || errCode(doc) != "miner_not_approved" {
		t.Fatalf("new join under removed cap: %d %v", status, doc)
	}
}

func TestOperatorAddsChangesAndRemovesAHotelAtRuntime(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	// d is sealed by configuration: it joins only with an attestation that passes.
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}, attestation: snpAttestation(t, attestOpts{})}
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	join := map[string]any{"id": "d", "api": hs.URL, "key": joinKey, "sealed": true}

	if status, _ := tc.call(t, "key1", "POST", "/v1/broker/hotels", join); status != 401 {
		t.Fatalf("guest key joined a hotel: %d", status)
	}
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", join)
	if status != 201 || doc["id"] != "d" || doc["runtime"] != true {
		t.Fatalf("join: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", join); status != 409 || errCode(doc) != "hotel_exists" {
		t.Fatalf("second join: %d %v", status, doc)
	}
	if fi, err := os.Stat(dir + "/hotel-keys/d.key"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	if raw, _ := os.ReadFile(dir + "/" + runtimeHotelsFile); strings.Contains(string(raw), joinKey) {
		t.Fatalf("hotels.json holds the key")
	}
	h := tc.b.hotelByID("d")
	tc.b.mu.Lock()
	h.ok, h.slots = true, 10
	tc.b.mu.Unlock()
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"d"}}); !strings.HasPrefix(id, "d.") {
		t.Fatalf("room on %s", id)
	}
	// A hotel with rooms cannot leave.
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/d", nil); status != 409 || errCode(doc) != "hotel_not_empty" {
		t.Fatalf("leave with rooms: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/d", map[string]any{"drain": true}); status != 200 || doc["drain"] != true {
		t.Fatalf("drain: %d %v", status, doc)
	}
	// A config hotel cannot leave at runtime.
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/a", nil); status != 409 || errCode(doc) != "hotel_in_config" {
		t.Fatalf("leave config hotel: %d %v", status, doc)
	}

	// After a restart the runtime hotel is back, with its labels and drain flag.
	tc.start(t)
	h = tc.b.hotelByID("d")
	if h == nil || h.cfg.Labels["sealed"] != "true" || !h.cfg.Drain || h.key != joinKey {
		t.Fatalf("hotel after restart: %+v", h)
	}
	// Empty hotel: it leaves, and stays gone after a restart.
	if status, _ := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/d", nil); status != 204 {
		t.Fatalf("leave: %d", status)
	}
	if _, err := os.Stat(dir + "/hotel-keys/d.key"); !os.IsNotExist(err) {
		t.Fatalf("key file kept: %v", err)
	}
	tc.start(t)
	if tc.b.hotelByID("d") != nil {
		t.Fatalf("hotel came back")
	}
}

func TestRuntimeHotelMutationsRefuseFailedStateSave(t *testing.T) {
	newHotelToJoin := func(t *testing.T) map[string]any {
		t.Helper()
		_, origin := newOperatorHotel(t, 1, nil)
		return map[string]any{"id": "durable", "api": origin, "key": joinKey}
	}
	blockSave := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.Mkdir(filepath.Join(dir, runtimeHotelsFile+".tmp"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("join", func(t *testing.T) {
		dir := t.TempDir()
		tc := newChainState(t, dir)
		join := newHotelToJoin(t)
		blockSave(t, dir)
		if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", join); status != 500 || errCode(doc) != "state_write_failed" {
			t.Fatalf("join acknowledged without state save: %d %v", status, doc)
		}
		if tc.b.hotelByID("durable") != nil {
			t.Fatal("failed join remained placeable")
		}
		if _, err := os.Stat(filepath.Join(dir, "hotel-keys", "durable.key")); !os.IsNotExist(err) {
			t.Fatalf("failed join kept key: %v", err)
		}
	})
	for _, action := range []string{"patch", "leave"} {
		t.Run(action, func(t *testing.T) {
			dir := t.TempDir()
			tc := newChainState(t, dir)
			join := newHotelToJoin(t)
			if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", join); status != 201 {
				t.Fatalf("initial join: %d %v", status, doc)
			}
			if action == "patch" {
				if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/durable", map[string]any{"drain": true}); status != 200 {
					t.Fatalf("initial drain: %d %v", status, doc)
				}
			}
			blockSave(t, dir)
			method, body := "PATCH", any(map[string]any{"drain": false, "max_slots": 1})
			if action == "leave" {
				method, body = "DELETE", nil
			}
			if status, doc := tc.call(t, "operator-key", method, "/v1/broker/hotels/durable", body); status != 500 || errCode(doc) != "state_write_failed" {
				t.Fatalf("%s acknowledged without state save: %d %v", action, status, doc)
			}
			h := tc.b.hotelByID("durable")
			if h == nil || h.drain() != (action == "patch") || h.cfg.MaxSlots != 0 || h.leaving {
				t.Fatalf("%s failure changed live hotel: %+v", action, h)
			}
			tc.start(t)
			if h = tc.b.hotelByID("durable"); h == nil || h.drain() != (action == "patch") || h.cfg.MaxSlots != 0 {
				t.Fatalf("%s failure changed saved hotel: %+v", action, h)
			}
		})
	}
}

func TestMinerEnrollmentKeyCannotOperateOutsideMinerScope(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 1, nil)
	for _, path := range []string{"/v1/broker/hotels/a", "/v1/broker/hotels/b"} {
		if status, doc := tc.call(t, "enroller-key", "GET", path, nil); status != 403 || errCode(doc) != "enroller_scope" {
			t.Fatalf("read operator hotel %s: %d %v", path, status, doc)
		}
		if status, doc := tc.call(t, "enroller-key", "PATCH", path, map[string]any{"drain": true}); status != 403 || errCode(doc) != "enroller_scope" {
			t.Fatalf("drain operator hotel %s: %d %v", path, status, doc)
		}
		if status, doc := tc.call(t, "enroller-key", "DELETE", path, nil); status != 403 || errCode(doc) != "enroller_scope" {
			t.Fatalf("leave operator hotel %s: %d %v", path, status, doc)
		}
	}
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"max_rooms": 1}); status != 401 {
		t.Fatalf("enroller changed guest policy: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels/m1/escape-nonce", map[string]any{}); status != 403 || errCode(doc) != "enroller_scope" {
		t.Fatalf("enroller planted nonce: %d %v", status, doc)
	}
	for _, body := range []map[string]any{
		{"id": "x", "api": "https://127.0.0.1:1", "key": joinKey, "sealed": true},
		{"id": "x", "api": "http://127.0.0.1:1", "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey},
		{"id": "x", "api": "https://127.0.0.1:1", "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey, "verify": false},
		{"id": "x", "api": "https://127.0.0.1:1", "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey, "reserved_for": "g1"},
		{"id": "x", "api": "https://127.0.0.1:1", "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey, "labels": map[string]string{"zone": "x"}},
	} {
		if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", body); status != 403 || errCode(doc) != "enroller_scope" {
			t.Fatalf("out-of-scope join %v: %d %v", body, status, doc)
		}
	}
	var contacted atomic.Int32
	var sentKey atomic.Bool
	tlsHotel := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted.Add(1)
		if r.Header.Get("Authorization") != "" {
			sentKey.Store(true)
		}
		w.WriteHeader(200)
	}))
	defer tlsHotel.Close()
	if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "x", "api": tlsHotel.URL, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey,
	}); status != 422 || errCode(doc) != "attestation_failed" || contacted.Load() != 1 || sentKey.Load() {
		t.Fatalf("scoped join sent key before attested TLS: %d %v contacts=%d key=%t", status, doc, contacted.Load(), sentKey.Load())
	}
	if status, doc := tc.call(t, "enroller-key", "GET", "/v1/broker/hotels/m1", nil); status != 200 || doc["miner_hotkey"] != minerHotkey {
		t.Fatalf("read miner hotel: %d %v", status, doc)
	}
	for _, body := range []map[string]any{{"drain": false}, {"labels": map[string]string{"zone": "x"}}, {"max_slots": 1}, {"reserved_for": "g1"}} {
		if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", body); status != 403 || errCode(doc) != "enroller_scope" {
			t.Fatalf("out-of-scope miner patch %v: %d %v", body, status, doc)
		}
	}
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true}); status != 200 || doc["drain"] != true {
		t.Fatalf("drain miner hotel: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "enroller-key", "DELETE", "/v1/broker/hotels/m1", nil); status != 204 {
		t.Fatalf("leave empty miner hotel: %d %v", status, doc)
	}
}

func TestScopedMinerJoinPinsAttestedGuestBeforeSendingHotelKey(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	m, url := newMinerHotel(t, 1, snpAttestation(t, attestOpts{chip: 77}))
	join := map[string]any{"id": "pinned", "api": url, "health": url, "key": joinKey,
		"sealed": true, "miner_hotkey": minerHotkey}
	if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", join); status != 201 {
		t.Fatalf("attested guest join: %d %v", status, doc)
	}
	h := tc.b.hotelByID("pinned")
	if h == nil || h.cfg.TLSSPKISHA256 == "" || h.tlsPinErr != nil {
		t.Fatalf("joined miner lacks peer pin: %+v", h)
	}
	var impostorSawKey atomic.Bool
	impostor := newDistinctTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			impostorSawKey.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(m.attestation)
	}))
	defer impostor.Close()
	join["id"], join["api"], join["health"] = "impostor", impostor.URL, impostor.URL
	if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", join); status != 422 || errCode(doc) != "attestation_failed" || impostorSawKey.Load() {
		t.Fatalf("host TLS key accepted or saw hotel key: %d %v key=%t", status, doc, impostorSawKey.Load())
	}
	if tc.b.hotelByID("impostor") != nil {
		t.Fatal("impostor joined")
	}
	for name, change := range map[string]any{
		"verify":          false,
		"tls_spki_sha256": h.cfg.TLSSPKISHA256,
		"api":             "http://127.0.0.1:1",
	} {
		operatorJoin := map[string]any{"id": "operator-" + name, "api": url, "health": url,
			"key": joinKey, "sealed": true, "miner_hotkey": minerHotkey}
		operatorJoin[name] = change
		if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", operatorJoin); status != 409 || errCode(doc) != "guest_tls_required" {
			t.Fatalf("operator bypass %s: %d %v", name, status, doc)
		}
	}
	// The same pin guards both data and control calls, including after restart.
	for _, pinned := range []*hotel{h} {
		if _, _, _, err := pinned.doBase(context.Background(), impostor.URL, "GET", "/v1/status", nil, nil, time.Second); err == nil {
			t.Fatal("data client accepted a changed miner TLS key")
		}
		var status map[string]any
		if err := pinned.getJSON(context.Background(), impostor.URL, "/v1/status", nil, &status); err == nil {
			t.Fatal("control client accepted a changed miner TLS key")
		}
		if impostorSawKey.Load() {
			t.Fatal("changed miner TLS peer received hotel key")
		}
	}
	tc.start(t)
	restored := tc.b.hotelByID("pinned")
	if restored == nil || restored.cfg.TLSSPKISHA256 != h.cfg.TLSSPKISHA256 || restored.tlsPinErr != nil {
		t.Fatalf("restart lost miner TLS pin: %+v", restored)
	}
	if _, _, _, err := restored.doBase(context.Background(), impostor.URL, "GET", "/v1/status", nil, nil, time.Second); err == nil || impostorSawKey.Load() {
		t.Fatalf("restored broker sent key to changed peer: %v", err)
	}
	if code, _, _, err := restored.do(context.Background(), "GET", "/v1/status", nil, nil, time.Second); err != nil || code != 200 {
		t.Fatalf("restored broker could not reach pinned peer: %d %v", code, err)
	}
}

func TestMinerHotelDoesNotFollowRedirectWithKey(t *testing.T) {
	var targetSawKey atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			targetSawKey.Store(true)
		}
	}))
	defer target.Close()
	redirect := newDistinctTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/stolen", http.StatusFound)
	}))
	defer redirect.Close()
	sum := sha256.Sum256(redirect.Certificate().RawSubjectPublicKeyInfo)
	h := newHotel(hotelConfig{ID: "redirect", API: redirect.URL, Health: redirect.URL,
		MinerHotkey: minerHotkey, TLSSPKISHA256: hex.EncodeToString(sum[:])}, joinKey)
	if h.tlsPinErr != nil {
		t.Fatal(h.tlsPinErr)
	}
	if code, _, _, err := h.do(context.Background(), "GET", "/v1/status", nil, nil, time.Second); err != nil || code != http.StatusFound || targetSawKey.Load() {
		t.Fatalf("miner data client followed redirect: %d %v target_key=%t", code, err, targetSawKey.Load())
	}
	var doc map[string]any
	if err := h.getJSON(context.Background(), redirect.URL, "/v1/status", nil, &doc); err == nil || targetSawKey.Load() {
		t.Fatalf("miner control client followed redirect: %v target_key=%t", err, targetSawKey.Load())
	}
}

func TestMinerHotelWithoutPersistedPinIsSkippedOnRestart(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	_, origin := newMinerHotel(t, 1, snpAttestation(t, attestOpts{chip: 91}))
	if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "old-miner", "api": origin, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey,
	}); status != 201 {
		t.Fatalf("miner join: %d %v", status, doc)
	}
	path := dir + "/" + runtimeHotelsFile
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var saved []hotelConfig
	if err := json.Unmarshal(raw, &saved); err != nil || len(saved) != 1 || saved[0].TLSSPKISHA256 == "" {
		t.Fatalf("pin not persisted: %v %+v", err, saved)
	}
	saved[0].TLSSPKISHA256 = "" // model a runtime record from before pinning existed
	raw, _ = json.Marshal(saved)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.start(t)
	if tc.b.hotelByID("old-miner") != nil {
		t.Fatal("runtime miner without an attested TLS pin was loaded")
	}
}

func TestStaticMinerHotelCannotBypassTLSBootstrap(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Hotels = append(cfg.Hotels, hotelConfig{ID: "static-miner", API: "http://127.0.0.1:1",
		Health: "http://127.0.0.1:1", Sealed: true, MinerHotkey: minerHotkey})
	raw, _ = json.Marshal(cfg)
	path := t.TempDir() + "/config.json"
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBroker(path); err == nil || !strings.Contains(err.Error(), "must join with attested guest TLS") {
		t.Fatalf("static miner bypassed guest TLS bootstrap: %v", err)
	}
}

func newDistinctTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(handler)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	s.StartTLS()
	return s
}

func TestMinerEnrollmentKeyConfigRejectsReuse(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var original config
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	for name, digest := range map[string]string{
		"operator":  original.OperatorKeySHA256,
		"guest":     original.Guests[0].KeySHA256,
		"view":      original.Guests[0].ViewTokenSHA256,
		"malformed": "not-a-digest",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := original
			cfg.MinerEnrollKeySHA256 = digest
			body, _ := json.Marshal(cfg)
			path := t.TempDir() + "/config.json"
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadBroker(path); err == nil {
				t.Fatal("reused or malformed miner enrollment key was accepted")
			}
		})
	}
}

func TestJoinChecksTheHotelAndTheInput(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	cases := []struct {
		body map[string]any
		want int
		code string
	}{
		{map[string]any{"id": "x", "api": dead.URL, "key": joinKey}, 502, "hotel_unreachable"},
		{map[string]any{"id": "x.y", "api": dead.URL, "key": joinKey}, 400, "invalid_hotel"},
		{map[string]any{"id": "x", "api": "file:///etc/passwd", "key": joinKey}, 400, "invalid_hotel"},
		{map[string]any{"id": "x", "api": dead.URL, "key": "short"}, 400, "invalid_hotel"},
		{map[string]any{"id": "x", "api": dead.URL, "key": joinKey, "miner_hotkey": minerHotkey}, 400, "invalid_hotel"},
		{map[string]any{"id": "x", "api": dead.URL, "key": joinKey, "labels": map[string]string{"sealed": "true"}}, 400, "invalid_hotel"},
	}
	for _, c := range cases {
		status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", c.body)
		if status != c.want || errCode(doc) != c.code {
			t.Fatalf("%v: %d %v", c.body, status, doc)
		}
	}
	if tc.b.hotelByID("x") != nil {
		t.Fatalf("a refused hotel was added")
	}
}

func TestRuntimeUnsealedHotelCannotGainSealedLabel(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	_, url := newMinerHotel(t, 5, nil)
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "plain", "api": url, "key": joinKey, "verify": false,
	})
	if status != 201 {
		t.Fatalf("join unsealed operator hotel: %d %v", status, doc)
	}
	status, doc = tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/plain", map[string]any{
		"labels": map[string]string{"sealed": "true"},
	})
	if status != 400 || errCode(doc) != "invalid_hotel" {
		t.Fatalf("unsealed hotel gained sealed label: %d %v", status, doc)
	}
	if tc.b.hotelByID("plain").labels()["sealed"] == "true" {
		t.Fatal("unsealed hotel kept sealed label")
	}
}

func TestLegacyRuntimeSealedLabelCannotTakeRooms(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	h := newHotel(hotelConfig{ID: "old-label", Labels: map[string]string{"sealed": "true"}}, joinKey)
	h.runtime, h.ok, h.slots = true, true, 5
	if err := tc.b.addHotel(h); err != nil {
		t.Fatal(err)
	}
	tc.b.mu.Lock()
	free := tc.b.admissibleFree(h, time.Now())
	tc.b.mu.Unlock()
	if free != 0 {
		t.Fatalf("unsealed runtime hotel offers %d sealed-labeled rooms", free)
	}
}

func TestLiveViewSignInByPost(t *testing.T) {
	tc := newChain(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.PostForm(tc.srv.URL+"/g1/live/sign-in", url.Values{"token": {"wrong"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || len(resp.Cookies()) != 0 {
		t.Fatalf("wrong token: %d %v", resp.StatusCode, resp.Cookies())
	}
	resp, err = client.PostForm(tc.srv.URL+"/g1/live/sign-in", url.Values{"token": {"view1"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/g1/live" || len(resp.Cookies()) != 1 {
		t.Fatalf("sign in: %d %v", resp.StatusCode, resp.Header)
	}
	c := resp.Cookies()[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/g1/" {
		t.Fatalf("cookie: %+v", c)
	}
	req, _ := http.NewRequest("GET", tc.srv.URL+"/g1/live", nil)
	req.AddCookie(c)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("live with cookie: %d", resp.StatusCode)
	}
	// Without a cookie the page is the sign-in form, not a link to a ?token= URL.
	resp, err = client.Get(tc.srv.URL + "/g1/live")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if resp.StatusCode != 401 || !strings.Contains(string(buf[:n]), `action="/g1/live/sign-in"`) {
		t.Fatalf("sign-in form: %d %s", resp.StatusCode, buf[:n])
	}
	// The ?token= link still works.
	resp, err = client.Get(tc.srv.URL + "/g1/live?token=view1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Fatalf("token link: %d", resp.StatusCode)
	}
}
