package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSealPlantNonceRoundTrip(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("window-nonce-fixture1")
	env, err := sealPlantNonce(plain, priv.PublicKey().Bytes(), "c46-sealed", "win-1")
	if err != nil {
		t.Fatal(err)
	}
	if env["algorithm"] != plantAlgorithm {
		t.Fatalf("algorithm %q", env["algorithm"])
	}
	got, err := openPlantNonce(env, priv, "c46-sealed", "win-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("opened %q", got)
	}
	if _, err := openPlantNonce(env, priv, "c46-sealed", "win-other"); err == nil {
		t.Fatal("aad mismatch opened")
	}
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openPlantNonce(env, other, "c46-sealed", "win-1"); err == nil {
		t.Fatal("wrong key opened")
	}
}

func TestEscapeNoncePlantHappyPathEncrypts(t *testing.T) {
	tc := newChain(t)
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := tc.b.hotelByID("a")
	h.cfg.Sealed = true
	h.cfg.Labels = map[string]string{"sealed": "true", "escape": "true"}
	f := tc.hotels["a"]
	f.mu.Lock()
	f.plantKeyB64 = base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	f.mu.Unlock()

	nonce := "control-plane-nonce-1"
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-2026-10-27", "nonce": nonce})
	if status != 200 || doc["ok"] != true {
		t.Fatalf("plant: %d %v", status, doc)
	}
	leak, err := json.Marshal(doc)
	if err != nil || bytes.Contains(leak, []byte(nonce)) {
		t.Fatalf("broker echoed the nonce: %v", doc)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.plantPosts) != 1 {
		t.Fatalf("hotel posts %d", len(f.plantPosts))
	}
	if bytes.Contains(f.plantPosts[0], []byte(nonce)) {
		t.Fatalf("plaintext nonce crossed the hotel hop: %s", f.plantPosts[0])
	}
	var posted map[string]any
	if json.Unmarshal(f.plantPosts[0], &posted) != nil {
		t.Fatalf("hotel body: %s", f.plantPosts[0])
	}
	if posted["window_id"] != "win-2026-10-27" || posted["algorithm"] != plantAlgorithm {
		t.Fatalf("posted %v", posted)
	}
	if posted["ciphertext_b64"] == nil || posted["nonce"] != nil {
		t.Fatalf("expected ciphertext only: %v", posted)
	}
	if !strings.HasPrefix(f.plantAuth[0], "Bearer ") {
		t.Fatalf("hotel auth %q", f.plantAuth[0])
	}
}

func TestEscapeNoncePlantRefusesANonEscapeHotel(t *testing.T) {
	tc := newChain(t)
	tc.b.hotelByID("a").cfg.Sealed = true
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 403 || errCode(doc) != "escape_hotel_required" {
		t.Fatalf("unlabelled: %d %v", status, doc)
	}
	tc.b.hotelByID("b").cfg.Labels = map[string]string{"escape": "true"}
	status, doc = tc.call(t, "operator-key", "POST", "/v1/broker/hotels/b/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 403 || errCode(doc) != "escape_hotel_required" {
		t.Fatalf("unsealed: %d %v", status, doc)
	}
	if n := len(tc.hotels["a"].plantPosts) + len(tc.hotels["b"].plantPosts); n != 0 {
		t.Fatalf("hotel was called %d times", n)
	}
}

func TestEscapeNoncePlantGuestKeyIsUnauthorized(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.call(t, "key1", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 401 || errCode(doc) != "unauthorized" {
		t.Fatalf("guest: %d %v", status, doc)
	}
}

func TestEscapeNoncePlantHotelFailure(t *testing.T) {
	tc := newChain(t)
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := tc.b.hotelByID("a")
	h.cfg.Sealed = true
	h.cfg.Labels = map[string]string{"sealed": "true", "escape": "true"}
	f := tc.hotels["a"]
	f.mu.Lock()
	f.plantKeyB64 = base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	f.plantFail = true
	f.mu.Unlock()

	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 502 || errCode(doc) != "plant_failed" {
		t.Fatalf("hotel fail: %d %v", status, doc)
	}
}

func TestEscapeNoncePlantRequiresEncryptionWhenNoKey(t *testing.T) {
	tc := newChain(t)
	h := tc.b.hotelByID("a")
	h.cfg.Sealed = true
	h.cfg.Labels = map[string]string{"sealed": "true", "escape": "true"}
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 409 || errCode(doc) != "encryption_required" {
		t.Fatalf("no key: %d %v", status, doc)
	}
	if len(tc.hotels["a"].plantPosts) != 0 {
		t.Fatal("plaintext reached the hotel")
	}
}

func TestEscapeNoncePlantPlaintextFlag(t *testing.T) {
	tc := newChain(t)
	tc.b.cfg.EscapeNonceAllowPlaintext = true
	h := tc.b.hotelByID("a")
	h.cfg.Sealed = true
	h.cfg.Labels = map[string]string{"sealed": "true", "escape": "true"}
	nonce := "control-plane-nonce-1"
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": nonce})
	if status != 200 || doc["ok"] != true {
		t.Fatalf("plaintext flag: %d %v", status, doc)
	}
	f := tc.hotels["a"]
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.plantPosts) != 1 || !bytes.Contains(f.plantPosts[0], []byte(nonce)) {
		t.Fatalf("expected plaintext hop: %v", f.plantPosts)
	}
}

func TestFilterHotelReceiptsDropsAPlantReceipt(t *testing.T) {
	mine := []byte(`{"statement":{"sandbox_id":"room-a","action":"create"},"signature_b64":"sig-a"}`)
	plant := []byte(`{"statement":{"sandbox_id":null,"action":"escape_nonce_plant","window_id":"win-1","nonce_sha256":"ab"},"signature_b64":"sig-plant"}`)
	body := []byte(`{"binding_sha256":"bb","head":"hh","count":2,"receipts":[` + string(mine) + `,` + string(plant) + `]}`)
	out, err := filterHotelReceipts(body, map[string]bool{"room-a": true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, mine) {
		t.Fatalf("owned create dropped: %s", out)
	}
	for _, leak := range []string{"escape_nonce_plant", "sig-plant", "win-1"} {
		if bytes.Contains(out, []byte(leak)) {
			t.Fatalf("plant receipt visible to a room client: %s", leak)
		}
	}
}

func TestEscapeNoncePlantUnknownHotel(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/nosuch/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 404 || errCode(doc) != "hotel_not_found" {
		t.Fatalf("missing hotel: %d %v", status, doc)
	}
}
