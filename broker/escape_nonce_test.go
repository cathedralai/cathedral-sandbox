package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signPlantKey(t *testing.T, receiptPriv ed25519.PrivateKey, hotel, bindingSHA string, x25519Pub []byte) map[string]string {
	t.Helper()
	doc := map[string]string{
		"algorithm":         plantAlgorithm,
		"binding_sha256":    bindingSHA,
		"hotel":             hotel,
		"purpose":           plantKeyPurpose,
		"x25519_public_b64": base64.StdEncoding.EncodeToString(x25519Pub),
	}
	msg, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc["signature_b64"] = base64.StdEncoding.EncodeToString(ed25519.Sign(receiptPriv, msg))
	return doc
}

func admitEscapeHotel(h *hotel, receiptPub ed25519.PublicKey, bindingSHA string) {
	h.cfg.Sealed = true
	h.cfg.Labels = map[string]string{"sealed": "true", "escape": "true"}
	h.adm.receiptKey = append([]byte(nil), receiptPub...)
	h.adm.bindingSHA = bindingSHA
	h.adm.attestedAt = time.Now()
}

func escapePlantKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, *ecdh.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, x
}

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
	receiptPub, receiptPriv, plant := escapePlantKeys(t)
	h := tc.b.hotelByID("a")
	admitEscapeHotel(h, receiptPub, "binding-a")
	f := tc.hotels["a"]
	f.mu.Lock()
	f.plantKeyDoc = signPlantKey(t, receiptPriv, "a", "binding-a", plant.PublicKey().Bytes())
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

func TestEscapeNoncePlantRefusesAHostSubstitutedKey(t *testing.T) {
	tc := newChain(t)
	guestPub, _, _ := escapePlantKeys(t)
	_, hostPriv, hostPlant := escapePlantKeys(t)
	h := tc.b.hotelByID("a")
	admitEscapeHotel(h, guestPub, "binding-a")
	f := tc.hotels["a"]
	f.mu.Lock()
	f.plantKeyDoc = signPlantKey(t, hostPriv, "a", "binding-a", hostPlant.PublicKey().Bytes())
	f.mu.Unlock()

	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 409 || errCode(doc) != "plant_key_unverified" {
		t.Fatalf("host key: %d %v", status, doc)
	}
	if len(f.plantPosts) != 0 {
		t.Fatalf("nonce was delivered to a substituted key: %d posts", len(f.plantPosts))
	}
}

func TestEscapeNoncePlantRefusesAnUnsignedKey(t *testing.T) {
	tc := newChain(t)
	receiptPub, _, plant := escapePlantKeys(t)
	h := tc.b.hotelByID("a")
	admitEscapeHotel(h, receiptPub, "binding-a")
	f := tc.hotels["a"]
	f.mu.Lock()
	f.plantKeyB64 = base64.StdEncoding.EncodeToString(plant.PublicKey().Bytes())
	f.mu.Unlock()

	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 409 || errCode(doc) != "plant_key_unverified" {
		t.Fatalf("unsigned: %d %v", status, doc)
	}
	if len(f.plantPosts) != 0 {
		t.Fatal("unsigned key delivered a nonce")
	}
}

func TestEscapeNoncePlantRefusesANonAttestedSigner(t *testing.T) {
	tc := newChain(t)
	guestPub, _, plant := escapePlantKeys(t)
	_, otherPriv, _ := escapePlantKeys(t)
	h := tc.b.hotelByID("a")
	admitEscapeHotel(h, guestPub, "binding-a")
	f := tc.hotels["a"]
	f.mu.Lock()
	f.plantKeyDoc = signPlantKey(t, otherPriv, "a", "binding-a", plant.PublicKey().Bytes())
	f.mu.Unlock()

	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 409 || errCode(doc) != "plant_key_unverified" {
		t.Fatalf("non-attested signer: %d %v", status, doc)
	}
	if len(f.plantPosts) != 0 {
		t.Fatal("nonce delivered for a non-attested signer")
	}
}

func TestEscapeNoncePlantRefusesASignatureForAnotherRoom(t *testing.T) {
	tc := newChain(t)
	receiptPub, receiptPriv, plant := escapePlantKeys(t)
	h := tc.b.hotelByID("a")
	admitEscapeHotel(h, receiptPub, "binding-a")
	f := tc.hotels["a"]
	f.mu.Lock()
	f.plantKeyDoc = signPlantKey(t, receiptPriv, "other-hotel", "binding-a", plant.PublicKey().Bytes())
	f.mu.Unlock()

	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 409 || errCode(doc) != "plant_key_unverified" {
		t.Fatalf("other room: %d %v", status, doc)
	}
	if len(f.plantPosts) != 0 {
		t.Fatal("nonce delivered for a signature bound to another hotel")
	}
}

func TestEscapeNoncePlantPlaintextFlagDoesNotBypassABadKey(t *testing.T) {
	tc := newChain(t)
	tc.b.cfg.EscapeNonceAllowPlaintext = true
	receiptPub, _, plant := escapePlantKeys(t)
	h := tc.b.hotelByID("a")
	admitEscapeHotel(h, receiptPub, "binding-a")
	f := tc.hotels["a"]
	f.mu.Lock()
	f.plantKeyB64 = base64.StdEncoding.EncodeToString(plant.PublicKey().Bytes())
	f.mu.Unlock()

	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 409 || errCode(doc) != "plant_key_unverified" {
		t.Fatalf("plaintext flag: %d %v", status, doc)
	}
	if len(f.plantPosts) != 0 {
		t.Fatal("plaintext flag delivered an unsigned key's nonce")
	}
}

func TestEscapeNoncePlantRefusesWhenNotAdmitted(t *testing.T) {
	tc := newChain(t)
	receiptPub, receiptPriv, plant := escapePlantKeys(t)
	h := tc.b.hotelByID("a")
	admitEscapeHotel(h, receiptPub, "binding-a")
	h.runtime = true
	h.adm.attestedAt = time.Time{}
	f := tc.hotels["a"]
	f.mu.Lock()
	f.plantKeyDoc = signPlantKey(t, receiptPriv, "a", "binding-a", plant.PublicKey().Bytes())
	f.mu.Unlock()

	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels/a/escape-nonce",
		map[string]string{"window_id": "win-1", "nonce": "control-plane-nonce-1"})
	if status != 409 || errCode(doc) != "hotel_not_admitted" {
		t.Fatalf("not admitted: %d %v", status, doc)
	}
	if len(f.plantPosts) != 0 {
		t.Fatal("nonce delivered to a hotel that is not admitted")
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
	receiptPub, receiptPriv, plant := escapePlantKeys(t)
	h := tc.b.hotelByID("a")
	admitEscapeHotel(h, receiptPub, "binding-a")
	f := tc.hotels["a"]
	f.mu.Lock()
	f.plantKeyDoc = signPlantKey(t, receiptPriv, "a", "binding-a", plant.PublicKey().Bytes())
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
	receiptPub, _, _ := escapePlantKeys(t)
	h := tc.b.hotelByID("a")
	admitEscapeHotel(h, receiptPub, "binding-a")
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
	receiptPub, _, _ := escapePlantKeys(t)
	h := tc.b.hotelByID("a")
	admitEscapeHotel(h, receiptPub, "binding-a")
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
