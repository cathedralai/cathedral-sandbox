// Escape Room nonce plant: the control plane pushes a per-window nonce into
// a sealed Escape hotel guest. The host can read broker-to-hotel HTTP, so the
// broker encrypts to a guest-held X25519 key when the hotel publishes one.
//
//	POST /v1/broker/hotels/<id>/escape-nonce   operator key
//
// Hotel gate: sealed=true and label escape=true. Fail closed otherwise.
// The hotel never echoes the nonce. This file must not log it.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

const (
	plantAlgorithm    = "x25519-hkdf-sha256-aes256gcm-v1"
	plantBodyMax      = 8192
	plantHotelTimeout = 30 * time.Second
	escapeHotelLabel  = "escape"
	escapeHotelWant   = "true"
)

var (
	plantHKDFInfo = []byte("cathedral.escape-nonce-plant.v1")
	windowIDRE    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	plantNonceRE  = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{16,512}$`)
)

type escapePlantRequest struct {
	WindowID string `json:"window_id"`
	Nonce    string `json:"nonce"`
}

type escapePlantKey struct {
	Algorithm       string `json:"algorithm"`
	X25519PublicB64 string `json:"x25519_public_b64"`
}

func (h *hotel) isEscape() bool {
	labels := h.labels()
	return labels != nil && labels[escapeHotelLabel] == escapeHotelWant
}

func (b *broker) handleEscapeNoncePlant(w http.ResponseWriter, r *http.Request, id string) {
	h := b.hotelByID(id)
	if h == nil {
		writeErr(w, 404, "hotel_not_found", "no hotel "+id)
		return
	}
	if !h.cfg.Sealed || !h.isEscape() {
		writeErr(w, 403, "escape_hotel_required", "nonce plant is only for sealed hotels labelled escape=true")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, plantBodyMax))
	if err != nil {
		writeErr(w, 413, "body_too_large", "plant body over 8192 bytes")
		return
	}
	var req escapePlantRequest
	if json.Unmarshal(raw, &req) != nil {
		writeErr(w, 400, "invalid_json", "request body is not JSON")
		return
	}
	if !windowIDRE.MatchString(req.WindowID) {
		writeErr(w, 400, "invalid_request", "window_id must be 1 to 128 of [A-Za-z0-9._:-]")
		return
	}
	if !plantNonceRE.MatchString(req.Nonce) {
		writeErr(w, 400, "invalid_request", "nonce must be 16 to 512 of [A-Za-z0-9+/=_-]")
		return
	}
	hotelBody, err := b.sealEscapePlant(r.Context(), h, req)
	if err != nil {
		writeErr(w, 409, "encryption_required", err.Error())
		return
	}
	status, hdr, out, err := h.doBase(r.Context(), h.cfg.Health, "POST", "/room/escape-nonce", nil, hotelBody, plantHotelTimeout)
	if err != nil {
		writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
		return
	}
	if v := hdr.Get("Content-Type"); v != "" {
		w.Header().Set("Content-Type", v)
	}
	if v := hdr.Get("X-Room-Receipt"); v != "" {
		w.Header().Set("X-Room-Receipt", v)
	}
	if v := hdr.Get("X-Room-Receipt-Error"); v != "" {
		w.Header().Set("X-Room-Receipt-Error", v)
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

func (b *broker) sealEscapePlant(ctx context.Context, h *hotel, req escapePlantRequest) ([]byte, error) {
	pub, err := b.fetchEscapePlantKey(ctx, h)
	if err == nil && pub != nil {
		env, sealErr := sealPlantNonce([]byte(req.Nonce), pub.Bytes(), h.cfg.ID, req.WindowID)
		if sealErr != nil {
			return nil, fmt.Errorf("the hotel plant key could not be used")
		}
		env["window_id"] = req.WindowID
		return json.Marshal(env)
	}
	if !b.cfg.EscapeNonceAllowPlaintext {
		if err != nil {
			return nil, fmt.Errorf("the hotel published no plant key and plaintext is off")
		}
		return nil, fmt.Errorf("the hotel published no plant key and plaintext is off")
	}
	// TODO Mr Spock: remove this branch with the pin move once every escape
	// hotel image decrypts. The host can read this hop.
	return json.Marshal(map[string]string{"window_id": req.WindowID, "nonce": req.Nonce})
}

func (b *broker) fetchEscapePlantKey(ctx context.Context, h *hotel) (*ecdh.PublicKey, error) {
	status, _, out, err := h.doBase(ctx, h.cfg.Health, "GET", "/room/escape-plant-key", nil, nil, plantHotelTimeout)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("hotel plant key status %d", status)
	}
	var doc escapePlantKey
	if json.Unmarshal(out, &doc) != nil || doc.Algorithm != plantAlgorithm || doc.X25519PublicB64 == "" {
		return nil, fmt.Errorf("hotel plant key is unreadable")
	}
	raw, err := base64.StdEncoding.DecodeString(doc.X25519PublicB64)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("hotel plant key is unreadable")
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("hotel plant key is unreadable")
	}
	return pub, nil
}

func plantAAD(hotel, windowID string) []byte {
	return []byte("escape-nonce-plant:" + hotel + ":" + windowID)
}

func sealPlantNonce(plaintext, recipientPub []byte, hotel, windowID string) (map[string]string, error) {
	curve := ecdh.X25519()
	recipient, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return nil, err
	}
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(recipient)
	if err != nil || isZero(shared) {
		return nil, fmt.Errorf("x25519 exchange failed")
	}
	rawEph := eph.PublicKey().Bytes()
	rawRec := recipient.Bytes()
	aad := plantAAD(hotel, windowID)
	key := hkdfSHA256(shared, aad, append(append(append([]byte{}, plantHKDFInfo...), rawEph...), rawRec...), 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	n := make([]byte, 12)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, n, plaintext, aad)
	return map[string]string{
		"algorithm":            plantAlgorithm,
		"ephemeral_public_b64": base64.StdEncoding.EncodeToString(rawEph),
		"nonce_b64":            base64.StdEncoding.EncodeToString(n),
		"ciphertext_b64":       base64.StdEncoding.EncodeToString(ct),
	}, nil
}

func openPlantNonce(env map[string]string, private *ecdh.PrivateKey, hotel, windowID string) ([]byte, error) {
	if env["algorithm"] != plantAlgorithm {
		return nil, fmt.Errorf("ciphertext does not open")
	}
	rawEph, err := base64.StdEncoding.DecodeString(env["ephemeral_public_b64"])
	if err != nil || len(rawEph) != 32 {
		return nil, fmt.Errorf("ciphertext does not open")
	}
	aesN, err := base64.StdEncoding.DecodeString(env["nonce_b64"])
	if err != nil || len(aesN) != 12 {
		return nil, fmt.Errorf("ciphertext does not open")
	}
	ct, err := base64.StdEncoding.DecodeString(env["ciphertext_b64"])
	if err != nil || len(ct) < 16 || len(ct) > 2048 {
		return nil, fmt.Errorf("ciphertext does not open")
	}
	eph, err := ecdh.X25519().NewPublicKey(rawEph)
	if err != nil {
		return nil, fmt.Errorf("ciphertext does not open")
	}
	shared, err := private.ECDH(eph)
	if err != nil || isZero(shared) {
		return nil, fmt.Errorf("ciphertext does not open")
	}
	aad := plantAAD(hotel, windowID)
	rawRec := private.PublicKey().Bytes()
	key := hkdfSHA256(shared, aad, append(append(append([]byte{}, plantHKDFInfo...), rawEph...), rawRec...), 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ciphertext does not open")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ciphertext does not open")
	}
	plain, err := aead.Open(nil, aesN, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("ciphertext does not open")
	}
	return plain, nil
}

func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(secret)
	prk := extract.Sum(nil)
	var (
		out, prev []byte
		counter   byte
	)
	for len(out) < length {
		counter++
		expand := hmac.New(sha256.New, prk)
		expand.Write(prev)
		expand.Write(info)
		expand.Write([]byte{counter})
		prev = expand.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

func isZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}
