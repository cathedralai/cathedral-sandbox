// Escape Room nonce plant: the control plane pushes a per-window nonce into
// a sealed Escape hotel guest. The host can read broker-to-hotel HTTP, so the
// broker encrypts to a guest-held X25519 key. There is no plaintext
// fallback: if the hotel publishes no attested plant key, the nonce is
// not delivered. That key is signed by the guest's attested receipt key
// (the Ed25519 key named by receipt_key_ed25519_b64 in the binding
// REPORT_DATA commits to). The broker verifies the signature before it
// encrypts. It also refuses unless, for this exact binding, the AMD
// SEV-SNP chain already passed and the launch measurement is on
// sealed_measurements. An unsigned, swapped, unverifiable, or unattested
// key fails closed; the nonce is not delivered.
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
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	plantAlgorithm    = "x25519-hkdf-sha256-aes256gcm-v1"
	plantKeyPurpose   = "escape-plant-key"
	plantBodyMax      = 8192
	plantHotelTimeout = 30 * time.Second
	escapeHotelLabel  = "escape"
	escapeHotelWant   = "true"
)

var (
	errNoPlantKey       = errors.New("the hotel published no plant key")
	errBadPlantKey      = errors.New("the hotel plant key is not attested")
	errNotAdmitted      = errors.New("the hotel is not admitted")
	errNoReceiptKey     = errors.New("the hotel published no attested receipt key")
	errUnverifiedAttest = errors.New("the hotel attestation is not AMD-chain verified for this binding")
	plantHKDFInfo       = []byte("cathedral.escape-nonce-plant.v1")
	windowIDRE          = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	plantNonceRE        = regexp.MustCompile(`^[A-Za-z0-9+/=_-]{16,512}$`)
	freshIDRE           = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	freshRoomRE         = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// escapeFreshSchema is the AB#683 assignment the guest signs into the plant
// receipt (polariscomputer docs/AB683_FRESH_EVIDENCE.md). The broker only
// checks its shape and forwards it; the guest refuses a plant whose
// assignment, room incarnation or create receipt is not its own.
const escapeFreshSchema = "cathedral.escape.fresh_evidence/v1"

type escapeFreshPlant struct {
	Schema              string `json:"schema"`
	AttemptID           string `json:"attempt_id"`
	ReportID            string `json:"report_id"`
	RequestSHA256       string `json:"request_sha256"`
	CreateReceiptSHA256 string `json:"create_receipt_sha256"`
}

type escapePlantRequest struct {
	WindowID string `json:"window_id"`
	Nonce    string `json:"nonce"`
	// AB#683: both or neither. SandboxID is the hotel-local room id the
	// signed create receipt names.
	SandboxID   string            `json:"sandbox_id,omitempty"`
	EscapeFresh *escapeFreshPlant `json:"escape_fresh,omitempty"`
}

func (f *escapeFreshPlant) valid() bool {
	return f.Schema == escapeFreshSchema && freshIDRE.MatchString(f.AttemptID) &&
		freshIDRE.MatchString(f.ReportID) && sha256HexRE.MatchString(f.RequestSHA256) &&
		sha256HexRE.MatchString(f.CreateReceiptSHA256)
}

// decodePlantRequest refuses unknown fields, so a mistyped or extra fresh
// field is not silently dropped and the plant sent without it.
func decodePlantRequest(raw []byte) (escapePlantRequest, string, bool) {
	var req escapePlantRequest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || dec.More() {
		return req, "request body is not JSON", false
	}
	if (req.SandboxID == "") != (req.EscapeFresh == nil) {
		return req, "sandbox_id and escape_fresh go together", false
	}
	if req.EscapeFresh != nil && (!freshRoomRE.MatchString(req.SandboxID) || !req.EscapeFresh.valid()) {
		return req, "escape_fresh must be the fresh_evidence/v1 assignment and its create receipt", false
	}
	return req, "", true
}

type escapePlantKey struct {
	Algorithm       string `json:"algorithm"`
	BindingSHA256   string `json:"binding_sha256"`
	Hotel           string `json:"hotel"`
	Purpose         string `json:"purpose"`
	X25519PublicB64 string `json:"x25519_public_b64"`
	SignatureB64    string `json:"signature_b64"`
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
	req, why, ok := decodePlantRequest(raw)
	if !ok {
		code := "invalid_request"
		if why == "request body is not JSON" {
			code = "invalid_json"
		}
		writeErr(w, 400, code, why)
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
		writeErr(w, 409, plantErrCode(err), err.Error())
		return
	}
	status, hdr, out, err := h.doBase(r.Context(), h.cfg.Health, "POST", "/room/escape-nonce", nil, hotelBody, plantHotelTimeout)
	if err != nil {
		writeHotelErr(w, h, err)
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

func plantErrCode(err error) string {
	switch {
	case errors.Is(err, errNotAdmitted):
		return "hotel_not_admitted"
	case errors.Is(err, errUnverifiedAttest):
		return "plant_attestation_unverified"
	case errors.Is(err, errBadPlantKey), errors.Is(err, errNoReceiptKey):
		return "plant_key_unverified"
	default:
		return "encryption_required"
	}
}

func refusePlaintextEscapeNonce(flag *bool) error {
	if flag == nil {
		return nil
	}
	if *flag {
		return fmt.Errorf("config: escape_nonce_allow_plaintext=true is refused; the nonce is only delivered sealed")
	}
	log.Printf("config: escape_nonce_allow_plaintext is ignored; plaintext nonce delivery has been removed")
	return nil
}

func (b *broker) sealEscapePlant(ctx context.Context, h *hotel, req escapePlantRequest) ([]byte, error) {
	receiptKey, bindingSHA, err := b.escapeReceiptKey(ctx, h)
	if err != nil {
		return nil, err
	}
	pub, err := b.fetchEscapePlantKey(ctx, h, receiptKey, bindingSHA)
	if err != nil {
		return nil, err
	}
	if pub == nil {
		return nil, errNoPlantKey
	}
	env, sealErr := sealPlantNonce([]byte(req.Nonce), pub.Bytes(), h.cfg.ID, req.WindowID)
	if sealErr != nil {
		return nil, fmt.Errorf("the hotel plant key could not be used")
	}
	body := map[string]any{"window_id": req.WindowID}
	for k, v := range env {
		body[k] = v
	}
	if req.EscapeFresh != nil {
		body["sandbox_id"] = req.SandboxID
		body["escape_fresh"] = req.EscapeFresh
	}
	return json.Marshal(body)
}

// escapeReceiptKey is the Ed25519 public key named by the attested binding.
// The key is trusted only when the AMD chain passed for this exact binding
// and the launch measurement is on sealed_measurements. That holds for
// every hotel kind: joined miners, joined non-miners, and config hotels,
// including one that skips admission with "sealed_admission": "off"
// (AB#596). Admission requires the AMD chain for every gated hotel; the plant
// path reuses checkAttestation / verifyAMDChain and fails closed if those
// checks have not passed.
func (b *broker) escapeReceiptKey(ctx context.Context, h *hotel) ([]byte, string, error) {
	if b.cfg.AMDVerifier == nil || len(b.sealedMeasurements()) == 0 {
		return nil, "", errUnverifiedAttest
	}
	b.mu.Lock()
	needs := b.needsAttestation(h)
	admitted := b.admitted(h, time.Now())
	stored := append([]byte(nil), h.adm.receiptKey...)
	bindingSHA := h.adm.bindingSHA
	measurement := h.adm.measurement
	amdOK := h.adm.amd != nil && h.adm.amdBinding == bindingSHA && bindingSHA != ""
	b.mu.Unlock()
	if needs && !admitted {
		return nil, "", errNotAdmitted
	}
	if len(stored) == ed25519.PublicKeySize && amdOK && inFold(b.sealedMeasurements(), measurement) {
		return stored, bindingSHA, nil
	}
	res, err := b.checkAttestation(ctx, h)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", errUnverifiedAttest, err)
	}
	if len(res.receiptKey) != ed25519.PublicKeySize {
		return nil, "", errNoReceiptKey
	}
	if res.amd == nil || res.amdBinding != res.bindingSHA || res.bindingSHA == "" {
		return nil, "", errUnverifiedAttest
	}
	if !inFold(b.sealedMeasurements(), res.measurement) {
		return nil, "", errUnverifiedAttest
	}
	return res.receiptKey, res.bindingSHA, nil
}

func (b *broker) fetchEscapePlantKey(ctx context.Context, h *hotel, receiptKey []byte, bindingSHA string) (*ecdh.PublicKey, error) {
	status, _, out, err := h.doBase(ctx, h.cfg.Health, "GET", "/room/escape-plant-key", nil, nil, plantHotelTimeout)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, errNoPlantKey
	}
	var doc escapePlantKey
	if json.Unmarshal(out, &doc) != nil {
		return nil, errBadPlantKey
	}
	pub, err := verifyPlantKey(doc, receiptKey, h.cfg.ID, bindingSHA)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func plantKeyStatement(doc escapePlantKey) ([]byte, error) {
	return json.Marshal(map[string]string{
		"algorithm":         doc.Algorithm,
		"binding_sha256":    doc.BindingSHA256,
		"hotel":             doc.Hotel,
		"purpose":           doc.Purpose,
		"x25519_public_b64": doc.X25519PublicB64,
	})
}

func verifyPlantKey(doc escapePlantKey, receiptKey []byte, hotelID, bindingSHA string) (*ecdh.PublicKey, error) {
	if len(receiptKey) != ed25519.PublicKeySize {
		return nil, errNoReceiptKey
	}
	if doc.Algorithm != plantAlgorithm || doc.Purpose != plantKeyPurpose || doc.X25519PublicB64 == "" {
		return nil, errBadPlantKey
	}
	if doc.Hotel != hotelID {
		return nil, errBadPlantKey
	}
	if bindingSHA != "" && !strings.EqualFold(doc.BindingSHA256, bindingSHA) {
		return nil, errBadPlantKey
	}
	if doc.SignatureB64 == "" {
		return nil, errBadPlantKey
	}
	sig, err := base64.StdEncoding.DecodeString(doc.SignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errBadPlantKey
	}
	msg, err := plantKeyStatement(doc)
	if err != nil {
		return nil, errBadPlantKey
	}
	if !ed25519.Verify(receiptKey, msg, sig) {
		return nil, errBadPlantKey
	}
	raw, err := base64.StdEncoding.DecodeString(doc.X25519PublicB64)
	if err != nil || len(raw) != 32 {
		return nil, errBadPlantKey
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, errBadPlantKey
	}
	return pub, nil
}

func plantAAD(hotel, windowID string) []byte {
	return []byte("escape-nonce-plant:" + hotel + ":" + windowID)
}

func sealPlantNonce(plaintext, recipientPub []byte, hotel, windowID string) (map[string]string, error) {
	return sealX25519Envelope(plaintext, recipientPub, plantHKDFInfo, plantAAD(hotel, windowID))
}

// sealX25519Envelope is room_receipts._seal_envelope: X25519 to the recipient,
// HKDF-SHA256 (salt = AAD, info = info || ephemeral || recipient), AES-256-GCM
// with the same AAD. The plant nonce and the hotel key install use it.
func sealX25519Envelope(plaintext, recipientPub, info, aad []byte) (map[string]string, error) {
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
	key := hkdfSHA256(shared, aad, append(append(append([]byte{}, info...), rawEph...), rawRec...), 32)
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
