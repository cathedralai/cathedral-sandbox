package main

// Config hotel key installer (AB#817, docs/CONFIG_HOTEL_KEY_INSTALLER.md).
//
// A "guest_tls" config hotel's guest (room-kit SEALED_MINER=1) holds no hotel
// key at boot: it accepts one only through POST /room/hotel-key, sealed to the
// install key its attested binding names and signed by a pinned install
// signer. The control plane installs keys into miner hotels only. For config
// hotels the broker does it: it already holds the key (key_file) and already
// verifies and pins the guest's TLS key, so no new party learns the key.
//
// The install runs right after syncGuestPin pins a new attested key (a reboot
// or a receipts restart makes one) and again on every pin recheck while the
// current pin has no good install (a lost answer, a refusal). Admission waits
// for it. Nothing here logs the key, the seed or the envelope.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	installSchema   = "cathedral_hotel_key_install_v1"
	installPurpose  = "hotel-key-install"
	installHTTPWait = 10 * time.Second
)

var (
	installHKDFInfo = []byte("cathedral.hotel-key-install.v1")
	// The guest's HOTEL_KEY_RE (room_receipts.py): a key outside it is refused there.
	installableKey = regexp.MustCompile(`^[A-Za-z0-9_-]{32,256}$`)
)

// keyInstall is a config hotel's install state. Guarded by broker.mu.
type keyInstall struct {
	pin        string // guest TLS pin hex the current key was installed for; "" none
	keySHA     string // sha256 hex of the installed key
	lastIssued int64  // issued_at of the last request sent; the next is greater
	err        string // code of the last failed install; "" after a good one
	at         time.Time
}

// loadInstallSigner reads hotel_key_install_signing_key_file: base64 of a
// 32-byte Ed25519 seed, readable by the owner only.
func loadInstallSigner(hc hotelConfig) (ed25519.PrivateKey, error) {
	if hc.HotelKeyInstallSigningKeyFile == "" {
		return nil, nil
	}
	if !hc.GuestTLS {
		return nil, fmt.Errorf(`config: hotel %q: hotel_key_install_signing_key_file needs "guest_tls": true`, hc.ID)
	}
	st, err := os.Stat(hc.HotelKeyInstallSigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("config: hotel %q: hotel key install signer: %w", hc.ID, err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("config: hotel %q: hotel_key_install_signing_key_file must be mode 600", hc.ID)
	}
	raw, err := os.ReadFile(hc.HotelKeyInstallSigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("config: hotel %q: hotel key install signer: %w", hc.ID, err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("config: hotel %q: hotel_key_install_signing_key_file must hold base64 of a 32-byte Ed25519 seed", hc.ID)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func installSignerPublicB64(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}

// installBinding is the part of the attested binding the installer reads.
type installBinding struct {
	Hotel         string   `json:"hotel"`
	ReceiptKeyB64 string   `json:"receipt_key_ed25519_b64"`
	TLSSPKISHA256 string   `json:"tls_spki_sha256"`
	InstallX25519 string   `json:"hotel_key_install_x25519_b64"`
	Signers       []string `json:"hotel_key_install_signers_ed25519_b64"`
	KeySource     string   `json:"hotel_key_source"`
}

type installKeyDoc struct {
	Algorithm       string `json:"algorithm"`
	BindingSHA256   string `json:"binding_sha256"`
	Purpose         string `json:"purpose"`
	X25519PublicB64 string `json:"x25519_public_b64"`
	SignatureB64    string `json:"signature_b64"`
}

// installRefusal is a failed install, named by a short code only.
type installRefusal struct{ code string }

func (e installRefusal) Error() string { return "hotel key install: " + e.code }

func refuse(code string) error { return installRefusal{code} }

// canonicalJSON is room_receipts.canonical for the ASCII documents of this
// protocol: sorted keys (encoding/json sorts map keys), no spaces, no HTML
// escaping.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// installNeeded reports whether h has an installer and no good install on
// its current pin. Caller holds b.mu.
func (h *hotel) installNeeded() bool {
	return h.installer != nil && h.keyInst.pin != h.pinHex()
}

// installHotelKey installs h's key into the guest whose attestation raw the
// caller verified (verifyMinerBootstrap) for the pin peerSPKI, which must be
// h's current pin. A failure is logged once per code and leaves the hotel
// unadmitted; the next pin recheck tries again.
func (b *broker) installHotelKey(ctx context.Context, h *hotel, raw []byte, peerSPKI string) {
	if h.installer == nil {
		return
	}
	keySHA, err := b.sendHotelKeyInstall(ctx, h, raw, peerSPKI)
	b.mu.Lock()
	defer b.mu.Unlock()
	h.keyInst.at = time.Now()
	if err != nil {
		code := err.Error()
		var r installRefusal
		if errors.As(err, &r) {
			code = r.code
		} else {
			code = "install_unreachable"
		}
		if h.keyInst.err != code {
			log.Printf("hotel %s: hotel key not installed in the guest: %s", h.cfg.ID, code)
		}
		h.keyInst.err = code
		return
	}
	if h.pinHex() != peerSPKI {
		return // re-pinned while this ran; the next recheck installs for the new pin
	}
	h.keyInst.pin, h.keyInst.keySHA, h.keyInst.err = peerSPKI, keySHA, ""
	// The install is the last step of a new boot: let the sync loop check
	// health and admission at once instead of at the next attest retry.
	h.adm.checkedAt = time.Time{}
	log.Printf("hotel %s: hotel key %s... installed in the guest on TLS key %s...", h.cfg.ID, keySHA[:12], peerSPKI[:16])
}

func (b *broker) sendHotelKeyInstall(ctx context.Context, h *hotel, raw []byte, peerSPKI string) (string, error) {
	rawBinding := attestationBinding(raw)
	if len(rawBinding) == 0 {
		return "", refuse("install_no_binding")
	}
	sum := sha256.Sum256(rawBinding)
	bindingSHA := hex.EncodeToString(sum[:])
	var bd installBinding
	if json.Unmarshal(rawBinding, &bd) != nil {
		return "", refuse("install_no_binding")
	}
	if bd.Hotel != h.cfg.ID || bd.TLSSPKISHA256 != peerSPKI || bd.KeySource != "install" {
		return "", refuse("install_binding_mismatch")
	}
	signer := installSignerPublicB64(h.installer)
	pinned := false
	for _, s := range bd.Signers {
		pinned = pinned || s == signer
	}
	if !pinned {
		// The kit was built with other SEALED_HOTEL_KEY_INSTALL_SIGNERS.
		return "", refuse("install_signer_not_in_binding")
	}
	receiptKey, err := base64.StdEncoding.DecodeString(bd.ReceiptKeyB64)
	if err != nil || len(receiptKey) != ed25519.PublicKeySize {
		return "", refuse("install_no_receipt_key")
	}
	if !installableKey.MatchString(h.key) {
		return "", refuse("install_key_file_invalid")
	}

	status, out, err := h.installCall(ctx, "GET", "/room/hotel-key-install-key", nil)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", refuse(fmt.Sprintf("install_key_http_%d", status))
	}
	var doc installKeyDoc
	if json.Unmarshal(out, &doc) != nil {
		return "", refuse("install_key_invalid")
	}
	recipient, err := verifyInstallKey(doc, receiptKey, bindingSHA, bd.InstallX25519)
	if err != nil {
		return "", err
	}

	keySum := sha256.Sum256([]byte(h.key))
	keySHA := hex.EncodeToString(keySum[:])
	env, err := sealX25519Envelope([]byte(h.key), recipient.Bytes(), installHKDFInfo, []byte("hotel-key-install:"+bindingSHA))
	if err != nil {
		return "", refuse("install_seal_failed")
	}
	b.mu.Lock()
	issued := max(time.Now().Unix(), h.keyInst.lastIssued+1)
	h.keyInst.lastIssued = issued
	b.mu.Unlock()
	req := map[string]any{
		"schema":         installSchema,
		"binding_sha256": bindingSHA,
		"hotel_id":       h.cfg.ID,
		"key_sha256":     keySHA,
		"issued_at":      issued,
		"envelope":       env,
	}
	msg, err := canonicalJSON(req)
	if err != nil {
		return "", refuse("install_encode_failed")
	}
	req["signature_b64"] = base64.StdEncoding.EncodeToString(ed25519.Sign(h.installer, msg))
	body, err := canonicalJSON(req)
	if err != nil {
		return "", refuse("install_encode_failed")
	}
	status, out, err = h.installCall(ctx, "POST", "/room/hotel-key", body)
	if err != nil {
		return "", err
	}
	if status != 200 {
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(out, &e)
		if e.Error.Code == "" || !installCode.MatchString(e.Error.Code) {
			return "", refuse(fmt.Sprintf("install_http_%d", status))
		}
		return "", refuse(e.Error.Code)
	}
	var ans struct {
		KeySHA256 string `json:"key_sha256"`
		HotelID   string `json:"hotel_id"`
		IssuedAt  int64  `json:"issued_at"`
		Status    string `json:"status"`
	}
	if json.Unmarshal(out, &ans) != nil || ans.KeySHA256 != keySHA || ans.HotelID != h.cfg.ID || ans.IssuedAt != issued ||
		(ans.Status != "installed" && ans.Status != "unchanged") {
		return "", refuse("install_answer_invalid")
	}
	return keySHA, nil
}

var installCode = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)

// verifyInstallKey checks GET /room/hotel-key-install-key against the
// binding: the statement room_receipts.install_key_statement builds, signed
// by the binding's receipt key, for this binding and the install key the
// binding names.
func verifyInstallKey(doc installKeyDoc, receiptKey []byte, bindingSHA, bindingX25519 string) (*ecdh.PublicKey, error) {
	if doc.Algorithm != plantAlgorithm || doc.Purpose != installPurpose || doc.BindingSHA256 != bindingSHA ||
		doc.X25519PublicB64 == "" || doc.X25519PublicB64 != bindingX25519 {
		return nil, refuse("install_key_invalid")
	}
	sig, err := base64.StdEncoding.DecodeString(doc.SignatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, refuse("install_key_signature_invalid")
	}
	msg, err := canonicalJSON(map[string]string{
		"algorithm":         doc.Algorithm,
		"binding_sha256":    doc.BindingSHA256,
		"purpose":           doc.Purpose,
		"x25519_public_b64": doc.X25519PublicB64,
	})
	if err != nil || !ed25519.Verify(receiptKey, msg, sig) {
		return nil, refuse("install_key_signature_invalid")
	}
	rawPub, err := base64.StdEncoding.DecodeString(doc.X25519PublicB64)
	if err != nil || len(rawPub) != 32 {
		return nil, refuse("install_key_invalid")
	}
	pub, err := ecdh.X25519().NewPublicKey(rawPub)
	if err != nil {
		return nil, refuse("install_key_invalid")
	}
	return pub, nil
}

// installCall is one install request over the control client, which is
// pinned to the attested guest key. It carries no bearer: the guest has no
// key yet, and these two routes need none.
func (h *hotel) installCall(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	if err := h.keyedCallErr(h.cfg.Health); err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, installHTTPWait)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.cfg.Health+path, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.ctl.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, out, nil
}

// installDoc is the install part of a hotel document. Caller holds b.mu.
func (h *hotel) installDoc() map[string]any {
	if h.installer == nil {
		return nil
	}
	d := map[string]any{"signer_ed25519_b64": installSignerPublicB64(h.installer), "installed": h.keyInst.pin != "" && !h.installNeeded()}
	if h.keyInst.keySHA != "" {
		d["key_sha256_prefix"] = h.keyInst.keySHA[:12]
	}
	if h.keyInst.err != "" {
		d["error"] = h.keyInst.err
	}
	if !h.keyInst.at.IsZero() {
		d["at"] = h.keyInst.at.UTC().Format(time.RFC3339)
	}
	return d
}
