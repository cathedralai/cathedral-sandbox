package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// fetchMinerAttestation sends no hotel key. The certificate is not trusted
// until its observed SPKI is found in an AMD-verified SNP binding below.
func fetchMinerAttestation(ctx context.Context, origin string) ([]byte, string, error) {
	if !strings.HasPrefix(origin, "https://") {
		return nil, "", errors.New("miner attestation needs HTTPS")
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}} //nolint:gosec // no secret is sent; SNP binds the observed peer key
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", origin+"/room/attestation", nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, "", errors.New("miner guest did not answer attestation over TLS")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, "", errors.New("miner attestation is unreadable or too large")
	}
	sum := sha256.Sum256(resp.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	return raw, hex.EncodeToString(sum[:]), nil
}

// pinMinerTransport checks every TLS connection, including resumed ones,
// against one fixed pin. The room-kit guest uses a self-issued cert, so SPKI
// in the SNP binding is the trust anchor. The caller must verify that binding
// before using this.
func pinMinerTransport(tr *http.Transport, pin string) error {
	want, err := decodePin(pin)
	if err != nil {
		return err
	}
	var p atomic.Pointer[[sha256.Size]byte]
	p.Store(&want)
	pinTransport(tr, &p)
	return nil
}

func decodePin(pin string) ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != sha256.Size || pin != strings.ToLower(pin) {
		return out, errors.New("guest TLS SPKI pin must be 64 lower-case hex characters")
	}
	copy(out[:], want)
	return out, nil
}

// pinTransport makes tr accept only a peer whose SPKI is the current value of
// pin, read on every handshake. A nil pin refuses every handshake, so the
// request (and the hotel key on it) is never written.
func pinTransport(tr *http.Transport, pin *atomic.Pointer[[sha256.Size]byte]) {
	tr.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection pins the attested guest on every connection
		VerifyConnection: func(state tls.ConnectionState) error {
			want := pin.Load()
			if want == nil {
				return errGuestPinPending
			}
			if len(state.PeerCertificates) == 0 {
				return errors.New("guest TLS peer has no certificate")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], want[:]) != 1 {
				return fmt.Errorf("guest TLS peer is not the attested guest")
			}
			return nil
		},
	}
}

// errGuestPinPending: a guest TLS hotel whose attested TLS key the broker has
// not verified yet. No call carries the hotel key until it has.
var errGuestPinPending = errors.New("guest TLS hotel has no verified TLS pin yet; the hotel key is not sent")

// guestTLS reports whether h is reached only over its attested guest TLS key:
// a miner hotel, or a hotel with "guest_tls": true (AB#378). Both fields are
// fixed when the hotel is made, so no lock is needed.
func (h *hotel) guestTLS() bool {
	return h.cfg.MinerHotkey != "" || h.cfg.GuestTLS
}

// pinHex is the current guest TLS pin, "" when there is none.
func (h *hotel) pinHex() string {
	if p := h.guestPin.Load(); p != nil {
		return hex.EncodeToString(p[:])
	}
	return ""
}

// keyedCallErr is non-nil when a call to base must not carry the hotel key:
// a guest TLS hotel without a verified pin, or a base that is not HTTPS
// (VerifyConnection runs only on a TLS handshake).
func (h *hotel) keyedCallErr(base string) error {
	if !h.guestTLS() {
		return nil
	}
	if h.tlsPinErr != nil {
		return h.tlsPinErr
	}
	if h.guestPin.Load() == nil {
		return errGuestPinPending
	}
	if !strings.HasPrefix(base, "https://") {
		return errors.New("guest TLS hotel API requires attested HTTPS")
	}
	return nil
}

// pinMinerHotel pins both of a guest TLS hotel's clients to h.guestPin. A
// miner hotel must arrive with the pin its join verified (tlsPinErr
// otherwise, and it never gets one later). A "guest_tls" hotel may start
// without one: the sync loop verifies one keylessly (syncGuestPin).
func pinMinerHotel(h *hotel) error {
	if !h.guestTLS() {
		return nil
	}
	if h.cfg.TLSSPKISHA256 != "" {
		want, err := decodePin(h.cfg.TLSSPKISHA256)
		if err != nil {
			return err
		}
		h.guestPin.Store(&want)
	} else if h.cfg.MinerHotkey != "" {
		return errors.New("miner hotel has no attested TLS pin")
	}
	for _, client := range []*http.Client{h.client, h.ctl} {
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			return errors.New("guest TLS hotel has no HTTP transport")
		}
		pinTransport(tr, &h.guestPin)
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return nil
}

// guestPinRecheck is how often the sync loop asks a "guest_tls" hotel for its
// attestation again while the hotel does not answer on its pin.
const guestPinRecheck = attestRetry

// syncGuestPin verifies a "guest_tls" hotel's TLS key without sending the
// hotel key, and pins it: at the first sync, and after the hotel stopped
// answering on its pin (a reboot makes a new guest key). A new key is
// accepted only after the full check of verifyMinerBootstrap: the measurement
// allowlist, the binding and REPORT_DATA, the AMD chain, tls_spki_sha256
// equal to the key the TLS peer showed, and hotel_key_source "install". A
// miner hotel is never re-pinned here; it joins again.
func (b *broker) syncGuestPin(ctx context.Context, h *hotel) {
	if !h.cfg.GuestTLS || h.cfg.MinerHotkey != "" || h.tlsPinErr != nil {
		return
	}
	now := time.Now()
	cur := h.pinHex()
	b.mu.Lock()
	answering := !h.lastOK.IsZero() && now.Sub(h.lastOK) < guestPinRecheck
	due := now.Sub(h.pinCheckedAt) >= guestPinRecheck
	if (cur != "" && answering) || !due {
		b.mu.Unlock()
		return
	}
	h.pinCheckedAt = now
	b.mu.Unlock()
	fail := func(err error) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if h.pinErr != err.Error() {
			log.Printf("hotel %s: guest TLS pin not verified: %v", h.cfg.ID, err)
		}
		h.pinErr = err.Error()
	}
	raw, peerSPKI, err := fetchMinerAttestation(ctx, h.cfg.Health)
	if err != nil {
		fail(err)
		return
	}
	if peerSPKI == cur {
		return // the same verified key: the hotel is down or slow for another reason
	}
	if err := b.verifyMinerBootstrap(ctx, raw, peerSPKI); err != nil {
		fail(err)
		return
	}
	// A good guest is not enough: it must be this hotel's guest. The binding
	// names the hotel (the broker hotel id, which guest-boot.sh takes from
	// fw_cfg), and a re-pin must stay on the chip of the key it replaces, so
	// a host cannot route this hotel to another hotel's guest and receive
	// this hotel's key there.
	var bd snpBinding
	_ = json.Unmarshal(attestationBinding(raw), &bd)
	b.mu.Lock()
	prevChip := h.pinChip
	b.mu.Unlock()
	switch {
	case bd.Hotel != h.cfg.ID:
		fail(fmt.Errorf("the attested guest is hotel %q, not %q", bd.Hotel, h.cfg.ID))
		return
	case prevChip != "" && bd.ChipID != prevChip:
		fail(errors.New("the attested guest is on another chip than the key it would replace; restart the broker to move a hotel"))
		return
	}
	want, err := decodePin(peerSPKI)
	if err != nil {
		fail(err)
		return
	}
	h.guestPin.Store(&want)
	// Connections to the old key are dead after a reboot; drop the idle ones
	// so every new request handshakes against the new pin.
	for _, client := range []*http.Client{h.client, h.ctl} {
		if tr, ok := client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	b.mu.Lock()
	h.pinErr, h.pinChip = "", bd.ChipID
	// A new guest key is a new boot: admission starts again.
	h.adm.attestedAt, h.adm.checkedAt = time.Time{}, time.Time{}
	b.mu.Unlock()
	if cur == "" {
		log.Printf("hotel %s: guest TLS pinned to the attested key %s...", h.cfg.ID, peerSPKI[:16])
	} else {
		log.Printf("hotel %s: guest TLS key changed %s... -> %s... (new boot, verified); pinned", h.cfg.ID, cur[:16], peerSPKI[:16])
	}
}

// validateGuestTLS checks a config file hotel entry against "guest_tls" and
// the top-level require_sealed_guest_tls.
func validateGuestTLS(hc hotelConfig, required bool) error {
	if required && hc.Sealed && !hc.GuestTLS {
		return fmt.Errorf(`config: hotel %q: require_sealed_guest_tls is on, so a sealed hotel needs "guest_tls": true`, hc.ID)
	}
	if !hc.GuestTLS {
		return nil
	}
	switch {
	case !hc.Sealed:
		return fmt.Errorf(`config: hotel %q: guest_tls needs "sealed": true (only a sealed guest names its TLS key in an SNP binding)`, hc.ID)
	case hc.SealedAdmission == sealedAdmissionOff:
		return fmt.Errorf(`config: hotel %q: guest_tls needs the admission gate; remove sealed_admission "off"`, hc.ID)
	case hc.TLSSPKISHA256 != "":
		return fmt.Errorf(`config: hotel %q: tls_spki_sha256 is derived from the hotel's attestation; remove it`, hc.ID)
	case !strings.HasPrefix(hc.API, "https://") || !strings.HasPrefix(hc.Health, "https://"):
		return fmt.Errorf(`config: hotel %q: guest_tls needs https:// api and health`, hc.ID)
	}
	return nil
}

// attestationBinding is the binding of a GET /room/attestation body, nil when
// the body has none. Call it only on a body verifyMinerBootstrap passed.
func attestationBinding(raw []byte) []byte {
	var att struct {
		Binding json.RawMessage `json:"binding"`
	}
	if json.Unmarshal(raw, &att) != nil {
		return nil
	}
	return att.Binding
}
