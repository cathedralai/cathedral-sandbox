package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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

// pinMinerTransport checks every TLS connection, including resumed ones.
// The room-kit guest uses a self-issued cert, so SPKI in the SNP binding is
// the trust anchor. The caller must verify that binding before using this.
func pinMinerTransport(tr *http.Transport, pin string) error {
	want, err := hex.DecodeString(pin)
	if err != nil || len(want) != sha256.Size || pin != strings.ToLower(pin) {
		return errors.New("miner TLS SPKI pin must be 64 lower-case hex characters")
	}
	tr.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // VerifyConnection pins the attested guest on every connection
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("miner TLS peer has no certificate")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], want) != 1 {
				return fmt.Errorf("miner TLS peer is not the attested guest")
			}
			return nil
		},
	}
	return nil
}

func pinMinerHotel(h *hotel) error {
	if h.cfg.MinerHotkey == "" {
		return nil
	}
	if h.cfg.TLSSPKISHA256 == "" {
		return errors.New("miner hotel has no attested TLS SPKI pin")
	}
	for _, client := range []*http.Client{h.client, h.ctl} {
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			return errors.New("miner hotel has no HTTP transport")
		}
		if err := pinMinerTransport(tr, h.cfg.TLSSPKISHA256); err != nil {
			return err
		}
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return nil
}
