package main

// DNS-01 challenge service for Preview URL certificates (AB#423).
//
// Decision (13 Nov): one Let's Encrypt wildcard per hotel, the private key made
// in the sealed guest, DNS-01 through our own challenge service that lets each
// hotel set only its own record. This is that service.
//
// PUT /v1/broker/acme-challenge carries no Bearer key. The hotel signs the raw
// body with its receipt key, the Ed25519 key its attested binding names, so
// only the measured code inside that guest can sign. The broker takes the key
// it stored at admission (never a live fetch: the route is unauthenticated)
// and trusts it under the escape-plant rule: AMD chain passed for this exact
// binding, measurement on sealed_measurements, hotel admitted now.
//
// The record name comes from broker config only: _acme-challenge.<hotel id>.
// <zone>, which is the DNS-01 name for both <id>.<zone> and *.<id>.<zone>.
// The zone must hold hotel names only: a miner picks its own hotel id, so a
// shared zone would let a miner named "www" prove www.<zone>.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	acmeDNSPurpose   = "cathedral-acme-dns01-v1"
	acmeDNSBodyMax   = 4096
	acmeDNSSkew      = 120 * time.Second
	acmeDNSMaxVals   = 2 // the wildcard and the bare name share one record name
	acmeDNSTTL       = 60
	acmeDNSSigHdr    = "X-Cathedral-Hotel-Signature"
	cloudflareAPI    = "https://api.cloudflare.com/client/v4"
	acmeDNSCFTimeout = 20 * time.Second
)

var (
	// The SHA-256 of a key authorization, base64url without padding (RFC 8555 8.4).
	acmeTXTRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	// One DNS label: the hotel id becomes <id>.<zone>.
	dnsLabelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	dnsZoneRE  = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
	cfZoneIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// acmeDNSConfig is "acme_dns" in the broker config. Absent: the route is off.
type acmeDNSConfig struct {
	// Zone holds hotel names only (see above), for example hotels.example.com.
	Zone             string `json:"zone"`
	CloudflareZoneID string `json:"cloudflare_zone_id"`
	// TokenFile: a Cloudflare API token with DNS edit on that zone only. Read
	// at each call so a rotation needs no restart; never logged.
	TokenFile string `json:"token_file"`
	// APIBase overrides the Cloudflare API base (tests). Must be https.
	APIBase string `json:"api_base,omitempty"`
}

func (c *acmeDNSConfig) validate() error {
	if c == nil {
		return nil
	}
	if !dnsZoneRE.MatchString(c.Zone) || len(c.Zone) > 200 {
		return errors.New("zone must be a lower-case DNS name")
	}
	if !cfZoneIDRE.MatchString(c.CloudflareZoneID) {
		return errors.New("cloudflare_zone_id must be 32 lower-case hex characters")
	}
	if c.TokenFile == "" {
		return errors.New("token_file is required")
	}
	if c.APIBase != "" {
		u, err := url.Parse(c.APIBase)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return errors.New("api_base must be an https URL")
		}
	}
	return nil
}

func (c *acmeDNSConfig) apiBase() string {
	if c.APIBase != "" {
		return strings.TrimRight(c.APIBase, "/")
	}
	return cloudflareAPI
}

// acmeDNSState serializes record changes and holds the last accepted ts per
// hotel (replay). In memory: after a restart a body signed within the skew
// window can be sent once more; it can only set that hotel's own record to
// values the hotel signed, and zone plus binding_sha256 in the body keep it
// to this broker and this boot.
type acmeDNSState struct {
	mu     sync.Mutex
	lastTS map[string]int64
	client *http.Client
}

type acmeChallengeRequest struct {
	Purpose    string   `json:"purpose"`
	Zone       string   `json:"zone"`
	Hotel      string   `json:"hotel"`
	BindingSHA string   `json:"binding_sha256"`
	Values     []string `json:"values"`
	TS         int64    `json:"ts"`
}

func acmeDNSSignedMessage(body []byte) []byte {
	return append([]byte(acmeDNSPurpose+"\n"), body...)
}

// acmeRecordName is the one TXT name a hotel may set.
func (c *acmeDNSConfig) acmeRecordName(hotelID string) string {
	return "_acme-challenge." + hotelID + "." + c.Zone
}

// acmeHotelKey is the stored receipt key and binding of h when they are
// trusted now, else nil. Caller must not hold b.mu.
func (b *broker) acmeHotelKey(h *hotel) (ed25519.PublicKey, string) {
	if b.cfg.AMDVerifier == nil || len(b.cfg.SealedMeasurements) == 0 || !h.cfg.Sealed {
		return nil, ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if h.leaving || !b.needsAttestation(h) || !b.admitted(h, time.Now()) {
		return nil, ""
	}
	bindingSHA := h.adm.bindingSHA
	amdOK := h.adm.amd != nil && h.adm.amdBinding == bindingSHA && bindingSHA != ""
	if len(h.adm.receiptKey) != ed25519.PublicKeySize || !amdOK || !inFold(b.cfg.SealedMeasurements, h.adm.measurement) {
		return nil, ""
	}
	return append(ed25519.PublicKey(nil), h.adm.receiptKey...), bindingSHA
}

// handleACMEChallenge serves PUT /v1/broker/acme-challenge.
func (b *broker) handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	c := b.cfg.ACMEDNS
	if c == nil {
		writeErr(w, 404, "not_enabled", "the DNS-01 challenge service is not configured on this broker")
		return
	}
	if r.Method != "PUT" {
		w.Header().Set("Allow", "PUT")
		writeErr(w, 405, "method_not_allowed", "use PUT")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, acmeDNSBodyMax))
	if err != nil {
		writeErr(w, 413, "body_too_large", fmt.Sprintf("body over %d bytes", acmeDNSBodyMax))
		return
	}
	var req acmeChallengeRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil {
		writeErr(w, 400, "invalid_json", "request body is not the challenge JSON")
		return
	}
	// One answer for every reason the signature cannot be trusted, so the
	// route tells an unauthenticated caller nothing about hotel ids or state.
	refuse := func() { writeErr(w, 403, "forbidden", "not a valid signed challenge from an admitted sealed hotel") }
	sig, err := base64.StdEncoding.DecodeString(r.Header.Get(acmeDNSSigHdr))
	if err != nil || len(sig) != ed25519.SignatureSize || req.Purpose != acmeDNSPurpose || req.Zone != c.Zone {
		refuse()
		return
	}
	h := b.hotelByID(req.Hotel)
	if h == nil {
		refuse()
		return
	}
	key, bindingSHA := b.acmeHotelKey(h)
	if key == nil || !strings.EqualFold(req.BindingSHA, bindingSHA) || !ed25519.Verify(key, acmeDNSSignedMessage(raw), sig) {
		refuse()
		return
	}
	// Signed by that hotel from here on: precise errors are fine.
	if !dnsLabelRE.MatchString(req.Hotel) {
		writeErr(w, 409, "hotel_id_not_dns_label", "the hotel id must be one lower-case DNS label to get a Preview URL name")
		return
	}
	if len(req.Values) > acmeDNSMaxVals {
		writeErr(w, 400, "invalid_request", fmt.Sprintf("at most %d values", acmeDNSMaxVals))
		return
	}
	for _, v := range req.Values {
		if !acmeTXTRE.MatchString(v) {
			writeErr(w, 400, "invalid_request", "each value is 43 characters of base64url (RFC 8555 8.4)")
			return
		}
	}
	now := time.Now()
	if d := now.Sub(time.Unix(req.TS, 0)); d > acmeDNSSkew || d < -acmeDNSSkew {
		writeErr(w, 400, "stale_request", "ts is more than 120 seconds from the broker clock")
		return
	}
	st := &b.acmeDNS
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.lastTS == nil {
		st.lastTS = map[string]int64{}
	}
	if req.TS <= st.lastTS[req.Hotel] {
		writeErr(w, 409, "replayed_request", "ts must be later than the last accepted request from this hotel")
		return
	}
	name := c.acmeRecordName(req.Hotel)
	ctx, cancel := context.WithTimeout(r.Context(), acmeDNSCFTimeout)
	defer cancel()
	if err := st.setTXT(ctx, c, name, req.Values); err != nil {
		log.Printf("acme-dns: hotel %s: %v", req.Hotel, err)
		writeErr(w, 502, "dns_update_failed", "the DNS provider did not accept the change; try again")
		return
	}
	st.lastTS[req.Hotel] = req.TS
	log.Printf("acme-dns: hotel %s set %d value(s) on %s", req.Hotel, len(req.Values), name)
	writeJSON(w, 200, map[string]any{"name": name, "values": len(req.Values)})
}

// setTXT makes the TXT records at name exactly values (none: removed).
func (st *acmeDNSState) setTXT(ctx context.Context, c *acmeDNSConfig, name string, values []string) error {
	tok, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return errors.New("token file unreadable")
	}
	token := strings.TrimSpace(string(tok))
	base := c.apiBase() + "/zones/" + c.CloudflareZoneID + "/dns_records"
	var list struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := st.cf(ctx, token, "GET", base+"?type=TXT&per_page=100&name="+url.QueryEscape(name), nil, &list); err != nil {
		return err
	}
	for _, rec := range list.Result {
		if err := st.cf(ctx, token, "DELETE", base+"/"+url.PathEscape(rec.ID), nil, nil); err != nil {
			return err
		}
	}
	for _, v := range values {
		body := map[string]any{"type": "TXT", "name": name, "content": v, "ttl": acmeDNSTTL}
		if err := st.cf(ctx, token, "POST", base, body, nil); err != nil {
			return err
		}
	}
	return nil
}

// cf makes one Cloudflare API call. Errors name the method and status only:
// a provider body can carry account details.
func (st *acmeDNSState) cf(ctx context.Context, token, method, u string, body, out any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := st.client
	if client == nil {
		client = &http.Client{Timeout: acmeDNSCFTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare %s: no answer", method)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("cloudflare %s: status %d", method, resp.StatusCode)
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return fmt.Errorf("cloudflare %s: unreadable answer", method)
	}
	return nil
}
