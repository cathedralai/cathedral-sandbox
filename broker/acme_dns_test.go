package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	acmeTestZone   = "hotels.example.com"
	acmeTestZoneID = "0123456789abcdef0123456789abcdef"
	acmeTestToken  = "cf-test-token"
	acmeTestBind   = "1111111111111111111111111111111111111111111111111111111111111111"
)

// fakeCloudflare keeps TXT records by name, the way the DNS records API does.
type fakeCloudflare struct {
	mu      sync.Mutex
	next    int
	records map[string]map[string]string // name -> id -> content
	calls   []string
	fail    bool
}

func (f *fakeCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method)
	if r.Header.Get("Authorization") != "Bearer "+acmeTestToken || f.fail {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"account 42 secret detail"}]}`))
		return
	}
	prefix := "/zones/" + acmeTestZoneID + "/dns_records"
	switch {
	case r.Method == "GET" && r.URL.Path == prefix:
		var out []map[string]string
		for id := range f.records[r.URL.Query().Get("name")] {
			out = append(out, map[string]string{"id": id})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": out})
	case r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, prefix+"/"):
		id := strings.TrimPrefix(r.URL.Path, prefix+"/")
		for _, recs := range f.records {
			delete(recs, id)
		}
		_, _ = w.Write([]byte(`{"success":true}`))
	case r.Method == "POST" && r.URL.Path == prefix:
		var rec struct{ Type, Name, Content string }
		_ = json.NewDecoder(r.Body).Decode(&rec)
		if rec.Type != "TXT" {
			w.WriteHeader(400)
			return
		}
		f.next++
		if f.records[rec.Name] == nil {
			f.records[rec.Name] = map[string]string{}
		}
		f.records[rec.Name][fmt.Sprint(f.next)] = rec.Content
		_, _ = w.Write([]byte(`{"success":true}`))
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeCloudflare) txt(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, v := range f.records[name] {
		out = append(out, v)
	}
	return out
}

type acmeTest struct {
	tc   *testChain
	cf   *fakeCloudflare
	priv ed25519.PrivateKey
	ts   int64
}

// newACMETest: broker with acme_dns on, hotel "a" an admitted sealed hotel
// whose binding names a receipt key the test holds.
func newACMETest(t *testing.T) *acmeTest {
	t.Helper()
	tc := newChain(t)
	cf := &fakeCloudflare{records: map[string]map[string]string{}}
	srv := httptest.NewTLSServer(cf)
	t.Cleanup(srv.Close)
	tok := filepath.Join(t.TempDir(), "cf.token")
	if err := os.WriteFile(tok, []byte(acmeTestToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &acmeDNSConfig{Zone: acmeTestZone, CloudflareZoneID: acmeTestZoneID, TokenFile: tok, APIBase: srv.URL}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tc.b.mu.Lock()
	tc.b.cfg.ACMEDNS = c
	tc.b.acmeDNS.client = srv.Client()
	h := tc.b.hotelByID("a")
	h.cfg.Sealed = true
	h.adm.receiptKey = append([]byte(nil), pub...)
	h.adm.bindingSHA = acmeTestBind
	h.adm.measurement = strings.Repeat("ab", 48)
	h.adm.amd = map[string]any{"product": "Genoa", "ark_sha256": testARKPin}
	h.adm.amdBinding = acmeTestBind
	h.adm.attestedAt = time.Now()
	tc.b.mu.Unlock()
	return &acmeTest{tc: tc, cf: cf, priv: priv, ts: time.Now().Unix() - 60}
}

func (a *acmeTest) body(hotel string, values ...string) map[string]any {
	a.ts++
	if values == nil {
		values = []string{}
	}
	return map[string]any{"purpose": acmeDNSPurpose, "zone": acmeTestZone, "hotel": hotel,
		"binding_sha256": acmeTestBind, "values": values, "ts": a.ts}
}

func (a *acmeTest) put(t *testing.T, priv ed25519.PrivateKey, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	return a.putRaw(t, priv, raw)
}

func (a *acmeTest) putRaw(t *testing.T, priv ed25519.PrivateKey, raw []byte) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("PUT", a.tc.srv.URL+"/v1/broker/acme-challenge", bytes.NewReader(raw))
	if priv != nil {
		req.Header.Set(acmeDNSSigHdr, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, acmeDNSSignedMessage(raw))))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, doc
}

var (
	acmeVal1 = strings.Repeat("A", 42) + "1"
	acmeVal2 = strings.Repeat("b", 42) + "_"
)

func TestACMEChallengeSetsAndClearsOnlyTheHotelsOwnRecord(t *testing.T) {
	a := newACMETest(t)
	name := "_acme-challenge.a." + acmeTestZone
	status, doc := a.put(t, a.priv, a.body("a", acmeVal1, acmeVal2))
	if status != 200 || doc["name"] != name {
		t.Fatalf("set: %d %v", status, doc)
	}
	if got := a.cf.txt(name); len(got) != 2 {
		t.Fatalf("records: %v", got)
	}
	status, _ = a.put(t, a.priv, a.body("a", acmeVal2))
	if got := a.cf.txt(name); status != 200 || len(got) != 1 || got[0] != acmeVal2 {
		t.Fatalf("replace: %d %v", status, got)
	}
	status, _ = a.put(t, a.priv, a.body("a"))
	if got := a.cf.txt(name); status != 200 || len(got) != 0 {
		t.Fatalf("clear: %d %v", status, got)
	}
	for n := range a.cf.records {
		if n != name {
			t.Fatalf("touched another name: %s", n)
		}
	}
}

func TestACMEChallengeRefusesEveryUntrustedSignatureAlike(t *testing.T) {
	a := newACMETest(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	wrongZone := a.body("a", acmeVal1)
	wrongZone["zone"] = "other.example.com"
	wrongBinding := a.body("a", acmeVal1)
	wrongBinding["binding_sha256"] = strings.Repeat("2", 64)
	wrongPurpose := a.body("a", acmeVal1)
	wrongPurpose["purpose"] = "receipt"
	cases := map[string]struct {
		priv ed25519.PrivateKey
		body map[string]any
	}{
		"no signature":           {nil, a.body("a", acmeVal1)},
		"another key":            {other, a.body("a", acmeVal1)},
		"another hotel's record": {a.priv, a.body("b", acmeVal1)}, // b names no receipt key
		"unknown hotel":          {a.priv, a.body("nope", acmeVal1)},
		"another zone":           {a.priv, wrongZone},
		"another boot":           {a.priv, wrongBinding},
		"another purpose":        {a.priv, wrongPurpose},
	}
	for label, c := range cases {
		status, doc := a.put(t, c.priv, c.body)
		if status != 403 || errCode(doc) != "forbidden" {
			t.Fatalf("%s: %d %v", label, status, doc)
		}
	}
	// A signature over a different body does not carry over.
	raw, _ := json.Marshal(a.body("a", acmeVal1))
	req, _ := http.NewRequest("PUT", a.tc.srv.URL+"/v1/broker/acme-challenge", bytes.NewReader(raw))
	req.Header.Set(acmeDNSSigHdr, base64.StdEncoding.EncodeToString(ed25519.Sign(a.priv, raw))) // no purpose prefix
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("unprefixed signature: %d", resp.StatusCode)
	}
	if len(a.cf.calls) != 0 {
		t.Fatalf("DNS provider called: %v", a.cf.calls)
	}
}

func TestACMEChallengeNeedsATrustedAdmissionNow(t *testing.T) {
	steps := map[string]func(b *broker, h *hotel){
		"attestation expired":     func(b *broker, h *hotel) { h.adm.attestedAt = time.Now().Add(-time.Hour) },
		"amd chain for old boot":  func(b *broker, h *hotel) { h.adm.amdBinding = strings.Repeat("3", 64) },
		"measurement not listed":  func(b *broker, h *hotel) { h.adm.measurement = strings.Repeat("cd", 48) },
		"not sealed":              func(b *broker, h *hotel) { h.cfg.Sealed = false },
		"leaving":                 func(b *broker, h *hotel) { h.leaving = true },
		"admission off":           func(b *broker, h *hotel) { h.cfg.SealedAdmission = sealedAdmissionOff },
		"no amd verifier":         func(b *broker, h *hotel) { b.cfg.AMDVerifier = nil },
		"short receipt key":       func(b *broker, h *hotel) { h.adm.receiptKey = h.adm.receiptKey[:16] },
		"no sealed measurements":  func(b *broker, h *hotel) { b.cfg.SealedMeasurements = nil },
		"no amd result for chain": func(b *broker, h *hotel) { h.adm.amd = nil },
	}
	for label, step := range steps {
		a := newACMETest(t)
		a.tc.b.mu.Lock()
		step(a.tc.b, a.tc.b.hotelByID("a"))
		a.tc.b.mu.Unlock()
		status, doc := a.put(t, a.priv, a.body("a", acmeVal1))
		if status != 403 || errCode(doc) != "forbidden" {
			t.Fatalf("%s: %d %v", label, status, doc)
		}
		if len(a.cf.calls) != 0 {
			t.Fatalf("%s: DNS provider called", label)
		}
	}
}

func TestACMEChallengeRefusesReplayStaleAndBadValues(t *testing.T) {
	a := newACMETest(t)
	first := a.body("a", acmeVal1)
	raw, _ := json.Marshal(first)
	if status, doc := a.putRaw(t, a.priv, raw); status != 200 {
		t.Fatalf("first: %d %v", status, doc)
	}
	if status, doc := a.putRaw(t, a.priv, raw); status != 409 || errCode(doc) != "replayed_request" {
		t.Fatalf("replay: %d %v", status, doc)
	}
	old := a.body("a", acmeVal1)
	old["ts"] = time.Now().Add(-10 * time.Minute).Unix()
	if status, doc := a.put(t, a.priv, old); status != 400 || errCode(doc) != "stale_request" {
		t.Fatalf("stale: %d %v", status, doc)
	}
	future := a.body("a", acmeVal1)
	future["ts"] = time.Now().Add(10 * time.Minute).Unix()
	if status, doc := a.put(t, a.priv, future); status != 400 || errCode(doc) != "stale_request" {
		t.Fatalf("future: %d %v", status, doc)
	}
	for _, bad := range [][]string{{"short"}, {acmeVal1 + "x"}, {strings.Repeat("A", 42) + "="}, {acmeVal1, acmeVal1, acmeVal2}} {
		if status, doc := a.put(t, a.priv, a.body("a", bad...)); status != 400 || errCode(doc) != "invalid_request" {
			t.Fatalf("values %v: %d %v", bad, status, doc)
		}
	}
	extra := a.body("a", acmeVal1)
	extra["name"] = "_acme-challenge.www." + acmeTestZone
	if status, doc := a.put(t, a.priv, extra); status != 400 || errCode(doc) != "invalid_json" {
		t.Fatalf("unknown field: %d %v", status, doc)
	}
	if got := a.cf.txt("_acme-challenge.a." + acmeTestZone); len(got) != 1 || got[0] != acmeVal1 {
		t.Fatalf("records changed: %v", got)
	}
}

func TestACMEChallengeProviderFailureIsNotAcceptedAndLeaksNothing(t *testing.T) {
	a := newACMETest(t)
	a.cf.mu.Lock()
	a.cf.fail = true
	a.cf.mu.Unlock()
	body := a.body("a", acmeVal1)
	status, doc := a.put(t, a.priv, body)
	if status != 502 || errCode(doc) != "dns_update_failed" {
		t.Fatalf("fail: %d %v", status, doc)
	}
	if raw, _ := json.Marshal(doc); bytes.Contains(raw, []byte("secret")) || bytes.Contains(raw, []byte(acmeTestZoneID)) {
		t.Fatalf("provider detail in answer: %s", raw)
	}
	// The same ts may be sent again once the provider is back.
	a.cf.mu.Lock()
	a.cf.fail = false
	a.cf.mu.Unlock()
	if status, doc := a.put(t, a.priv, body); status != 200 {
		t.Fatalf("retry: %d %v", status, doc)
	}
}

func TestACMEChallengeOffWithoutConfigAndPutOnly(t *testing.T) {
	a := newACMETest(t)
	if status, doc := a.tc.call(t, "", "GET", "/v1/broker/acme-challenge", nil); status != 405 {
		t.Fatalf("GET: %d %v", status, doc)
	}
	a.tc.b.mu.Lock()
	a.tc.b.cfg.ACMEDNS = nil
	a.tc.b.mu.Unlock()
	if status, doc := a.put(t, a.priv, a.body("a", acmeVal1)); status != 404 || errCode(doc) != "not_enabled" {
		t.Fatalf("off: %d %v", status, doc)
	}
}

func TestACMEDNSConfigValidation(t *testing.T) {
	good := acmeDNSConfig{Zone: acmeTestZone, CloudflareZoneID: acmeTestZoneID, TokenFile: "/x"}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	for label, mut := range map[string]func(c *acmeDNSConfig){
		"upper zone":  func(c *acmeDNSConfig) { c.Zone = "Hotels.example.com" },
		"bare label":  func(c *acmeDNSConfig) { c.Zone = "hotels" },
		"zone id":     func(c *acmeDNSConfig) { c.CloudflareZoneID = "xyz" },
		"no token":    func(c *acmeDNSConfig) { c.TokenFile = "" },
		"http base":   func(c *acmeDNSConfig) { c.APIBase = "http://api.example.com" },
		"broken base": func(c *acmeDNSConfig) { c.APIBase = "https://" },
	} {
		c := good
		mut(&c)
		if c.validate() == nil {
			t.Fatalf("%s: accepted", label)
		}
	}
}
