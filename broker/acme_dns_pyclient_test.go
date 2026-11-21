package main

// Cross-checks the guest's ACME DNS-01 client (room-kit/room_acme.py, AB#422)
// against this handler. The static vector is made by that client with a fixed
// key and ts (tests/test_ab422_acme_client.py checks the client still makes
// exactly these bytes); a vector named by ACME_PY_VECTOR is made fresh by the
// Python test, so its ts is current and the whole handler can accept it.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"testing"
)

type pyACMEVector struct {
	PublicKeyB64 string   `json:"public_key_b64"`
	BodyB64      string   `json:"body_b64"`
	SignatureB64 string   `json:"signature_b64"`
	Values       []string `json:"values"`
}

func loadPyACMEVector(t *testing.T, path string) (ed25519.PublicKey, []byte, string, []string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v pyACMEVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(v.PublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key: %v", err)
	}
	body, err := base64.StdEncoding.DecodeString(v.BodyB64)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PublicKey(pub), body, v.SignatureB64, v.Values
}

func TestACMEDNSPythonClientStaticVector(t *testing.T) {
	pub, body, sigB64, values := loadPyACMEVector(t, "../tests/vectors/acme_dns01_v1.json")
	var req acmeChallengeRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		t.Fatalf("the handler would refuse the body: %v", err)
	}
	if req.Purpose != acmeDNSPurpose || req.Hotel != "a" || req.Zone != acmeTestZone || req.BindingSHA != acmeTestBind {
		t.Fatalf("body fields: %+v", req)
	}
	for _, v := range req.Values {
		if !acmeTXTRE.MatchString(v) {
			t.Fatalf("value %q is not a DNS-01 digest", v)
		}
	}
	if len(req.Values) != len(values) {
		t.Fatalf("values: %v vs %v", req.Values, values)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature header is not standard base64 of 64 bytes: %v", err)
	}
	if !ed25519.Verify(pub, acmeDNSSignedMessage(body), sig) {
		t.Fatal("the signature does not verify over the purpose line and the raw body")
	}
}

func TestACMEDNSPythonClientFreshVector(t *testing.T) {
	path := os.Getenv("ACME_PY_VECTOR")
	if path == "" {
		t.Skip("ACME_PY_VECTOR not set (tests/test_ab422_acme_client.py sets it)")
	}
	pub, body, sigB64, values := loadPyACMEVector(t, path)
	a := newACMETest(t)
	a.tc.b.mu.Lock()
	a.tc.b.hotelByID("a").adm.receiptKey = append([]byte(nil), pub...)
	a.tc.b.mu.Unlock()
	req, _ := http.NewRequest("PUT", a.tc.srv.URL+"/v1/broker/acme-challenge", bytes.NewReader(body))
	req.Header.Set(acmeDNSSigHdr, sigB64)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if resp.StatusCode != 200 {
		t.Fatalf("the handler refused the Python client's request: %d %v", resp.StatusCode, doc)
	}
	got := a.cf.txt("_acme-challenge.a." + acmeTestZone)
	sort.Strings(got)
	want := append([]string(nil), values...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("records %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("records %v, want %v", got, want)
		}
	}
}
