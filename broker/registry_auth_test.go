package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A create may carry the guest's own registry login in the object form of
// image (AB#817). The broker passes it to the hotel in the create bytes, only
// over an encrypted create leg, and never answers it back.

const testRegistryPassword = "dckr_pat_never-echo-this"

func authImage(ref string) map[string]any {
	return map[string]any{"image": ref, "registry_auth": map[string]any{"username": "const", "password": testRegistryPassword}}
}

// serveOverTLS moves hotel id's API to an https test server and makes the
// broker's client trust it, as an unsealed operator hotel behind TLS.
func serveOverTLS(t *testing.T, tc *testChain, id string) {
	t.Helper()
	ts := httptest.NewTLSServer(tc.hotels[id])
	t.Cleanup(ts.Close)
	h := tc.b.hotelByID(id)
	tc.b.mu.Lock()
	h.cfg.API = ts.URL
	h.client = ts.Client()
	tc.b.mu.Unlock()
}

func TestRegistryAuthCreateReachesAnEncryptedHotelUnchanged(t *testing.T) {
	tc := r6Chain(t, "", nil)
	serveOverTLS(t, tc, "c")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": authImage("acme/private:1")})
	if status != 202 || doc["hotel"] != "c" {
		t.Fatalf("create with registry_auth: %d %v", status, doc)
	}
	for _, id := range []string{"a", "b"} {
		if n := len(tc.hotels[id].creates); n != 0 {
			t.Fatalf("hotel %s (plain http) got %d creates carrying a login", id, n)
		}
	}
	f := tc.hotels["c"]
	f.mu.Lock()
	got := f.creates[0]["image"].(map[string]any)
	sent := string(f.createBodies[0])
	f.mu.Unlock()
	auth, _ := got["registry_auth"].(map[string]any)
	if got["image"] != "acme/private:1" || auth["username"] != "const" || auth["password"] != testRegistryPassword {
		t.Fatalf("hotel got image %v", got)
	}
	if !strings.Contains(sent, testRegistryPassword) {
		t.Fatalf("the login did not reach the hotel")
	}
	if strings.Contains(asJSON(doc), testRegistryPassword) {
		t.Fatalf("the create answer names the password")
	}
}

func TestRegistryAuthCreateRefusedWithoutAnEncryptedHotel(t *testing.T) {
	tc := r6Chain(t, "", nil)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": authImage("acme/private:1")})
	if status != 409 || errCode(doc) != "registry_auth_needs_encrypted_hotel" {
		t.Fatalf("want 409 registry_auth_needs_encrypted_hotel, got %d %v", status, doc)
	}
	if n := hotelCreates(tc); n != 0 {
		t.Fatalf("a login reached a plain http hotel %d times", n)
	}
}

// The object form names a local snapshot image the same way the string form does.
func TestRegistryAuthObjectFormKeepsTheLocalImageRefusal(t *testing.T) {
	tc := r6Chain(t, "", nil)
	serveOverTLS(t, tc, "c")
	for _, img := range []map[string]any{authImage(snapRef + ":latest"), {"image": "sha256:" + hexID}} {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": img})
		if status != 422 {
			t.Fatalf("image %v: want 422, got %d %v", img["image"], status, doc)
		}
	}
	if n := hotelCreates(tc); n != 0 {
		t.Fatalf("a refused create reached a hotel %d times", n)
	}
}

func TestRegistryAuthShapeChecked(t *testing.T) {
	tc := r6Chain(t, "", nil)
	serveOverTLS(t, tc, "c")
	for _, auth := range []any{
		"const:" + testRegistryPassword,
		map[string]any{"username": "const"},
		map[string]any{"username": "", "password": testRegistryPassword},
		map[string]any{"username": "const", "password": testRegistryPassword, "registry": "x"},
		map[string]any{"username": "const", "password": 7},
	} {
		body := map[string]any{"image": map[string]any{"image": "acme/private:1", "registry_auth": auth}}
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", body)
		if status != 400 || errCode(doc) != "invalid_registry_auth" {
			t.Fatalf("auth %v: want 400 invalid_registry_auth, got %d %v", auth, status, doc)
		}
		if strings.Contains(asJSON(doc), testRegistryPassword) {
			t.Fatalf("the refusal names the password")
		}
	}
	if n := hotelCreates(tc); n != 0 {
		t.Fatalf("a refused create reached a hotel %d times", n)
	}
}

// The create bytes hold the login: they are never returned.
func TestRegistryAuthCreateBytesNotReturned(t *testing.T) {
	tc := r6Chain(t, "", nil)
	serveOverTLS(t, tc, "c")
	raw := []byte(`{"image":{"image":"acme/private:1","registry_auth":{"username":"const","password":"` + testRegistryPassword + `"}}}`)
	req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set(returnCreateHeader, "1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 400 || !strings.Contains(string(out), "create_request_with_registry_auth") {
		t.Fatalf("want 400 create_request_with_registry_auth, got %d %s", resp.StatusCode, out)
	}
	if n := hotelCreates(tc); n != 0 {
		t.Fatalf("a refused create reached a hotel %d times", n)
	}
}

// With the guest's own login, the registry's rate limit is the guest's
// quota: the create stops on the first hotel and rests none.
func TestRegistryAuthRateLimitIsTheGuestsFault(t *testing.T) {
	tc := r6Chain(t, "", nil)
	serveOverTLS(t, tc, "b")
	serveOverTLS(t, tc, "c")
	tc.hotels["b"].pullLimited = true
	tc.hotels["c"].pullLimited = true
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": authImage("acme/private:1")})
	if status != 502 || errCode(doc) != "image_pull_failed" {
		t.Fatalf("rate limited pull: %d %v", status, doc)
	}
	if n := hotelCreates(tc); n != 1 {
		t.Fatalf("the create went to %d hotels, want 1", n)
	}
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	for _, id := range []string{"b", "c"} {
		if time.Now().Before(tc.b.hotelByID(id).backoffUntil) {
			t.Fatalf("hotel %s rested for the guest's own rate limit", id)
		}
	}
}

// Without a login the registry's rate limit is the hotel's, as before.
func TestAnonymousRateLimitStillRestsTheHotel(t *testing.T) {
	tc := r6Chain(t, "", nil)
	tc.hotels["b"].pullLimited = true
	status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if status != 502 {
		t.Fatalf("rate limited anonymous pull: %d", status)
	}
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	if !time.Now().Before(tc.b.hotelByID("b").backoffUntil) {
		t.Fatalf("an anonymous rate limit did not rest the hotel")
	}
}

func TestEncryptedCreateLeg(t *testing.T) {
	for _, c := range []struct {
		name string
		hc   hotelConfig
		want bool
	}{
		{"unsealed https", hotelConfig{API: "https://h:8443"}, true},
		{"unsealed http", hotelConfig{API: "http://h:8080"}, false},
		{"sealed config, host TLS", hotelConfig{API: "https://h:8443", Sealed: true}, false},
		{"sealed label, host TLS", hotelConfig{API: "https://h:8443", Labels: map[string]string{"sealed": "true"}}, false},
		{"sealed guest TLS", hotelConfig{API: "https://h:8443", Sealed: true, GuestTLS: true}, true},
		{"miner guest TLS", hotelConfig{API: "https://h:8443", Sealed: true, MinerHotkey: "5abc"}, true},
	} {
		if got := encryptedCreateLeg(&hotel{cfg: c.hc}); got != c.want {
			t.Errorf("%s: encryptedCreateLeg = %v, want %v", c.name, got, c.want)
		}
	}
}

func asJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
