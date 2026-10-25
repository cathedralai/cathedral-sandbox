package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func (tc *testChain) postRaw(t *testing.T, key, path string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest("POST", tc.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, raw
}

func TestHotelAttestPassesBodyAndAnswerUnchanged(t *testing.T) {
	tc := newChain(t)
	in := []byte(`{"report_data_hex":"` + strings.Repeat("ab", 64) + `"}`)
	resp, out := tc.postRaw(t, "key1", "/v1/hotels/a/attest", in)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, out)
	}
	f := tc.hotels["a"]
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.attestIn) != 1 || !bytes.Equal(f.attestIn[0], in) {
		t.Fatalf("hotel got %q, want %q", f.attestIn, in)
	}
	if f.attestAuth[0] != "Bearer hotel-key" {
		t.Fatalf("hotel auth %q: the broker must use the hotel key, not the guest key", f.attestAuth[0])
	}
	want := `{"report_b64":"UkVQT1JU","cert_chain_b64":null,"binding_sha256":"bb","measurement":"aa","generated_at":1761400000,"echo":` + `"{\"report_data_hex\":\"` + strings.Repeat("ab", 64) + `\"}"}`
	if string(out) != want {
		t.Fatalf("answer changed:\n got %s\nwant %s", out, want)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
}

func TestHotelAttestPassesHotelErrorsThrough(t *testing.T) {
	tc := newChain(t)
	resp, out := tc.postRaw(t, "key1", "/v1/hotels/a/attest", []byte(`{"report_data_hex":"slow-down"}`))
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") != "17" || !bytes.Contains(out, []byte("attest_rate_limit")) {
		t.Fatalf("429 not passed through: %d %q %s", resp.StatusCode, resp.Header.Get("Retry-After"), out)
	}
}

func TestHotelAttestNeedsAGuestKey(t *testing.T) {
	tc := newChain(t)
	for _, key := range []string{"", "nope", "operator-key"} {
		resp, _ := tc.postRaw(t, key, "/v1/hotels/a/attest", []byte(`{}`))
		if resp.StatusCode != 401 {
			t.Fatalf("key %q: status %d", key, resp.StatusCode)
		}
	}
	if n := len(tc.hotels["a"].attestIn); n != 0 {
		t.Fatalf("hotel asked %d time(s) without a guest key", n)
	}
}

func TestHotelAttestOutsideTheGuestListIs404(t *testing.T) {
	tc := newChain(t)
	tc.b.guests["g1"].limits = guestLimits{Hotels: []string{"b"}}
	resp, _ := tc.postRaw(t, "key1", "/v1/hotels/a/attest", []byte(`{"report_data_hex":"`+strings.Repeat("00", 64)+`"}`))
	if resp.StatusCode != 404 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if n := len(tc.hotels["a"].attestIn); n != 0 {
		t.Fatalf("hotel outside the guest's list was asked %d time(s)", n)
	}
	// The other guest, with every hotel, still gets through.
	if resp, out := tc.postRaw(t, "key2", "/v1/hotels/a/attest", []byte(`{}`)); resp.StatusCode != 200 {
		t.Fatalf("guest g2: %d %s", resp.StatusCode, out)
	}
}

func TestHotelAttestRefusesOtherMethodsAndBigBodies(t *testing.T) {
	tc := newChain(t)
	if status, _ := tc.body(t, "key1", "GET", "/v1/hotels/a/attest"); status != 404 {
		t.Fatalf("GET attest: %d", status)
	}
	if status, _ := tc.body(t, "key1", "POST", "/v1/hotels/nosuch/attest"); status != 404 {
		t.Fatalf("unknown hotel: %d", status)
	}
	resp, _ := tc.postRaw(t, "key1", "/v1/hotels/a/attest", bytes.Repeat([]byte("a"), hotelAttestBodyMax+1))
	if resp.StatusCode != 413 {
		t.Fatalf("big body: %d", resp.StatusCode)
	}
	if n := len(tc.hotels["a"].attestIn); n != 0 {
		t.Fatalf("hotel asked %d time(s)", n)
	}
}
