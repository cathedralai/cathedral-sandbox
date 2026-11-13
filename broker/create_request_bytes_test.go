package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
)

// The caller of a native create can ask for the exact bytes the broker sent
// to the hotel (X-Broker-Return-Create-Request: 1), so it can check them
// against what the hotel signed. These tests pin that the returned bytes are
// the bytes the hotel received, through every path a create can take.

// createWithAsk posts a native create. ask sets the request header; extra
// headers are added as given.
func createWithAsk(t *testing.T, tc *testChain, body map[string]any, ask bool, ua string) (*http.Response, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer key1")
	if ask {
		req.Header.Set("X-Broker-Return-Create-Request", "1")
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(out, &doc)
	return resp, doc
}

func decodeCreateRequest(t *testing.T, doc map[string]any) []byte {
	t.Helper()
	s, ok := doc["create_request_b64"].(string)
	if !ok {
		t.Fatalf("answer has no create_request_b64: %v", doc)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("create_request_b64 is not standard base64: %v", err)
	}
	return raw
}

func lastCreateBody(f *fakeHotel) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.createBodies) == 0 {
		return nil
	}
	return f.createBodies[len(f.createBodies)-1]
}

func sameBytes(t *testing.T, got, want []byte) {
	t.Helper()
	if len(want) == 0 {
		t.Fatalf("the hotel got no create")
	}
	if sha256.Sum256(got) != sha256.Sum256(want) {
		t.Fatalf("returned bytes differ from what the hotel got:\n got  %s\n want %s", got, want)
	}
}

func TestCreateRequestBytesPlain(t *testing.T) {
	tc := newChain(t)
	resp, doc := createWithAsk(t, tc, map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}, true, "")
	if resp.StatusCode != 202 {
		t.Fatalf("create: %d %v", resp.StatusCode, doc)
	}
	sameBytes(t, decodeCreateRequest(t, doc), lastCreateBody(tc.hotels["b"]))
}

func TestCreateRequestBytesIncludeBrokerLabels(t *testing.T) {
	tc := newChain(t)
	resp, doc := createWithAsk(t, tc, map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "count": 1}, true, "")
	if resp.StatusCode != 202 {
		t.Fatalf("create: %d %v", resp.StatusCode, doc)
	}
	raw := decodeCreateRequest(t, doc)
	sameBytes(t, raw, lastCreateBody(tc.hotels["b"]))
	var sent map[string]any
	if err := json.Unmarshal(raw, &sent); err != nil {
		t.Fatal(err)
	}
	labels, _ := sent["labels"].(map[string]any)
	if labels[guestLabel] == nil || labels[batchLabel] == nil {
		t.Fatalf("broker labels missing from the returned bytes: %v", labels)
	}
	nw, _ := sent["network"].(map[string]any)
	if nw["mode"] != "deny_all" {
		t.Fatalf("network the caller left out is not the broker's deny_all object: %v", sent["network"])
	}
	for _, k := range []string{"sealed", "hotels", "count"} {
		if _, ok := sent[k]; ok {
			t.Fatalf("broker-only field %q is in the bytes sent to the hotel", k)
		}
	}
}

func TestCreateRequestBytesAfterRetryOnSecondHotel(t *testing.T) {
	tc := newChain(t)
	var failures int32 = 1
	for _, id := range []string{"b", "c"} {
		tc.hotels[id].failFirst = &failures
		tc.hotels[id].receiptTag = ":" + id
	}
	resp, doc := createWithAsk(t, tc, map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}, true, "")
	if resp.StatusCode != 202 {
		t.Fatalf("create after one 503: %d %v", resp.StatusCode, doc)
	}
	b, c := lastCreateBody(tc.hotels["b"]), lastCreateBody(tc.hotels["c"])
	if len(b) == 0 || len(c) == 0 {
		t.Fatalf("both hotels should have seen the create: b %d bytes, c %d bytes", len(b), len(c))
	}
	sameBytes(t, b, c)
	winner := resp.Header.Get("X-Broker-Hotel")
	if got := resp.Header.Get("X-Room-Receipt"); got != "signed-create:"+winner {
		t.Fatalf("receipt %q does not name the hotel %q that answered", got, winner)
	}
	sameBytes(t, decodeCreateRequest(t, doc), lastCreateBody(tc.hotels[winner]))
}

func TestCreateRequestBytesAfterTunablesReap(t *testing.T) {
	// b starts the room without applying tunables, so the broker reaps it and
	// sends the same bytes to c. Placement is random and a hotel that holds the
	// image is preferred, so only the first create of a fresh chain can start
	// on b: go on with a new chain until it did.
	for i := 0; i < 40; i++ {
		tc := newChain(t)
		tc.hotels["c"].appliesTunables = true
		tc.b.mu.Lock()
		tc.b.hotelByID("c").slots = 1 // make b the likely first try
		tc.b.mu.Unlock()
		resp, doc := createWithAsk(t, tc, map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}, "tunables": coldTunables()}, true, "")
		if resp.StatusCode != 202 || doc["hotel"] != "c" {
			t.Fatalf("create %d: %d %v", i, resp.StatusCode, doc)
		}
		raw := decodeCreateRequest(t, doc)
		sameBytes(t, raw, lastCreateBody(tc.hotels["c"]))
		if len(tc.hotels["b"].createBodies) > 0 {
			sameBytes(t, raw, lastCreateBody(tc.hotels["b"]))
			return
		}
	}
	t.Fatalf("hotel b was never tried first in 40 creates")
}

func TestCreateWithoutAskHasNoExtraKey(t *testing.T) {
	tc := newChain(t)
	resp, doc := createWithAsk(t, tc, map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}, false, "")
	if resp.StatusCode != 202 {
		t.Fatalf("create: %d %v", resp.StatusCode, doc)
	}
	if _, ok := doc["create_request_b64"]; ok {
		t.Fatalf("answer carries create_request_b64 without the header: %v", doc)
	}
}

func TestCreateRequestBytesCountOverOneRefused(t *testing.T) {
	tc := newChain(t)
	resp, doc := createWithAsk(t, tc, map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "count": 2}, true, "")
	if resp.StatusCode != 400 || errCode(doc) != "create_request_batch_unsupported" {
		t.Fatalf("count 2 with the header: %d %v", resp.StatusCode, doc)
	}
	for id, n := range createsOn(tc) {
		if n != 0 {
			t.Fatalf("hotel %s got %d creates from a refused request", id, n)
		}
	}
}

func TestCreateRequestBytesFailedCreateHasNone(t *testing.T) {
	tc := newChain(t)
	resp, doc := createWithAsk(t, tc, map[string]any{"image": "nosuch/x:1", "hotels": []string{"b"}}, true, "")
	if resp.StatusCode == 202 {
		t.Fatalf("create should fail: %v", doc)
	}
	if _, ok := doc["create_request_b64"]; ok {
		t.Fatalf("a failed create carries create_request_b64: %v", doc)
	}
}

func TestCreateRequestBytesIgnoredOnCompat(t *testing.T) {
	tc := newChain(t)
	resp, doc := createWithAsk(t, tc, map[string]any{"template": "room-2x8"}, true, "ctcli/1.0")
	if resp.StatusCode != 201 {
		t.Fatalf("compat create: %d %v", resp.StatusCode, doc)
	}
	if _, ok := doc["create_request_b64"]; ok {
		t.Fatalf("compat answer carries create_request_b64: %v", doc)
	}
	_ = atomic.LoadInt32
}
