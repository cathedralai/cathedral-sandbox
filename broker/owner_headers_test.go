package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
)

// ownerSeen records the headers each hotel create arrived with.
type ownerSeen struct {
	mu      sync.Mutex
	headers map[string][]http.Header // hotel id -> one entry per create
}

func (o *ownerSeen) wrap(refuseUnsigned string) func(id string, f *fakeHotel, next http.Handler) http.Handler {
	return func(id string, f *fakeHotel, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/sandboxes" && r.Method == "POST" {
				o.mu.Lock()
				o.headers[id] = append(o.headers[id], r.Header.Clone())
				o.mu.Unlock()
				// Like room_receipts.py on a dedicated machine.
				if id == refuseUnsigned && r.Header.Get("X-Cathedral-Owner-Signature") == "" {
					writeErr(w, 403, "owner_signature_required", "this is a dedicated machine")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (o *ownerSeen) on(id string) []http.Header {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]http.Header(nil), o.headers[id]...)
}

func postWithHeaders(t *testing.T, tc *testChain, key string, body any, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+key)
	for k, v := range hdr {
		req.Header.Set(k, v)
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

const (
	testOwnerSig = "c2lnbmF0dXJlLWJ5dGVzLW9mLXRoZS1vd25lcg=="
	testOwnerTS  = "1761700000"
)

func TestOwnerSignatureHeadersReachTheHotelWithEachCreate(t *testing.T) {
	seen := &ownerSeen{headers: map[string][]http.Header{}}
	tc := r6Chain(t, "", seen.wrap(""))
	signed := map[string]string{
		"X-Cathedral-Owner-Signature": testOwnerSig,
		"X-Cathedral-Owner-Timestamp": testOwnerTS,
		// A guest header the broker must still not copy.
		"X-Cathedral-Guest": "g2",
	}
	status, doc := postWithHeaders(t, tc, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "count": 3}, signed)
	if status != 202 || doc["count"].(float64) != 3 {
		t.Fatalf("create: %d %v", status, doc)
	}
	got := seen.on("b")
	if len(got) != 3 {
		t.Fatalf("hotel b got %d creates, want 3", len(got))
	}
	for _, h := range got {
		if h.Get("X-Cathedral-Owner-Signature") != testOwnerSig || h.Get("X-Cathedral-Owner-Timestamp") != testOwnerTS {
			t.Fatalf("owner headers not passed through: %v", h)
		}
		if h.Get("X-Cathedral-Guest") != "" {
			t.Fatalf("the guest's X-Cathedral-Guest reached the hotel: %v", h)
		}
		if h.Get("Authorization") != "Bearer hotel-key" {
			t.Fatalf("hotel create without the hotel key: %v", h)
		}
	}
	// The body is the broker's, as before: guest label, batch label, no placement.
	last := r6LastCreate(tc)
	labels, _ := last["labels"].(map[string]any)
	if labels[guestLabel] != "g1" || labels[batchLabel] == nil || last["hotels"] != nil || last["count"] != nil {
		t.Fatalf("hotel create body changed: %v", last)
	}

	// An unsigned create carries no owner header at all.
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}})
	for _, h := range seen.on("c") {
		if _, ok := h["X-Cathedral-Owner-Signature"]; ok {
			t.Fatalf("unsigned create sent an owner signature header: %v", h)
		}
		if _, ok := h["X-Cathedral-Owner-Timestamp"]; ok {
			t.Fatalf("unsigned create sent an owner timestamp header: %v", h)
		}
	}
}

func TestOwnerSignatureRefusalIsTheGuestsErrorAndDoesNotRestTheHotel(t *testing.T) {
	seen := &ownerSeen{headers: map[string][]http.Header{}}
	tc := r6Chain(t, "", seen.wrap("b"))
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if status != 403 || errCode(doc) != "owner_signature_required" {
		t.Fatalf("unsigned create on a dedicated hotel: %d %v", status, doc)
	}
	h := tc.b.hotelByID("b")
	tc.b.mu.Lock()
	resting, failed := !h.backoffUntil.IsZero(), h.failed
	tc.b.mu.Unlock()
	if resting || failed != 0 {
		t.Fatalf("an owner refusal rested the hotel (backoff %v, failed %d)", resting, failed)
	}
	// The owner's signed create goes through at once.
	status, doc = postWithHeaders(t, tc, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}},
		map[string]string{"X-Cathedral-Owner-Signature": testOwnerSig, "X-Cathedral-Owner-Timestamp": testOwnerTS})
	if status != 202 {
		t.Fatalf("signed create after a refusal: %d %v", status, doc)
	}
}
