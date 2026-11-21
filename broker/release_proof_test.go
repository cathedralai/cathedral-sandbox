package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func proofRoom(t *testing.T, handler http.HandlerFunc) (*testChain, string) {
	t.Helper()
	tc := newChain(t)
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	guest := httptest.NewServer(handler)
	t.Cleanup(guest.Close)
	tc.b.hotelByID("a").cfg.Health = guest.URL
	return tc, room
}

func TestReleaseProofOwnedRoomAndExactAnswer(t *testing.T) {
	challenge := []byte(`{"issued_at":9007199254740991,"sandbox_id":"customer-uuid","nonce_b64":"abc"}`)
	answer := []byte(`{"receipt":{"statement":{"sandbox_id":"local"},"signature_b64":"signed"}}`)
	var received []byte
	var path, auth, guest string
	tc, room := proofRoom(t, func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		path, auth, guest = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get(guestHeader)
		w.Header().Set("Content-Type", "application/json")
		w.Write(answer)
	})
	resp, out := tc.postRaw(t, "key1", "/v1/sandboxes/"+room+"/release-proof", challenge)
	if resp.StatusCode != 200 || !bytes.Equal(answer, out) {
		t.Fatalf("answer: %d %q", resp.StatusCode, out)
	}
	var got struct {
		Room      string          `json:"sandbox_id"`
		Challenge json.RawMessage `json:"challenge"`
	}
	if err := json.Unmarshal(received, &got); err != nil {
		t.Fatal(err)
	}
	if got.Room != strings.TrimPrefix(room, "a.") || !bytes.Equal(got.Challenge, challenge) {
		t.Fatalf("wrong target or challenge: %s", received)
	}
	if path != "/room/release-proof" || auth != "Bearer hotel-key" || guest != "g1" {
		t.Fatalf("wrong forwarding: %s %s %s", path, auth, guest)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Fatal("lost content type")
	}
}

func TestReleaseProofRefusalsNeverReachGuest(t *testing.T) {
	var calls atomic.Int32
	tc, room := proofRoom(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte(`{}`)) })
	path := "/v1/sandboxes/" + room + "/release-proof"
	for _, key := range []string{"", "nope", "operator-key", "key2"} {
		resp, _ := tc.postRaw(t, key, path, []byte(`{}`))
		if resp.StatusCode != 401 && resp.StatusCode != 404 {
			t.Fatalf("key %q: %d", key, resp.StatusCode)
		}
	}
	for _, tail := range []string{"/release-proof/extra", "/release-proof;x", "/release-proof?x=1"} {
		resp, _ := tc.postRaw(t, "key1", "/v1/sandboxes/"+room+tail, []byte(`{}`))
		if resp.StatusCode != 404 {
			t.Fatalf("tail %s: %d", tail, resp.StatusCode)
		}
	}
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		status, _ := tc.body(t, "key1", method, path)
		if status != 405 {
			t.Fatalf("method %s: %d", method, status)
		}
	}
	for _, body := range [][]byte{nil, []byte(`[]`), []byte(`{"a":`), []byte(`{} {}`), []byte(`null`), bytes.Repeat([]byte("x"), releaseChallengeMax+1)} {
		resp, _ := tc.postRaw(t, "key1", path, body)
		if resp.StatusCode != 400 && resp.StatusCode != 413 {
			t.Fatalf("invalid body accepted: %d", resp.StatusCode)
		}
	}
	resp, _ := tc.postRaw(t, "key1", "/v1/sandboxes/a.missing/release-proof", []byte(`{}`))
	if resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	tc.b.guests["g1"].limits = guestLimits{Hotels: []string{"b"}}
	resp, _ = tc.postRaw(t, "key1", path, []byte(`{}`))
	if resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	tc.b.guests["g1"].limits = guestLimits{}
	h := tc.b.hotelByID("a")
	tc.b.mu.Lock()
	h.rooms[strings.TrimPrefix(room, "a.")].guest = ""
	tc.b.mu.Unlock()
	resp, _ = tc.postRaw(t, "key1", path, []byte(`{}`))
	if resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
	if calls.Load() != 0 {
		t.Fatalf("unauthorized calls: %d", calls.Load())
	}
}

func TestReleaseProofBoundedRepliesAndNoRedirect(t *testing.T) {
	for _, code := range []int{200, 307, 403, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var calls, redirects atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirects.Add(1) }))
			defer other.Close()
			tc, room := proofRoom(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", other.URL)
				w.WriteHeader(code)
				if code == 200 {
					w.(http.Flusher).Flush()
					w.Write(bytes.Repeat([]byte("x"), releaseProofAnswerMax+1))
				} else {
					w.Write([]byte(`{"error":"refused"}`))
				}
			})
			resp, out := tc.postRaw(t, "key1", "/v1/sandboxes/"+room+"/release-proof", []byte(`{}`))
			want := code
			if code == 200 {
				want = 502
			}
			if resp.StatusCode != want || calls.Load() != 1 || redirects.Load() != 0 {
				t.Fatalf("status %d calls %d redirects %d", resp.StatusCode, calls.Load(), redirects.Load())
			}
			if len(out) > releaseProofAnswerMax {
				t.Fatal("oversized or partial reply escaped")
			}
		})
	}
}

func TestReleaseProofCancellationReachesGuest(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	tc, room := proofRoom(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
		close(stopped)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", tc.srv.URL+"/v1/sandboxes/"+room+"/release-proof", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer key1")
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		resp, _ := http.DefaultClient.Do(req)
		if resp != nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("guest not called")
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("guest call not cancelled")
	}
	<-finished
}

func TestReleaseProofCannotBypassMissingGuestTLSPin(t *testing.T) {
	var calls atomic.Int32
	tc, room := proofRoom(t, func(w http.ResponseWriter, r *http.Request) { calls.Add(1) })
	tc.b.hotelByID("a").cfg.GuestTLS = true
	resp, _ := tc.postRaw(t, "key1", "/v1/sandboxes/"+room+"/release-proof", []byte(`{}`))
	if resp.StatusCode != 502 || calls.Load() != 0 {
		t.Fatalf("status %d calls %d", resp.StatusCode, calls.Load())
	}
}
