package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// AB#772: a guest port dial reaches the hotel with the caller's method,
// target and content headers, and never with the caller's own credentials.
func TestGuestPortDialForwardsGuestMethodAndTarget(t *testing.T) {
	tc := newChain(t)
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	h := tc.b.hotelByID("b")
	var mu sync.Mutex
	var seen http.Header
	var seenBody []byte
	var seenPath string
	hotel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen, seenBody, seenPath = r.Header.Clone(), b, r.URL.Path
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(hotel.Close)
	h.cfg.API = hotel.URL

	req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes/"+id+"/ports/8080/http", bytes.NewReader([]byte("a=1")))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("X-Guest-Method", "POST")
	req.Header.Set("X-Guest-Target", "/form?x=1")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Cookie", "s=secret")
	req.Header.Set("X-Cathedral-Port-Token", "tok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(out) != "hello" {
		t.Fatalf("broker answered %d %q, want 200 hello", resp.StatusCode, out)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := "/ports/8080/http"; len(seenPath) < len(want) || seenPath[len(seenPath)-len(want):] != want {
		t.Fatalf("hotel path %q", seenPath)
	}
	for k, want := range map[string]string{
		"X-Guest-Method": "POST", "X-Guest-Target": "/form?x=1",
		"Content-Type": "application/x-www-form-urlencoded", "Accept": "text/html",
	} {
		if got := seen.Get(k); got != want {
			t.Errorf("hotel %s = %q, want %q", k, got, want)
		}
	}
	if seen.Get("Cookie") != "" || seen.Get("X-Cathedral-Port-Token") != "" {
		t.Errorf("caller cookie or port token reached the hotel: %v", seen)
	}
	if seen.Get("Authorization") == "Bearer key1" {
		t.Errorf("caller's broker key reached the hotel")
	}
	if string(seenBody) != "a=1" {
		t.Errorf("hotel body %q", seenBody)
	}
}

func TestGuestPortHeadersOnlyOnThePortRoute(t *testing.T) {
	for _, c := range []struct {
		method, tail string
		want         bool
	}{
		{"POST", "ports/8080/http", true},
		{"GET", "ports/8080/http", false},
		{"POST", "exec", false},
		{"POST", "ports/8080", false},
		{"POST", "ports/8080/http/x", false},
	} {
		r := httptest.NewRequest(c.method, "/", nil)
		r.Header.Set("X-Guest-Target", "/a")
		if got := guestPortHeaders(r, c.tail) != nil; got != c.want {
			t.Errorf("%s %s: headers %v, want %v", c.method, c.tail, got, c.want)
		}
	}
}
