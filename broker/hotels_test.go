package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

const joinKey = "hotel-d-key-0123456789abcdefghijklmnop"

func TestOperatorAddsChangesAndRemovesAHotelAtRuntime(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	join := map[string]any{"id": "d", "api": hs.URL, "key": joinKey, "labels": map[string]string{"sealed": "true"}}

	if status, _ := tc.call(t, "key1", "POST", "/v1/broker/hotels", join); status != 401 {
		t.Fatalf("guest key joined a hotel: %d", status)
	}
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", join)
	if status != 201 || doc["id"] != "d" || doc["runtime"] != true {
		t.Fatalf("join: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", join); status != 409 || errCode(doc) != "hotel_exists" {
		t.Fatalf("second join: %d %v", status, doc)
	}
	if fi, err := os.Stat(dir + "/hotel-keys/d.key"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	if raw, _ := os.ReadFile(dir + "/" + runtimeHotelsFile); strings.Contains(string(raw), joinKey) {
		t.Fatalf("hotels.json holds the key")
	}
	h := tc.b.hotelByID("d")
	tc.b.mu.Lock()
	h.ok, h.slots = true, 10
	tc.b.mu.Unlock()
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"d"}}); !strings.HasPrefix(id, "d.") {
		t.Fatalf("room on %s", id)
	}
	// A hotel with rooms cannot leave.
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/d", nil); status != 409 || errCode(doc) != "hotel_not_empty" {
		t.Fatalf("leave with rooms: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/d", map[string]any{"drain": true}); status != 200 || doc["drain"] != true {
		t.Fatalf("drain: %d %v", status, doc)
	}
	// A config hotel cannot leave at runtime.
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/a", nil); status != 409 || errCode(doc) != "hotel_in_config" {
		t.Fatalf("leave config hotel: %d %v", status, doc)
	}

	// After a restart the runtime hotel is back, with its labels and drain flag.
	tc.start(t)
	h = tc.b.hotelByID("d")
	if h == nil || h.cfg.Labels["sealed"] != "true" || !h.cfg.Drain || h.key != joinKey {
		t.Fatalf("hotel after restart: %+v", h)
	}
	// Empty hotel: it leaves, and stays gone after a restart.
	if status, _ := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/d", nil); status != 204 {
		t.Fatalf("leave: %d", status)
	}
	if _, err := os.Stat(dir + "/hotel-keys/d.key"); !os.IsNotExist(err) {
		t.Fatalf("key file kept: %v", err)
	}
	tc.start(t)
	if tc.b.hotelByID("d") != nil {
		t.Fatalf("hotel came back")
	}
}

func TestJoinChecksTheHotelAndTheInput(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	cases := []struct {
		body map[string]any
		want int
		code string
	}{
		{map[string]any{"id": "x", "api": dead.URL, "key": joinKey}, 502, "hotel_unreachable"},
		{map[string]any{"id": "x.y", "api": dead.URL, "key": joinKey}, 400, "invalid_hotel"},
		{map[string]any{"id": "x", "api": "file:///etc/passwd", "key": joinKey}, 400, "invalid_hotel"},
		{map[string]any{"id": "x", "api": dead.URL, "key": "short"}, 400, "invalid_hotel"},
	}
	for _, c := range cases {
		status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", c.body)
		if status != c.want || errCode(doc) != c.code {
			t.Fatalf("%v: %d %v", c.body, status, doc)
		}
	}
	if tc.b.hotelByID("x") != nil {
		t.Fatalf("a refused hotel was added")
	}
}

func TestLiveViewSignInByPost(t *testing.T) {
	tc := newChain(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.PostForm(tc.srv.URL+"/g1/live/sign-in", url.Values{"token": {"wrong"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || len(resp.Cookies()) != 0 {
		t.Fatalf("wrong token: %d %v", resp.StatusCode, resp.Cookies())
	}
	resp, err = client.PostForm(tc.srv.URL+"/g1/live/sign-in", url.Values{"token": {"view1"}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 || resp.Header.Get("Location") != "/g1/live" || len(resp.Cookies()) != 1 {
		t.Fatalf("sign in: %d %v", resp.StatusCode, resp.Header)
	}
	c := resp.Cookies()[0]
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/g1/" {
		t.Fatalf("cookie: %+v", c)
	}
	req, _ := http.NewRequest("GET", tc.srv.URL+"/g1/live", nil)
	req.AddCookie(c)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("live with cookie: %d", resp.StatusCode)
	}
	// Without a cookie the page is the sign-in form, not a link to a ?token= URL.
	resp, err = client.Get(tc.srv.URL + "/g1/live")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if resp.StatusCode != 401 || !strings.Contains(string(buf[:n]), `action="/g1/live/sign-in"`) {
		t.Fatalf("sign-in form: %d %s", resp.StatusCode, buf[:n])
	}
	// The ?token= link still works.
	resp, err = client.Get(tc.srv.URL + "/g1/live?token=view1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Fatalf("token link: %d", resp.StatusCode)
	}
}
