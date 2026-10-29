package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const joinKey = "hotel-d-key-0123456789abcdefghijklmnop"

func TestOperatorAddsChangesAndRemovesAHotelAtRuntime(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	// d is sealed by configuration: it joins only with an attestation that passes.
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}, attestation: snpAttestation(t, attestOpts{})}
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	join := map[string]any{"id": "d", "api": hs.URL, "key": joinKey, "sealed": true}

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

func TestMinerEnrollmentKeyCannotOperateOutsideMinerScope(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 1, nil)
	for _, path := range []string{"/v1/broker/hotels/a", "/v1/broker/hotels/b"} {
		if status, doc := tc.call(t, "enroller-key", "GET", path, nil); status != 403 || errCode(doc) != "enroller_scope" {
			t.Fatalf("read operator hotel %s: %d %v", path, status, doc)
		}
		if status, doc := tc.call(t, "enroller-key", "PATCH", path, map[string]any{"drain": true}); status != 403 || errCode(doc) != "enroller_scope" {
			t.Fatalf("drain operator hotel %s: %d %v", path, status, doc)
		}
		if status, doc := tc.call(t, "enroller-key", "DELETE", path, nil); status != 403 || errCode(doc) != "enroller_scope" {
			t.Fatalf("leave operator hotel %s: %d %v", path, status, doc)
		}
	}
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/guests/g1", map[string]any{"max_rooms": 1}); status != 401 {
		t.Fatalf("enroller changed guest policy: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels/m1/escape-nonce", map[string]any{}); status != 403 || errCode(doc) != "enroller_scope" {
		t.Fatalf("enroller planted nonce: %d %v", status, doc)
	}
	for _, body := range []map[string]any{
		{"id": "x", "api": "https://127.0.0.1:1", "key": joinKey, "sealed": true},
		{"id": "x", "api": "http://127.0.0.1:1", "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey},
		{"id": "x", "api": "https://127.0.0.1:1", "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey, "verify": false},
		{"id": "x", "api": "https://127.0.0.1:1", "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey, "reserved_for": "g1"},
		{"id": "x", "api": "https://127.0.0.1:1", "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey, "labels": map[string]string{"zone": "x"}},
	} {
		if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", body); status != 403 || errCode(doc) != "enroller_scope" {
			t.Fatalf("out-of-scope join %v: %d %v", body, status, doc)
		}
	}
	var contacted atomic.Int32
	tlsHotel := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted.Add(1)
		w.WriteHeader(200)
	}))
	defer tlsHotel.Close()
	if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "x", "api": tlsHotel.URL, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey,
	}); status != 409 || errCode(doc) != "guest_tls_required" || contacted.Load() != 0 {
		t.Fatalf("scoped join sent key before attested TLS: %d %v contacts=%d", status, doc, contacted.Load())
	}
	if status, doc := tc.call(t, "enroller-key", "GET", "/v1/broker/hotels/m1", nil); status != 200 || doc["miner_hotkey"] != minerHotkey {
		t.Fatalf("read miner hotel: %d %v", status, doc)
	}
	for _, body := range []map[string]any{{"drain": false}, {"labels": map[string]string{"zone": "x"}}, {"max_slots": 1}, {"reserved_for": "g1"}} {
		if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", body); status != 403 || errCode(doc) != "enroller_scope" {
			t.Fatalf("out-of-scope miner patch %v: %d %v", body, status, doc)
		}
	}
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true}); status != 200 || doc["drain"] != true {
		t.Fatalf("drain miner hotel: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "enroller-key", "DELETE", "/v1/broker/hotels/m1", nil); status != 204 {
		t.Fatalf("leave empty miner hotel: %d %v", status, doc)
	}
}

func TestMinerEnrollmentKeyConfigRejectsReuse(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var original config
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	for name, digest := range map[string]string{
		"operator":  original.OperatorKeySHA256,
		"guest":     original.Guests[0].KeySHA256,
		"view":      original.Guests[0].ViewTokenSHA256,
		"malformed": "not-a-digest",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := original
			cfg.MinerEnrollKeySHA256 = digest
			body, _ := json.Marshal(cfg)
			path := t.TempDir() + "/config.json"
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadBroker(path); err == nil {
				t.Fatal("reused or malformed miner enrollment key was accepted")
			}
		})
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
		{map[string]any{"id": "x", "api": dead.URL, "key": joinKey, "miner_hotkey": minerHotkey}, 400, "invalid_hotel"},
		{map[string]any{"id": "x", "api": dead.URL, "key": joinKey, "labels": map[string]string{"sealed": "true"}}, 400, "invalid_hotel"},
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

func TestRuntimeUnsealedHotelCannotGainSealedLabel(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	_, url := newMinerHotel(t, 5, nil)
	status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "plain", "api": url, "key": joinKey, "verify": false,
	})
	if status != 201 {
		t.Fatalf("join unsealed operator hotel: %d %v", status, doc)
	}
	status, doc = tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/plain", map[string]any{
		"labels": map[string]string{"sealed": "true"},
	})
	if status != 400 || errCode(doc) != "invalid_hotel" {
		t.Fatalf("unsealed hotel gained sealed label: %d %v", status, doc)
	}
	if tc.b.hotelByID("plain").labels()["sealed"] == "true" {
		t.Fatal("unsealed hotel kept sealed label")
	}
}

func TestLegacyRuntimeSealedLabelCannotTakeRooms(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	h := newHotel(hotelConfig{ID: "old-label", Labels: map[string]string{"sealed": "true"}}, joinKey)
	h.runtime, h.ok, h.slots = true, true, 5
	if err := tc.b.addHotel(h); err != nil {
		t.Fatal(err)
	}
	tc.b.mu.Lock()
	free := tc.b.admissibleFree(h, time.Now())
	tc.b.mu.Unlock()
	if free != 0 {
		t.Fatalf("unsealed runtime hotel offers %d sealed-labeled rooms", free)
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
