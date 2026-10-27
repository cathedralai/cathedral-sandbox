package main

// Review round 6, other angles: the live config shape under the strict loader,
// and a fuzz pass over the broker's JSON entry points. Nothing here reaches a
// real hotel; the fake answers every call at once.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// liveShapeConfig mirrors the field set of the deployed broker config (ids and
// hashes replaced): five hotels, one of them sealed and one with max_slots,
// three guests with max_rooms, max_creates_per_minute, default_sealed, ops and
// a hotel list, plus state_dir, the operator key, and the leftover
// escape_nonce_allow_plaintext=false key live configs still carry.
func liveShapeConfig(t testing.TB, hotelURL string) string {
	dir := t.TempDir()
	key := filepath.Join(dir, "hotel.key")
	if err := os.WriteFile(key, []byte("hotel-key-with-forty-eight-characters-0123456789ab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hotel := func(id, name string, threads, ram, conc int, extra string) string {
		return fmt.Sprintf(`{"id": %q, "name": %q, "threads": %d, "ram_gib": %d, "api": %q, "health": %q, "key_file": %q, "concurrency": %d, "drain": false%s}`,
			id, name, threads, ram, hotelURL, hotelURL, key, conc, extra)
	}
	cfg := `{
 "listen": "127.0.0.1:18100",
 "hotels": [
  ` + hotel("h1", "Hotel 1", 256, 1001, 16, "") + `,
  ` + hotel("h2", "Hotel 2", 192, 752, 40, `, "max_slots": 700`) + `,
  ` + hotel("h3", "Hotel 3", 48, 187, 16, "") + `,
  ` + hotel("h4", "Hotel 4", 32, 62, 8, "") + `,
  ` + hotel("h5", "Hotel 5 (sealed)", 96, 384, 40, `, "sealed": true`) + `
 ],
 "guests": [
  {"id": "ops", "key_sha256": "` + sha("ops-key") + `", "view_token_sha256": "` + sha("ops-view") + `", "max_rooms": 10000, "ops": true, "hotels": ["h1", "h2", "h3", "h4"]},
  {"id": "dedicated", "key_sha256": "` + sha("dedicated-key") + `", "view_token_sha256": "` + sha("dedicated-view") + `", "max_rooms": 1000, "max_creates_per_minute": 600, "default_sealed": true, "hotels": ["h2", "h3", "h4", "h5"]},
  {"id": "eng", "key_sha256": "` + sha("eng-key") + `", "view_token_sha256": "` + sha("eng-view") + `", "max_rooms": 10000, "max_creates_per_minute": 600, "default_sealed": false, "ops": true, "hotels": ["h1", "h2", "h3", "h4"]}
 ],
 "state_dir": "` + dir + `",
 "operator_key_sha256": "` + sha("operator-key") + `",
 "escape_nonce_allow_plaintext": false
}`
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLiveConfigShapeLoadsUnderTheStrictLoader(t *testing.T) {
	b, err := loadBroker(liveShapeConfig(t, "http://127.0.0.1:1"))
	if err != nil {
		t.Fatalf("the deployed config shape is refused by the strict loader: %v", err)
	}
	if n := len(b.hotelList()); n != 5 {
		t.Fatalf("hotels loaded: %d, want 5", n)
	}
	if n := len(b.guests); n != 3 {
		t.Fatalf("guests loaded: %d, want 3", n)
	}
	g := b.guests["dedicated"]
	if g == nil || !g.limits.DefaultSealed || g.limits.MaxRooms != 1000 || g.limits.MaxCreatesPerMinute != 600 || len(g.limits.Hotels) != 4 {
		t.Fatalf("dedicated guest limits not carried: %+v", g)
	}
	sealed := 0
	for _, h := range b.hotelList() {
		if h.cfg.Sealed {
			sealed++
		}
		if h.cfg.ID == "h2" && h.cfg.MaxSlots != 700 {
			t.Fatalf("max_slots not carried: %+v", h.cfg)
		}
	}
	if sealed != 1 {
		t.Fatalf("sealed hotels: %d, want 1", sealed)
	}
}

// FuzzLoadBroker: any bytes in the config file end in an error or a broker,
// never a panic.
func FuzzLoadBroker(f *testing.F) {
	raw, err := os.ReadFile(liveShapeConfig(f, "http://127.0.0.1:1"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"hotel": []}`))
	f.Add([]byte(`{"guests": [{"id": ""}]}`))
	f.Add([]byte(`{"hotels": [{"id": "a.b"}]}`))
	f.Add([]byte(`{"guests": [{"id": "x", "key_sha256": "AB"}, {"id": "y", "key_sha256": "ab"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Skip()
		}
		_, _ = loadBroker(p)
	})
}

// fuzzRoutes are the guest and operator routes whose bodies, suffixes and
// queries come from the caller. The hotel join route is left out: it would
// contact whatever URL the body names.
var fuzzRoutes = []struct {
	method, path string
	admin        bool
}{
	{"POST", "/v1/sandboxes", false}, {"GET", "/v1/sandboxes", false}, {"DELETE", "/v1/sandboxes", false},
	{"GET", "/v1/sandboxes/%s", false}, {"DELETE", "/v1/sandboxes/%s", false}, {"PATCH", "/v1/sandboxes/%s", false},
	{"POST", "/v1/sandboxes/%s/exec", false}, {"GET", "/v1/sandboxes/%s/exec/%s", false},
	{"PUT", "/v1/sandboxes/%s/files", false}, {"GET", "/v1/sandboxes/%s/files", false},
	{"POST", "/v1/sandboxes/%s/network", false}, {"POST", "/v1/sandboxes/%s/snapshot", false},
	{"POST", "/v1/sandboxes/%s/lifetime", false}, {"GET", "/v1/sandboxes/%s/logs", false},
	{"GET", "/v1/hotels/%s/receipts", false}, {"GET", "/v1/hotels/%s", false},
	{"GET", "/v1/quota", false}, {"GET", "/v1/usage", false},
	{"POST", "/v1/images/prefetch", false}, {"GET", "/v1/images/prefetch/%s", false},
	{"POST", "/v1/images/build", false}, {"GET", "/v1/images/build/%s", false},
	{"GET", "/v1/snapshots", false}, {"GET", "/v1/snapshots/%s", false}, {"DELETE", "/v1/snapshots/%s", false},
	{"POST", "/v1/snapshots/%s/push", false},
	{"GET", "/v1/sandboxes/catalog", false},
	{"GET", "/v1/broker/hotels", false}, {"GET", "/v1/broker/stats", false}, {"POST", "/v1/broker/probe", false},
	{"GET", "/v1/status", false},
	{"PATCH", "/v1/broker/hotels/%s", true}, {"DELETE", "/v1/broker/hotels/%s", true},
	{"GET", "/v1/broker/guests", true}, {"PATCH", "/v1/broker/guests/%s", true},
	{"POST", "/ops/live/sign-in", false}, {"GET", "/ops/live", false},
	{"GET", "/healthz", false}, {"GET", "/%s", false},
}

// FuzzServeHTTP: every route answers with a status; no body, suffix or query
// makes a handler panic. The fake hotel answers 200 {} to everything so the
// broker's parsing of hotel answers is exercised too.
func FuzzServeHTTP(f *testing.F) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer fake.Close()
	b, err := loadBroker(liveShapeConfig(f, fake.URL))
	if err != nil {
		f.Fatal(err)
	}
	if err := b.loadCompat(); err != nil {
		f.Fatal(err)
	}
	for _, h := range b.hotelList() {
		h.ok, h.slots = true, 100
	}
	f.Add(uint8(0), false, "sbx_1", []byte(`{"image": "alpine:3.20", "count": 1}`), "label.job")
	f.Add(uint8(0), true, "sbx_1", []byte(`{"image_id": "img_1", "shape": {"vcpus": 2, "memory_mib": 8192}}`), "")
	f.Add(uint8(6), false, "sbx_1", []byte(`{"command": ["sh", "-c", "true"], "timeout_seconds": 1e308}`), "")
	f.Add(uint8(12), false, "sbx_1", []byte(`{"extend_by_seconds": -1, "lifetime_seconds": 1e18}`), "")
	f.Add(uint8(33), true, "h2", []byte(`{"drain": true, "labels": {"sealed": "false"}}`), "")
	f.Add(uint8(35), true, "dedicated", []byte(`{"max_rooms": -5, "hotels": ["nope"]}`), "")
	f.Add(uint8(36), false, "", []byte(`token=abc`), "")
	f.Fuzz(func(t *testing.T, route uint8, compat bool, suffix string, body []byte, query string) {
		rt := fuzzRoutes[int(route)%len(fuzzRoutes)]
		path := rt.path
		esc := url.PathEscape(suffix)
		switch {
		case bytes.Count([]byte(path), []byte("%s")) == 2:
			path = fmt.Sprintf(path, esc, esc)
		case bytes.Contains([]byte(path), []byte("%s")):
			path = fmt.Sprintf(path, esc)
		}
		u := url.URL{Scheme: "http", Host: "broker", Path: path, RawQuery: url.Values{"group_by": {query}, "state": {query}, "limit": {query}, "since": {query}}.Encode()}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req := httptest.NewRequestWithContext(ctx, rt.method, u.String(), bytes.NewReader(body))
		if rt.admin {
			req.Header.Set("Authorization", "Bearer operator-key")
		} else {
			req.Header.Set("Authorization", "Bearer ops-key")
		}
		if compat {
			req.Header.Set("User-Agent", compatAgents[0]+"/0.1")
		}
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		b.ServeHTTP(rec, req)
		if rec.Code < 100 || rec.Code > 599 {
			t.Fatalf("%s %s: status %d", rt.method, path, rec.Code)
		}
	})
}
