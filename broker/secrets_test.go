package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const testSecretValue = "test-secret-value-7f3a"

// secretHotel adds the hotel secret routes to fakeHotel. Like the hotel it
// keeps values per guest (X-Cathedral-Guest) and never returns a value.
type secretHotel struct {
	*fakeHotel
	smu     sync.Mutex
	values  map[string]map[string]string // guest -> name -> value
	headers []string
	down    bool
}

func (f *secretHotel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/v1/secrets") {
		f.fakeHotel.ServeHTTP(w, r)
		return
	}
	f.smu.Lock()
	defer f.smu.Unlock()
	if f.down {
		writeErr(w, 503, "egress_unavailable", "down")
		return
	}
	guest := r.Header.Get(guestHeader)
	f.headers = append(f.headers, guest)
	mine := f.values[guest]
	if mine == nil {
		mine = map[string]string{}
		f.values[guest] = mine
	}
	name := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, "/v1/secrets"), "/")
	switch {
	case name == "" && r.Method == "GET":
		out := []map[string]any{}
		for n := range mine {
			out = append(out, map[string]any{"name": n, "updated_at": "2026-10-21T00:00:00Z"})
		}
		writeJSON(w, 200, map[string]any{"secrets": out})
	case r.Method == "PUT":
		var doc map[string]string
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &doc)
		mine[name] = doc["value"]
		writeJSON(w, 200, map[string]any{"name": name, "updated_at": "2026-10-21T00:00:00Z"})
	case r.Method == "DELETE":
		if _, ok := mine[name]; !ok {
			writeErr(w, 404, "secret_not_found", "no such secret")
			return
		}
		delete(mine, name)
		w.WriteHeader(204)
	default:
		writeErr(w, 404, "route_not_found", r.URL.Path)
	}
}

type secretChain struct {
	*testChain
	sh map[string]*secretHotel
}

func newSecretChain(t *testing.T, g1Hotels []string) *secretChain {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "hotel.key")
	if err := os.WriteFile(key, []byte("hotel-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc := &secretChain{testChain: &testChain{hotels: map[string]*fakeHotel{}}, sh: map[string]*secretHotel{}}
	g1 := guestConfig{ID: "g1", KeySHA256: sha("key1"), ViewTokenSHA256: sha("view1")}
	g1.Hotels = g1Hotels
	cfg := config{InsecureCookie: true, Guests: []guestConfig{g1, {ID: "g2", KeySHA256: sha("key2")}}}
	for _, id := range []string{"a", "b", "c"} {
		f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
		h := &secretHotel{fakeHotel: f, values: map[string]map[string]string{}}
		hs := httptest.NewServer(h)
		t.Cleanup(hs.Close)
		sc.hotels[id] = f
		sc.sh[id] = h
		cfg.Hotels = append(cfg.Hotels, hotelConfig{ID: id, Name: id, API: hs.URL, Health: hs.URL, KeyFile: key, Concurrency: 4})
	}
	raw, _ := json.Marshal(cfg)
	sc.cfgPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(sc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sc.start(t)
	return sc
}

func rawCall(t *testing.T, url, key, method, path, body string, hdr map[string]string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, url+path, rd)
	req.Header.Set("Authorization", "Bearer "+key)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func TestSecretPutGoesToTheGuestHotelsAndNoAnswerHasTheValue(t *testing.T) {
	sc := newSecretChain(t, []string{"a", "b"})
	status, out := rawCall(t, sc.srv.URL, "key1", "PUT", "/v1/secrets/PIP_TOKEN", `{"value":"`+testSecretValue+`"}`, nil)
	if status != 200 || strings.Contains(out, testSecretValue) {
		t.Fatalf("put: %d %s", status, out)
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(out), &doc)
	if h := doc["hotels"].(map[string]any); h["a"] != "done" || h["b"] != "done" || h["c"] != nil {
		t.Fatalf("hotels %v", h)
	}
	if sc.sh["a"].values["g1"]["PIP_TOKEN"] != testSecretValue || sc.sh["c"].values["g1"] != nil {
		t.Fatal("the value did not reach exactly the guest's hotels")
	}
	status, out = rawCall(t, sc.srv.URL, "key1", "GET", "/v1/secrets", "", nil)
	if status != 200 || strings.Contains(out, testSecretValue) || !strings.Contains(out, `"PIP_TOKEN"`) {
		t.Fatalf("list: %d %s", status, out)
	}
	// The live view and its data stream do not carry secrets.
	snap, _ := json.Marshal(sc.b.snapshot(sc.b.guests["g1"]))
	if strings.Contains(string(snap), testSecretValue) || strings.Contains(string(snap), "PIP_TOKEN") {
		t.Fatal("live view shows a secret")
	}
	status, _ = rawCall(t, sc.srv.URL, "key1", "DELETE", "/v1/secrets/PIP_TOKEN", "", nil)
	if status != 204 {
		t.Fatalf("delete: %d", status)
	}
	status, out = rawCall(t, sc.srv.URL, "key1", "DELETE", "/v1/secrets/PIP_TOKEN", "", nil)
	if status != 404 || !strings.Contains(out, "secret_not_found") {
		t.Fatalf("second delete: %d %s", status, out)
	}
}

func TestSecretDeletePartialHotelFailureIs502(t *testing.T) {
	sc := newSecretChain(t, []string{"a", "b"})
	rawCall(t, sc.srv.URL, "key1", "PUT", "/v1/secrets/PIP_TOKEN", `{"value":"`+testSecretValue+`"}`, nil)
	sc.sh["b"].down = true
	status, out := rawCall(t, sc.srv.URL, "key1", "DELETE", "/v1/secrets/PIP_TOKEN", "", nil)
	if status != 502 || !strings.Contains(out, "secrets_partial") {
		t.Fatalf("partial delete: %d %s", status, out)
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(out), &doc)
	hotels := doc["hotels"].(map[string]any)
	if hotels["a"] != "done" || hotels["b"] != "failed" {
		t.Fatalf("hotels %v", hotels)
	}
	if sc.sh["a"].values["g1"]["PIP_TOKEN"] != "" {
		t.Fatal("hotel a still has the secret after a partial delete report")
	}
}

func TestSecretsOfAnotherGuestAreInvisible(t *testing.T) {
	sc := newSecretChain(t, nil)
	rawCall(t, sc.srv.URL, "key1", "PUT", "/v1/secrets/PIP_TOKEN", `{"value":"`+testSecretValue+`"}`, nil)
	// A forged guest header from g2 does not reach the hotels.
	forged := map[string]string{guestHeader: "g1"}
	status, out := rawCall(t, sc.srv.URL, "key2", "GET", "/v1/secrets", "", forged)
	if status != 200 || strings.Contains(out, "PIP_TOKEN") {
		t.Fatalf("g2 list: %d %s", status, out)
	}
	status, out = rawCall(t, sc.srv.URL, "key2", "DELETE", "/v1/secrets/PIP_TOKEN", "", forged)
	if status != 404 || !strings.Contains(out, "secret_not_found") {
		t.Fatalf("g2 delete: %d %s", status, out)
	}
	if sc.sh["b"].values["g1"]["PIP_TOKEN"] != testSecretValue {
		t.Fatal("g2 deleted the secret of g1")
	}
	for id, h := range sc.sh {
		h.smu.Lock()
		for _, g := range h.headers[1:] {
			if g != "g2" {
				t.Fatalf("hotel %s got guest %q for a g2 call", id, g)
			}
		}
		h.smu.Unlock()
	}
}

func TestSecretBadInputsAndHotelErrorsDoNotEchoTheValue(t *testing.T) {
	sc := newSecretChain(t, nil)
	for _, name := range []string{"pip_token", "..%2FX", "A-B", strings.Repeat("A", 65)} {
		status, _ := rawCall(t, sc.srv.URL, "key1", "PUT", "/v1/secrets/"+name, `{"value":"x"}`, nil)
		if status != 400 && status != 404 {
			t.Fatalf("name %q: %d", name, status)
		}
	}
	status, out := rawCall(t, sc.srv.URL, "key1", "PUT", "/v1/secrets/PIP_TOKEN", `{"value":`+testSecretValue, nil)
	if status != 400 || strings.Contains(out, testSecretValue) {
		t.Fatalf("broken JSON: %d %s", status, out)
	}
	for _, h := range sc.sh {
		h.down = true
	}
	status, out = rawCall(t, sc.srv.URL, "key1", "PUT", "/v1/secrets/PIP_TOKEN", `{"value":"`+testSecretValue+`"}`, nil)
	if status != 502 || strings.Contains(out, testSecretValue) {
		t.Fatalf("hotels down: %d %s", status, out)
	}
}
