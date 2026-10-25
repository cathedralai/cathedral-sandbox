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

// wsHotel adds the hotel workspace routes to fakeHotel. Like the hotel, it
// keeps workspaces per guest (the X-Cathedral-Guest header) and answers 404
// for a workspace of another guest.
type wsHotel struct {
	*fakeHotel
	wmu     sync.Mutex
	ws      map[string]map[string]bool // guest -> name -> exists
	headers []string                   // X-Cathedral-Guest of each workspace call
}

func (f *wsHotel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if !strings.HasPrefix(p, "/v1/workspaces") {
		f.fakeHotel.ServeHTTP(w, r)
		return
	}
	guest := r.Header.Get(guestHeader)
	f.wmu.Lock()
	defer f.wmu.Unlock()
	f.headers = append(f.headers, guest)
	mine := f.ws[guest]
	if mine == nil {
		mine = map[string]bool{}
		f.ws[guest] = mine
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(p, "/v1/workspaces"), "/")
	name, tail, _ := strings.Cut(rest, "/")
	switch {
	case rest == "" && r.Method == "POST":
		var req map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		n, _ := req["name"].(string)
		mine[n] = true
		writeJSON(w, 201, map[string]any{"name": n, "versions": []any{}})
	case rest == "" && r.Method == "GET":
		out := []map[string]any{}
		for n := range mine {
			out = append(out, map[string]any{"name": n})
		}
		writeJSON(w, 200, map[string]any{"workspaces": out})
	case !mine[name]:
		writeErr(w, 404, "workspace_not_found", "no workspace "+name)
	case tail == "" && r.Method == "DELETE":
		delete(mine, name)
		w.WriteHeader(204)
	case tail == "versions" && r.Method == "POST":
		writeJSON(w, 201, map[string]any{"version": 1, "reason": "request"})
	default:
		writeJSON(w, 200, map[string]any{"name": name, "versions": []any{}})
	}
}

type wsChain struct {
	*testChain
	ws map[string]*wsHotel
}

// newWSChain is newChain with workspace routes on hotels "a" (sealed), "b" and "c".
func newWSChain(t *testing.T) *wsChain {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "hotel.key")
	if err := os.WriteFile(key, []byte("hotel-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	wc := &wsChain{testChain: &testChain{hotels: map[string]*fakeHotel{}}, ws: map[string]*wsHotel{}}
	cfg := config{InsecureCookie: true, Guests: []guestConfig{
		{ID: "g1", KeySHA256: sha("key1"), ViewTokenSHA256: sha("view1")},
		{ID: "g2", KeySHA256: sha("key2")},
	}}
	for _, id := range []string{"a", "b", "c"} {
		f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
		wh := &wsHotel{fakeHotel: f, ws: map[string]map[string]bool{}}
		hs := httptest.NewServer(wh)
		t.Cleanup(hs.Close)
		wc.hotels[id] = f
		wc.ws[id] = wh
		hc := hotelConfig{ID: id, Name: id, API: hs.URL, Health: hs.URL, KeyFile: key, Concurrency: 4}
		if id == "a" {
			hc.Labels = map[string]string{"sealed": "true"}
		}
		cfg.Hotels = append(cfg.Hotels, hc)
	}
	raw, _ := json.Marshal(cfg)
	wc.cfgPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(wc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	wc.start(t)
	return wc
}

func TestWorkspaceCreateGoesToTheChosenHotelWithTheGuestHeader(t *testing.T) {
	tc := newWSChain(t)
	status, doc := tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "repo", "hotels": []string{"c"}})
	if status != 201 || doc["id"] != "c.repo" || doc["hotel"] != "c" {
		t.Fatalf("create: %d %v", status, doc)
	}
	if !tc.ws["c"].ws["g1"]["repo"] {
		t.Fatalf("hotel c has no workspace for g1: %v", tc.ws["c"].ws)
	}
	for id, h := range tc.ws {
		for _, g := range h.headers {
			if g != "g1" {
				t.Fatalf("hotel %s got guest header %q", id, g)
			}
		}
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "repo"})
	if status != 409 || errCode(doc) != "workspace_exists" {
		t.Fatalf("second create: %d %v", status, doc)
	}
}

func TestWorkspaceRoomGoesToTheHotelThatHoldsIt(t *testing.T) {
	tc := newWSChain(t)
	tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "repo", "hotels": []string{"b"}})
	before := createsOn(tc.testChain)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "count": 5,
		"workspace": map[string]any{"name": "b.repo", "version_on_delete": true}})
	if status != 202 || doc["count"] != float64(5) {
		t.Fatalf("create: %d %v", status, doc)
	}
	after := createsOn(tc.testChain)
	if after["b"]-before["b"] != 5 || after["a"] != before["a"] || after["c"] != before["c"] {
		t.Fatalf("creates by hotel: before %v after %v", before, after)
	}
	// The hotel gets the bare name; the other fields stay.
	f := tc.hotels["b"]
	f.mu.Lock()
	last := f.creates[len(f.creates)-1]
	f.mu.Unlock()
	ws := last["workspace"].(map[string]any)
	if ws["name"] != "repo" || ws["version_on_delete"] != true {
		t.Fatalf("hotel create workspace %v", ws)
	}
	// A bare name works too.
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "workspace": "repo"}); !strings.HasPrefix(id, "b.") {
		t.Fatalf("room %s not on hotel b", id)
	}
}

func TestWorkspaceOfAnotherGuestIs404Everywhere(t *testing.T) {
	tc := newWSChain(t)
	tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "repo", "hotels": []string{"b"}})
	before := createsOn(tc.testChain)
	for _, ref := range []string{"repo", "b.repo"} {
		status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "workspace": ref})
		if status != 404 || errCode(doc) != "workspace_not_found" {
			t.Fatalf("g2 room with %s: %d %v", ref, status, doc)
		}
		for _, c := range []struct{ method, path string }{
			{"GET", "/v1/workspaces/" + ref},
			{"DELETE", "/v1/workspaces/" + ref},
			{"GET", "/v1/workspaces/" + ref + "/versions"},
			{"POST", "/v1/workspaces/" + ref + "/versions"},
			{"POST", "/v1/workspaces/" + ref + "/rollback"},
		} {
			status, doc := tc.call(t, "key2", c.method, c.path, map[string]any{"version": 1})
			if status != 404 || errCode(doc) != "workspace_not_found" {
				t.Fatalf("g2 %s %s: %d %v", c.method, c.path, status, doc)
			}
		}
	}
	if after := createsOn(tc.testChain); after["b"] != before["b"] {
		t.Fatalf("a foreign workspace started a room: %v", after)
	}
	status, doc := tc.call(t, "key2", "GET", "/v1/workspaces", nil)
	if status != 200 || doc["count"] != float64(0) {
		t.Fatalf("g2 list: %d %v", status, doc)
	}
	// g1 still has it.
	status, doc = tc.call(t, "key1", "GET", "/v1/workspaces", nil)
	if status != 200 || doc["count"] != float64(1) {
		t.Fatalf("g1 list: %d %v", status, doc)
	}
	if !tc.ws["b"].ws["g1"]["repo"] {
		t.Fatal("g2 deleted the workspace of g1")
	}
}

func TestWorkspaceGuestHeaderCannotBeSetByTheGuest(t *testing.T) {
	tc := newWSChain(t)
	tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "repo", "hotels": []string{"b"}})
	req, _ := http.NewRequest("GET", tc.srv.URL+"/v1/workspaces/b.repo", nil)
	req.Header.Set("Authorization", "Bearer key2")
	req.Header.Set(guestHeader, "g1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("g2 with a forged guest header: %d", resp.StatusCode)
	}
	h := tc.ws["b"]
	h.wmu.Lock()
	defer h.wmu.Unlock()
	if last := h.headers[len(h.headers)-1]; last != "g2" {
		t.Fatalf("hotel saw guest %q", last)
	}
}

func TestWorkspaceAndSnapshotOnDifferentHotelsConflict(t *testing.T) {
	tc := newWSChain(t)
	tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "repo", "hotels": []string{"b"}})
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}})
	_, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", map[string]any{})
	snap := doc["result"].(map[string]any)["snapshot_id"].(string)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": snap, "workspace": "repo"})
	if status != 409 || errCode(doc) != "workspace_snapshot_conflict" {
		t.Fatalf("fork + workspace: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "workspace": "repo", "hotels": []string{"c"}})
	if status != 409 || errCode(doc) != "workspace_hotel_excluded" {
		t.Fatalf("workspace outside the selection: %d %v", status, doc)
	}
}

func TestWorkspaceRoutesWithBadRefs(t *testing.T) {
	tc := newWSChain(t)
	for _, path := range []string{"/v1/workspaces/..%2Fetc", "/v1/workspaces/b..", "/v1/workspaces/x.repo"} {
		status, doc := tc.call(t, "key1", "GET", path, nil)
		if status != 404 {
			t.Fatalf("%s: %d %v", path, status, doc)
		}
	}
	status, doc := tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "a.b"})
	if status != 400 || errCode(doc) != "invalid_workspace_name" {
		t.Fatalf("dotted name: %d %v", status, doc)
	}
}

func TestWorkspaceDeleteAndVersionGoToTheHotel(t *testing.T) {
	tc := newWSChain(t)
	tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "repo", "hotels": []string{"b"}})
	status, doc := tc.call(t, "key1", "POST", "/v1/workspaces/repo/versions", nil)
	if status != 201 || doc["version"] != float64(1) {
		t.Fatalf("version: %d %v", status, doc)
	}
	status, _ = tc.call(t, "key1", "DELETE", "/v1/workspaces/b.repo", nil)
	if status != 204 || tc.ws["b"].ws["g1"]["repo"] {
		t.Fatalf("delete: %d", status)
	}
}
