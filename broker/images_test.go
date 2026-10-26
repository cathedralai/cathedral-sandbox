package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHotel is a minimal hotel /v1 API: rooms, snapshots and prefetch.
type fakeHotel struct {
	t           *testing.T
	mu          sync.Mutex
	creates     []map[string]any
	authFail    bool                      // answer creates 401, like a hotel whose API key changed
	pullOutage  bool                      // answer creates 502 image_pull_failed for a registry outage
	calls       []string                  // "METHOD /path?query" of every request
	snaps       map[string]map[string]any // hotel snapshot id -> document
	prefetch    []map[string]any
	pushes      []map[string]any
	deleted     []string
	failPull    bool
	pullDelay   time.Duration
	n           int
	execs       []map[string]any
	builds      []map[string]any
	failBuild   bool
	createDelay time.Duration
	healthFail  bool
	rooms       []map[string]any // id + labels, for the room list
	networks    []map[string]any // bodies of PUT /v1/sandboxes/{id}/network
	receipts    []byte           // body of GET /room/receipts
	attestIn    [][]byte         // bodies of POST /room/attest
	attestAuth  []string         // Authorization of POST /room/attest
	attestGuest []string         // X-Cathedral-Guest of POST /room/attest
	roomDeletes []string         // room ids of DELETE /v1/sandboxes/{id}
	bulkDeletes [][]string       // label filters of DELETE /v1/sandboxes
}

func (f *fakeHotel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req map[string]any
	_ = json.Unmarshal(body, &req)
	p := r.URL.Path
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	switch {
	case p == "/v1/sandboxes" && r.Method == "POST":
		if f.createDelay > 0 {
			d := f.createDelay
			f.mu.Unlock()
			time.Sleep(d)
			f.mu.Lock()
		}
		f.creates = append(f.creates, req)
		if req["image"] == "nosuch/x:1" {
			writeErr(w, 502, "image_pull_failed", "docker pull failed for nosuch/x:1: Error response from daemon: pull access denied for nosuch/x, repository does not exist")
			return
		}
		if f.pullOutage {
			writeErr(w, 502, "image_pull_failed", "docker pull failed for alpine:3.20: Error response from daemon: Get \"https://registry-1.docker.io/v2/\": dial tcp: lookup registry-1.docker.io: no such host")
			return
		}
		if f.authFail {
			writeErr(w, 401, "unauthorized", "bad hotel key")
			return
		}
		if nw, ok := req["network"].(map[string]any); ok && nw["mode"] == "allowlist" {
			if allow, _ := nw["allow"].([]any); len(allow) > 0 && allow[0] == "bad.example:9" {
				writeErr(w, 400, "invalid_network_allowlist", "port 9 is not allowed")
				return
			}
		}
		if sid, ok := req["snapshot_id"].(string); ok {
			if _, known := f.snaps[sid]; !known {
				writeErr(w, 404, "snapshot_not_found", "no snapshot "+sid)
				return
			}
		}
		f.n++
		id := fmt.Sprintf("sbx_%d", f.n)
		f.rooms = append(f.rooms, map[string]any{"id": id, "state": "running", "labels": req["labels"]})
		w.Header().Set("X-Room-Receipt", "signed-create")
		writeJSON(w, 202, map[string]any{"id": id, "state": "running", "snapshot_id": req["snapshot_id"]})
	case p == "/v1/sandboxes" && r.Method == "GET":
		// Like a hotel: every "label" filter must match.
		out := []map[string]any{}
		for _, rm := range f.rooms {
			labels, _ := rm["labels"].(map[string]any)
			keep := true
			for _, want := range r.URL.Query()["label"] {
				k, v, _ := strings.Cut(want, "=")
				if labels[k] != v {
					keep = false
				}
			}
			if keep {
				out = append(out, rm)
			}
		}
		writeJSON(w, 200, map[string]any{"sandboxes": out})
	case p == "/v1/sandboxes" && r.Method == "DELETE":
		f.bulkDeletes = append(f.bulkDeletes, r.URL.Query()["label"])
		kept := f.rooms[:0]
		for _, rm := range f.rooms {
			labels, _ := rm["labels"].(map[string]any)
			match := true
			for _, want := range r.URL.Query()["label"] {
				k, v, _ := strings.Cut(want, "=")
				if labels[k] != v {
					match = false
				}
			}
			if !match {
				kept = append(kept, rm)
			}
		}
		f.rooms = kept
		w.WriteHeader(204)
	case p == "/room/attest" && r.Method == "POST":
		f.attestIn = append(f.attestIn, body)
		f.attestAuth = append(f.attestAuth, r.Header.Get("Authorization"))
		f.attestGuest = append(f.attestGuest, r.Header.Get(guestHeader))
		if bytes.Contains(body, []byte("slow-down")) {
			w.Header().Set("Retry-After", "17")
			writeJSON(w, 429, map[string]string{"error": "attest_rate_limit"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"report_b64":"UkVQT1JU","cert_chain":null,"binding_sha256":"bb","measurement":"aa","generated_at":1761400000,"echo":` + strconv.Quote(string(body)) + `}`))
	case p == "/room/receipts" && r.Method == "GET":
		if f.receipts == nil {
			writeErr(w, 404, "no_receipts", "no chain")
			return
		}
		// Page like a real hotel when after/limit are set so broker walk tests
		// can leave a guest receipt past the first hotel page. Ops (and old
		// callers) with no query still get the stored bytes unchanged.
		afterStr, limitStr := r.URL.Query().Get("after"), r.URL.Query().Get("limit")
		if afterStr != "" || limitStr != "" {
			var chain struct {
				Binding  string            `json:"binding_sha256"`
				Head     string            `json:"head"`
				Receipts []json.RawMessage `json:"receipts"`
			}
			if json.Unmarshal(f.receipts, &chain) == nil && len(chain.Receipts) > 0 {
				after, _ := strconv.Atoi(afterStr)
				limit, _ := strconv.Atoi(limitStr)
				if limit < 1 {
					limit = len(chain.Receipts)
				}
				if after < 0 {
					after = 0
				}
				end := after + limit
				if after > len(chain.Receipts) {
					after = len(chain.Receipts)
				}
				if end > len(chain.Receipts) {
					end = len(chain.Receipts)
				}
				page := chain.Receipts[after:end]
				out, _ := json.Marshal(map[string]any{
					"binding_sha256": chain.Binding, "head": chain.Head,
					"count": len(page), "receipts": page,
				})
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				_, _ = w.Write(out)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(f.receipts)
	case p == "/room/health" && f.healthFail:
		writeErr(w, 503, "busy", "health did not answer")
	case p == "/room/health" || p == "/v1/quota" || p == "/v1/status":
		writeJSON(w, 200, map[string]any{})
	case strings.HasSuffix(p, "/network") && r.Method == "PUT":
		f.networks = append(f.networks, req)
		if req["mode"] == "allowlist" && len(req["allow"].([]any)) > 0 && req["allow"].([]any)[0] == "::1" {
			writeErr(w, 400, "invalid_network_allowlist", "IPv6 is not supported")
			return
		}
		w.Header().Set("X-Room-Receipt", "signed-receipt")
		policy := map[string]any{"mode": req["mode"], "allow": req["allow"]}
		writeJSON(w, 200, map[string]any{"sandbox_id": strings.Split(p, "/")[3],
			"network": map[string]any{"mode": req["mode"], "allow": req["allow"], "policy": policy, "policy_sha256": "abc"}})
	case strings.HasSuffix(p, "/exec") && r.Method == "POST":
		f.execs = append(f.execs, req)
		w.Header().Set("X-Room-Receipt", "signed-exec")
		writeJSON(w, 200, map[string]any{"exit_code": 0, "stdout": "", "stderr": "", "timed_out": false})
	case p == "/v1/images/build" && r.Method == "POST":
		f.builds = append(f.builds, req)
		if f.failBuild {
			writeErr(w, 502, "image_build_failed", "docker build failed")
			return
		}
		writeJSON(w, 200, map[string]any{"image": "cathedral-build-0123456789abcdef:latest", "cached": false})
	case strings.HasSuffix(p, "/snapshot") && r.Method == "POST":
		f.n++
		sid := "snap_" + string(rune('a'+f.n))
		doc := map[string]any{"snapshot_id": sid, "labels": req["labels"], "size_bytes": 10}
		if name, ok := req["name"].(string); ok {
			doc["name"] = name
		}
		f.snaps[sid] = doc
		writeJSON(w, 202, map[string]any{"operation_id": "op_1", "status": "done", "result": doc})
	case p == "/v1/snapshots" && r.Method == "GET":
		want := r.URL.Query().Get("label")
		k, v, _ := strings.Cut(want, "=")
		out := []map[string]any{}
		for _, d := range f.snaps {
			labels, _ := d["labels"].(map[string]any)
			if labels[k] == v {
				cp := map[string]any{}
				for kk, vv := range d {
					cp[kk] = vv
				}
				out = append(out, cp)
			}
		}
		writeJSON(w, 200, map[string]any{"snapshots": out})
	case strings.HasPrefix(p, "/v1/snapshots/") && strings.HasSuffix(p, "/push"):
		sid := strings.TrimSuffix(strings.TrimPrefix(p, "/v1/snapshots/"), "/push")
		f.pushes = append(f.pushes, req)
		writeJSON(w, 200, map[string]any{"snapshot_id": sid, "image": req["image"], "includes_work": false})
	case strings.HasPrefix(p, "/v1/snapshots/") && r.Method == "DELETE":
		sid := strings.TrimPrefix(p, "/v1/snapshots/")
		delete(f.snaps, sid)
		f.deleted = append(f.deleted, sid)
		writeJSON(w, 200, map[string]any{"deleted": true})
	case p == "/v1/images/prefetch":
		f.prefetch = append(f.prefetch, req)
		if f.pullDelay > 0 {
			f.mu.Unlock()
			time.Sleep(f.pullDelay)
			f.mu.Lock()
		}
		if f.failPull {
			writeErr(w, 502, "image_pull_failed", "pull access denied")
			return
		}
		images := []any{}
		for _, ref := range req["images"].([]any) {
			images = append(images, map[string]any{"ref": ref, "size_bytes": 3640000})
		}
		writeJSON(w, 202, map[string]any{"operation_id": "op_2", "status": "done", "result": map[string]any{"images": images}})
	case strings.HasPrefix(p, "/v1/sandboxes/") && strings.Count(p, "/") == 3 && r.Method == "GET":
		id := strings.TrimPrefix(p, "/v1/sandboxes/")
		for _, rm := range f.rooms {
			if rm["id"] == id {
				writeJSON(w, 200, map[string]any{"id": id, "state": "running", "labels": rm["labels"], "runtime": "docker",
					"network": map[string]any{"mode": "deny_all", "allow": []any{}}})
				return
			}
		}
		writeErr(w, 404, "sandbox_not_found", id)
	case strings.HasPrefix(p, "/v1/sandboxes/") && strings.Count(p, "/") == 3 && r.Method == "DELETE":
		id := strings.TrimPrefix(p, "/v1/sandboxes/")
		f.roomDeletes = append(f.roomDeletes, id)
		for i, rm := range f.rooms {
			if rm["id"] == id {
				f.rooms = append(f.rooms[:i], f.rooms[i+1:]...)
				w.Header().Set("X-Room-Receipt", "signed-delete")
				w.WriteHeader(204)
				return
			}
		}
		writeErr(w, 404, "sandbox_not_found", "no sandbox "+id)
	default:
		writeErr(w, 404, "route_not_found", p)
	}
}

type testChain struct {
	b       *broker
	srv     *httptest.Server
	hotels  map[string]*fakeHotel
	cfgPath string
}

// newChain builds a broker over fake hotels "a" (sealed), "b" and "c".
func newChain(t *testing.T) *testChain { return newChainState(t, "") }

// newChainState is newChain with a broker state_dir.
func newChainState(t *testing.T, stateDir string) *testChain {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "hotel.key")
	if err := os.WriteFile(key, []byte("hotel-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	tc := &testChain{hotels: map[string]*fakeHotel{}}
	cfg := config{StateDir: stateDir, OperatorKeySHA256: sha("operator-key"), InsecureCookie: true, Guests: []guestConfig{{ID: "g1", KeySHA256: sha("key1"), ViewTokenSHA256: sha("view1")}, {ID: "g2", KeySHA256: sha("key2")}}}
	for _, id := range []string{"a", "b", "c"} {
		f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
		hs := httptest.NewServer(f)
		t.Cleanup(hs.Close)
		tc.hotels[id] = f
		hc := hotelConfig{ID: id, Name: id, API: hs.URL, Health: hs.URL, KeyFile: key, Concurrency: 4}
		if id == "a" {
			hc.Labels = map[string]string{"sealed": "true"}
		}
		cfg.Hotels = append(cfg.Hotels, hc)
	}
	raw, _ := json.Marshal(cfg)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.cfgPath = cfgPath
	tc.start(t)
	return tc
}

// start (or restart) the broker over the same hotels and config.
func (tc *testChain) start(t *testing.T) {
	t.Helper()
	if tc.srv != nil {
		tc.srv.Close()
	}
	b, err := loadBroker(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.loadCompat(); err != nil {
		t.Fatal(err)
	}
	if err := b.loadRuntimeHotels(); err != nil {
		t.Fatal(err)
	}
	for _, h := range b.hotelList() {
		h.ok, h.slots = true, 100
	}
	tc.b = b
	tc.srv = httptest.NewServer(b)
	t.Cleanup(tc.srv.Close)
}

func (tc *testChain) call(t *testing.T, key, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, tc.srv.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, doc
}

func errCode(doc map[string]any) string {
	e, _ := doc["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func (tc *testChain) room(t *testing.T, key string, body map[string]any) string {
	t.Helper()
	status, doc := tc.call(t, key, "POST", "/v1/sandboxes", body)
	if status != 202 {
		t.Fatalf("create: %d %v", status, doc)
	}
	return doc["id"].(string)
}

func createsOn(tc *testChain) map[string]int {
	out := map[string]int{}
	for id, f := range tc.hotels {
		f.mu.Lock()
		out[id] = len(f.creates)
		f.mu.Unlock()
	}
	return out
}

func TestSnapshotIDNamesTheOwnerHotelAndForksGoOnlyThere(t *testing.T) {
	tc := newChain(t)
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if !strings.HasPrefix(room, "b.") {
		t.Fatalf("room %s not on hotel b", room)
	}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", map[string]any{"name": "busy"})
	if status != 202 {
		t.Fatalf("snapshot: %d %v", status, doc)
	}
	res := doc["result"].(map[string]any)
	snapID := res["snapshot_id"].(string)
	if !strings.HasPrefix(snapID, "b.snap_") || res["name"] != "busy" || res["hotel"] != "b" {
		t.Fatalf("snapshot result %v", res)
	}
	// The hotel got the guest label and a guest-scoped name.
	for _, d := range tc.hotels["b"].snaps {
		if d["name"] != "g1:busy" || d["labels"].(map[string]any)[guestLabel] != "g1" {
			t.Fatalf("hotel snapshot %v", d)
		}
	}
	before := createsOn(tc)
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": snapID, "count": 6})
	if status != 202 || doc["count"].(float64) != 6 {
		t.Fatalf("fork: %d %v", status, doc)
	}
	after := createsOn(tc)
	if after["a"] != before["a"] || after["c"] != before["c"] || after["b"]-before["b"] != 6 {
		t.Fatalf("forks scattered: before %v after %v", before, after)
	}
	for _, s := range doc["sandboxes"].([]any) {
		if s.(map[string]any)["snapshot_id"] != snapID {
			t.Fatalf("fork doc %v", s)
		}
	}
	// A fork by the bare name also finds hotel b.
	status, _ = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": "busy"})
	if status != 202 || createsOn(tc)["b"] != after["b"]+1 {
		t.Fatalf("fork by name: %d", status)
	}
}

func TestForkOfUnknownOrForeignSnapshotIs404AndStartsNothing(t *testing.T) {
	tc := newChain(t)
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	_, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", map[string]any{})
	snapID := doc["result"].(map[string]any)["snapshot_id"].(string)
	before := createsOn(tc)
	for _, c := range []struct{ key, ref string }{
		{"key1", "a.snap_zzz"},
		{"key1", "snap_zzz"},
		{"key2", snapID}, // another guest's snapshot
	} {
		status, doc := tc.call(t, c.key, "POST", "/v1/sandboxes", map[string]any{"snapshot_id": c.ref})
		if status != 404 || errCode(doc) != "snapshot_not_found" {
			t.Fatalf("%s %s: %d %v", c.key, c.ref, status, doc)
		}
	}
	if after := createsOn(tc); after["a"] != before["a"] || after["b"] != before["b"] || after["c"] != before["c"] {
		t.Fatalf("a refused fork reached a hotel: %v -> %v", before, after)
	}
}

func TestForkWaitsForTheOwnerHotelInsteadOfScattering(t *testing.T) {
	tc := newChain(t)
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}})
	_, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", map[string]any{})
	snapID := doc["result"].(map[string]any)["snapshot_id"].(string)
	tc.b.mu.Lock()
	tc.b.hotelByID("c").cfg.Drain = true
	tc.b.mu.Unlock()
	before := createsOn(tc)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": snapID})
	if status != 503 || errCode(doc) != "snapshot_hotel_unavailable" {
		t.Fatalf("fork to a draining owner: %d %v", status, doc)
	}
	if after := createsOn(tc); after["a"] != before["a"] || after["b"] != before["b"] {
		t.Fatalf("fork went to another hotel")
	}
}

func TestSnapshotListPushAndDeleteThroughTheBroker(t *testing.T) {
	tc := newChain(t)
	r1 := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	r2 := tc.room(t, "key2", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	_, d1 := tc.call(t, "key1", "POST", "/v1/sandboxes/"+r1+"/snapshot", map[string]any{"name": "one"})
	tc.call(t, "key2", "POST", "/v1/sandboxes/"+r2+"/snapshot", map[string]any{"name": "two"})
	snapID := d1["result"].(map[string]any)["snapshot_id"].(string)

	status, doc := tc.call(t, "key1", "GET", "/v1/snapshots", nil)
	list := doc["snapshots"].([]any)
	if status != 200 || len(list) != 1 || list[0].(map[string]any)["snapshot_id"] != snapID || list[0].(map[string]any)["name"] != "one" {
		t.Fatalf("list: %d %v", status, doc)
	}

	auth := map[string]any{"username": "robot", "password": "s3cret"}
	status, doc = tc.call(t, "key1", "POST", "/v1/snapshots/"+snapID+"/push", map[string]any{"image": "ghcr.io/acme/forks:one", "registry_auth": auth})
	if status != 200 || doc["snapshot_id"] != snapID || doc["image"] != "ghcr.io/acme/forks:one" {
		t.Fatalf("push: %d %v", status, doc)
	}
	if got := tc.hotels["a"].pushes[0]["registry_auth"].(map[string]any)["password"]; got != "s3cret" {
		t.Fatalf("login not passed to the hotel")
	}
	// Guest 2 cannot push or delete guest 1's snapshot.
	if status, _ := tc.call(t, "key2", "DELETE", "/v1/snapshots/"+snapID, nil); status != 404 {
		t.Fatalf("foreign delete: %d", status)
	}
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/snapshots/"+snapID, nil); status != 200 {
		t.Fatalf("delete: %d", status)
	}
	if len(tc.hotels["a"].deleted) != 1 {
		t.Fatalf("hotel delete not called")
	}
	// After a push, a create from the image goes to any hotel.
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "ghcr.io/acme/forks:one"}); status != 202 {
		t.Fatalf("create from pushed image: %d", status)
	}
}

func TestCreateByHotelLabelsAndIDs(t *testing.T) {
	tc := newChain(t)
	for i := 0; i < 5; i++ {
		if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotel_labels": map[string]string{"sealed": "true"}}); !strings.HasPrefix(id, "a.") {
			t.Fatalf("sealed room on %s", id)
		}
		if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "exclude_hotel_labels": map[string]string{"sealed": "true"}}); strings.HasPrefix(id, "a.") {
			t.Fatalf("excluded hotel used: %s", id)
		}
	}
	// The broker fields never reach a hotel.
	for _, f := range tc.hotels {
		for _, c := range f.creates {
			for _, k := range []string{"hotels", "hotel_labels", "exclude_hotel_labels"} {
				if _, ok := c[k]; ok {
					t.Fatalf("hotel got %s", k)
				}
			}
		}
	}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotel_labels": map[string]string{"sealed": "maybe"}})
	if status != 409 || errCode(doc) != "no_matching_hotel" {
		t.Fatalf("no match: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"zz"}})
	if status != 409 || errCode(doc) != "unknown_hotel" { // CONST: unknown hotel is 409, not 400

		t.Fatalf("unknown hotel: %d %v", status, doc)
	}
	// Selected hotel full: 429, never another hotel.
	tc.b.mu.Lock()
	tc.b.hotelByID("a").slots = len(tc.b.hotelByID("a").rooms)
	tc.b.mu.Unlock()
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotel_labels": map[string]string{"sealed": "true"}})
	if status != 429 || errCode(doc) != "no_free_rooms" {
		t.Fatalf("full sealed hotel: %d %v", status, doc)
	}
	// Selected hotel down: 503 hotels_unavailable — not "all hotels are full".
	setHotel(tc, "a", func(h *hotel) { h.ok = false; h.slots = 100 })
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	if status != 503 || errCode(doc) != "hotels_unavailable" {
		t.Fatalf("down hotel: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "GET", "/v1/broker/hotels", nil)
	if status != 200 || len(doc["hotels"].([]any)) != 3 {
		t.Fatalf("hotels: %d %v", status, doc)
	}
}

func TestForkOutsideTheHotelSelectionIs409(t *testing.T) {
	tc := newChain(t)
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	_, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", map[string]any{})
	snapID := doc["result"].(map[string]any)["snapshot_id"].(string)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": snapID, "hotel_labels": map[string]string{"sealed": "true"}})
	if status != 409 || errCode(doc) != "snapshot_hotel_excluded" {
		t.Fatalf("%d %v", status, doc)
	}
}

func waitPrefetch(t *testing.T, tc *testChain, key, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, doc := tc.call(t, key, "GET", "/v1/images/prefetch/"+id, nil)
		if status != 200 {
			t.Fatalf("status: %d %v", status, doc)
		}
		if doc["state"] != "pulling" || time.Now().After(deadline) {
			return doc
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPrefetchToChosenHotelsWithLoginAndStatus(t *testing.T) {
	tc := newChain(t)
	tc.hotels["c"].failPull = true
	tc.hotels["a"].pullDelay = 200 * time.Millisecond
	auth := map[string]any{"username": "robot", "password": "s3cret"}
	status, doc := tc.call(t, "key1", "POST", "/v1/images/prefetch", map[string]any{
		"images": []string{"ghcr.io/acme/private:1"}, "registry_auth": auth, "hotels": []string{"a", "c"},
	})
	if status != 202 || doc["state"] != "pulling" {
		t.Fatalf("prefetch: %d %v", status, doc)
	}
	if strings.Contains(mustJSON(doc), "s3cret") {
		t.Fatalf("answer shows the password")
	}
	id := doc["prefetch_id"].(string)
	hotels := doc["hotels"].(map[string]any)
	if len(hotels) != 2 || hotels["b"] != nil {
		t.Fatalf("targets: %v", hotels)
	}
	final := waitPrefetch(t, tc, "key1", id)
	hs := final["hotels"].(map[string]any)
	a := hs["a"].(map[string]any)
	c := hs["c"].(map[string]any)
	if a["state"] != "done" || a["images"].([]any)[0].(map[string]any)["size_bytes"].(float64) != 3640000 {
		t.Fatalf("hotel a: %v", a)
	}
	if c["state"] != "failed" || c["error"].(map[string]any)["code"] != "image_pull_failed" {
		t.Fatalf("hotel c: %v", c)
	}
	if final["state"] != "failed" || strings.Contains(mustJSON(final), "s3cret") {
		t.Fatalf("final: %v", final)
	}
	if got := tc.hotels["a"].prefetch[0]["registry_auth"].(map[string]any)["password"]; got != "s3cret" {
		t.Fatalf("login not passed to the hotel")
	}
	if len(tc.hotels["b"].prefetch) != 0 {
		t.Fatalf("hotel b was not chosen")
	}
	// Another guest cannot read the job.
	if status, _ := tc.call(t, "key2", "GET", "/v1/images/prefetch/"+id, nil); status != 404 {
		t.Fatalf("foreign status: %d", status)
	}
	// By label, no login.
	status, doc = tc.call(t, "key1", "POST", "/v1/images/prefetch", map[string]any{"images": []string{"alpine:3.20"}, "hotel_labels": map[string]string{"sealed": "true"}})
	if status != 202 || len(doc["hotels"].(map[string]any)) != 1 {
		t.Fatalf("label prefetch: %d %v", status, doc)
	}
	waitPrefetch(t, tc, "key1", doc["prefetch_id"].(string))
	if _, ok := tc.hotels["a"].prefetch[1]["registry_auth"]; ok {
		t.Fatalf("login sent when none was given")
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestCompatUnknownTemplateIsAnErrorNotABaseImageRoom(t *testing.T) {
	tc := newChain(t)
	send := func(tpl string) int {
		raw, _ := json.Marshal(map[string]any{"template": tpl})
		req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer key1")
		req.Header.Set("User-Agent", "ctcli/1.0")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	before := createsOn(tc)
	if got := send("no-such-template"); got != 404 {
		t.Fatalf("unknown template: %d", got)
	}
	after := createsOn(tc)
	for id := range before {
		if after[id] != before[id] {
			t.Fatalf("unknown template reached hotel %s", id)
		}
	}
	if got := send("room-2x8"); got != 201 {
		t.Fatalf("catalog template: %d", got)
	}
	var last map[string]any
	for _, f := range tc.hotels {
		if len(f.creates) > 0 {
			last = f.creates[len(f.creates)-1]
		}
	}
	if res := last["resources"].(map[string]any); res["vcpu"].(float64) != 2 || res["memory_gib"].(float64) != 8 {
		t.Fatalf("template resources: %v", res)
	}
}

func TestSealedHotelTakesOnlySealedCreates(t *testing.T) {
	tc := newChain(t)
	// Make "b" a config-sealed hotel: exclusive, label added by the broker.
	h := tc.b.hotelByID("b")
	h.cfg.Sealed = true
	h.cfg.Labels = map[string]string{"sealed": "true"}
	for i := 0; i < 20; i++ {
		if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"}); strings.HasPrefix(id, "b.") {
			t.Fatalf("plain create landed on the sealed hotel: %s", id)
		}
		if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "sealed": true}); strings.HasPrefix(id, "c.") {
			t.Fatalf("sealed create landed on an unsealed hotel: %s", id)
		}
	}
	if id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}); !strings.HasPrefix(id, "b.") {
		t.Fatalf("named sealed hotel not used: %s", id)
	}
	for _, f := range tc.hotels {
		for _, c := range f.creates {
			if _, ok := c["sealed"]; ok {
				t.Fatal("hotel got the broker field sealed")
			}
		}
	}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "sealed": "yes"})
	if status != 400 || errCode(doc) != "invalid_hotel_selection" {
		t.Fatalf("bad sealed value: %d %v", status, doc)
	}
}

// A guest's bad request (4xx from the hotel) must not rest the hotel: the
// next create, from any guest, still lands there.
func TestClientErrorDoesNotRestHotel(t *testing.T) {
	tc := newChain(t)
	bad := map[string]any{"image": "alpine:3.20", "hotels": []string{"b"},
		"network": map[string]any{"mode": "allowlist", "allow": []string{"bad.example:9"}}}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", bad)
	if status != 400 || errCode(doc) != "invalid_network_allowlist" {
		t.Fatalf("bad allowlist: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if status != 202 {
		t.Fatalf("next create after a client error: %d %v", status, doc)
	}
}

// A hotel that rejects the broker's own key (401/403) is broken, not the
// request: rest it so the next create goes to a working hotel.
func TestHotelAuthErrorRestsHotel(t *testing.T) {
	tc := newChain(t)
	tc.hotels["b"].authFail = true
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if status != 401 {
		t.Fatalf("create on broken hotel: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	resting := time.Now().Before(tc.b.hotelByID("b").backoffUntil)
	tc.b.mu.Unlock()
	if !resting {
		t.Fatalf("hotel answering 401 to the broker key is not rested")
	}
}

// A guest's contract error (400) must not rest the hotel.
func TestClientErrorLeavesHotelUnrested(t *testing.T) {
	tc := newChain(t)
	bad := map[string]any{"image": "alpine:3.20", "hotels": []string{"b"},
		"network": map[string]any{"mode": "allowlist", "allow": []string{"bad.example:9"}}}
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", bad); status != 400 {
		t.Fatalf("bad allowlist: %d", status)
	}
	tc.b.mu.Lock()
	resting := time.Now().Before(tc.b.hotelByID("b").backoffUntil)
	tc.b.mu.Unlock()
	if resting {
		t.Fatalf("a guest's 400 rested the hotel")
	}
}

func callsTo(f *fakeHotel, prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// An image the guest names wrongly is the guest's error: it must not rest
// the hotel for every other guest.
func TestImagePullFailureDoesNotRestHotel(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "nosuch/x:1", "hotels": []string{"b"}})
	if status != 502 || errCode(doc) != "image_pull_failed" {
		t.Fatalf("bad image: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	resting := time.Now().Before(tc.b.hotelByID("b").backoffUntil)
	tc.b.mu.Unlock()
	if resting {
		t.Fatalf("a guest's unpullable image rested the hotel")
	}
}

// Bulk delete only reaches the guest's own hotels.
func TestBulkDeleteKeepsToGuestHotels(t *testing.T) {
	tc := limitedChain(t, guestLimits{Hotels: []string{"b", "c"}})
	tc.call(t, "key1", "DELETE", "/v1/sandboxes?label=job%3Dx", nil)
	if n := callsTo(tc.hotels["a"], "DELETE /v1/sandboxes"); n != 0 {
		t.Fatalf("bulk delete reached hotel a outside the guest's list (%d)", n)
	}
	if callsTo(tc.hotels["b"], "DELETE /v1/sandboxes") == 0 {
		t.Fatalf("bulk delete did not reach an allowed hotel")
	}
}

// A guest reads receipts only of hotels in its list, ops included: a
// dedicated hotel's chain belongs to its guest.
func TestReceiptsOfHotelOutsideListAre404(t *testing.T) {
	tc := limitedChain(t, guestLimits{Hotels: []string{"b", "c"}})
	tc.b.guests["g1"].cfg.Ops = true
	tc.hotels["a"].receipts = []byte(`{"receipts":[],"count":0}`)
	if status, doc := tc.call(t, "key1", "GET", "/v1/hotels/a/receipts", nil); status != 404 {
		t.Fatalf("receipts of a hotel outside the list: %d %v", status, doc)
	}
}

// A hotel that cannot reach the registry is the hotel's fault: rest it and
// place the create on another hotel.
func TestRegistryOutageRestsHotelAndRetries(t *testing.T) {
	tc := newChain(t)
	tc.hotels["b"].pullOutage = true
	tc.hotels["c"].pullOutage = false
	tc.b.mu.Lock()
	tc.b.hotelByID("c").slots = 1 // prefer b first
	tc.b.mu.Unlock()
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if status != 502 {
		t.Fatalf("outage on the only hotel: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	resting := time.Now().Before(tc.b.hotelByID("b").backoffUntil)
	tc.b.mu.Unlock()
	if !resting {
		t.Fatalf("a hotel that cannot reach the registry is not rested")
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}})
	if status != 202 || doc["hotel"] != "c" {
		t.Fatalf("create did not move to a working hotel: %d %v", status, doc)
	}
}
