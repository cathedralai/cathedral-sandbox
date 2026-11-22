package main

// Test rig of the ready-room pool (AB#894 phase 2 PR 2): a fake sealed hotel
// that behaves as room_receipts.py in front of the hotel API for the calls
// the pool makes, and a broker over such hotels.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePoolRoom is one room of a fakePoolHotel.
type fakePoolRoom struct {
	id       string
	labels   map[string]string
	expires  time.Time
	receipts [][]byte // this room's receipts in the front's current chain
}

// fakePoolCall is one request the fake got.
type fakePoolCall struct {
	at     time.Time
	method string
	path   string
	body   []byte
	header http.Header
}

type fakePoolHotel struct {
	t       *testing.T
	mu      sync.Mutex
	priv    ed25519.PrivateKey
	attest  []byte // GET /room/attestation body
	binding string // its binding_sha256
	n       int
	rooms   map[string]*fakePoolRoom
	calls   []fakePoolCall
	// Knobs.
	signNoPool    bool          // sign creates without "pool": true (the front withholds it)
	signOtherKey  bool          // sign creates with a key the binding does not name
	signOtherRoom bool          // the receipt names another room id
	noReceipt     bool          // answer creates without X-Room-Receipt
	createTTL     time.Duration // 0: the ttl_seconds sent
	healthFail    bool
	listFail      bool
	attestFail    bool
	deleteFail    bool
	createFail    bool            // answer creates 503 and start no room
	coldImages    map[string]bool // a prefetch of one of these answers 502: the image stays cold
	readFail      bool
	prefetchGate  chan struct{} // non-nil: a prefetch waits for it
}

func newFakePoolHotel(t *testing.T) *fakePoolHotel {
	f := &fakePoolHotel{t: t, rooms: map[string]*fakePoolRoom{}}
	f.newBinding()
	return f
}

// newBinding is a receipts front restart (or a guest reboot): a new receipt
// key, so a new binding, and a new, empty chain.
func (f *fakePoolHotel) newBinding() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	f.priv = priv
	f.attest = snpAttestation(f.t, attestOpts{receiptKey: pub})
	var doc struct {
		BindingSHA string `json:"binding_sha256"`
	}
	_ = json.Unmarshal(f.attest, &doc)
	f.binding = doc.BindingSHA
	for _, r := range f.rooms {
		r.receipts = nil
	}
}

// receipt signs a statement as the front does and returns the canonical
// receipt.
func (f *fakePoolHotel) receipt(priv ed25519.PrivateKey, st map[string]any) []byte {
	stmt, err := canonicalJSON(st)
	if err != nil {
		f.t.Fatal(err)
	}
	sum := sha256.Sum256(stmt)
	rc := map[string]any{"statement": json.RawMessage(stmt), "signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, stmt)),
		"receipt_sha256": hex.EncodeToString(sum[:])}
	raw, err := canonicalJSON(rc)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// createStatement is the statement of a create receipt of room id.
func (f *fakePoolHotel) createStatement(id, image string, pool bool) map[string]any {
	st := map[string]any{"schema": sealedReceiptSchema, "binding_sha256": f.binding, "hotel": "miner", "action": "create",
		"target": "POST /v1/sandboxes", "sandbox_id": id, "image": image, "status": 201,
		"network_policy": map[string]any{"mode": "deny_all", "allow": []string{}}, "room_sequence": 1,
		"room_previous_receipt_sha256": nil, "issued_at": time.Now().Unix()}
	if pool {
		st["pool"] = true
	}
	return st
}

// addRoom puts a pool-labelled room on the hotel, as one left from before
// a broker restart. receipts: "pool" (its receipt 1), "claim" (a claim
// after it), "create" (a create not signed pool), "pool-other-image" (a pool
// receipt 1 of an image that is no key). None: the front's chain holds
// nothing for it.
func (f *fakePoolHotel) addRoom(id string, receipts ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := &fakePoolRoom{id: id, labels: map[string]string{poolLabel: "1", guestLabel: poolGuestID}, expires: time.Now().Add(4 * time.Hour)}
	for _, kind := range receipts {
		switch kind {
		case "pool", "create":
			r.receipts = append(r.receipts, f.receipt(f.priv, f.createStatement(id, nodeImage(), kind == "pool")))
		case "pool-other-image":
			r.receipts = append(r.receipts, f.receipt(f.priv, f.createStatement(id, "alpine:3.20", true)))
		case "claim":
			prev := sha256.Sum256(r.receipts[len(r.receipts)-1])
			r.receipts = append(r.receipts, f.receipt(f.priv, map[string]any{"schema": sealedReceiptSchema, "binding_sha256": f.binding,
				"action": "claim", "sandbox_id": id, "status": 200, "room_sequence": len(r.receipts) + 1,
				"room_previous_receipt_sha256": hex.EncodeToString(prev[:]), "cathedral_sandbox_id": "00000000-0000-4000-8000-000000000001"}))
		}
	}
	f.rooms[id] = r
}

func nodeImage() string {
	t, _ := templateByName("node-22")
	return t.Image
}

func (f *fakePoolHotel) callsOf(method, prefix string) []fakePoolCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakePoolCall
	for _, c := range f.calls {
		if c.method == method && strings.HasPrefix(c.path, prefix) {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakePoolHotel) creates() []fakePoolCall { return f.callsOf("POST", "/v1/sandboxes") }

func (f *fakePoolHotel) roomDeletes() []fakePoolCall {
	var out []fakePoolCall
	for _, c := range f.callsOf("DELETE", "/v1/sandboxes/") {
		out = append(out, c)
	}
	return out
}

func (f *fakePoolHotel) roomCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rooms)
}

func (f *fakePoolHotel) set(fn func(f *fakePoolHotel)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakePoolHotel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, fakePoolCall{at: time.Now(), method: r.Method, path: r.URL.Path, body: body, header: r.Header.Clone()})
	gate := f.prefetchGate
	f.mu.Unlock()
	if r.Method == "POST" && r.URL.Path == "/v1/images/prefetch" && gate != nil {
		<-gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	p := r.URL.Path
	switch {
	case p == "/room/health":
		if f.healthFail {
			reply(503, map[string]any{"error": "down"})
			return
		}
		reply(200, map[string]any{"slots": 100, "sandboxes_running": len(f.rooms), "live": map[string]any{"host_mem_used_pct": 10.0}})
	case p == "/room/attestation":
		if f.attestFail || f.healthFail {
			reply(503, map[string]any{"error": "down"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.attest)
	case p == "/v1/quota":
		reply(200, map[string]any{"usage": map[string]any{}})
	case p == "/v1/images/prefetch" && r.Method == "POST":
		var doc struct {
			Images []string `json:"images"`
		}
		_ = json.Unmarshal(body, &doc)
		for _, img := range doc.Images {
			if f.coldImages[img] {
				reply(502, map[string]any{"error": map[string]any{"code": "image_pull_failed"}})
				return
			}
		}
		reply(200, map[string]any{"state": "done"})
	case p == "/v1/sandboxes" && r.Method == "GET":
		if f.listFail || f.healthFail {
			reply(503, map[string]any{"error": "list failed"})
			return
		}
		ids := make([]string, 0, len(f.rooms))
		for id := range f.rooms {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		list := []map[string]any{}
		for _, id := range ids {
			rm := f.rooms[id]
			list = append(list, map[string]any{"id": id, "state": "running", "labels": rm.labels,
				"resources": map[string]any{"vcpu": 1, "memory_gib": 4, "disk_gib": 10}, "expires_at": rm.expires.UTC().Format(time.RFC3339)})
		}
		reply(200, map[string]any{"sandboxes": list})
	case p == "/v1/sandboxes" && r.Method == "POST" && f.createFail:
		reply(503, map[string]any{"error": map[string]any{"code": "pool_state_unknown"}})
	case p == "/v1/sandboxes" && r.Method == "POST":
		var doc struct {
			Image  string            `json:"image"`
			Labels map[string]string `json:"labels"`
			TTL    int               `json:"ttl_seconds"`
		}
		_ = json.Unmarshal(body, &doc)
		f.n++
		id := fmt.Sprintf("sbx-%d", f.n)
		ttl := time.Duration(doc.TTL) * time.Second
		if f.createTTL > 0 {
			ttl = f.createTTL
		}
		rm := &fakePoolRoom{id: id, labels: doc.Labels, expires: time.Now().Add(ttl)}
		f.rooms[id] = rm
		named := id
		if f.signOtherRoom {
			named = "sbx-other"
		}
		priv := f.priv
		if f.signOtherKey {
			_, priv, _ = ed25519.GenerateKey(rand.Reader)
		}
		rc := f.receipt(priv, f.createStatement(named, doc.Image, !f.signNoPool))
		rm.receipts = append(rm.receipts, rc)
		if !f.noReceipt {
			w.Header().Set("X-Room-Receipt", base64.URLEncoding.EncodeToString(rc))
		}
		reply(201, map[string]any{"id": id, "state": "running", "labels": doc.Labels,
			"resources": map[string]any{"vcpu": 1, "memory_gib": 4, "disk_gib": 10}, "expires_at": rm.expires.UTC().Format(time.RFC3339)})
	case strings.HasPrefix(p, "/v1/sandboxes/") && strings.HasSuffix(p, "/receipts") && r.Method == "GET":
		if f.readFail {
			reply(503, map[string]any{"error": "busy"})
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(p, "/v1/sandboxes/"), "/receipts")
		var list []json.RawMessage
		head := any(nil)
		if rm := f.rooms[id]; rm != nil {
			for _, rc := range rm.receipts {
				list = append(list, rc)
			}
			if n := len(rm.receipts); n > 0 {
				var rc signedReceipt
				_ = json.Unmarshal(rm.receipts[n-1], &rc)
				head = rc.ReceiptSHA256
			}
		}
		if list == nil {
			list = []json.RawMessage{}
		}
		reply(200, map[string]any{"sandbox_id": id, "binding_sha256": f.binding, "count": len(list), "room_head": head, "receipts": list})
	case strings.HasPrefix(p, "/v1/sandboxes/") && r.Method == "DELETE":
		if f.deleteFail {
			reply(500, map[string]any{"error": "delete failed"})
			return
		}
		id := strings.TrimPrefix(p, "/v1/sandboxes/")
		if f.rooms[id] == nil {
			reply(404, map[string]any{"error": map[string]any{"code": "sandbox_not_found"}})
			return
		}
		delete(f.rooms, id)
		w.WriteHeader(204)
	default:
		reply(404, map[string]any{"error": "no route " + r.Method + " " + p})
	}
}

// poolChain is a broker with ready_rooms over fake sealed hotels.
type poolChain struct {
	t        *testing.T
	b        *broker
	srv      *httptest.Server
	hotels   map[string]*fakePoolHotel
	cfgPath  string
	stateDir string
}

// newPoolChain builds a broker with ready_rooms (key node-22), prewarm on,
// over fake sealed hotels ids. mutate may change the config first.
func newPoolChain(t *testing.T, ids []string, mutate func(c *config)) *poolChain {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "hotel.key")
	if err := os.WriteFile(key, []byte("hotel-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	amd := fakeAMDVerifier(t)
	pc := &poolChain{t: t, hotels: map[string]*fakePoolHotel{}, stateDir: filepath.Join(dir, "state")}
	cfg := config{StateDir: pc.stateDir, OperatorKeySHA256: sha("operator-key"), InsecureCookie: true,
		SealedMeasurements: []string{strings.Repeat("ab", 48)}, PrewarmCatalog: true,
		AMDVerifier: &amdVerifierConfig{Command: []string{"/bin/sh", filepath.Join(amd, "verify.sh")}, ARKSHA256: arkPins{testARKPin}},
		Guests:      []guestConfig{{ID: "g1", KeySHA256: sha("key1")}},
		ReadyRooms:  &readyRoomsConfig{Guest: poolGuestID, Keys: []readyRoomKeyEntry{{Template: "node-22"}}}}
	for _, id := range ids {
		f := newFakePoolHotel(t)
		hs := httptest.NewServer(f)
		t.Cleanup(hs.Close)
		pc.hotels[id] = f
		cfg.Hotels = append(cfg.Hotels, hotelConfig{ID: id, Name: id, API: hs.URL, Health: hs.URL, KeyFile: key, Concurrency: 4, Sealed: true})
	}
	if mutate != nil {
		mutate(&cfg)
	}
	raw, _ := json.Marshal(cfg)
	pc.cfgPath = filepath.Join(dir, "config.json")
	if err := os.WriteFile(pc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	old := poolCreateEvery
	poolCreateEvery = 0 // tests step creates back to back; TestPoolCreatesAtMostOneASecondPerHotel keeps the second
	t.Cleanup(func() { poolCreateEvery = old })
	pc.start()
	return pc
}

// start (or restart) the broker over the same hotels, config and state_dir.
// No loop runs: tests drive the sync and the pool steps.
func (pc *poolChain) start() {
	t := pc.t
	t.Helper()
	if pc.srv != nil {
		pc.srv.Close()
		pc.b.pool.close()
	}
	b, err := loadBroker(pc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.loadCompat(); err != nil {
		t.Fatal(err)
	}
	pc.b = b
	pc.srv = httptest.NewServer(b)
	t.Cleanup(pc.srv.Close)
	t.Cleanup(b.pool.close)
}

// up syncs hotel id until it is admitted with its image warm.
func (pc *poolChain) up(id string) {
	pc.t.Helper()
	h := pc.b.hotelByID(id)
	img := nodeImage()
	waitFor(pc.t, "hotel "+id+" admitted and warm", func() bool {
		pc.b.syncHotel(context.Background(), h)
		pc.b.mu.Lock()
		defer pc.b.mu.Unlock()
		return pc.b.admitted(h, time.Now()) && h.warm[img]
	})
}

func (pc *poolChain) sync(id string) { pc.b.syncHotel(context.Background(), pc.b.hotelByID(id)) }

func (pc *poolChain) step(id string) { pc.b.poolStep(context.Background(), pc.b.hotelByID(id)) }

// steps runs n pool steps of hotel id.
func (pc *poolChain) steps(id string, n int) {
	for i := 0; i < n; i++ {
		pc.step(id)
	}
}

// operator calls the broker with the operator key.
func (pc *poolChain) operator(method, path string, body any) (int, map[string]any) {
	pc.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, pc.srv.URL+path, rd)
	req.Header.Set("Authorization", "Bearer operator-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		pc.t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, doc
}

// target sets every hotel's node-22 target to n through the route.
func (pc *poolChain) target(n int) {
	pc.t.Helper()
	st, doc := pc.operator("PUT", "/v1/broker/ready-rooms", map[string]any{"per_hotel": map[string]int{"node-22": n},
		"refill_per_second": 4, "refill_during_claims": 1, "reserve_share": 0.25})
	if st != 200 {
		pc.t.Fatalf("PUT ready-rooms: %d %v", st, doc)
	}
}

// counts is hotel id's pool counts.
func (pc *poolChain) counts(id string) poolCounts {
	pc.b.mu.Lock()
	defer pc.b.mu.Unlock()
	return pc.b.pool.countsLocked(id)
}

func (pc *poolChain) debug(id string) string {
	pc.b.mu.Lock()
	defer pc.b.mu.Unlock()
	return pc.b.pool.poolDebugString(id)
}

// fill steps hotel id until it holds n ready rooms.
func (pc *poolChain) fill(id string, n int) {
	pc.t.Helper()
	for i := 0; i < 4*n+10 && pc.counts(id).ready < n; i++ {
		pc.step(id)
	}
	if c := pc.counts(id); c.ready != n {
		pc.t.Fatalf("hotel %s: %d ready, want %d\n%s", id, c.ready, n, pc.debug(id))
	}
}
