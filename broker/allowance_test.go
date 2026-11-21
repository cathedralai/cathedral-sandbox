package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// lifeHotel sits in front of a fakeHotel's room API. It answers the routes
// that reset a room's deadline (PATCH on the room, heartbeat, lifetime, and
// the room kit's claim) and the room document, and records what each got.
// Everything else goes to the fakeHotel.
type lifeHotel struct {
	inner  *fakeHotel
	mu     sync.Mutex
	seen   []string   // "METHOD /path" of every request
	got    []lifeCall // the lifetime calls, with their bodies
	docTTL any        // ttl_seconds of GET /v1/sandboxes/{id}; nil: none in the document
	// hideDeletes: a room DELETE answers 204 but the container stays, and
	// the room list hides the room, like a hotel whose container removal
	// keeps failing (cathedral/sandbox_provider.py list skips "deleting").
	hideDeletes bool
	hidden      map[string]bool
	// holdCreates, when set, holds each room create until it is closed;
	// enteredCreate gets the hotel's name when a create arrives.
	holdCreates   chan struct{}
	enteredCreate chan string
	name          string
	// holdDeletes, when set, holds each room DELETE until it is closed.
	holdDeletes chan struct{}
	// holdList, when set, takes the room list (no label filter) at once,
	// says so on listTaken, and answers it only when holdList is closed: an
	// answer that arrives later than the moment it describes.
	holdList  chan struct{}
	listTaken chan struct{}
	// holdLabelLists: holdList applies to label-filtered lists (the orphan
	// cleanup) instead of the plain room list.
	holdLabelLists bool
}

type lifeCall struct {
	method, path string
	body         map[string]any
}

func (l *lifeHotel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	l.seen = append(l.seen, r.Method+" "+r.URL.Path)
	hide, holdCreates, entered, holdDeletes := l.hideDeletes, l.holdCreates, l.enteredCreate, l.holdDeletes
	holdList, listTaken, labelLists := l.holdList, l.listTaken, l.holdLabelLists
	l.mu.Unlock()
	if holdList != nil && r.Method == "GET" && r.URL.Path == "/v1/sandboxes" && (r.URL.RawQuery != "") == labelLists {
		rec := httptest.NewRecorder()
		l.inner.ServeHTTP(rec, r)
		listTaken <- struct{}{}
		<-holdList
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
		return
	}
	if holdDeletes != nil && r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/sandboxes/") {
		<-holdDeletes
	}
	if holdCreates != nil && r.URL.Path == "/v1/sandboxes" && r.Method == "POST" {
		entered <- l.name
		<-holdCreates
	}
	if hide && r.URL.Path == "/v1/sandboxes" && r.Method == "GET" {
		rec := httptest.NewRecorder()
		l.inner.ServeHTTP(rec, r)
		var list struct {
			Sandboxes []map[string]any `json:"sandboxes"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &list)
		out := []map[string]any{}
		l.mu.Lock()
		for _, rm := range list.Sandboxes {
			if id, _ := rm["id"].(string); !l.hidden[id] {
				out = append(out, rm)
			}
		}
		l.mu.Unlock()
		writeJSON(w, rec.Code, map[string]any{"sandboxes": out})
		return
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/v1/sandboxes/"); ok && hide && r.Method == "DELETE" && !strings.Contains(rest, "/") {
		l.mu.Lock()
		if l.hidden == nil {
			l.hidden = map[string]bool{}
		}
		l.hidden[rest] = true
		l.mu.Unlock()
		w.WriteHeader(204)
		return
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/v1/sandboxes/"); ok {
		id, tail, _ := strings.Cut(rest, "/")
		tail, _, _ = strings.Cut(tail, ";") // as the hotel's urlparse drops ";params"
		m := strings.ToUpper(r.Method)      // as the hotel matches methods
		if (tail == "" && m == "PATCH") || ((tail == "heartbeat" || tail == "lifetime" || tail == "claim") && (m == "POST" || m == "PATCH")) {
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			l.mu.Lock()
			l.got = append(l.got, lifeCall{m, r.URL.Path, body})
			l.mu.Unlock()
			writeJSON(w, 200, map[string]any{"id": id, "state": "running", "ttl_seconds": body["ttl_seconds"]})
			return
		}
		if tail == "" && m == "GET" {
			l.mu.Lock()
			doc := map[string]any{"id": id, "state": "running"}
			if l.docTTL != nil {
				doc["ttl_seconds"] = l.docTTL
			}
			l.mu.Unlock()
			writeJSON(w, 200, doc)
			return
		}
	}
	l.inner.ServeHTTP(w, r)
}

func (l *lifeHotel) gotCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.got)
}

func (l *lifeHotel) seenCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.seen)
}

func (l *lifeHotel) last() lifeCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.got[len(l.got)-1]
}

// meteredChain is newChainState with a state_dir, guest g1 metered in the
// config, and every hotel API behind a lifeHotel. edit may change the config
// first. Every hotel lists its rooms once, so no recount is pending.
func meteredChain(t *testing.T, edit func(*config)) (*testChain, map[string]*lifeHotel) {
	t.Helper()
	tc := newChainState(t, t.TempDir())
	raw, err := os.ReadFile(tc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	lives := map[string]*lifeHotel{}
	for i := range cfg.Hotels {
		id := cfg.Hotels[i].ID
		l := &lifeHotel{inner: tc.hotels[id], docTTL: 900.0, name: id}
		s := httptest.NewServer(l)
		t.Cleanup(s.Close)
		cfg.Hotels[i].API = s.URL
		lives[id] = l
	}
	cfg.Guests[0].Metered = true // g1; g2 is not metered
	if edit != nil {
		edit(&cfg)
	}
	out, _ := json.Marshal(cfg)
	if err := os.WriteFile(tc.cfgPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	return tc, lives
}

func allowanceBody(issue, cap int) map[string]any {
	return map[string]any{"issue": issue, "cap": cap, "lease_seconds": 600, "max_ttl_seconds": 3600, "max_memory_gib": 4}
}

func (tc *testChain) putAllowance(t *testing.T, guest string, body map[string]any) map[string]any {
	t.Helper()
	status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/"+guest+"/allowance", body)
	if status != 200 {
		t.Fatalf("PUT allowance %v: %d %v", body, status, doc)
	}
	return doc
}

func (tc *testChain) getAllowance(t *testing.T, guest string) map[string]any {
	t.Helper()
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/guests/"+guest+"/allowance", nil)
	if status != 200 {
		t.Fatalf("GET allowance: %d %v", status, doc)
	}
	return doc
}

// ageLease moves guest's ledger_seen_at back by d, as if the ledger had
// been quiet that long.
func (tc *testChain) ageLease(guest string, d time.Duration) {
	tc.b.mu.Lock()
	a := *tc.b.allow.byGuest[guest]
	a.LedgerSeenAt = a.LedgerSeenAt.Add(-d)
	tc.b.allow.byGuest[guest] = &a
	tc.b.mu.Unlock()
}

// syncAll runs one room list on the named hotels (all when none named).
func (tc *testChain) syncAll(ids ...string) {
	for _, h := range tc.b.hotelList() {
		if len(ids) == 0 || slicesContains(ids, h.cfg.ID) {
			tc.b.syncHotel(context.Background(), h)
		}
	}
}

func slicesContains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// hotelCalls counts every request the hotels got, and the creates and
// deletes among them.
func hotelCalls(tc *testChain, lives map[string]*lifeHotel) (all, creates, deletes int) {
	for id, f := range tc.hotels {
		f.mu.Lock()
		creates += len(f.creates)
		deletes += len(f.roomDeletes) + len(f.bulkDeletes)
		f.mu.Unlock()
		if l := lives[id]; l != nil {
			l.mu.Lock()
			all += len(l.seen)
			for _, c := range l.seen {
				if strings.HasPrefix(c, "DELETE ") {
					deletes++
				}
			}
			l.mu.Unlock()
		}
	}
	return all, creates, deletes
}

// anyCode is the error code of a native answer or of a client envelope.
func anyCode(doc map[string]any) string {
	if c := errCode(doc); c != "" {
		return c
	}
	d, _ := doc["detail"].(map[string]any)
	c, _ := d["error"].(string)
	return c
}

func (tc *testChain) clientCallAs(t *testing.T, key, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(mustMarshal(body))
	}
	req, _ := http.NewRequest(method, tc.srv.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("User-Agent", "ctcli/1.0")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, doc
}

// lastCreateOn is the last create body hotel id received.
func lastCreateOn(t *testing.T, tc *testChain, id string) map[string]any {
	t.Helper()
	f := tc.hotels[id]
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.creates) == 0 {
		t.Fatalf("no create reached hotel %s", id)
	}
	return f.creates[len(f.creates)-1]
}

func (tc *testChain) uuidOf(bid string) string {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	return tc.b.byBID(bid).uuid
}

// ---------------------------------------------------------------- admission

func TestMeteredCapThreeAdmitsExactlyThreeOfHundredConcurrent(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 3))
	// Every create passes the early check while nothing is reserved; hold
	// them all there, so the cap rests on admit's reservation alone.
	var arrived sync.WaitGroup
	arrived.Add(100)
	all := make(chan struct{})
	go func() { arrived.Wait(); close(all) }()
	saved := afterMeteredCheck
	afterMeteredCheck = func() {
		arrived.Done()
		select {
		case <-all:
		case <-time.After(10 * time.Second):
		}
	}
	defer func() { afterMeteredCheck = saved }()
	var wg sync.WaitGroup
	var mu sync.Mutex
	statuses := map[string]int{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes", bytes.NewReader(mustMarshal(map[string]any{"image": "alpine:3.20"})))
			req.Header.Set("Authorization", "Bearer key1")
			resp, err := http.DefaultClient.Do(req)
			key := "error"
			if err == nil {
				var doc map[string]any
				_ = json.NewDecoder(resp.Body).Decode(&doc)
				resp.Body.Close()
				key = http.StatusText(resp.StatusCode) + " " + errCode(doc)
			}
			mu.Lock()
			statuses[key]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if statuses["Accepted "] != 3 || statuses["Payment Required allowance_exhausted"] != 97 {
		t.Fatalf("answers %v, want 3 accepted and 97 allowance_exhausted", statuses)
	}
	if _, creates, deletes := hotelCalls(tc, lives); creates != 3 || deletes != 0 {
		t.Fatalf("hotels got %d creates and %d deletes, want 3 and 0", creates, deletes)
	}
}

func TestMeteredCapZeroRefusesWithNoHotelCreateOrDelete(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	running := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	tc.putAllowance(t, "g1", allowanceBody(2, 0))
	_, creates0, _ := hotelCalls(tc, lives)
	for _, body := range []map[string]any{
		{"image": "alpine:3.20"},
		{"image": "alpine:3.20", "count": 5},
		{"image": "alpine:3.20", "snapshot_id": "b.snap_x"}, // refused before the snapshot lookup
	} {
		status, _, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes", body)
		if status != 402 || errCode(doc) != "allowance_exhausted" {
			t.Fatalf("create %v at cap 0: %d %v", body, status, doc)
		}
	}
	if status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil); status != 402 || anyCode(doc) != "allowance_exhausted" {
		t.Fatalf("client create at cap 0: %d %v", status, doc)
	}
	tc.syncAll()
	tc.syncAll()
	all, creates, deletes := hotelCalls(tc, lives)
	if creates != creates0 || deletes != 0 {
		t.Fatalf("cap 0: hotels got %d more creates and %d deletes (%d calls)", creates-creates0, deletes, all)
	}
	// The running room is untouched and still the guest's.
	if status, doc := tc.call(t, "key1", "GET", "/v1/sandboxes/"+running, nil); status != 200 {
		t.Fatalf("running room after cap 0: %d %v", status, doc)
	}
}

func TestMeteredLeaseExpiryRefusesAndTouchesNothing(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	if v := tc.getAllowance(t, "g1"); v["lease_fresh"] != true || v["live_rooms"] != 1.0 || v["lease_seconds_left"].(float64) < 590 {
		t.Fatalf("view with a fresh lease: %v", v)
	}
	tc.ageLease("g1", 601*time.Second)
	_, creates0, _ := hotelCalls(tc, lives)
	status, hdr, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status != 402 || errCode(doc) != "allowance_lease_expired" || hdr.Get("Retry-After") != "30" {
		t.Fatalf("create after the lease: %d %v %v", status, hdr, doc)
	}
	msg := doc["error"].(map[string]any)["message"].(string)
	if !strings.Contains(msg, "sold out") || strings.Contains(msg, "unavailable") {
		t.Fatalf("lease wording %q", msg)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/heartbeat", map[string]any{"ttl_seconds": 600}); status != 402 || errCode(doc) != "allowance_lease_expired" {
		t.Fatalf("heartbeat after the lease: %d %v", status, doc)
	}
	tc.syncAll()
	tc.syncAll()
	if _, creates, deletes := hotelCalls(tc, lives); creates != creates0 || deletes != 0 || lives[hotelOf(bid)].gotCount() != 0 {
		t.Fatalf("after the lease: %d more creates, %d deletes, %d lifetime calls", creates-creates0, deletes, lives[hotelOf(bid)].gotCount())
	}
	if status, _ := tc.call(t, "key1", "GET", "/v1/sandboxes/"+bid, nil); status != 200 {
		t.Fatalf("running room after the lease: %d", status)
	}
	if v := tc.getAllowance(t, "g1"); v["lease_fresh"] != false || v["lease_seconds_left"] != 0.0 {
		t.Fatalf("view after the lease: %v", v)
	}
	// The ledger speaks again: creates work.
	tc.putAllowance(t, "g1", allowanceBody(2, 5))
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
}

func TestMeteredGuestFromConfigIsClosedUntilAnAllowance(t *testing.T) {
	tc, lives := meteredChain(t, func(c *config) { c.Guests[0].Metered = true })
	v := tc.getAllowance(t, "g1")
	if v["metered"] != true || v["cap"] != 0.0 || v["ledger_seen_at"] != nil || v["lease_fresh"] != false {
		t.Fatalf("config-metered view: %v", v)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_lease_expired" {
		t.Fatalf("create with no allowance: %d %v", status, doc)
	}
	if status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil); status != 402 || anyCode(doc) != "allowance_lease_expired" {
		t.Fatalf("client create with no allowance: %d %v", status, doc)
	}
	if _, creates, _ := hotelCalls(tc, lives); creates != 0 {
		t.Fatalf("hotels got %d creates", creates)
	}
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
}

func TestMeteredConfigNeedsStateDir(t *testing.T) {
	tc := newChain(t)
	raw, _ := os.ReadFile(tc.cfgPath)
	var cfg config
	_ = json.Unmarshal(raw, &cfg)
	cfg.Guests[0].Metered = true
	out, _ := json.Marshal(cfg)
	_ = os.WriteFile(tc.cfgPath, out, 0o600)
	if _, err := loadBroker(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "state_dir") {
		t.Fatalf("metered guest without state_dir: %v", err)
	}
	// Without state_dir no guest is metered, so no allowance is taken.
	tc2 := newChain(t)
	if status, doc := tc2.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(1, 1)); status != 409 || errCode(doc) != "guest_not_metered" {
		t.Fatalf("PUT without state_dir: %d %v", status, doc)
	}
}

// ---------------------------------------------------------------- restart

func TestMeteredCapZeroAndLeaseTimeSurviveRestart(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 0))
	before := tc.getAllowance(t, "g1")
	path := filepath.Join(tc.b.cfg.StateDir, allowancesFile)
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("allowance file: %v %v", fi, err)
	}
	tc.restart(t)
	after := tc.getAllowance(t, "g1")
	if after["cap"] != 0.0 || after["issue"] != 1.0 || after["ledger_seen_at"] != before["ledger_seen_at"] || after["metered"] != true {
		t.Fatalf("after restart %v, before %v", after, before)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("cap 0 after restart: %d %v", status, doc)
	}
	// The issue survives too.
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(1, 5)); status != 409 || errCode(doc) != "stale_allowance" {
		t.Fatalf("stale issue after restart: %d %v", status, doc)
	}
	// A lease keeps its ledger_seen_at across a restart, so it expires there.
	tc.putAllowance(t, "g1", allowanceBody(2, 5))
	raw, _ := os.ReadFile(path)
	var f allowanceFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	a := f.Guests["g1"]
	a.LedgerSeenAt = time.Now().Add(-601 * time.Second)
	f.Guests["g1"] = a
	raw, _ = json.Marshal(f)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_lease_expired" {
		t.Fatalf("lease past its time across a restart: %d %v", status, doc)
	}
}

func TestMeteredRestartWaitsForEveryHotelToList(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 3))
	for i := 0; i < 3; i++ {
		tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	}
	tc.start(t) // a restart; hotel b's first list is held back
	tc.syncAll("a", "c")
	_, creates0, _ := hotelCalls(tc, lives)
	for i := 0; i < 3; i++ {
		status, hdr, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
		if status != 503 || errCode(doc) != "allowance_recount" || hdr.Get("Retry-After") != "5" {
			t.Fatalf("create before hotel b listed: %d %v %v", status, hdr, doc)
		}
	}
	if v := tc.getAllowance(t, "g1"); v["recount_pending"] != true {
		t.Fatalf("view before hotel b listed: %v", v)
	}
	tc.syncAll("b")
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"})
	if status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create after hotel b listed its 3 rooms at cap 3: %d %v", status, doc)
	}
	if _, creates, _ := hotelCalls(tc, lives); creates != creates0 {
		t.Fatalf("restart at a full cap dispatched %d creates", creates-creates0)
	}
	// A guest that is not metered never waits for the recount.
	tc.start(t)
	tc.room(t, "key2", map[string]any{"image": "alpine:3.20"})
}

func TestMeteredDeletingRoomsCountUntilReleased(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 2))
	r1 := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+r1, nil); status != 204 {
		t.Fatalf("delete: %d", status)
	}
	tc.syncAll() // the room is gone from the list, not yet released
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create while a room is being removed: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	rm := tc.b.byBID(r1)
	rm.vanished = time.Now().Add(-3 * time.Second)
	tc.b.mu.Unlock()
	tc.syncAll() // now released
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
}

func TestMeteredStaleIssueAfterCapZeroChangesNothing(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(5, 3))
	tc.putAllowance(t, "g1", allowanceBody(6, 0))
	for _, issue := range []int{5, 6} {
		status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(issue, 3))
		if status != 409 || errCode(doc) != "stale_allowance" {
			t.Fatalf("issue %d after 6: %d %v", issue, status, doc)
		}
	}
	if v := tc.getAllowance(t, "g1"); v["cap"] != 0.0 || v["issue"] != 6.0 {
		t.Fatalf("after stale PUTs: %v", v)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create after a stale cap 3: %d %v", status, doc)
	}
}

func TestMeteredCorruptAllowanceFileKeepsGuestClosed(t *testing.T) {
	tc, _ := meteredChain(t, func(c *config) { c.Guests[0].Metered = true })
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	path := filepath.Join(tc.b.cfg.StateDir, allowancesFile)
	if err := os.WriteFile(path, []byte(`{"version": 1, "guests": {"g1": {"cap": 5,`), 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_lease_expired" {
		t.Fatalf("create after a corrupt file: %d %v", status, doc)
	}
	v := tc.getAllowance(t, "g1")
	if v["cap"] != 0.0 || v["ledger_seen_at"] != nil || v["issue"].(float64) < float64(time.Now().Add(-time.Minute).UnixMilli()) {
		t.Fatalf("view after a corrupt file: %v", v)
	}
	// The stored issues are lost: only an issue above the broker clock at
	// start (unix ms) opens the guest, so a delayed old push stays out.
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(2, 5)); status != 409 || errCode(doc) != "stale_allowance" {
		t.Fatalf("old issue after a corrupt file: %d %v", status, doc)
	}
	// The corrupt file is kept aside and replaced by the closed state, so a
	// second start keeps the watermark (TestMeteredRecoveryWatermarkSurvivesTwoRestarts).
	aside, _ := filepath.Glob(path + ".corrupt-*")
	var fresh allowanceFile
	raw, err := os.ReadFile(path)
	if len(aside) != 1 || err != nil || json.Unmarshal(raw, &fresh) != nil || fresh.Guests["g1"].Issue != int64(v["issue"].(float64)) || fresh.Guests["g1"].LeaseSeconds != 0 {
		t.Fatalf("corrupt file not kept aside and replaced: %v %v %s", aside, err, raw)
	}
	// An entry that parses but cannot open admission keeps that guest closed.
	bad := `{"version": 1, "guests": {"g1": {"issue": 3, "cap": 5, "lease_seconds": 600, "max_ttl_seconds": 0, "max_memory_gib": 4, "ledger_seen_at": "` + time.Now().UTC().Format(time.RFC3339Nano) + `"}}}`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_lease_expired" {
		t.Fatalf("create after an unusable entry: %d %v", status, doc)
	}
	// The issue of an unusable entry is kept: issue 3 or lower stays out,
	// the ledger's next issue opens the guest again.
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(3, 5)); status != 409 || errCode(doc) != "stale_allowance" {
		t.Fatalf("issue 3 after an unusable entry with issue 3: %d %v", status, doc)
	}
	tc.putAllowance(t, "g1", allowanceBody(4, 5))
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	// An entry whose issue is not usable: the clock watermark applies.
	bad = `{"version": 1, "guests": {"g1": {"issue": 0, "cap": 5, "lease_seconds": 600, "max_ttl_seconds": 3600, "max_memory_gib": 4, "ledger_seen_at": "` + time.Now().UTC().Format(time.RFC3339Nano) + `"}}}`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(5, 5)); status != 409 || errCode(doc) != "stale_allowance" {
		t.Fatalf("small issue after an unusable issue: %d %v", status, doc)
	}
	ms := int(time.Now().UnixMilli()) + 1000
	tc.putAllowance(t, "g1", allowanceBody(ms, 5))
}

// ---------------------------------------------------------------- size and lifetime

func TestMeteredCreateTTLIsClampedOnTheHotelBody(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 10))
	for _, c := range []struct {
		ask  any
		want float64
	}{{172800, 3600}, {nil, 3600}, {600, 600}, {3600, 3600}} {
		body := map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}
		if c.ask != nil {
			body["ttl_seconds"] = c.ask
		}
		tc.room(t, "key1", body)
		got := lastCreateOn(t, tc, "b")
		if got["ttl_seconds"] != c.want {
			t.Fatalf("ttl %v: the hotel got %v, want %v", c.ask, got["ttl_seconds"], c.want)
		}
		if res, _ := got["resources"].(map[string]any); res["memory_gib"] != 4.0 {
			t.Fatalf("memory not explicit on the hotel body: %v", got["resources"])
		}
	}
	// The client route: lifetime_seconds 172800 reaches the hotel as 3600.
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image": "alpine:3.20", "lifetime_seconds": 172800, "hotels": []string{"b"}}), nil)
	if status != 201 {
		t.Fatalf("client create: %d %v", status, doc)
	}
	if got := lastCreateOn(t, tc, "b"); got["ttl_seconds"] != 3600.0 {
		t.Fatalf("client create: the hotel got ttl %v", got["ttl_seconds"])
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "ttl_seconds": "999999"}); status != 400 || errCode(doc) != "invalid_ttl" {
		t.Fatalf("string ttl: %d %v", status, doc)
	}
}

func TestMeteredOversizeMemoryRefusedWithNoHotelCall(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 10))
	all0, _, _ := hotelCalls(tc, lives)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "resources": map[string]any{"memory_gib": 64}})
	if status != 400 || errCode(doc) != "memory_limit" {
		t.Fatalf("64 GiB on a 4 GiB key: %d %v", status, doc)
	}
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image": "alpine:3.20", "shape": map[string]any{"memory_mib": 65536}}), nil)
	if status != 400 || anyCode(doc) != "memory_limit" {
		t.Fatalf("client 64 GiB on a 4 GiB key: %d %v", status, doc)
	}
	if all, _, _ := hotelCalls(tc, lives); all != all0 {
		t.Fatalf("oversize creates reached the hotels: %d calls", all-all0)
	}
	// At the limit it goes through.
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "resources": map[string]any{"memory_gib": 4}})
}

// lifetimeRoutes are the routes that reset a room's deadline, as a native
// and a client caller send them.
func lifetimeRoutes(bid, uuid string) []struct {
	name, method, path string
	client             bool
} {
	return []struct {
		name, method, path string
		client             bool
	}{
		{"PATCH room", "PATCH", "/v1/sandboxes/" + bid, false},
		{"POST heartbeat", "POST", "/v1/sandboxes/" + bid + "/heartbeat", false},
		{"POST lifetime", "POST", "/v1/sandboxes/" + bid + "/lifetime", false},
		{"PATCH lifetime", "PATCH", "/v1/sandboxes/" + bid + "/lifetime", false},
		{"lower-case patch lifetime", "patch", "/v1/sandboxes/" + bid + "/lifetime", false},
		{"heartbeat with params", "POST", "/v1/sandboxes/" + bid + "/heartbeat;x", false},
		{"client POST lifetime", "POST", "/v1/sandboxes/" + uuid + "/lifetime", true},
		{"client PATCH lifetime", "PATCH", "/v1/sandboxes/" + uuid + "/lifetime", true},
		{"client heartbeat", "POST", "/v1/sandboxes/" + uuid + "/heartbeat", true},
		{"client PATCH room", "PATCH", "/v1/sandboxes/" + uuid, true},
	}
}

func TestMeteredLifetimeRoutesAreClampedAndGated(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	uuid := tc.uuidOf(bid)
	l := lives["b"]
	call := func(method, path string, client bool, body any) (int, map[string]any) {
		if client {
			return tc.clientCallAs(t, "key1", method, path, body)
		}
		return tc.call(t, "key1", method, path, body)
	}
	// Allowed: 172800 s reaches the hotel as at most 3600 s.
	for _, rt := range lifetimeRoutes(bid, uuid) {
		n := l.gotCount()
		status, doc := call(rt.method, rt.path, rt.client, map[string]any{"ttl_seconds": 172800})
		if status >= 300 || l.gotCount() != n+1 {
			t.Fatalf("%s: %d %v, hotel calls %d", rt.name, status, doc, l.gotCount()-n)
		}
		if got := l.last().body["ttl_seconds"]; got != 3600.0 {
			t.Fatalf("%s: the hotel got ttl_seconds %v, want 3600", rt.name, got)
		}
	}
	// No ttl_seconds: the room's own ttl, sent explicitly, never above the maximum.
	for _, c := range []struct {
		own  any
		want float64
	}{{900.0, 900}, {7200.0, 3600}} {
		l.mu.Lock()
		l.docTTL = c.own
		l.mu.Unlock()
		if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/heartbeat", nil); status != 200 || l.last().body["ttl_seconds"] != c.want {
			t.Fatalf("empty heartbeat, room ttl %v: %d %v, hotel got %v", c.own, status, doc, l.last().body)
		}
	}
	l.mu.Lock()
	l.docTTL = nil
	l.mu.Unlock()
	n := l.gotCount()
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/heartbeat", nil); status != 502 || l.gotCount() != n {
		t.Fatalf("empty heartbeat with no room ttl: %d %v", status, doc)
	}
	// A room claim is refused for a metered key.
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/claim", map[string]any{"lifetime_seconds": 172800}); status != 403 || errCode(doc) != "claim_refused_metered" || l.gotCount() != n {
		t.Fatalf("claim: %d %v", status, doc)
	}
	// Cap below the live rooms, then a stale lease: every route is refused
	// and the hotel receives nothing, so the room keeps its deadline.
	for _, c := range []struct {
		setup func()
		code  string
	}{
		{func() { tc.putAllowance(t, "g1", allowanceBody(2, 0)) }, "allowance_exhausted"},
		{func() { tc.putAllowance(t, "g1", allowanceBody(3, 5)); tc.ageLease("g1", time.Hour) }, "allowance_lease_expired"},
	} {
		c.setup()
		for _, rt := range lifetimeRoutes(bid, uuid) {
			n := l.gotCount()
			status, doc := call(rt.method, rt.path, rt.client, map[string]any{"ttl_seconds": 600})
			if status != 402 || anyCode(doc) != c.code || l.gotCount() != n {
				t.Fatalf("%s (%s): %d %v, hotel calls %d", rt.name, c.code, status, doc, l.gotCount()-n)
			}
		}
	}
	// At cap 1 with one live room, an extension fits.
	tc.putAllowance(t, "g1", allowanceBody(4, 1))
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/heartbeat", map[string]any{"ttl_seconds": 60}); status != 200 || l.last().body["ttl_seconds"] != 60.0 {
		t.Fatalf("extension at a full cap: %d %v", status, doc)
	}
}

// ---------------------------------------------------------------- not metered

func TestNonMeteredGuestIsUnaffected(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 0)) // another guest is metered and closed
	if v := tc.getAllowance(t, "g2"); v["metered"] != false {
		t.Fatalf("g2 view: %v", v)
	}
	tc.room(t, "key2", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "ttl_seconds": 172800, "resources": map[string]any{"memory_gib": 64}})
	got := lastCreateOn(t, tc, "b")
	if got["ttl_seconds"] != 172800.0 || got["resources"].(map[string]any)["memory_gib"] != 64.0 {
		t.Fatalf("g2 create body changed: %v", got)
	}
	bid := tc.room(t, "key2", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	got = lastCreateOn(t, tc, "b")
	if _, ok := got["ttl_seconds"]; ok {
		t.Fatalf("g2 create got a ttl_seconds: %v", got)
	}
	if _, ok := got["resources"]; ok {
		t.Fatalf("g2 create got resources: %v", got)
	}
	l := lives["b"]
	if status, _ := tc.call(t, "key2", "POST", "/v1/sandboxes/"+bid+"/heartbeat", map[string]any{"ttl_seconds": 172800}); status != 200 || l.last().body["ttl_seconds"] != 172800.0 {
		t.Fatalf("g2 heartbeat changed: %d %v", status, l.last().body)
	}
	seen := l.seenCount()
	if status, _ := tc.call(t, "key2", "POST", "/v1/sandboxes/"+bid+"/heartbeat", nil); status != 200 || l.last().body != nil || l.seenCount() != seen+1 {
		t.Fatalf("g2 empty heartbeat changed: %d %v, %d hotel calls", status, l.last().body, l.seenCount()-seen)
	}
	// Restarted with no room list yet: a guest that is not metered creates at once.
	tc.start(t)
	tc.room(t, "key2", map[string]any{"image": "alpine:3.20"})
}

// ---------------------------------------------------------------- operator route

func TestAllowanceRouteChecksItsInput(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	if status, _ := tc.call(t, "key1", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(1, 1)); status != 401 {
		t.Fatalf("guest key: %d", status)
	}
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/nobody/allowance", allowanceBody(1, 1)); status != 404 || errCode(doc) != "guest_not_found" {
		t.Fatalf("unknown guest: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/guests/nobody/allowance", nil); status != 404 || errCode(doc) != "guest_not_found" {
		t.Fatalf("unknown guest GET: %d %v", status, doc)
	}
	with := func(k string, v any) map[string]any {
		b := allowanceBody(1, 1)
		if v == nil {
			delete(b, k)
		} else {
			b[k] = v
		}
		return b
	}
	for _, body := range []map[string]any{
		with("issue", nil), with("issue", 0), with("cap", -1), with("lease_seconds", 0), with("max_ttl_seconds", 0),
		with("max_ttl_seconds", 172801), with("max_memory_gib", 0), with("cap", 1.5), with("extra", true), with("cap", "3"),
	} {
		if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", body); status != 400 {
			t.Fatalf("bad body %v: %d %v", body, status, doc)
		}
	}
	if v := tc.getAllowance(t, "g1"); v["metered"] != true || v["cap"] != 0.0 || v["ledger_seen_at"] != nil {
		t.Fatalf("bad bodies changed the guest: %v", v)
	}
	// A guest not metered in the config takes no allowance, and nothing changes.
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g2/allowance", allowanceBody(1, 5)); status != 409 || errCode(doc) != "guest_not_metered" {
		t.Fatalf("PUT for a guest not metered: %d %v", status, doc)
	}
	if v := tc.getAllowance(t, "g2"); v["metered"] != false {
		t.Fatalf("g2 after a refused PUT: %v", v)
	}
	if _, err := os.Stat(filepath.Join(tc.b.cfg.StateDir, allowancesFile)); !os.IsNotExist(err) {
		t.Fatalf("a refused PUT wrote the allowance file: %v", err)
	}
	doc := tc.putAllowance(t, "g1", allowanceBody(1, 2))
	if doc["metered"] != true || doc["cap"] != 2.0 || doc["issue"] != 1.0 || doc["lease_seconds"] != 600.0 || doc["max_ttl_seconds"] != 3600.0 || doc["max_memory_gib"] != 4.0 || doc["ledger_seen_at"] == nil {
		t.Fatalf("PUT answer: %v", doc)
	}
}

// ---------------------------------------------------------------- review round 1

// doJSON is tc.call for goroutines: it returns the error instead of failing.
func doJSON(base, key, method, path string, body any) (int, map[string]any, error) {
	req, _ := http.NewRequest(method, base+path, bytes.NewReader(mustMarshal(body)))
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, doc, nil
}

// signalBody tells reading once the handler first reads its request body.
type signalBody struct {
	io.ReadCloser
	once    sync.Once
	reading chan<- struct{}
}

func (s *signalBody) Read(p []byte) (int, error) {
	s.once.Do(func() { s.reading <- struct{}{} })
	return s.ReadCloser.Read(p)
}

// bodyReadServer serves the broker and signals on reading each time a
// handler enters its body read.
func bodyReadServer(t *testing.T, tc *testChain) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	reading := make(chan struct{}, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = &signalBody{ReadCloser: r.Body, reading: reading}
		tc.b.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, reading
}

// heldRequest sends a request's headers now and its body only when send is
// called, over a raw connection to srv, so the broker waits on the body.
func heldRequest(t *testing.T, srv *httptest.Server, method, path, userAgent string, body any) (send func() (int, map[string]any)) {
	t.Helper()
	raw := mustMarshal(body)
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	head := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: broker\r\nAuthorization: Bearer key1\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n", method, path, len(raw))
	if userAgent != "" {
		head += "User-Agent: " + userAgent + "\r\n"
	}
	if _, err := io.WriteString(conn, head+"\r\n"); err != nil {
		t.Fatal(err)
	}
	return func() (int, map[string]any) {
		t.Helper()
		if _, err := conn.Write(raw); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		return resp.StatusCode, doc
	}
}

func TestMeteredHeldLifetimeBodyMeetsTheAllowanceAtDispatch(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	uuid := tc.uuidOf(bid)
	l := lives["b"]
	srv, reading := bodyReadServer(t, tc)
	issue := 1
	for _, c := range []struct {
		name   string
		change func()
		code   string
	}{
		{"lease expires", func() { tc.ageLease("g1", time.Hour) }, "allowance_lease_expired"},
		{"cap drops to 0", func() { issue++; tc.putAllowance(t, "g1", allowanceBody(issue, 0)) }, "allowance_exhausted"},
	} {
		issue++
		tc.putAllowance(t, "g1", allowanceBody(issue, 5)) // allowed when the headers arrive
		n := l.gotCount()
		native := heldRequest(t, srv, "POST", "/v1/sandboxes/"+bid+"/heartbeat", "", map[string]any{"ttl_seconds": 600})
		waitReading(t, reading)
		client := heldRequest(t, srv, "POST", "/v1/sandboxes/"+uuid+"/lifetime", "ctcli/1.0", map[string]any{"lifetime_seconds": 600})
		waitReading(t, reading) // both handlers are in their body reads
		c.change()
		if status, doc := native(); status != 402 || anyCode(doc) != c.code {
			t.Fatalf("%s: held native heartbeat: %d %v", c.name, status, doc)
		}
		if status, doc := client(); status != 402 || anyCode(doc) != c.code {
			t.Fatalf("%s: held client lifetime: %d %v", c.name, status, doc)
		}
		if l.gotCount() != n {
			t.Fatalf("%s: the hotel got %d lifetime calls", c.name, l.gotCount()-n)
		}
	}
}

func TestMeteredLostCreateAnswerCountsUntilReaped(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	setFail := func(fail int) {
		for _, id := range []string{"b", "c"} {
			f := tc.hotels[id]
			f.mu.Lock()
			f.createFail, f.createFailAfterStart, f.labelListFail = fail, fail != 0, fail
			f.mu.Unlock()
		}
	}
	setFail(503) // a room starts, its answer is an error, and the orphan reap cannot list it
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}})
	if _, creates, _ := hotelCalls(tc, lives); status != 503 || creates != 1 {
		t.Fatalf("lost answer at cap 1: %d %v, %d creates dispatched (no retry may join the uncertain room)", status, doc, creates)
	}
	// The uncertain room counts until its reap is confirmed.
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create while the orphan is unreaped: %d %v", status, doc)
	}
	if v := tc.getAllowance(t, "g1"); v["live_rooms"] != 1.0 {
		t.Fatalf("view while the orphan is unreaped: %v", v)
	}
	if _, creates, _ := hotelCalls(tc, lives); creates != 1 {
		t.Fatalf("%d creates dispatched at cap 1", creates)
	}
	setFail(0) // the background reap now confirms the orphan gone
	deadline := time.Now().Add(15 * time.Second)
	for {
		tc.b.mu.Lock()
		left := 0
		for _, h := range tc.b.hotelList() {
			left += len(h.unreaped)
		}
		tc.b.mu.Unlock()
		if left == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the orphan was never reaped")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if v := tc.getAllowance(t, "g1"); v["live_rooms"] != 0.0 {
		t.Fatalf("view after the reap: %v", v)
	}
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}) // the hotel that failed rests
}

func TestMeteredLimitsComeFromTheAllowanceThatReserves(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	wide := map[string]any{"issue": 1, "cap": 2, "lease_seconds": 600, "max_ttl_seconds": 7200, "max_memory_gib": 64}
	tc.putAllowance(t, "g1", wide)
	saved := afterMeteredCheck
	defer func() { afterMeteredCheck = saved }()
	for i, c := range []struct {
		body  map[string]any
		check func(status int, doc map[string]any)
	}{
		{map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "resources": map[string]any{"memory_gib": 64}}, func(status int, doc map[string]any) {
			if _, creates, _ := hotelCalls(tc, lives); status != 400 || errCode(doc) != "memory_limit" || creates != 0 {
				t.Fatalf("64 GiB checked against the older allowance: %d %v, %d creates", status, doc, creates)
			}
		}},
		{map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "ttl_seconds": 7200}, func(status int, doc map[string]any) {
			if status != 202 || lastCreateOn(t, tc, "b")["ttl_seconds"] != 3600.0 {
				t.Fatalf("ttl checked against the older allowance: %d %v, hotel got %v", status, doc, lastCreateOn(t, tc, "b")["ttl_seconds"])
			}
		}},
	} {
		held, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		afterMeteredCheck = func() { once.Do(func() { close(held); <-release }) }
		type answer struct {
			status int
			doc    map[string]any
			err    error
		}
		done := make(chan answer, 1)
		go func() {
			status, doc, err := doJSON(tc.srv.URL, "key1", "POST", "/v1/sandboxes", c.body)
			done <- answer{status, doc, err}
		}()
		<-held // passed the early check against the wide allowance
		tc.putAllowance(t, "g1", map[string]any{"issue": 2*i + 2, "cap": 2, "lease_seconds": 600, "max_ttl_seconds": 3600, "max_memory_gib": 4})
		close(release)
		a := <-done
		if a.err != nil {
			t.Fatal(a.err)
		}
		c.check(a.status, a.doc)
		wide["issue"] = 2*i + 3
		tc.putAllowance(t, "g1", wide)
	}
}

func TestMeteredStaleIssueAfterPartialCorruption(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(6, 0))
	path := filepath.Join(tc.b.cfg.StateDir, allowancesFile)
	raw, _ := os.ReadFile(path)
	var f allowanceFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	a := f.Guests["g1"]
	a.MaxTTLSeconds = 0 // one field goes bad; the issue stays readable
	f.Guests["g1"] = a
	raw, _ = json.Marshal(f)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(5, 3)); status != 409 || errCode(doc) != "stale_allowance" {
		t.Fatalf("delayed issue 5 after issue 6 and a bad field: %d %v", status, doc)
	}
	if v := tc.getAllowance(t, "g1"); v["issue"] != 6.0 || v["cap"] != 0.0 {
		t.Fatalf("view: %v", v)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 {
		t.Fatalf("create: %d %v", status, doc)
	}
}

func TestMeteredFailedSaveClosesTheGuest(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	saved := syncAllowanceDir
	syncAllowanceDir = func(string) error { return errors.New("injected directory sync failure") }
	status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(2, 5))
	syncAllowanceDir = saved
	if status != 500 || errCode(doc) != "state_write_failed" {
		t.Fatalf("PUT with a failing directory sync: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_lease_expired" {
		t.Fatalf("create after a failed save: %d %v", status, doc)
	}
	if v := tc.getAllowance(t, "g1"); v["cap"] != 0.0 || v["lease_fresh"] != false || v["issue"] != 2.0 {
		t.Fatalf("view after a failed save: %v", v)
	}
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(2, 5)); status != 409 || errCode(doc) != "stale_allowance" {
		t.Fatalf("same issue after a failed save: %d %v", status, doc)
	}
	tc.putAllowance(t, "g1", allowanceBody(3, 5)) // durably saved: open again
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
}

func TestMeteredRuntimeJoinWaitsForItsFirstList(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}, listFail: true} // holds back its first list
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	tc.hotels["d"] = f
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "d", "api": hs.URL, "key": joinKey}); status != 201 {
		t.Fatalf("join d: %d %v", status, doc)
	}
	t.Cleanup(func() { stopSyncLoop(t, tc, "d") }) // no background sync logs into a later test
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}); status != 503 || errCode(doc) != "allowance_recount" {
		t.Fatalf("metered create before the joined hotel listed: %d %v", status, doc)
	}
	tc.room(t, "key2", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}) // not metered: no wait
	f.mu.Lock()
	f.listFail = false
	f.mu.Unlock()
	tc.syncAll("d")
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
}

func TestMeteredUnreadyImageAtCapZeroRefusedBeforeBuilds(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	for _, f := range tc.hotels {
		f.mu.Lock()
		f.failBuild = true
		f.mu.Unlock()
	}
	body, ctype := buildForm(t, "FROM alpine:3.20\n", []byte("ctx"))
	_, doc := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	imgID, _ := doc["image_id"].(string)
	if imgID == "" {
		t.Fatalf("build: %v", doc)
	}
	waitImage(t, tc, imgID)
	tc.putAllowance(t, "g1", allowanceBody(1, 0))
	builds := func() int {
		n := 0
		for _, f := range tc.hotels {
			f.mu.Lock()
			n += len(f.builds)
			f.mu.Unlock()
		}
		return n
	}
	before := builds()
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": imgID}), nil)
	time.Sleep(100 * time.Millisecond) // a build the create started would have reached a hotel
	if status != 402 || anyCode(doc) != "allowance_exhausted" || builds() != before {
		t.Fatalf("cap 0 create of an unready image: %d %v, %d new builds", status, doc, builds()-before)
	}
}

// A room whose container removal keeps failing is hidden from the hotel's
// list. After a broker restart it is not counted: the documented bound is
// one extra room per such room, which is not listed, so not metered.
func TestMeteredHiddenDeletingRoomBoundAfterRestart(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	lives["b"].mu.Lock()
	lives["b"].hideDeletes = true
	lives["b"].mu.Unlock()
	r1 := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+r1, nil); status != 204 {
		t.Fatalf("delete: %d", status)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create while the room is being removed: %d %v", status, doc)
	}
	tc.restart(t)
	tc.b.mu.Lock()
	known := tc.b.byBID(r1) != nil
	tc.b.mu.Unlock()
	if known {
		t.Fatal("the hidden room was listed after the restart")
	}
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}}) // the one extra room of the bound
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("second create after the restart: %d %v", status, doc)
	}
}

// ---------------------------------------------------------------- review round 2

func waitReading(t *testing.T, reading <-chan struct{}) {
	t.Helper()
	select {
	case <-reading:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler never read its body")
	}
}

// lostCreateNoRoom makes hotels b and c answer a create 504 without starting
// a room, like a proxy that timed out while the hotel may go on, and returns
// the hotel that got the create and its batch label.
func lostCreateNoRoom(t *testing.T, tc *testChain, lives map[string]*lifeHotel) (string, string) {
	t.Helper()
	for _, id := range []string{"b", "c"} {
		f := tc.hotels[id]
		f.mu.Lock()
		f.createFail = 504
		f.mu.Unlock()
	}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}})
	_, creates, deletes := hotelCalls(tc, lives)
	if status != 504 || creates != 1 || deletes != 0 {
		t.Fatalf("lost create at cap 1: %d %v, %d creates, %d deletes", status, doc, creates, deletes)
	}
	for _, id := range []string{"b", "c"} {
		f := tc.hotels[id]
		f.mu.Lock()
		f.createFail = 0
		f.mu.Unlock()
	}
	for _, id := range []string{"b", "c"} {
		f := tc.hotels[id]
		f.mu.Lock()
		if len(f.creates) == 1 {
			labels, _ := f.creates[0]["labels"].(map[string]any)
			batch, _ := labels[batchLabel].(string)
			f.mu.Unlock()
			return id, batch
		}
		f.mu.Unlock()
	}
	t.Fatal("no hotel got the create")
	return "", ""
}

func TestMeteredLostCreateWithNoRoomIsHeld(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	hotelID, batch := lostCreateNoRoom(t, tc, lives)
	// The reap found no room, but the hotel may still start it: held.
	for i := 0; i < 2; i++ {
		if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 402 || errCode(doc) != "allowance_exhausted" {
			t.Fatalf("create during the hold: %d %v", status, doc)
		}
		tc.syncAll() // a sync that lists no room keeps the hold
	}
	if _, creates, deletes := hotelCalls(tc, lives); creates != 1 || deletes != 0 {
		t.Fatalf("during the hold: %d creates, %d deletes", creates, deletes)
	}
	tc.b.mu.Lock()
	ub := tc.b.hotelByID(hotelID).unreaped[batch]
	if ub == nil || time.Until(ub.holdUntil) < hotelCreateTimeout-time.Minute {
		tc.b.mu.Unlock()
		t.Fatalf("hold record %+v, want one lasting the create timeout (%s)", ub, hotelCreateTimeout)
	}
	ub.holdUntil = time.Now().Add(-time.Second) // the hold passes
	tc.b.mu.Unlock()
	tc.syncAll()
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}})
	if _, _, deletes := hotelCalls(tc, lives); deletes != 0 {
		t.Fatalf("%d deletes", deletes)
	}
}

func TestMeteredLateRoomInTheHoldIsReapedAsAnOrphan(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	hotelID, batch := lostCreateNoRoom(t, tc, lives)
	// The hotel finishes the create after all: its room appears in the list.
	f := tc.hotels[hotelID]
	f.mu.Lock()
	f.rooms = append(f.rooms, map[string]any{"id": "sbx_late", "state": "running", "labels": map[string]any{guestLabel: "g1", batchLabel: batch}})
	f.mu.Unlock()
	release := make(chan struct{})
	lives[hotelID].mu.Lock()
	lives[hotelID].holdDeletes = release // the reap's DELETE waits until the refusal is checked
	lives[hotelID].mu.Unlock()
	tc.syncAll(hotelID)
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create while the late room is reaped: %d %v", status, doc)
	}
	close(release)
	deadline := time.Now().Add(10 * time.Second)
	for {
		tc.b.mu.Lock()
		left := len(tc.b.hotelByID(hotelID).unreaped)
		tc.b.mu.Unlock()
		if left == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the late room was never reaped")
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.mu.Lock()
	deleted := append([]string(nil), f.roomDeletes...)
	f.mu.Unlock()
	if len(deleted) != 1 || deleted[0] != "sbx_late" {
		t.Fatalf("late room not reaped as an orphan: %v", deleted)
	}
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}})
}

func TestMeteredTunablesRetryIsGated(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	for _, id := range []string{"b", "c"} { // no hotel applies tunables, and cleanup DELETEs fail
		f := tc.hotels[id]
		f.mu.Lock()
		f.roomDeleteFail = 503
		f.mu.Unlock()
	}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}, "tunables": coldTunables()})
	if _, creates, _ := hotelCalls(tc, lives); status != 409 || errCode(doc) != "tunables_unavailable" || creates != 1 {
		t.Fatalf("tunables create at cap 1 with failing cleanup: %d %v, %d creates dispatched", status, doc, creates)
	}
	if v := tc.getAllowance(t, "g1"); v["live_rooms"] != 1.0 {
		t.Fatalf("the room being removed must count: %v", v)
	}
}

func TestMeteredRetryIsCheckedAgainstTheAllowanceOfItsMoment(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", map[string]any{"issue": 1, "cap": 1, "lease_seconds": 600, "max_ttl_seconds": 7200, "max_memory_gib": 64})
	hold, entered := make(chan struct{}), make(chan string, 4)
	for _, id := range []string{"b", "c"} {
		f := tc.hotels[id]
		f.mu.Lock()
		f.createFail = 503 // the first attempt fails, so the create would move on
		f.mu.Unlock()
		lives[id].mu.Lock()
		lives[id].holdCreates, lives[id].enteredCreate = hold, entered
		lives[id].mu.Unlock()
	}
	type answer struct {
		status int
		doc    map[string]any
		err    error
	}
	done := make(chan answer, 1)
	go func() {
		status, doc, err := doJSON(tc.srv.URL, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}, "ttl_seconds": 7200, "resources": map[string]any{"memory_gib": 64}})
		done <- answer{status, doc, err}
	}()
	<-entered // the first attempt is at a hotel
	// The cap rises (room for the failed attempt and a retry) while the limits shrink.
	tc.putAllowance(t, "g1", map[string]any{"issue": 2, "cap": 2, "lease_seconds": 600, "max_ttl_seconds": 3600, "max_memory_gib": 4})
	close(hold)
	a := <-done
	if a.err != nil {
		t.Fatal(a.err)
	}
	if _, creates, _ := hotelCalls(tc, lives); a.status != 503 || creates != 1 {
		t.Fatalf("retry of a 64 GiB, 7200 s create under a 4 GiB, 3600 s allowance: %d %v, %d creates sent", a.status, a.doc, creates)
	}
}

func TestMeteredRecoveryWatermarkSurvivesTwoRestarts(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(6, 0))
	path := filepath.Join(tc.b.cfg.StateDir, allowancesFile)
	if err := os.WriteFile(path, []byte(`{"version": 1, "guests": {"g1": {"issue": 6,`), 0o600); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	w := tc.getAllowance(t, "g1")["issue"]
	tc.restart(t) // a second start before any PUT
	if v := tc.getAllowance(t, "g1"); v["issue"] != w || v["cap"] != 0.0 {
		t.Fatalf("after two restarts: %v, want issue %v", v, w)
	}
	for _, issue := range []int{5, 7} {
		if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(issue, 3)); status != 409 || errCode(doc) != "stale_allowance" {
			t.Fatalf("delayed issue %d after two restarts: %d %v", issue, status, doc)
		}
	}
	tc.putAllowance(t, "g1", allowanceBody(int(w.(float64))+1, 3))
	// The closed state cannot be written: the broker does not start.
	if err := os.WriteFile(path, []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".tmp", 0o700); err != nil { // the temporary file cannot be created
		t.Fatal(err)
	}
	if _, err := loadBroker(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "closed state could not be written") {
		t.Fatalf("start with a corrupt file and no way to write the closed state: %v", err)
	}
}

func TestMeteredFailedSaveThenRestartIsBoundedByOneLease(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	path := filepath.Join(tc.b.cfg.StateDir, allowancesFile)
	seenAt := func() time.Time {
		raw, _ := os.ReadFile(path)
		var f allowanceFile
		_ = json.Unmarshal(raw, &f)
		return f.Guests["g1"].LedgerSeenAt
	}
	// The rename is done and the directory sync fails: the file holds the
	// allowance the ledger just sent, with its own ledger_seen_at.
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	saved := syncAllowanceDir
	syncAllowanceDir = func(string) error { return errors.New("injected directory sync failure") }
	before := time.Now()
	status, _ := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(2, 5))
	syncAllowanceDir = saved
	if status != 500 {
		t.Fatalf("PUT with a failing directory sync: %d", status)
	}
	tc.restart(t)
	if v := tc.getAllowance(t, "g1"); v["issue"] != 2.0 || seenAt().Before(before) {
		t.Fatalf("after the restart: %v, ledger_seen_at %v, want issue 2 stamped at the failed PUT", v, seenAt())
	}
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"}) // what the ledger authorised
	tc.ageLease("g1", 601*time.Second)
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_lease_expired" {
		t.Fatalf("after its own lease: %d %v", status, doc)
	}
	// A failure before the rename: the file keeps the previous allowance
	// with its original ledger_seen_at, so it expires on that schedule.
	tc.putAllowance(t, "g1", allowanceBody(3, 5))
	original := seenAt()
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if status, _ := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(4, 0)); status != 500 {
		t.Fatalf("PUT that cannot write its file: %d", status)
	}
	if err := os.Remove(path + ".tmp"); err != nil {
		t.Fatal(err)
	}
	tc.restart(t)
	if v := tc.getAllowance(t, "g1"); v["issue"] != 3.0 || !seenAt().Equal(original) {
		t.Fatalf("after the restart: %v, ledger_seen_at %v, want issue 3 at %v", v, seenAt(), original)
	}
	tc.ageLease("g1", 601*time.Second)
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 402 || errCode(doc) != "allowance_lease_expired" {
		t.Fatalf("previous allowance after its original lease: %d %v", status, doc)
	}
}

func TestMeteredJoinedHotelKeepsNonMeteredAdmission(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	join := func(id string, extra map[string]any) {
		f := &fakeHotel{t: t, snaps: map[string]map[string]any{}, listFail: true} // health answers, room lists fail
		hs := httptest.NewServer(f)
		t.Cleanup(hs.Close)
		tc.hotels[id] = f
		body := map[string]any{"id": id, "api": hs.URL, "key": joinKey}
		for k, v := range extra {
			body[k] = v
		}
		if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", body); status != 201 {
			t.Fatalf("join %s: %d %v", id, status, doc)
		}
		t.Cleanup(func() { stopSyncLoop(t, tc, id) }) // no background sync logs into a later test
		setHotel(tc, id, func(h *hotel) { h.ok, h.slots = true, 10 })
	}
	join("d1", map[string]any{"disk_extra_gib": 5})
	join("d2", map[string]any{"reserved_for": "g2"})
	// A guest that is not metered: as on main.
	if status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"d1"}, "resources": map[string]any{"disk_gib": 11}}); status != 202 || doc["hotel"] != "d1" {
		t.Fatalf("extra-disk create on a joined hotel before its first list: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"d2"}}); status != 202 || doc["hotel"] != "d2" {
		t.Fatalf("create on a hotel reserved for the guest before its first list: %d %v", status, doc)
	}
	// A metered guest that may use d1 waits for its first list.
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}); status != 503 || errCode(doc) != "allowance_recount" {
		t.Fatalf("metered create before the joined hotel listed: %d %v", status, doc)
	}
	f := tc.hotels["d1"]
	f.mu.Lock()
	f.listFail = false
	f.mu.Unlock()
	tc.syncAll("d1")
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
}

// ---------------------------------------------------------------- review round 3

// waitRecord waits until cond holds for h's unreaped record of batch (nil:
// none), checked under the broker lock.
func waitRecord(t *testing.T, tc *testChain, hotelID, batch string, cond func(ub *unreapedBatch) bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		tc.b.mu.Lock()
		ub := tc.b.hotelByID(hotelID).unreaped[batch]
		ok := cond(ub)
		tc.b.mu.Unlock()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("record of batch %s on hotel %s: condition never held", batch, hotelID)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestMeteredHoldSurvivesAFailedThenEmptyCleanup(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	for _, id := range []string{"b", "c"} {
		f := tc.hotels[id]
		f.mu.Lock()
		f.createFail, f.labelListFail = 504, 503 // no room yet, and the first cleanup list fails
		f.mu.Unlock()
	}
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}})
	if status != 504 {
		t.Fatalf("lost create: %d %v", status, doc)
	}
	hotelID, batch := "", ""
	for _, id := range []string{"b", "c"} {
		f := tc.hotels[id]
		f.mu.Lock()
		f.createFail, f.labelListFail = 0, 0 // the background cleanup list now succeeds, empty
		if len(f.creates) == 1 {
			labels, _ := f.creates[0]["labels"].(map[string]any)
			hotelID, batch = id, labels[batchLabel].(string)
		}
		f.mu.Unlock()
	}
	// The background pass (after 1 s) lists nothing: the record stays, held.
	waitRecord(t, tc, hotelID, batch, func(ub *unreapedBatch) bool { return ub != nil && !ub.busy })
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create after a failed then empty cleanup, during the hold: %d %v", status, doc)
	}
	tc.syncAll()
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 402 {
		t.Fatalf("create after a sync during the hold: %d", status)
	}
	if _, _, deletes := hotelCalls(tc, lives); deletes != 0 {
		t.Fatalf("%d deletes", deletes)
	}
}

func TestMeteredBatchHoldKeepsUnfinishedAttempts(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 2))
	f := tc.hotels["b"]
	f.mu.Lock()
	f.createFail = 504
	f.mu.Unlock()
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "count": 2})
	if _, creates, _ := hotelCalls(tc, lives); status != 504 || creates != 2 {
		t.Fatalf("batch of 2, both answers lost: %d %v, %d creates", status, doc, creates)
	}
	f.mu.Lock()
	f.createFail = 0
	labels, _ := f.creates[0]["labels"].(map[string]any)
	batch := labels[batchLabel].(string)
	// One attempt's room appears late; the other never does.
	f.rooms = append(f.rooms, map[string]any{"id": "sbx_late", "state": "running", "labels": map[string]any{guestLabel: "g1", batchLabel: batch}})
	f.mu.Unlock()
	if v := tc.getAllowance(t, "g1"); v["live_rooms"] != 2.0 {
		t.Fatalf("both lost attempts held: %v", v)
	}
	tc.syncAll("b")
	waitRecord(t, tc, "b", batch, func(ub *unreapedBatch) bool {
		f.mu.Lock()
		deleted := len(f.roomDeletes)
		f.mu.Unlock()
		return ub != nil && !ub.busy && deleted == 1
	})
	if v := tc.getAllowance(t, "g1"); v["live_rooms"] != 1.0 {
		t.Fatalf("after the late room is reaped, the other attempt must still count: %v", v)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "count": 2}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("a batch of 2 beside the unfinished attempt: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	tc.b.hotelByID("b").unreaped[batch].holdUntil = time.Now().Add(-time.Second) // the hold passes
	tc.b.mu.Unlock()
	tc.syncAll("b")
	if v := tc.getAllowance(t, "g1"); v["live_rooms"] != 0.0 {
		t.Fatalf("after the hold: %v", v)
	}
}

// Known limit: a restart forgets a hold. Only an attempt whose room the
// hotel had not listed yet escapes; a listed room counts after the restart.
func TestMeteredRestartDuringTheHold(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	lostCreateNoRoom(t, tc, lives)
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 402 {
		t.Fatalf("create during the hold: %d", status)
	}
	tc.restart(t) // the hold was in memory only; the hotel lists no room yet
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 202 {
		t.Fatalf("create after a restart with no room listed (the documented limit): %d %v", status, doc)
	}

	tc2, lives2 := meteredChain(t, nil)
	tc2.putAllowance(t, "g1", allowanceBody(1, 1))
	for _, id := range []string{"b", "c"} { // the room starts, its answer is lost, the cleanup list fails
		f := tc2.hotels[id]
		f.mu.Lock()
		f.createFail, f.createFailAfterStart, f.labelListFail = 503, true, 503
		f.mu.Unlock()
	}
	if status, _ := tc2.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 503 {
		t.Fatalf("lost create with its room: %d", status)
	}
	for _, id := range []string{"b", "c"} {
		f := tc2.hotels[id]
		f.mu.Lock()
		f.createFail, f.createFailAfterStart = 0, false
		f.mu.Unlock()
	}
	tc2.restart(t) // the hotel lists the room: it counts as the guest's
	if status, doc := tc2.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create after a restart with the room listed: %d %v", status, doc)
	}
	if _, creates, _ := hotelCalls(tc2, lives2); creates != 1 {
		t.Fatalf("%d creates", creates)
	}
}

// Known limit: a room the hotel hides while its removal fails is not
// counted, with or without a restart. It is not listed, so not metered.
func TestMeteredHiddenRoomsAreNotCountedWithoutARestart(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	lives["b"].mu.Lock()
	lives["b"].hideDeletes = true
	lives["b"].mu.Unlock()
	// An orphan: the room starts, its answer is lost, the cleanup DELETE
	// answers 204 and the hotel hides the room.
	f := tc.hotels["b"]
	f.mu.Lock()
	f.createFail, f.createFailAfterStart = 503, true
	f.mu.Unlock()
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}); status != 503 {
		t.Fatalf("lost create: %d", status)
	}
	f.mu.Lock()
	f.createFail, f.createFailAfterStart = 0, false
	hidden := len(f.rooms)
	f.mu.Unlock()
	tc.syncAll()
	if hidden != 1 {
		t.Fatalf("the orphan container should still exist at the hotel: %d rooms", hidden)
	}
	r1 := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}}) // one extra room per hidden room
	// A room of the guest: deleted, hidden, released by the sync loop.
	tc.putAllowance(t, "g1", allowanceBody(2, 1))
	lives["c"].mu.Lock()
	lives["c"].hideDeletes = true
	lives["c"].mu.Unlock()
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+r1, nil); status != 204 {
		t.Fatalf("delete: %d", status)
	}
	tc.b.mu.Lock()
	tc.b.byBID(r1).vanished = time.Now().Add(-3 * time.Second)
	tc.b.mu.Unlock()
	tc.syncAll()
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}})
}

func TestMeteredJoinRecountEndsAtTheFirstSuccessfulList(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	tc.hotels["d"] = f
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "d", "api": hs.URL, "key": joinKey}); status != 201 {
		t.Fatalf("join d: %d %v", status, doc)
	}
	stopSyncLoop(t, tc, "d")
	tc.syncAll("d") // the first list succeeds
	f.mu.Lock()
	f.listFail = true // later lists fail, before any metered request
	f.mu.Unlock()
	tc.syncAll("d")
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
}

// ---------------------------------------------------------------- review round 4

func TestMeteredHoldEndsOnlyOnAListAskedAfterItsDeadline(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	hotelID, batch := lostCreateNoRoom(t, tc, lives)
	deadline := time.Now().Add(400 * time.Millisecond)
	tc.b.mu.Lock()
	tc.b.hotelByID(hotelID).unreaped[batch].holdUntil = deadline
	tc.b.mu.Unlock()
	l, f := lives[hotelID], tc.hotels[hotelID]
	release, taken := make(chan struct{}), make(chan struct{}, 1)
	l.mu.Lock()
	l.holdList, l.listTaken = release, taken
	l.mu.Unlock()
	done := make(chan struct{})
	go func() { tc.syncAll(hotelID); close(done) }()
	<-taken // the hotel's list is taken before the deadline: empty
	f.mu.Lock()
	f.rooms = append(f.rooms, map[string]any{"id": "sbx_late", "state": "running", "labels": map[string]any{guestLabel: "g1", batchLabel: batch}})
	f.mu.Unlock() // the room starts before the deadline
	time.Sleep(time.Until(deadline) + 50*time.Millisecond)
	close(release) // the old empty answer arrives after the deadline
	<-done
	l.mu.Lock()
	l.holdList = nil
	l.mu.Unlock()
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create after an empty list asked for before the deadline: %d %v", status, doc)
	}
	// The next list shows the room: it counts until it is reaped.
	held := make(chan struct{})
	l.mu.Lock()
	l.holdDeletes = held
	l.mu.Unlock()
	tc.syncAll(hotelID)
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create while the late room is listed: %d %v", status, doc)
	}
	close(held)
	if _, creates, _ := hotelCalls(tc, lives); creates != 1 {
		t.Fatalf("%d creates dispatched at cap 1", creates)
	}
}

func TestMeteredHoldOutlivesItsHotelLeaving(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}, createFail: 504} // the answer is lost, no room yet
	hs := httptest.NewServer(f)
	t.Cleanup(hs.Close)
	tc.hotels["d"] = f
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "d", "api": hs.URL, "key": joinKey}); status != 201 {
		t.Fatalf("join d: %d %v", status, doc)
	}
	setHotel(tc, "d", func(h *hotel) { h.ok, h.slots = true, 10 })
	tc.syncAll("d")
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"d"}}); status != 504 {
		t.Fatalf("lost create on d: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/d", nil); status != 204 {
		t.Fatalf("leave d during the hold: %d %v", status, doc) // the leave is not blocked
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create after the hotel left during the hold: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	for _, ha := range tc.b.allow.held {
		ha.until = time.Now().Add(-time.Second) // the hold passes
	}
	tc.b.mu.Unlock()
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
}

func TestMeteredCleanupListAskedBeforeTheDeadlineKeepsTheHold(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	for _, id := range []string{"b", "c"} {
		f := tc.hotels[id]
		f.mu.Lock()
		f.createFail, f.labelListFail = 504, 503 // no room yet, and the first cleanup list fails
		f.mu.Unlock()
	}
	release, taken := make(chan struct{}), make(chan struct{}, 4)
	for _, id := range []string{"b", "c"} {
		lives[id].mu.Lock()
		lives[id].holdList, lives[id].listTaken, lives[id].holdLabelLists = release, taken, true
		lives[id].mu.Unlock()
	}
	go func() { // the first cleanup list (it fails) passes at once
		<-taken
		release <- struct{}{}
	}()
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 504 {
		t.Fatalf("lost create: %d", status)
	}
	hotelID, batch := "", ""
	for _, id := range []string{"b", "c"} {
		f := tc.hotels[id]
		f.mu.Lock()
		f.createFail, f.labelListFail = 0, 0
		if len(f.creates) == 1 {
			labels, _ := f.creates[0]["labels"].(map[string]any)
			hotelID, batch = id, labels[batchLabel].(string)
		}
		f.mu.Unlock()
	}
	<-taken // the background cleanup list is asked for: empty
	deadline := time.Now().Add(200 * time.Millisecond)
	tc.b.mu.Lock()
	tc.b.hotelByID(hotelID).unreaped[batch].holdUntil = deadline
	tc.b.mu.Unlock()
	f := tc.hotels[hotelID]
	f.mu.Lock()
	f.rooms = append(f.rooms, map[string]any{"id": "sbx_late", "state": "running", "labels": map[string]any{guestLabel: "g1", batchLabel: batch}})
	f.mu.Unlock() // the room starts before the deadline
	time.Sleep(time.Until(deadline) + 50*time.Millisecond)
	for _, id := range []string{"b", "c"} {
		lives[id].mu.Lock()
		lives[id].holdList = nil
		lives[id].mu.Unlock()
	}
	release <- struct{}{} // the old empty answer arrives after the deadline
	waitRecord(t, tc, hotelID, batch, func(ub *unreapedBatch) bool { return ub == nil || !ub.busy })
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b", "c"}}); status != 402 || errCode(doc) != "allowance_exhausted" {
		t.Fatalf("create after a cleanup list asked for before the deadline: %d %v", status, doc)
	}
	if _, creates, _ := hotelCalls(tc, lives); creates != 1 {
		t.Fatalf("%d creates dispatched at cap 1", creates)
	}
}
