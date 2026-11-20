package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
}

type lifeCall struct {
	method, path string
	body         map[string]any
}

func (l *lifeHotel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	l.seen = append(l.seen, r.Method+" "+r.URL.Path)
	l.mu.Unlock()
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

// meteredChain is newChainState with a state_dir and every hotel API behind
// a lifeHotel. edit may change the config first. Every hotel lists its rooms
// once, so no recount is pending.
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
		l := &lifeHotel{inner: tc.hotels[id], docTTL: 900.0}
		s := httptest.NewServer(l)
		t.Cleanup(s.Close)
		cfg.Hotels[i].API = s.URL
		lives[id] = l
	}
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
	// An allowance cannot be kept without state_dir either.
	tc2 := newChain(t)
	if status, doc := tc2.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", allowanceBody(1, 1)); status != 409 || errCode(doc) != "no_state_dir" {
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
	if v := tc.getAllowance(t, "g1"); v["cap"] != 0.0 || v["ledger_seen_at"] != nil {
		t.Fatalf("view after a corrupt file: %v", v)
	}
	aside, _ := filepath.Glob(path + ".corrupt-*")
	if _, err := os.Stat(path); len(aside) != 1 || !os.IsNotExist(err) {
		t.Fatalf("corrupt file not moved aside: %v %v", aside, err)
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
	// The ledger's next allowance opens it again.
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
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
	if v := tc.getAllowance(t, "g1"); v["metered"] != false {
		t.Fatalf("bad bodies changed the guest: %v", v)
	}
	doc := tc.putAllowance(t, "g1", allowanceBody(1, 2))
	if doc["metered"] != true || doc["cap"] != 2.0 || doc["issue"] != 1.0 || doc["lease_seconds"] != 600.0 || doc["max_ttl_seconds"] != 3600.0 || doc["max_memory_gib"] != 4.0 || doc["ledger_seen_at"] == nil {
		t.Fatalf("PUT answer: %v", doc)
	}
}
