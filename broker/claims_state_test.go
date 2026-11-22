package main

// Tests of the mapping from a claimed ready room to the customer's run
// (AB#894 phase 2 PR 4; design table 8.1): one test per row, with a mapping
// injected through mapRoomLocked, the function the win (PR 6) and the
// restart use.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// mappedHotel wraps a fakePoolHotel with the hotel routes the mapping paths
// call and the pool's own tests do not: a list filtered by label, one room's
// document, freeze, exec, usage, bulk delete, and room deletes that fail. It
// is a new file's wrapper so the pool's fake and its tests stay as they are.
type mappedHotel struct {
	f       *fakePoolHotel
	mu      sync.Mutex
	created map[string]time.Time // room id -> created_at; absent: the wrapper's start
	frozen  map[string]bool
	delFail map[string]int // room id -> the status its delete answers
	start   time.Time
}

func (m *mappedHotel) createdAt(id string) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.created[id]; ok {
		return t
	}
	return m.start
}

// doc is room r as the hotel documents it. Caller holds m.f.mu.
func (m *mappedHotel) doc(r *fakePoolRoom) map[string]any {
	m.mu.Lock()
	state := "running"
	if m.frozen[r.id] {
		state = "frozen"
	}
	m.mu.Unlock()
	return map[string]any{"id": r.id, "state": state, "labels": r.labels, "ttl_seconds": 14400,
		"resources":  map[string]any{"vcpu": 1, "memory_gib": 4, "disk_gib": 10},
		"created_at": m.createdAt(r.id).UTC().Format(time.RFC3339Nano), "expires_at": r.expires.UTC().Format(time.RFC3339)}
}

func (m *mappedHotel) record(r *http.Request) {
	m.f.mu.Lock()
	m.f.calls = append(m.f.calls, fakePoolCall{at: time.Now(), method: r.Method, path: r.URL.Path, header: r.Header.Clone()})
	m.f.mu.Unlock()
}

func (m *mappedHotel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, q := r.URL.Path, r.URL.Query()
	reply := func(status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	id, tail, _ := strings.Cut(strings.TrimPrefix(p, "/v1/sandboxes/"), "/")
	room := strings.HasPrefix(p, "/v1/sandboxes/") && id != ""
	switch {
	case p == "/v1/sandboxes" && r.Method == "GET" && len(q["label"]) > 0:
		m.f.mu.Lock()
		list := []map[string]any{}
		for _, rm := range m.f.rooms {
			if labelsMatch(rm.labels, q["label"]) {
				list = append(list, m.doc(rm))
			}
		}
		m.f.mu.Unlock()
		reply(200, map[string]any{"sandboxes": list})
	case p == "/v1/sandboxes" && r.Method == "DELETE":
		m.record(r)
		m.f.mu.Lock()
		n := 0
		for rid, rm := range m.f.rooms {
			if labelsMatch(rm.labels, q["label"]) {
				delete(m.f.rooms, rid)
				n++
			}
		}
		m.f.mu.Unlock()
		reply(200, map[string]any{"deleted": n})
	case p == "/v1/usage" && r.Method == "GET":
		key := strings.TrimPrefix(q.Get("group_by"), "label.")
		if key == "" {
			key = "job"
		}
		groups := map[string]any{}
		m.f.mu.Lock()
		for _, rm := range m.f.rooms {
			if !labelsMatch(rm.labels, q["label"]) {
				continue
			}
			name := rm.labels[key]
			if name == "" {
				name = "unlabelled"
			}
			hours := time.Since(m.createdAt(rm.id)).Hours()
			g, _ := groups[name].(map[string]any)
			if g == nil {
				g = map[string]any{"sandbox_hours": 0.0, "vcpu_hours": 0.0, "gib_hours": 0.0}
				groups[name] = g
			}
			g["sandbox_hours"] = g["sandbox_hours"].(float64) + hours
			g["vcpu_hours"] = g["vcpu_hours"].(float64) + hours
			g["gib_hours"] = g["gib_hours"].(float64) + 4*hours
		}
		m.f.mu.Unlock()
		reply(200, map[string]any{"group_by": "label." + key, "groups": groups})
	case room && tail == "freeze" && r.Method == "POST":
		m.record(r)
		m.mu.Lock()
		m.frozen[id] = true
		m.mu.Unlock()
		reply(200, map[string]any{"id": id, "state": "frozen"})
	case room && tail == "exec" && r.Method == "POST":
		m.record(r)
		reply(200, map[string]any{"exit_code": 0, "stdout": "ok", "stderr": ""})
	case room && tail == "" && r.Method == "GET":
		m.f.mu.Lock()
		rm := m.f.rooms[id]
		var doc map[string]any
		if rm != nil {
			doc = m.doc(rm)
		}
		m.f.mu.Unlock()
		if doc == nil {
			reply(404, map[string]any{"error": map[string]any{"code": "sandbox_not_found"}})
			return
		}
		reply(200, doc)
	case room && tail == "" && r.Method == "DELETE" && m.failsDelete(id) != 0:
		m.record(r)
		reply(m.failsDelete(id), map[string]any{"error": "delete failed"})
	default:
		m.f.ServeHTTP(w, r)
	}
}

func (m *mappedHotel) failsDelete(id string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.delFail[id]
}

// newMappedChain is a pool chain over one hotel "a" behind a mappedHotel,
// with guests g1 (key1) and g2 (key2), a meter key, and rooms ready rooms
// sbx-1 to sbx-<rooms>.
func newMappedChain(t *testing.T, rooms int) (*poolChain, *mappedHotel) {
	t.Helper()
	pc := newPoolChain(t, []string{"a"}, func(c *config) {
		c.Guests = append(c.Guests, guestConfig{ID: "g2", KeySHA256: sha("key2")})
		c.MeterKeySHA256 = sha("meter-key")
	})
	mh := &mappedHotel{f: pc.hotels["a"], created: map[string]time.Time{}, frozen: map[string]bool{}, delFail: map[string]int{}, start: time.Now()}
	srv := httptest.NewServer(mh)
	t.Cleanup(srv.Close)
	raw, err := os.ReadFile(pc.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Hotels[0].API, cfg.Hotels[0].Health = srv.URL, srv.URL
	raw, _ = json.Marshal(cfg)
	if err := os.WriteFile(pc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	pc.start()
	pc.up("a")
	pc.target(rooms)
	pc.fill("a", rooms)
	return pc, mh
}

// mapRoom does to ready room hid of hotel a what a won claim does (PR 6):
// the front signs the claim receipt, and the broker maps the room to guest.
// It returns the run id.
func (pc *poolChain) mapRoom(hid, guest string, labels map[string]string, wonAt time.Time) string {
	pc.t.Helper()
	run := newUUID()
	f := pc.hotels["a"]
	f.mu.Lock()
	r := f.rooms[hid]
	if r == nil || len(r.receipts) == 0 {
		f.mu.Unlock()
		pc.t.Fatalf("no ready room %s with its receipt 1 on the fake hotel", hid)
	}
	prev := sha256.Sum256(r.receipts[len(r.receipts)-1])
	r.receipts = append(r.receipts, f.receipt(f.priv, map[string]any{"schema": sealedReceiptSchema, "binding_sha256": f.binding,
		"action": "claim", "sandbox_id": hid, "status": 200, "room_sequence": len(r.receipts) + 1,
		"room_previous_receipt_sha256": hex.EncodeToString(prev[:]), "cathedral_sandbox_id": run}))
	f.mu.Unlock()
	h := pc.b.hotelByID("a")
	pc.b.mu.Lock()
	rm := h.rooms[hid]
	if rm == nil {
		pc.b.mu.Unlock()
		pc.t.Fatalf("room %s not in the broker's room map", hid)
	}
	pc.b.mapRoomLocked(h, rm, guest, roomMapping{run: run, customerLabels: labels, wonAt: wonAt, vcpu: 1, memGiB: 4})
	pc.b.mu.Unlock()
	return run
}

// writeWon appends the mapping part of a won record (design 2.1) to the
// running broker's claim journal, as PR 5 will write it.
func (pc *poolChain) writeWon(guest, hid, run string, labels map[string]string, wonAt time.Time) {
	pc.t.Helper()
	body, _ := json.Marshal(map[string]any{"request_key": "key-" + run, "guest": guest,
		"winner":          map[string]any{"attempt_id": run, "room": "a." + hid},
		"run":             map[string]any{"run_id": run, "started_at": wonAt.UnixMilli(), "vcpu": 1, "memory_gib": 4},
		"customer_labels": labels})
	if err := <-pc.b.pool.journal.append(claimRecord{Kind: "won", Body: body}); err != nil {
		pc.t.Fatal(err)
	}
}

// as calls the broker with a guest key (or the meter key); compat: as a
// compat client.
func (pc *poolChain) as(key, method, path string, compat bool) (int, map[string]any) {
	pc.t.Helper()
	var body *bytes.Reader
	if method == "POST" {
		body = bytes.NewReader([]byte(`{"cmd":["true"]}`))
	} else {
		body = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, pc.srv.URL+path, body)
	req.Header.Set("Authorization", "Bearer "+key)
	if compat {
		req.Header.Set("User-Agent", "ctcli/test")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		pc.t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return resp.StatusCode, doc
}

// listIDs is the room ids a list answer holds.
func listIDs(doc map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	list, _ := doc["sandboxes"].([]any)
	for _, x := range list {
		if s, ok := x.(map[string]any); ok {
			id, _ := s["id"].(string)
			out[id] = s
		}
	}
	return out
}

func labelsOf(doc map[string]any) map[string]string {
	out := map[string]string{}
	m, _ := doc["labels"].(map[string]any)
	for k, v := range m {
		out[k], _ = v.(string)
	}
	return out
}

func sameLabels(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func endedCount(rs []usageReading) int {
	n := 0
	for _, r := range rs {
		if r.State == "ended" {
			n++
		}
	}
	return n
}

var jobA = map[string]string{"job": "a"}

// Row "meter sighting": a claimed room's readings are the customer's run,
// billable; the physical id never carries the customer.
func TestMappedRoomSightingIsTheCustomersRun(t *testing.T) {
	pc, _ := newMappedChain(t, 1)
	run := pc.mapRoom("sbx-1", "g1", jobA, time.Now())
	pc.sync("a")
	pc.sync("a")
	rs := pc.readingsOfRun(run)
	if len(rs) == 0 || rs[0].Guest != "g1" || rs[0].Hotel != "a" || rs[0].Billable != nil {
		t.Fatalf("readings of the customer's run %s: %+v, want g1's, billable", run, rs)
	}
	for _, r := range pc.readingsOfRun("a.sbx-1") {
		if r.Guest == "g1" && !notBillable(r) {
			t.Fatalf("the physical id carries the customer, billable: %+v", r)
		}
	}
}

// Row "meter single-delete hook": the customer's delete ends the customer's
// run, native and compat.
func TestMappedRoomDeleteEndsTheCustomersRun(t *testing.T) {
	for _, compat := range []bool{false, true} {
		name := map[bool]string{false: "native", true: "compat"}[compat]
		t.Run(name, func(t *testing.T) {
			pc, _ := newMappedChain(t, 1)
			run := pc.mapRoom("sbx-1", "g1", jobA, time.Now())
			pc.sync("a")
			path := "/v1/sandboxes/a.sbx-1"
			if compat {
				path = "/v1/sandboxes/" + run
			}
			if st, doc := pc.as("key1", "DELETE", path, compat); st != 204 && st != 200 {
				t.Fatalf("delete %s: %d %v", path, st, doc)
			}
			if rs := pc.readingsOfRun(run); endedCount(rs) != 1 || rs[len(rs)-1].State != "ended" {
				t.Fatalf("readings of the customer's run after its delete: %+v, want one ended reading last", rs)
			}
		})
	}
}

// Row "meter leftover and orphan sightings": a mapped room listed by its
// hotel is sighted as the customer's run, never by its physical id.
func TestMappedRoomNeverSightedByPhysicalID(t *testing.T) {
	pc, _ := newMappedChain(t, 1)
	run := pc.mapRoom("sbx-1", "g1", jobA, time.Now())
	h := pc.b.hotelByID("a")
	pc.b.mu.Lock()
	s := pc.b.usageSightingOfListed(h, "sbx-1", map[string]string{poolLabel: "1", guestLabel: poolGuestID}, nil)
	pc.b.mu.Unlock()
	if s.run != run || s.guest != "g1" || !s.billable {
		t.Fatalf("sighting of the listed mapped room: %+v, want run %s of g1, billable", s, run)
	}
}

// Row "meter hotel pass": the customer's run stays present while its room
// runs; the pass does not end it.
func TestMappedRunStaysPresentInTheHotelPass(t *testing.T) {
	pc, _ := newMappedChain(t, 1)
	run := pc.mapRoom("sbx-1", "g1", jobA, time.Now())
	for i := 0; i < 3; i++ {
		pc.sync("a")
	}
	pc.b.usageMeter.mu.Lock()
	open := pc.b.usageMeter.runs[run] != nil
	pc.b.usageMeter.mu.Unlock()
	if rs := pc.readingsOfRun(run); !open || endedCount(rs) != 0 {
		t.Fatalf("customer's run open %v, readings %+v; want open with no ended reading", open, rs)
	}
}

// Rows "bulk delete" and "bulk delete meter pre-list": a customer's bulk
// delete by label removes its claimed rooms whose customer labels match and
// ends their runs; the others stay.
func TestBulkDeleteEndsMatchingMappedRuns(t *testing.T) {
	pc, _ := newMappedChain(t, 2)
	runA := pc.mapRoom("sbx-1", "g1", jobA, time.Now())
	runB := pc.mapRoom("sbx-2", "g1", map[string]string{"job": "b"}, time.Now())
	pc.sync("a")
	if st, doc := pc.as("key1", "DELETE", "/v1/sandboxes?label="+url.QueryEscape("job=a"), false); st != 200 {
		t.Fatalf("bulk delete: %d %v", st, doc)
	}
	f := pc.hotels["a"]
	if f.roomCount() != 1 || len(f.callsOf("DELETE", "/v1/sandboxes/sbx-1")) != 1 || len(f.callsOf("DELETE", "/v1/sandboxes/sbx-2")) != 0 {
		t.Fatalf("hotel rooms %d, deletes of sbx-1 %d, of sbx-2 %d; want sbx-1 deleted once, sbx-2 kept",
			f.roomCount(), len(f.callsOf("DELETE", "/v1/sandboxes/sbx-1")), len(f.callsOf("DELETE", "/v1/sandboxes/sbx-2")))
	}
	if rs := pc.readingsOfRun(runA); endedCount(rs) != 1 {
		t.Fatalf("matching claimed run: %+v, want ended once", rs)
	}
	if rs := pc.readingsOfRun(runB); endedCount(rs) != 0 {
		t.Fatalf("claimed run of another label: %+v, want it running", rs)
	}
}

// A one-by-one delete of a claimed room that fails after the hotel bulk
// delete answered: the customer is never told the room is gone while it runs
// and bills (409 bulk_delete_incomplete, naming it); a retry finishes.
func TestBulkDeleteNeverReportsARunningClaimedRoomGone(t *testing.T) {
	pc, mh := newMappedChain(t, 1)
	run := pc.mapRoom("sbx-1", "g1", jobA, time.Now())
	pc.sync("a")
	mh.mu.Lock()
	mh.delFail["sbx-1"] = 500
	mh.mu.Unlock()
	path := "/v1/sandboxes?label=" + url.QueryEscape("job=a")
	st, doc := pc.as("key1", "DELETE", path, false)
	rooms, _ := doc["rooms"].(map[string]any)
	if st != 409 || errCode(doc) != "bulk_delete_incomplete" || rooms["a.sbx-1"] != float64(500) {
		t.Fatalf("bulk delete with the claimed room's delete failing: %d %v, want 409 bulk_delete_incomplete naming a.sbx-1", st, doc)
	}
	if st, _ := pc.as("key1", "GET", "/v1/sandboxes/a.sbx-1", false); st != 200 {
		t.Fatalf("the room still runs: GET %d, want 200", st)
	}
	if rs := pc.readingsOfRun(run); endedCount(rs) != 0 {
		t.Fatalf("run of the room that still runs: %+v, want no ended reading", rs)
	}
	mh.mu.Lock()
	delete(mh.delFail, "sbx-1")
	mh.mu.Unlock()
	if st, doc := pc.as("key1", "DELETE", path, false); st != 200 {
		t.Fatalf("retry: %d %v, want 200", st, doc)
	}
	if rs := pc.readingsOfRun(run); endedCount(rs) != 1 {
		t.Fatalf("run after the retry: %+v, want ended once", rs)
	}
}

// Rows "native list, compat list": the customer lists its claimed rooms with
// its own labels and the win time; filters use those labels; the pool's other
// rooms and another customer's claimed rooms never appear.
func TestMappedRoomListedWithCustomerLabels(t *testing.T) {
	pc, _ := newMappedChain(t, 3)
	wonAt := time.Now().Add(-time.Minute)
	run1 := pc.mapRoom("sbx-1", "g1", jobA, wonAt)
	run2 := pc.mapRoom("sbx-2", "g2", jobA, wonAt)
	pc.sync("a")
	_, doc := pc.as("key1", "GET", "/v1/sandboxes", false)
	ids := listIDs(doc)
	s := ids["a.sbx-1"]
	if s == nil || ids["a.sbx-2"] != nil || ids["a.sbx-3"] != nil {
		t.Fatalf("native list of g1: %v, want a.sbx-1 only of the ready rooms", doc)
	}
	if !sameLabels(labelsOf(s), jobA) || s["created_at"] != wonAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("listed claimed room %v, want labels %v and created_at the win", s, jobA)
	}
	for filter, want := range map[string]bool{"job=a": true, "job=b": false, poolLabel + "=1": false} {
		_, doc := pc.as("key1", "GET", "/v1/sandboxes?label="+url.QueryEscape(filter), false)
		if got := listIDs(doc)["a.sbx-1"] != nil; got != want {
			t.Fatalf("list with label %s: a.sbx-1 listed %v, want %v", filter, got, want)
		}
	}
	_, doc = pc.as("key1", "GET", "/v1/sandboxes", true)
	ids = listIDs(doc)
	if ids[run1] == nil || ids[run2] != nil || len(ids) != 1 {
		t.Fatalf("compat list of g1: %v, want only %s", doc, run1)
	}
}

// Row "usage parts": a claimed room's hours count from the win, never its
// pool time, and never another customer's claimed room.
func TestUsageCountsMappedRoomFromTheWin(t *testing.T) {
	pc, mh := newMappedChain(t, 3)
	mh.mu.Lock()
	for _, id := range []string{"sbx-1", "sbx-2", "sbx-3"} {
		mh.created[id] = time.Now().Add(-3 * time.Hour) // pool time before the win
	}
	mh.mu.Unlock()
	pc.mapRoom("sbx-1", "g1", jobA, time.Now().Add(-time.Hour))
	pc.mapRoom("sbx-2", "g2", jobA, time.Now().Add(-2*time.Hour))
	pc.mapRoom("sbx-3", "g1", map[string]string{"job": "b"}, time.Now().Add(-30*time.Minute))
	pc.sync("a")
	if st, _ := pc.as("key1", "DELETE", "/v1/sandboxes/a.sbx-3", false); st != 204 {
		t.Fatalf("delete of a.sbx-3: %d", st)
	}
	pc.sync("a")
	pc.letGo("a") // sbx-3 leaves the room map: its end record holds its hours
	_, doc := pc.as("key1", "GET", "/v1/usage?group_by=label.job", false)
	hotels, _ := doc["hotels"].(map[string]any)
	part, _ := hotels["a"].(map[string]any)
	groups, _ := part["groups"].(map[string]any)
	near := func(name string, want float64) {
		g, _ := groups[name].(map[string]any)
		got, _ := g["sandbox_hours"].(float64)
		if got < want-0.02 || got > want+0.02 {
			t.Fatalf("group %s: %v sandbox hours, want %.2f (from the win, no pool time, no other customer); answer %v", name, got, want, doc)
		}
		if gib, _ := g["gib_hours"].(float64); gib < 4*want-0.08 || gib > 4*want+0.08 {
			t.Fatalf("group %s: %v GiB hours, want %.2f", name, gib, 4*want)
		}
	}
	near("a", 1.0)
	near("b", 0.5)
}

// Row "meter-key rooms and freeze-all": the meter sees and freezes the
// guest's claimed rooms, never the pool's or another customer's.
func TestMeterRoutesSeeAndFreezeMappedRooms(t *testing.T) {
	pc, mh := newMappedChain(t, 3)
	wonAt := time.Now().Add(-time.Minute)
	pc.mapRoom("sbx-1", "g1", jobA, wonAt)
	pc.mapRoom("sbx-2", "g2", jobA, wonAt)
	pc.sync("a")
	_, doc := pc.as("meter-key", "GET", "/v1/broker/guests/g1/rooms", false)
	ids := map[string]map[string]any{}
	list, _ := doc["rooms"].([]any)
	for _, x := range list {
		if s, ok := x.(map[string]any); ok {
			id, _ := s["id"].(string)
			ids[id] = s
		}
	}
	if s := ids["a.sbx-1"]; s == nil || ids["a.sbx-2"] != nil || ids["a.sbx-3"] != nil || s["created_at"] != wonAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("meter rooms of g1: %v, want a.sbx-1 only, created at the win", doc)
	}
	_, doc = pc.as("meter-key", "POST", "/v1/broker/guests/g1/freeze-all", false)
	frozen, _ := doc["frozen"].([]any)
	mh.mu.Lock()
	f1, f2, f3 := mh.frozen["sbx-1"], mh.frozen["sbx-2"], mh.frozen["sbx-3"]
	mh.mu.Unlock()
	if len(frozen) != 1 || frozen[0] != "a.sbx-1" || !f1 || f2 || f3 {
		t.Fatalf("freeze-all of g1: %v; hotel frozen sbx-1 %v sbx-2 %v sbx-3 %v; want only sbx-1", doc, f1, f2, f3)
	}
}

// Row "room GET": the customer's GET shows its labels and the win time,
// native and compat; another customer's claimed room is not found.
func TestMappedRoomGetShowsCustomerLabelsAndWinTime(t *testing.T) {
	pc, _ := newMappedChain(t, 2)
	wonAt := time.Now().Add(-time.Minute)
	run1 := pc.mapRoom("sbx-1", "g1", jobA, wonAt)
	run2 := pc.mapRoom("sbx-2", "g2", jobA, wonAt)
	pc.sync("a")
	for _, c := range []struct {
		path   string
		compat bool
	}{{"/v1/sandboxes/a.sbx-1", false}, {"/v1/sandboxes/" + run1, true}} {
		st, doc := pc.as("key1", "GET", c.path, c.compat)
		if st != 200 || !sameLabels(labelsOf(doc), jobA) || doc["created_at"] != wonAt.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("GET %s (compat %v): %d %v, want labels %v and created_at the win", c.path, c.compat, st, doc, jobA)
		}
	}
	if st, _ := pc.as("key1", "GET", "/v1/sandboxes/a.sbx-2", false); st != 404 {
		t.Fatalf("g1 GET of g2's claimed room: %d, want 404", st)
	}
	if st, doc := pc.as("key1", "GET", "/v1/sandboxes/"+run2, true); st != 404 {
		t.Fatalf("g1 compat GET of g2's claimed room: %d %v, want 404", st, doc)
	}
}

// Row "quota views": a claimed room counts as the guest's running room. The
// hotel's quota is hotel-wide and the guest count goes by rm.guest, so no
// code changes for it: this test pins that.
func TestQuotaCountsMappedRooms(t *testing.T) {
	pc, _ := newMappedChain(t, 2)
	pc.mapRoom("sbx-1", "g1", jobA, time.Now())
	pc.sync("a")
	_, doc := pc.as("key1", "GET", "/v1/quota", false)
	guest, _ := doc["guest"].(map[string]any)
	if guest["running_sandboxes"] != float64(1) {
		t.Fatalf("quota of g1: %v, want 1 running sandbox (its claimed room)", doc)
	}
}

// Row "end records": a claimed room's end record carries the customer, its
// client id and the win time; label attribution of a bulk delete uses the
// customer's labels.
func TestMappedRoomEndRecordCarriesCustomerAndWinTime(t *testing.T) {
	pc, _ := newMappedChain(t, 1)
	wonAt := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	run := pc.mapRoom("sbx-1", "g1", jobA, wonAt)
	pc.sync("a")
	h := pc.b.hotelByID("a")
	pc.b.mu.Lock()
	pc.b.addTombstone("g1", []string{"job=a"}, time.Now())
	attributed := pc.b.bulkDeleted(h.rooms["sbx-1"])
	pc.b.mu.Unlock()
	if !attributed {
		t.Fatal("a bulk delete by the customer's label is not attributed to the claimed room")
	}
	f := pc.hotels["a"]
	f.mu.Lock()
	delete(f.rooms, "sbx-1") // the room goes at the hotel
	f.mu.Unlock()
	pc.sync("a")
	pc.letGo("a")
	rec := pc.b.endedByUUID("g1", run)
	if rec == nil || rec.Guest != "g1" || rec.UUID != run || rec.CreatedAt == nil || !rec.CreatedAt.Equal(wonAt) {
		t.Fatalf("end record %+v, want g1's, client id %s, created at the win %s", rec, run, wonAt)
	}
}

// Row "noteListed and the creation time": syncs keep the customer's labels,
// guest and win time.
func TestSyncKeepsCustomerLabelsAndWinTime(t *testing.T) {
	pc, _ := newMappedChain(t, 1)
	wonAt := time.Now().Add(-time.Minute)
	run := pc.mapRoom("sbx-1", "g1", jobA, wonAt)
	for i := 0; i < 10; i++ {
		pc.sync("a")
	}
	h := pc.b.hotelByID("a")
	pc.b.mu.Lock()
	rm := h.rooms["sbx-1"]
	ok := rm != nil && rm.guest == "g1" && rm.uuid == run && rm.born.Equal(wonAt) && rm.mapping != nil && sameLabels(rm.viewLabels(), jobA)
	pc.b.mu.Unlock()
	if !ok {
		t.Fatalf("after ten syncs: %+v, want g1's room %s born at the win with labels %v", rm, run, jobA)
	}
	if _, doc := pc.as("key1", "GET", "/v1/sandboxes/a.sbx-1", false); !sameLabels(labelsOf(doc), jobA) {
		t.Fatalf("GET after ten syncs: %v, want labels %v", doc, jobA)
	}
}

// Row "receipt ownership history and attestation lookup": the claimed room
// stays the customer's for receipts after it leaves the room map.
func TestMappedRoomReceiptsStayTheCustomersAfterRelease(t *testing.T) {
	pc, _ := newMappedChain(t, 1)
	pc.mapRoom("sbx-1", "g1", jobA, time.Now())
	pc.sync("a")
	f := pc.hotels["a"]
	f.mu.Lock()
	delete(f.rooms, "sbx-1")
	f.mu.Unlock()
	pc.sync("a")
	pc.letGo("a")
	pc.b.mu.Lock()
	gone := pc.b.hotelByID("a").rooms["sbx-1"] == nil
	pc.b.mu.Unlock()
	if !gone || !pc.b.guestRoomIDs("g1", "a")["sbx-1"] {
		t.Fatalf("room released %v; g1's receipt rooms %v, want sbx-1 kept", gone, pc.b.guestRoomIDs("g1", "a"))
	}
}

// mappedRestart maps sbx-1 to g1 with its won record, meters it, and
// restarts the broker over the same state; broken: the journal loses a
// segment first. It returns the run and the room's readings before.
func mappedRestart(t *testing.T, pc *poolChain, wonAt time.Time, broken bool) (string, []usageReading) {
	t.Helper()
	run := pc.mapRoom("sbx-1", "g1", jobA, wonAt)
	pc.writeWon("g1", "sbx-1", run, jobA, wonAt)
	pc.sync("a")
	time.Sleep(1100 * time.Millisecond)
	pc.sync("a")
	before := pc.readingsOfRun(run)
	if err := pc.b.saveCompat(); err != nil { // client-state.json as the one-second save leaves it
		t.Fatal(err)
	}
	if broken {
		pc.breakJournal()
	}
	pc.start()
	return run, before
}

// Row "sync adoption after a restart" (work order): after a restart the
// journal's mapping comes back before the first sync adopts the room: the
// customer's guest, client id, run, labels and win time; the run goes on.
func TestMappedRunContinuesAcrossRestart(t *testing.T) {
	pc, _ := newMappedChain(t, 1)
	wonAt := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	run, before := mappedRestart(t, pc, wonAt, false)
	if len(before) == 0 {
		t.Fatalf("no reading of the customer's run %s before the restart", run)
	}
	pc.up("a")
	pc.sync("a")
	h := pc.b.hotelByID("a")
	pc.b.mu.Lock()
	rm := h.rooms["sbx-1"]
	ok := rm != nil && rm.guest == "g1" && rm.uuid == run && rm.runID() == run && rm.born.Equal(wonAt) && sameLabels(rm.viewLabels(), jobA)
	pc.b.mu.Unlock()
	if !ok {
		t.Fatalf("after the restart: %+v, want g1's room %s, born %s, labels %v", rm, run, wonAt, jobA)
	}
	if st, doc := pc.as("key1", "GET", "/v1/sandboxes/"+run, true); st != 200 || !sameLabels(labelsOf(doc), jobA) {
		t.Fatalf("compat GET after the restart: %d %v", st, doc)
	}
	time.Sleep(1100 * time.Millisecond)
	pc.sync("a")
	pc.b.usageMeter.checkpoint(time.Now()) // the reading a clean stop writes: seconds since the last one
	after := pc.readingsOfRun(run)
	last, first := after[len(after)-1], before[len(before)-1]
	if len(after) <= len(before) || endedCount(after) != 0 || last.Guest != "g1" || last.Billable != nil ||
		last.StartedAt != before[0].StartedAt || last.Seconds <= first.Seconds {
		t.Fatalf("readings of %s after the restart: %+v, want the same run going on (g1's, billable, same start, more seconds than %d, none ended)", run, after, first.Seconds)
	}
	for i := 1; i < len(after); i++ {
		if after[i].Seconds < after[i-1].Seconds {
			t.Fatalf("run seconds went back: %+v", after)
		}
	}
}

// Work order: a mapped room is never the pool's after a restart: no receipts
// read, not in the pool's counts or bound, not quarantined, no alarm.
func TestMappedRoomNeverAdoptedAsPool(t *testing.T) {
	pc, _ := newMappedChain(t, 1)
	mappedRestart(t, pc, time.Now().Add(-time.Minute), false)
	f := pc.hotels["a"]
	reads := len(f.callsOf("GET", "/v1/sandboxes/sbx-1/receipts"))
	pc.up("a")
	for i := 0; i < 4; i++ {
		pc.sync("a")
		pc.step("a")
	}
	pc.b.mu.Lock()
	ph := pc.b.pool.hotel("a")
	pr, alarm := ph.rooms["sbx-1"], ph.alarm
	pc.b.mu.Unlock()
	if n := len(f.callsOf("GET", "/v1/sandboxes/sbx-1/receipts")) - reads; n != 0 || pr != nil || alarm != "" {
		t.Fatalf("after the restart: %d receipts reads of the mapped room, pool record %+v, alarm %q; want none", n, pr, alarm)
	}
	if c := pc.counts("a"); c.quarantined != 0 || c.unverified != 0 {
		t.Fatalf("pool counts %+v, want the mapped room in none", c)
	}
}

// Decision 1: on an incomplete journal a claimed room is not the customer's
// any more: not found on GET, exec and list; its run ended by the meter as
// an absent room; nothing of its later time charged.
func TestIncompleteJournalLeavesClaimedRoomUnreachableAndEnded(t *testing.T) {
	pc, _ := newMappedChain(t, 1)
	run, before := mappedRestart(t, pc, time.Now().Add(-time.Minute), true)
	if pc.b.pool.journalState != "incomplete" {
		t.Fatalf("journal %s, want incomplete", pc.b.pool.journalState)
	}
	if len(before) == 0 {
		t.Fatalf("no reading of the customer's run %s before the restart", run)
	}
	pc.up("a")
	for i := 0; i < 3; i++ {
		pc.sync("a")
		pc.step("a")
	}
	for _, c := range []struct {
		method, path string
		compat       bool
	}{{"GET", "/v1/sandboxes/a.sbx-1", false}, {"POST", "/v1/sandboxes/a.sbx-1/exec", false}, {"GET", "/v1/sandboxes/" + run, true}} {
		if st, doc := pc.as("key1", c.method, c.path, c.compat); st != 404 && !(c.compat && st == 200 && doc["state"] == "deleted") {
			t.Fatalf("%s %s (compat %v) on an incomplete journal: %d %v, want not found", c.method, c.path, c.compat, st, doc)
		}
	}
	if _, doc := pc.as("key1", "GET", "/v1/sandboxes", false); listIDs(doc)["a.sbx-1"] != nil {
		t.Fatalf("g1 lists the set-aside room: %v", doc)
	}
	rs := pc.readingsOfRun(run)
	last := before[len(before)-1]
	if endedCount(rs) != 1 || rs[len(rs)-1].State != "ended" || rs[len(rs)-1].Seconds > last.Seconds {
		t.Fatalf("customer's run after the restart: %+v, want ended once with no seconds past %d", rs, last.Seconds)
	}
	for _, r := range pc.readingsOfRun("a.sbx-1") {
		if r.At > last.At && (r.Guest != poolGuestID || !notBillable(r)) {
			t.Fatalf("a reading of the room after the restart is not the pool's, not billable: %+v", r)
		}
	}
	if n := len(pc.hotels["a"].roomDeletes()); n != 0 {
		t.Fatalf("%d deletes of the set-aside room, want none", n)
	}
}

// Rule 1 of the late open tells a claim run from a physical run by the shape
// of its id. This pins both shapes: an attempt id as the claim path makes it
// (newUUID) and a broker room id taken from a real sync's room map. If either
// shape changes, this test fails first.
func TestUsageClaimRunShapes(t *testing.T) {
	for i := 0; i < 100; i++ {
		if id := newUUID(); !usageClaimRun(id) {
			t.Fatalf("attempt id %q is not a claim run", id)
		}
	}
	pc, _ := newMappedChain(t, 1)
	pc.b.mu.Lock()
	var ids []string
	for _, rm := range pc.b.hotelByID("a").rooms {
		ids = append(ids, rm.id, rm.runID())
	}
	pc.b.mu.Unlock()
	if len(ids) == 0 {
		t.Fatal("no room in the room map")
	}
	for _, id := range ids {
		if usageClaimRun(id) {
			t.Fatalf("broker room id %q reads as a claim run", id)
		}
	}
	if usageClaimRun("") {
		t.Fatal("an empty id reads as a claim run")
	}
}

// writeRecord appends a record of kind with body to the running broker's
// claim journal.
func (pc *poolChain) writeRecord(kind string, body map[string]any) {
	pc.t.Helper()
	raw, _ := json.Marshal(body)
	if err := <-pc.b.pool.journal.append(claimRecord{Kind: kind, Body: raw}); err != nil {
		pc.t.Fatal(err)
	}
}

// The replay keeps a won's mapping only while no later cancel or removed
// names its run: those rooms stay the pool's after a restart.
func TestReplayDropsCancelledAndRemovedRuns(t *testing.T) {
	pc, _ := newMappedChain(t, 3)
	wonAt := time.Now().Add(-time.Minute)
	runs := map[string]string{}
	for _, hid := range []string{"sbx-1", "sbx-2", "sbx-3"} {
		runs[hid] = pc.mapRoom(hid, "g1", jobA, wonAt)
		pc.writeWon("g1", hid, runs[hid], jobA, wonAt)
	}
	pc.writeRecord("cancel", map[string]any{"run_id": runs["sbx-1"]})
	pc.writeRecord("removed", map[string]any{"run_id": runs["sbx-2"]})
	pc.sync("a")
	mustFlush(t, pc.b.usageMeter) // the runs' first readings on disk, as PR 6 requires before a claim's answer
	pc.start()
	pc.up("a")
	pc.sync("a")
	h := pc.b.hotelByID("a")
	pc.b.mu.Lock()
	got := map[string]string{}
	for _, hid := range []string{"sbx-1", "sbx-2", "sbx-3"} {
		if rm := h.rooms[hid]; rm != nil {
			got[hid] = rm.guest
		}
	}
	pc.b.mu.Unlock()
	if got["sbx-1"] != poolGuestID || got["sbx-2"] != poolGuestID || got["sbx-3"] != "g1" {
		t.Fatalf("guests after the restart %v; want sbx-1 (cancelled) and sbx-2 (removed) the pool's, sbx-3 g1's", got)
	}
}

// A run the usage meter has already ended is never mapped back at a restart:
// the meter would write nothing more for it, so the room stays set aside.
func TestEndedRunIsNotMappedAtRestart(t *testing.T) {
	pc, _ := newMappedChain(t, 1)
	wonAt := time.Now().Add(-time.Minute)
	run := pc.mapRoom("sbx-1", "g1", jobA, wonAt)
	pc.writeWon("g1", "sbx-1", run, jobA, wonAt)
	pc.sync("a")
	pc.b.usageMeter.end(run, time.Now(), false) // as a delete answered 204 while the hotel kept the room
	before := pc.readingsOfRun(run)
	pc.start()
	pc.up("a")
	for i := 0; i < 3; i++ {
		pc.sync("a")
	}
	pc.b.mu.Lock()
	rm := pc.b.hotelByID("a").rooms["sbx-1"]
	guest := ""
	if rm != nil {
		guest = rm.guest
	}
	pc.b.mu.Unlock()
	if guest != poolGuestID {
		t.Fatalf("room of an ended run after the restart: guest %q, want the pool's (set aside)", guest)
	}
	if st, _ := pc.as("key1", "GET", "/v1/sandboxes/a.sbx-1", false); st != 404 {
		t.Fatalf("g1 GET of the set-aside room: %d, want 404", st)
	}
	if after := pc.readingsOfRun(run); len(after) != len(before) || endedCount(after) != 1 {
		t.Fatalf("readings of the ended run: before %d, after %d (%+v); want no new reading, ended once", len(before), len(after), after)
	}
}
