package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// AB#604, CS-5: snapshot receipts travel through the broker, and the fork's
// "cannot be placed" answer is split in two.

// machineTap stands in front of one fake hotel. It counts every call and can
// decorate or replace answers. A nil handler for a call means: ask the fake.
type machineTap struct {
	mu    sync.Mutex
	calls []string
	// extra is added (Header.Add, so duplicates stay) to the answer of a call
	// that match accepts.
	match func(r *http.Request) bool
	extra http.Header
	// override answers the call itself when it returns true.
	override func(w http.ResponseWriter, r *http.Request) bool
}

func (m *machineTap) count(method, path string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if c == method+" "+path {
			n++
		}
	}
	return n
}

// tapMachine points the broker's hotel id at a tap in front of the fake.
func tapMachine(t *testing.T, tc *testChain, id string) *machineTap {
	t.Helper()
	m := &machineTap{}
	f := tc.hotels[id]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.calls = append(m.calls, r.Method+" "+r.URL.Path)
		override, match, extra := m.override, m.match, m.extra
		m.mu.Unlock()
		if override != nil && override(w, r) {
			return
		}
		rec := httptest.NewRecorder()
		f.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		if match != nil && match(r) {
			for k, vs := range extra {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	t.Cleanup(srv.Close)
	h := tc.b.hotelByID(id)
	tc.b.mu.Lock()
	h.cfg.API = srv.URL
	tc.b.mu.Unlock()
	return m
}

func rawCallResp(t *testing.T, tc *testChain, key, method, path string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, tc.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func roomHeaders(h http.Header) http.Header {
	out := http.Header{}
	for k, v := range h {
		if strings.HasPrefix(k, "X-Room-") {
			out[k] = v
		}
	}
	return out
}

// longB64 is a base64 value like a signed receipt: long, with '=' and '+/'.
func longB64() string {
	raw := make([]byte, 24*1024)
	for i := range raw {
		raw[i] = byte(i*7 + 3)
	}
	return base64.StdEncoding.EncodeToString(raw) + "=="
}

// snapOn makes a room and a snapshot of it on hotel b, through the broker,
// before any tap is set. It returns the room id and the snapshot id.
func snapOn(t *testing.T, tc *testChain) (string, string) {
	t.Helper()
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	_, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", map[string]any{"name": "keep"})
	return room, doc["result"].(map[string]any)["snapshot_id"].(string)
}

func snapshotPostOrDelete(r *http.Request) bool {
	return (r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/snapshot")) ||
		(r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/snapshots/"))
}

func machineRoomHeaders(long string) http.Header {
	h := http.Header{}
	h.Add("X-Room-Receipt", long)
	h.Add("X-Room-Receipt-Seq", "42")
	h.Add("X-Room-Receipt-Error", "none")
	// Outside the pass-through rule: must not reach the caller.
	h.Add("X-Broker-Hotel", "spoofed")
	h.Add("X-Roomy", "no-dash-after-room")
	h.Add("X-Internal-Secret", "do-not-forward")
	h.Add("Set-Cookie", "a=b")
	return h
}

func assertRoomHeaders(t *testing.T, resp *http.Response, want http.Header) {
	t.Helper()
	for k, v := range want {
		if strings.HasPrefix(k, "X-Room-") && !reflect.DeepEqual(resp.Header[k], v) {
			t.Fatalf("%s: got %q want %q", k, resp.Header[k], v)
		}
	}
	for _, k := range []string{"X-Broker-Hotel", "X-Roomy", "X-Internal-Secret", "Set-Cookie"} {
		if v := resp.Header.Values(k); len(v) != 0 {
			t.Fatalf("header %s outside the rule reached the caller: %q", k, v)
		}
	}
}

func TestSnapshotThroughBrokerPassesRoomHeadersByteForByte(t *testing.T) {
	tc := newChain(t)
	room, _ := snapOn(t, tc)
	m := tapMachine(t, tc, "b")
	long := longB64()
	m.match, m.extra = snapshotPostOrDelete, machineRoomHeaders(long)
	resp, body := rawCallResp(t, tc, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", []byte(`{"name":"two"}`))
	if resp.StatusCode != 202 || !strings.Contains(string(body), `"snapshot_id":"b.snap_`) {
		t.Fatalf("snapshot: %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Room-Receipt"); got != long {
		t.Fatalf("receipt changed: len %d want %d", len(got), len(long))
	}
	assertRoomHeaders(t, resp, m.extra)
}

func TestSnapshotDeleteThroughBrokerPassesRoomHeadersByteForByte(t *testing.T) {
	tc := newChain(t)
	_, snapID := snapOn(t, tc)
	m := tapMachine(t, tc, "b")
	long := longB64()
	m.match, m.extra = snapshotPostOrDelete, machineRoomHeaders(long)
	resp, body := rawCallResp(t, tc, "key1", "DELETE", "/v1/snapshots/"+snapID, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("delete: %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Room-Receipt"); got != long {
		t.Fatalf("receipt changed: len %d want %d", len(got), len(long))
	}
	assertRoomHeaders(t, resp, m.extra)
}

func TestSnapshotFromMachineWithoutRoomHeadersIsUnchanged(t *testing.T) {
	tc := newChain(t)
	room, _ := snapOn(t, tc)
	tapMachine(t, tc, "b") // a tap that adds nothing
	resp, body := rawCallResp(t, tc, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", []byte(`{"name":"old"}`))
	if resp.StatusCode != 202 || !strings.Contains(string(body), `"status":"done"`) {
		t.Fatalf("snapshot: %d %s", resp.StatusCode, body)
	}
	if rh := roomHeaders(resp.Header); len(rh) != 0 {
		t.Fatalf("headers appeared from nowhere: %v", rh)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	resp, body = rawCallResp(t, tc, "key1", "DELETE", "/v1/snapshots/b.snap_zzz", nil)
	if resp.StatusCode != 404 || len(roomHeaders(resp.Header)) != 0 {
		t.Fatalf("delete of an unknown snapshot: %d %s %v", resp.StatusCode, body, resp.Header)
	}
}

// The existing rule is copyRoomHeaders (main.go): every header whose
// canonical name starts "X-Room-", all its values in order, no length limit
// in the broker. The new handlers must behave as the existing room route does.
func TestSnapshotHandlersFollowTheExistingHeaderRuleForDuplicatesAndLongValues(t *testing.T) {
	tc := newChain(t)
	room, snapID := snapOn(t, tc)
	m := tapMachine(t, tc, "b")
	huge := strings.Repeat("A", 256*1024)
	extra := http.Header{}
	extra.Add("X-Room-Dup", "one")
	extra.Add("X-Room-Dup", "two")
	extra.Add("X-Room-Huge", huge)
	m.match = func(r *http.Request) bool { return true }
	m.extra = extra

	// The existing route is the reference.
	ref, _ := rawCallResp(t, tc, "key1", "GET", "/v1/sandboxes/"+room, nil)
	want := roomHeaders(ref.Header)
	if !reflect.DeepEqual(want["X-Room-Dup"], []string{"one", "two"}) || want.Get("X-Room-Huge") != huge {
		t.Fatalf("reference route does not show the rule: dup %q huge %d", want["X-Room-Dup"], len(want.Get("X-Room-Huge")))
	}
	for name, call := range map[string]func() *http.Response{
		"snapshot": func() *http.Response {
			r, _ := rawCallResp(t, tc, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", []byte(`{}`))
			return r
		},
		"delete": func() *http.Response {
			r, _ := rawCallResp(t, tc, "key1", "DELETE", "/v1/snapshots/"+snapID, nil)
			return r
		},
	} {
		got := roomHeaders(call().Header)
		if !reflect.DeepEqual(got["X-Room-Dup"], want["X-Room-Dup"]) || got.Get("X-Room-Huge") != huge {
			t.Fatalf("%s: dup %q huge %d, existing route gives dup %q huge %d", name,
				got["X-Room-Dup"], len(got.Get("X-Room-Huge")), want["X-Room-Dup"], len(want.Get("X-Room-Huge")))
		}
	}
}

// ---------------------------------------------------------------- fork

func forkCall(t *testing.T, tc *testChain, snapID string) (*http.Response, map[string]any) {
	t.Helper()
	resp, body := rawCallResp(t, tc, "key1", "POST", "/v1/sandboxes", []byte(`{"snapshot_id":"`+snapID+`"}`))
	return resp, decodeDoc(body)
}

func decodeDoc(body []byte) map[string]any {
	var doc map[string]any
	_ = json.Unmarshal(body, &doc)
	return doc
}

func TestForkMachine429PassesThroughAndLaterForkIsSoldOutWhileResting(t *testing.T) {
	tc := newChain(t)
	_, snapID := snapOn(t, tc)
	m := tapMachine(t, tc, "b")
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			w.Header().Set("Retry-After", "3")
			writeErr(w, 429, "no_free_rooms", "machine full")
			return true
		}
		return false
	}
	// As main: the machine's own 429, body and Retry-After.
	resp, doc := forkCall(t, tc, snapID)
	if resp.StatusCode != 429 || errCode(doc) != "no_free_rooms" || resp.Header.Get("Retry-After") != "3" {
		t.Fatalf("fork to a full machine: %d %q %v", resp.StatusCode, resp.Header.Get("Retry-After"), doc)
	}
	// The machine now rests after saying it is full: the broker's own 503 says sold out.
	resp, doc = forkCall(t, tc, snapID)
	if resp.StatusCode != 503 || errCode(doc) != "snapshot_hotel_sold_out" {
		t.Fatalf("fork while the machine rests after a 429: %d %v", resp.StatusCode, doc)
	}
	if n := m.count("POST", "/v1/sandboxes"); n != 1 {
		t.Fatalf("machine got %d creates, want 1", n)
	}
	// The rest ends: a machine now held as down is unreachable, not sold out.
	tc.b.mu.Lock()
	h := tc.b.hotelByID("b")
	h.backoffUntil, h.ok = time.Now().Add(-time.Second), false
	tc.b.mu.Unlock()
	resp, doc = forkCall(t, tc, snapID)
	if resp.StatusCode != 503 || errCode(doc) != "snapshot_hotel_unreachable" {
		t.Fatalf("after the rest, machine down: %d %v", resp.StatusCode, doc)
	}
}

func TestForkMachineRestingAfterAFailureIsNotSoldOutAndTheFlagClears(t *testing.T) {
	tc := newChain(t)
	_, snapID := snapOn(t, tc)
	// A 429 sets the flag; a later failed call replaces the rest and clears it.
	tc.b.mu.Lock()
	h := tc.b.hotelByID("b")
	h.backoffUntil, h.restFull = time.Now().Add(time.Minute), true
	tc.b.mu.Unlock()
	m := tapMachine(t, tc, "b")
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			w.WriteHeader(500)
			return true
		}
		return false
	}
	tc.b.mu.Lock()
	h.backoffUntil = time.Time{} // let the create through to fail
	tc.b.mu.Unlock()
	if resp, _ := forkCall(t, tc, snapID); resp.StatusCode != 500 {
		t.Fatalf("failing create: %d", resp.StatusCode)
	}
	resp, doc := forkCall(t, tc, snapID) // resting after a failure
	if resp.StatusCode != 503 || errCode(doc) != "snapshot_hotel_unreachable" {
		t.Fatalf("resting after a failure: %d %v", resp.StatusCode, doc)
	}
}

func TestForkBrokerCountsNoFreeRoomIsHotelSoldOut(t *testing.T) {
	tc := newChain(t)
	_, snapID := snapOn(t, tc)
	m := tapMachine(t, tc, "b")
	tc.b.mu.Lock()
	h := tc.b.hotelByID("b")
	h.slots = h.used() // every slot taken
	tc.b.mu.Unlock()
	resp, doc := forkCall(t, tc, snapID)
	if resp.StatusCode != 503 || errCode(doc) != "snapshot_hotel_sold_out" {
		t.Fatalf("fork to a machine with no free slot: %d %v", resp.StatusCode, doc)
	}
	if n := m.count("POST", "/v1/sandboxes"); n != 0 {
		t.Fatalf("machine was called %d times", n)
	}
}

func TestForkDrainingMachineIsSoldOutAndDownMachineIsUnreachable(t *testing.T) {
	tc := newChain(t)
	_, snapID := snapOn(t, tc)
	tc.b.mu.Lock()
	tc.b.hotelByID("b").cfg.Drain = true
	tc.b.mu.Unlock()
	resp, doc := forkCall(t, tc, snapID)
	if resp.StatusCode != 503 || errCode(doc) != "snapshot_hotel_sold_out" {
		t.Fatalf("draining: %d %v", resp.StatusCode, doc)
	}
	tc.b.mu.Lock()
	h := tc.b.hotelByID("b")
	h.cfg.Drain, h.ok = false, false
	tc.b.mu.Unlock()
	resp, doc = forkCall(t, tc, snapID)
	if resp.StatusCode != 503 || errCode(doc) != "snapshot_hotel_unreachable" {
		t.Fatalf("down: %d %v", resp.StatusCode, doc)
	}
}

func TestForkMachineTimeoutStaysHotelUnreachable502(t *testing.T) {
	tc := newChain(t)
	_, snapID := snapOn(t, tc)
	m := tapMachine(t, tc, "b")
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			time.Sleep(800 * time.Millisecond)
			return true
		}
		return false
	}
	old := hotelCreateTimeout
	hotelCreateTimeout = 200 * time.Millisecond
	t.Cleanup(func() { hotelCreateTimeout = old })
	resp, doc := forkCall(t, tc, snapID)
	if resp.StatusCode != 502 || errCode(doc) != "hotel_unreachable" {
		t.Fatalf("timeout: %d %v", resp.StatusCode, doc)
	}
	if n := m.count("POST", "/v1/sandboxes"); n != 1 {
		t.Fatalf("machine got %d creates, want 1 (no retry)", n)
	}
}

func TestForkMachineRefusedConnectionStaysHotelUnreachable502(t *testing.T) {
	tc := newChain(t)
	_, snapID := snapOn(t, tc)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://" + ln.Addr().String()
	_ = ln.Close() // nothing listens: connection refused
	tc.b.mu.Lock()
	tc.b.hotelByID("b").cfg.API = dead
	tc.b.mu.Unlock()
	resp, doc := forkCall(t, tc, snapID)
	if resp.StatusCode != 502 || errCode(doc) != "hotel_unreachable" {
		t.Fatalf("refused: %d %v", resp.StatusCode, doc)
	}
}

func TestForkMachineJunk500PassesThroughRawAndIsNotRetried(t *testing.T) {
	tc := newChain(t)
	_, snapID := snapOn(t, tc)
	m := tapMachine(t, tc, "b")
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			w.WriteHeader(500)
			_, _ = w.Write([]byte("<html>boom</html>"))
			return true
		}
		return false
	}
	resp, body := rawCallResp(t, tc, "key1", "POST", "/v1/sandboxes", []byte(`{"snapshot_id":"`+snapID+`"}`))
	if resp.StatusCode != 500 || string(body) != "<html>boom</html>" {
		t.Fatalf("500 with junk: %d %q", resp.StatusCode, body)
	}
	if n := m.count("POST", "/v1/sandboxes"); n != 1 {
		t.Fatalf("machine got %d creates, want 1 (no retry)", n)
	}
}

func TestForkMachine5xxWithAnErrorBodyTheBrokerUnderstandsPassesThrough(t *testing.T) {
	tc := newChain(t)
	_, snapID := snapOn(t, tc)
	m := tapMachine(t, tc, "b")
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
			writeErr(w, 503, "hotel_busy", "try later")
			return true
		}
		return false
	}
	resp, doc := forkCall(t, tc, snapID)
	if resp.StatusCode != 503 || errCode(doc) != "hotel_busy" {
		t.Fatalf("understood 5xx: %d %v", resp.StatusCode, doc)
	}
}

func TestForkMachineOther4xxPassesThroughNotFoldedIntoEitherName(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
	}{{404, "snapshot_not_found"}, {409, "snapshot_deleting"}, {422, "snapshot_overlay_unsupported"}} {
		tc := newChain(t)
		_, snapID := snapOn(t, tc)
		m := tapMachine(t, tc, "b")
		m.override = func(w http.ResponseWriter, r *http.Request) bool {
			if r.Method == "POST" && r.URL.Path == "/v1/sandboxes" {
				writeErr(w, c.status, c.code, "gone")
				return true
			}
			return false
		}
		resp, doc := forkCall(t, tc, snapID)
		if resp.StatusCode != c.status || errCode(doc) != c.code {
			t.Fatalf("%d %s: got %d %v", c.status, c.code, resp.StatusCode, doc)
		}
		if n := m.count("POST", "/v1/sandboxes"); n != 1 {
			t.Fatalf("%d: machine got %d creates", c.status, n)
		}
	}
}
