package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
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

// snapshotCall is a snapshot, a snapshot delete or a snapshot push.
func snapshotCall(r *http.Request) bool {
	return (r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/snapshot")) ||
		strings.HasPrefix(r.URL.Path, "/v1/snapshots/")
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
	m.match, m.extra = snapshotCall, machineRoomHeaders(long)
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
	m.match, m.extra = snapshotCall, machineRoomHeaders(long)
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
	// A delete the machine itself refuses (the lookup found the snapshot, the
	// forwarded call answers 404) also carries no header from nowhere.
	m := tapMachine(t, tc, "b")
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/snapshots/") {
			writeErr(w, 404, "snapshot_not_found", "gone")
			return true
		}
		return false
	}
	_, snapID := snapOn(t, tc)
	resp, body = rawCallResp(t, tc, "key1", "DELETE", "/v1/snapshots/"+snapID, nil)
	if resp.StatusCode != 404 || len(roomHeaders(resp.Header)) != 0 || m.count("DELETE", "/v1/snapshots/"+strings.TrimPrefix(snapID, "b.")) != 1 {
		t.Fatalf("machine 404 on delete: %d %s %v", resp.StatusCode, body, resp.Header)
	}
}

func TestSnapshotPushThroughBrokerPassesRoomHeadersByteForByte(t *testing.T) {
	tc := newChain(t)
	_, snapID := snapOn(t, tc)
	m := tapMachine(t, tc, "b")
	long := longB64()
	m.match, m.extra = snapshotCall, machineRoomHeaders(long)
	resp, body := rawCallResp(t, tc, "key1", "POST", "/v1/snapshots/"+snapID+"/push", []byte(`{"image":"ghcr.io/acme/forks:one"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("push: %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Room-Receipt"); got != long {
		t.Fatalf("receipt changed: len %d want %d", len(got), len(long))
	}
	assertRoomHeaders(t, resp, m.extra)
}

// A signed failure must reach the caller: the header rides on a machine 4xx
// and 5xx, with a JSON body and with a body the broker cannot parse. The
// existing room route does the same (main.go copies before it writes the
// status, whatever the status is).
func TestSnapshotFailuresFromTheMachineKeepTheirRoomHeaders(t *testing.T) {
	tc := newChain(t)
	room, snapID := snapOn(t, tc)
	m := tapMachine(t, tc, "b")
	long := longB64()
	fail := 404
	junk := false
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if !snapshotCall(r) {
			return false
		}
		w.Header().Set("X-Room-Receipt", long)
		w.Header().Set("X-Broker-Hotel", "spoofed")
		if junk {
			w.WriteHeader(fail)
			_, _ = w.Write([]byte("<html>no</html>"))
			return true
		}
		writeErr(w, fail, "machine_says_no", "no")
		return true
	}
	for _, c := range []struct {
		status int
		junk   bool
	}{{404, false}, {409, false}, {500, false}, {503, true}} {
		fail, junk = c.status, c.junk
		for name, call := range map[string]func() (*http.Response, []byte){
			"snapshot": func() (*http.Response, []byte) {
				return rawCallResp(t, tc, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", []byte(`{}`))
			},
			"delete": func() (*http.Response, []byte) {
				return rawCallResp(t, tc, "key1", "DELETE", "/v1/snapshots/"+snapID, nil)
			},
			"push": func() (*http.Response, []byte) {
				return rawCallResp(t, tc, "key1", "POST", "/v1/snapshots/"+snapID+"/push", []byte(`{"image":"x/y:1"}`))
			},
		} {
			resp, body := call()
			if resp.StatusCode != c.status || resp.Header.Get("X-Room-Receipt") != long || resp.Header.Get("X-Broker-Hotel") != "" {
				t.Fatalf("%s %d junk=%v: status %d receipt len %d broker-hotel %q body %s", name, c.status, c.junk, resp.StatusCode, len(resp.Header.Get("X-Room-Receipt")), resp.Header.Get("X-Broker-Hotel"), body)
			}
		}
	}
	// Reference: the existing room route behaves the same.
	m.override = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "GET" && r.URL.Path == "/v1/sandboxes/"+strings.TrimPrefix(room, "b.") {
			w.Header().Set("X-Room-Receipt", long)
			writeErr(w, 500, "machine_says_no", "no")
			return true
		}
		return false
	}
	resp, _ := rawCallResp(t, tc, "key1", "GET", "/v1/sandboxes/"+room, nil)
	if resp.StatusCode != 500 || resp.Header.Get("X-Room-Receipt") != long {
		t.Fatalf("existing room route on a 5xx: %d receipt len %d", resp.StatusCode, len(resp.Header.Get("X-Room-Receipt")))
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
