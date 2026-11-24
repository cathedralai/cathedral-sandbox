package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// AB#683 fresh slot destroy: the broker answers "destroyed" only after the
// slot's host confirmed the launch stopped, replays that answer byte for
// byte, and refuses (409) anything but the live original.

var (
	escReport1   = strings.Repeat("1", 64)
	escReport2   = strings.Repeat("2", 64)
	escBinding1  = strings.Repeat("b", 64)
	escBinding2  = strings.Repeat("c", 64)
	escMeasure   = strings.Repeat("ab", 48)
	escAttempt   = strings.Repeat("a", 32)
	escRequest   = strings.Repeat("e", 64)
	escDestroySH = strings.Repeat("d", 64)
)

// escapeSlot makes hotel a a one-room fresh slot with launch 1 admitted.
func escapeSlot(t *testing.T, tc *testChain) *hotel {
	t.Helper()
	h := tc.b.hotelByID("a")
	h.cfg.Labels = map[string]string{"sealed": "true", "escape": "true"}
	h.cfg.MaxSlots = 1
	tc.b.escDestroyWait = 150 * time.Millisecond
	admitLaunch(t, tc, h, escReport1, escBinding1)
	return h
}

// admitLaunch applies a passing attestation of one launch to h.
func admitLaunch(t *testing.T, tc *testChain, h *hotel, report, binding string) error {
	t.Helper()
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	res := admission{reportID: report, bindingSHA: binding, measurement: escMeasure, amd: map[string]any{"product": "Genoa"}, amdBinding: binding}
	return tc.b.noteAttestation(h, res, nil, time.Now())
}

func escFence() map[string]string {
	return map[string]string{
		"schema": escapeDestroyRequestSchema, "destroy_request_sha256": escDestroySH, "attempt_id": escAttempt,
		"report_id": escReport1, "binding_sha256": escBinding1, "measurement": escMeasure, "request_sha256": escRequest,
	}
}

func escCall(t *testing.T, tc *testChain, key, method, path string, body any) (int, []byte) {
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
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func destroy(t *testing.T, tc *testChain, fence map[string]string) (int, []byte) {
	t.Helper()
	return escCall(t, tc, "operator-key", "POST", "/v1/broker/hotels/a/escape-destroy", fence)
}

func hostConfirm(t *testing.T, tc *testChain, report, binding string) int {
	t.Helper()
	status, _ := escCall(t, tc, "hotel-key", "POST", "/v1/broker/hotels/a/escape-retire", map[string]string{
		"schema": escapeRetireConfirmSchema, "slot": "a", "report_id": report, "binding_sha256": binding, "state": "stopped",
	})
	return status
}

func hostPending(t *testing.T, tc *testChain) []any {
	t.Helper()
	status, raw := escCall(t, tc, "hotel-key", "GET", "/v1/broker/hotels/a/escape-retire", nil)
	var doc map[string]any
	if status != 200 || json.Unmarshal(raw, &doc) != nil || doc["schema"] != escapeRetireRequestSchema || doc["slot"] != "a" {
		t.Fatalf("retire list: %d %s", status, raw)
	}
	list, _ := doc["retire"].([]any)
	return list
}

func wantDestroyed(t *testing.T, raw []byte) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("result: %s", raw)
	}
	// fresh_destroy.py accepts only the fence, result schema, slot and state.
	want := map[string]any{}
	for k, v := range escFence() {
		want[k] = v
	}
	want["schema"], want["slot"], want["state"] = escapeDestroyResultSchema, "a", "destroyed"
	if len(got) != len(want) {
		t.Fatalf("result keys: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("result %s = %v, want %v", k, got[k], v)
		}
	}
}

func escAdmitted(tc *testChain, h *hotel) bool {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	return tc.b.admitted(h, time.Now())
}

func TestEscapeDestroyAnswersDestroyedOnlyAfterTheHostStopsTheLaunch(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	h := escapeSlot(t, tc)
	if !escAdmitted(tc, h) {
		t.Fatal("slot not admitted before the destroy")
	}
	tc.b.escDestroyWait = 5 * time.Second
	type answer struct {
		status int
		raw    []byte
	}
	done := make(chan answer, 1)
	go func() {
		s, raw := destroy(t, tc, escFence())
		done <- answer{s, raw}
	}()
	// The host sees the retire only once the broker recorded it.
	deadline := time.Now().Add(3 * time.Second)
	for len(hostPending(t, tc)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("retire never offered to the host")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if escAdmitted(tc, h) {
		t.Fatal("a retired launch is still admitted: a create could land on it")
	}
	select {
	case a := <-done:
		t.Fatalf("answered before the host confirmed: %d %s", a.status, a.raw)
	default:
	}
	if s := hostConfirm(t, tc, escReport1, escBinding1); s != 200 {
		t.Fatalf("confirm: %d", s)
	}
	a := <-done
	if a.status != 200 {
		t.Fatalf("destroy: %d %s", a.status, a.raw)
	}
	wantDestroyed(t, a.raw)
	if n := len(hostPending(t, tc)); n != 0 {
		t.Fatalf("still pending for the host: %d", n)
	}
	// The relaunch attests on a new REPORT_ID and serves the slot again.
	if err := admitLaunch(t, tc, h, escReport2, escBinding2); err != nil || !escAdmitted(tc, h) {
		t.Fatalf("relaunch not admitted: %v", err)
	}
}

func TestEscapeDestroyReplaysTheRecordedResultByteForByte(t *testing.T) {
	state := t.TempDir()
	tc := newChainState(t, state)
	h := escapeSlot(t, tc)
	if s, raw := destroy(t, tc, escFence()); s != 503 || !strings.Contains(string(raw), "escape_destroy_pending") {
		t.Fatalf("first: %d %s", s, raw)
	}
	if s := hostConfirm(t, tc, escReport1, escBinding1); s != 200 {
		t.Fatalf("confirm: %d", s)
	}
	s1, first := destroy(t, tc, escFence())
	s2, second := destroy(t, tc, escFence())
	if s1 != 200 || s2 != 200 || !bytes.Equal(first, second) {
		t.Fatalf("replay: %d %s / %d %s", s1, first, s2, second)
	}
	wantDestroyed(t, first)
	// A second confirm of the same stop is harmless.
	if s := hostConfirm(t, tc, escReport1, escBinding1); s != 200 {
		t.Fatalf("repeat confirm: %d", s)
	}
	// After a broker restart: same bytes, and the launch stays retired.
	tc.start(t)
	h = tc.b.hotelByID("a")
	h.cfg.Labels, h.cfg.MaxSlots = map[string]string{"sealed": "true", "escape": "true"}, 1
	s3, third := destroy(t, tc, escFence())
	if s3 != 200 || !bytes.Equal(first, third) {
		t.Fatalf("replay after restart: %d %s", s3, third)
	}
	if err := admitLaunch(t, tc, h, escReport1, escBinding1); err != errEscapeLaunchRetired {
		t.Fatalf("retired launch passed again after a restart: %v", err)
	}
}

func TestEscapeDestroyRefusesAnythingButTheLiveOriginal(t *testing.T) {
	with := func(k, v string) map[string]string {
		f := escFence()
		f[k] = v
		return f
	}
	cases := map[string]struct {
		setup func(t *testing.T, tc *testChain, h *hotel)
		fence map[string]string
		code  string
	}{
		"unknown launch":    {fence: with("report_id", strings.Repeat("3", 64)), code: "escape_destroy_unknown_launch"},
		"other binding":     {fence: with("binding_sha256", escBinding2), code: "escape_destroy_fence_mismatch"},
		"other measurement": {fence: with("measurement", strings.Repeat("cd", 48)), code: "escape_destroy_fence_mismatch"},
		"not a one-room slot": {
			setup: func(t *testing.T, tc *testChain, h *hotel) { h.cfg.MaxSlots = 0 },
			fence: escFence(), code: "escape_slot_required",
		},
		"not an escape hotel": {
			setup: func(t *testing.T, tc *testChain, h *hotel) { h.cfg.Labels = map[string]string{"sealed": "true"} },
			fence: escFence(), code: "escape_slot_required",
		},
		"same digest, other fence": {
			setup: func(t *testing.T, tc *testChain, h *hotel) {
				if s, _ := destroy(t, tc, escFence()); s != 503 {
					t.Fatalf("setup destroy: %d", s)
				}
			},
			fence: with("request_sha256", strings.Repeat("f", 64)), code: "escape_destroy_mismatch",
		},
		"second request for the launch": {
			setup: func(t *testing.T, tc *testChain, h *hotel) {
				if s, _ := destroy(t, tc, escFence()); s != 503 {
					t.Fatalf("setup destroy: %d", s)
				}
			},
			fence: with("destroy_request_sha256", strings.Repeat("9", 64)), code: "escape_destroy_conflict",
		},
		"attempt not the one sent to the launch": {
			setup: func(t *testing.T, tc *testChain, h *hotel) {
				other := `{"schema":"x","attempt_id":"` + strings.Repeat("7", 32) + `","report_id":"` + escReport1 + `","request_sha256":"` + escRequest + `"}`
				rec := &freshRecord{freshRaw: other, done: make(chan struct{})}
				tc.b.freshReplays.recs = map[string]*freshRecord{"report:" + escReport1: rec, "attempt:" + strings.Repeat("7", 32): rec}
			},
			fence: escFence(), code: "escape_destroy_attempt_mismatch",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			tc := newChainState(t, t.TempDir())
			h := escapeSlot(t, tc)
			if c.setup != nil {
				c.setup(t, tc, h)
			}
			status, raw := destroy(t, tc, c.fence)
			var doc map[string]any
			_ = json.Unmarshal(raw, &doc)
			if status != 409 || errCode(doc) != c.code {
				t.Fatalf("destroy: %d %s, want 409 %s", status, raw, c.code)
			}
		})
	}
}

func TestEscapeDestroyRefusesAMalformedFenceAndOtherKeys(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	escapeSlot(t, tc)
	bad := map[string]func(map[string]string){
		"extra field":    func(f map[string]string) { f["slot"] = "a" },
		"missing field":  func(f map[string]string) { delete(f, "request_sha256") },
		"wrong schema":   func(f map[string]string) { f["schema"] = escapeDestroyResultSchema },
		"upper hex":      func(f map[string]string) { f["binding_sha256"] = strings.ToUpper(escBinding1) },
		"zero binding":   func(f map[string]string) { f["binding_sha256"] = strings.Repeat("0", 64) },
		"short attempt":  func(f map[string]string) { f["attempt_id"] = "a1" },
		"short measured": func(f map[string]string) { f["measurement"] = strings.Repeat("ab", 47) },
	}
	for name, mutate := range bad {
		f := escFence()
		mutate(f)
		if status, raw := destroy(t, tc, f); status != 400 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
	for _, key := range []string{"hotel-key", "enroller-key", "reader-key", "key1"} {
		status, _ := escCall(t, tc, key, "POST", "/v1/broker/hotels/a/escape-destroy", escFence())
		if status != 401 && status != 403 {
			t.Fatalf("key %s: %d", key, status)
		}
	}
	if n := len(hostPending(t, tc)); n != 0 {
		t.Fatalf("a refused request retired the launch: %d pending", n)
	}
}

func TestEscapeDestroyHostTimeoutIsNotDestroyed(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	h := escapeSlot(t, tc)
	for i := 0; i < 3; i++ {
		start := time.Now()
		status, raw := destroy(t, tc, escFence())
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		if status != 503 || errCode(doc) != "escape_destroy_pending" || doc["state"] != nil {
			t.Fatalf("try %d: %d %s", i, status, raw)
		}
		if waited := time.Since(start); waited < tc.b.escDestroyWait {
			t.Fatalf("answered after %v without waiting for the host", waited)
		}
	}
	// Retired durably even though never destroyed: not admitted, and the
	// same REPORT_ID cannot pass the gate again.
	if escAdmitted(tc, h) {
		t.Fatal("retired launch still admitted")
	}
	if err := admitLaunch(t, tc, h, escReport1, escBinding1); err != errEscapeLaunchRetired {
		t.Fatalf("retired launch re-admitted: %v", err)
	}
	if list := hostPending(t, tc); len(list) != 1 {
		t.Fatalf("pending: %v", list)
	}
}

func TestEscapeRetireChannelTakesOnlyTheSlotsHotelKey(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	escapeSlot(t, tc)
	for _, key := range []string{"operator-key", "enroller-key", "key1", "wrong"} {
		if status, _ := escCall(t, tc, key, "GET", "/v1/broker/hotels/a/escape-retire", nil); status != 401 {
			t.Fatalf("GET with %s: %d", key, status)
		}
	}
	if status, _ := escCall(t, tc, "hotel-key", "GET", "/v1/broker/hotels/nope/escape-retire", nil); status != 401 {
		t.Fatalf("unknown hotel: %d", status)
	}
	// A stop nobody asked for is refused, so a host cannot pre-confirm a launch.
	if s := hostConfirm(t, tc, escReport1, escBinding1); s != 409 {
		t.Fatalf("unrequested confirm: %d", s)
	}
	if s, _ := destroy(t, tc, escFence()); s != 503 {
		t.Fatalf("destroy: %d", s)
	}
	if s := hostConfirm(t, tc, escReport1, escBinding2); s != 409 {
		t.Fatalf("confirm with another binding: %d", s)
	}
	status, _ := escCall(t, tc, "hotel-key", "POST", "/v1/broker/hotels/a/escape-retire", map[string]string{
		"schema": escapeRetireConfirmSchema, "slot": "b", "report_id": escReport1, "binding_sha256": escBinding1, "state": "stopped",
	})
	if status != 400 {
		t.Fatalf("confirm naming another slot: %d", status)
	}
}

func TestEscapeDestroyNeedsAStateDir(t *testing.T) {
	tc := newChain(t) // no state_dir: nothing can be recorded durably
	escapeSlot(t, tc)
	status, raw := destroy(t, tc, escFence())
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	if status != 503 || errCode(doc) != "escape_destroy_unsaved" {
		t.Fatalf("destroy: %d %s", status, raw)
	}
	if n := len(hostPending(t, tc)); n != 0 {
		t.Fatalf("unsaved destroy still retired the launch: %d", n)
	}
}
