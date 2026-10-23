package main

// Broker hardening from review round 5. Each test failed on 2734448.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rawCall is tc.call without t.Fatal, so it is safe from goroutines.
func rawCall(tc *testChain, key, ua, method, path string, body []byte) (int, []byte, error) {
	req, _ := http.NewRequest(method, tc.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, nil
}

// the compat file, tar and stat routes put the Go transport error, which
// carries the hotel's private API URL, into the guest's error message.
func TestCompatFileErrorHidesHotelURL(t *testing.T) {
	tc := newChain(t)
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	tc.b.mu.Lock()
	rm := tc.b.byBID(id)
	u, h := rm.uuid, rm.h
	tc.b.mu.Unlock()
	h.cfg.API = "http://127.0.0.1:9/private-hotel-path" // nothing listens: connection refused
	for _, c := range []struct{ method, path string }{
		{"PUT", "/v1/sandboxes/" + u + "/files?path=/tmp/x"},
		{"GET", "/v1/sandboxes/" + u + "/files?path=/tmp/x"},
		{"PUT", "/v1/sandboxes/" + u + "/tar?path=/tmp"},
		{"GET", "/v1/sandboxes/" + u + "/tar?path=/tmp"},
		{"GET", "/v1/sandboxes/" + u + "/stat?path=/tmp"},
	} {
		status, raw, err := rawCall(tc, "key1", "ctcli/1.0", c.method, c.path, []byte("hi"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "127.0.0.1:9") || strings.Contains(string(raw), "private-hotel-path") {
			t.Errorf("%s %s: hotel address in the guest error: %d %s", c.method, c.path, status, raw)
		}
	}
}

// list, quota and usage fan out to every hotel, including hotels outside
// the guest's hotel list. A hung foreign hotel stalls the guest's calls and
// its id appears in the answer.
func TestListQuotaUsageKeepToGuestHotels(t *testing.T) {
	tc := newChain(t)
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits = guestLimits{Hotels: []string{"b", "c"}}
	tc.b.mu.Unlock()
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(hang.Close)
	tc.b.hotelByID("a").cfg.API = hang.URL
	client := &http.Client{Timeout: 2 * time.Second}
	for _, p := range []string{"/v1/sandboxes", "/v1/quota", "/v1/usage"} {
		req, _ := http.NewRequest("GET", tc.srv.URL+p, nil)
		req.Header.Set("Authorization", "Bearer key1")
		t0 := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("GET %s waited %.1fs on hotel a, which g1 may not use: %v", p, time.Since(t0).Seconds(), err)
			continue
		}
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		resp.Body.Close()
		if he, _ := doc["hotel_errors"].(map[string]any); he["a"] != nil {
			t.Errorf("GET %s names hotel a: %v", p, doc)
		}
		if hs, _ := doc["hotels"].(map[string]any); hs["a"] != nil {
			t.Errorf("GET %s names hotel a: %v", p, doc)
		}
	}
}

// PATCH {"hotels": []} showed an empty list but meant every hotel, and
// {"max_rooms": 0} meant 1,000. Both widen a guest an operator meant to cut
// off, so both are refused and the guest keeps its limits.
func TestPatchGuestEmptyHotelListIsNotAllHotels(t *testing.T) {
	tc := newChain(t)
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits = guestLimits{Hotels: []string{"b"}, MaxRooms: 5}
	tc.b.mu.Unlock()
	for _, body := range []string{`{"hotels": []}`, `{"max_rooms": 0}`} {
		req, _ := http.NewRequest("PATCH", tc.srv.URL+"/v1/broker/guests/g1", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer operator-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("PATCH %s: want 400, got %d", body, resp.StatusCode)
		}
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}}); status != 409 {
		t.Fatalf("guest left its hotel list after a refused PATCH: %d %v", status, doc)
	}
}

// a short (truncated) build context file is trusted after a restart, and
// a resubmit of the same build keeps the short one.
func TestTruncatedBuildContextIsReplacedOnResubmit(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	full := []byte("full-context-bytes")
	body, ctype := buildForm(t, "FROM alpine:3.20\n", full)
	_, img := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	id := img["image_id"].(string)
	waitImage(t, tc, id)
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, contextsDir, id+".tar.gz"), full[:4], 0o600); err != nil {
		t.Fatal(err)
	}
	tc.start(t)
	_, again := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	if again["image_id"] != id {
		t.Fatalf("id changed: %v", again)
	}
	waitImage(t, tc, id)
	time.Sleep(200 * time.Millisecond)
	short := 0
	for hid, f := range tc.hotels {
		f.mu.Lock()
		for _, b := range f.builds {
			ctx, _ := base64.StdEncoding.DecodeString(fmt.Sprint(b["context_tar_b64"]))
			if !bytes.Equal(ctx, full) {
				short++
				t.Logf("hotel %s was asked to build with context %q", hid, ctx)
			}
		}
		f.mu.Unlock()
	}
	if short > 0 {
		t.Fatalf("%d build requests after the restart carried the truncated context", short)
	}
}

// The room route appended the tail to the hotel path as given. Dot segments
// must not reach the hotel: a normalizing proxy in front of it would turn
// /v1/sandboxes/<mine>/../.. into the hotel-wide list.
func TestRoomTailIsNotPassedWithDotSegments(t *testing.T) {
	tc := newChain(t)
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	f := tc.hotels[hotelOf(id)]
	f.mu.Lock()
	before := len(f.calls)
	f.mu.Unlock()
	status, _, err := rawCall(tc, "key1", "", "GET", "/v1/sandboxes/"+id+"/../..", nil)
	if err != nil {
		t.Fatal(err)
	}
	if status != 400 {
		t.Errorf("want 400 for a dot segment, got %d", status)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls[before:] {
		if strings.Contains(c, "..") {
			t.Fatalf("hotel received %q", c)
		}
	}
}
