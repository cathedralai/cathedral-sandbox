package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clientCall sends a request as the published client (compatibility path).
func (tc *testChain) clientCall(t *testing.T, method, path string, body []byte, hdr map[string]string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, tc.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("User-Agent", "cathedral-harbor/0.1.5")
	if body != nil && hdr["Content-Type"] == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	return resp.StatusCode, doc
}

func mustMarshal(v any) []byte { b, _ := json.Marshal(v); return b }

func TestHotelPathRejectsStringCmd(t *testing.T) {
	// Hotel ids (a.sbx_…) skip compatExecBody; requireExecCmdList must still refuse a string.
	tc := newChain(t)
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+id+"/exec", map[string]any{"cmd": "echo hi"})
	if status != 400 || errCode(doc) != "invalid_exec" {
		t.Fatalf("hotel-path string cmd: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes/"+id+"/exec", map[string]any{"cmd": []string{"true"}})
	if status != 200 {
		t.Fatalf("hotel-path list cmd: %d %v", status, doc)
	}
}

func TestTruncateExecJSONCapsStdoutAndSetsFlag(t *testing.T) {
	big := strings.Repeat("x", execOutputCapBytes+64)
	raw, _ := json.Marshal(map[string]any{"stdout": big, "stderr": "", "exit_code": 0, "truncated": false})
	out := truncateExecJSON(raw)
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["truncated"] != true {
		t.Fatalf("truncated flag: %v", doc["truncated"])
	}
	if s, _ := doc["stdout"].(string); len(s) != execOutputCapBytes {
		t.Fatalf("stdout len %d, want %d", len(s), execOutputCapBytes)
	}
	small, _ := json.Marshal(map[string]any{"stdout": "ok", "truncated": false})
	if got := truncateExecJSON(small); !bytes.Equal(got, small) {
		t.Fatalf("short output rewritten: %s", got)
	}
}

func TestExecTimeoutOfFourHoursPassesToTheHotel(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	id := doc["id"].(string)
	// cmd must be a list of strings (CONST feedback fix E).
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/exec", mustMarshal(map[string]any{"command": "true", "timeout_seconds": 14400}), nil)
	if status != 400 {
		t.Fatalf("string cmd: want 400 invalid_exec, got %d %v", status, doc)
	}
	if doc["detail"].(map[string]any)["error"] != "invalid_exec" {
		t.Fatalf("string cmd error code: %v", doc)
	}
	// List cmd is accepted; timeout passes through.
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/exec", mustMarshal(map[string]any{"cmd": []string{"true"}, "timeout_seconds": 14400}), nil)
	if status != 200 {
		t.Fatalf("exec: %d %v", status, doc)
	}
	var got float64
	for _, f := range tc.hotels {
		for _, e := range f.execs {
			got = e["timeout_seconds"].(float64)
		}
	}
	if got != 14400 {
		t.Fatalf("hotel got timeout %v, want 14400", got)
	}
	_, cat := tc.clientCall(t, "GET", "/v1/sandboxes/catalog", nil, nil)
	if cat["max_exec_seconds"].(float64) != 14400 {
		t.Fatalf("catalog: %v", cat["max_exec_seconds"])
	}
	// The operator limit in the config wins.
	tc.b.cfg.MaxExecSeconds = 600
	tc.clientCall(t, "POST", "/v1/sandboxes/"+id+"/exec", mustMarshal(map[string]any{"cmd": []string{"true"}, "timeout_seconds": 14400}), nil)
	for _, f := range tc.hotels {
		for _, e := range f.execs {
			got = e["timeout_seconds"].(float64)
		}
	}
	if got != 600 {
		t.Fatalf("hotel got timeout %v, want 600", got)
	}
}

func TestSpillTokenReachesTheHotelOnNativeAndCompat(t *testing.T) {
	tc := newChain(t)
	token := "0123456789abcdef0123456789abcdef"
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+id+"/exec", map[string]any{
		"cmd": []string{"true"}, "spill_token": token,
	})
	if status != 200 {
		t.Fatalf("native exec: %d %v", status, doc)
	}
	if got := latestSpill(tc); got != token {
		t.Fatalf("native hotel spill_token %q", got)
	}

	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 && status != 202 {
		t.Fatalf("compat create: %d %v", status, doc)
	}
	uuid, _ := doc["id"].(string)
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes/"+uuid+"/exec", mustMarshal(map[string]any{
		"cmd": []string{"true"}, "spill_token": "not-a-token",
	}), nil)
	if status != 400 {
		t.Fatalf("bad spill token: %d %v", status, doc)
	}
	status, doc = tc.clientCall(t, "POST", "/v1/sandboxes/"+uuid+"/exec", mustMarshal(map[string]any{
		"cmd": []string{"true"}, "spill_token": token,
	}), nil)
	if status != 200 {
		t.Fatalf("compat exec: %d %v", status, doc)
	}
	if got := latestSpill(tc); got != token {
		t.Fatalf("compat hotel spill_token %q", got)
	}
}

func latestSpill(tc *testChain) string {
	var token string
	for _, f := range tc.hotels {
		for _, ex := range f.execs {
			if s, ok := ex["spill_token"].(string); ok {
				token = s
			}
		}
	}
	return token
}

func buildForm(t *testing.T, dockerfile string, ctx []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range map[string]string{"cpu": "2", "memory_gib": "8", "minimum_free_disk_gib": "10", "dockerfile": dockerfile, "labels": "{}"} {
		_ = mw.WriteField(k, v)
	}
	fw, _ := mw.CreateFormFile("context", "context.tar.gz")
	_, _ = fw.Write(ctx)
	_ = mw.Close()
	return buf.Bytes(), mw.FormDataContentType()
}

// AB#650 and AB#776: every hotel is a shared sealed hotel and no hotel
// builds. A build is refused at once, no hotel is asked, and nothing is kept.
func TestBuildIsRefusedAndNoHotelBuilds(t *testing.T) {
	tc := newChain(t)
	body, ctype := buildForm(t, "FROM alpine:3.20\n", []byte("gzip-bytes"))
	status, doc := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	detail, _ := doc["detail"].(map[string]any)
	if status != 409 || detail["error"] != "shared_hotel_build_refused" {
		t.Fatalf("build: %d %v, want 409 shared_hotel_build_refused", status, doc)
	}
	time.Sleep(50 * time.Millisecond)
	for id, f := range tc.hotels {
		f.mu.Lock()
		n := len(f.builds)
		f.mu.Unlock()
		if n != 0 {
			t.Fatalf("hotel %s was asked to build", id)
		}
	}
	tc.b.compat.mu.Lock()
	n := len(tc.b.compat.images)
	tc.b.compat.mu.Unlock()
	if n != 0 {
		t.Fatalf("a refused build left %d image(s)", n)
	}
}

// A built image left in older state can never become ready: it reads as
// failed with shared_hotel_build_refused, and a create from it gets the same
// code with no retry hint, never the retrying image_not_ready.
func TestBuiltImageFromOlderStateIsRefused(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	const id = "0a1b2c3d-0000-0000-0000-000000000001"
	tc.b.compat.mu.Lock()
	tc.b.compat.images[id] = &compatImage{ID: id, CPU: 1, MemoryGiB: 4, DiskGiB: 10, Build: true, Dockerfile: "FROM alpine:3.20\n"}
	tc.b.compat.mu.Unlock()
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	tc.start(t) // restart over the same state_dir
	status, view := tc.clientCall(t, "GET", "/v1/images/"+id, nil, nil)
	if status != 200 || view["state"] != "failed" || view["error"] != "shared_hotel_build_refused" {
		t.Fatalf("image view: %d %v", status, view)
	}
	before := totalCreates(tc)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": id}), nil)
	detail, _ := doc["detail"].(map[string]any)
	if status != 409 || detail["error"] != "shared_hotel_build_refused" {
		t.Fatalf("create from a built image: %d %v", status, doc)
	}
	if totalCreates(tc) != before {
		t.Fatalf("a refused create reached a hotel")
	}
}

func TestIdempotentCreateSurvivesABrokerRestart(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	hdr := map[string]string{"Idempotency-Key": "create-1"}
	status, first := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), hdr)
	if status != 201 {
		t.Fatalf("create: %d %v", status, first)
	}
	id := first["id"].(string)
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(dir, stateFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	before := createsOn(tc)

	tc.start(t) // restart: a new broker process over the same state_dir
	for _, h := range tc.b.hotelList() {
		tc.b.syncHotel(context.Background(), h)
	}
	status, again := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), hdr)
	if status != 201 || again["id"] != id {
		t.Fatalf("replay after restart: %d %v (first id %s)", status, again, id)
	}
	if after := createsOn(tc); after["a"] != before["a"] || after["b"] != before["b"] || after["c"] != before["c"] {
		t.Fatalf("replay started a new room: %v -> %v", before, after)
	}
	// The room keeps its client id after the restart.
	if status, doc := tc.clientCall(t, "GET", "/v1/sandboxes/"+id, nil, nil); status != 200 || doc["id"] != id {
		t.Fatalf("room after restart: %d %v", status, doc)
	}
}

// Harbor image import warms only the guest's own hotels.
func TestCompatImportKeepsToGuestHotels(t *testing.T) {
	tc := newChain(t)
	tc.b.mu.Lock()
	tc.b.guests["g1"].limits = guestLimits{Hotels: []string{"b", "c"}}
	tc.b.mu.Unlock()
	status, doc := tc.clientCall(t, "POST", "/v1/images/import", mustMarshal(map[string]any{"image": "alpine:3.20"}), nil)
	if status != 200 {
		t.Fatalf("import: %d %v", status, doc)
	}
	time.Sleep(200 * time.Millisecond) // prefetch runs in the background
	if n := callsTo(tc.hotels["a"], "POST /v1/images/prefetch"); n != 0 {
		t.Fatalf("import warmed hotel a outside the guest's list")
	}
}

// A live network change on the Harbor path must name its mode; a missing
// mode must not open the room to the internet.
func TestCompatNetworkChangeNeedsMode(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image": "alpine:3.20", "network": "deny_all"}), nil)
	if status != 200 && status != 201 && status != 202 {
		t.Fatalf("create: %d %v", status, doc)
	}
	id, _ := doc["sandbox_id"].(string)
	if id == "" {
		id, _ = doc["id"].(string)
	}
	status, doc = tc.clientCall(t, "PUT", "/v1/sandboxes/"+id+"/network", mustMarshal(map[string]any{"network_allow": []string{"pypi.org"}}), nil)
	if status != 400 {
		t.Fatalf("network change without mode: %d %v", status, doc)
	}
}
