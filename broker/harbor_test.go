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

func waitImage(t *testing.T, tc *testChain, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, doc := tc.clientCall(t, "GET", "/v1/images/"+id, nil, nil)
		if doc["state"] != "pending" || time.Now().After(deadline) {
			return doc
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestBuildThroughTheBrokerAndCreateOnlyWhereBuilt(t *testing.T) {
	tc := newChain(t)
	tc.hotels["c"].failBuild = true
	tc.b.hotelByID("b").cfg.Drain = true // a draining hotel does not build
	body, ctype := buildForm(t, "FROM alpine:3.20\n", []byte("gzip-bytes"))
	status, doc := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	if status != 200 || doc["image_id"] == nil {
		t.Fatalf("build: %d %v", status, doc)
	}
	view := waitImage(t, tc, doc["image_id"].(string))
	if view["state"] != "ready" || view["image"] != "cathedral-build-0123456789abcdef:latest" {
		t.Fatalf("view: %v", view)
	}
	got := tc.hotels["a"].builds[0]
	if got["dockerfile"] != "FROM alpine:3.20\n" || got["context_tar_b64"] != "Z3ppcC1ieXRlcw==" {
		t.Fatalf("hotel build body: %v", got)
	}
	if len(tc.hotels["b"].builds) != 0 {
		t.Fatalf("draining hotel built")
	}
	tc.b.hotelByID("b").cfg.Drain = false
	before := createsOn(tc)
	for i := 0; i < 4; i++ {
		status, doc = tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": view["image_id"]}), nil)
		if status != 201 {
			t.Fatalf("create: %d %v", status, doc)
		}
	}
	after := createsOn(tc)
	if after["a"]-before["a"] != 4 {
		t.Fatalf("creates went to hotels without the image: %v -> %v", before, after)
	}
	last := tc.hotels["a"].creates[len(tc.hotels["a"].creates)-1]
	if res := last["resources"].(map[string]any); res["vcpu"].(float64) != 2 || last["image"] != "cathedral-build-0123456789abcdef:latest" {
		t.Fatalf("create body: %v", last)
	}
}

func TestBuildFailureIsReported(t *testing.T) {
	tc := newChain(t)
	for _, f := range tc.hotels {
		f.failBuild = true
	}
	body, ctype := buildForm(t, "FROM alpine:3.20\nRUN false\n", nil)
	_, doc := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	view := waitImage(t, tc, doc["image_id"].(string))
	if view["state"] != "failed" || view["error"] != "image_build_failed" || !strings.Contains(view["message"].(string), "docker build failed") {
		t.Fatalf("view: %v", view)
	}
	status, _ := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"image_id": view["image_id"]}), nil)
	if status != 409 {
		t.Fatalf("create from failed build: %d", status)
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
	body, ctype := buildForm(t, "FROM alpine:3.20\n", []byte("ctx"))
	_, img := tc.clientCall(t, "POST", "/v1/images/build", body, map[string]string{"Content-Type": ctype})
	waitImage(t, tc, img["image_id"].(string))
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
	// A built image is known after the restart and builds again from the saved context.
	view := waitImage(t, tc, img["image_id"].(string))
	if view["state"] != "ready" {
		t.Fatalf("image after restart: %v", view)
	}
}
