package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Cancel of a background exec (AB#406): the broker needs no code. The room
// passthrough carries the tail `exec/cancel`, the body and the answer as they
// are, and copies X-Room-Receipt. A change that rewrites or inspects it fails here.
var execCancelBody = []byte(`{"spill_token":"` + strings.Repeat("ab", 16) + `"}`)

// The answer holds no room id, so the passthrough's id rewrite cannot change it.
var execCancelAnswer = []byte(`{"result":"stopped","token_sha256":"` + strings.Repeat("e", 64) + `"}`)

func TestExecCancelPassesThroughByteForByte(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	hotelID, _, _ := strings.Cut(bid, ".")
	f := tc.hotels[hotelID]
	f.mu.Lock()
	f.execCancelAnswer = execCancelAnswer
	f.mu.Unlock()
	_, hid, _ := strings.Cut(bid, ".")

	req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes/"+bid+"/exec/cancel", bytes.NewReader(execCancelBody))
	req.Header.Set("Authorization", "Bearer key1")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("exec cancel: %d %s", resp.StatusCode, out)
	}
	if !bytes.Equal(out, execCancelAnswer) {
		t.Fatalf("the answer changed on the way:\n got %s\nwant %s", out, execCancelAnswer)
	}
	if resp.Header.Get("X-Room-Receipt") != "signed-exec-cancel" {
		t.Fatalf("receipt header: %q", resp.Header.Get("X-Room-Receipt"))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.execCancelBodies) != 1 || !bytes.Equal(f.execCancelBodies[0], execCancelBody) {
		t.Fatalf("the hotel got another body: %q", f.execCancelBodies)
	}
	if f.execCancelPaths[0] != "/v1/sandboxes/"+hid+"/exec/cancel" {
		t.Fatalf("hotel path: %s", f.execCancelPaths[0])
	}
	if len(f.execs) != 0 {
		t.Fatalf("a plaintext exec reached the hotel")
	}
}

func TestExecCancelIsTheOwnersOnly(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	hotelID, _, _ := strings.Cut(bid, ".")
	f := tc.hotels[hotelID]

	req, _ := http.NewRequest("POST", tc.srv.URL+"/v1/sandboxes/"+bid+"/exec/cancel", bytes.NewReader(execCancelBody))
	req.Header.Set("Authorization", "Bearer key2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != 404 {
		t.Fatalf("another guest's cancel: %d", resp.StatusCode)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.execCancelBodies) != 0 {
		t.Fatalf("it reached the hotel")
	}
}
