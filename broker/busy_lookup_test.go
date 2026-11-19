package main

import (
	"strings"
	"testing"
	"time"
)

// AB#819 follow-up to #600: a hotel whose data pool stays full answers
// errHotelBusy without being asked anything. A bare-name lookup that fans out
// across hotels must then answer 503 sold_out (retry), never "not found":
// the busy hotel may hold the name.

func TestForkOfASnapshotOnABusyHotelIs503NotFound(t *testing.T) {
	tc := newChain(t)
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+room+"/snapshot", map[string]any{"name": "keep"})
	if status != 202 {
		t.Fatalf("snapshot: %d %v", status, doc)
	}
	snapID := doc["result"].(map[string]any)["snapshot_id"].(string)
	free := fillConns(gateOf(tc, "b", 1, 50*time.Millisecond))
	before := createsOn(tc)

	for _, ref := range []string{"keep", snapID} {
		status, hdr, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": ref})
		if status != 503 || errCode(doc) != "sold_out" || hdr.Get("Retry-After") != "5" {
			t.Fatalf("fork of %s with its hotel busy: %d %v Retry-After %q", ref, status, doc, hdr.Get("Retry-After"))
		}
		status, hdr, doc = tc.rawCall(t, "key1", "DELETE", "/v1/snapshots/"+ref, nil)
		if status != 503 || errCode(doc) != "sold_out" || hdr.Get("Retry-After") != "5" {
			t.Fatalf("delete of %s with its hotel busy: %d %v Retry-After %q", ref, status, doc, hdr.Get("Retry-After"))
		}
	}
	if after := createsOn(tc); after["a"] != before["a"] || after["b"] != before["b"] || after["c"] != before["c"] {
		t.Fatalf("a fork on a busy hotel started a room: %v -> %v", before, after)
	}

	// A name no hotel has is still 404 once nothing is busy.
	free()
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": "nope"}); status != 404 || errCode(doc) != "snapshot_not_found" {
		t.Fatalf("unknown snapshot: %d %v", status, doc)
	}
	if status, _ := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"snapshot_id": "keep"}); status != 202 {
		t.Fatalf("fork once the hotel is free: %d", status)
	}
}

func TestWorkspaceOnABusyHotelIsNeverDuplicatedOrNotFound(t *testing.T) {
	tc := newWSChain(t)
	if status, doc := tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "repo", "hotels": []string{"b"}}); status != 201 {
		t.Fatalf("create: %d %v", status, doc)
	}
	free := fillConns(gateOf(tc.testChain, "b", 1, 50*time.Millisecond))
	before := createsOn(tc.testChain)

	// Same name again while hotel b is busy: no second copy on a or c.
	status, hdr, doc := tc.rawCall(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "repo"})
	if status != 503 || errCode(doc) != "sold_out" || hdr.Get("Retry-After") != "5" {
		t.Fatalf("create of an existing name with its hotel busy: %d %v Retry-After %q", status, doc, hdr.Get("Retry-After"))
	}
	for _, id := range []string{"a", "c"} {
		tc.ws[id].wmu.Lock()
		dup := tc.ws[id].ws["g1"]["repo"]
		tc.ws[id].wmu.Unlock()
		if dup {
			t.Fatalf("workspace repo duplicated on hotel %s", id)
		}
	}

	// Bare-name reads and room creates retry, not 404.
	for _, c := range []struct {
		method, path string
		body         map[string]any
	}{
		{"GET", "/v1/workspaces/repo", nil},
		{"GET", "/v1/workspaces/b.repo", nil},
		{"POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "workspace": "repo"}},
		{"POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "workspace": "b.repo"}},
	} {
		status, hdr, doc := tc.rawCall(t, "key1", c.method, c.path, c.body)
		if status != 503 || errCode(doc) != "sold_out" || hdr.Get("Retry-After") != "5" {
			t.Fatalf("%s %s %v with the hotel busy: %d %v Retry-After %q", c.method, c.path, c.body, status, doc, hdr.Get("Retry-After"))
		}
	}
	if after := createsOn(tc.testChain); after["a"] != before["a"] || after["b"] != before["b"] || after["c"] != before["c"] {
		t.Fatalf("a create on a busy workspace hotel started a room: %v -> %v", before, after)
	}

	// Once b frees, the name is found again and a fresh name still creates.
	free()
	if status, doc := tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "repo"}); status != 409 || errCode(doc) != "workspace_exists" {
		t.Fatalf("create of an existing name: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key1", "GET", "/v1/workspaces/nope", nil); status != 404 || errCode(doc) != "workspace_not_found" {
		t.Fatalf("unknown workspace: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": "fresh"}); status != 201 {
		t.Fatalf("create of a new name: %d %v", status, doc)
	}
}

func TestSecretDeleteWithABusyHotelIsRetryNotNotFound(t *testing.T) {
	sc := newSecretChain(t, []string{"a", "b"})
	secretCall(t, sc.srv.URL, "key1", "PUT", "/v1/secrets/PIP_TOKEN", `{"value":"`+testSecretValue+`"}`, nil)
	free := fillConns(gateOf(sc.testChain, "b", 1, 50*time.Millisecond))

	// a clears it, b was never asked: partial, retryable.
	status, hdr, doc := sc.rawCall(t, "key1", "DELETE", "/v1/secrets/PIP_TOKEN", nil)
	if status != 502 || errCode(doc) != "secrets_partial" || hdr.Get("Retry-After") != "5" {
		t.Fatalf("delete with b busy: %d %v Retry-After %q", status, doc, hdr.Get("Retry-After"))
	}
	if h := doc["hotels"].(map[string]any); h["a"] != "done" || h["b"] != "busy" {
		t.Fatalf("hotels %v", doc["hotels"])
	}
	// Only busy b may still hold it: retry, not 404.
	status, hdr, doc = sc.rawCall(t, "key1", "DELETE", "/v1/secrets/PIP_TOKEN", nil)
	if status != 503 || errCode(doc) != "sold_out" || hdr.Get("Retry-After") != "5" {
		t.Fatalf("second delete with b busy: %d %v Retry-After %q", status, doc, hdr.Get("Retry-After"))
	}
	if sc.sh["b"].values["g1"]["PIP_TOKEN"] != testSecretValue {
		t.Fatal("busy hotel b was sent the delete")
	}

	free()
	if status, _ := secretCall(t, sc.srv.URL, "key1", "DELETE", "/v1/secrets/PIP_TOKEN", "", nil); status != 204 {
		t.Fatalf("delete once b is free: %d", status)
	}
	if status, out := secretCall(t, sc.srv.URL, "key1", "DELETE", "/v1/secrets/PIP_TOKEN", "", nil); status != 404 || !strings.Contains(out, "secret_not_found") {
		t.Fatalf("delete of a gone secret: %d %s", status, out)
	}
}
