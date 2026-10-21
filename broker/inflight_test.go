package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

// hotelRooms is every room the fake hotels still hold, by hotel id.
func hotelRooms(tc *testChain) map[string]int {
	out := map[string]int{}
	for id, f := range tc.hotels {
		f.mu.Lock()
		if len(f.rooms) > 0 {
			out[id] = len(f.rooms)
		}
		f.mu.Unlock()
	}
	return out
}

func roomDeletes(tc *testChain) int {
	n := 0
	for _, f := range tc.hotels {
		f.mu.Lock()
		n += len(f.roomDeletes)
		f.mu.Unlock()
	}
	return n
}

func slowHotels(tc *testChain, d time.Duration) {
	for _, f := range tc.hotels {
		f.mu.Lock()
		f.createDelay = d
		f.mu.Unlock()
	}
}

// waitFor polls cond for up to 5 s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// brokerRunning counts the rooms the broker shows as running for guest g1.
func brokerRunning(tc *testChain) int {
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	n := 0
	for _, h := range tc.b.hotelList() {
		for _, rm := range h.rooms {
			if rm.guest == "g1" && rm.state == stRunning {
				n++
			}
		}
	}
	return n
}

func TestCancelledCreateLeavesNoRoom(t *testing.T) {
	tc := newChain(t)
	slowHotels(tc, 400*time.Millisecond)
	raw, _ := json.Marshal(map[string]any{"image": "alpine:3.20", "labels": map[string]any{"run": "r1"}})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", tc.srv.URL+"/v1/sandboxes", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer key1")
	if _, err := http.DefaultClient.Do(req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want a cancelled create, got %v", err)
	}
	// The hotel finishes the room after the cancel; the broker deletes it.
	waitFor(t, "the broker to delete the cancelled room", func() bool { return roomDeletes(tc) == 1 })
	if left := hotelRooms(tc); len(left) != 0 {
		t.Fatalf("orphan rooms on the hotels: %v", left)
	}
	if n := brokerRunning(tc); n != 0 {
		t.Fatalf("broker shows %d running rooms", n)
	}
	// A cancel is not a hotel failure: no backoff, no failed count.
	tc.b.mu.Lock()
	for _, h := range tc.b.hotelList() {
		if h.failed != 0 || time.Now().Before(h.backoffUntil) {
			t.Errorf("hotel %s penalised for a client cancel: failed %d", h.cfg.ID, h.failed)
		}
	}
	tc.b.mu.Unlock()
}

func TestDeleteByLabelCatchesACreateInFlight(t *testing.T) {
	tc := newChain(t)
	keep := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "labels": map[string]any{"run": "other"}})
	slowHotels(tc, 400*time.Millisecond)
	type answer struct {
		status int
		doc    map[string]any
	}
	done := make(chan answer, 1)
	go func() {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "labels": map[string]any{"run": "r1"}})
		done <- answer{status, doc}
	}()
	waitFor(t, "the create to reach a hotel", func() bool {
		tc.b.mu.Lock()
		defer tc.b.mu.Unlock()
		for _, h := range tc.b.hotelList() {
			if h.creating > 0 {
				return true
			}
		}
		return false
	})
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/sandboxes?label=run=r1", nil); status != 200 {
		t.Fatalf("bulk delete: %d", status)
	}
	got := <-done
	if got.status != 409 || errCode(got.doc) != "deleted_during_create" {
		t.Fatalf("create in flight: %d %v", got.status, got.doc)
	}
	if roomDeletes(tc) != 1 {
		t.Fatalf("want one room delete, got %d", roomDeletes(tc))
	}
	// Only the room of the other run is left.
	if left := hotelRooms(tc); len(left) != 1 {
		t.Fatalf("rooms left: %v", left)
	}
	if n := brokerRunning(tc); n != 1 {
		t.Fatalf("broker shows %d running rooms, want 1 (%s)", n, keep)
	}
	// A create that comes after the delete is a new create: it runs.
	slowHotels(tc, 0)
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "labels": map[string]any{"run": "r1"}})
}

func TestDeleteByLabelStopsAQueuedCreate(t *testing.T) {
	tc := newChain(t)
	// Fill every create slot, so the next create waits in the broker queue.
	var full []*hotel
	for _, h := range tc.b.hotelList() {
		for i := 0; i < cap(h.sem); i++ {
			h.sem <- struct{}{}
		}
		full = append(full, h)
	}
	done := make(chan int, 1)
	var doc map[string]any
	go func() {
		var status int
		status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "labels": map[string]any{"run": "r2"}})
		done <- status
	}()
	waitFor(t, "the create to queue", func() bool {
		tc.b.mu.Lock()
		defer tc.b.mu.Unlock()
		q := 0
		for _, h := range tc.b.hotelList() {
			q += h.queued
		}
		return q == 1
	})
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/sandboxes?label=run=r2", nil); status != 200 {
		t.Fatalf("bulk delete: %d", status)
	}
	for _, h := range full {
		for i := 0; i < cap(h.sem); i++ {
			<-h.sem
		}
	}
	if status := <-done; status != 409 || errCode(doc) != "deleted_during_create" {
		t.Fatalf("queued create: %d %v", status, doc)
	}
	if n := createsOn(tc); n["a"]+n["b"]+n["c"] != 0 {
		t.Fatalf("a hotel got the create: %v", n)
	}
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	for _, h := range tc.b.hotelList() {
		if h.queued != 0 || h.creating != 0 || len(h.sem) != 0 {
			t.Fatalf("hotel %s counters: queued %d creating %d slots held %d", h.cfg.ID, h.queued, h.creating, len(h.sem))
		}
	}
}

func TestTombstoneMatchesOnlyItsGuestLabelsAndTime(t *testing.T) {
	b := &broker{}
	t0 := time.Now()
	b.addTombstone("g1", []string{"run=r1", "kind=x"}, t0)
	labels := map[string]any{"run": "r1", "kind": "x", guestLabel: "g1"}
	if !b.tombstoned("g1", labels, t0.Add(-time.Second)) {
		t.Fatal("a create received before the delete must match")
	}
	if b.tombstoned("g1", labels, t0.Add(time.Second)) {
		t.Fatal("a create received after the delete must not match")
	}
	if b.tombstoned("g2", labels, t0.Add(-time.Second)) {
		t.Fatal("another guest's create must not match")
	}
	if b.tombstoned("g1", map[string]any{"run": "r1"}, t0.Add(-time.Second)) {
		t.Fatal("every filter label must match")
	}
	// Old tombstones go when a new one comes.
	b.addTombstone("g1", []string{"run=r9"}, t0.Add(tombstoneTTL+time.Second))
	if len(b.tombs["g1"]) != 1 {
		t.Fatalf("expired tombstone kept: %d", len(b.tombs["g1"]))
	}
}
