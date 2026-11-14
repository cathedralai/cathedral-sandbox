package main

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBulkDeleteRetriesClaimBusyHotel(t *testing.T) {
	tc := newChain(t)
	room := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "labels": map[string]any{"run": "r1"}})
	for _, f := range tc.hotels {
		f.mu.Lock()
		f.bulkClaimBusy = 1
		f.mu.Unlock()
	}
	status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes?label=run=r1", nil)
	if status != 200 {
		t.Fatalf("retryable claim busy must finish cleanup: %d %v", status, doc)
	}
	if left := hotelRooms(tc); len(left) != 0 {
		t.Fatalf("room %s remained after claimed success: %v", room, left)
	}
	for id, f := range tc.hotels {
		f.mu.Lock()
		calls := len(f.bulkDeletes)
		f.mu.Unlock()
		if calls != 2 {
			t.Errorf("hotel %s got %d bulk calls, want retry", id, calls)
		}
	}
}

func TestBulkDeleteDoesNotReportSuccessWhileClaimBusyPersists(t *testing.T) {
	tc := newChain(t)
	f := tc.hotels["a"]
	f.mu.Lock()
	f.bulkClaimBusy = -1
	f.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest("DELETE", "/v1/sandboxes?label=run=r1", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	tc.b.handleBulkDelete(rec, req, tc.b.guests["g1"])
	if rec.Code != 409 || errCodeOf(rec.Body.Bytes()) != "bulk_delete_claim_busy" {
		t.Fatalf("busy hotel must make bulk delete retryable, got %d %s", rec.Code, rec.Body.String())
	}
}
