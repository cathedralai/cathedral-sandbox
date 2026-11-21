package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// AB#863: a hotel frees quota when it kills a deleted room, before docker rm
// ends, and reports the disk still held as usage.removing_disk_gib. The
// broker counts it in the hotel's disk budget until the hotel stops sending it.

// quotaUsage serves the hotel's /v1/quota with usage, and the rest from f.
func quotaUsage(t *testing.T, f *fakeHotel, usage map[string]any) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/quota" {
			writeJSON(w, 200, map[string]any{"usage": usage})
			return
		}
		f.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRemovingDiskOfKilledRoomsCountsInDiskBudget(t *testing.T) {
	tc := newChain(t)
	setDiskBudget(tc, "b", intp(40))
	srv := quotaUsage(t, tc.hotels["b"], map[string]any{"running_sandboxes": 0, "deleting_sandboxes": 0, "removing_sandboxes": 2, "removing_disk_gib": 30})
	setHotel(tc, "b", func(h *hotel) { h.cfg.API = srv.URL })
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	if used, _ := diskUsed(tc, "b"); used != 30 {
		t.Fatalf("disk extra used: %d, want the 30 GiB of the killed rooms", used)
	}
	// 30 of 40 held by rooms still being removed: a 30 GiB extra does not fit.
	var fits bool
	setHotel(tc, "b", func(h *hotel) { fits = tc.b.diskFits(h, 40) })
	if fits {
		t.Fatalf("a 30 GiB extra fit a budget with 10 GiB left")
	}
}

func TestOldHotelWithoutRemovingDiskChangesNothing(t *testing.T) {
	tc := newChain(t)
	setDiskBudget(tc, "b", intp(40))
	srv := quotaUsage(t, tc.hotels["b"], map[string]any{"running_sandboxes": 0, "deleting_sandboxes": 1})
	setHotel(tc, "b", func(h *hotel) { h.cfg.API = srv.URL })
	tc.b.syncHotel(context.Background(), tc.b.hotelByID("b"))
	if used, _ := diskUsed(tc, "b"); used != 0 {
		t.Fatalf("disk extra used: %d, want 0", used)
	}
}
