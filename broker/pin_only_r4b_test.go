package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Astra r4 finding 3: when the first cleanup list fails, the record still
// carries the create deadline. A later empty retry proves nothing while the
// hotel may still start the room.
func TestFailedFirstCleanupListStillHoldsUntilTheDeadline(t *testing.T) {
	tc := pinChain(t) // generation 1
	ha := tc.b.hotelByID("a")
	upstream := ha.cfg.API
	var mu sync.Mutex
	var heldCreate []byte
	var heldReq *http.Request
	var lists atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == "POST" && r.URL.Path == "/v1/sandboxes":
			mu.Lock()
			heldCreate, heldReq = body, r.Clone(context.Background())
			mu.Unlock()
			hijackClose(w)
		case r.Method == "GET" && r.URL.Path == "/v1/sandboxes":
			if lists.Add(1) == 1 {
				hijackClose(w) // the first cleanup list fails
				return
			}
			status, hdr, out := forwardTo(upstream, r, body) // the retry: empty
			mu.Lock()
			cb, cr := heldCreate, heldReq
			heldCreate = nil
			mu.Unlock()
			if cb != nil { // then the hotel starts the room
				forwardTo(upstream, cr, cb)
			}
			passThrough(w, status, hdr, out)
		default:
			status, hdr, out := forwardTo(upstream, r, body)
			passThrough(w, status, hdr, out)
		}
	}))
	t.Cleanup(proxy.Close)
	setHotel(tc, "a", func(h *hotel) { h.cfg.API = proxy.URL })

	if status, _ := tc.callWith(t, "key2", dedMark(1), "POST", "/v1/sandboxes", dedBody()); status != 502 {
		t.Fatalf("create with a lost reply: %d", status)
	}
	// The background retry (about a second later) lists nothing, then the
	// room appears.
	pinWait(t, func() bool { f := tc.hotels["a"]; f.mu.Lock(); defer f.mu.Unlock(); return len(f.creates) == 1 })
	pinWait(t, func() bool {
		tc.b.mu.Lock()
		defer tc.b.mu.Unlock()
		for _, ub := range ha.unreaped {
			if ub.busy {
				return false
			}
		}
		return true
	})
	change := map[string]any{"reserved_for": "g2", "reservation_ref": "owner:g2:2", "expect_generation": 1}
	if status, doc := patchHotelDoc(t, tc, "a", change); status != 409 {
		t.Fatalf("reference change after the empty retry, room just appeared: %d %v", status, doc)
	}
	// A sync lists and reaps the room; the record stays to the deadline.
	tc.b.syncHotel(context.Background(), ha)
	pinWait(t, func() bool { return callsTo(tc.hotels["a"], "DELETE /v1/sandboxes/") >= 1 })
	pinWait(t, func() bool {
		tc.b.mu.Lock()
		defer tc.b.mu.Unlock()
		for _, ub := range ha.unreaped {
			if ub.busy {
				return false
			}
		}
		return true
	})
	if status, doc := patchHotelDoc(t, tc, "a", change); status != 409 {
		t.Fatalf("reference change before the deadline: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	for _, ub := range ha.unreaped {
		ub.holdUntil = time.Now().Add(-time.Second)
	}
	tc.b.mu.Unlock()
	tc.b.syncHotel(context.Background(), ha)
	if status, doc := patchHotelDoc(t, tc, "a", change); status != 200 {
		t.Fatalf("after the deadline and an empty list: %d %v", status, doc)
	}
}
