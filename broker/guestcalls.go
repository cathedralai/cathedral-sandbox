// Hotel calls made for one guest (workspaces #305, secrets #304).
//
// The broker sends the guest id to the hotel in the X-Cathedral-Guest header.
// The broker builds each hotel request itself and copies no guest header, so
// a guest cannot set it. The hotel keeps workspaces and secrets apart by it.
//
// One exception: the owner signature of a create on a dedicated sealed
// machine (room-kit/room_receipts.py). The guest signs its create with the
// owner key that the machine's HOST_DATA names, and the measured front inside
// the machine checks it. The broker only carries the two headers to the hotel
// that gets the create; it does not read or check them.
package main

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

const guestHeader = "X-Cathedral-Guest"

// ownerHeaders pass from a guest's create to the hotel unchanged.
var ownerHeaders = []string{"X-Cathedral-Owner-Signature", "X-Cathedral-Owner-Timestamp"}

type ownerHeadersKey struct{}

// withOwnerHeaders keeps the guest's owner signature headers in ctx for the
// hotel create calls of this request (createOne).
func withOwnerHeaders(ctx context.Context, r *http.Request) context.Context {
	h := http.Header{}
	for _, k := range ownerHeaders {
		if v := r.Header.Get(k); v != "" {
			h.Set(k, v)
		}
	}
	if len(h) == 0 {
		return ctx
	}
	return context.WithValue(ctx, ownerHeadersKey{}, h)
}

// ownerHeadersFrom is the owner signature headers of ctx, or nil.
func ownerHeadersFrom(ctx context.Context) http.Header {
	h, _ := ctx.Value(ownerHeadersKey{}).(http.Header)
	return h
}

// doGuest is a hotel call made for guest g.
func (h *hotel) doGuest(ctx context.Context, g *guestState, method, path string, query url.Values, body []byte, timeout time.Duration) (int, http.Header, []byte, error) {
	return h.doHeaders(ctx, h.cfg.API, method, path, query, body, timeout, http.Header{guestHeader: {g.cfg.ID}})
}
