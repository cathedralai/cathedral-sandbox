// Hotel calls made for one guest (workspaces #305, secrets #304).
//
// The broker sends the guest id to the hotel in the X-Cathedral-Guest header.
// The broker builds each hotel request itself and copies no guest header, so
// a guest cannot set it. The hotel keeps workspaces and secrets apart by it.
package main

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

const guestHeader = "X-Cathedral-Guest"

// doGuest is a hotel call made for guest g.
func (h *hotel) doGuest(ctx context.Context, g *guestState, method, path string, query url.Values, body []byte, timeout time.Duration) (int, http.Header, []byte, error) {
	return h.doHeaders(ctx, h.cfg.API, method, path, query, body, timeout, http.Header{guestHeader: {g.cfg.ID}})
}
