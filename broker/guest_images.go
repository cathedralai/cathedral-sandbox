// Cached images per hotel and image pins for a guest (AB#860).
//
// GET /v1/images?hotel=<id> asks that hotel for the images this guest pulled
// or was granted there (the hotel scopes the list by owner, AB#650) and
// passes the answer on with "hotel" added. Without ?hotel it asks every hotel
// in the guest's scope that is up, 4 at a time, 10 s each, and answers
// {"hotels": [one entry per hotel]}. A hotel with an older room kit has no
// list route; its entry says "images_list": "not_supported".
//
// Pins: a prefetch with "pin": true asks the hotels to keep the images from
// their image GC. The guest limit pin_max_gib (config, 0 by default) is the
// byte cap the broker sends with it in X-Pin-Max-Bytes; at 0 a pin answers
// 403 pins_not_enabled. DELETE /v1/images/pins?ref=<ref>&hotel=<id> unpins.
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	pinMaxHeader       = "X-Pin-Max-Bytes"
	imageListInFlight  = 4
	imageListNotKitted = "not_supported"
)

// imageListTimeout bounds one hotel's answer to a list. A variable for tests.
var imageListTimeout = 10 * time.Second

// pinMaxBytes is the guest's pin cap in bytes, 0 when pins are off.
func (l guestLimits) pinMaxBytes() int64 {
	if l.PinMaxGiB <= 0 {
		return 0
	}
	return int64(l.PinMaxGiB) << 30
}

// imageHotel is hotel id when g may reach it, as placement does (tierOf and
// own_hosts_only), else nil.
func (b *broker) imageHotel(g *guestState, id string) *hotel {
	h := b.hotelByID(id)
	if h == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if g.tierOf(h) == "" || (g.limits.OwnHostsOnly && isMinerHotel(h)) {
		return nil
	}
	return h
}

// imageListOn is one hotel's entry of a list.
func (b *broker) imageListOn(ctx context.Context, g *guestState, h *hotel) (int, map[string]any) {
	status, _, out, err := h.doGuest(ctx, g, "GET", "/v1/images", nil, nil, imageListTimeout)
	if err != nil {
		e := hotelAPIErr(h, err)
		return e.status, map[string]any{"hotel": h.cfg.ID, "error": map[string]any{"code": e.code, "message": e.msg}}
	}
	var doc map[string]any
	if json.Unmarshal(out, &doc) != nil || doc == nil {
		doc = map[string]any{}
	}
	switch {
	case status == 404:
		// A room kit before AB#860 has no list route.
		return 200, map[string]any{"hotel": h.cfg.ID, "images_list": imageListNotKitted, "images": []any{}}
	case status != 200:
		e, _ := doc["error"].(map[string]any)
		if e == nil {
			e = map[string]any{"code": "images_list_failed", "message": "hotel answered " + strconv.Itoa(status)}
		}
		return status, map[string]any{"hotel": h.cfg.ID, "error": e}
	}
	doc["hotel"] = h.cfg.ID
	return 200, doc
}

// GET /v1/images[?hotel=<id>]
func (b *broker) handleImageList(w http.ResponseWriter, r *http.Request, g *guestState) {
	if id := r.URL.Query().Get("hotel"); id != "" {
		h := b.imageHotel(g, id)
		if h == nil {
			writeErr(w, 404, "hotel_not_found", "no hotel "+id+" for this key")
			return
		}
		status, doc := b.imageListOn(r.Context(), g, h)
		writeJSON(w, status, doc)
		return
	}
	var targets []*hotel
	for _, h := range b.hotelList() {
		b.mu.Lock()
		up := h.ok
		b.mu.Unlock()
		if up && b.imageHotel(g, h.cfg.ID) != nil {
			targets = append(targets, h)
		}
	}
	out := make([]map[string]any, len(targets))
	sem := make(chan struct{}, imageListInFlight)
	var wg sync.WaitGroup
	for i, h := range targets {
		wg.Add(1)
		go func(i int, h *hotel) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			_, out[i] = b.imageListOn(r.Context(), g, h)
		}(i, h)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i]["hotel"].(string) < out[j]["hotel"].(string) })
	writeJSON(w, 200, map[string]any{"hotels": out})
}

// DELETE /v1/images/pins?ref=<ref>&hotel=<id>. Allowed with pins off, so a
// guest can still drop pins after its cap went to 0.
func (b *broker) handleUnpin(w http.ResponseWriter, r *http.Request, g *guestState) {
	q := r.URL.Query()
	ref, id := q.Get("ref"), q.Get("hotel")
	if ref == "" || id == "" {
		writeErr(w, 400, "invalid_unpin", "ref and hotel are required")
		return
	}
	h := b.imageHotel(g, id)
	if h == nil {
		writeErr(w, 404, "hotel_not_found", "no hotel "+id+" for this key")
		return
	}
	status, _, out, err := h.doGuest(r.Context(), g, "DELETE", "/v1/images/pins/"+url.PathEscape(ref), nil, nil, imageListTimeout)
	if err != nil {
		writeHotelErr(w, h, err)
		return
	}
	writeRaw(w, status, out)
}
