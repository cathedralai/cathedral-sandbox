// Pre-pull of catalog images and the warm preference (AB#532).
//
// The scratch disk of a sealed hotel is wiped every boot, so the first create
// of a catalog image there pulls it and holds a create slot (up to 12 minutes).
// With config prewarm_catalog on, a hotel that comes up pulls the live catalog
// images, and pickIn prefers a hotel that holds the create's image. The
// preference only narrows the candidates that already have a free room. It
// never removes capacity: when no warm hotel has room, cold hotels serve.
package main

import (
	"context"
	"encoding/json"
	"time"
)

// hotelWentDown forgets what the hotel held: it may reboot with a wiped disk.
// Caller holds b.mu.
func (b *broker) hotelWentDown(h *hotel) {
	h.warm = nil
	h.warmGen++
}

// prewarmHotel pulls each distinct live catalog image on h, one at a time, and
// marks it warm. A failed pull leaves the image cold; creates still pull it.
func (b *broker) prewarmHotel(h *hotel) {
	b.mu.Lock()
	gen := h.warmGen
	b.mu.Unlock()
	seen := map[string]bool{}
	for _, t := range catalogTemplates {
		if !t.Live || t.Image == "" || seen[t.Image] {
			continue
		}
		seen[t.Image] = true
		body, _ := json.Marshal(map[string]any{"images": []string{t.Image}})
		status, _, _, err := h.do(context.Background(), "POST", "/v1/images/prefetch", nil, body, 30*time.Minute)
		if err != nil || status >= 300 {
			continue
		}
		b.mu.Lock()
		if h.warmGen == gen { // the hotel did not go down while the pull ran
			if h.warm == nil {
				h.warm = map[string]bool{}
			}
			h.warm[t.Image] = true
		}
		b.mu.Unlock()
	}
}

// preferWarm zeroes the weight of cold hotels when at least one candidate that
// has a free room holds image. It returns the new total. Caller holds b.mu.
func (b *broker) preferWarm(hotels []*hotel, weight []float64, total float64, image string) float64 {
	if !b.cfg.PrewarmCatalog || image == "" {
		return total
	}
	warmTotal := 0.0
	for i, h := range hotels {
		if weight[i] > 0 && h.warm[image] {
			warmTotal += weight[i]
		}
	}
	if warmTotal <= 0 {
		return total
	}
	for i, h := range hotels {
		if !h.warm[image] {
			weight[i] = 0
		}
	}
	return warmTotal
}
