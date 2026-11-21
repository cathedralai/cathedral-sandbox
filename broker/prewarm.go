// Pre-pull of catalog images and the warm preference (AB#532).
//
// The scratch disk of a sealed hotel is wiped every boot, so the first create
// of a catalog image there pulls it and holds a create slot (up to 12 minutes).
// With config prewarm_catalog on, a hotel that comes up pulls the live catalog
// images, and pickIn prefers a hotel that holds the create's image. A non-empty
// prewarm_catalog_hotels limits the pull to the hotels it names. The
// preference only narrows the candidates that already have a free room. It
// never removes capacity: when no warm hotel has room, cold hotels serve.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"
)

// hotelWentDown forgets what the hotel held: it may reboot with a wiped disk.
// guestWant stays: replayGuestPrefetch pulls it again when the hotel is back.
// Caller holds b.mu.
func (b *broker) hotelWentDown(h *hotel) {
	h.warm = nil
	h.guestWarm = nil
	h.warmGen++
}

// prewarms reports whether h pulls the catalog images when it comes up:
// prewarm_catalog is on and prewarm_catalog_hotels is empty or names h.
func (b *broker) prewarms(h *hotel) bool {
	if !b.cfg.PrewarmCatalog {
		return false
	}
	return len(b.cfg.PrewarmCatalogHotels) == 0 || slices.Contains(b.cfg.PrewarmCatalogHotels, h.cfg.ID)
}

// prewarmHotel pulls each distinct live catalog image on h, one at a time, and
// marks it warm. A failed pull leaves the image cold; creates still pull it.
// An image is skipped while h's scratch is at or over the guest prefetch line
// (prewarmSkipsFullDisk).
func (b *broker) prewarmHotel(h *hotel) {
	b.mu.Lock()
	gen := h.warmGen
	b.mu.Unlock()
	seen := map[string]bool{}
	for _, t := range catalogTemplates {
		if !t.Live || t.Image == "" || seen[t.Image] || !prewarmsTemplate(h, t) {
			continue
		}
		seen[t.Image] = true
		if b.prewarmSkipsFullDisk(h, t.Image) {
			continue
		}
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

// prewarmSkipsFullDisk reports whether the catalog pull of image on h waits:
// h's scratch is at or over the guest prefetch line (prefetchDiskFull). A
// broker restart alone starts the catalog pulls, and the extra layers would
// fill the disk the hotel's rooms write to (AB#894, Astra r2 finding 4). The
// skip is logged once per hotel and image. The hotel stays placeable as
// before; the image stays cold, so a create of it pulls it as today.
func (b *broker) prewarmSkipsFullDisk(h *hotel, image string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.prefetchDiskFull(h) {
		return false
	}
	if !h.prewarmFull[image] {
		if h.prewarmFull == nil {
			h.prewarmFull = map[string]bool{}
		}
		h.prewarmFull[image] = true
		log.Printf("hotel %s: catalog pre-pull of %s skipped: scratch %.1f%% used, at or over the admission line", h.cfg.ID, image, *h.roomDataPct)
	}
	return true
}

// prewarmsTemplate reports whether h may ever run a create of t. A sealed-only
// template (the LFM images, about 1.3 GB each) never lands on an unsealed
// hotel, so pulling it there only fills the hotel's disk. 20 Nov 2026: every
// broker restart pulled them onto c46, whose 60 GB room volume was 99% full,
// and a polaris create on c46 failed with ENOSPC during the pull.
func prewarmsTemplate(h *hotel, t catalogTemplate) bool {
	return !t.SealedOnly || hotelClass(h) == classSealed
}

// preferGuestWarm reports whether a guest's own prefetches steer its
// creates: prefer_guest_warm, default on (AB#859).
func (b *broker) preferGuestWarm() bool {
	return b.cfg.PreferGuestWarm == nil || *b.cfg.PreferGuestWarm
}

// holds reports whether h holds image for a create of guest: a prewarmed
// catalog image, or one the guest itself prefetched there. Caller holds b.mu.
func (b *broker) holds(h *hotel, image, guest string) bool {
	if b.cfg.PrewarmCatalog && h.warm[image] {
		return true
	}
	return guest != "" && b.preferGuestWarm() && h.guestWarm[guest][image]
}

// preferWarm zeroes the weight of cold hotels when at least one candidate that
// has a free room holds image for guest. It returns the new total. Caller
// holds b.mu.
func (b *broker) preferWarm(hotels []*hotel, weight []float64, total float64, image, guest string) float64 {
	if image == "" || (!b.cfg.PrewarmCatalog && !b.preferGuestWarm()) {
		return total
	}
	warmTotal := 0.0
	for i, h := range hotels {
		if weight[i] > 0 && b.holds(h, image, guest) {
			warmTotal += weight[i]
		}
	}
	if warmTotal <= 0 {
		return total
	}
	for i, h := range hotels {
		if !b.holds(h, image, guest) {
			weight[i] = 0
		}
	}
	return warmTotal
}

// ------------------------------------------------- guest prefetch (AB#859)

const (
	prefetchPerHotel   = 4                  // ref pulls in flight per hotel
	prefetchRefTimeout = 30 * time.Minute   // cap of one ref call (the hotel's own docker pull stops at 10 min)
	guestWantMax       = 256                // refs replayed per guest and hotel
	guestWantKeep      = 7 * 24 * time.Hour // a ref not prefetched again for this long is not replayed
)

// prefetchDiskFull reports whether h's scratch is at or over its admission
// line: disk_admit_used_pct when set, else diskFullPct (disk.go). A pull there
// would fill the disk the hotel's rooms write to (AB#861). No reading yet:
// not full, as before. Caller holds b.mu.
func (b *broker) prefetchDiskFull(h *hotel) bool {
	if h.roomDataPct == nil {
		return false
	}
	line := diskFullPct
	if l := h.cfg.DiskAdmitUsedPct; l != nil {
		line = *l
	}
	return *h.roomDataPct >= line
}

// imageStoreFull is the prefetch error of a hotel refused by prefetchDiskFull.
// Caller holds b.mu.
func imageStoreFull(h *hotel) map[string]any {
	return map[string]any{"code": "image_store_full",
		"message": fmt.Sprintf("hotel %s scratch is %.1f%% used; it pulls no more images until it is under the admission line", h.cfg.ID, *h.roomDataPct)}
}

// prefetchRef pulls one ref on h, as guest g when g is set, and reports the
// entry for the prefetch view. On success it marks h warm for g, unless h
// went down since gen, and, for a pull without a login, keeps the ref for
// replayGuestPrefetch (keep; a replay itself does not renew the ref). auth
// is the registry_auth of the request (nil: none); it is passed to the hotel
// and never kept.
func (b *broker) prefetchRef(h *hotel, g *guestState, ref string, auth any, gen int, keep bool) map[string]any {
	hotelBody := map[string]any{"images": []string{ref}}
	if auth != nil {
		hotelBody["registry_auth"] = auth
	}
	body, _ := json.Marshal(hotelBody)
	var status int
	var out []byte
	var err error
	// A pull can take minutes, so it does not use the guest request context.
	// The guest id is forwarded so the hotel grants ownership of the pulled
	// image ids to this guest (AB#650).
	if g != nil {
		status, _, out, err = h.doGuest(context.Background(), g, "POST", "/v1/images/prefetch", nil, body, prefetchRefTimeout)
	} else {
		status, _, out, err = h.do(context.Background(), "POST", "/v1/images/prefetch", nil, body, prefetchRefTimeout)
	}
	entry := map[string]any{}
	var doc map[string]any
	_ = json.Unmarshal(out, &doc)
	switch {
	case err != nil:
		e := hotelAPIErr(h, err)
		entry["error"] = map[string]any{"code": e.code, "message": e.msg}
	case status == 200 || status == 202:
		if res, ok := doc["result"].(map[string]any); ok {
			if imgs, ok := res["images"].([]any); ok && len(imgs) > 0 {
				if m, ok := imgs[0].(map[string]any); ok {
					for k, v := range m {
						entry[k] = v
					}
				}
			}
		}
		entry["ref"], entry["state"] = ref, "done"
		if g != nil {
			b.markGuestWarm(h, g.cfg.ID, ref, gen, keep && auth == nil)
		}
		return entry
	default:
		entry["error"] = map[string]any{"code": "prefetch_failed", "message": fmt.Sprintf("hotel answered %d", status)}
		if e, ok := doc["error"].(map[string]any); ok {
			entry["error"] = map[string]any{"code": e["code"], "message": e["message"], "status": status}
		}
	}
	entry["ref"], entry["state"] = ref, "failed"
	return entry
}

// markGuestWarm marks ref warm on h for guest, unless h went down since gen,
// and with replay keeps the ref for the next time h comes up.
func (b *broker) markGuestWarm(h *hotel, guest, ref string, gen int, replay bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if replay {
		if h.guestWant == nil {
			h.guestWant = map[string]map[string]time.Time{}
		}
		want := h.guestWant[guest]
		if want == nil {
			want = map[string]time.Time{}
			h.guestWant[guest] = want
		}
		want[ref] = time.Now()
		for len(want) > guestWantMax { // drop the oldest
			oldest, at := "", time.Time{}
			for r, t := range want {
				if oldest == "" || t.Before(at) {
					oldest, at = r, t
				}
			}
			delete(want, oldest)
		}
	}
	if h.warmGen != gen {
		return
	}
	if h.guestWarm == nil {
		h.guestWarm = map[string]map[string]bool{}
	}
	if h.guestWarm[guest] == nil {
		h.guestWarm[guest] = map[string]bool{}
	}
	h.guestWarm[guest][ref] = true
}

// hotelHolds asks h, as guest g, whether ref is in its image cache
// (GET /v1/images/<ref>). Any error: false, so the replay pulls.
func (b *broker) hotelHolds(h *hotel, g *guestState, ref string) bool {
	status, _, out, err := h.doGuest(context.Background(), g, "GET", "/v1/images/"+ref, nil, nil, 30*time.Second)
	if err != nil || status != 200 {
		return false
	}
	var doc map[string]any
	return json.Unmarshal(out, &doc) == nil && doc["cached"] == true
}

// replayGuestPrefetch pulls again, as each guest, the refs the guests
// prefetched on h without a login, after h came up (a sealed hotel's scratch
// is wiped every boot). It stops when h goes down again, skips a guest that
// may no longer use h, and pulls nothing while h's disk is full. Refs that
// needed a login are not replayed: the login is never kept.
func (b *broker) replayGuestPrefetch(h *hotel) {
	b.mu.Lock()
	gen := h.warmGen
	type job struct{ guest, ref string }
	var jobs []job
	for guest, want := range h.guestWant {
		for ref, at := range want {
			if time.Since(at) > guestWantKeep {
				delete(want, ref)
				continue
			}
			jobs = append(jobs, job{guest, ref})
		}
		if len(want) == 0 {
			delete(h.guestWant, guest)
		}
	}
	b.mu.Unlock()
	if len(jobs) == 0 {
		return
	}
	allowed := map[string]bool{}
	for _, j := range jobs {
		if _, seen := allowed[j.guest]; !seen {
			g := b.guests[j.guest]
			allowed[j.guest] = g != nil && g.limitsAllow(b, h.cfg.ID)
		}
	}
	sem := make(chan struct{}, prefetchPerHotel)
	var wg sync.WaitGroup
	for _, j := range jobs {
		if !allowed[j.guest] {
			continue
		}
		sem <- struct{}{}
		b.mu.Lock()
		stop := h.warmGen != gen || !h.ok || b.prefetchDiskFull(h)
		b.mu.Unlock()
		if stop {
			<-sem
			break
		}
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()
			g := b.guests[j.guest]
			// A hotel that was only unreachable for a while still holds its
			// images: mark those warm without a pull. Only a wiped scratch
			// (a reboot, a sealed roll) pulls again.
			if b.hotelHolds(h, g, j.ref) {
				b.markGuestWarm(h, j.guest, j.ref, gen, false)
				return
			}
			b.prefetchRef(h, g, j.ref, nil, gen, false)
		}(j)
	}
	wg.Wait()
}
