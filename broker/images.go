// Hotel choice, snapshots and image prefetch through central booking.
//
// Hotel choice: a create (and a prefetch) can name hotels, or ask for hotels
// by label. "hotels": ["a", "b"] keeps only those hotels. "hotel_labels":
// {"sealed": "true"} keeps hotels with every pair. "exclude_hotel_labels"
// drops hotels with any pair. The broker removes these fields before it
// calls a hotel.
//
// Snapshots: a snapshot lives on the hotel that made it. The broker gives
// it the id "<hotel>.<hotel snapshot id>", like a room id. A fork with that
// id goes only to that hotel. The broker labels each snapshot with the guest
// and puts the guest id in front of a snapshot name, so a guest sees, forks,
// pushes and deletes only its own snapshots. To start rooms from a snapshot
// on any hotel, push it to a registry and create from the image.
//
// Prefetch: POST /v1/images/prefetch pulls images on the chosen hotels in the
// background. GET /v1/images/prefetch/<id> gives the state on each hotel.
// The optional registry login goes to the hotels and is not kept.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------- hotel choice

// placement limits where a create can go.
type placement struct {
	ids     map[string]bool   // empty: any hotel
	match   map[string]string // the hotel has every pair
	exclude map[string]string // the hotel has none of the pairs
	only    *hotel            // a fork: the hotel that holds the snapshot
	// snapshotRef is the broker snapshot id the guest sent; hotelSnap is the
	// id on the hotel.
	snapshotRef, hotelSnap string
	allowed                map[string]bool // non-empty: the guest may use only these hotels (guests.go)
	// images: non-empty for a create from a broker-built image, the hotels
	// that hold it. Unlike ids it is not a hotel choice: the sealed rule and
	// the guest's sealed default still apply.
	images          map[string]bool
	sealedByDefault bool // match["sealed"] comes from the guest default, not the request
}

func (pl placement) selects(h *hotel) bool {
	if len(pl.allowed) > 0 && !pl.allowed[h.cfg.ID] {
		return false
	}
	if len(pl.ids) > 0 && !pl.ids[h.cfg.ID] {
		return false
	}
	if len(pl.images) > 0 && !pl.images[h.cfg.ID] {
		return false
	}
	// A hotel with "sealed": true in the config takes only creates that ask
	// for a sealed room ("sealed": true or hotel label sealed=true) or name it.
	if h.cfg.Sealed && len(pl.ids) == 0 && pl.match["sealed"] != "true" {
		return false
	}
	for k, v := range pl.match {
		if h.labels()[k] != v {
			return false
		}
	}
	for k, v := range pl.exclude {
		if h.labels()[k] == v {
			return false
		}
	}
	return true
}

func (pl placement) allows(h *hotel) bool {
	return (pl.only == nil || pl.only == h) && pl.selects(h)
}

// apply removes the broker fields from a create body and sets the hotel
// snapshot id.
func (pl placement) apply(payload map[string]any) {
	delete(payload, "hotels")
	delete(payload, "hotel_labels")
	delete(payload, "exclude_hotel_labels")
	delete(payload, "sealed")
	if pl.hotelSnap != "" {
		payload["snapshot_id"] = pl.hotelSnap
	}
}

// noRoom is the answer when pick finds no hotel and no hotel was tried.
// Caller must NOT hold b.mu; noRoomReason locks.
func (b *broker) noRoom(pl placement) createResult {
	if pl.only != nil {
		return createResult{status: 503, header: http.Header{"Retry-After": {"5"}}, doc: errDoc("snapshot_hotel_unavailable",
			"the hotel that holds this snapshot has no free room or does not answer; retry later, or push the snapshot to a registry and create from the image")}
	}
	return b.noRoomReason(pl)
}

// noRoomReason distinguishes "hotels down" from "hotels full" so a dead hotel
// (e.g. green) is not reported as 429 all hotels are full.
func (b *broker) noRoomReason(pl placement) createResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	var matching, down, full, free int
	for _, h := range b.hotelList() {
		if !pl.allows(h) {
			continue
		}
		matching++
		if !h.ok || h.drain() || time.Now().Before(h.backoffUntil) {
			down++
			continue
		}
		if h.slots-h.used() > 0 {
			free++
		} else {
			full++
		}
	}
	ra := http.Header{"Retry-After": {"5"}}
	if matching == 0 {
		return createResult{status: 409, header: ra, doc: errDoc("no_matching_hotel", "no hotel matches the hotel selection")}
	}
	if free > 0 {
		// Race: a room freed between pick and noRoom; still ask the guest to retry.
		return createResult{status: 429, header: ra, doc: errDoc("no_free_rooms", "all hotels are full; retry later")}
	}
	if down > 0 && full == 0 {
		return createResult{status: 503, header: ra, doc: errDoc("hotels_unavailable",
			"selected hotels are down or draining; retry later")}
	}
	if down > 0 {
		return createResult{status: 503, header: ra, doc: errDoc("hotels_unavailable",
			"selected hotels are down or full; retry later")}
	}
	return createResult{status: 429, header: ra, doc: errDoc("no_free_rooms", "all hotels are full; retry later")}
}

func errDoc(code, msg string) map[string]any {
	return map[string]any{"error": map[string]string{"code": code, "message": msg}}
}

type apiErr struct {
	status    int
	code, msg string
}

func (e *apiErr) Error() string { return e.code + ": " + e.msg }

func stringMap(v any, field string) (map[string]string, *apiErr) {
	if v == nil {
		return nil, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, &apiErr{400, "invalid_hotel_selection", field + " must be an object of strings"}
	}
	out := map[string]string{}
	for k, x := range m {
		s, ok := x.(string)
		if !ok {
			return nil, &apiErr{400, "invalid_hotel_selection", field + " must be an object of strings"}
		}
		out[k] = s
	}
	return out, nil
}

// parseSelection reads "hotels", "hotel_labels", "exclude_hotel_labels" and
// "sealed", and applies the guest's hotel set and sealed default (guests.go).
// It answers 409 for an unknown hotel id and 409 when no hotel matches.
func (b *broker) parseSelection(g *guestState, payload map[string]any) (placement, *apiErr) {
	var pl placement
	if v, ok := payload["hotels"]; ok && v != nil {
		list, ok := v.([]any)
		if !ok {
			return pl, &apiErr{400, "invalid_hotel_selection", "hotels must be a list of hotel ids"}
		}
		pl.ids = map[string]bool{}
		for _, x := range list {
			id, _ := x.(string)
			if b.hotelByID(id) == nil || !g.limitsAllow(b, id) {
				return pl, &apiErr{409, "unknown_hotel", fmt.Sprintf("no hotel %q", fmt.Sprint(x))}
			}
			pl.ids[id] = true
		}
	}
	var e *apiErr
	if pl.match, e = stringMap(payload["hotel_labels"], "hotel_labels"); e != nil {
		return pl, e
	}
	// "sealed": true is short for hotel_labels {"sealed": "true"}.
	if v, ok := payload["sealed"]; ok && v != nil {
		sealed, ok := v.(bool)
		if !ok {
			return pl, &apiErr{400, "invalid_hotel_selection", "sealed must be true or false"}
		}
		if sealed {
			if pl.match == nil {
				pl.match = map[string]string{}
			}
			pl.match["sealed"] = "true"
		}
	}
	if pl.exclude, e = stringMap(payload["exclude_hotel_labels"], "exclude_hotel_labels"); e != nil {
		return pl, e
	}
	// "sealed": false asks for an unsealed hotel.
	if v, ok := payload["sealed"].(bool); ok && !v {
		if pl.exclude == nil {
			pl.exclude = map[string]string{}
		}
		pl.exclude["sealed"] = "true"
	}
	_, named := payload["hotels"]
	_, sealedField := payload["sealed"]
	b.scope(g, &pl, named && payload["hotels"] != nil, sealedField && payload["sealed"] != nil)
	for _, h := range b.hotelList() {
		if pl.selects(h) {
			return pl, nil
		}
	}
	return pl, &apiErr{409, "no_matching_hotel", "no hotel matches the hotel selection"}
}

// placementFor reads the hotel choice of a create and, for a fork, finds the
// hotel that holds the snapshot.
func (b *broker) placementFor(ctx context.Context, g *guestState, payload map[string]any) (placement, *apiErr) {
	ref, _ := payload["snapshot_id"].(string)
	pl, e := b.parseSelection(g, payload)
	if e != nil && !(ref != "" && e.code == "no_matching_hotel") {
		return pl, e
	}
	if ref == "" {
		return pl, nil
	}
	h, sid, e := b.findSnapshot(ctx, g, ref)
	if e != nil {
		return pl, e
	}
	// A fork goes to its snapshot's hotel. The guest's sealed default does not
	// stop a fork of a snapshot on an unsealed hotel.
	if pl.sealedByDefault && h.labels()["sealed"] != "true" {
		delete(pl.match, "sealed")
		pl.sealedByDefault = false
	}
	if !pl.selects(h) {
		return pl, &apiErr{409, "snapshot_hotel_excluded", "the hotel that holds this snapshot does not match the hotel selection"}
	}
	pl.only, pl.snapshotRef, pl.hotelSnap = h, h.cfg.ID+"."+sid, sid
	return pl, nil
}

// GET /v1/broker/hotels: hotel ids, labels and free rooms, so a guest can choose.
func (b *broker) handleHotels(w http.ResponseWriter, g *guestState) {
	b.mu.Lock()
	out := []map[string]any{}
	for _, h := range b.hotelList() {
		if !g.limits.allows(h.cfg.ID) {
			continue
		}
		free := h.slots - h.used()
		if free < 0 || !h.ok || h.drain() {
			free = 0
		}
		labels := h.labels()
		if labels == nil {
			labels = map[string]string{}
		}
		out = append(out, map[string]any{"id": h.cfg.ID, "name": h.cfg.Name, "labels": labels, "up": h.ok, "drain": h.drain(), "free_rooms": free})
	}
	b.mu.Unlock()
	writeJSON(w, 200, map[string]any{"hotels": out})
}

// ---------------------------------------------------------------- snapshots

// snapshotName is the hotel name of a guest snapshot name. Hotel names are
// global, so the guest id keeps guests apart.
func snapshotName(g *guestState, name string) string { return g.cfg.ID + ":" + name }

// guestSnapshot rewrites one hotel snapshot document for the guest.
func guestSnapshot(g *guestState, h *hotel, doc map[string]any) {
	if sid, ok := doc["snapshot_id"].(string); ok {
		doc["snapshot_id"] = h.cfg.ID + "." + sid
	}
	if name, ok := doc["name"].(string); ok {
		doc["name"] = strings.TrimPrefix(name, g.cfg.ID+":")
	}
	if labels, ok := doc["labels"].(map[string]any); ok {
		delete(labels, guestLabel)
	}
	doc["hotel"] = h.cfg.ID
}

// hotelSnapshots lists the guest's snapshots on one hotel.
func (b *broker) hotelSnapshots(ctx context.Context, g *guestState, h *hotel) ([]map[string]any, error) {
	q := url.Values{"label": {guestLabel + "=" + g.cfg.ID}}
	status, _, out, err := h.do(ctx, "GET", "/v1/snapshots", q, nil, 30*time.Second)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("HTTP %d", status)
	}
	var doc struct {
		Snapshots []map[string]any `json:"snapshots"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, err
	}
	return doc.Snapshots, nil
}

func matchSnapshot(g *guestState, list []map[string]any, ref string) string {
	for _, s := range list {
		sid, _ := s["snapshot_id"].(string)
		name, _ := s["name"].(string)
		if sid == ref || (name != "" && name == snapshotName(g, ref)) {
			return sid
		}
	}
	return ""
}

// findSnapshot finds the hotel and hotel snapshot id of a guest snapshot.
// ref is "<hotel>.<snapshot id or name>", or a bare snapshot name or id.
// The hotel must list the snapshot under the guest's label.
func (b *broker) findSnapshot(ctx context.Context, g *guestState, ref string) (*hotel, string, *apiErr) {
	notFound := &apiErr{404, "snapshot_not_found", "no snapshot " + ref}
	if hotelID, rest, ok := strings.Cut(ref, "."); ok && b.hotelByID(hotelID) != nil {
		h := b.hotelByID(hotelID)
		if !g.limitsAllow(b, h.cfg.ID) {
			return nil, "", notFound
		}
		list, err := b.hotelSnapshots(ctx, g, h)
		if err != nil {
			return nil, "", &apiErr{502, "hotel_unreachable", "hotel " + h.cfg.ID + " did not answer"}
		}
		if sid := matchSnapshot(g, list, rest); sid != "" {
			return h, sid, nil
		}
		return nil, "", notFound
	}
	// A bare name or id: ask every hotel. It must match on exactly one.
	type hit struct {
		h   *hotel
		sid string
	}
	var mu sync.Mutex
	var hits []hit
	var wg sync.WaitGroup
	for _, h := range b.hotelList() {
		if !g.limitsAllow(b, h.cfg.ID) { // a hotel outside the list may hang; it holds none of this guest's snapshots
			continue
		}
		wg.Add(1)
		go func(h *hotel) {
			defer wg.Done()
			list, err := b.hotelSnapshots(ctx, g, h)
			if err != nil {
				return
			}
			if sid := matchSnapshot(g, list, ref); sid != "" {
				mu.Lock()
				hits = append(hits, hit{h, sid})
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	switch len(hits) {
	case 1:
		return hits[0].h, hits[0].sid, nil
	case 0:
		return nil, "", notFound
	default:
		return nil, "", &apiErr{409, "snapshot_ambiguous", "several hotels have a snapshot " + ref + "; use the id <hotel>.<snapshot id>"}
	}
}

// roomSnapshot: POST /v1/sandboxes/<room>/snapshot goes to the room's hotel.
func (b *broker) roomSnapshot(w http.ResponseWriter, r *http.Request, g *guestState, h *hotel, hid string, body []byte) {
	payload := map[string]any{}
	if len(body) > 0 && json.Unmarshal(body, &payload) != nil {
		writeErr(w, 400, "invalid_json", "request body is not JSON")
		return
	}
	labels, _ := payload["labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
	}
	labels[guestLabel] = g.cfg.ID
	payload["labels"] = labels
	if name, ok := payload["name"].(string); ok && name != "" {
		payload["name"] = snapshotName(g, name)
	}
	out, _ := json.Marshal(payload)
	status, _, resp, err := h.do(r.Context(), "POST", "/v1/sandboxes/"+url.PathEscape(hid)+"/snapshot", nil, out, 10*time.Minute)
	if err != nil {
		writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
		return
	}
	var doc map[string]any
	if json.Unmarshal(resp, &doc) != nil {
		writeRaw(w, status, resp)
		return
	}
	if res, ok := doc["result"].(map[string]any); ok {
		guestSnapshot(g, h, res)
	}
	writeJSON(w, status, doc)
}

func writeRaw(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// GET /v1/snapshots: the guest's snapshots on all hotels.
func (b *broker) handleSnapshotList(w http.ResponseWriter, r *http.Request, g *guestState) {
	all := []map[string]any{}
	errs := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range b.hotelList() {
		if !g.limitsAllow(b, h.cfg.ID) {
			continue
		}
		wg.Add(1)
		go func(h *hotel) {
			defer wg.Done()
			list, err := b.hotelSnapshots(r.Context(), g, h)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs[h.cfg.ID] = "unavailable"
				return
			}
			for _, s := range list {
				guestSnapshot(g, h, s)
				all = append(all, s)
			}
		}(h)
	}
	wg.Wait()
	sort.Slice(all, func(i, j int) bool { return fmt.Sprint(all[i]["snapshot_id"]) < fmt.Sprint(all[j]["snapshot_id"]) })
	writeJSON(w, 200, map[string]any{"snapshots": all, "count": len(all), "hotel_errors": errs})
}

// DELETE /v1/snapshots/<id> and POST /v1/snapshots/<id>/push.
func (b *broker) handleSnapshot(w http.ResponseWriter, r *http.Request, g *guestState, rest string) {
	ref, tail, _ := strings.Cut(rest, "/")
	if ref == "" || !((r.Method == "DELETE" && tail == "") || (r.Method == "POST" && tail == "push")) {
		writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+r.URL.Path)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	h, sid, e := b.findSnapshot(r.Context(), g, ref)
	if e != nil {
		writeErr(w, e.status, e.code, e.msg)
		return
	}
	path := "/v1/snapshots/" + url.PathEscape(sid)
	timeout := 2 * time.Minute
	var arg []byte
	if tail == "push" {
		path += "/push"
		timeout = 30 * time.Minute
		arg = body
	}
	status, _, out, err := h.do(r.Context(), r.Method, path, nil, arg, timeout)
	if err != nil {
		writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
		return
	}
	var doc map[string]any
	if json.Unmarshal(out, &doc) == nil && doc["error"] == nil {
		if _, ok := doc["snapshot_id"]; ok {
			guestSnapshot(g, h, doc)
		}
		writeJSON(w, status, doc)
		return
	}
	writeRaw(w, status, out)
}

// ---------------------------------------------------------------- prefetch

type prefetchHotel struct {
	State      string           `json:"state"` // pulling, done, failed
	Images     []map[string]any `json:"images,omitempty"`
	Error      map[string]any   `json:"error,omitempty"`
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt *time.Time       `json:"finished_at,omitempty"`
}

type prefetchJob struct {
	ID      string                    `json:"prefetch_id"`
	guest   string                    // not shown
	Images  []string                  `json:"images"`
	Created time.Time                 `json:"created_at"`
	Hotels  map[string]*prefetchHotel `json:"hotels"`
}

type prefetchJobs struct {
	mu   sync.Mutex
	jobs map[string]*prefetchJob
}

const prefetchKeep = 24 * time.Hour

func newID(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// POST /v1/images/prefetch {images, registry_auth?, hotels?, hotel_labels?, exclude_hotel_labels?}
func (b *broker) handlePrefetch(w http.ResponseWriter, r *http.Request, g *guestState) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req map[string]any
	if err != nil || json.Unmarshal(raw, &req) != nil {
		writeErr(w, 400, "invalid_json", "request body is not JSON")
		return
	}
	list, _ := req["images"].([]any)
	images := []string{}
	for _, x := range list {
		if s, ok := x.(string); ok && s != "" {
			images = append(images, s)
		}
	}
	if len(images) == 0 || len(images) != len(list) {
		writeErr(w, 400, "invalid_prefetch", "images must be a non-empty list of image references")
		return
	}
	pl, e := b.parseSelection(g, req)
	if e != nil {
		writeErr(w, e.status, e.code, e.msg)
		return
	}
	hotelBody := map[string]any{"images": images}
	if auth, ok := req["registry_auth"]; ok && auth != nil {
		hotelBody["registry_auth"] = auth // passed to the hotels, never stored
	}
	body, _ := json.Marshal(hotelBody)

	job := &prefetchJob{ID: newID("pf_"), guest: g.cfg.ID, Images: images, Created: time.Now().UTC(), Hotels: map[string]*prefetchHotel{}}
	var targets []*hotel
	for _, h := range b.hotelList() {
		if pl.selects(h) {
			targets = append(targets, h)
			job.Hotels[h.cfg.ID] = &prefetchHotel{State: "pulling", StartedAt: job.Created}
		}
	}
	b.prefetch.mu.Lock()
	if b.prefetch.jobs == nil {
		b.prefetch.jobs = map[string]*prefetchJob{}
	}
	for id, j := range b.prefetch.jobs {
		if time.Since(j.Created) > prefetchKeep {
			delete(b.prefetch.jobs, id)
		}
	}
	b.prefetch.jobs[job.ID] = job
	view := b.prefetchView(job)
	b.prefetch.mu.Unlock()

	for _, h := range targets {
		go b.prefetchOn(h, job, body)
	}
	writeJSON(w, 202, view)
}

// prefetchOn pulls the images on one hotel. A pull can take minutes, so it
// does not use the guest request context.
func (b *broker) prefetchOn(h *hotel, job *prefetchJob, body []byte) {
	status, _, out, err := h.do(context.Background(), "POST", "/v1/images/prefetch", nil, body, 30*time.Minute)
	var doc map[string]any
	_ = json.Unmarshal(out, &doc)
	now := time.Now().UTC()
	b.prefetch.mu.Lock()
	defer b.prefetch.mu.Unlock()
	st := job.Hotels[h.cfg.ID]
	st.FinishedAt = &now
	switch {
	case err != nil:
		st.State, st.Error = "failed", map[string]any{"code": "hotel_unreachable", "message": "hotel " + h.cfg.ID + " did not answer"}
	case status == 200 || status == 202:
		st.State = "done"
		if res, ok := doc["result"].(map[string]any); ok {
			if imgs, ok := res["images"].([]any); ok {
				for _, x := range imgs {
					if m, ok := x.(map[string]any); ok {
						st.Images = append(st.Images, m)
					}
				}
			}
		}
	default:
		st.State = "failed"
		st.Error = map[string]any{"code": "prefetch_failed", "message": fmt.Sprintf("hotel answered %d", status)}
		if e, ok := doc["error"].(map[string]any); ok {
			st.Error = map[string]any{"code": e["code"], "message": e["message"], "status": status}
		}
	}
}

// prefetchView is a copy of the job for the guest. Caller holds b.prefetch.mu.
func (b *broker) prefetchView(job *prefetchJob) map[string]any {
	hotels := map[string]any{}
	summary := map[string]int{"pulling": 0, "done": 0, "failed": 0}
	for id, st := range job.Hotels {
		cp := *st
		hotels[id] = cp
		summary[st.State]++
	}
	state := "done"
	if summary["pulling"] > 0 {
		state = "pulling"
	} else if summary["failed"] > 0 {
		state = "failed"
	}
	return map[string]any{"prefetch_id": job.ID, "images": job.Images, "created_at": job.Created, "state": state, "summary": summary, "hotels": hotels}
}

// GET /v1/images/prefetch/<id>
func (b *broker) handlePrefetchStatus(w http.ResponseWriter, g *guestState, id string) {
	b.prefetch.mu.Lock()
	job := b.prefetch.jobs[id]
	if job == nil || job.guest != g.cfg.ID {
		b.prefetch.mu.Unlock()
		writeErr(w, 404, "prefetch_not_found", "no prefetch "+id)
		return
	}
	view := b.prefetchView(job)
	b.prefetch.mu.Unlock()
	writeJSON(w, 200, view)
}
