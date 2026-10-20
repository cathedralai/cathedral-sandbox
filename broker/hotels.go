// Hotels that join and leave at runtime (ctcli "hotel join").
//
// The config file lists the first hotels. An operator adds, changes and
// removes hotels with the operator key (config "operator_key_sha256"):
//
//	POST   /v1/broker/hotels        {id, name, api, health, key, concurrency, labels, threads, ram_gib}
//	PATCH  /v1/broker/hotels/<id>   {drain, labels}
//	DELETE /v1/broker/hotels/<id>   (only a hotel with no rooms; drain it first)
//
// A hotel added at runtime is kept in state_dir/hotels.json, and its key in
// state_dir/hotel-keys/<id>.key (mode 0600). A hotel from the config file
// cannot be removed at runtime; change the config file instead.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// hotelSet is an immutable list of hotels. A join or a leave replaces it.
type hotelSet struct {
	list []*hotel
	byID map[string]*hotel
}

func (b *broker) hotelList() []*hotel {
	if s := b.hset.Load(); s != nil {
		return s.list
	}
	return nil
}

func (b *broker) hotelByID(id string) *hotel {
	if s := b.hset.Load(); s != nil {
		return s.byID[id]
	}
	return nil
}

func newHotel(hc hotelConfig, key string) *hotel {
	if hc.Concurrency <= 0 {
		hc.Concurrency = 16
	}
	if hc.Sealed { // a sealed hotel always carries the label guests select it by
		labels := map[string]string{"sealed": "true"}
		for k, v := range hc.Labels {
			labels[k] = v
		}
		labels["sealed"] = "true"
		hc.Labels = labels
	}
	tr := &http.Transport{MaxIdleConns: 1024, MaxIdleConnsPerHost: hc.Concurrency + 64, MaxConnsPerHost: hc.Concurrency + 64, IdleConnTimeout: 90 * time.Second}
	return &hotel{cfg: hc, key: key, client: &http.Client{Transport: tr}, sem: make(chan struct{}, hc.Concurrency), rooms: map[string]*room{}}
}

// addHotel adds h to the hotel set. The caller starts its sync loop.
func (b *broker) addHotel(h *hotel) error {
	if strings.Contains(h.cfg.ID, ".") || h.cfg.ID == "" {
		return fmt.Errorf("hotel id %q: must be non-empty and have no dot", h.cfg.ID)
	}
	b.hotelsMu.Lock()
	defer b.hotelsMu.Unlock()
	old := b.hset.Load()
	next := &hotelSet{byID: map[string]*hotel{}}
	if old != nil {
		if old.byID[h.cfg.ID] != nil {
			return fmt.Errorf("hotel %s exists", h.cfg.ID)
		}
		next.list = append(next.list, old.list...)
		for k, v := range old.byID {
			next.byID[k] = v
		}
	}
	next.list = append(next.list, h)
	next.byID[h.cfg.ID] = h
	b.hset.Store(next)
	return nil
}

func (b *broker) dropHotel(id string) {
	b.hotelsMu.Lock()
	defer b.hotelsMu.Unlock()
	old := b.hset.Load()
	next := &hotelSet{byID: map[string]*hotel{}}
	for _, h := range old.list {
		if h.cfg.ID != id {
			next.list = append(next.list, h)
			next.byID[h.cfg.ID] = h
		}
	}
	b.hset.Store(next)
}

// startSync runs the sync loop of h until the hotel leaves.
func (b *broker) startSync(ctx context.Context, h *hotel) {
	ctx, cancel := context.WithCancel(ctx)
	h.stop = cancel
	go b.syncLoop(ctx, h)
}

// ---------------------------------------------------------------- operator routes

func (b *broker) isOperator(r *http.Request) bool {
	want := strings.ToLower(b.cfg.OperatorKeySHA256)
	a := r.Header.Get("Authorization")
	if want == "" || len(a) < 8 || !strings.EqualFold(a[:7], "bearer ") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sha(strings.TrimSpace(a[7:]))), []byte(want)) == 1
}

var hotelKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{32,}$`)

type joinRequest struct {
	hotelConfig
	Key    string `json:"key"`
	Verify *bool  `json:"verify"` // default true: the broker calls the hotel before it adds it
}

func validURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil
}

func (b *broker) handleHotelAdmin(w http.ResponseWriter, r *http.Request, id string) {
	if !b.isOperator(r) {
		writeErr(w, 401, "unauthorized", "the operator key is required")
		return
	}
	switch {
	case id == "" && r.Method == "POST":
		b.joinHotel(w, r)
	case id != "" && r.Method == "PATCH":
		b.patchHotel(w, r, id)
	case id != "" && r.Method == "DELETE":
		b.leaveHotel(w, id)
	default:
		writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+r.URL.Path)
	}
}

func (b *broker) joinHotel(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req joinRequest
	if json.Unmarshal(raw, &req) != nil {
		writeErr(w, 400, "invalid_json", "request body is not JSON")
		return
	}
	hc := req.hotelConfig
	switch {
	case hc.ID == "" || strings.Contains(hc.ID, ".") || len(hc.ID) > 64:
		writeErr(w, 400, "invalid_hotel", "id must be 1 to 64 characters with no dot")
		return
	case !validURL(hc.API):
		writeErr(w, 400, "invalid_hotel", "api must be an http or https URL")
		return
	case hc.Health != "" && !validURL(hc.Health):
		writeErr(w, 400, "invalid_hotel", "health must be an http or https URL")
		return
	case !hotelKeyRE.MatchString(req.Key):
		writeErr(w, 400, "invalid_hotel", "key must be 32 or more characters [A-Za-z0-9_-]")
		return
	}
	if b.cfg.StateDir == "" {
		writeErr(w, 409, "no_state_dir", "set state_dir in the config to add hotels at runtime")
		return
	}
	if hc.Health == "" {
		hc.Health = hc.API
	}
	if hc.Name == "" {
		hc.Name = hc.ID
	}
	if b.hotelByID(hc.ID) != nil {
		writeErr(w, 409, "hotel_exists", "hotel "+hc.ID+" exists")
		return
	}
	h := newHotel(hc, req.Key)
	if req.Verify == nil || *req.Verify {
		var st map[string]any
		if err := h.getJSON(r.Context(), hc.API, "/v1/status", nil, &st); err != nil {
			writeErr(w, 502, "hotel_unreachable", "the hotel did not answer GET /v1/status with this key")
			return
		}
	}
	keyDir := filepath.Join(b.cfg.StateDir, "hotel-keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		writeErr(w, 500, "state_write_failed", "cannot keep the hotel key")
		return
	}
	h.cfg.KeyFile = filepath.Join(keyDir, hc.ID+".key")
	if err := os.WriteFile(h.cfg.KeyFile, []byte(req.Key+"\n"), 0o600); err != nil {
		writeErr(w, 500, "state_write_failed", "cannot keep the hotel key")
		return
	}
	h.runtime = true
	if err := b.addHotel(h); err != nil {
		writeErr(w, 409, "hotel_exists", err.Error())
		return
	}
	if err := b.saveRuntimeHotels(); err != nil {
		log.Printf("runtime hotels not saved: %v", err)
	}
	b.startSync(context.Background(), h)
	writeJSON(w, 201, hotelDoc(h))
}

func (b *broker) patchHotel(w http.ResponseWriter, r *http.Request, id string) {
	h := b.hotelByID(id)
	if h == nil {
		writeErr(w, 404, "hotel_not_found", "no hotel "+id)
		return
	}
	var req struct {
		Drain  *bool             `json:"drain"`
		Labels map[string]string `json:"labels"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if json.Unmarshal(raw, &req) != nil {
		writeErr(w, 400, "invalid_json", "request body is not JSON")
		return
	}
	b.mu.Lock()
	if req.Drain != nil {
		h.cfg.Drain = *req.Drain
	}
	if req.Labels != nil {
		h.cfg.Labels = req.Labels
	}
	b.mu.Unlock()
	if h.runtime {
		if err := b.saveRuntimeHotels(); err != nil {
			log.Printf("runtime hotels not saved: %v", err)
		}
	}
	writeJSON(w, 200, hotelDoc(h))
}

func (b *broker) leaveHotel(w http.ResponseWriter, id string) {
	h := b.hotelByID(id)
	if h == nil {
		writeErr(w, 404, "hotel_not_found", "no hotel "+id)
		return
	}
	if !h.runtime {
		writeErr(w, 409, "hotel_in_config", "hotel "+id+" is in the config file; remove it there")
		return
	}
	b.mu.Lock()
	busy := len(h.rooms) + h.creating + h.queued
	b.mu.Unlock()
	if busy > 0 {
		writeErr(w, 409, "hotel_not_empty", fmt.Sprintf("hotel %s has %d rooms; drain it and wait until they are gone", id, busy))
		return
	}
	b.dropHotel(id)
	if h.stop != nil {
		h.stop()
	}
	if err := b.saveRuntimeHotels(); err != nil {
		log.Printf("runtime hotels not saved: %v", err)
	}
	_ = os.Remove(h.cfg.KeyFile)
	w.WriteHeader(204)
}

func hotelDoc(h *hotel) map[string]any {
	labels := h.cfg.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	return map[string]any{"id": h.cfg.ID, "name": h.cfg.Name, "labels": labels, "drain": h.cfg.Drain, "runtime": h.runtime}
}

// ---------------------------------------------------------------- persistence

const runtimeHotelsFile = "hotels.json"

func (b *broker) saveRuntimeHotels() error {
	var list []hotelConfig
	b.mu.Lock()
	for _, h := range b.hotelList() {
		if h.runtime {
			list = append(list, h.cfg)
		}
	}
	b.mu.Unlock()
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(b.cfg.StateDir, runtimeHotelsFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(b.cfg.StateDir, runtimeHotelsFile))
}

// loadRuntimeHotels adds the hotels that joined at runtime before a restart.
// The caller starts their sync loops.
func (b *broker) loadRuntimeHotels() error {
	if b.cfg.StateDir == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(b.cfg.StateDir, runtimeHotelsFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var list []hotelConfig
	if err := json.Unmarshal(raw, &list); err != nil {
		return err
	}
	for _, hc := range list {
		k, err := os.ReadFile(hc.KeyFile)
		if err != nil {
			log.Printf("runtime hotel %s skipped: key: %v", hc.ID, err)
			continue
		}
		h := newHotel(hc, strings.TrimSpace(string(k)))
		h.runtime = true
		if err := b.addHotel(h); err != nil {
			log.Printf("runtime hotel %s skipped: %v", hc.ID, err)
		}
	}
	return nil
}
