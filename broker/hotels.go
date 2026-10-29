// Hotels that join and leave at runtime (ctcli "hotel join").
//
// The config file lists the first hotels. An operator adds, changes and
// removes hotels with the operator key (config "operator_key_sha256"):
//
//	GET    /v1/broker/hotels/<id>   the hotel document with its admission state
//	POST   /v1/broker/hotels        {id, name, api, health, key, concurrency, labels, threads, ram_gib, sealed, max_slots, reserved_for, miner_hotkey}
//	PATCH  /v1/broker/hotels/<id>   {drain, labels, reserved_for, max_slots}  (reserved_for null: back to the pool)
//	DELETE /v1/broker/hotels/<id>   (only a hotel with no rooms; drain it first)
//
// A hotel added at runtime is kept in state_dir/hotels.json, and its key in
// state_dir/hotel-keys/<id>.key (mode 0600). A hotel from the config file
// cannot be removed at runtime; change the config file instead.
//
// A joined hotel takes rooms only after it passes admission (admission.go):
// health, and for a sealed hotel an SEV-SNP attestation check. A join with
// verify (the default) checks the attestation of a sealed hotel at once and
// refuses the hotel (422 attestation_failed) when the check fails.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
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

var (
	errMinerNotApproved      = errors.New("miner hotkey is not approved for broker hotels")
	errMinerCapReached       = errors.New("miner hotkey hotel cap reached")
	errMinerGlobalCapUnset   = errors.New("miner global hotel cap is not configured")
	errMinerGlobalCapReached = errors.New("miner global hotel cap reached")
)

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
	hc.Labels = fixedLabels(hc, hc.Labels)
	tr := &http.Transport{MaxIdleConns: 1024, MaxIdleConnsPerHost: hc.Concurrency + 64, MaxConnsPerHost: hc.Concurrency + 64, IdleConnTimeout: 90 * time.Second}
	// The sync loop (health, quota, list) uses its own small pool: when one
	// guest's long execs hold every data connection, the hotel must not look down.
	ctl := &http.Transport{MaxIdleConns: 8, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 8, IdleConnTimeout: 90 * time.Second}
	h := &hotel{cfg: hc, key: key, client: &http.Client{Transport: tr}, ctl: &http.Client{Transport: ctl}, sem: make(chan struct{}, hc.Concurrency), rooms: map[string]*room{}}
	h.tlsPinErr = pinMinerHotel(h)
	return h
}

// fixedLabels is labels plus the labels a hotel always carries: sealed=true
// for a sealed hotel (guests select it by that label), miner=true and
// miner_hotkey for a miner hotel (guests deny it by that label). It returns a
// new map when it adds any.
func fixedLabels(hc hotelConfig, labels map[string]string) map[string]string {
	if !hc.Sealed && hc.MinerHotkey == "" {
		return labels
	}
	out := map[string]string{}
	for k, v := range labels {
		out[k] = v
	}
	if hc.Sealed {
		out["sealed"] = "true"
	}
	if hc.MinerHotkey != "" {
		out["miner"] = "true"
		out["miner_hotkey"] = hc.MinerHotkey
	}
	return out
}

// labels and drain read the fields an operator PATCH may change at any time.
func (h *hotel) labels() map[string]string {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.cfg.Labels
}

// reservedFor is the guest the hotel is reserved for, or "" for a pool hotel.
func (h *hotel) reservedFor() string {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.cfg.ReservedFor
}

func (h *hotel) drain() bool {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.cfg.Drain
}

// addHotel adds h to the hotel set. The caller starts its sync loop.
func (b *broker) addHotel(h *hotel) error {
	return b.addHotelWithCapCheck(h, true)
}

// addHotelRestored retains an existing runtime hotel even if admission caps
// have since tightened. Caps govern new joins, not recovery of live hotels.
func (b *broker) addHotelRestored(h *hotel) error {
	return b.addHotelWithCapCheck(h, false)
}

func (b *broker) addHotelWithCapCheck(h *hotel, checkCaps bool) error {
	if strings.Contains(h.cfg.ID, ".") || h.cfg.ID == "" {
		return fmt.Errorf("hotel id %q: must be non-empty and have no dot", h.cfg.ID)
	}
	b.mu.Lock()
	if h.caps == nil && b.capsOnDisk[h.cfg.ID] != nil { // a runtime hotel keeps its probe results
		h.caps = b.capsOnDisk[h.cfg.ID]
	}
	b.mu.Unlock()
	b.hotelsMu.Lock()
	defer b.hotelsMu.Unlock()
	old := b.hset.Load()
	if hotkey := h.cfg.MinerHotkey; checkCaps && hotkey != "" {
		cap := b.cfg.MinerHotkeyCaps[hotkey]
		if cap < 1 {
			return errMinerNotApproved
		}
		if b.cfg.MinerMaxHotels < 1 {
			return errMinerGlobalCapUnset
		}
		used, total := 0, 0
		if old != nil {
			for _, existing := range old.list {
				if existing.cfg.MinerHotkey != "" {
					total++
				}
				if existing.cfg.MinerHotkey == hotkey {
					used++
				}
			}
		}
		if used >= cap {
			return fmt.Errorf("%w (%d)", errMinerCapReached, cap)
		}
		if total >= b.cfg.MinerMaxHotels {
			return fmt.Errorf("%w (%d)", errMinerGlobalCapReached, b.cfg.MinerMaxHotels)
		}
	}
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

// minerOverCap reports whether an existing miner hotel falls outside today's
// caps, in stable hotel order. A drained hotel still consumes a cap slot.
func (b *broker) minerOverCap(h *hotel) bool {
	hotkey := h.cfg.MinerHotkey
	if hotkey == "" {
		return false
	}
	cap := b.cfg.MinerHotkeyCaps[hotkey]
	if cap < 1 || b.cfg.MinerMaxHotels < 1 {
		return true
	}
	used, total := 0, 0
	for _, existing := range b.hotelList() {
		if existing == h {
			return used >= cap || total >= b.cfg.MinerMaxHotels
		}
		if existing.cfg.MinerHotkey != "" {
			total++
		}
		if existing.cfg.MinerHotkey == hotkey {
			used++
		}
	}
	return true
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

// dropHotelIf avoids removing a replacement that joined under the same id
// while an earlier leave was waiting for room state to settle.
func (b *broker) dropHotelIf(id string, expected *hotel) bool {
	b.hotelsMu.Lock()
	defer b.hotelsMu.Unlock()
	old := b.hset.Load()
	if old == nil || old.byID[id] != expected {
		return false
	}
	next := &hotelSet{byID: map[string]*hotel{}}
	for _, h := range old.list {
		if h != expected {
			next.list = append(next.list, h)
			next.byID[h.cfg.ID] = h
		}
	}
	b.hset.Store(next)
	return true
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

func (b *broker) isMinerEnroller(r *http.Request) bool {
	want := strings.ToLower(b.cfg.MinerEnrollKeySHA256)
	a := r.Header.Get("Authorization")
	if want == "" || len(a) < 8 || !strings.EqualFold(a[:7], "bearer ") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sha(strings.TrimSpace(a[7:]))), []byte(want)) == 1
}

var (
	hotelKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{32,}$`)
	ss58RE     = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{46,48}$`)
)

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
	operator := b.isOperator(r)
	enroller := !operator && b.isMinerEnroller(r)
	if !operator && !enroller {
		writeErr(w, 401, "unauthorized", "a hotel administration key is required")
		return
	}
	hotelID, action, hadAction := strings.Cut(id, "/")
	if hadAction && action == "escape-nonce" && hotelID != "" && r.Method == "POST" {
		if !operator {
			writeErr(w, 403, "enroller_scope", "miner enrollment cannot plant Escape nonces")
			return
		}
		b.handleEscapeNoncePlant(w, r, hotelID)
		return
	}
	switch {
	case id != "" && r.Method == "GET":
		h := b.hotelByID(id)
		if h == nil {
			writeErr(w, 404, "hotel_not_found", "no hotel "+id)
			return
		}
		if enroller && h.cfg.MinerHotkey == "" {
			writeErr(w, 403, "enroller_scope", "miner enrollment can read only miner hotels")
			return
		}
		writeJSON(w, 200, b.hotelDoc(h))
	case id == "" && r.Method == "POST":
		b.joinHotel(w, r, enroller)
	case id != "" && r.Method == "PATCH":
		b.patchHotel(w, r, id, enroller)
	case id != "" && r.Method == "DELETE":
		b.leaveHotel(w, id, enroller)
	default:
		writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+r.URL.Path)
	}
}

func (b *broker) joinHotel(w http.ResponseWriter, r *http.Request, enroller bool) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req joinRequest
	if json.Unmarshal(raw, &req) != nil {
		writeErr(w, 400, "invalid_json", "request body is not JSON")
		return
	}
	hc := req.hotelConfig
	if enroller {
		if hc.MinerHotkey == "" || !hc.Sealed || (req.Verify != nil && !*req.Verify) ||
			hc.ReservedFor != "" || hc.Labels != nil ||
			!strings.HasPrefix(hc.API, "https://") || (hc.Health != "" && !strings.HasPrefix(hc.Health, "https://")) {
			writeErr(w, 403, "enroller_scope", "miner enrollment requires a verified HTTPS sealed miner hotel without custom labels or reservation")
			return
		}
	}
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
	case hc.MinerHotkey != "" && !ss58RE.MatchString(hc.MinerHotkey):
		writeErr(w, 400, "invalid_hotel", "miner_hotkey must be an SS58 address")
		return
	case hc.MinerHotkey != "" && !hc.Sealed:
		writeErr(w, 400, "invalid_hotel", "miner hotels must be sealed")
		return
	case !hc.Sealed && hc.Labels["sealed"] == "true":
		writeErr(w, 400, "invalid_hotel", "unsealed hotels cannot claim the sealed label")
		return
	case hc.MaxSlots < 0:
		writeErr(w, 400, "invalid_hotel", "max_slots must be 0 (no cap) or more")
		return
	}
	if b.cfg.StateDir == "" {
		writeErr(w, 409, "no_state_dir", "set state_dir in the config to add hotels at runtime")
		return
	}
	if hc.Health == "" {
		hc.Health = hc.API
	}
	if hc.MinerHotkey != "" {
		if hc.TLSSPKISHA256 != "" || (req.Verify != nil && !*req.Verify) ||
			!strings.HasPrefix(hc.API, "https://") || !strings.HasPrefix(hc.Health, "https://") {
			writeErr(w, 409, "guest_tls_required", "miner join needs verified guest HTTPS; the broker derives its TLS pin from attestation")
			return
		}
		// This request has no bearer key. Verify that the observed TLS key is
		// committed by the AMD-verified SNP report before constructing a hotel
		// client that holds the key supplied in the join body.
		rawAtt, peerSPKI, err := fetchMinerAttestation(r.Context(), hc.Health)
		if err != nil {
			writeErr(w, 422, "attestation_failed", "the miner guest did not answer keyless HTTPS attestation")
			return
		}
		if err := b.verifyMinerBootstrap(r.Context(), rawAtt, peerSPKI); err != nil {
			writeErr(w, 422, "attestation_failed", "the miner guest TLS attestation did not pass: "+err.Error())
			return
		}
		hc.TLSSPKISHA256 = peerSPKI
	}
	if hc.Name == "" {
		hc.Name = hc.ID
	}
	if b.hotelByID(hc.ID) != nil {
		writeErr(w, 409, "hotel_exists", "hotel "+hc.ID+" exists")
		return
	}
	if hc.ReservedFor != "" && !b.guestExists(hc.ReservedFor) {
		writeErr(w, 409, "unknown_guest", "reserved_for names no guest "+hc.ReservedFor)
		return
	}
	h := newHotel(hc, req.Key)
	h.runtime = true
	if req.Verify == nil || *req.Verify {
		var st map[string]any
		if err := h.getJSON(r.Context(), hc.API, "/v1/status", nil, &st); err != nil {
			writeErr(w, 502, "hotel_unreachable", "the hotel did not answer GET /v1/status with this key")
			return
		}
		// A sealed hotel shows its attestation before it joins, so a bad
		// one is refused here and not left pending.
		b.mu.Lock()
		need := b.needsAttestation(h)
		b.mu.Unlock()
		if need {
			res, err := b.checkAttestation(r.Context(), h)
			if err != nil {
				writeErr(w, 422, "attestation_failed", "the hotel's SEV-SNP attestation did not pass: "+err.Error())
				return
			}
			b.mu.Lock()
			err = b.noteAttestation(h, res, nil, time.Now())
			b.mu.Unlock()
			if err != nil {
				writeErr(w, 409, "chip_in_use", err.Error())
				return
			}
		}
	}
	keyDir := filepath.Join(b.cfg.StateDir, "hotel-keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		writeErr(w, 500, "state_write_failed", "cannot keep the hotel key")
		return
	}
	h.cfg.KeyFile = filepath.Join(keyDir, hc.ID+".key")
	b.hotelsMutationMu.Lock()
	defer b.hotelsMutationMu.Unlock()
	// The stop function is set before the hotel is in the set, so a leave
	// that races this join reads it set.
	ctx, cancel := context.WithCancel(context.Background())
	h.stop = cancel
	// Add first, then write the key: of two joins with one id, only the
	// one that is added writes the key file. The hotel joins "leaving" (no
	// rooms) until the chip check below, made once it is in the set: of two
	// joins with one chip at once, the second to take b.mu sees the first.
	h.leaving = true
	if err := b.addHotel(h); err != nil {
		cancel()
		if errors.Is(err, errMinerNotApproved) {
			writeErr(w, 403, "miner_not_approved", err.Error())
			return
		}
		if errors.Is(err, errMinerCapReached) {
			writeErr(w, 409, "miner_cap_reached", err.Error())
			return
		}
		if errors.Is(err, errMinerGlobalCapUnset) {
			writeErr(w, 403, "miner_global_cap_unset", err.Error())
			return
		}
		if errors.Is(err, errMinerGlobalCapReached) {
			writeErr(w, 409, "miner_global_cap_reached", err.Error())
			return
		}
		writeErr(w, 409, "hotel_exists", err.Error())
		return
	}
	b.mu.Lock()
	var holder *hotel
	if h.adm.chipFull != "" && !h.adm.attestedAt.IsZero() {
		holder = b.chipHolder(h, h.adm.chipFull, time.Now())
	}
	if holder != nil {
		h.adm.attestedAt = time.Time{}
	}
	b.mu.Unlock()
	if holder != nil {
		b.dropHotel(h.cfg.ID)
		cancel()
		writeErr(w, 409, "chip_in_use", errChipInUse{other: holder.cfg.ID, chip: h.adm.chipID}.Error())
		return
	}
	if err := os.WriteFile(h.cfg.KeyFile, []byte(req.Key+"\n"), 0o600); err != nil {
		b.dropHotel(h.cfg.ID)
		cancel()
		writeErr(w, 500, "state_write_failed", "cannot keep the hotel key")
		return
	}
	b.mu.Lock()
	err := b.saveRuntimeHotelsLocked()
	if err == nil {
		h.leaving = false
	}
	b.mu.Unlock()
	if err != nil {
		log.Printf("runtime hotels not saved: %v", err)
		b.dropHotel(h.cfg.ID)
		cancel()
		_ = os.Remove(h.cfg.KeyFile)
		writeErr(w, 500, "state_write_failed", "cannot keep the runtime hotel list")
		return
	}
	go b.syncLoop(ctx, h)
	writeJSON(w, 201, b.hotelDoc(h))
}

func (b *broker) patchHotel(w http.ResponseWriter, r *http.Request, id string, enroller bool) {
	b.hotelsMutationMu.Lock()
	defer b.hotelsMutationMu.Unlock()
	h := b.hotelByID(id)
	if h == nil {
		writeErr(w, 404, "hotel_not_found", "no hotel "+id)
		return
	}
	if enroller && h.cfg.MinerHotkey == "" {
		writeErr(w, 403, "enroller_scope", "miner enrollment can drain only miner hotels")
		return
	}
	var req struct {
		Drain       *bool             `json:"drain"`
		MaxSlots    *int              `json:"max_slots"` // per-hotel room cap; 0: the hotel's own slots
		Labels      map[string]string `json:"labels"`
		ReservedFor json.RawMessage   `json:"reserved_for"` // a guest id, or null to release
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if json.Unmarshal(raw, &req) != nil {
		writeErr(w, 400, "invalid_json", "request body is not JSON")
		return
	}
	if enroller && (req.Drain == nil || !*req.Drain || req.MaxSlots != nil || req.Labels != nil || len(req.ReservedFor) != 0) {
		writeErr(w, 403, "enroller_scope", "miner enrollment may only set drain=true")
		return
	}
	if req.Drain != nil && !*req.Drain && b.minerOverCap(h) {
		writeErr(w, 409, "miner_cap_reached", "hotel is outside the current miner admission caps")
		return
	}
	if req.MaxSlots != nil && *req.MaxSlots < 0 {
		writeErr(w, 400, "invalid_hotel", "max_slots must be 0 (no cap) or more")
		return
	}
	if h.runtime && !h.cfg.Sealed && req.Labels["sealed"] == "true" {
		writeErr(w, 400, "invalid_hotel", "unsealed hotels cannot claim the sealed label")
		return
	}
	var reserve *string
	if len(req.ReservedFor) > 0 {
		v := ""
		if string(req.ReservedFor) != "null" {
			if json.Unmarshal(req.ReservedFor, &v) != nil || v == "" {
				writeErr(w, 400, "invalid_json", "reserved_for must be a guest id or null")
				return
			}
			if !b.guestExists(v) {
				writeErr(w, 409, "unknown_guest", "reserved_for names no guest "+v)
				return
			}
		}
		reserve = &v
	}
	b.mu.Lock()
	h.cfgMu.Lock()
	oldCfg := h.cfg
	if req.Drain != nil {
		h.cfg.Drain = *req.Drain
	}
	if req.Labels != nil {
		// The sealed and miner labels stay: guests select and deny by them.
		h.cfg.Labels = fixedLabels(h.cfg, req.Labels)
	}
	if req.MaxSlots != nil {
		h.cfg.MaxSlots = *req.MaxSlots
	}
	if reserve != nil {
		h.cfg.ReservedFor = *reserve
	}
	h.cfgMu.Unlock()
	if h.runtime {
		if err := b.saveRuntimeHotelsLocked(); err != nil {
			log.Printf("runtime hotels not saved: %v", err)
			h.cfgMu.Lock()
			h.cfg.Drain = oldCfg.Drain
			h.cfg.Labels = oldCfg.Labels
			h.cfg.MaxSlots = oldCfg.MaxSlots
			h.cfg.ReservedFor = oldCfg.ReservedFor
			h.cfgMu.Unlock()
			b.mu.Unlock()
			writeErr(w, 500, "state_write_failed", "cannot keep the runtime hotel update")
			return
		}
	}
	if req.MaxSlots != nil {
		if h.cfg.MaxSlots > 0 && h.slots > h.cfg.MaxSlots {
			h.resize(h.cfg.MaxSlots)
		}
	}
	b.mu.Unlock()
	writeJSON(w, 200, b.hotelDoc(h))
}

func (b *broker) leaveHotel(w http.ResponseWriter, id string, enroller bool) {
	b.hotelsMutationMu.Lock()
	defer b.hotelsMutationMu.Unlock()
	h := b.hotelByID(id)
	if h == nil {
		writeErr(w, 404, "hotel_not_found", "no hotel "+id)
		return
	}
	if enroller && h.cfg.MinerHotkey == "" {
		writeErr(w, 403, "enroller_scope", "miner enrollment can leave only miner hotels")
		return
	}
	if !h.runtime {
		writeErr(w, 409, "hotel_in_config", "hotel "+id+" is in the config file; remove it there")
		return
	}
	// The check and the mark are one step under b.mu: pick holds b.mu, so
	// no create can be placed on the hotel between "empty" and "gone".
	b.mu.Lock()
	busy := len(h.rooms) + h.creating + h.queued
	leaving := h.leaving
	if busy == 0 {
		h.leaving = true
	}
	b.mu.Unlock()
	if leaving {
		writeErr(w, 404, "hotel_not_found", "hotel "+id+" is leaving")
		return
	}
	if busy > 0 {
		writeErr(w, 409, "hotel_not_empty", fmt.Sprintf("hotel %s has %d rooms; drain it and wait until they are gone", id, busy))
		return
	}
	if !b.dropHotelIf(id, h) {
		writeErr(w, 409, "hotel_changed", "hotel changed during leave; retry")
		return
	}
	b.mu.Lock()
	err := b.saveRuntimeHotelsLocked()
	b.mu.Unlock()
	if err != nil {
		log.Printf("runtime hotels not saved: %v", err)
		if addErr := b.addHotelRestored(h); addErr != nil {
			log.Printf("runtime hotel %s could not be restored after failed save: %v", id, addErr)
		}
		b.mu.Lock()
		h.leaving = false
		b.mu.Unlock()
		writeErr(w, 500, "state_write_failed", "cannot keep the runtime hotel removal")
		return
	}
	if h.stop != nil {
		h.stop()
	}
	_ = os.Remove(h.cfg.KeyFile)
	w.WriteHeader(204)
}

func (b *broker) hotelDoc(h *hotel) map[string]any {
	labels := h.labels()
	if labels == nil {
		labels = map[string]string{}
	}
	var reserved any
	if r := h.reservedFor(); r != "" {
		reserved = r
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	return map[string]any{"id": h.cfg.ID, "name": h.cfg.Name, "labels": labels, "drain": h.drain(), "runtime": h.runtime,
		"reserved_for": reserved, "class": hotelClass(h), "up": h.ok, "slots": h.slots, "max_slots": h.cfg.MaxSlots,
		"free_rooms": b.admissibleFree(h, now), "miner_hotkey": h.cfg.MinerHotkey, "admission": b.admissionDoc(h, now)}
}

func (b *broker) guestExists(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.guests[id] != nil
}

// ---------------------------------------------------------------- persistence

const runtimeHotelsFile = "hotels.json"

// saveRuntimeHotelsLocked keeps the current runtime snapshot stable through
// the atomic file replacement. Callers hold b.mu and hotelsMutationMu.
func (b *broker) saveRuntimeHotelsLocked() error {
	var list []hotelConfig
	for _, h := range b.hotelList() {
		if h.runtime {
			list = append(list, h.cfg)
		}
	}
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
		if hc.MinerHotkey != "" && hc.TLSSPKISHA256 == "" {
			log.Printf("runtime miner hotel %s skipped: no attested TLS pin", hc.ID)
			continue
		}
		k, err := os.ReadFile(hc.KeyFile)
		if err != nil {
			log.Printf("runtime hotel %s skipped: key: %v", hc.ID, err)
			continue
		}
		h := newHotel(hc, strings.TrimSpace(string(k)))
		h.runtime = true
		if err := b.addHotelRestored(h); err != nil {
			log.Printf("runtime hotel %s skipped: %v", hc.ID, err)
		}
	}
	// Keep every restored hotel in the snapshot, but stop new placement on any
	// miner hotel outside the current per-hotkey or global admission limits.
	for _, h := range b.hotelList() {
		if b.minerOverCap(h) {
			h.cfgMu.Lock()
			h.cfg.Drain = true
			h.cfgMu.Unlock()
			log.Printf("runtime miner hotel %s retained but drained: admission cap changed", h.cfg.ID)
		}
	}
	return nil
}
