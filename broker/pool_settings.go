// Ready rooms, settings (AB#894, phase 2 PR 2): the pool guest, the pool
// keys, the runtime targets and their state file.
//
// Broker config:
//
//	"ready_rooms": {"guest": "cathedral-pool", "keys": [{"template": "node-22"}]}
//
// turns the pool manager (pool.go) on. The guest is the reserved internal
// guest cathedral-pool: no key, so no client can act as it; not metered;
// sealed by default; max_rooms at least the pool total. The id is refused as
// a configured guest whether or not ready_rooms is set. A key is a catalog
// template that is live, sealed ready and pinned by digest; its image and
// resources are what every pool room of the key is made with. ready_rooms
// needs state_dir: the targets and the claim journal live there.
//
// Targets are set at runtime (no restart) with the operator key:
//
//	PUT /v1/broker/ready-rooms {"per_hotel": {"node-22": 100}, "refill_per_second": 4,
//	                             "refill_during_claims": 1, "reserve_share": 0.25}
//	GET /v1/broker/ready-rooms  the settings, the journal state and per hotel counts
//
// stored in state_dir/ready-rooms.json as the guest allowances are stored
// (temporary file, fsync, rename, directory fsync), written before they
// apply. Default: every target 0, which makes nothing and, once set at
// runtime, is the rollback: the manager deletes the rooms it proved
// unclaimed and nothing else. This pull request reads per_hotel only; the
// refill settings and the reserve are kept for the refill policy (PR 3) and
// the claim path, and every hotel gets at most 1 pool create a second.
//
// ready_rooms_unsealed_for_tests (LOAD-RIG.md 6.2, the Mac rig only) also lets
// the pool use a hotel with "sealed_admission": "off" (the config-only ops
// escape) whose receipts front runs at level 1 (an Ed25519 hotel chain, no
// SNP report). It is refused at load unless ready_rooms is set and the
// listen address and every hotel's api and health are on 127.0.0.1, and a
// hotel that joins later is used that way only when it is on 127.0.0.1 too
// (a joined hotel cannot turn the gate off anyway). Production pool rooms
// stay on hotels with a verified SEV-SNP attestation.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	poolGuestID    = "cathedral-pool"
	readyRoomsFile = "ready-rooms.json"
	// poolTargetMax bounds one key's target on one hotel: a hotel has at
	// most about 1,000 slots (design 6.1). The hotel bounds are PR 3's.
	poolTargetMax = 1000
	// poolRefillMax refuses a typo: a hotel does 8 to 12 creates a second
	// (design 6.3). PR 2 makes at most 1 a second per hotel whatever it says.
	poolRefillMax = 12
)

type readyRoomsConfig struct {
	Guest string              `json:"guest"`
	Keys  []readyRoomKeyEntry `json:"keys"`
}

type readyRoomKeyEntry struct {
	Template string `json:"template"`
}

// readyRoomsSettings are the runtime settings of PUT /v1/broker/ready-rooms.
type readyRoomsSettings struct {
	PerHotel           map[string]int `json:"per_hotel"`
	RefillPerSecond    float64        `json:"refill_per_second"`
	RefillDuringClaims float64        `json:"refill_during_claims"`
	ReserveShare       float64        `json:"reserve_share"`
}

// defaultReadyRoomsSettings: every target 0 (nothing is made); the refill
// values are the design's (6.2, 6.3) and do nothing in this pull request.
func defaultReadyRoomsSettings() readyRoomsSettings {
	return readyRoomsSettings{PerHotel: map[string]int{}, RefillPerSecond: 4, RefillDuringClaims: 1, ReserveShare: 0.25}
}

type readyRoomsFileDoc struct {
	Version int `json:"version"`
	readyRoomsSettings
}

// poolKey is one pool key: a pinned catalog template.
type poolKey struct {
	name      string
	image     string
	resources map[string]any
	diskGiB   int
}

func (p *readyRooms) key(name string) *poolKey {
	for i := range p.keys {
		if p.keys[i].name == name {
			return &p.keys[i]
		}
	}
	return nil
}

// keysWithTarget is the keys whose target is above 0. Caller holds b.mu.
func (p *readyRooms) keysWithTarget() []string {
	var out []string
	for _, k := range p.keys {
		if p.settings.target(k.name) > 0 {
			out = append(out, k.name)
		}
	}
	return out
}

func (p *readyRooms) keyByImage(image string) *poolKey {
	for i := range p.keys {
		if p.keys[i].image == image {
			return &p.keys[i]
		}
	}
	return nil
}

// loadReadyRooms checks the ready_rooms config, loads the targets and opens
// the claim journal. Without ready_rooms it only refuses the reserved guest
// id, so a broker without it is unchanged.
func (b *broker) loadReadyRooms() error {
	if b.guests[poolGuestID] != nil {
		return fmt.Errorf("config: guest id %q is reserved for the ready-room pool (AB#894) and cannot be a configured guest", poolGuestID)
	}
	rc := b.cfg.ReadyRooms
	if rc == nil {
		if b.cfg.ReadyRoomsUnsealedForTests {
			return errors.New("config: ready_rooms_unsealed_for_tests needs ready_rooms")
		}
		return nil
	}
	if rc.Guest != poolGuestID {
		return fmt.Errorf("config: ready_rooms.guest must be %q, the reserved pool guest", poolGuestID)
	}
	if b.cfg.StateDir == "" {
		return errors.New("config: ready_rooms needs state_dir (its targets and the claim journal live there)")
	}
	if len(rc.Keys) == 0 {
		return errors.New("config: ready_rooms.keys needs at least one key")
	}
	p := &readyRooms{hotels: map[string]*poolHotel{}}
	for _, k := range rc.Keys {
		t, ok := templateByName(k.Template)
		if !ok {
			return fmt.Errorf("config: ready_rooms key %q is not a catalog template", k.Template)
		}
		_, digest, pinned := strings.Cut(t.Image, "@")
		if !t.Live || t.Sealed != sealedReady || !pinned || !digestPin.MatchString(digest) {
			return fmt.Errorf("config: ready_rooms key %q must be a live, sealed-ready template pinned by digest", k.Template)
		}
		if p.key(t.Name) != nil {
			return fmt.Errorf("config: ready_rooms key %q appears twice", k.Template)
		}
		p.keys = append(p.keys, poolKey{name: t.Name, image: t.Image, resources: t.resources(), diskGiB: t.DiskGiB})
	}
	if b.cfg.ReadyRoomsUnsealedForTests {
		if err := checkLoopbackRig(b.cfg); err != nil {
			return err
		}
		log.Printf("config: ready_rooms_unsealed_for_tests is ON: the pool may use level-1 receipts fronts on 127.0.0.1 (test rig only)")
	}
	settings, err := loadReadyRoomsSettings(b.cfg.StateDir, p)
	if err != nil {
		return err
	}
	p.settings = settings
	g := &guestState{cfg: guestConfig{ID: poolGuestID}}
	g.cfg.DefaultSealed = true
	g.limits = g.cfg.guestLimits
	b.guests[poolGuestID] = g
	p.guest = g
	b.pool = p
	b.setPoolMaxRoomsLocked()
	p.openJournal(b.cfg.StateDir)
	return nil
}

// checkLoopbackRig is the load check of ready_rooms_unsealed_for_tests.
func checkLoopbackRig(c config) error {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil || host != "127.0.0.1" {
		return errors.New("config: ready_rooms_unsealed_for_tests needs listen on 127.0.0.1")
	}
	for _, hc := range c.Hotels {
		if !loopbackURL(hc.API) || !loopbackURL(hc.Health) {
			return fmt.Errorf("config: ready_rooms_unsealed_for_tests needs every hotel on 127.0.0.1; hotel %q is not", hc.ID)
		}
	}
	return nil
}

func loopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Hostname() == "127.0.0.1"
}

// setPoolMaxRoomsLocked keeps the pool guest's max_rooms at least the pool
// total. Caller holds b.mu, or runs before the broker serves.
func (b *broker) setPoolMaxRoomsLocked() {
	p := b.pool
	total := 0
	for _, n := range p.settings.PerHotel {
		total += n
	}
	total *= max(len(b.hotelList()), 1)
	p.guest.limits.MaxRooms = max(defaultMaxRooms, total)
}

// validate checks settings against the configured keys.
func (s readyRoomsSettings) validate(p *readyRooms) error {
	for name, n := range s.PerHotel {
		if p.key(name) == nil {
			return fmt.Errorf("per_hotel names %q, which is not a ready_rooms key", name)
		}
		if n < 0 || n > poolTargetMax {
			return fmt.Errorf("per_hotel %q must be between 0 and %d", name, poolTargetMax)
		}
	}
	finite := func(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
	switch {
	case !finite(s.RefillPerSecond) || s.RefillPerSecond < 0 || s.RefillPerSecond > poolRefillMax:
		return fmt.Errorf("refill_per_second must be between 0 and %d", poolRefillMax)
	case !finite(s.RefillDuringClaims) || s.RefillDuringClaims < 0 || s.RefillDuringClaims > s.RefillPerSecond:
		return errors.New("refill_during_claims must be between 0 and refill_per_second")
	case !finite(s.ReserveShare) || s.ReserveShare < 0 || s.ReserveShare >= 1:
		return errors.New("reserve_share must be at least 0 and below 1")
	}
	return nil
}

// target is the per-hotel target of key name. Caller holds b.mu.
func (s readyRoomsSettings) target(name string) int { return s.PerHotel[name] }

// loadReadyRoomsSettings reads state_dir/ready-rooms.json. A missing file is
// the default (every target 0). A file that does not parse or does not
// validate is kept aside and the default applies: the pool makes nothing
// until an operator sets targets again. A file that cannot be read stops the
// broker, as the allowance file does.
func loadReadyRoomsSettings(stateDir string, p *readyRooms) (readyRoomsSettings, error) {
	path := filepath.Join(stateDir, readyRoomsFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return defaultReadyRoomsSettings(), nil
	}
	if err != nil {
		return readyRoomsSettings{}, fmt.Errorf("%s: %w", path, err)
	}
	var doc readyRoomsFileDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	why := ""
	switch err := dec.Decode(&doc); {
	case err != nil:
		why = "does not parse"
	case doc.Version != 1:
		why = fmt.Sprintf("has version %d, not 1", doc.Version)
	default:
		if doc.PerHotel == nil {
			doc.PerHotel = map[string]int{}
		}
		if verr := doc.readyRoomsSettings.validate(p); verr != nil {
			why = verr.Error()
		}
	}
	if why == "" {
		return doc.readyRoomsSettings, nil
	}
	aside := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
	if err := os.Rename(path, aside); err != nil {
		log.Printf("%s %s; it could not be kept aside (%v); every ready-room target is 0", path, why, err)
	} else {
		log.Printf("%s %s; kept as %s; every ready-room target is 0", path, why, aside)
	}
	return defaultReadyRoomsSettings(), nil
}

// saveReadyRoomsSettings writes s to state_dir: a temporary file, synced,
// renamed over the old one, then the directory synced. Caller holds
// p.saveMu.
func (b *broker) saveReadyRoomsSettings(s readyRoomsSettings) error {
	raw, err := json.MarshalIndent(readyRoomsFileDoc{Version: 1, readyRoomsSettings: s}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return err
	}
	final := filepath.Join(b.cfg.StateDir, readyRoomsFile)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil { // a leftover tmp file keeps its old mode
		f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := poolSyncFile(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	return poolSyncDir(b.cfg.StateDir) // the rename is durable only once the directory is
}

// poolSyncFile and poolSyncDir are variables so a test can make them fail.
var (
	poolSyncFile = func(f *os.File) error { return f.Sync() }
	poolSyncDir  = func(dir string) error {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		if err := d.Sync(); err != nil {
			d.Close()
			return err
		}
		return d.Close()
	}
)

// handleReadyRooms serves GET and PUT /v1/broker/ready-rooms (operator key).
func (b *broker) handleReadyRooms(w http.ResponseWriter, r *http.Request) {
	if !b.isOperator(r) {
		writeErr(w, 401, "unauthorized", "operator key required")
		return
	}
	if b.pool == nil {
		writeErr(w, 404, "ready_rooms_off", "this broker has no ready_rooms config")
		return
	}
	switch r.Method {
	case "GET":
		b.mu.Lock()
		view := b.readyRoomsViewLocked(time.Now())
		b.mu.Unlock()
		writeJSON(w, 200, view)
	case "PUT":
		b.putReadyRooms(w, r)
	default:
		w.Header().Set("Allow", "GET, PUT")
		writeErr(w, 405, "method_not_allowed", "ready rooms are read with GET and set with PUT")
	}
}

func (b *broker) putReadyRooms(w http.ResponseWriter, r *http.Request) {
	p := b.pool
	var req struct {
		PerHotel           *map[string]int `json:"per_hotel"`
		RefillPerSecond    *float64        `json:"refill_per_second"`
		RefillDuringClaims *float64        `json:"refill_during_claims"`
		ReserveShare       *float64        `json:"reserve_share"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		writeErr(w, 400, "invalid_json", "body must be one JSON object with per_hotel (key to a whole number), refill_per_second, refill_during_claims and reserve_share")
		return
	}
	if req.PerHotel == nil || *req.PerHotel == nil || req.RefillPerSecond == nil || req.RefillDuringClaims == nil || req.ReserveShare == nil {
		writeErr(w, 400, "invalid_ready_rooms", "per_hotel, refill_per_second, refill_during_claims and reserve_share are all required")
		return
	}
	s := readyRoomsSettings{PerHotel: map[string]int{}, RefillPerSecond: *req.RefillPerSecond,
		RefillDuringClaims: *req.RefillDuringClaims, ReserveShare: *req.ReserveShare}
	for k, v := range *req.PerHotel {
		s.PerHotel[k] = v
	}
	if err := s.validate(p); err != nil {
		writeErr(w, 400, "invalid_ready_rooms", err.Error())
		return
	}
	p.saveMu.Lock()
	defer p.saveMu.Unlock()
	// Written before it applies. A write that fails leaves the settings in
	// memory as they were; the file may hold either value.
	if err := b.saveReadyRoomsSettings(s); err != nil {
		log.Printf("ready rooms: settings not written: %v; nothing changed in memory", err)
		writeErr(w, 500, "state_write_failed", "could not write "+readyRoomsFile+"; nothing changed in memory, and the file may hold either value: send the PUT again")
		return
	}
	b.mu.Lock()
	p.settings = s
	b.setPoolMaxRoomsLocked()
	view := b.readyRoomsViewLocked(time.Now())
	b.mu.Unlock()
	log.Printf("ready rooms: per-hotel targets now %v", s.PerHotel)
	writeJSON(w, 200, view)
}

// readyRoomsViewLocked is the GET answer. Caller holds b.mu.
func (b *broker) readyRoomsViewLocked(now time.Time) map[string]any {
	p := b.pool
	keys := make([]map[string]any, 0, len(p.keys))
	for _, k := range p.keys {
		keys = append(keys, map[string]any{"template": k.name, "image": k.image, "resources": k.resources})
	}
	per := make(map[string]int, len(p.keys))
	for _, k := range p.keys {
		per[k.name] = p.settings.target(k.name)
	}
	totals := map[string]int{}
	hotels := map[string]any{}
	ids := []string{}
	for _, h := range b.hotelList() {
		ids = append(ids, h.cfg.ID)
	}
	sort.Strings(ids)
	for _, id := range ids {
		h := b.hotelByID(id)
		if h == nil {
			continue
		}
		c := p.countsLocked(id)
		why := b.poolCreateRefusalLocked(h, p.hotel(id), now)
		d := map[string]any{"ready": c.ready, "claiming": 0, "stale": c.stale, "quarantined": c.quarantined,
			"unverified": c.unverified, "creating": c.creating, "mapped": 0, "bound": p.boundLocked(),
			"pool_creates": why == "", "listed_since_start": p.hotel(id).listed}
		if cold := b.poolColdKeysLocked(h); len(cold) > 0 {
			d["cold_keys"] = cold // these keys get no pool create here until their image is warm
			if why == "" && len(cold) == len(p.keysWithTarget()) {
				why = "image of " + strings.Join(cold, ", ") + " not warm"
				d["pool_creates"] = false
			}
		}
		if why != "" {
			d["why_no_creates"] = why
		}
		if a := p.hotel(id).alarm; a != "" {
			d["alarm"] = a
		}
		hotels[id] = d
		totals["ready"] += c.ready
		totals["stale"] += c.stale
		totals["quarantined"] += c.quarantined
		totals["unverified"] += c.unverified
		totals["creating"] += c.creating
	}
	totals["claiming"], totals["mapped"] = 0, 0
	journal := map[string]any{"state": p.journalState, "opens_tried": p.journalTries}
	if p.journalWhy != "" {
		journal["why"] = p.journalWhy
	}
	if p.journalState == "unavailable" && !p.journalNextTry.IsZero() {
		journal["next_try"] = p.journalNextTry.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"guest": poolGuestID, "keys": keys,
		"settings": map[string]any{"per_hotel": per, "refill_per_second": p.settings.RefillPerSecond,
			"refill_during_claims": p.settings.RefillDuringClaims, "reserve_share": p.settings.ReserveShare},
		"creates_per_second_per_hotel_max": 1, "journal": journal, "hotels": hotels, "totals": totals,
	}
}
