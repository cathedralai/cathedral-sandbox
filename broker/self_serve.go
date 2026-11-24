// Self-serve metered guests (AB#894, direct broker key for every customer).
//
// The config file's optional "self_serve" block turns this on:
//
//	"self_serve": {"id_prefix": "acct-", "max_rooms_ceiling": 50, "max_creates_per_minute": 120, "policy": {...}}
//
// Absent: off, and the routes below answer 404. It needs state_dir. The
// Polaris API mints a key for an account and registers its hash here, so a
// customer gets a broker key without a config file change:
//
//	PUT    /v1/broker/self-serve/<id>  {"key_sha256": "<hex>", "max_rooms": n}   create, rotate the key, or change max_rooms
//	DELETE /v1/broker/self-serve/<id>                                            revoke the key; the guest and its rooms stay
//	GET    /v1/broker/self-serve                                                 list; never a hash
//
// Operator key only. Every self-serve guest is forced: metered (closed until
// the ledger sends an allowance), not postpaid, no hotels list, the block's
// policy, own_hosts_only and default_sealed false, the block's creates per
// minute. A hotel reserved_for another guest is out of its reach whatever the
// policy names (guestState.tierOf), and no hotel can be reserved for it (the
// config file's reserved_for must name a config file guest).
//
// The guests are kept in state_dir/self-serve-guests.json (0600, temporary
// file, fsync, rename, directory fsync) before a PUT or DELETE answers. They
// load at start after the config file guests and before the allowances. An
// entry whose id is now a config file guest's is skipped (the file wins) and
// kept in the file. A file that does not parse is moved aside and the broker
// starts with none: those keys do not work until the API sends them again.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const selfServeFile = "self-serve-guests.json"

// selfServeIDRE is the shape of a self-serve guest id (and of id_prefix,
// without the length bounds).
var (
	selfServeIDRE     = regexp.MustCompile(`^[a-z0-9-]{6,64}$`)
	selfServePrefixRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

// selfServeConfig is the config file's "self_serve" block.
type selfServeConfig struct {
	IDPrefix            string       `json:"id_prefix"`
	MaxRoomsCeiling     int          `json:"max_rooms_ceiling"`
	MaxCreatesPerMinute int          `json:"max_creates_per_minute"`
	Policy              *guestPolicy `json:"policy"`
}

// validateSelfServe checks the block at start, reload and -check-config.
func validateSelfServe(c config) error {
	s := c.SelfServe
	if s == nil {
		return nil
	}
	if !selfServePrefixRE.MatchString(s.IDPrefix) {
		return errors.New("config: self_serve.id_prefix must be 1 to 32 of a-z, 0-9 and -")
	}
	if s.MaxRoomsCeiling < 1 {
		return errors.New("config: self_serve.max_rooms_ceiling must be 1 or more")
	}
	if s.MaxCreatesPerMinute < 1 {
		return errors.New("config: self_serve.max_creates_per_minute must be 1 or more (0 would mean no limit)")
	}
	if s.Policy == nil {
		return errors.New("config: self_serve.policy is required: it names the hotels every self-serve guest may use")
	}
	if err := s.Policy.validate(); err != nil {
		return fmt.Errorf("config: self_serve: %w", err)
	}
	if c.StateDir == "" {
		return errors.New("config: self_serve needs state_dir (its guests and their allowances live there)")
	}
	return nil
}

// selfServeEntry is one self-serve guest as kept on disk. KeySHA256 empty:
// revoked. An entry is replaced, never changed in place.
type selfServeEntry struct {
	ID        string    `json:"id"`
	KeySHA256 string    `json:"key_sha256,omitempty"`
	MaxRooms  int       `json:"max_rooms"`
	CreatedAt time.Time `json:"created_at"`
}

type selfServeFileDoc struct {
	Version int                       `json:"version"`
	Guests  map[string]selfServeEntry `json:"guests"`
}

// selfServeState is the self-serve guests of a broker. nil: the feature is off.
type selfServeState struct {
	cfg *selfServeConfig
	// mu keeps one PUT or DELETE at a time, from its checks through its save
	// and apply. A reload takes it too (after hotelsMutationMu, before b.mu),
	// so a reload and a PUT cannot lose each other's keys or both take one id.
	mu sync.Mutex
	// entries is id -> the entry of every loaded self-serve guest. Guarded by
	// b.mu.
	entries map[string]*selfServeEntry
	// skipped holds entries not loaded (the id is a config file guest's, or no
	// longer fits the prefix); every save writes them back. Guarded by b.mu.
	skipped map[string]selfServeEntry
}

// newSelfServeGuest builds the guest of e, with every forced setting.
func newSelfServeGuest(sc *selfServeConfig, e *selfServeEntry) *guestState {
	g := &guestState{cfg: guestConfig{ID: e.ID}, selfServe: true}
	g.limits = guestLimits{MaxRooms: e.MaxRooms, MaxCreatesPerMinute: sc.MaxCreatesPerMinute, Policy: sc.Policy, Metered: true}
	return g
}

// idProblem says why id cannot be a self-serve id ("": it can).
func (sc *selfServeConfig) idProblem(id string) string {
	if !strings.HasPrefix(id, sc.IDPrefix) || !selfServeIDRE.MatchString(id) {
		return fmt.Sprintf("a self-serve guest id must start with %q and be 6 to 64 of a-z, 0-9 and -", sc.IDPrefix)
	}
	return ""
}

// reservedGuestID reports ids the broker keeps for itself.
func reservedGuestID(id string) bool { return id == poolGuestID || id == freshGuestID }

// loadSelfServe reads state_dir/self-serve-guests.json at start, after the
// config file guests and before the allowances. It adds the guests to
// b.guests and their keys to b.byKey (nothing reads them concurrently yet).
func (b *broker) loadSelfServe() error {
	sc := b.cfg.SelfServe
	if sc == nil {
		return nil
	}
	b.selfServe = &selfServeState{cfg: sc, entries: map[string]*selfServeEntry{}, skipped: map[string]selfServeEntry{}}
	path := filepath.Join(b.cfg.StateDir, selfServeFile)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	var f selfServeFileDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil || f.Version != 1 || f.Guests == nil {
		// Fail closed: no self-serve key works until the API sends it again.
		aside := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
		if rerr := os.Rename(path, aside); rerr != nil {
			log.Printf("%s: does not parse (%v); not moved aside (%v); the broker starts with no self-serve guests", path, err, rerr)
		} else {
			log.Printf("%s: does not parse (%v); kept at %s; the broker starts with no self-serve guests", path, err, aside)
		}
		return nil
	}
	ids := make([]string, 0, len(f.Guests))
	for id := range f.Guests {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := f.Guests[id]
		e.ID = id
		switch {
		case sc.idProblem(id) != "" || reservedGuestID(id):
			log.Printf("%s: guest %s skipped: the id does not fit self_serve.id_prefix %q", path, id, sc.IDPrefix)
			b.selfServe.skipped[id] = e
			continue
		case b.guests[id] != nil:
			log.Printf("%s: guest %s skipped: a config file guest has this id (the file wins)", path, id)
			b.selfServe.skipped[id] = e
			continue
		}
		if e.MaxRooms < 1 || e.MaxRooms > sc.MaxRoomsCeiling {
			log.Printf("%s: guest %s: max_rooms %d is outside 1 to %d; set to %d", path, id, e.MaxRooms, sc.MaxRoomsCeiling, sc.MaxRoomsCeiling)
			e.MaxRooms = sc.MaxRoomsCeiling
		}
		if e.KeySHA256 != "" {
			e.KeySHA256 = strings.ToLower(e.KeySHA256)
			if !validKeyHash(e.KeySHA256) {
				log.Printf("%s: guest %s: the key hash is not a SHA-256 hex digest; the guest is revoked", path, id)
				e.KeySHA256 = ""
			} else if why := b.keyHashTakenLocked(e.KeySHA256, id); why != "" {
				log.Printf("%s: guest %s: its key hash is %s; the guest is revoked", path, id, why)
				e.KeySHA256 = ""
			}
		}
		ep := &e
		g := newSelfServeGuest(sc, ep)
		b.guests[id] = g
		b.selfServe.entries[id] = ep
		if ep.KeySHA256 != "" {
			b.byKey[ep.KeySHA256] = g
		}
	}
	return nil
}

func validKeyHash(h string) bool {
	raw, err := hex.DecodeString(h)
	return err == nil && len(raw) == sha256.Size
}

// keyHashTakenLocked says who else holds hash (lower case): another guest's
// key, next key or view token, the operator, operator read, meter or miner
// enrollment key. "": nobody but guest self (or nobody). Caller holds b.mu
// (or the broker is not serving yet).
func (b *broker) keyHashTakenLocked(hash, self string) string {
	for name, k := range map[string]string{"the operator key": b.cfg.OperatorKeySHA256, "the operator read key": b.cfg.OperatorReadKeySHA256,
		"the meter key": b.cfg.MeterKeySHA256, "the miner enrollment key": b.cfg.MinerEnrollKeySHA256} {
		if k != "" && strings.EqualFold(k, hash) {
			return "in use by " + name
		}
	}
	if g := b.currentKeysLocked()[hash]; g != nil && g.cfg.ID != self {
		return "in use by another guest"
	}
	if fc := b.fileCfg.Load(); fc != nil {
		for _, gc := range fc.Guests {
			if strings.EqualFold(gc.ViewTokenSHA256, hash) || (gc.ID != self && (strings.EqualFold(gc.KeySHA256, hash) || strings.EqualFold(gc.NextKeySHA256, hash))) {
				return "in use by another guest"
			}
		}
	}
	return ""
}

// selfServeKeysLocked is hash -> guest for every self-serve guest with a key.
// A reload puts them in the index it builds. Caller holds b.mu.
func (b *broker) selfServeKeysLocked() map[string]*guestState {
	out := map[string]*guestState{}
	if b.selfServe == nil {
		return out
	}
	for id, e := range b.selfServe.entries {
		if e.KeySHA256 != "" {
			if g := b.guests[id]; g != nil {
				out[e.KeySHA256] = g
			}
		}
	}
	return out
}

// swapKeysLocked replaces the key index with a copy that edit changed, like
// a reload does. Caller holds b.mu.
func (b *broker) swapKeysLocked(edit func(map[string]*guestState)) {
	cur := b.currentKeysLocked()
	next := make(map[string]*guestState, len(cur)+1)
	for k, g := range cur {
		next[k] = g
	}
	edit(next)
	b.keys.Store(&next)
}

// saveSelfServe writes entries (plus the skipped ones) to state_dir. Caller
// holds b.selfServe.mu, not b.mu.
func (b *broker) saveSelfServe(entries map[string]*selfServeEntry, skipped map[string]selfServeEntry) error {
	doc := selfServeFileDoc{Version: 1, Guests: make(map[string]selfServeEntry, len(entries)+len(skipped))}
	for id, e := range skipped {
		doc.Guests[id] = e
	}
	for id, e := range entries {
		c := *e
		c.CreatedAt = c.CreatedAt.UTC()
		doc.Guests[id] = c
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return err
	}
	return writeFileDurable(filepath.Join(b.cfg.StateDir, selfServeFile), raw)
}

// ---------------------------------------------------------------- routes

// handleSelfServe serves /v1/broker/self-serve[/<id>]. rest is the path after
// /v1/broker/self-serve.
func (b *broker) handleSelfServe(w http.ResponseWriter, r *http.Request, rest string) {
	if b.selfServe == nil {
		writeErr(w, 404, "route_not_found", "self-serve guests are off on this broker")
		return
	}
	if !b.isOperator(r) {
		writeErr(w, 401, "unauthorized", "operator key required")
		return
	}
	id, ok := strings.CutPrefix(rest, "/")
	switch {
	case rest == "" && r.Method == "GET":
		b.listSelfServe(w)
	case ok && id != "" && !strings.Contains(id, "/") && r.Method == "PUT":
		b.putSelfServe(w, r, id)
	case ok && id != "" && !strings.Contains(id, "/") && r.Method == "DELETE":
		b.deleteSelfServe(w, id)
	default:
		writeErr(w, 404, "route_not_found", "no such self-serve route")
	}
}

// selfServeViewLocked is the operator view of one self-serve guest. Caller
// holds b.mu.
func (b *broker) selfServeViewLocked(e *selfServeEntry) map[string]any {
	active := 0
	if g := b.guests[e.ID]; g != nil {
		active = b.activeRooms(g)
	}
	return map[string]any{"id": e.ID, "max_rooms": e.MaxRooms, "revoked": e.KeySHA256 == "",
		"active_rooms": active, "created_at": e.CreatedAt.UTC().Format(time.RFC3339)}
}

func (b *broker) listSelfServe(w http.ResponseWriter) {
	b.mu.Lock()
	out := make([]map[string]any, 0, len(b.selfServe.entries))
	for _, e := range b.selfServe.entries {
		out = append(out, b.selfServeViewLocked(e))
	}
	b.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
	writeJSON(w, 200, map[string]any{"guests": out})
}

// copyEntriesLocked is a shallow copy of the entries map. Caller holds b.mu.
func (s *selfServeState) copyEntriesLocked() map[string]*selfServeEntry {
	next := make(map[string]*selfServeEntry, len(s.entries)+1)
	for k, v := range s.entries {
		next[k] = v
	}
	return next
}

func (b *broker) putSelfServe(w http.ResponseWriter, r *http.Request, id string) {
	sc := b.selfServe.cfg
	var req struct {
		KeySHA256 *string `json:"key_sha256"`
		MaxRooms  *int    `json:"max_rooms"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		writeErr(w, 400, "invalid_json", `body must be one JSON object {"key_sha256": "<hex>", "max_rooms": n}`)
		return
	}
	if req.KeySHA256 == nil || !validKeyHash(strings.ToLower(*req.KeySHA256)) {
		writeErr(w, 400, "invalid_key_sha256", "key_sha256 must be the hex SHA-256 of the key")
		return
	}
	if req.MaxRooms == nil || *req.MaxRooms < 1 || *req.MaxRooms > sc.MaxRoomsCeiling {
		writeErr(w, 400, "invalid_limit", fmt.Sprintf("max_rooms must be a whole number from 1 to %d", sc.MaxRoomsCeiling))
		return
	}
	if why := sc.idProblem(id); why != "" {
		writeErr(w, 400, "invalid_guest_id", why)
		return
	}
	hash := strings.ToLower(*req.KeySHA256)

	b.selfServe.mu.Lock()
	defer b.selfServe.mu.Unlock()
	b.mu.Lock()
	if reservedGuestID(id) || b.selfServe.skipped[id].ID != "" {
		b.mu.Unlock()
		writeErr(w, 409, "guest_exists", "guest "+id+" exists and is not a self-serve guest; nothing changed")
		return
	}
	if g := b.guests[id]; g != nil && !g.selfServe {
		b.mu.Unlock()
		writeErr(w, 409, "guest_exists", "guest "+id+" exists and is not a self-serve guest; nothing changed")
		return
	}
	if why := b.keyHashTakenLocked(hash, id); why != "" {
		b.mu.Unlock()
		writeErr(w, 409, "key_in_use", "this key hash is "+why+"; nothing changed")
		return
	}
	old := b.selfServe.entries[id]
	ne := &selfServeEntry{ID: id, KeySHA256: hash, MaxRooms: *req.MaxRooms, CreatedAt: time.Now().UTC().Truncate(time.Second)}
	if old != nil {
		ne.CreatedAt = old.CreatedAt
	}
	next := b.selfServe.copyEntriesLocked()
	next[id] = ne
	skipped := b.selfServe.skipped
	b.mu.Unlock()

	// Saved before it applies: an answer means the guest survives a restart.
	if err := b.saveSelfServe(next, skipped); err != nil {
		log.Printf("self-serve guest %s not written: %v; nothing changed", id, err)
		writeErr(w, 500, "state_write_failed", "could not write "+selfServeFile+"; nothing changed")
		return
	}

	b.mu.Lock()
	g := b.guests[id]
	created := g == nil
	if created {
		g = newSelfServeGuest(sc, ne)
		b.guestsMu.Lock()
		b.guests[id] = g
		b.guestsMu.Unlock()
	} else {
		g.limits.MaxRooms = ne.MaxRooms
	}
	b.selfServe.entries = next
	keyChanged := old == nil || old.KeySHA256 != hash
	if keyChanged {
		b.swapKeysLocked(func(keys map[string]*guestState) {
			if old != nil && old.KeySHA256 != "" {
				delete(keys, old.KeySHA256) // the old key stops at once; rooms stay the guest's
			}
			keys[hash] = g
		})
	}
	view := b.selfServeViewLocked(ne)
	b.mu.Unlock()
	view["created"] = created
	view["key_changed"] = keyChanged
	status := 200
	if created {
		status = 201
		log.Printf("self-serve guest %s created, max_rooms %d", id, ne.MaxRooms)
	} else if keyChanged {
		log.Printf("self-serve guest %s: key replaced, max_rooms %d", id, ne.MaxRooms)
	}
	writeJSON(w, status, view)
}

func (b *broker) deleteSelfServe(w http.ResponseWriter, id string) {
	b.selfServe.mu.Lock()
	defer b.selfServe.mu.Unlock()
	b.mu.Lock()
	old := b.selfServe.entries[id]
	if old == nil {
		b.mu.Unlock()
		writeErr(w, 404, "guest_not_found", "no self-serve guest "+id)
		return
	}
	if old.KeySHA256 == "" {
		view := b.selfServeViewLocked(old)
		b.mu.Unlock()
		writeJSON(w, 200, view)
		return
	}
	ne := *old
	ne.KeySHA256 = ""
	next := b.selfServe.copyEntriesLocked()
	next[id] = &ne
	// The key leaves the index before the save: a revoke that cannot be
	// written still stops the key now (fail closed); the 500 tells the
	// caller to send it again so a restart keeps it.
	b.selfServe.entries = next
	b.swapKeysLocked(func(keys map[string]*guestState) { delete(keys, old.KeySHA256) })
	skipped := b.selfServe.skipped
	view := b.selfServeViewLocked(&ne)
	b.mu.Unlock()
	log.Printf("self-serve guest %s: key revoked", id)
	if err := b.saveSelfServe(next, skipped); err != nil {
		log.Printf("self-serve guest %s: revoke not written: %v; revoked in memory only", id, err)
		writeErr(w, 500, "state_write_failed", "the key is revoked now, but "+selfServeFile+" was not written, so a restart would bring it back; send the DELETE again")
		return
	}
	writeJSON(w, 200, view)
}
