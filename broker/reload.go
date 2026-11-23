// Live config reload (AB#946): new customer keys, new hotels and new
// measurements without a restart.
//
//	POST /v1/broker/config/reload   operator key; body {"sha256": "<hex of the config file>"}
//
// The broker reads its config file again (the path it started with) and
// checks it exactly as a start does (validateTopConfig, prepareConfigHotel,
// buildGuests). It then compares the file with the last file it applied (the
// start's, or the last reload's), never with live state: a runtime PATCH
// (guest limits, a drain, a lend) stays unless the file changed that same
// field. Only these changes apply; any other change refuses the whole reload
// (409 needs_restart, naming each field) and nothing changes:
//
//   - a new guest; key_sha256 and next_key_sha256 of a guest (the old hash
//     stops working at once; rooms stay the guest's); each changed limit of a
//     guest (max_rooms, max_creates_per_minute, default_sealed, hotels,
//     policy, own_hosts_only, pin_max_gib);
//   - sealed_measurements, sealed_host_data, miner_hotkey_caps and
//     miner_max_hotels;
//   - a new hotel; drain of a config file hotel.
//
// A guest or hotel removed from the file, and every other field, needs a
// restart: they have start-time state (allowances, the usage meter, the pool,
// listeners) a reload would skip. The body's sha256 must be the file's, so a
// reload applies the file its caller wrote and not one a second writer put
// there since. The answer names what changed; it never holds a key or hash.
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
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"
)

// admissionLists are the config lists a reload swaps while admission and
// joins read them. nil in b.adml: the start values in b.cfg.
type admissionLists struct {
	measurements []string
	hostData     []string
	hotkeyCaps   map[string]int
	maxHotels    int
}

func (b *broker) admLists() *admissionLists {
	if p := b.adml.Load(); p != nil {
		return p
	}
	return &admissionLists{b.cfg.SealedMeasurements, b.cfg.SealedHostData, b.cfg.MinerHotkeyCaps, b.cfg.MinerMaxHotels}
}

func (b *broker) sealedMeasurements() []string { return b.admLists().measurements }
func (b *broker) sealedHostData() []string     { return b.admLists().hostData }
func (b *broker) minerHotkeyCaps() map[string]int {
	return b.admLists().hotkeyCaps
}
func (b *broker) minerMaxHotels() int { return b.admLists().maxHotels }

// guestByID reads b.guests. A reload adds guests while handlers without b.mu
// look them up, so the map is guarded by guestsMu (writers also hold b.mu).
func (b *broker) guestByID(id string) *guestState {
	b.guestsMu.RLock()
	defer b.guestsMu.RUnlock()
	return b.guests[id]
}

// keyGuest finds the guest of a key hash: the reload's index once one ran,
// else the start's.
func (b *broker) keyGuest(hash string) *guestState {
	if p := b.keys.Load(); p != nil {
		return (*p)[hash]
	}
	return b.byKey[hash]
}

// configReloadable are the top-level fields a reload may change. Guests and
// hotels are compared entry by entry.
var configReloadable = map[string]bool{"guests": true, "hotels": true, "sealed_measurements": true,
	"sealed_host_data": true, "miner_hotkey_caps": true, "miner_max_hotels": true}

// guestLimitFields are the guest fields a reload applies one by one.
var guestLimitFields = map[string]bool{"key_sha256": true, "next_key_sha256": true, "max_rooms": true,
	"max_creates_per_minute": true, "default_sealed": true, "hotels": true, "policy": true,
	"own_hosts_only": true, "pin_max_gib": true}

// reloadSummary is the reload answer: ids and counts only.
type reloadSummary struct {
	SHA256             string   `json:"sha256"`
	GuestsAdded        []string `json:"guests_added"`
	GuestKeysChanged   []string `json:"guest_keys_changed"`
	GuestLimitsChanged []string `json:"guest_limits_changed"`
	MeasurementsAdded  int      `json:"sealed_measurements_added"`
	MeasurementsGone   int      `json:"sealed_measurements_removed"`
	HostDataChanged    bool     `json:"sealed_host_data_changed"`
	MinerCapsChanged   bool     `json:"miner_caps_changed"`
	HotelsAdded        []string `json:"hotels_added"`
	HotelsDrainChanged []string `json:"hotels_drain_changed"`
}

func (s reloadSummary) empty() bool {
	return len(s.GuestsAdded)+len(s.GuestKeysChanged)+len(s.GuestLimitsChanged)+len(s.HotelsAdded)+len(s.HotelsDrainChanged)+s.MeasurementsAdded+s.MeasurementsGone == 0 &&
		!s.HostDataChanged && !s.MinerCapsChanged
}

// reloadErr is a refused reload.
type reloadErr struct {
	status int
	code   string
	msg    string
}

func (e *reloadErr) Error() string { return e.msg }

func (b *broker) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeErr(w, 405, "method_not_allowed", "POST only")
		return
	}
	var req struct {
		SHA256 string `json:"sha256"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	if json.Unmarshal(raw, &req) != nil {
		writeErr(w, 400, "invalid_json", `body must be {"sha256": "<hex sha256 of the config file>"}`)
		return
	}
	sum, err := b.reloadConfig(strings.ToLower(strings.TrimSpace(req.SHA256)))
	if err != nil {
		var re *reloadErr
		if errors.As(err, &re) {
			writeErr(w, re.status, re.code, re.msg)
			return
		}
		writeErr(w, 500, "reload_failed", err.Error())
		return
	}
	writeJSON(w, 200, sum)
}

// parseConfigFile decodes and checks a config file as a start does, with no
// side effect: nothing in state_dir is read or written, no hotel is called.
// It returns the config and the prepared hotels and guests.
func parseConfigFile(raw []byte) (config, []*hotel, map[string]*guestState, map[string]*guestState, error) {
	var c config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, nil, nil, nil, fmt.Errorf("config: %w", err)
	}
	if err := validateTopConfig(c); err != nil {
		return c, nil, nil, nil, err
	}
	if _, err := newAlerter(c.Alerts); err != nil {
		return c, nil, nil, nil, err
	}
	var hotels []*hotel
	seen := map[string]bool{}
	for _, hc := range c.Hotels {
		h, err := prepareConfigHotel(c, hc)
		if err != nil {
			return c, nil, nil, nil, err
		}
		if seen[hc.ID] {
			return c, nil, nil, nil, fmt.Errorf("hotel %s exists", hc.ID)
		}
		seen[hc.ID] = true
		hotels = append(hotels, h)
	}
	if len(c.PrewarmCatalogHotels) > 0 && !c.PrewarmCatalog {
		return c, nil, nil, nil, errors.New("config: prewarm_catalog_hotels needs \"prewarm_catalog\": true (the list only narrows it)")
	}
	for _, id := range c.PrewarmCatalogHotels {
		if !seen[id] {
			return c, nil, nil, nil, fmt.Errorf("config: prewarm_catalog_hotels entry %q is not a hotel in hotels", id)
		}
	}
	guests, byKey, err := buildGuests(c)
	if err != nil {
		return c, nil, nil, nil, err
	}
	if err := checkMeteredGuests(c, guests); err != nil {
		return c, nil, nil, nil, err
	}
	if guests[poolGuestID] != nil {
		return c, nil, nil, nil, fmt.Errorf("config: guest id %q is reserved for the ready-room pool (AB#894) and cannot be a configured guest", poolGuestID)
	}
	if err := c.AMDVerifier.validate(); err != nil {
		return c, nil, nil, nil, fmt.Errorf("config: amd_verifier: %w", err)
	}
	if err := c.ACMEDNS.validate(); err != nil {
		return c, nil, nil, nil, fmt.Errorf("config: acme_dns: %w", err)
	}
	for _, h := range hotels {
		if rf := h.cfg.ReservedFor; rf != "" && guests[rf] == nil {
			return c, nil, nil, nil, fmt.Errorf("config: hotel %q is reserved_for unknown guest %q", h.cfg.ID, rf)
		}
		if h.cfg.LentFrom != "" || h.cfg.LentReportID != "" {
			return c, nil, nil, nil, fmt.Errorf("config: hotel %q: lent_from and lent_report_id are set by PATCH {\"lend\": true} and kept in state_dir, not in the config file", h.cfg.ID)
		}
	}
	return c, hotels, guests, byKey, nil
}

// checkConfigFile is the -check-config flag: the start's checks, no side effect.
func checkConfigFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	_, _, _, _, err = parseConfigFile(raw)
	return err
}

// fields is a JSON object's members, for a field-by-field compare.
func fields(v any) map[string]json.RawMessage {
	raw, _ := json.Marshal(v)
	m := map[string]json.RawMessage{}
	_ = json.Unmarshal(raw, &m)
	return m
}

// changedFields lists the members of a and b that differ, minus skip.
func changedFields(a, b any, skip map[string]bool) []string {
	fa, fb := fields(a), fields(b)
	var out []string
	for k := range fa {
		if !skip[k] && !bytes.Equal(fa[k], fb[k]) {
			out = append(out, k)
		}
	}
	for k := range fb {
		if _, ok := fa[k]; !ok && !skip[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (b *broker) reloadConfig(wantSHA string) (reloadSummary, error) {
	// Lists are [] when empty, never null: readers index them.
	sum := reloadSummary{GuestsAdded: []string{}, GuestKeysChanged: []string{}, GuestLimitsChanged: []string{},
		HotelsAdded: []string{}, HotelsDrainChanged: []string{}}
	if raw, err := hex.DecodeString(wantSHA); err != nil || len(raw) != sha256.Size {
		return sum, &reloadErr{400, "invalid_sha256", "sha256 must be the hex SHA-256 of the config file"}
	}
	b.hotelsMutationMu.Lock() // one reload at a time, and none during a join, PATCH or leave
	defer b.hotelsMutationMu.Unlock()
	raw, err := os.ReadFile(b.cfgPath)
	if err != nil {
		return sum, &reloadErr{500, "config_unreadable", "cannot read the config file"}
	}
	if sha(string(raw)) != wantSHA {
		return sum, &reloadErr{409, "config_changed", "the config file's sha256 is not the one asked; read it again"}
	}
	sum.SHA256 = wantSHA
	nc, newHotels, newGuests, _, err := parseConfigFile(raw)
	if err != nil {
		return sum, &reloadErr{400, "invalid_config", err.Error()}
	}
	old := b.fileCfg.Load()
	if old == nil {
		return sum, &reloadErr{500, "no_baseline", "the broker has no applied config to compare with"}
	}

	// 1. Refuse anything outside the reloadable set.
	var restart []string
	for _, k := range changedFields(*old, nc, configReloadable) {
		restart = append(restart, k)
	}
	oldHotels := map[string]hotelConfig{}
	for _, hc := range old.Hotels {
		oldHotels[hc.ID] = hc
	}
	newHotelCfg := map[string]bool{}
	for _, hc := range nc.Hotels {
		newHotelCfg[hc.ID] = true
		if o, ok := oldHotels[hc.ID]; ok {
			for _, f := range changedFields(o, hc, map[string]bool{"drain": true}) {
				restart = append(restart, "hotels["+hc.ID+"]."+f)
			}
		}
	}
	for id := range oldHotels {
		if !newHotelCfg[id] {
			restart = append(restart, "hotels["+id+"] removed")
		}
	}
	oldGuests := map[string]guestConfig{}
	for _, gc := range old.Guests {
		oldGuests[gc.ID] = gc
	}
	for _, gc := range nc.Guests {
		if o, ok := oldGuests[gc.ID]; ok {
			for _, f := range changedFields(o, gc, guestLimitFields) {
				restart = append(restart, "guests["+gc.ID+"]."+f)
			}
		}
	}
	for id := range oldGuests {
		if newGuests[id] == nil {
			restart = append(restart, "guests["+id+"] removed")
		}
	}
	if len(restart) > 0 {
		sort.Strings(restart)
		return sum, &reloadErr{409, "needs_restart", "these changes need a restart; nothing was applied: " + strings.Join(restart, ", ")}
	}

	// 2. Checks against the live broker, before anything applies.
	var added []*hotel
	for _, h := range newHotels {
		if _, ok := oldHotels[h.cfg.ID]; ok {
			continue
		}
		if b.hotelByID(h.cfg.ID) != nil {
			return sum, &reloadErr{409, "hotel_exists", "hotel " + h.cfg.ID + " is already in the broker (joined at runtime); nothing was applied"}
		}
		added = append(added, h)
	}
	b.mu.Lock()
	for id := range newGuests {
		if _, inOld := oldGuests[id]; !inOld && b.guests[id] != nil {
			b.mu.Unlock()
			return sum, &reloadErr{409, "guest_exists", "guest " + id + " already exists in the broker; nothing was applied"}
		}
	}
	// The new key index: every hash of the new file, each on the guest that
	// is live (an existing guest keeps its state: counters, pending creates).
	keys := map[string]*guestState{}
	live := func(id string) *guestState {
		if g := b.guests[id]; g != nil {
			return g
		}
		return newGuests[id]
	}
	for _, gc := range nc.Guests {
		for _, k := range []string{gc.KeySHA256, gc.NextKeySHA256} {
			if k != "" {
				keys[strings.ToLower(k)] = live(gc.ID)
			}
		}
	}
	for k, g := range b.currentKeysLocked() {
		if g.cfg.ID == poolGuestID {
			keys[k] = g // not in the file
		}
	}

	// 3. Apply, all under b.mu: a create sees the old config or the new one.
	b.guestsMu.Lock()
	for _, gc := range nc.Guests {
		o, inOld := oldGuests[gc.ID]
		if !inOld {
			b.guests[gc.ID] = newGuests[gc.ID]
			sum.GuestsAdded = append(sum.GuestsAdded, gc.ID)
			continue
		}
		if !strings.EqualFold(o.KeySHA256, gc.KeySHA256) || !strings.EqualFold(o.NextKeySHA256, gc.NextKeySHA256) {
			sum.GuestKeysChanged = append(sum.GuestKeysChanged, gc.ID)
		}
		if applyGuestLimits(b.guests[gc.ID], o.guestLimits, gc.guestLimits) {
			sum.GuestLimitsChanged = append(sum.GuestLimitsChanged, gc.ID)
		}
	}
	b.guestsMu.Unlock()
	b.keys.Store(&keys)

	nl := &admissionLists{nc.SealedMeasurements, nc.SealedHostData, nc.MinerHotkeyCaps, nc.MinerMaxHotels}
	ol := b.admLists()
	for _, m := range nl.measurements {
		if !inFold(ol.measurements, m) {
			sum.MeasurementsAdded++
		}
	}
	for _, m := range ol.measurements {
		if !inFold(nl.measurements, m) {
			sum.MeasurementsGone++
		}
	}
	sum.HostDataChanged = !slices.Equal(ol.hostData, nl.hostData)
	sum.MinerCapsChanged = ol.maxHotels != nl.maxHotels || !reflect.DeepEqual(ol.hotkeyCaps, nl.hotkeyCaps)
	if sum.MeasurementsAdded+sum.MeasurementsGone > 0 || sum.HostDataChanged || sum.MinerCapsChanged {
		b.adml.Store(nl)
		b.admissionListsChangedLocked(sum.MeasurementsGone > 0)
	}

	for _, hc := range nc.Hotels {
		o, ok := oldHotels[hc.ID]
		if !ok || o.Drain == hc.Drain {
			continue // only a drain the file changed applies; a PATCHed drain stays
		}
		h := b.hotelByID(hc.ID)
		if h == nil || h.runtime {
			continue
		}
		h.cfgMu.Lock()
		h.cfg.Drain = hc.Drain
		h.cfgMu.Unlock()
		h.fileDrain = hc.Drain
		delete(b.drains, hc.ID) // the file wins over a saved PATCH
		sum.HotelsDrainChanged = append(sum.HotelsDrainChanged, hc.ID)
	}
	if len(sum.HotelsDrainChanged) > 0 {
		if err := b.saveConfigDrainsLocked(); err != nil {
			log.Printf("config reload: drains not saved: %v; a restart reads the file's drain", err)
		}
	}
	for _, h := range added {
		h.roomsUnchecked = true // a reserved hotel waits for its first room list (lend.go)
		h.fileDrain = h.cfg.Drain
		if e, ok := b.lendsOnDisk[h.cfg.ID]; ok { // a lent hotel back in the file keeps its lend
			h.cfg.LentFrom, h.cfg.LentReportID, h.cfg.ReservedFor = e.LentFrom, e.LentReportID, ""
			delete(b.lendsOnDisk, h.cfg.ID)
		}
	}
	b.mu.Unlock()
	for _, h := range added {
		if err := b.addHotel(h); err != nil {
			// Checked above under hotelsMutationMu, which every join takes
			// before it adds: this does not happen.
			log.Printf("config reload: hotel %s not added: %v", h.cfg.ID, err)
			continue
		}
		b.startSync(b.loopsContext(), h)
		sum.HotelsAdded = append(sum.HotelsAdded, h.cfg.ID)
	}
	b.fileCfg.Store(&nc)
	for _, l := range [][]string{sum.GuestsAdded, sum.GuestKeysChanged, sum.GuestLimitsChanged, sum.HotelsAdded, sum.HotelsDrainChanged} {
		sort.Strings(l)
	}
	if sum.empty() {
		log.Printf("config reload %s: no change", wantSHA[:12])
	} else {
		log.Printf("config reload %s: guests added %v, keys changed %v, limits changed %v, measurements +%d -%d, host data changed %v, miner caps changed %v, hotels added %v, drains changed %v",
			wantSHA[:12], sum.GuestsAdded, sum.GuestKeysChanged, sum.GuestLimitsChanged, sum.MeasurementsAdded, sum.MeasurementsGone,
			sum.HostDataChanged, sum.MinerCapsChanged, sum.HotelsAdded, sum.HotelsDrainChanged)
	}
	return sum, nil
}

// currentKeysLocked is the live key index. Caller holds b.mu.
func (b *broker) currentKeysLocked() map[string]*guestState {
	if p := b.keys.Load(); p != nil {
		return *p
	}
	return b.byKey
}

// applyGuestLimits sets on g each limit the file changed from was to now,
// field by field, so a runtime PATCH of another field stays. Caller holds b.mu.
func applyGuestLimits(g *guestState, was, now guestLimits) bool {
	changed := false
	if was.MaxRooms != now.MaxRooms {
		g.limits.MaxRooms, changed = now.MaxRooms, true
	}
	if was.MaxCreatesPerMinute != now.MaxCreatesPerMinute {
		g.limits.MaxCreatesPerMinute, changed = now.MaxCreatesPerMinute, true
	}
	if was.DefaultSealed != now.DefaultSealed {
		g.limits.DefaultSealed, changed = now.DefaultSealed, true
	}
	if !slices.Equal(was.Hotels, now.Hotels) {
		g.limits.Hotels, changed = append([]string(nil), now.Hotels...), true
	}
	if !reflect.DeepEqual(was.Policy, now.Policy) {
		g.limits.Policy, changed = now.Policy, true // never changed in place (guests.go)
	}
	if was.OwnHostsOnly != now.OwnHostsOnly {
		g.limits.OwnHostsOnly, changed = now.OwnHostsOnly, true
	}
	if was.PinMaxGiB != now.PinMaxGiB {
		g.limits.PinMaxGiB, changed = now.PinMaxGiB, true
	}
	return changed
}

// admissionListsChangedLocked makes every gated hotel check again now, and
// refuses at once a hotel whose admitted measurement left the list. Other
// passes stand until that check (a few seconds), so a reload that only adds
// never stops a hotel. A check that started before the swap is discarded
// (admGen). Caller holds b.mu.
func (b *broker) admissionListsChangedLocked(narrowed bool) {
	b.admGen.Add(1)
	ms := b.sealedMeasurements()
	for _, h := range b.hotelList() {
		if !b.needsAttestation(h) {
			continue
		}
		h.adm.checkedAt = time.Time{}
		if narrowed && !h.adm.attestedAt.IsZero() && !inFold(ms, h.adm.measurement) {
			h.adm.attestedAt = time.Time{}
			h.adm.reason = "measurement no longer in sealed_measurements (config reload)"
			log.Printf("hotel %s refused: %s", h.cfg.ID, h.adm.reason)
		}
	}
}
