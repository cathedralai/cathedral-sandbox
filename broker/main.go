// Thin broker ("central booking") in front of room hosts ("hotels").
//
// It does four things and nothing more:
//   - Scatter: a create goes to one hotel, picked at random with weight = free rooms.
//     Each hotel has a bounded number of creates in flight.
//   - Gather: list, quota and usage ask every hotel in parallel and merge.
//   - Route: a room id is "<hotel>.<hotel room id>"; calls on a room go to its hotel.
//   - Show: /<guest>/live is a live view of the hotels and the guest's rooms.
//
// Hotel addresses, hotel keys, guest keys and view tokens come from a private
// config file. Guest keys and view tokens are stored as SHA-256 hashes only.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

//go:embed live.html
var liveHTML []byte

type hotelConfig struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Threads     int    `json:"threads"`
	RAMGiB      int    `json:"ram_gib"`
	API         string `json:"api"`    // base URL of the hotel /v1 API (private path)
	Health      string `json:"health"` // base URL of the hotel /room/health endpoint
	KeyFile     string `json:"key_file"`
	Concurrency int    `json:"concurrency"` // creates in flight at this hotel
	Drain       bool   `json:"drain"`       // true: no new rooms here; existing rooms keep working
	// Labels describe the hotel, for example {"sealed": "true"}. A guest can
	// ask for rooms only on hotels with (or without) some labels.
	Labels   map[string]string `json:"labels"`
	Sealed   bool              `json:"sealed"`    // true: a sealed hotel (SEV-SNP guest); only creates with "sealed": true go here
	MaxSlots int               `json:"max_slots"` // > 0: cap on the slots the hotel reports, set at the broker (no hotel restart)
	// ReservedFor: a guest id. Only that guest may use the hotel; every other
	// guest treats it as denied (capacity.go). Empty: a pool hotel.
	ReservedFor string `json:"reserved_for,omitempty"`
	// MinerHotkey: the SS58 hotkey of the SN94 miner that runs the hotel.
	// The hotel then carries the labels miner=true and miner_hotkey=<key>,
	// so a guest policy can deny miner hotels ({"label": {"miner": "true"}}).
	MinerHotkey string `json:"miner_hotkey,omitempty"`
}

type guestConfig struct {
	ID              string `json:"id"`
	KeySHA256       string `json:"key_sha256"`        // empty: the guest has a view only
	ViewTokenSHA256 string `json:"view_token_sha256"` // token for /<id>/live
	Ops             bool   `json:"ops"`               // may run the probe and reset the broker counters
	guestLimits            // max_rooms, max_creates_per_minute, default_sealed, hotels (guests.go)
}

type config struct {
	Listen         string        `json:"listen"`
	StateDir       string        `json:"state_dir"` // optional: keeps probe results across restarts
	Hotels         []hotelConfig `json:"hotels"`
	Guests         []guestConfig `json:"guests"`
	InsecureCookie bool          `json:"insecure_cookie"` // true only for plain-HTTP local tests
	// MaxExecSeconds is the longest exec the broker accepts (default 14,400).
	// Keep it at or below the hotels' CATHEDRAL_SANDBOX_EXEC_TIMEOUT_MAX.
	MaxExecSeconds int `json:"max_exec_seconds"`
	// MaxQueueWaitSeconds: a create that waits longer than this for a create
	// slot at its hotel moves to another eligible hotel (default 10; -1: never).
	MaxQueueWaitSeconds float64 `json:"max_queue_wait_seconds"`
	// MemFullPct: a hotel whose host memory use is at or above this percent
	// takes no new rooms (default 90; -1: no memory limit). Slots come from an
	// install-time sizing with memory overcommit, so they cannot see rooms
	// that use their full memory limit.
	MemFullPct float64 `json:"mem_full_pct"`
	// OperatorKeySHA256 is the SHA-256 of the operator key. It allows hotel
	// join, change and leave at runtime (hotels.go). Empty: no operator routes.
	OperatorKeySHA256 string `json:"operator_key_sha256"`
	// Admission of joined hotels (admission.go). SealedAdmission "off" turns
	// the attestation gate off; anything else ("" or "enforce") keeps it.
	SealedAdmission    string   `json:"sealed_admission,omitempty"`
	SealedMeasurements []string `json:"sealed_measurements,omitempty"`  // non-empty: a joined sealed hotel's measurement must be one of these
	SealedHostData     []string `json:"sealed_host_data,omitempty"`     // non-empty: its HOST_DATA must be one of these
	AttestTTLSeconds   float64  `json:"attest_ttl_seconds,omitempty"`   // a pass is good this long (default 600)
	AttestEverySeconds float64  `json:"attest_every_seconds,omitempty"` // check a passed hotel again this often (default 60)
	// AMDVerifier runs room-kit/verify_receipts.py on a sealed hotel's
	// attestation to check the AMD chain (amd_chain.go). Required for miner hotels.
	AMDVerifier *amdVerifierConfig `json:"amd_verifier,omitempty"`
}

func (b *broker) maxExec() int {
	if b.cfg.MaxExecSeconds > 0 {
		return b.cfg.MaxExecSeconds
	}
	return defaultMaxExecSeconds
}

// Room states. One byte each, so the live view can send a grid as a string.
const (
	stFree     = '.'
	stCreating = 'c'
	stRunning  = 'r'
	stDeleting = 'd'
	stFailed   = 'f'
	stOther    = 'o' // a room of another guest (live view only)
)

const guestLabel = "broker_guest"

type room struct {
	id       string // broker id: <hotel>.<hotel room id>
	uuid     string // id shown to the Cathedral clients (compat.go)
	hid      string // hotel room id
	h        *hotel
	guest    string
	state    byte
	slot     int // index in the hotel grid, -1 if not drawn
	since    time.Time
	vanished time.Time
	// deleteSent: the guest asked for the delete. A room marked deleting by
	// the sync loop alone may be listed again (a late list) and come back.
	deleteSent bool
}

type latencies struct{ hotel, queue, overhead []float64 }

type hotel struct {
	cfg    hotelConfig
	key    string
	client *http.Client
	ctl    *http.Client // sync loop and hotel documents
	cfgMu  sync.RWMutex // guards cfg.Labels, cfg.Drain and cfg.ReservedFor, which PATCH changes while creates read them
	sem    chan struct{}

	// Guarded by broker.mu.
	slots        int
	grid         []*room
	rooms        map[string]*room // by hotel room id
	queued       int
	creating     int
	backoffUntil time.Time
	ok           bool         // health answered within okWindow, or room calls did (see syncHotel)
	healthLate   bool         // ok only because room calls answer; health is late
	lastOK       time.Time    // last good /room/health answer
	downSince    time.Time    // when ok last went false; zero while ok
	lastAnswer   atomic.Int64 // unix ns of the last room call the hotel answered (status < 500)
	healthMs     float64      // duration of the last /room/health call
	listOK       bool         // last room list answered
	lastErr      string
	caps         map[string]any // capability probe results (probe.go)
	cpuPct       float64
	memPct       float64
	memGiB       float64
	load1        float64
	containers   int
	apiRunning   int
	apiDeleting  int
	created      int
	failed       int
	rejected     int
	lat          latencies
	createEWMA   float64            // seconds, moving average of the hotel create call (placement.go)
	moved        int                // creates that left this hotel's queue for another hotel
	runtime      bool               // joined at runtime (hotels.go), not from the config file
	adm          admission          // attestation gate of a joined sealed hotel (admission.go)
	leaving      bool               // a leave passed its empty check; no new rooms (hotels.go)
	stop         context.CancelFunc // stops the sync loop when the hotel leaves
}

type guestState struct {
	cfg      guestConfig
	created  int
	failed   int
	rejected int // 429 sent to the guest
	queued   int
	recent   []time.Time // create times in the last 60 s
	limits   guestLimits // from the config; an operator can change them at runtime (guests.go)
	pending  int         // rooms admitted and not yet placed or failed
	admits   []time.Time // admitted rooms in the last 60 s, for max_creates_per_minute
}

type broker struct {
	cfg          config
	mu           sync.Mutex
	hset         atomic.Pointer[hotelSet] // hotels; replaced as a whole when one joins or leaves (hotels.go)
	hotelsMu     sync.Mutex               // serialises joins and leaves
	hotelsSaveMu sync.Mutex               // serialises writes of state_dir/hotels.json
	guests       map[string]*guestState
	capsOnDisk   map[string]map[string]any // probe results read from state_dir at start
	byKey        map[string]*guestState    // sha256(key) -> guest
	byUUID       map[string]*room
	compat       *compatState
	prefetch     prefetchJobs
	started      time.Time

	// Durable client state (state.go).
	savedUUIDs map[string]string // broker room id -> client id, from the state file
	dirty      atomic.Bool

	// guestRooms is guest id -> hotel id -> hotel-local room id. It keeps
	// rooms after they leave the hotel list, so a guest can still read their
	// own receipts. Guarded by b.mu.
	guestRooms map[string]map[string]map[string]struct{}

	// tombs is guest id -> recent deletes by label, which also catch creates
	// in flight (inflight.go). Guarded by b.mu.
	tombs map[string][]tombstone
}

// A hotel counts as answering while its last good health answer is younger than okWindow.
const okWindow = 15 * time.Second

// byBID finds a room by its broker id. Caller holds b.mu.
func (b *broker) byBID(bid string) *room {
	hotelID, hid, _ := strings.Cut(bid, ".")
	if h := b.hotelByID(hotelID); h != nil {
		return h.rooms[hid]
	}
	return nil
}

// register gives a room its client UUID. Caller holds b.mu.
func (b *broker) register(rm *room) {
	if rm.uuid == "" {
		// After a restart, a room keeps the client id it had (state.go).
		if u := b.savedUUIDs[rm.id]; u != "" && b.byUUID[u] == nil {
			rm.uuid = u
			delete(b.savedUUIDs, rm.id)
		} else {
			rm.uuid = newUUID()
		}
	}
	b.byUUID[rm.uuid] = rm
	b.markDirty()
	if rm.h != nil {
		b.rememberGuestRoom(rm.guest, rm.h.cfg.ID, rm.hid)
	}
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func loadBroker(path string) (*broker, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c config
	// An unknown field is a typo, and a typo here fails open: "hotel" for
	// "hotels" gives a dedicated guest every hotel. Refuse the file.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	b := &broker{cfg: c, guests: map[string]*guestState{}, byKey: map[string]*guestState{}, byUUID: map[string]*room{}, compat: newCompat(), started: time.Now()}
	for _, hc := range c.Hotels {
		if strings.Contains(hc.ID, ".") || hc.ID == "" {
			return nil, fmt.Errorf("hotel id %q: must be non-empty and have no dot", hc.ID)
		}
		k, err := os.ReadFile(hc.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("hotel %s key: %w", hc.ID, err)
		}
		if hc.Concurrency <= 0 {
			hc.Concurrency = 16
		}
		h := newHotel(hc, strings.TrimSpace(string(k)))
		if err := b.addHotel(h); err != nil {
			return nil, err
		}
	}
	for _, gc := range c.Guests {
		if gc.ID == "" {
			return nil, errors.New("config: a guest has no id (rooms with no broker_guest label would be its own)")
		}
		if b.guests[gc.ID] != nil {
			return nil, fmt.Errorf("config: guest id %q appears twice", gc.ID)
		}
		if gc.Policy != nil {
			if err := gc.Policy.validate(); err != nil {
				return nil, fmt.Errorf("config: guest %q: %w", gc.ID, err)
			}
		}
		g := &guestState{cfg: gc, limits: gc.guestLimits}
		g.limits.Hotels = append([]string(nil), gc.Hotels...)
		b.guests[gc.ID] = g
		if gc.KeySHA256 != "" {
			k := strings.ToLower(gc.KeySHA256)
			if other := b.byKey[k]; other != nil {
				return nil, fmt.Errorf("config: guests %q and %q share one key hash", other.cfg.ID, gc.ID)
			}
			b.byKey[k] = g
		}
	}
	if err := c.AMDVerifier.validate(); err != nil {
		return nil, fmt.Errorf("config: amd_verifier: %w", err)
	}
	for _, h := range b.hotelList() {
		if r := h.cfg.ReservedFor; r != "" && b.guests[r] == nil {
			return nil, fmt.Errorf("config: hotel %q is reserved_for unknown guest %q", h.cfg.ID, r)
		}
	}
	return b, nil
}

// ---------------------------------------------------------------- hotel calls

func (h *hotel) do(ctx context.Context, method, path string, query url.Values, body []byte, timeout time.Duration) (int, http.Header, []byte, error) {
	return h.doBase(ctx, h.cfg.API, method, path, query, body, timeout)
}

func (h *hotel) doBase(ctx context.Context, base, method, path string, query url.Values, body []byte, timeout time.Duration) (int, http.Header, []byte, error) {
	return h.doHeaders(ctx, base, method, path, query, body, timeout, nil)
}

// doHeaders is doBase with extra request headers (the guest id of
// guestcalls.go).
func (h *hotel) doHeaders(ctx context.Context, base, method, path string, query url.Values, body []byte, timeout time.Duration, extra http.Header) (int, http.Header, []byte, error) {
	u := base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range extra {
		req.Header[k] = v
	}
	req.Header.Set("Authorization", "Bearer "+h.key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err == nil && resp.StatusCode < 500 {
		// The hotel answers room calls. syncHotel keeps it "answering" while
		// these continue, even when its health endpoint is slow under load.
		h.lastAnswer.Store(time.Now().UnixNano())
	}
	return resp.StatusCode, resp.Header, out, err
}

func (h *hotel) getJSON(ctx context.Context, base, path string, query url.Values, v any) error {
	u := base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	req.Header.Set("Authorization", "Bearer "+h.key)
	resp, err := h.ctl.Do(req) // its own connections: a guest's execs cannot starve the sync loop
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// ---------------------------------------------------------------- grid

func (h *hotel) resize(slots int) {
	if slots <= 0 || slots == h.slots {
		return
	}
	grid := make([]*room, slots)
	for _, r := range h.grid {
		if r != nil && r.slot >= 0 && r.slot < slots {
			grid[r.slot] = r
		} else if r != nil {
			r.slot = -1
		}
	}
	h.grid, h.slots = grid, slots
}

func (h *hotel) place(r *room) {
	r.slot = -1
	for i, x := range h.grid {
		if x == nil {
			h.grid[i], r.slot = r, i
			return
		}
	}
}

func (b *broker) release(h *hotel, r *room) {
	if r.uuid != "" && b.byUUID[r.uuid] == r {
		delete(b.byUUID, r.uuid)
		b.markDirty()
	}
	h.release(r)
}

func (h *hotel) release(r *room) {
	if r.slot >= 0 && r.slot < len(h.grid) && h.grid[r.slot] == r {
		h.grid[r.slot] = nil
	}
	r.slot = -1
	if r.hid != "" && h.rooms[r.hid] == r {
		delete(h.rooms, r.hid)
	}
}

func (h *hotel) used() int { return len(h.rooms) + h.creating + h.queued }

// pick a hotel at random among the hotels that pl allows. The weight is the
// free rooms times the hotel's headroom (placement.go). With a guest policy
// and no tier set, the preferred hotels come first: the allowed hotels are a
// candidate only when no preferred hotel has a free room (capacity.go).
// Caller holds b.mu.
func (b *broker) pick(exclude map[*hotel]bool, pl placement) *hotel {
	if pl.policy != nil && pl.tier == "" {
		for _, t := range []string{tierPrefer, tierAllow} {
			tp := pl
			tp.tier = t
			if h := b.pickIn(exclude, tp); h != nil {
				return h
			}
		}
		return nil
	}
	return b.pickIn(exclude, pl)
}

// pickIn is pick inside one candidate set.
func (b *broker) pickIn(exclude map[*hotel]bool, pl placement) *hotel {
	now := time.Now()
	hotels := b.hotelList()
	total := 0.0
	weight := make([]float64, len(hotels))
	for i, h := range hotels {
		if exclude[h] || !pl.allows(h) {
			continue
		}
		if f := b.admissibleFree(h, now); f > 0 {
			weight[i] = h.weight(f)
			total += weight[i]
		}
	}
	if total <= 0 {
		return nil
	}
	n := rand.Float64() * total
	for i, w := range weight {
		if w > 0 && n < w {
			return hotels[i]
		}
		n -= w
	}
	for i := len(weight) - 1; i >= 0; i-- { // rounding: the last eligible hotel
		if weight[i] > 0 {
			return hotels[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------- HTTP helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func (b *broker) guestFromKey(r *http.Request) *guestState {
	a := r.Header.Get("Authorization")
	if len(a) < 8 || !strings.EqualFold(a[:7], "bearer ") {
		return nil
	}
	return b.byKey[sha(strings.TrimSpace(a[7:]))]
}

// downSince is when the hotel went down, for the hotel lists; nil while up.
func downSince(h *hotel) any {
	if h.ok || h.downSince.IsZero() {
		return nil
	}
	return h.downSince.UTC().Format(time.RFC3339)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// ---------------------------------------------------------------- scatter

type createResult struct {
	status int
	header http.Header
	body   []byte
	doc    map[string]any
	// lost: hotels that got the create but never answered. Each may hold a
	// room this guest does not know about; handleCreate reaps them.
	lost []*hotel
}

// batchLabel marks every room of one create request, so the rooms a hotel
// started for a request whose answer was lost can be found and removed.
const batchLabel = "broker_batch"

// createOne places one room. body is the create as the hotel receives it,
// marshaled once per request; labels are its labels, for the delete by label
// tombstones (inflight.go); tRecv is when the guest request arrived.
func (b *broker) createOne(ctx context.Context, g *guestState, body []byte, labels map[string]any, tRecv time.Time, pl placement) createResult {
	tried := map[*hotel]bool{}
	var last createResult
	var lost []*hotel
	finish := func(r createResult) createResult { r.lost = lost; return r }
	asked, fellBack := pl, false
	for attempt := 0; attempt < 3; attempt++ {
		b.mu.Lock()
		h := b.pick(tried, pl)
		if h == nil && !fellBack {
			// "placement": "prefer": the named hotels are down or full.
			if fb, ok := b.fallbackFor(pl); ok {
				pl, fellBack = fb, true
				h = b.pick(tried, pl)
			}
		}
		if h == nil {
			if last.status >= 500 {
				g.failed++
			}
			b.mu.Unlock()
			if last.status != 0 {
				return finish(last)
			}
			return finish(b.noRoom(asked))
		}
		tried[h] = true
		h.queued++
		g.queued++
		b.mu.Unlock()

		// Wait for a create slot. A create that waits too long moves to
		// another eligible hotel (placement.go).
		h = b.waitSlot(ctx, g, h, pl, tried)
		if h == nil {
			return finish(clientGone())
		}
		b.mu.Lock()
		// The hotel was admitted when the create was placed, but the create
		// may have queued for its slot past a refused or expired attestation,
		// or past a leave. Give the slot back and place the create again.
		if h.leaving || !b.admitted(h, time.Now()) {
			h.queued--
			g.queued--
			b.mu.Unlock()
			<-h.sem
			continue
		}
		gone, doomed := ctx.Err() != nil, b.tombstoned(g.cfg.ID, labels, tRecv)
		if gone || doomed {
			// The guest went away, or deleted this create by label, while it
			// waited for a slot: start no room.
			h.queued--
			g.queued--
			b.mu.Unlock()
			<-h.sem
			if gone {
				return finish(clientGone())
			}
			return finish(deletedDuringCreate())
		}
		b.mu.Unlock()
		tDispatch := time.Now()
		rm := &room{h: h, guest: g.cfg.ID, state: stCreating, since: tDispatch}
		b.mu.Lock()
		h.queued--
		g.queued--
		h.creating++
		h.place(rm)
		b.mu.Unlock()

		// The hotel does not stop a create when the guest goes away. Keep the
		// call open, so the broker learns the room id and can delete the room.
		status, hdr, out, err := h.do(context.WithoutCancel(ctx), "POST", "/v1/sandboxes", nil, body, hotelCreateTimeout)
		<-h.sem
		tDone := time.Now()

		b.mu.Lock()
		h.creating--
		var doc map[string]any
		if err == nil {
			_ = json.Unmarshal(out, &doc)
		}
		hid, _ := doc["id"].(string)
		started := err == nil && (status == 200 || status == 202) && hid != ""
		if started && (ctx.Err() != nil || b.tombstoned(g.cfg.ID, labels, tRecv)) {
			gone := ctx.Err() != nil
			h.release(rm)
			rm.hid, rm.id = hid, h.cfg.ID+"."+hid
			b.mu.Unlock()
			b.reapRoom(h, rm)
			if gone {
				return finish(clientGone())
			}
			return finish(deletedDuringCreate())
		}
		switch {
		case started:
			rm.hid, rm.id, rm.state, rm.since = hid, h.cfg.ID+"."+hid, stRunning, tDone
			if old := h.rooms[hid]; old != nil && old != rm { // the sync loop saw it first
				b.release(h, old)
			}
			h.rooms[hid] = rm
			b.register(rm)
			h.created++
			g.created++
			g.recent = append(g.recent, tDone)
			doc["id"] = rm.id
			doc["hotel"] = h.cfg.ID
			// A fallback create can still end on a named hotel (waitSlot,
			// or a retry once it recovers); only a room elsewhere is a fallback.
			fellBack = fellBack && !asked.ids[h.cfg.ID]
			if fellBack {
				doc["placement_fallback"] = true
			}
			tier := ""
			if pl.policy != nil {
				tier = pl.policy.tier(h)
				doc["placement_tier"] = tier
			}
			doc["isolation"] = isolationDoc(h, doc)
			if pl.snapshotRef != "" {
				doc["snapshot_id"] = pl.snapshotRef
			}
			queue, call := tDispatch.Sub(tRecv), tDone.Sub(tDispatch)
			h.lat.queue = append(h.lat.queue, ms(queue))
			h.lat.hotel = append(h.lat.hotel, ms(call))
			h.noteCreate(call)
			b.mu.Unlock()
			hdrs := http.Header{}
			copyRoomHeaders(hdrs, hdr)
			hdrs.Set("X-Broker-Hotel", h.cfg.ID)
			if fellBack {
				hdrs.Set("X-Broker-Fallback", "true")
			}
			if tier != "" {
				hdrs.Set("X-Broker-Placement-Tier", tier)
			}
			hdrs.Set("X-Broker-Queue-Ms", strconv.FormatFloat(ms(queue), 'f', 1, 64))
			hdrs.Set("X-Broker-Hotel-Ms", strconv.FormatFloat(ms(call), 'f', 1, 64))
			return finish(createResult{status: 202, header: hdrs, doc: doc})
		case err == nil && status == 429:
			h.release(rm)
			h.rejected++
			ra, _ := strconv.Atoi(hdr.Get("Retry-After"))
			if ra <= 0 {
				ra = 2
			}
			h.backoffUntil = time.Now().Add(time.Duration(ra) * time.Second)
			b.mu.Unlock()
			last = createResult{status: 429, header: http.Header{"Retry-After": {strconv.Itoa(ra)}}, body: out}
			continue // try another hotel
		default:
			// The hotel could not start the room (for example a full bridge).
			// Rest it for a short time and try another hotel.
			rm.state, rm.since = stFailed, tDone
			// A 4xx usually means the request is wrong, not the hotel:
			// resting the hotel would turn one guest's bad input into a 503
			// for the next create of every guest. 401 and 403 are the
			// exception: the hotel rejects the broker's own key, so it is
			// broken for every guest and must rest.
			// image_pull_failed (502) is the guest's error only when the
			// registry says the image is missing or denied; a hotel that
			// cannot reach the registry (DNS, network, rate limit, disk) is
			// at fault and must rest so the create moves on.
			guestImage := status == 502 && errCodeOf(out) == "image_pull_failed" && guestImageFault(out)
			if err != nil || (status >= 500 && !guestImage) || status == 401 || status == 403 {
				h.failed++
				h.backoffUntil = time.Now().Add(hotelFailBackoff)
			}
			if err != nil {
				// The hotel may have started the room before the answer was lost.
				lost = append(lost, h)
				last = createResult{status: 502, doc: map[string]any{"error": map[string]string{"code": "hotel_unreachable", "message": "hotel " + h.cfg.ID + " did not answer"}}}
			} else {
				last = createResult{status: status, body: out, header: http.Header{"X-Broker-Hotel": {h.cfg.ID}}}
			}
			if (status >= 400 && status < 500) || guestImage { // the request itself is wrong: no retry
				g.failed++
				b.mu.Unlock()
				return finish(last)
			}
			b.mu.Unlock()
			continue
		}
	}
	if last.status >= 500 {
		b.mu.Lock()
		g.failed++
		b.mu.Unlock()
	}
	return finish(last)
}

// createMany places count rooms for one request. The hotel's copy of the
// request is marshaled once: every room of a batch sends the same bytes (a
// 1 MiB body times count stays 1 MiB). A hotel that got a create and never
// answered may hold a room the guest does not know about: what this request
// did not receive is reaped.
func (b *broker) createMany(ctx context.Context, g *guestState, payload map[string]any, count int, tRecv time.Time, pl placement) []createResult {
	labels, _ := payload["labels"].(map[string]any)
	if labels == nil {
		labels = map[string]any{}
	}
	batchID := newUUID()
	labels[guestLabel] = g.cfg.ID
	labels[batchLabel] = batchID
	payload["labels"] = labels
	delete(payload, "count")
	body, _ := json.Marshal(payload)
	results := make([]createResult, count)
	if count == 1 {
		results[0] = b.createOne(ctx, g, body, labels, tRecv, pl)
		b.unreserve(g, 1)
	} else {
		// Batch: one create per room, all in parallel; the hotel semaphores bound the load.
		var wg sync.WaitGroup
		for i := 0; i < count; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = b.createOne(ctx, g, body, labels, tRecv, pl)
				b.unreserve(g, 1)
			}(i)
		}
		wg.Wait()
	}
	lost := map[*hotel]bool{}
	keep := map[*hotel]map[string]bool{}
	for _, res := range results {
		for _, h := range res.lost {
			lost[h] = true
		}
		if res.status == 202 {
			if hid, ok := res.doc["id"].(string); ok {
				if hotelID, id, ok := strings.Cut(hid, "."); ok {
					if h := b.hotelByID(hotelID); h != nil {
						if keep[h] == nil {
							keep[h] = map[string]bool{}
						}
						keep[h][id] = true
					}
				}
			}
		}
	}
	for h := range lost {
		b.reapOrphans(h, g, batchID, keep[h])
	}
	return results
}

// reapOrphans removes the rooms of one create request that hotel h started
// although its answer never reached the broker. keep holds the hotel room
// ids this request did receive on h. The first pass runs before the guest
// gets its answer; later passes retry in the background.
func (b *broker) reapOrphans(h *hotel, g *guestState, batchID string, keep map[string]bool) {
	pass := func(timeout time.Duration) bool {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		q := url.Values{}
		q.Add("label", batchLabel+"="+batchID)
		q.Add("label", guestLabel+"="+g.cfg.ID)
		status, _, out, err := h.do(ctx, "GET", "/v1/sandboxes", q, nil, timeout)
		if err != nil || status != 200 {
			return false
		}
		var list struct {
			Sandboxes []struct {
				ID string `json:"id"`
			} `json:"sandboxes"`
		}
		if json.Unmarshal(out, &list) != nil {
			return false
		}
		ok := true
		for _, s := range list.Sandboxes {
			if keep[s.ID] {
				continue
			}
			st, _, _, derr := h.do(ctx, "DELETE", "/v1/sandboxes/"+url.PathEscape(s.ID), nil, nil, timeout)
			if derr != nil || (st != 204 && st != 404) {
				ok = false
				continue
			}
			b.mu.Lock()
			if rm := h.rooms[s.ID]; rm != nil { // the sync loop adopted it meanwhile
				b.release(h, rm)
			}
			b.mu.Unlock()
			log.Printf("orphan room %s.%s of guest %s removed (create answer lost)", h.cfg.ID, s.ID, g.cfg.ID)
		}
		return ok
	}
	if pass(3 * time.Second) {
		return
	}
	go func() {
		for _, wait := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second} {
			time.Sleep(wait)
			if pass(10 * time.Second) {
				return
			}
		}
		log.Printf("orphan rooms of guest %s on hotel %s (batch %s) could not be reaped; the sync loop will list them", g.cfg.ID, h.cfg.ID, batchID)
	}()
}

// hotelFailBackoff rests a hotel after a failed room start.
const hotelFailBackoff = 10 * time.Second

// hotelCreateTimeout bounds one create call to a hotel: a cold image pull
// can take minutes. A variable, not a constant, so a test can shorten it.
var hotelCreateTimeout = 5 * time.Minute

func (b *broker) handleCreate(w http.ResponseWriter, r *http.Request, g *guestState) {
	tRecv := time.Now()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, 400, "bad_body", "cannot read body")
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeErr(w, 400, "invalid_json", "request body is not JSON")
		return
	}
	// Same rule as the compat path: a create that names no network fails
	// closed. Without this the hotel's own default (internet) applies.
	if v, ok := payload["network"]; !ok || v == nil || v == "" {
		payload["network"] = map[string]any{"mode": "deny_all", "allow": []any{}}
	}
	count := 1
	if c, ok := payload["count"].(float64); ok {
		count = int(c)
	}
	if count < 1 || count > 10000 {
		writeErr(w, 400, "invalid_count", "count must be between 1 and 10000")
		return
	}
	pl, perr := b.placementFor(r.Context(), g, payload)
	if perr != nil {
		writeErr(w, perr.status, perr.code, perr.msg)
		return
	}
	pl.apply(payload)
	if e, retry := b.admit(g, count); e != nil {
		writeLimitErr(w, e, retry)
		return
	}
	results := b.createMany(r.Context(), g, payload, count, tRecv, pl)
	if count == 1 {
		b.finishCreate(w, results[0], tRecv)
		return
	}
	var docs []any
	errs := map[string]int{}
	for _, res := range results {
		if res.status == 202 {
			docs = append(docs, res.doc)
			continue
		}
		code := strconv.Itoa(res.status)
		if e, ok := res.doc["error"].(map[string]string); ok {
			code += " " + e["code"]
		}
		errs[code]++
	}
	status := 202
	if len(docs) == 0 {
		status = results[0].status
		if status == 429 {
			w.Header().Set("Retry-After", "5")
		}
	}
	writeJSON(w, status, map[string]any{"sandboxes": docs, "count": len(docs), "errors": errs})
}

func (b *broker) finishCreate(w http.ResponseWriter, res createResult, tRecv time.Time) {
	for k, v := range res.header {
		w.Header()[k] = v
	}
	if res.status == 202 {
		q, _ := strconv.ParseFloat(res.header.Get("X-Broker-Queue-Ms"), 64)
		c, _ := strconv.ParseFloat(res.header.Get("X-Broker-Hotel-Ms"), 64)
		over := ms(time.Since(tRecv)) - q - c
		w.Header().Set("X-Broker-Overhead-Ms", strconv.FormatFloat(over, 'f', 2, 64))
		b.mu.Lock()
		if h := b.hotelByID(res.header.Get("X-Broker-Hotel")); h != nil {
			h.lat.overhead = append(h.lat.overhead, over)
		}
		b.mu.Unlock()
	}
	if res.doc != nil {
		writeJSON(w, res.status, res.doc)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res.status)
	_, _ = w.Write(res.body)
}

// ---------------------------------------------------------------- route

func (b *broker) handleRoom(w http.ResponseWriter, r *http.Request, g *guestState, rest string) {
	bid, tail, _ := strings.Cut(rest, "/")
	// Room terminals stay closed until every hotel runs a package where a
	// terminal line goes through the runtime's exec (B154).
	if tail == "terminals" || strings.HasPrefix(tail, "terminals/") {
		writeErr(w, 403, "terminals_disabled", "room terminals are disabled on this broker; use exec")
		return
	}
	// The tail goes to the hotel as part of its path. A dot segment would
	// climb out of this room if anything between us and the hotel normalized it.
	for _, seg := range strings.Split(tail, "/") {
		if seg == "." || seg == ".." {
			writeErr(w, 400, "invalid_path", "a sandbox path cannot contain . or .. segments")
			return
		}
	}
	hotelID, hid, ok := strings.Cut(bid, ".")
	h := b.hotelByID(hotelID)
	if !ok || h == nil {
		writeErr(w, 404, "sandbox_not_found", "no sandbox "+bid)
		return
	}
	b.mu.Lock()
	rm := h.rooms[hid]
	owned := rm != nil && rm.guest != "" && rm.guest == g.cfg.ID // an unlabeled room belongs to no guest
	b.mu.Unlock()
	if !owned {
		writeErr(w, 404, "sandbox_not_found", "no sandbox "+bid)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 256<<20+1))
	if len(body) > 256<<20 {
		// Forwarding the first 256 MiB would write a short file and answer 200.
		writeErr(w, 413, "request_too_large", "the body is over 256 MiB")
		return
	}
	if r.Method == "POST" && tail == "snapshot" {
		b.roomSnapshot(w, r, g, h, hid, body)
		return
	}
	// Hotel ids (nc-sealed.sbx_…) proxy the body as-is. Reject a string cmd
	// here so the hotel path matches the client UUID path and the docs.
	if r.Method == "POST" && tail == "exec" {
		if err := requireExecCmdList(body); err != nil {
			writeErr(w, 400, "invalid_exec", err.Error())
			return
		}
	}
	path := "/v1/sandboxes/" + url.PathEscape(hid)
	if tail != "" {
		path += "/" + tail
	}
	timeout := 2 * time.Minute
	if strings.HasSuffix(tail, "exec") || strings.HasSuffix(tail, "wait") {
		timeout = 20 * time.Minute
		// A long exec must not lose its answer: wait for its own limit plus a margin.
		var req struct {
			Timeout float64 `json:"timeout_seconds"`
		}
		if json.Unmarshal(body, &req) == nil && req.Timeout > 0 {
			if t := time.Duration(req.Timeout)*time.Second + 2*time.Minute; t > timeout {
				timeout = t
			}
		}
	}
	var bodyArg []byte
	if r.Method != "GET" && r.Method != "DELETE" {
		bodyArg = body
	}
	status, hdr, out, err := h.do(r.Context(), r.Method, path, r.URL.Query(), bodyArg, timeout)
	if err != nil {
		writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
		return
	}
	if r.Method == "DELETE" && tail == "" && (status == 204 || status == 404) {
		b.mu.Lock()
		if rm.state == stRunning {
			rm.state, rm.vanished = stDeleting, time.Now()
		}
		rm.deleteSent = true
		b.mu.Unlock()
	}
	for _, k := range []string{"Content-Type", "Content-Range", "Content-Length", "Retry-After", "Accept-Ranges"} {
		if v := hdr.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	copyRoomHeaders(w.Header(), hdr)
	// Signed receipts must reach the guest byte for byte: no id rewrite there.
	if strings.HasPrefix(hdr.Get("Content-Type"), "application/json") && tail != "receipts" {
		out = bytes.ReplaceAll(out, []byte(`"`+hid+`"`), []byte(`"`+bid+`"`))
		if tail == "exec" && status == 200 {
			out = truncateExecJSON(out)
		}
		w.Header().Del("Content-Length")
		// The room document itself says what its placement isolates.
		if r.Method == "GET" && tail == "" && status == 200 {
			var doc map[string]any
			if json.Unmarshal(out, &doc) == nil {
				doc["hotel"] = h.cfg.ID
				doc["isolation"] = isolationDoc(h, doc)
				if re, err := json.Marshal(doc); err == nil {
					out = re
				}
			}
		}
	}
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

// copyRoomHeaders passes the hotel's X-Room-* headers (for example the signed
// receipt of a sealed hotel, X-Room-Receipt) to the guest unchanged.
func copyRoomHeaders(dst, src http.Header) {
	for k, v := range src {
		if strings.HasPrefix(k, "X-Room-") {
			dst[k] = v
		}
	}
}

// requireExecCmdList enforces the published contract: cmd / command must be a
// non-empty list of non-empty strings. A shell string is refused.
func requireExecCmdList(raw []byte) error {
	var req map[string]any
	if json.Unmarshal(raw, &req) != nil {
		return fmt.Errorf("request body is not JSON")
	}
	cmd := req["command"]
	if cmd == nil {
		cmd = req["cmd"]
	}
	if cmd == nil {
		return fmt.Errorf("cmd is required")
	}
	list, ok := cmd.([]any)
	if !ok || len(list) == 0 {
		return fmt.Errorf("cmd must be a non-empty list of strings")
	}
	for _, x := range list {
		s, ok := x.(string)
		if !ok || s == "" {
			return fmt.Errorf("cmd must be a non-empty list of strings")
		}
	}
	return nil
}

// execOutputCapBytes is the maximum stdout/stderr the broker returns on an
// exec. Matches the hotel guest cap; a hotel that forgets to truncate is
// clipped here and marked truncated.
const execOutputCapBytes = 16 << 20

// clipExecDoc caps stdout/stderr on an exec JSON object and sets truncated
// when either stream was longer than the cap.
func clipExecDoc(doc map[string]any) {
	for _, k := range []string{"stdout", "stderr"} {
		s, ok := doc[k].(string)
		if !ok {
			continue
		}
		b := []byte(s)
		if len(b) > execOutputCapBytes {
			doc[k] = string(b[:execOutputCapBytes])
			doc["truncated"] = true
		}
	}
}

// truncateExecJSON caps stdout/stderr in an exec JSON answer and sets
// truncated when either stream was longer than the cap.
func truncateExecJSON(out []byte) []byte {
	var doc map[string]any
	if json.Unmarshal(out, &doc) != nil {
		return out
	}
	before, _ := json.Marshal(doc)
	clipExecDoc(doc)
	re, err := json.Marshal(doc)
	if err != nil || bytes.Equal(before, re) {
		return out
	}
	return re
}

// handleHotelDoc passes a hotel's attestation or receipt chain to a guest:
// GET /v1/hotels/<id>/attestation and GET /v1/hotels/<id>/receipts.
// The hotel chain is one list per boot. A guest sees only receipts for rooms
// they have owned. An ops key sees the whole chain.
func (b *broker) handleHotelDoc(w http.ResponseWriter, r *http.Request, rest string, g *guestState) {
	id, doc, _ := strings.Cut(rest, "/")
	h := b.hotelByID(id)
	if h != nil && doc == "attest" && r.Method == "POST" {
		b.handleHotelAttest(w, r, h, g)
		return
	}
	if h == nil || (doc != "attestation" && doc != "receipts") || r.Method != "GET" {
		writeErr(w, 404, "route_not_found", "no such hotel document")
		return
	}
	// The receipt chain of a hotel outside the guest's list (for example one
	// dedicated to another guest) is not this guest's, ops included. The
	// attestation stays public: it proves the machine, not anyone's work.
	if doc == "receipts" && !g.limitsAllow(b, h.cfg.ID) {
		writeErr(w, 404, "route_not_found", "no such hotel document")
		return
	}
	if doc == "receipts" && !g.cfg.Ops {
		// Walk the hotel chain so a busy hotel's oldest page does not hide
		// this guest's newer receipts (CONST / Affinities empty /receipts).
		filtered, ferr := b.filterGuestHotelReceipts(r.Context(), h, g.cfg.ID, r.URL.Query())
		if ferr != nil {
			writeErr(w, 502, "receipts_unreadable", "hotel receipt chain could not be filtered")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Del("Content-Length")
		w.WriteHeader(200)
		_, _ = w.Write(filtered)
		return
	}
	status, hdr, out, err := h.doBase(r.Context(), h.cfg.Health, "GET", "/room/"+doc, r.URL.Query(), nil, time.Minute)
	if err != nil {
		writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
		return
	}
	if v := hdr.Get("Content-Type"); v != "" {
		w.Header().Set("Content-Type", v)
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

// hotelAttestBodyMax caps POST /v1/hotels/<id>/attest. The body is one
// field of 128 hex characters.
const hotelAttestBodyMax = 4096

// handleHotelAttest passes POST /v1/hotels/<id>/attest to the hotel's
// POST /room/attest: a fresh SEV-SNP report whose REPORT_DATA is the 64
// bytes the caller sent. A hotel outside the guest's list answers 404, as
// for receipts. The body goes to the hotel unchanged and the hotel's JSON
// (status, body, Retry-After) comes back unchanged; the hotel validates.
func (b *broker) handleHotelAttest(w http.ResponseWriter, r *http.Request, h *hotel, g *guestState) {
	if !g.limitsAllow(b, h.cfg.ID) {
		writeErr(w, 404, "route_not_found", "no such hotel document")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, hotelAttestBodyMax))
	if err != nil {
		writeErr(w, 413, "body_too_large", "attest body over 4096 bytes")
		return
	}
	// Pass the guest id so the hotel rate-limits attest per guest, not per
	// hotel (shared hotels serve many Escape / capacity callers).
	status, hdr, out, err := h.doHeaders(
		r.Context(), h.cfg.Health, "POST", "/room/attest", nil, body, time.Minute,
		http.Header{guestHeader: {g.cfg.ID}},
	)
	if err != nil {
		writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
		return
	}
	for _, k := range []string{"Content-Type", "Retry-After"} {
		if v := hdr.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.Header().Del("Content-Length")
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

// ---------------------------------------------------------------- gather

// fanout asks every hotel in the guest's list. A hotel outside the list is
// not asked: it may hang, and its id and totals are not the guest's.
func (b *broker) fanout(ctx context.Context, g *guestState, path string, q url.Values) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range b.hotelList() {
		if !g.limitsAllow(b, h.cfg.ID) {
			continue
		}
		wg.Add(1)
		go func(h *hotel) {
			defer wg.Done()
			status, _, body, err := h.do(ctx, "GET", path, q, nil, 30*time.Second)
			mu.Lock()
			defer mu.Unlock()
			if err != nil || status != 200 {
				out[h.cfg.ID] = json.RawMessage(`{"error":"unavailable"}`)
				return
			}
			out[h.cfg.ID] = body
		}(h)
	}
	wg.Wait()
	return out
}

func (b *broker) handleList(w http.ResponseWriter, r *http.Request, g *guestState) {
	q := r.URL.Query()
	q.Add("label", guestLabel+"="+g.cfg.ID)
	parts := b.fanout(r.Context(), g, "/v1/sandboxes", q)
	all := []map[string]any{}
	errs := map[string]string{}
	for hid, raw := range parts {
		var doc struct {
			Sandboxes []map[string]any `json:"sandboxes"`
			Error     any              `json:"error"`
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Error != nil {
			errs[hid] = "unavailable"
			continue
		}
		for _, s := range doc.Sandboxes {
			if id, ok := s["id"].(string); ok {
				s["id"] = hid + "." + id
			}
			s["hotel"] = hid
			if h := b.hotelByID(hid); h != nil {
				s["isolation"] = isolationDoc(h, s)
			}
			all = append(all, s)
		}
	}
	sort.Slice(all, func(i, j int) bool { return fmt.Sprint(all[i]["id"]) < fmt.Sprint(all[j]["id"]) })
	writeJSON(w, 200, map[string]any{"sandboxes": all, "count": len(all), "hotel_errors": errs})
}

func sumInto(dst map[string]any, src map[string]any) {
	for k, v := range src {
		switch x := v.(type) {
		case float64:
			d, _ := dst[k].(float64)
			dst[k] = d + x
		case map[string]any:
			sub, _ := dst[k].(map[string]any)
			if sub == nil {
				sub = map[string]any{}
				dst[k] = sub
			}
			sumInto(sub, x)
		}
	}
}

func (b *broker) handleQuota(w http.ResponseWriter, r *http.Request, g *guestState) {
	parts := b.fanout(r.Context(), g, "/v1/quota", nil)
	total := map[string]any{}
	hotels := map[string]any{}
	for hid, raw := range parts {
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil || doc["error"] != nil {
			hotels[hid] = "unavailable"
			continue
		}
		sumInto(total, map[string]any{"limits": doc["limits"], "usage": doc["usage"]})
		hotels[hid] = map[string]any{"limits": doc["limits"], "usage": doc["usage"]}
	}
	b.mu.Lock()
	mine := 0
	for _, h := range b.hotelList() {
		for _, rm := range h.rooms {
			if rm.guest == g.cfg.ID && rm.state == stRunning {
				mine++
			}
		}
	}
	lim := g.limits
	b.mu.Unlock()
	allowed := lim.Hotels
	if allowed == nil {
		allowed = []string{}
	}
	total["hotels"] = hotels
	total["guest"] = map[string]any{"id": g.cfg.ID, "running_sandboxes": mine, "max_rooms": lim.maxRooms(),
		"max_creates_per_minute": lim.MaxCreatesPerMinute, "default_sealed": lim.DefaultSealed, "allowed_hotels": allowed}
	writeJSON(w, 200, total)
}

func (b *broker) handleUsage(w http.ResponseWriter, r *http.Request, g *guestState) {
	q := r.URL.Query()
	q.Add("label", guestLabel+"="+g.cfg.ID)
	parts := b.fanout(r.Context(), g, "/v1/usage", q)
	writeJSON(w, 200, map[string]any{"hotels": parts})
}

func (b *broker) handleBulkDelete(w http.ResponseWriter, r *http.Request, g *guestState) {
	q := r.URL.Query()
	if len(q["label"]) == 0 {
		writeErr(w, 400, "invalid_label", "bulk delete requires a label filter")
		return
	}
	// Creates in flight that match this filter are deleted too (inflight.go).
	b.mu.Lock()
	b.addTombstone(g.cfg.ID, q["label"], time.Now())
	b.mu.Unlock()
	q.Add("label", guestLabel+"="+g.cfg.ID)
	res := map[string]int{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range b.hotelList() {
		if !g.limitsAllow(b, h.cfg.ID) { // a guest has no rooms outside its list
			continue
		}
		wg.Add(1)
		go func(h *hotel) {
			defer wg.Done()
			status, _, _, err := h.do(r.Context(), "DELETE", "/v1/sandboxes", q, nil, 30*time.Minute)
			if err != nil {
				status = 502
			}
			mu.Lock()
			res[h.cfg.ID] = status
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	writeJSON(w, 200, map[string]any{"hotels": res})
}

// ---------------------------------------------------------------- stats

func pct(xs []float64) map[string]float64 {
	if len(xs) == 0 {
		return map[string]float64{"n": 0}
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	at := func(p float64) float64 { return s[int(p*float64(len(s)-1))] }
	return map[string]float64{"n": float64(len(s)), "p50": at(0.5), "p95": at(0.95), "p99": at(0.99), "max": s[len(s)-1]}
}

func (b *broker) handleStats(w http.ResponseWriter, r *http.Request, g *guestState) {
	if r.Method == "POST" && !g.cfg.Ops {
		writeErr(w, 403, "forbidden", "this key may not reset the broker counters")
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.Method == "POST" {
		for _, h := range b.hotelList() {
			h.created, h.failed, h.rejected, h.lat = 0, 0, 0, latencies{}
		}
		for _, x := range b.guests {
			x.created, x.failed, x.rejected = 0, 0, 0
		}
		writeJSON(w, 200, map[string]string{"reset": "ok"})
		return
	}
	hotels := []any{}
	for _, h := range b.hotelList() {
		running := 0
		for _, rm := range h.rooms {
			if rm.state == stRunning {
				running++
			}
		}
		hotels = append(hotels, map[string]any{
			"id": h.cfg.ID, "ok": h.ok, "drain": h.drain(), "sealed": h.cfg.Sealed, "slots": h.slots, "broker_running": running, "queued": h.queued, "creating": h.creating,
			"api_running": h.apiRunning, "api_deleting": h.apiDeleting, "containers": h.containers,
			"cpu_pct": h.cpuPct, "mem_pct": h.memPct, "mem_gib": h.memGiB, "load1": h.load1, "mem_full": b.memFull(h),
			"created": h.created, "failed": h.failed, "rejected_429": h.rejected,
			"hotel_ms": pct(h.lat.hotel), "queue_ms": pct(h.lat.queue), "overhead_ms": pct(h.lat.overhead),
		})
	}
	writeJSON(w, 200, map[string]any{"guest": g.cfg.ID, "created": g.created, "failed": g.failed, "rejected_429": g.rejected, "hotels": hotels})
}

// ---------------------------------------------------------------- sync loop

type healthDoc struct {
	Slots            int  `json:"slots"`
	SandboxesRunning *int `json:"sandboxes_running"`
	Live             struct {
		CPU    *float64 `json:"host_cpu_pct"`
		MemPct float64  `json:"host_mem_used_pct"`
		MemGiB float64  `json:"host_mem_used_gib"`
		Load1  float64  `json:"load1"`
	} `json:"live"`
}

func (b *broker) syncHotel(ctx context.Context, h *hotel) {
	var hd healthDoc
	t0 := time.Now()
	herr := h.getJSON(ctx, h.cfg.Health, "/room/health", nil, &hd)
	healthMs := ms(time.Since(t0))
	var quota struct {
		Usage map[string]float64 `json:"usage"`
	}
	qerr := h.getJSON(ctx, h.cfg.API, "/v1/quota", nil, &quota)
	var list struct {
		Sandboxes []struct {
			ID     string            `json:"id"`
			State  string            `json:"state"`
			Labels map[string]string `json:"labels"`
		} `json:"sandboxes"`
	}
	lerr := h.getJSON(ctx, h.cfg.API, "/v1/sandboxes", nil, &list)
	defer b.syncAdmission(ctx, h, herr == nil) // after the health state below is stored

	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	h.lastErr = ""
	if err := errors.Join(herr, qerr, lerr); err != nil {
		h.lastErr = err.Error()
	}
	h.listOK = lerr == nil
	if herr == nil {
		h.lastOK, h.healthMs = now, healthMs
	}
	healthOK := !h.lastOK.IsZero() && now.Sub(h.lastOK) < okWindow
	// A slow health endpoint does not take a hotel out of placement while
	// the hotel still answers room calls (a sealed guest at full CPU answered
	// rooms but not health at about 1,000 rooms).
	callsOK := now.Sub(time.Unix(0, h.lastAnswer.Load())) < okWindow
	wasOK := h.ok
	h.ok = healthOK || (callsOK && !h.lastOK.IsZero())
	h.healthLate = !healthOK && h.ok
	switch {
	case h.ok:
		if !h.downSince.IsZero() {
			log.Printf("hotel %s up again after %s down", h.cfg.ID, now.Sub(h.downSince).Round(time.Second))
		}
		h.downSince = time.Time{}
	case h.downSince.IsZero():
		h.downSince = now
		// A hotel that comes back must pass attestation again: it may have
		// rebooted into another binding.
		h.adm.attestedAt, h.adm.checkedAt = time.Time{}, time.Time{}
		if wasOK {
			log.Printf("hotel %s down: %s", h.cfg.ID, h.lastErr)
		}
	}
	if herr == nil {
		slots := hd.Slots
		if h.cfg.MaxSlots > 0 && slots > h.cfg.MaxSlots {
			slots = h.cfg.MaxSlots
		}
		h.resize(slots)
		if hd.Live.CPU != nil {
			h.cpuPct = *hd.Live.CPU
		}
		h.memPct, h.memGiB, h.load1 = hd.Live.MemPct, hd.Live.MemGiB, hd.Live.Load1
		if hd.SandboxesRunning != nil {
			h.containers = *hd.SandboxesRunning
		}
	}
	if qerr == nil {
		h.apiRunning = int(quota.Usage["running_sandboxes"] + quota.Usage["frozen_sandboxes"])
		h.apiDeleting = int(quota.Usage["deleting_sandboxes"])
	}
	if lerr != nil {
		return
	}
	seen := make(map[string]bool, len(list.Sandboxes))
	for _, s := range list.Sandboxes {
		seen[s.ID] = true
		if rm := h.rooms[s.ID]; rm != nil {
			if rm.state == stDeleting && !rm.deleteSent {
				// A list that missed the room (built before its create landed)
				// marked it deleting; the hotel lists it, so it runs.
				rm.state, rm.since, rm.vanished = stRunning, now, time.Time{}
				if rm.slot < 0 {
					h.place(rm)
				}
			}
			continue
		}
		rm := &room{hid: s.ID, id: h.cfg.ID + "." + s.ID, h: h, guest: s.Labels[guestLabel], state: stRunning, since: now}
		h.rooms[s.ID] = rm
		b.register(rm)
		h.place(rm)
	}
	var deleting []*room
	for hid, rm := range h.rooms {
		if !seen[hid] && rm.state == stRunning && now.Sub(rm.since) > 5*time.Second {
			rm.state, rm.vanished = stDeleting, now
		}
		if rm.state == stDeleting {
			deleting = append(deleting, rm)
		}
	}
	// The hotel keeps a gone room in a hidden "deleting" state until its
	// container is removed. Show that many of the most recently gone rooms
	// as deleting; free the rest.
	sort.Slice(deleting, func(i, j int) bool { return deleting[i].vanished.After(deleting[j].vanished) })
	for i, rm := range deleting {
		if seen[rm.hid] {
			continue // DELETE sent, record still listed
		}
		if i >= h.apiDeleting && now.Sub(rm.vanished) > 2*time.Second {
			b.release(h, rm)
		}
	}
	for i, rm := range h.grid {
		if rm != nil && rm.state == stFailed && now.Sub(rm.since) > 30*time.Second {
			h.grid[i] = nil
		}
	}
}

func (b *broker) syncLoop(ctx context.Context, h *hotel) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		b.syncHotel(ctx, h)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---------------------------------------------------------------- live view

func (b *broker) viewGuest(r *http.Request, guestID string) (*guestState, string) {
	g := b.guests[guestID]
	if g == nil || g.cfg.ViewTokenSHA256 == "" {
		return nil, ""
	}
	want := []byte(strings.ToLower(g.cfg.ViewTokenSHA256))
	if t := r.URL.Query().Get("token"); t != "" && subtle.ConstantTimeCompare([]byte(sha(t)), want) == 1 {
		return g, t
	}
	if c, err := r.Cookie("bv_" + guestID); err == nil && subtle.ConstantTimeCompare([]byte(sha(c.Value)), want) == 1 {
		return g, ""
	}
	return nil, ""
}

// writeSignIn answers 401 with a form that asks for the view token. The form posts the token in the body,
// so it does not stay in the browser history like a ?token= link.
func writeSignIn(w http.ResponseWriter, guestID, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(401)
	note := "Enter the view token, or open the link that has the token."
	if msg != "" {
		note = msg
	}
	_, _ = fmt.Fprintf(w, `<!doctype html><meta name="viewport" content="width=device-width"><title>Central booking</title>
<body style="font:16px system-ui;background:#0A0A1A;color:#F0F0F5;padding:24px">
<form method="post" action="/%s/live/sign-in" style="display:flex;flex-direction:column;gap:12px;max-width:420px">
<label for="token">%s</label>
<input id="token" name="token" type="password" autocomplete="current-password" required style="font:16px system-ui;padding:8px">
<button type="submit" style="font:16px system-ui;padding:8px">Sign in</button>
</form></body>`, url.PathEscape(guestID), html.EscapeString(note))
}

// handleSignIn: POST /<guest>/live/sign-in with form field "token" sets the
// view cookie and redirects to the live view.
func (b *broker) handleSignIn(w http.ResponseWriter, r *http.Request, guestID string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	token := ""
	if r.ParseForm() == nil {
		token = r.PostForm.Get("token")
	}
	g := b.guests[guestID]
	if g == nil || g.cfg.ViewTokenSHA256 == "" || token == "" ||
		subtle.ConstantTimeCompare([]byte(sha(token)), []byte(strings.ToLower(g.cfg.ViewTokenSHA256))) != 1 {
		writeSignIn(w, guestID, "The token is not correct. Try again.")
		return
	}
	b.setViewCookie(w, guestID, token)
	http.Redirect(w, r, "/"+guestID+"/live", http.StatusSeeOther)
}

func (b *broker) setViewCookie(w http.ResponseWriter, guestID, token string) {
	// Lax, not Strict: a link opened from another app (for example a
	// terminal) is a cross-site navigation, and Strict would drop the
	// cookie on the redirect that follows.
	http.SetCookie(w, &http.Cookie{Name: "bv_" + guestID, Value: token, Path: "/" + guestID + "/", MaxAge: 30 * 86400,
		HttpOnly: true, Secure: !b.cfg.InsecureCookie, SameSite: http.SameSiteLaxMode})
}

func (b *broker) handleLive(w http.ResponseWriter, r *http.Request, guestID, tail string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	g, fresh := b.viewGuest(r, guestID)
	if g == nil {
		writeSignIn(w, guestID, "")
		return
	}
	if fresh != "" {
		b.setViewCookie(w, guestID, fresh)
		http.Redirect(w, r, "/"+guestID+"/live", http.StatusSeeOther)
		return
	}
	switch tail {
	case "live":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'")
		_, _ = w.Write(liveHTML)
	case "live/events":
		b.stream(w, r, g)
	default:
		http.NotFound(w, r)
	}
}

func (b *broker) snapshot(g *guestState) map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	cut := 0
	for cut < len(g.recent) && now.Sub(g.recent[cut]) > 60*time.Second {
		cut++
	}
	g.recent = g.recent[cut:]
	perSec := 0
	for _, t := range g.recent {
		if now.Sub(t) <= 5*time.Second {
			perSec++
		}
	}
	tot := map[string]int{"running": 0, "creating": 0, "deleting": 0, "failed_now": 0}
	hotels := []any{}
	for _, h := range b.hotelList() {
		grid := make([]byte, len(h.grid))
		mine := map[byte]int{}
		for i, rm := range h.grid {
			switch {
			case rm == nil:
				grid[i] = stFree
			case rm.guest == g.cfg.ID:
				grid[i] = rm.state
				mine[rm.state]++
			default:
				grid[i] = stOther
			}
		}
		tot["running"] += mine[stRunning]
		tot["creating"] += mine[stCreating]
		tot["deleting"] += mine[stDeleting]
		tot["failed_now"] += mine[stFailed]
		hotels = append(hotels, map[string]any{
			"id": h.cfg.ID, "name": h.cfg.Name, "threads": h.cfg.Threads, "ram_gib": h.cfg.RAMGiB, "slots": h.slots, "ok": h.ok, "drain": h.drain(), "sealed": h.cfg.Sealed,
			"grid": string(grid), "cpu": h.cpuPct, "mem_pct": h.memPct, "mem_gib": h.memGiB, "load1": h.load1,
			"containers": h.containers, "rooms_all": h.apiRunning, "deleting_all": h.apiDeleting,
			"queued": h.queued, "creating": h.creating,
			"seen_age_s": seenAge(h.lastOK, now), "down_since": downSince(h), "health_late": h.healthLate, "health_ms": h.healthMs, "list_ok": h.listOK, "caps": h.caps,
			"mine": map[string]int{"running": mine[stRunning], "creating": mine[stCreating], "deleting": mine[stDeleting], "failed": mine[stFailed]},
		})
	}
	return map[string]any{
		"t": now.UnixMilli(), "guest": g.cfg.ID, "hotels": hotels,
		"totals": map[string]any{"running": tot["running"], "creating": tot["creating"], "deleting": tot["deleting"],
			"queued": g.queued, "created": g.created, "failed": g.failed, "rejected": g.rejected, "creates_per_s": float64(perSec) / 5},
	}
}

func seenAge(t, now time.Time) float64 {
	if t.IsZero() {
		return -1
	}
	return float64(now.Sub(t).Milliseconds()) / 1000
}

func (b *broker) stream(w http.ResponseWriter, r *http.Request, g *guestState) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "no streaming", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		data, _ := json.Marshal(b.snapshot(g))
		if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
			return
		}
		fl.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-t.C:
		}
	}
}

// ---------------------------------------------------------------- routing

func (b *broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/healthz" {
		writeJSON(w, 200, map[string]string{"status": "ok"})
		return
	}
	if (p == "/v1/broker/hotels" && r.Method != "GET") || strings.HasPrefix(p, "/v1/broker/hotels/") {
		b.handleHotelAdmin(w, r, strings.TrimPrefix(strings.TrimPrefix(p, "/v1/broker/hotels"), "/"))
		return
	}
	if p == "/v1/broker/capacity" && r.Method == "GET" && b.isOperator(r) {
		b.handleCapacity(w, nil) // every hotel; a guest key gets its own view (serveNative)
		return
	}
	if p == "/v1/broker/guests" || strings.HasPrefix(p, "/v1/broker/guests/") {
		b.handleGuestAdmin(w, r, strings.TrimPrefix(strings.TrimPrefix(p, "/v1/broker/guests"), "/"))
		return
	}
	if strings.HasPrefix(p, "/v1/") {
		g := b.guestFromKey(r)
		if g == nil {
			if isCompat(r) {
				compatErr(w, 401, "unauthorized", "missing or unknown Bearer key", 0)
				return
			}
			writeErr(w, 401, "unauthorized", "missing or unknown Bearer key")
			return
		}
		if isCompat(r) {
			b.serveCompat(w, r, g)
			return
		}
		b.serveNative(w, r, g)
		return
	}
	// /<guest>/live and /<guest>/live/events
	parts := strings.SplitN(strings.TrimPrefix(p, "/"), "/", 2)
	if len(parts) == 2 && parts[1] == "live/sign-in" && r.Method == "POST" {
		b.handleSignIn(w, r, parts[0])
		return
	}
	if len(parts) == 2 && (parts[1] == "live" || parts[1] == "live/events") {
		b.handleLive(w, r, parts[0], parts[1])
		return
	}
	http.NotFound(w, r)
}

func (b *broker) serveNative(w http.ResponseWriter, r *http.Request, g *guestState) {
	p := r.URL.Path
	{
		switch {
		case p == "/v1/sandboxes" && r.Method == "POST":
			b.handleCreate(w, r, g)
		case p == "/v1/sandboxes" && r.Method == "GET":
			b.handleList(w, r, g)
		case p == "/v1/sandboxes" && r.Method == "DELETE":
			b.handleBulkDelete(w, r, g)
		case strings.HasPrefix(p, "/v1/sandboxes/"):
			b.handleRoom(w, r, g, strings.TrimPrefix(p, "/v1/sandboxes/"))
		case strings.HasPrefix(p, "/v1/hotels/"):
			b.handleHotelDoc(w, r, strings.TrimPrefix(p, "/v1/hotels/"), g)
		case p == "/v1/quota" && r.Method == "GET":
			b.handleQuota(w, r, g)
		case p == "/v1/usage" && r.Method == "GET":
			b.handleUsage(w, r, g)
		case p == "/v1/images/prefetch" && r.Method == "POST":
			b.handlePrefetch(w, r, g)
		case strings.HasPrefix(p, "/v1/images/prefetch/") && r.Method == "GET":
			b.handlePrefetchStatus(w, g, strings.TrimPrefix(p, "/v1/images/prefetch/"))
		case p == "/v1/snapshots" && r.Method == "GET":
			b.handleSnapshotList(w, r, g)
		case strings.HasPrefix(p, "/v1/snapshots/"):
			b.handleSnapshot(w, r, g, strings.TrimPrefix(p, "/v1/snapshots/"))
		case p == "/v1/workspaces" && (r.Method == "GET" || r.Method == "POST"):
			b.handleWorkspaces(w, r, g)
		case strings.HasPrefix(p, "/v1/workspaces/"):
			b.handleWorkspace(w, r, g, strings.TrimPrefix(p, "/v1/workspaces/"))
		case p == "/v1/secrets" || strings.HasPrefix(p, "/v1/secrets/"):
			name, ok := secretRoute(p)
			if !ok {
				writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+p)
				return
			}
			b.handleSecrets(w, r, g, name)
		case p == "/v1/broker/hotels" && r.Method == "GET":
			b.handleHotels(w, g)
		case p == "/v1/broker/capacity" && r.Method == "GET":
			b.handleCapacity(w, g)
		case p == "/v1/broker/stats":
			b.handleStats(w, r, g)
		case p == "/v1/broker/probe" && r.Method == "POST":
			if !g.cfg.Ops {
				writeErr(w, 403, "forbidden", "this key may not run the probe")
				return
			}
			b.handleProbe(w, r, g)
		case p == "/v1/status":
			b.mu.Lock()
			up := 0
			for _, h := range b.hotelList() {
				if h.ok {
					up++
				}
			}
			b.mu.Unlock()
			writeJSON(w, 200, map[string]any{"service": "central-booking", "hotels": len(b.hotelList()), "hotels_up": up, "uptime_s": int(time.Since(b.started).Seconds())})
		default:
			writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+p)
		}
	}
}

// count 429s sent to guests (no free rooms) for the live counters.
type countingWriter struct {
	http.ResponseWriter
	status int
}

func (c *countingWriter) WriteHeader(s int) { c.status = s; c.ResponseWriter.WriteHeader(s) }
func (c *countingWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func main() {
	cfgPath := flag.String("config", "/etc/thin-broker/config.json", "private config file")
	flag.Parse()
	b, err := loadBroker(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	if strings.TrimSpace(b.cfg.Listen) == "" {
		log.Fatal("config: listen is required (an empty listen would bind :http on every interface)")
	}
	ctx, stopLoops := context.WithCancel(context.Background())
	if err := b.loadCompat(); err != nil {
		log.Printf("client state not loaded: %v", err)
	}
	if err := b.loadRuntimeHotels(); err != nil {
		log.Printf("runtime hotels not loaded: %v", err)
	}
	b.loadCaps() // after the runtime hotels, or their probe results are dropped
	saved := make(chan struct{})
	go func() {
		b.saveLoop(ctx)
		close(saved)
	}()
	for _, h := range b.hotelList() {
		b.startSync(ctx, h)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cw := &countingWriter{ResponseWriter: w, status: 200}
		b.ServeHTTP(cw, r)
		if cw.status == 429 && r.URL.Path == "/v1/sandboxes" && r.Method == "POST" {
			if g := b.guestFromKey(r); g != nil {
				b.mu.Lock()
				g.rejected++
				b.mu.Unlock()
			}
		}
	})
	// No WriteTimeout: an exec may run for hours. IdleTimeout closes kept-alive
	// connections that send nothing, so they cannot pile up to the fd limit.
	srv := &http.Server{Addr: b.cfg.Listen, Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	// A restart (systemctl sends SIGTERM) stops taking requests, lets the ones
	// in flight finish for a short while, then writes the client state: ids
	// and idempotency answers from the last second must not be lost.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-stop
		log.Printf("%s: stopping, saving client state", sig)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		stopLoops()
		<-saved // saveLoop writes dirty state on its way out
		os.Exit(0)
	}()
	log.Printf("central booking on %s: %d hotels, %d guests", b.cfg.Listen, len(b.hotelList()), len(b.guests))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
	select {} // the signal goroutine exits the process
}

// errCodeOf reads error.code from a hotel's JSON error body.
func errCodeOf(body []byte) string {
	var doc struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &doc)
	return doc.Error.Code
}

// guestImageFault reports whether a hotel's image_pull_failed message names
// a missing or denied image (the guest's error) rather than a hotel fault.
func guestImageFault(body []byte) bool {
	var doc struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &doc)
	m := strings.ToLower(doc.Error.Message)
	for _, s := range []string{"manifest unknown", "not found", "pull access denied", "repository does not exist", "invalid reference format", "unauthorized"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}
