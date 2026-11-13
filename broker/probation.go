// Miner probation (AB#334).
//
// With "miner_probation_seconds" > 0, a miner hotel that joins starts on
// probation. On probation it takes test traffic only: a guest reaches it
// only when its policy opts in to miner hotels (label miner=true) and also
// sets "miner_probation": true. A shared-pool guest, which opts in to miner
// hotels without that flag, does not see it in the catalog and cannot place
// on it. minerOptIn (capacity.go) is the one check, so placement, the
// catalog, the live view, forks and workspaces all agree. A miner hotel off
// probation also carries the computed label graduated=true (hotel.labels),
// so a shared-pool policy can prefer graduated miners by label.
//
// The hotel graduates to the shared pool when the broker has observed it for
// the window and it was up for at least "miner_probation_min_uptime_pct"
// (default 99) of the observed time. "Up" is the verified state the placer
// uses: health answers (h.ok), the SEV-SNP admission pass is fresh
// (admission.go), and the hotel is neither draining nor leaving. The sync
// loop samples it every tick; an interval counts as up only when the samples
// at both ends saw the hotel up. Time the broker did not observe (the broker
// was down) is not counted either way: after a restart the first sample only
// sets the clock.
//
// A window that ends under the minimum does not graduate: the miss is counted,
// its uptime is kept for the readback, and a fresh window starts. A graduated
// hotel stays graduated; keeping it online after that is uptime enforcement
// (AB#323), not probation.
//
// State lives in state_dir/miner-probation.json, keyed by hotel id with the
// miner hotkey and the attested TLS pin, so a restart keeps the progress and
// a different machine under the same id does not inherit it. A join or rejoin
// always starts a fresh probation. When probation is turned on for the first
// time (no file yet), the miner hotels that are already serving are
// grandfathered as graduated, so their running rooms stay reachable.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"time"
)

const (
	probationFile          = "miner-probation.json"
	defaultProbationMinPct = 99.0
	probationSaveEvery     = time.Minute
)

// probation is the probation state of a miner hotel. Guarded by broker.mu,
// except that hotel.probationOn mirrors !graduated for lock-free reads.
type probation struct {
	set           bool // initialised for this hotel object (addHotel)
	graduated     bool
	grandfathered bool      // graduated because it served before probation was turned on
	graduatedAt   time.Time // zero while on probation
	startedAt     time.Time // start of the current window
	lastSample    time.Time // zero: the next sample only sets the clock
	lastUp        bool
	observed      time.Duration // in the current window
	up            time.Duration // in the current window
	windowsFailed int
	lastWindowBP  int // uptime of the last failed window in basis points; -1: none
}

// probationWindow is the configured window, 0 when probation is off.
func (b *broker) probationWindow() time.Duration {
	if b.cfg.MinerProbationSeconds <= 0 {
		return 0
	}
	return time.Duration(b.cfg.MinerProbationSeconds * float64(time.Second))
}

// probationMinBP is the minimum uptime in basis points (9900 for 99%).
func (b *broker) probationMinBP() int64 {
	pct := b.cfg.MinerProbationMinUptimePct
	if pct == 0 {
		pct = defaultProbationMinPct
	}
	return int64(math.Round(pct * 100))
}

func validateProbationConfig(c config) error {
	if c.MinerProbationSeconds < 0 || math.IsNaN(c.MinerProbationSeconds) || math.IsInf(c.MinerProbationSeconds, 0) {
		return errors.New("config: miner_probation_seconds must be 0 (off) or a positive number of seconds")
	}
	if p := c.MinerProbationMinUptimePct; p < 0 || p > 100 || math.IsNaN(p) {
		return errors.New("config: miner_probation_min_uptime_pct must be in (0, 100] (absent or 0: 99)")
	}
	return nil
}

// inProbation reports whether h takes test traffic only. Lock-free.
func (h *hotel) inProbation() bool { return h.probationOn.Load() }

// initProbation starts the probation of a miner hotel that is added to the
// set. A hotel object that was added before (a failed leave puts it back)
// keeps its state. Caller holds b.mu.
func (b *broker) initProbation(h *hotel) {
	if h.prob.set {
		return
	}
	h.prob = probation{set: true, lastWindowBP: -1}
	if h.cfg.MinerHotkey == "" || b.probationWindow() == 0 {
		h.prob.graduated = true
		return
	}
	h.probationOn.Store(true)
}

// graduate ends the probation of h at now. Caller holds b.mu.
func (h *hotel) graduate(now time.Time, grandfathered bool) {
	h.prob.graduated, h.prob.grandfathered, h.prob.graduatedAt = true, grandfathered, now
	h.probationOn.Store(false)
}

// step adds one sample. It reports whether the state changed in a way that
// must be saved now (graduation or a failed window). Caller holds b.mu.
func (h *hotel) probationStep(now time.Time, up bool, window time.Duration, minBP int64) bool {
	p := &h.prob
	if !p.set || p.graduated || window <= 0 {
		return false
	}
	if p.lastSample.IsZero() {
		p.lastSample, p.lastUp = now, up
		if p.startedAt.IsZero() {
			p.startedAt = now
		}
		return false
	}
	dt := now.Sub(p.lastSample)
	if dt < 0 {
		dt = 0
	}
	p.observed += dt
	if p.lastUp && up {
		p.up += dt
	}
	p.lastSample, p.lastUp = now, up
	if p.observed < window {
		return false
	}
	obs, upMs := p.observed.Milliseconds(), p.up.Milliseconds()
	if upMs*10000 >= obs*minBP {
		h.graduate(now, false)
		log.Printf("miner hotel %s graduated from probation: up %d of %d ms observed", h.cfg.ID, upMs, obs)
		return true
	}
	p.windowsFailed++
	p.lastWindowBP = int(upMs * 10000 / obs)
	log.Printf("miner hotel %s stays on probation: uptime %.2f%% under the minimum %.2f%%; a new window starts",
		h.cfg.ID, float64(p.lastWindowBP)/100, float64(minBP)/100)
	p.observed, p.up, p.startedAt = 0, 0, now
	return true
}

// probationUp is the verified up state of the package comment. Caller holds b.mu.
func (b *broker) probationUp(h *hotel, now time.Time) bool {
	return h.ok && !h.leaving && !h.drain() && b.admitted(h, now)
}

// sampleProbation is the sync loop's probation step for h, run after the
// health and attestation steps of the same tick.
func (b *broker) sampleProbation(h *hotel) {
	window := b.probationWindow()
	if window == 0 || h.cfg.MinerHotkey == "" {
		return
	}
	b.mu.Lock()
	if b.hotelByID(h.cfg.ID) != h { // left meanwhile
		b.mu.Unlock()
		return
	}
	now := time.Now()
	was := h.prob.graduated
	changed := h.probationStep(now, b.probationUp(h, now), window, b.probationMinBP())
	save := changed || (!was && now.Sub(b.probationSavedAt) >= probationSaveEvery)
	if save {
		b.probationSavedAt = now
	}
	b.mu.Unlock()
	if save {
		b.saveProbationLogged()
	}
}

// savedProbation is one hotel in miner-probation.json.
type savedProbation struct {
	MinerHotkey   string    `json:"miner_hotkey"`
	TLSSPKISHA256 string    `json:"tls_spki_sha256"`
	Graduated     bool      `json:"graduated"`
	Grandfathered bool      `json:"grandfathered,omitempty"`
	GraduatedAt   time.Time `json:"graduated_at,omitempty"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	ObservedMs    int64     `json:"observed_ms"`
	UpMs          int64     `json:"up_ms"`
	WindowsFailed int       `json:"windows_failed"`
	LastWindowBP  int       `json:"last_window_uptime_bp"`
}

// saveProbation writes the probation state of every miner hotel. It takes
// probationFileMu, then b.mu for the snapshot only; callers hold neither.
func (b *broker) saveProbation() error {
	if b.cfg.StateDir == "" || b.probationWindow() == 0 {
		return nil
	}
	b.probationFileMu.Lock()
	defer b.probationFileMu.Unlock()
	out := map[string]savedProbation{}
	b.mu.Lock()
	for _, h := range b.hotelList() {
		if h.cfg.MinerHotkey == "" || !h.prob.set {
			continue
		}
		p := h.prob
		out[h.cfg.ID] = savedProbation{MinerHotkey: h.cfg.MinerHotkey, TLSSPKISHA256: h.cfg.TLSSPKISHA256,
			Graduated: p.graduated, Grandfathered: p.grandfathered, GraduatedAt: p.graduatedAt, StartedAt: p.startedAt,
			ObservedMs: p.observed.Milliseconds(), UpMs: p.up.Milliseconds(), WindowsFailed: p.windowsFailed, LastWindowBP: p.lastWindowBP}
	}
	b.mu.Unlock()
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(b.cfg.StateDir, probationFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(b.cfg.StateDir, probationFile))
}

func (b *broker) saveProbationLogged() {
	if err := b.saveProbation(); err != nil {
		log.Printf("MINER PROBATION NOT SAVED: %v; a restart would lose the progress since the last save", err)
	}
}

// loadProbation restores the probation state of the miner hotels restored
// from hotels.json. Runs once at start, before the sync loops.
func (b *broker) loadProbation() error {
	if b.cfg.StateDir == "" || b.probationWindow() == 0 {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(b.cfg.StateDir, probationFile))
	first := os.IsNotExist(err)
	if err != nil && !first {
		return err
	}
	saved := map[string]savedProbation{}
	if !first {
		if err := json.Unmarshal(raw, &saved); err != nil {
			return fmt.Errorf("%s: %w", probationFile, err)
		}
	}
	now := time.Now()
	b.mu.Lock()
	for _, h := range b.hotelList() {
		if h.cfg.MinerHotkey == "" || !h.prob.set || h.prob.graduated {
			continue
		}
		if first {
			// Probation was just turned on: this hotel was already serving.
			h.graduate(now, true)
			log.Printf("miner hotel %s grandfathered: it served before miner probation was turned on", h.cfg.ID)
			continue
		}
		s, ok := saved[h.cfg.ID]
		if !ok || s.MinerHotkey != h.cfg.MinerHotkey || s.TLSSPKISHA256 != h.cfg.TLSSPKISHA256 {
			continue // a fresh probation
		}
		if s.Graduated {
			h.graduate(s.GraduatedAt, s.Grandfathered)
			continue
		}
		h.prob.startedAt, h.prob.observed, h.prob.up = s.StartedAt, time.Duration(s.ObservedMs)*time.Millisecond, time.Duration(s.UpMs)*time.Millisecond
		h.prob.windowsFailed, h.prob.lastWindowBP = s.WindowsFailed, s.LastWindowBP
	}
	b.mu.Unlock()
	return b.saveProbation()
}

// probationDoc is the probation readback of a miner hotel, nil when probation
// is off or h is not a miner hotel. Caller holds b.mu.
func (b *broker) probationDoc(h *hotel) map[string]any {
	window := b.probationWindow()
	if window == 0 || h.cfg.MinerHotkey == "" || !h.prob.set {
		return nil
	}
	p := h.prob
	d := map[string]any{"state": "probation", "window_s": window.Seconds(), "min_uptime_pct": float64(b.probationMinBP()) / 100,
		"observed_s": p.observed.Seconds(), "up_s": p.up.Seconds(), "windows_failed": p.windowsFailed}
	if obs := p.observed.Milliseconds(); obs > 0 {
		d["uptime_pct"] = float64(p.up.Milliseconds()*10000/obs) / 100
	}
	if p.lastWindowBP >= 0 {
		d["last_window_uptime_pct"] = float64(p.lastWindowBP) / 100
	}
	if !p.startedAt.IsZero() {
		d["started_at"] = p.startedAt.UTC().Format(time.RFC3339)
	}
	if p.graduated {
		d["state"] = "graduated"
		if p.grandfathered {
			d["grandfathered"] = true
		}
		if !p.graduatedAt.IsZero() {
			d["graduated_at"] = p.graduatedAt.UTC().Format(time.RFC3339)
		}
	}
	return d
}
