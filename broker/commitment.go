// Capacity commitment of a miner hotel (AB#331).
//
// A miner declares at join how much it commits: a number of slots and the
// hours per UTC day it keeps them up ("commitment": {"slots": 8,
// "daily_hours": 20}). The broker config can set a floor,
// "miner_min_commitment": {"slots": 4, "daily_hours": 12}. With a floor set,
// a miner join without a commitment is refused (422 commitment_required), and
// so is one below the floor in either field (422 commitment_below_minimum).
// Nothing is stored for a refused join. Without a floor a commitment is
// optional. The floor governs new joins only: a hotel restored from
// hotels.json after a restart keeps the commitment it joined with, as with
// the hotkey caps.
//
// The sync loop measures what the hotel delivers against the declaration,
// per UTC day:
//
//   - hours_up: up (h.ok), admitted, not drained and not leaving;
//   - hours_at_commitment: of that, the time it offered at least the
//     committed slots;
//   - slot_hours: offered slots over time, each tick's slots capped at the
//     committed number (more than declared earns no extra).
//
// Offered slots are the slots the hotel reported this tick, capped by
// max_slots; when health did not answer but room calls do, the slots
// placement still uses. An operator PATCH of max_slots below the committed
// slots is allowed, and shows here as a shortfall. A day is met when
// hours_at_commitment reaches daily_hours. Each day carries "since", its
// first tick, so a partial day (the join day, or after a broker restart) is
// visible. The counters live in memory: a broker restart starts a new day
// record.
package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"time"
)

// maxDeliveryTick is the longest gap between two sync ticks that is credited.
// One tick makes three sequential hotel calls of up to 10 s each; a longer
// gap means the loop stalled, and the stall is not credited.
const maxDeliveryTick = 40 * time.Second

// capacityCommitment is what a miner hotel declares, or the broker's floor.
type capacityCommitment struct {
	Slots      int     `json:"slots"`
	DailyHours float64 `json:"daily_hours"`
}

// deliveryDay is one UTC day of delivered capacity. Seconds internally.
type deliveryDay struct {
	day                string // YYYY-MM-DD, UTC
	since              time.Time
	upSec, atCommitSec float64
	slotSec            float64
}

// delivery is the measurement of a committed hotel. Guarded by broker.mu.
type delivery struct {
	lastTick time.Time
	today    *deliveryDay
	previous *deliveryDay
}

// validateCommitment checks the shape of a declared commitment. maxSlots is
// the hotel's max_slots (0: no cap).
func validateCommitment(c *capacityCommitment, maxSlots int) error {
	switch {
	case c.Slots < 1:
		return errors.New("commitment.slots must be 1 or more")
	case math.IsNaN(c.DailyHours) || c.DailyHours <= 0 || c.DailyHours > 24:
		return errors.New("commitment.daily_hours must be more than 0 and at most 24")
	case maxSlots > 0 && c.Slots > maxSlots:
		return fmt.Errorf("commitment.slots %d is more than max_slots %d", c.Slots, maxSlots)
	}
	return nil
}

// validateMinCommitment checks the broker config's miner_min_commitment.
func validateMinCommitment(c *capacityCommitment) error {
	if c == nil {
		return nil
	}
	if c.Slots < 0 || math.IsNaN(c.DailyHours) || c.DailyHours < 0 || c.DailyHours > 24 {
		return errors.New("config: miner_min_commitment needs slots >= 0 and daily_hours from 0 to 24")
	}
	return nil
}

// minCommitmentSet reports whether the broker has a floor.
func (b *broker) minCommitmentSet() bool {
	m := b.cfg.MinerMinCommitment
	return m != nil && (m.Slots > 0 || m.DailyHours > 0)
}

// errCommitment is a join refused for its commitment: code is the error code.
type errCommitment struct {
	status int
	code   string
	msg    string
}

func (e errCommitment) Error() string { return e.msg }

// checkJoinCommitment is the admission check of a join's commitment. It runs
// before any call to the hotel.
func (b *broker) checkJoinCommitment(hc hotelConfig) error {
	c := hc.Commitment
	if hc.MinerHotkey == "" {
		if c != nil {
			return errCommitment{400, "invalid_commitment", "only a miner hotel declares a commitment"}
		}
		return nil
	}
	if c == nil {
		if b.minCommitmentSet() {
			m := b.cfg.MinerMinCommitment
			return errCommitment{422, "commitment_required",
				fmt.Sprintf("a miner hotel must declare a commitment of at least %d slots for %g hours a day", m.Slots, m.DailyHours)}
		}
		return nil
	}
	if err := validateCommitment(c, hc.MaxSlots); err != nil {
		return errCommitment{400, "invalid_commitment", err.Error()}
	}
	if b.minCommitmentSet() {
		m := b.cfg.MinerMinCommitment
		if c.Slots < m.Slots || c.DailyHours < m.DailyHours {
			return errCommitment{422, "commitment_below_minimum",
				fmt.Sprintf("commitment of %d slots for %g hours a day is below the minimum of %d slots for %g hours a day",
					c.Slots, c.DailyHours, m.Slots, m.DailyHours)}
		}
	}
	return nil
}

// recordDelivery credits one sync tick to h's delivery. offered is the slots
// the hotel offers this tick (max_slots applied). slotsTrusted is true only
// when this tick got a fresh /room/health slot report; a health miss must not
// credit stale last-known slots (AB#331). Caller holds b.mu.
func (b *broker) recordDelivery(h *hotel, offered int, now time.Time, slotsTrusted bool) {
	c := h.cfg.Commitment
	if c == nil {
		return
	}
	d := &h.delivery
	day := now.UTC().Format("2006-01-02")
	if d.today == nil || d.today.day != day {
		if d.today != nil {
			d.previous = d.today
			p := d.previous
			log.Printf("hotel %s commitment %s: %.2f of %g hours at %d slots (met: %v), %.2f hours up, %.2f slot-hours",
				h.cfg.ID, p.day, p.atCommitSec/3600, c.DailyHours, c.Slots, p.atCommitSec/3600 >= c.DailyHours, p.upSec/3600, p.slotSec/3600)
		}
		d.today = &deliveryDay{day: day, since: now}
	}
	dt := 0.0
	if !d.lastTick.IsZero() && now.After(d.lastTick) && now.Sub(d.lastTick) <= maxDeliveryTick {
		dt = now.Sub(d.lastTick).Seconds()
	}
	d.lastTick = now
	if dt == 0 || !h.ok || h.leaving || h.drain() || !b.admitted(h, now) {
		return
	}
	d.today.upSec += dt
	if !slotsTrusted {
		// Room calls can keep h.ok true while health is late; uptime still
		// counts, but slot delivery needs a trusted report this tick.
		return
	}
	if offered >= c.Slots {
		d.today.atCommitSec += dt
	}
	d.today.slotSec += float64(min(offered, c.Slots)) * dt
}

func roundHours(sec float64) float64 { return math.Round(sec/36) / 100 }

func (d *deliveryDay) doc(c *capacityCommitment) map[string]any {
	return map[string]any{"day": d.day, "since": d.since.UTC().Format(time.RFC3339),
		"hours_up": roundHours(d.upSec), "hours_at_commitment": roundHours(d.atCommitSec),
		"slot_hours": roundHours(d.slotSec), "slot_hours_committed": float64(c.Slots) * c.DailyHours,
		"met": d.atCommitSec/3600 >= c.DailyHours}
}

// commitmentDoc is the commitment part of a hotel document: nil without a
// commitment. Caller holds b.mu.
func (b *broker) commitmentDoc(h *hotel) map[string]any {
	c := h.cfg.Commitment
	if c == nil {
		return nil
	}
	d := map[string]any{"slots": c.Slots, "daily_hours": c.DailyHours, "today": nil, "previous_day": nil}
	if h.delivery.today != nil {
		d["today"] = h.delivery.today.doc(c)
	}
	if h.delivery.previous != nil {
		d["previous_day"] = h.delivery.previous.doc(c)
	}
	return d
}
