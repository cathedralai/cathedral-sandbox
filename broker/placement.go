// Placement weight and queue moves (run 5, 2000-room step).
//
// The broker used to fix a create's hotel when the create arrived, with
// weight = free rooms. A hotel with many free rooms but a full create queue
// and a busy CPU kept getting creates: creates waited up to 19 minutes on a
// hotel at 99-100% CPU while another hotel had hundreds of free rooms.
//
// Now:
//   - The weight of a hotel is free rooms x CPU headroom / (create time x
//     (1 + expected queue wait)). CPU comes from the hotel health
//     (host_cpu_pct); create time is a moving average of the hotel create call.
//   - A create that waits longer than max_queue_wait_seconds for a create
//     slot moves to another eligible hotel that has a free room and less
//     than half the expected wait. Otherwise it keeps waiting. It may move
//     back to a hotel it left earlier.
package main

import (
	"context"
	"time"
)

const (
	defaultMaxQueueWait = 10 * time.Second
	defaultCreateSec    = 1.0  // create time before the first measured create
	minHeadroom         = 0.05 // a hotel at 100% CPU keeps a small weight
	ewmaAlpha           = 0.2
	defaultMemFullPct   = 90.0 // host memory use at which a hotel takes no new rooms
)

// memFull reports whether h is at the memory limit (config mem_full_pct).
// The reading is the hotel's host_mem_used_pct (MemTotal minus MemAvailable,
// so page cache does not count). A hotel with no reading yet has memPct 0,
// which is under any limit. Caller holds b.mu.
func (b *broker) memFull(h *hotel) bool {
	limit := b.cfg.MemFullPct
	switch {
	case limit < 0:
		return false
	case limit == 0:
		limit = defaultMemFullPct
	}
	return h.memPct >= limit
}

// freeFor is the number of rooms h can take now: its free slots, or 0 when
// it is at the memory limit. Caller holds b.mu.
func (b *broker) freeFor(h *hotel) int {
	if b.memFull(h) {
		return 0
	}
	return h.slots - h.used()
}

func (b *broker) maxQueueWait() time.Duration {
	switch v := b.cfg.MaxQueueWaitSeconds; {
	case v < 0:
		return 0 // never move
	case v == 0:
		return defaultMaxQueueWait
	default:
		return time.Duration(v * float64(time.Second))
	}
}

// noteCreate adds one create call time to the moving average. Caller holds b.mu.
func (h *hotel) noteCreate(d time.Duration) {
	sec := d.Seconds()
	if h.createEWMA == 0 {
		h.createEWMA = sec
		return
	}
	h.createEWMA = ewmaAlpha*sec + (1-ewmaAlpha)*h.createEWMA
}

// expectedWait is the time in seconds until a create that joins the queue
// now (extra = 1) or is already in it (extra = 0) can start. Caller holds b.mu.
func (h *hotel) expectedWait(extra int) float64 {
	create := h.createEWMA
	if create <= 0 {
		create = defaultCreateSec
	}
	slots := cap(h.sem)
	if slots < 1 {
		slots = 1
	}
	ahead := h.queued + h.creating + extra - slots
	if ahead < 0 {
		ahead = 0
	}
	return float64(ahead) / float64(slots) * create
}

// weight of a hotel with free > 0 free rooms. Caller holds b.mu.
func (h *hotel) weight(free int) float64 {
	headroom := 1.0
	if h.cpuPct > 0 {
		headroom = (100 - h.cpuPct) / 100
	}
	if headroom < minHeadroom {
		headroom = minHeadroom
	}
	create := h.createEWMA
	if create <= 0 {
		create = defaultCreateSec
	}
	slots := cap(h.sem)
	if slots < 1 {
		slots = 1
	}
	wait := float64(h.queued+h.creating) / float64(slots) * create // seconds until a new create starts
	return float64(free) * headroom / (create * (1 + wait))
}

// waitSlot waits for a create slot at h. h.queued and g.queued count the
// create while it waits. After the queue wait limit it moves the create to
// another eligible hotel that pick chooses, if there is one. It returns the
// hotel whose slot it holds, or nil when ctx ends (counts released).
func (b *broker) waitSlot(ctx context.Context, g *guestState, h *hotel, pl placement, tried map[*hotel]bool) *hotel {
	limit := b.maxQueueWait()
	var timer <-chan time.Time
	if limit > 0 {
		t := time.NewTimer(limit)
		defer t.Stop()
		timer = t.C
	}
	for {
		select {
		case h.sem <- struct{}{}:
			return h
		case <-ctx.Done():
			b.mu.Lock()
			h.queued--
			g.queued--
			b.mu.Unlock()
			return nil
		case <-timer:
			// Only the current hotel is excluded: a create that left a hotel
			// may go back to it when that hotel is the faster one now. The
			// move needs a clear gain (half the expected wait), so creates
			// do not swing between two hotels.
			b.mu.Lock()
			// A create queued on a preferred hotel moves only to another
			// preferred hotel: that hotel has a room, so the allowed tier is
			// not open to it.
			mpl := pl
			if pl.policy != nil && pl.tier == "" && pl.policy.tier(h) == tierPrefer {
				mpl.tier = tierPrefer
			}
			if alt := b.pick(map[*hotel]bool{h: true}, mpl); alt != nil && alt.expectedWait(1) < h.expectedWait(0)/2 {
				h.queued--
				alt.queued++
				h.moved++
				tried[alt] = true
				h = alt
			}
			b.mu.Unlock()
			timer = time.After(limit)
		}
	}
}
