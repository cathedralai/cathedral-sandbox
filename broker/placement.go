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
//     slot moves to another eligible hotel, if one has a free room. If none
//     has, it keeps waiting where it is.
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
)

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
			b.mu.Lock()
			exclude := map[*hotel]bool{h: true}
			for t := range tried {
				exclude[t] = true
			}
			if alt := b.pick(exclude, pl); alt != nil {
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
