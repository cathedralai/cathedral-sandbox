// Disk budget of a hotel (AB#831).
//
// A room's disk is its resources.disk_gib (the hotel default is 10 GiB). The
// hotel enforces it (rootfs size and the /work quota), but its slots assume
// 10 GiB per room and scratch is thin, so nothing refused a room the scratch
// could not hold: a full scratch showed up as ENOSPC in the middle of a job.
//
// A hotel with "disk_extra_gib" set takes rooms above the base disk only
// while the extra of its rooms (disk_gib - 10 for each room above 10 GiB,
// counting rooms queued and creating) plus the new room's extra fits the
// budget, and while its last health reading of room_data_used_pct is under
// diskFullPct. Rooms of 10 GiB or less are never affected. A hotel without
// disk_extra_gib has no disk admission at all (the behaviour before AB#831).
//
// A hotel with "disk_admit_used_pct" set admits by real use instead (AB#831,
// 50 GiB default): every room's disk is its ceiling, not a reservation, so
// the room count stays bound by memory. It takes any room while its last
// room_data_used_pct is under the value and no room at all at or above it
// (sold out, not an error); disk_extra_gib is not counted there. With no
// reading yet it takes rooms of the base disk or less only.
//
// The check runs in pickIn, under b.mu, with the queue and slot counts, so
// two big creates can never both take the last of one hotel's budget.
// When no hotel fits only because of disk, the create answers 429
// disk_sold_out with Retry-After.
package main

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
)

const (
	baseRoomDiskGiB       = 10   // the disk every hotel slot assumes; rooms at or under it never count
	diskFullPct           = 80.0 // room_data_used_pct at which a hotel takes no more big-disk rooms
	diskSoldOutRetryAfter = 60   // seconds; disk frees only as rooms end
)

// noDiskCheck as a placement's diskGiB skips the disk check (withoutDisk).
const noDiskCheck = -1

// diskExtra is how much of a room's disk counts against a hotel budget.
func diskExtra(diskGiB int) int { return max(diskGiB-baseRoomDiskGiB, 0) }

// diskGiBOf reads resources.disk_gib from a create body or a hotel room
// document. 0: absent or not a number (the hotel default, 10 GiB).
func diskGiBOf(resources any) int {
	m, ok := resources.(map[string]any)
	if !ok {
		return 0
	}
	switch v := m["disk_gib"].(type) {
	case float64:
		if v > 0 && v < math.MaxInt32 {
			return int(math.Ceil(v))
		}
	case int:
		return max(v, 0)
	}
	return 0
}

// checkDiskConfig validates disk_extra_gib of a config file hotel or a join.
func checkDiskConfig(hc hotelConfig) error {
	if hc.DiskExtraGiB != nil && *hc.DiskExtraGiB < 0 {
		return fmt.Errorf("disk_extra_gib must be absent (no disk limit), 0 (rooms of %d GiB or less only) or more", baseRoomDiskGiB)
	}
	if p := hc.DiskAdmitUsedPct; p != nil && (math.IsNaN(*p) || *p < 1 || *p > 99) {
		return fmt.Errorf("disk_admit_used_pct must be absent (disk_extra_gib rule) or 1 to 99")
	}
	return nil
}

// holdDisk takes (sign 1) or gives back (sign -1) the extra disk of a create
// of pl on h while it is queued or creating. Caller holds b.mu.
func (h *hotel) holdDisk(pl placement, sign int) {
	extra := diskExtra(pl.diskGiB)
	if extra == 0 {
		return
	}
	h.diskPending += sign * extra
}

// diskExtraUsed is the extra disk of h's rooms plus the creates queued or
// creating there. A room the sync loop adopts while its create is still in
// flight counts twice until the create returns: on purpose, as the error is
// a short false disk_sold_out, never a hotel filled over budget (skipping
// such rooms undercounted a started room of a failed create until its batch
// ended). A room the hotel killed after a delete is out of the room list
// but holds its disk until docker rm ends: the hotel reports that extra disk
// as removing_disk_gib (AB#863) and it counts here. Caller holds b.mu.
func (h *hotel) diskExtraUsed() int {
	n := h.diskPending + h.removingDiskGiB
	for _, rm := range h.rooms {
		n += diskExtra(rm.diskGiB)
	}
	return n
}

// diskFits reports whether h may take a room of diskGiB now (0: the hotel
// default, noDiskCheck: always). Caller holds b.mu.
func (b *broker) diskFits(h *hotel, diskGiB int) bool {
	if diskGiB == noDiskCheck {
		return true
	}
	extra := diskExtra(diskGiB)
	if limit := h.cfg.DiskAdmitUsedPct; limit != nil {
		if h.roomDataPct == nil {
			return extra == 0
		}
		return *h.roomDataPct < *limit
	}
	budget := h.cfg.DiskExtraGiB
	if extra <= 0 || budget == nil {
		return true
	}
	if h.roomsUnchecked {
		// Loaded at start and no room list has answered yet: h.rooms is
		// empty, so the whole budget would look free.
		return false
	}
	if h.roomDataPct != nil && *h.roomDataPct >= diskFullPct {
		return false
	}
	return h.diskExtraUsed()+extra <= *budget
}

// diskSoldOut is the answer when a hotel would take the create but none has
// the disk for it.
func diskSoldOut(diskGiB int) createResult {
	return createResult{status: 429, header: http.Header{"Retry-After": {strconv.Itoa(diskSoldOutRetryAfter)}},
		doc: errDoc("disk_sold_out", fmt.Sprintf("no hotel has %d GiB of disk free; try a smaller disk_gib or retry later", diskGiB))}
}

// guestDiskDoc is the guest's view of h's disk (AB#860): how full the data
// volume is and the line at which it takes no more rooms, null when unknown
// or unset. The budget and its use stay operator only. Caller holds b.mu.
func guestDiskDoc(h *hotel, d map[string]any) {
	var pct, admitPct any
	if h.roomDataPct != nil {
		pct = *h.roomDataPct
	}
	if h.cfg.DiskAdmitUsedPct != nil {
		admitPct = *h.cfg.DiskAdmitUsedPct
	}
	d["disk_used_pct"] = pct
	d["disk_admit_used_pct"] = admitPct
}

// diskDoc is the operator readback of h's disk budget. Caller holds b.mu.
func diskDoc(h *hotel, d map[string]any) {
	var budget, pct any
	if h.cfg.DiskExtraGiB != nil {
		budget = *h.cfg.DiskExtraGiB
	}
	if h.roomDataPct != nil {
		pct = *h.roomDataPct
	}
	var admitPct any
	if h.cfg.DiskAdmitUsedPct != nil {
		admitPct = *h.cfg.DiskAdmitUsedPct
	}
	d["disk_admit_used_pct"] = admitPct // null: the disk_extra_gib rule
	d["disk_extra_gib"] = budget        // null: no disk limit
	d["disk_extra_used_gib"] = h.diskExtraUsed()
	d["room_data_used_pct"] = pct // null: no reading yet
}
