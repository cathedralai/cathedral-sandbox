// Miner exits with live rooms (AB#329).
//
// When a miner hotel goes down while it holds customer rooms, the broker
// keeps one exit record: the hotel, its miner hotkey, when it went down, the
// rooms it held, and whether it was drained at that moment. The record is
// the input the delivered room-hour feed needs to forfeit that miner's hours
// for the window (AB#319); the broker itself pays and forfeits nothing.
//
// A record ends in one of two ways:
//   - "up": the same attested guest answered again (a miner guest that
//     reboots gets a new TLS key, so its pinned calls keep failing and it
//     never comes back this way). On the first room list after that, each
//     room is marked lost or not, so a short network drop with every room
//     intact is told apart from a lost room.
//   - "forgotten": the operator forgot the rooms of the dead guest
//     (miner_forget.go). Every room is lost, and its client id is
//     tombstoned, so the client can retry the room on another hotel.
//
// drained_at_down is the drain flag when the hotel went down. A miner's own
// enroll key can set drain, so it is not proof of advance notice; the notice
// rule is AB#328.
//
// The broker cannot re-create a live room elsewhere: it keeps no create
// request per room, and a sealed room's state is on the lost machine. The
// record lists the rooms (broker id, client id, guest) for the client to act on.
//
// GET /v1/broker/miner-exits[?since=RFC3339] lists the records, oldest
// first, for the operator key and the read-only operator key. Records are
// kept in client-state.json for minerExitKeep, and at most minerExitMax
// (minerExitMaxPerHotel per hotel).
package main

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	minerExitKeep        = 8 * 24 * time.Hour // past the validator's 7-day window
	minerExitMax         = 1000
	minerExitMaxPerHotel = 50

	exitEndedUp        = "up"
	exitEndedForgotten = "forgotten"
)

type exitRoom struct {
	ID    string `json:"id"`             // broker room id <hotel>.<hotel room id>
	UUID  string `json:"uuid,omitempty"` // client id, when the room has one
	Guest string `json:"guest"`
	// Lost: nil until known. false: the hotel listed the room again after it
	// came back. true: it did not, or the operator forgot the room.
	Lost *bool `json:"lost"`
}

type minerExit struct {
	Hotel         string     `json:"hotel"`
	MinerHotkey   string     `json:"miner_hotkey"`
	DownAt        time.Time  `json:"down_at"`
	DrainedAtDown bool       `json:"drained_at_down"`
	Ended         string     `json:"ended,omitempty"` // "", "up" or "forgotten"
	EndedAt       *time.Time `json:"ended_at"`
	RoomsChecked  bool       `json:"rooms_checked"` // every room has lost set
	Rooms         []exitRoom `json:"rooms"`
}

func (e *minerExit) clone() minerExit {
	out := *e
	out.Rooms = make([]exitRoom, len(e.Rooms))
	for i, r := range e.Rooms {
		out.Rooms[i] = r
		if r.Lost != nil {
			v := *r.Lost
			out.Rooms[i].Lost = &v
		}
	}
	if e.EndedAt != nil {
		t := *e.EndedAt
		out.EndedAt = &t
	}
	return out
}

// noteMinerDown records a miner hotel that went down holding customer rooms.
// A room with no guest label (adopted from a hotel list) is not a customer
// room and is not listed. Caller holds b.mu.
func (b *broker) noteMinerDown(h *hotel, now time.Time) {
	if h.cfg.MinerHotkey == "" {
		return
	}
	var rooms []exitRoom
	for _, rm := range h.rooms {
		if rm.state == stRunning && rm.guest != "" {
			rooms = append(rooms, exitRoom{ID: rm.id, UUID: rm.uuid, Guest: rm.guest})
		}
	}
	if len(rooms) == 0 {
		return
	}
	sort.Slice(rooms, func(i, j int) bool { return rooms[i].ID < rooms[j].ID })
	b.minerExits = append(b.minerExits, &minerExit{
		Hotel: h.cfg.ID, MinerHotkey: h.cfg.MinerHotkey, DownAt: now.UTC(),
		DrainedAtDown: h.drain(), Rooms: rooms,
	})
	b.pruneMinerExits(now)
	b.markDirty()
}

// noteMinerUp ends the open records of h: the hotel answered again. Caller
// holds b.mu.
func (b *broker) noteMinerUp(h *hotel, now time.Time) {
	b.endMinerExits(h.cfg.ID, exitEndedUp, now, nil)
}

// noteMinerForgotten ends the open records of hotel id: the operator forgot
// its rooms. Every room is lost. Caller holds b.mu.
func (b *broker) noteMinerForgotten(id string, now time.Time) {
	lost := true
	b.endMinerExits(id, exitEndedForgotten, now, &lost)
}

func (b *broker) endMinerExits(id, how string, now time.Time, lost *bool) {
	changed := false
	for _, e := range b.minerExits {
		if e.Hotel != id || e.Ended != "" {
			continue
		}
		t := now.UTC()
		e.Ended, e.EndedAt = how, &t
		if lost != nil {
			for i := range e.Rooms {
				v := *lost
				e.Rooms[i].Lost = &v
			}
			e.RoomsChecked = true
		}
		changed = true
	}
	if changed {
		b.markDirty()
	}
}

// checkMinerExitRooms marks each room of h's records that ended "up" and are
// not checked yet: lost unless the hotel listed it now. listed holds the
// hotel room ids of a room list that answered. Caller holds b.mu.
func (b *broker) checkMinerExitRooms(h *hotel, listed map[string]bool) {
	changed := false
	prefix := h.cfg.ID + "."
	for _, e := range b.minerExits {
		if e.Hotel != h.cfg.ID || e.Ended != exitEndedUp || e.RoomsChecked {
			continue
		}
		for i := range e.Rooms {
			hid := strings.TrimPrefix(e.Rooms[i].ID, prefix)
			lost := !listed[hid]
			e.Rooms[i].Lost = &lost
		}
		e.RoomsChecked = true
		changed = true
	}
	if changed {
		b.markDirty()
	}
}

// pruneMinerExits drops records older than minerExitKeep, then the oldest
// records of a hotel over minerExitMaxPerHotel (so one flapping hotel cannot
// push out the others), then the oldest over minerExitMax. Caller holds b.mu.
func (b *broker) pruneMinerExits(now time.Time) {
	perHotel := map[string]int{}
	for _, e := range b.minerExits {
		if now.Sub(e.DownAt) <= minerExitKeep {
			perHotel[e.Hotel]++
		}
	}
	kept := b.minerExits[:0]
	for _, e := range b.minerExits {
		if now.Sub(e.DownAt) > minerExitKeep {
			continue
		}
		if perHotel[e.Hotel] > minerExitMaxPerHotel {
			perHotel[e.Hotel]--
			continue
		}
		kept = append(kept, e)
	}
	if over := len(kept) - minerExitMax; over > 0 {
		kept = kept[over:]
	}
	for i := len(kept); i < len(b.minerExits); i++ {
		b.minerExits[i] = nil
	}
	b.minerExits = kept
}

// minerExitsSnapshot copies the records. Caller holds b.mu.
func (b *broker) minerExitsSnapshot() []minerExit {
	out := make([]minerExit, 0, len(b.minerExits))
	for _, e := range b.minerExits {
		out = append(out, e.clone())
	}
	return out
}

// restoreMinerExits takes the records read from the state file. Caller holds b.mu.
func (b *broker) restoreMinerExits(list []minerExit, now time.Time) {
	b.minerExits = nil
	for i := range list {
		e := list[i].clone()
		if e.Hotel == "" || e.DownAt.IsZero() {
			continue
		}
		b.minerExits = append(b.minerExits, &e)
	}
	sort.SliceStable(b.minerExits, func(i, j int) bool { return b.minerExits[i].DownAt.Before(b.minerExits[j].DownAt) })
	b.pruneMinerExits(now)
}

// handleMinerExits: GET /v1/broker/miner-exits[?since=RFC3339].
func (b *broker) handleMinerExits(w http.ResponseWriter, r *http.Request) {
	var since time.Time
	if s := r.URL.Query().Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeErr(w, 400, "invalid_since", "since must be an RFC 3339 time")
			return
		}
		since = t
	}
	b.mu.Lock()
	all := b.minerExitsSnapshot()
	b.mu.Unlock()
	out := make([]minerExit, 0, len(all))
	for _, e := range all {
		if !e.DownAt.Before(since) {
			out = append(out, e)
		}
	}
	writeJSON(w, 200, map[string]any{"exits": out})
}
