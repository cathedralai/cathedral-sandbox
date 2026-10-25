package main

// Creates in flight (#299).
//
// A guest can cancel a create, or delete by label, while the hotel still
// starts the room. The hotel does not see the cancel: it finishes the room.
// Without the rules below that room runs with no owner until its TTL.
//
//   - The broker keeps the hotel call open when the guest goes away. When
//     the hotel answers with a room and the guest is gone, the broker deletes
//     that room at once.
//   - A delete by label leaves a tombstone: (guest, label filter, time). A
//     create that the broker received before the tombstone, and whose labels
//     match it, does not start. If it already started, the broker deletes the
//     room when the hotel answers. The guest gets 409 deleted_during_create.

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"
)

// tombstoneTTL is how long a delete by label catches creates in flight. It is
// longer than a create can take: the queue wait plus the 5 min hotel call.
const tombstoneTTL = 15 * time.Minute

type tombstone struct {
	want map[string]string // every label must match
	at   time.Time
}

// parseLabelFilters reads "k=v" filters. A filter with no "=" matches no label.
func parseLabelFilters(filters []string) map[string]string {
	want := map[string]string{}
	for _, f := range filters {
		k, v, _ := strings.Cut(f, "=")
		want[k] = v
	}
	return want
}

// addTombstone records a delete by label for guest. Caller holds b.mu.
func (b *broker) addTombstone(guest string, filters []string, at time.Time) {
	if b.tombs == nil {
		b.tombs = map[string][]tombstone{}
	}
	kept := b.tombs[guest][:0]
	for _, t := range b.tombs[guest] {
		if at.Sub(t.at) < tombstoneTTL {
			kept = append(kept, t)
		}
	}
	b.tombs[guest] = append(kept, tombstone{want: parseLabelFilters(filters), at: at})
}

// tombstoned reports whether a delete by label that came after recv matches
// labels. Caller holds b.mu.
func (b *broker) tombstoned(guest string, labels map[string]any, recv time.Time) bool {
	for _, t := range b.tombs[guest] {
		if !t.at.After(recv) || time.Since(t.at) >= tombstoneTTL {
			continue
		}
		match := true
		for k, v := range t.want {
			got, ok := labels[k]
			if !ok || fmt.Sprint(got) != v {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// deletedDuringCreate is the answer to a create that a delete by label caught.
func deletedDuringCreate() createResult {
	return createResult{status: 409, doc: map[string]any{"error": map[string]string{
		"code":    "deleted_during_create",
		"message": "a delete by label matched this room while it was created; the broker deleted it",
	}}}
}

// clientGone is the answer to a create whose guest went away.
func clientGone() createResult {
	return createResult{status: 499, doc: map[string]any{"error": map[string]string{"code": "client_gone", "message": "request cancelled"}}}
}

// reapRoom deletes a room that nobody owns: its create was cancelled or a
// delete by label caught it. The room stays in h.rooms as "deleting", so the
// sync loop does not show it as a running room in the meantime. The caller
// does not hold b.mu.
func (b *broker) reapRoom(h *hotel, rm *room) {
	b.mu.Lock()
	rm.state, rm.since, rm.vanished = stDeleting, time.Now(), time.Now()
	if old := h.rooms[rm.hid]; old != nil && old != rm { // the sync loop saw it first
		b.release(h, old)
	}
	h.rooms[rm.hid] = rm
	b.rememberGuestRoom(rm.guest, h.cfg.ID, rm.hid)
	b.mu.Unlock()
	path := "/v1/sandboxes/" + url.PathEscape(rm.hid)
	for attempt := 0; attempt < 3; attempt++ {
		status, _, _, err := h.do(context.Background(), "DELETE", path, nil, nil, 2*time.Minute)
		if err == nil && (status == 204 || status == 200 || status == 404) {
			return
		}
		log.Printf("reap %s.%s: attempt %d: status %d err %v", h.cfg.ID, rm.hid, attempt+1, status, err)
		time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
	}
	// The hotel did not take the delete. The room stays "deleting" here and
	// the operator sees it in the hotel list; its TTL still ends it.
}
