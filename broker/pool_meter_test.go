package main

import (
	"testing"
)

// A room of the pool guest is metered not billable from its first reading,
// and that first reading is no turn a caller must wait for; a customer
// room's sighting is as before (AB#894, design 8.2).
func TestPoolGuestSightingIsNotBillableAndNeedsNoWait(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	h := &hotel{cfg: hotelConfig{ID: "h"}}
	pool := &room{id: "h.p1", guest: poolGuestID, uuid: "00000000-0000-4000-8000-0000000000aa"}
	cust := &room{id: "h.c1", guest: "g1", uuid: "00000000-0000-4000-8000-0000000000bb"}
	ps, cs := usageSightingOf(h, pool, nil), usageSightingOf(h, cust, nil)
	if ps.billable || !ps.pool || ps.guest != poolGuestID {
		t.Fatalf("pool sighting %+v", ps)
	}
	if !cs.billable || cs.pool {
		t.Fatalf("customer sighting %+v", cs)
	}
	if m.seen(ps, at(0)) {
		t.Fatal("a pool room's first reading asks the caller to wait for a durable turn")
	}
	if m.seen(ps, at(70)) {
		t.Fatal("a later pool reading asks the caller to wait")
	}
	if m.seen(cs, at(0)) {
		t.Fatal("a customer room's first reading turned not billable")
	}
	mustFlush(t, m)
	rs := logReadings(t, dir)
	for _, r := range readingsOf(rs, "h.p1") {
		if r.Billable == nil || *r.Billable || r.Guest != poolGuestID {
			t.Fatalf("pool reading %+v", r)
		}
	}
	if got := readingsOf(rs, "h.c1"); len(got) != 1 || got[0].Billable != nil {
		t.Fatalf("customer readings %+v", got)
	}
	if n := len(readingsOf(rs, "h.p1")); n != 2 {
		t.Fatalf("%d pool readings, want 2 (first sight, then after usage_meter_every_seconds)", n)
	}
}

// With usage_meter_min_second on (#654), a pool run's ended reading is not
// rounded up: a room that waits for a claim is never billable, not even 1 s.
func TestPoolRunIsNotRoundedUpByTheMinimumSecond(t *testing.T) {
	dir := t.TempDir()
	m := testUsageMeter(t, dir, 60)
	m.minSecond = true
	h := &hotel{cfg: hotelConfig{ID: "h"}}
	pool := &room{id: "h.p1", guest: poolGuestID, uuid: "00000000-0000-4000-8000-0000000000aa"}
	m.seen(usageSightingOf(h, pool, nil), at(0))
	m.end("h.p1", at(0.4), true)
	mustFlush(t, m)
	rs := readingsOf(logReadings(t, dir), "h.p1")
	if len(rs) != 2 || rs[1].State != "ended" || rs[1].Seconds != 0 || rs[1].Billable == nil || *rs[1].Billable {
		t.Fatalf("pool readings with the minimum second on: %+v", rs)
	}
}

// A listed pool room that is not in the room map (the list paths #656 added,
// usageSightingOfListed) is not billable either: a pool room is never
// billable on any sighting path.
func TestPoolListedRoomOutsideTheRoomMapIsNotBillable(t *testing.T) {
	b := &broker{}
	h := &hotel{cfg: hotelConfig{ID: "h"}, rooms: map[string]*room{}}
	b.mu.Lock()
	s := b.usageSightingOfListed(h, "p9", map[string]string{guestLabel: poolGuestID, poolLabel: "1"}, nil)
	c := b.usageSightingOfListed(h, "c9", map[string]string{guestLabel: "g1"}, nil)
	b.mu.Unlock()
	if s.billable || !s.pool || s.guest != poolGuestID {
		t.Fatalf("listed pool room sighting %+v", s)
	}
	if !c.billable || c.pool {
		t.Fatalf("listed customer room sighting %+v, want billable as #656 has it", c)
	}
}
