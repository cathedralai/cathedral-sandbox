package main

import (
	"testing"
	"time"
)

// minerExits reads GET /v1/broker/miner-exits with key and returns the records.
func minerExitsOf(t *testing.T, tc *testChain, key, query string) []map[string]any {
	t.Helper()
	status, doc := tc.call(t, key, "GET", "/v1/broker/miner-exits"+query, nil)
	if status != 200 {
		t.Fatalf("miner exits with %s: %d %v", key, status, doc)
	}
	var out []map[string]any
	for _, e := range doc["exits"].([]any) {
		out = append(out, e.(map[string]any))
	}
	return out
}

func exitRooms(e map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range e["rooms"].([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

// blipDown makes h stop answering health while the guest stays the same, and
// runs one sync so the broker marks it down.
func blipDown(t *testing.T, tc *testChain, h *hotel, g *rebootingGuest) {
	t.Helper()
	g.healthStatus.Store(503)
	tc.b.mu.Lock()
	h.lastOK = h.lastOK.Add(-2 * okWindow)
	tc.b.mu.Unlock()
	h.lastAnswer.Store(time.Now().Add(-2 * okWindow).UnixNano())
	syncNow(tc, h.cfg.ID)
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	if h.ok {
		t.Fatalf("hotel %s still up with health failing", h.cfg.ID)
	}
}

func TestMinerHotelThatGoesDownWithARoomIsRecorded(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g := newRebootingGuest(t, "m1")
	h, roomID := joinWithRoom(t, tc, "m1", g)
	if got := minerExitsOf(t, tc, "operator-key", ""); len(got) != 0 {
		t.Fatalf("exit recorded while the hotel is up: %v", got)
	}
	before := time.Now().UTC().Add(-time.Second)
	goDown(t, tc, h, g, 0)
	got := minerExitsOf(t, tc, "operator-key", "")
	if len(got) != 1 {
		t.Fatalf("exits after the miner went down: %v", got)
	}
	e := got[0]
	down, err := time.Parse(time.RFC3339, e["down_at"].(string))
	if err != nil || down.Before(before) {
		t.Fatalf("down_at %v: %v", e["down_at"], err)
	}
	rooms := exitRooms(e)
	if e["hotel"] != "m1" || e["miner_hotkey"] != minerHotkey || e["drained_at_down"] != false || e["ended"] != nil ||
		e["ended_at"] != nil || e["rooms_checked"] != false || len(rooms) != 1 ||
		rooms[0]["id"] != roomID || rooms[0]["guest"] != "g1" || rooms[0]["lost"] != nil {
		t.Fatalf("exit record: %v", e)
	}
	// Another sync while still down adds nothing.
	syncNow(tc, "m1")
	if got := minerExitsOf(t, tc, "operator-key", ""); len(got) != 1 {
		t.Fatalf("second sync while down: %v", got)
	}
}

func TestMinerExitThatComesBackWithItsRoomsIsNotLost(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g := newRebootingGuest(t, "m1")
	h, _ := joinWithRoom(t, tc, "m1", g)
	blipDown(t, tc, h, g)
	g.healthStatus.Store(0)
	syncNow(tc, "m1")
	got := minerExitsOf(t, tc, "operator-key", "")
	if len(got) != 1 {
		t.Fatalf("exits: %v", got)
	}
	rooms := exitRooms(got[0])
	if got[0]["ended"] != "up" || got[0]["ended_at"] == nil || got[0]["rooms_checked"] != true || rooms[0]["lost"] != false {
		t.Fatalf("hotel back with its room: %v", got[0])
	}
}

func TestMinerExitThatComesBackWithoutItsRoomMarksItLost(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g := newRebootingGuest(t, "m1")
	h, _ := joinWithRoom(t, tc, "m1", g)
	blipDown(t, tc, h, g)
	g.fakeHotel.mu.Lock()
	g.fakeHotel.rooms = nil // the room did not survive
	g.fakeHotel.mu.Unlock()
	g.healthStatus.Store(0)
	syncNow(tc, "m1")
	got := minerExitsOf(t, tc, "operator-key", "")
	if len(got) != 1 {
		t.Fatalf("exits: %v", got)
	}
	rooms := exitRooms(got[0])
	if got[0]["ended"] != "up" || got[0]["rooms_checked"] != true || rooms[0]["lost"] != true {
		t.Fatalf("hotel back without its room: %v", got[0])
	}
}

func TestDrainedMinerExitIsMarkedDrained(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g := newRebootingGuest(t, "m1")
	h, _ := joinWithRoom(t, tc, "m1", g)
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true}); status != 200 {
		t.Fatalf("drain: %d %v", status, doc)
	}
	goDown(t, tc, h, g, 0)
	got := minerExitsOf(t, tc, "operator-key", "")
	if len(got) != 1 || got[0]["drained_at_down"] != true {
		t.Fatalf("drained exit: %v", got)
	}
}

func TestForgottenMinerExitLosesEveryRoom(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	_, _, clientID := readyToForget(t, tc, newRebootingGuest(t, "m1"))
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/m1?forget_rooms=true", nil); status != 204 {
		t.Fatalf("forget: %d %v", status, doc)
	}
	got := minerExitsOf(t, tc, "reader-key", "")
	if len(got) != 1 {
		t.Fatalf("exits: %v", got)
	}
	rooms := exitRooms(got[0])
	if got[0]["ended"] != "forgotten" || got[0]["rooms_checked"] != true || len(rooms) != 1 || rooms[0]["lost"] != true {
		t.Fatalf("forgotten exit: %v", got[0])
	}
	// The client id was set after the hotel went down; the record keeps the
	// broker id, and the tombstone is what the client reads.
	tc.b.compat.mu.Lock()
	_, tomb := tc.b.compat.tombs[clientID]
	tc.b.compat.mu.Unlock()
	if !tomb {
		t.Fatal("forgotten room has no tombstone")
	}
}

func TestNoExitRecordWithoutCustomerRoomsOrMiner(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	// A miner hotel with no rooms.
	g := newRebootingGuest(t, "m1")
	tc.hotels["m1"] = g.fakeHotel
	if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "m1", "api": g.url, "health": g.url, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey,
	}); status != 201 {
		t.Fatalf("join: %d %v", status, doc)
	}
	syncNow(tc, "m1")
	goDown(t, tc, tc.b.hotelByID("m1"), g, 0)
	// An operator hotel with a room.
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}}); status != 201 && status != 202 {
		t.Fatalf("create on b: %d %v", status, doc)
	}
	tc.hotels["b"].healthFail = true
	setHotel(tc, "b", func(h *hotel) { h.lastOK = time.Now().Add(-2 * okWindow) })
	hb := tc.b.hotelByID("b")
	hb.lastAnswer.Store(time.Now().Add(-2 * okWindow).UnixNano())
	syncNow(tc, "b")
	tc.b.mu.Lock()
	down, used := !hb.ok, hb.used()
	tc.b.mu.Unlock()
	if !down || used != 1 {
		t.Fatalf("operator hotel b: down=%v rooms=%d", down, used)
	}
	if got := minerExitsOf(t, tc, "operator-key", ""); len(got) != 0 {
		t.Fatalf("exit recorded without a miner customer room: %v", got)
	}
}

func TestMinerExitsRouteKeys(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	for _, key := range []string{"key1", "enroller-key", "nope"} {
		if status, doc := tc.call(t, key, "GET", "/v1/broker/miner-exits", nil); status < 400 {
			t.Fatalf("%s read miner exits: %d %v", key, status, doc)
		}
	}
	if status, doc := tc.call(t, "reader-key", "POST", "/v1/broker/miner-exits", nil); status < 400 {
		t.Fatalf("read key POST: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/miner-exits?since=yesterday", nil); status != 400 || errCode(doc) != "invalid_since" {
		t.Fatalf("bad since: %d %v", status, doc)
	}
	for _, key := range []string{"operator-key", "reader-key"} {
		if got := minerExitsOf(t, tc, key, ""); len(got) != 0 {
			t.Fatalf("%s: %v", key, got)
		}
	}
}

func TestMinerExitsSinceFilterAndRestart(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	g := newRebootingGuest(t, "m1")
	h, roomID := joinWithRoom(t, tc, "m1", g)
	goDown(t, tc, h, g, 0)
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if got := minerExitsOf(t, tc, "operator-key", "?since="+future); len(got) != 0 {
		t.Fatalf("since filter: %v", got)
	}
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	tc.start(t)
	got := minerExitsOf(t, tc, "operator-key", "")
	if len(got) != 1 || got[0]["hotel"] != "m1" || exitRooms(got[0])[0]["id"] != roomID {
		t.Fatalf("exits after restart: %v", got)
	}
}

func TestPruneMinerExits(t *testing.T) {
	b := &broker{}
	now := time.Now()
	b.minerExits = append(b.minerExits, &minerExit{Hotel: "old", DownAt: now.Add(-minerExitKeep - time.Hour)})
	for i := 0; i < minerExitMaxPerHotel+5; i++ {
		b.minerExits = append(b.minerExits, &minerExit{Hotel: "flap", DownAt: now.Add(time.Duration(i-100) * time.Minute)})
	}
	b.minerExits = append(b.minerExits, &minerExit{Hotel: "other", DownAt: now})
	b.pruneMinerExits(now)
	count := map[string]int{}
	for _, e := range b.minerExits {
		count[e.Hotel]++
	}
	if count["old"] != 0 || count["flap"] != minerExitMaxPerHotel || count["other"] != 1 {
		t.Fatalf("after prune: %v", count)
	}
	// The newest flap records stay.
	if first := b.minerExits[0]; first.Hotel != "flap" || !first.DownAt.Equal(now.Add(-95*time.Minute)) {
		t.Fatalf("oldest kept flap record: %+v", first)
	}

	b.minerExits = nil
	for i := 0; i < minerExitMax+10; i++ {
		b.minerExits = append(b.minerExits, &minerExit{Hotel: string(rune('A' + i%40)), DownAt: now.Add(time.Duration(i-2000) * time.Second)})
	}
	b.pruneMinerExits(now)
	if len(b.minerExits) != minerExitMax || !b.minerExits[0].DownAt.Equal(now.Add(time.Duration(10-2000)*time.Second)) {
		t.Fatalf("global cap: %d records, first %v", len(b.minerExits), b.minerExits[0].DownAt)
	}
}
