package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func readExitUpdates(t *testing.T, b *broker, after string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	b.handleMinerExits(w, httptest.NewRequest("GET", "/v1/broker/miner-exits?after="+url.QueryEscape(after), nil))
	if w.Code != 200 {
		t.Fatalf("updates: %d %s", w.Code, w.Body.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if w.Header().Get("Cache-Control") != "no-store" || doc["schema"] != "cathedral_miner_exit_updates_v1" {
		t.Fatalf("missing cursor response contract: %v %v", w.Header(), doc)
	}
	return doc
}

func addCursorExit(b *broker, hotel string, at time.Time) *minerExit {
	e := &minerExit{Hotel: hotel, MinerHotkey: minerHotkey, DownAt: at,
		Rooms: []exitRoom{{ID: hotel + ".r1", Guest: "g1"}}}
	b.touchMinerExit(e)
	b.minerExits = append(b.minerExits, e)
	return e
}

func requireExitReset(t *testing.T, doc map[string]any, reason string, count int) {
	t.Helper()
	if doc["reset_required"] != (reason != "") || doc["reset_reason"] != reason || len(doc["exits"].([]any)) != count {
		t.Fatalf("want reset %q with %d records: %v", reason, count, doc)
	}
}

func TestMinerExitCursorInitialAndIdle(t *testing.T) {
	b := &broker{}
	first := readExitUpdates(t, b, "")
	requireExitReset(t, first, "initial_snapshot", 0)
	second := readExitUpdates(t, b, first["next_cursor"].(string))
	requireExitReset(t, second, "", 0)
	if second["next_cursor"] != first["next_cursor"] {
		t.Fatal("idle reads advance the cursor")
	}
}

func TestMinerExitCursorTracksLateRoomResolution(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g := newRebootingGuest(t, "m1")
	h, _ := joinWithRoom(t, tc, "m1", g)
	blipDown(t, tc, h, g)
	first := readExitUpdates(t, tc.b, "")
	requireExitReset(t, first, "initial_snapshot", 1)
	e := first["exits"].([]any)[0].(map[string]any)
	if e["event_id"] == "" || e["sequence"] != "1" || exitRooms(e)[0]["lost"] != nil {
		t.Fatalf("initial record: %v", e)
	}
	g.healthStatus.Store(0)
	syncNow(tc, "m1")
	second := readExitUpdates(t, tc.b, first["next_cursor"].(string))
	requireExitReset(t, second, "", 1)
	updated := second["exits"].([]any)[0].(map[string]any)
	if updated["event_id"] != e["event_id"] || updated["sequence"] != "3" || exitRooms(updated)[0]["lost"] != false {
		t.Fatalf("late resolution did not update the same record: %v", updated)
	}
	syncNow(tc, "m1")
	third := readExitUpdates(t, tc.b, second["next_cursor"].(string))
	requireExitReset(t, third, "", 0)
}

func TestMinerExitCursorForgottenAndRetry(t *testing.T) {
	b := &broker{}
	e := addCursorExit(b, "m1", time.Now())
	first := readExitUpdates(t, b, "")
	b.noteMinerForgotten("m1", time.Now())
	second := readExitUpdates(t, b, first["next_cursor"].(string))
	requireExitReset(t, second, "", 1)
	updated := second["exits"].([]any)[0].(map[string]any)
	if updated["event_id"] != e.EventID || updated["ended"] != "forgotten" || exitRooms(updated)[0]["lost"] != true {
		t.Fatalf("forgotten record: %v", updated)
	}
	b.noteMinerForgotten("m1", time.Now())
	retry := readExitUpdates(t, b, first["next_cursor"].(string))
	raw, _ := json.Marshal(second)
	got, _ := json.Marshal(retry)
	if string(raw) != string(got) {
		t.Fatalf("retry changed the snapshot: %s vs %s", raw, got)
	}
}

func TestMinerExitCursorSavedIDsSurviveButRestartResets(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g := newRebootingGuest(t, "m1")
	h, _ := joinWithRoom(t, tc, "m1", g)
	blipDown(t, tc, h, g)
	before := readExitUpdates(t, tc.b, "")
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	tc.start(t)
	after := readExitUpdates(t, tc.b, before["next_cursor"].(string))
	requireExitReset(t, after, "epoch_changed", 1)
	oldID := before["exits"].([]any)[0].(map[string]any)["event_id"]
	newID := after["exits"].([]any)[0].(map[string]any)["event_id"]
	if oldID == "" || oldID != newID || before["next_cursor"] == after["next_cursor"] {
		t.Fatalf("restart identity/cursor: %v %v", before, after)
	}
	// A fresh process with no saved records must also signal the discontinuity.
	requireExitReset(t, readExitUpdates(t, &broker{}, before["next_cursor"].(string)), "epoch_changed", 0)
}

func TestMinerExitCursorLegacyAndDuplicateIDs(t *testing.T) {
	b := &broker{}
	now := time.Now()
	b.restoreMinerExits([]minerExit{
		{Hotel: "legacy", DownAt: now},
		{EventID: "same", Hotel: "one", DownAt: now},
		{EventID: "same", Hotel: "two", DownAt: now},
	}, now)
	seen := map[string]bool{}
	for _, e := range b.minerExits {
		if e.EventID == "" || seen[e.EventID] || e.Sequence == 0 {
			t.Fatalf("invalid restored identity: %+v", e)
		}
		seen[e.EventID] = true
	}
	if !b.dirty.Load() {
		t.Fatal("legacy identities were not scheduled to persist")
	}
}

func TestMinerExitCursorRetentionGaps(t *testing.T) {
	for _, mode := range []string{"age", "hotel", "global"} {
		t.Run(mode, func(t *testing.T) {
			b := &broker{}
			initial := readExitUpdates(t, b, "")["next_cursor"].(string)
			now := time.Now()
			want := 0
			switch mode {
			case "age":
				addCursorExit(b, "m1", now.Add(-minerExitKeep-time.Minute))
			case "hotel":
				for i := 0; i < minerExitMaxPerHotel+1; i++ {
					addCursorExit(b, "m1", now.Add(time.Duration(i-100)*time.Second))
				}
				want = minerExitMaxPerHotel
			case "global":
				for i := 0; i < minerExitMax+1; i++ {
					addCursorExit(b, fmt.Sprintf("m%d", i), now.Add(time.Duration(i-2000)*time.Second))
				}
				want = minerExitMax
			}
			gap := readExitUpdates(t, b, initial)
			requireExitReset(t, gap, "retention_gap", want)
			// Resuming from the returned baseline does not erase the historical
			// gap; it only establishes a cursor for subsequent observations.
			requireExitReset(t, readExitUpdates(t, b, gap["next_cursor"].(string)), "", 0)
		})
	}
}

func TestMinerExitCursorEvictedLateUpdateIsAGap(t *testing.T) {
	b := &broker{}
	now := time.Now()
	old := addCursorExit(b, "m1", now.Add(-minerExitKeep+time.Minute))
	first := readExitUpdates(t, b, "")
	b.noteMinerForgotten("m1", now)
	old.DownAt = now.Add(-minerExitKeep - time.Minute)
	requireExitReset(t, readExitUpdates(t, b, first["next_cursor"].(string)), "retention_gap", 0)
}

func TestMinerExitCursorAlreadyCollectedEvictionIsNotAGap(t *testing.T) {
	b := &broker{}
	e := addCursorExit(b, "m1", time.Now())
	b.noteMinerForgotten("m1", time.Now())
	first := readExitUpdates(t, b, "")
	e.DownAt = time.Now().Add(-minerExitKeep - time.Minute)
	requireExitReset(t, readExitUpdates(t, b, first["next_cursor"].(string)), "", 0)
}

func TestMinerExitCursorCollectedButUnresolvedEvictionIsAGap(t *testing.T) {
	b := &broker{}
	e := addCursorExit(b, "m1", time.Now())
	first := readExitUpdates(t, b, "")
	e.DownAt = time.Now().Add(-minerExitKeep - time.Minute)
	requireExitReset(t, readExitUpdates(t, b, first["next_cursor"].(string)), "retention_gap", 0)
}

func TestMinerExitCursorRejectsAmbiguousQueries(t *testing.T) {
	for _, query := range []string{
		"after=bad", "after=&since=", "after=&after=", "after=" + newUUID() + ":01",
		"after=" + newUUID() + ":-1", "after=" + newUUID() + ":18446744073709551616",
		"after=AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA:1",
	} {
		b := &broker{}
		w := httptest.NewRecorder()
		b.handleMinerExits(w, httptest.NewRequest("GET", "/v1/broker/miner-exits?"+query, nil))
		if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_exit_cursor") {
			t.Fatalf("%s: %d %s", query, w.Code, w.Body.String())
		}
	}
}

func TestMinerExitCursorAheadAndCounterRollover(t *testing.T) {
	b := &broker{}
	e := addCursorExit(b, "m1", time.Now())
	first := readExitUpdates(t, b, "")
	requireExitReset(t, readExitUpdates(t, b, b.minerExitEpoch+":2"), "cursor_ahead", 1)
	b.minerExitSeq = ^uint64(0)
	b.touchMinerExit(e)
	requireExitReset(t, readExitUpdates(t, b, first["next_cursor"].(string)), "epoch_changed", 1)
}

func TestMinerExitCursorRouteKeepsOperatorOnlyBoundary(t *testing.T) {
	tc := newChain(t)
	for _, key := range []string{"key1", "enroller-key", "nope"} {
		if status, _ := tc.call(t, key, "GET", "/v1/broker/miner-exits?after=", nil); status < 400 {
			t.Fatalf("%s read update records", key)
		}
	}
	for _, key := range []string{"operator-key", "reader-key"} {
		if status, doc := tc.call(t, key, "GET", "/v1/broker/miner-exits?after=", nil); status != 200 || doc["reset_required"] != true {
			t.Fatalf("%s cannot read initial snapshot: %d %v", key, status, doc)
		}
	}
}
