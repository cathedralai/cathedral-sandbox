package main

// Room end records (AB#864): a room that leaves the broker for good answers
// 410 sandbox_gone with a reason to its own guest for endedKeep.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// releaseGone runs the two sync steps that mark rooms the hotel no longer
// lists as deleting and then release them, with the waits backdated.
func releaseGone(t *testing.T, tc *testChain, hotelID string) {
	t.Helper()
	h := tc.b.hotelByID(hotelID)
	tc.b.mu.Lock()
	for _, rm := range h.rooms {
		rm.since = rm.since.Add(-10 * time.Second)
	}
	tc.b.mu.Unlock()
	syncNow(tc, hotelID)
	tc.b.mu.Lock()
	for _, rm := range h.rooms {
		if rm.state == stDeleting {
			rm.vanished = rm.vanished.Add(-3 * time.Second)
		}
	}
	tc.b.mu.Unlock()
	syncNow(tc, hotelID)
}

// dropFromHotel removes broker room bid from its fake hotel's list.
func dropFromHotel(tc *testChain, bid string) {
	hotelID, hid, _ := strings.Cut(bid, ".")
	f := tc.hotels[hotelID]
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, rm := range f.rooms {
		if rm["id"] == hid {
			f.rooms = append(f.rooms[:i], f.rooms[i+1:]...)
			return
		}
	}
}

// setOnHotel sets field k of hotel room bid in its fake hotel's list.
func setOnHotel(tc *testChain, bid, k string, v any) {
	hotelID, hid, _ := strings.Cut(bid, ".")
	f := tc.hotels[hotelID]
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rm := range f.rooms {
		if rm["id"] == hid {
			rm[k] = v
		}
	}
}

func vanish(t *testing.T, tc *testChain, bid string) {
	t.Helper()
	dropFromHotel(tc, bid)
	hotelID, _, _ := strings.Cut(bid, ".")
	releaseGone(t, tc, hotelID)
}

// goneDoc checks a 410 sandbox_gone answer and returns its sandbox document.
func goneDoc(t *testing.T, status int, doc map[string]any, bid string) map[string]any {
	t.Helper()
	if status != 410 || errCode(doc) != "sandbox_gone" {
		t.Fatalf("GET %s: %d %v, want 410 sandbox_gone", bid, status, doc)
	}
	sb, _ := doc["sandbox"].(map[string]any)
	if sb["id"] != bid || sb["state"] != "gone" || sb["gone_at"] == nil || sb["gone_at"] == "" {
		t.Fatalf("410 body %v", doc)
	}
	return sb
}

func goneReason(t *testing.T, tc *testChain, key, bid string) string {
	t.Helper()
	status, doc := tc.call(t, key, "GET", "/v1/sandboxes/"+bid, nil)
	sb := goneDoc(t, status, doc, bid)
	r, _ := sb["reason"].(string)
	return r
}

func TestVanishedRoomAnswers410ToItsGuestOnly(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	syncNow(tc, "b")
	vanish(t, tc, bid)
	status, doc := tc.call(t, "key1", "GET", "/v1/sandboxes/"+bid, nil)
	sb := goneDoc(t, status, doc, bid)
	if sb["reason"] != "unknown" || sb["hotel"] != "b" {
		t.Fatalf("410 body %v, want reason unknown on hotel b", doc)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/exec", map[string]any{"cmd": []string{"true"}}); status != 410 || errCode(doc) != "sandbox_gone" {
		t.Fatalf("exec on a gone room: %d %v, want 410", status, doc)
	}
	// Another guest, or a wrong id, learns nothing.
	if status, doc := tc.call(t, "key2", "GET", "/v1/sandboxes/"+bid, nil); status != 404 || errCode(doc) != "sandbox_not_found" {
		t.Fatalf("other guest: %d %v, want 404", status, doc)
	}
	if status, doc := tc.call(t, "key1", "GET", "/v1/sandboxes/b.sbx_nope", nil); status != 404 || errCode(doc) != "sandbox_not_found" {
		t.Fatalf("wrong id: %d %v, want 404", status, doc)
	}
}

func TestListedExpiryGivesTTLExpired(t *testing.T) {
	tc := newChain(t)
	past := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	future := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	setOnHotel(tc, past, "expires_at", time.Now().Add(-time.Minute).UTC().Format("2006-01-02T15:04:05.000000+00:00"))
	setOnHotel(tc, future, "expires_at", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	syncNow(tc, "b")
	dropFromHotel(tc, past)
	dropFromHotel(tc, future)
	releaseGone(t, tc, "b")
	if r := goneReason(t, tc, "key1", past); r != "ttl_expired" {
		t.Fatalf("room past its listed expiry: reason %q, want ttl_expired", r)
	}
	if r := goneReason(t, tc, "key1", future); r != "unknown" {
		t.Fatalf("room before its listed expiry: reason %q, want unknown", r)
	}
}

func TestDeletedRoomAnswers410Deleted(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+bid, nil); status != 204 {
		t.Fatalf("delete: %d %v", status, doc)
	}
	releaseGone(t, tc, "b")
	if r := goneReason(t, tc, "key1", bid); r != "deleted" {
		t.Fatalf("reason %q, want deleted", r)
	}
}

func TestBulkDeleteGivesDeleted(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "labels": map[string]string{"job": "x"}})
	other := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "labels": map[string]string{"job": "y"}})
	syncNow(tc, "b") // the list carries the labels
	if status, doc := tc.call(t, "key1", "DELETE", "/v1/sandboxes?label=job=x", nil); status != 200 {
		t.Fatalf("bulk delete: %d %v", status, doc)
	}
	dropFromHotel(tc, other) // gone the same tick, not by the delete
	releaseGone(t, tc, "b")
	if r := goneReason(t, tc, "key1", bid); r != "deleted" {
		t.Fatalf("bulk deleted room: reason %q, want deleted", r)
	}
	if r := goneReason(t, tc, "key1", other); r != "unknown" {
		t.Fatalf("room outside the label filter: reason %q, want unknown", r)
	}
}

func TestCompatVanishedRoomReadsDeletedWithReason(t *testing.T) {
	tc := newChain(t)
	mk := func() (string, string) {
		status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
		if status != 200 && status != 201 && status != 202 {
			t.Fatalf("client create: %d %v", status, doc)
		}
		uuid, _ := doc["id"].(string)
		tc.b.mu.Lock()
		bid := tc.b.byUUID[uuid].id
		tc.b.mu.Unlock()
		return uuid, bid
	}
	uuid, bid := mk()
	syncNow(tc, strings.SplitN(bid, ".", 2)[0])
	vanish(t, tc, bid)
	status, doc := tc.clientCall(t, "GET", "/v1/sandboxes/"+uuid, nil, nil)
	if status != 200 || doc["state"] != "deleted" || doc["end_reason"] != "unknown" || doc["gone_at"] == nil || doc["id"] != uuid {
		t.Fatalf("client GET of a vanished room: %d %v, want 200 deleted with end_reason unknown", status, doc)
	}
	uuid2, _ := mk()
	if status, doc := tc.clientCall(t, "DELETE", "/v1/sandboxes/"+uuid2, nil, nil); status != 200 {
		t.Fatalf("client delete: %d %v", status, doc)
	}
	status, doc = tc.clientCall(t, "GET", "/v1/sandboxes/"+uuid2, nil, nil)
	if status != 200 || doc["state"] != "deleted" || doc["end_reason"] != "deleted" {
		t.Fatalf("client GET of a deleted room: %d %v, want end_reason deleted", status, doc)
	}
}

func endedOf(t *testing.T, tc *testChain, key, query string) (int, []map[string]any) {
	t.Helper()
	status, doc := tc.call(t, key, "GET", "/v1/sandboxes/ended"+query, nil)
	var out []map[string]any
	items, _ := doc["ended"].([]any)
	for _, it := range items {
		out = append(out, it.(map[string]any))
	}
	return status, out
}

func TestEndedListNewestFirstWithSinceAndLimit(t *testing.T) {
	tc := newChain(t)
	var ids []string
	for i := 0; i < 3; i++ {
		bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
		syncNow(tc, "b")
		vanish(t, tc, bid)
		ids = append(ids, bid)
		time.Sleep(5 * time.Millisecond)
	}
	status, all := endedOf(t, tc, "key1", "")
	if status != 200 || len(all) != 3 || all[0]["id"] != ids[2] || all[2]["id"] != ids[0] {
		t.Fatalf("ended: %d %v, want %v newest first", status, all, ids)
	}
	if all[0]["reason"] != "unknown" || all[0]["hotel"] != "b" {
		t.Fatalf("ended record %v", all[0])
	}
	if _, one := endedOf(t, tc, "key1", "?limit=1"); len(one) != 1 || one[0]["id"] != ids[2] {
		t.Fatalf("limit=1: %v", one)
	}
	since := all[1]["gone_at"].(string)
	if _, some := endedOf(t, tc, "key1", "?since="+since); len(some) != 2 || some[1]["id"] != ids[1] {
		t.Fatalf("since %s: %v", since, some)
	}
	if status, none := endedOf(t, tc, "key2", ""); status != 200 || len(none) != 0 {
		t.Fatalf("other guest: %d %v", status, none)
	}
	for _, q := range []string{"?limit=1001", "?limit=0", "?limit=x", "?since=yesterday"} {
		if status, _ := endedOf(t, tc, "key1", q); status != 400 {
			t.Errorf("ended%s: %d, want 400", q, status)
		}
	}
}

func TestEndRecordsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+bid, nil); status != 204 {
		t.Fatal("delete")
	}
	releaseGone(t, tc, "b")
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, stateFile))
	var sections map[string]json.RawMessage
	_ = json.Unmarshal(raw, &sections)
	if _, ok := sections["ended_rooms"]; !ok {
		t.Fatalf("client state has no ended_rooms section: %s", raw)
	}
	tc.start(t)
	if r := goneReason(t, tc, "key1", bid); r != "deleted" {
		t.Fatalf("after restart: reason %q, want deleted", r)
	}
}

func TestEndRecordsAreCappedPerGuestAndAged(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	var recs []map[string]any
	for i := 0; i < 50001; i++ { // oldest first
		recs = append(recs, map[string]any{"id": fmt.Sprintf("b.sbx_%d", i), "guest": "g1", "hotel": "b",
			"gone_at": now.Add(-time.Hour + time.Duration(i)*time.Millisecond), "reason": "unknown"})
	}
	recs = append(recs,
		map[string]any{"id": "b.sbx_old", "guest": "g2", "hotel": "b", "gone_at": now.Add(-25 * time.Hour), "reason": "unknown"},
		map[string]any{"id": "b.sbx_new", "guest": "g2", "hotel": "b", "gone_at": now.Add(-time.Minute), "reason": "deleted"})
	raw, _ := json.Marshal(map[string]any{"ended_rooms": recs})
	if err := os.WriteFile(filepath.Join(dir, stateFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tc := newChainState(t, dir)
	if err := tc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(filepath.Join(dir, stateFile))
	var st struct {
		Ended []struct {
			ID    string `json:"id"`
			Guest string `json:"guest"`
		} `json:"ended_rooms"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	per := map[string]int{}
	ids := map[string]bool{}
	for _, e := range st.Ended {
		per[e.Guest]++
		ids[e.ID] = true
	}
	if per["g1"] != 50000 || ids["b.sbx_0"] || !ids["b.sbx_50000"] {
		t.Fatalf("g1 kept %d records (oldest kept: %v), want 50000 without the oldest", per["g1"], ids["b.sbx_0"])
	}
	if per["g2"] != 1 || ids["b.sbx_old"] {
		t.Fatalf("g2 kept %d records (25 h old kept: %v), want 1", per["g2"], ids["b.sbx_old"])
	}
	if status, list := endedOf(t, tc, "key2", ""); status != 200 || len(list) != 1 || list[0]["reason"] != "deleted" {
		t.Fatalf("g2 ended: %d %v", status, list)
	}
}

func TestLiveStreamSendsRoomGoneOnce(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	syncNow(tc, "b")
	req, _ := http.NewRequest("GET", tc.srv.URL+"/g1/live/events", nil)
	req.AddCookie(&http.Cookie{Name: "bv_g1", Value: "view1"})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	events := make(chan string, 100)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		event := ""
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: ") && event == "room_gone":
				events <- strings.TrimPrefix(line, "data: ")
				event = ""
			case line == "":
				event = ""
			}
		}
	}()
	time.Sleep(1200 * time.Millisecond)
	vanish(t, tc, bid)
	var got []string
	deadline := time.After(3500 * time.Millisecond)
loop:
	for {
		select {
		case e := <-events:
			got = append(got, e)
		case <-deadline:
			break loop
		}
	}
	if len(got) != 1 {
		t.Fatalf("room_gone events %v, want one", got)
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(got[0]), &ev); err != nil || ev["id"] != bid || ev["reason"] != "unknown" || ev["hotel"] != "b" {
		t.Fatalf("room_gone %s", got[0])
	}
}

func TestHotelEndReasonWins(t *testing.T) {
	tc := newChain(t)
	idle := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	oom := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	odd := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	// The hotel lists a dead container with its reason; the room ends later.
	setOnHotel(tc, oom, "container_state", "exited")
	setOnHotel(tc, oom, "end_reason", "oom_killed")
	syncNow(tc, "b")
	idleHid := strings.SplitN(idle, ".", 2)[1]
	oddHid := strings.SplitN(odd, ".", 2)[1]
	f := tc.hotels["b"]
	f.mu.Lock()
	f.listExtra = map[string]any{"ended": []map[string]any{
		{"id": idleHid, "end_reason": "idle_timeout", "ended_at": time.Now().UTC().Format(time.RFC3339)},
		{"id": oddHid, "end_reason": "<script>", "ended_at": time.Now().UTC().Format(time.RFC3339)},
	}}
	f.mu.Unlock()
	dropFromHotel(tc, idle)
	dropFromHotel(tc, oom)
	dropFromHotel(tc, odd)
	releaseGone(t, tc, "b")
	if r := goneReason(t, tc, "key1", idle); r != "idle_timeout" {
		t.Fatalf("hotel ended reason: %q, want idle_timeout", r)
	}
	if r := goneReason(t, tc, "key1", oom); r != "oom_killed" {
		t.Fatalf("listed container death: %q, want oom_killed", r)
	}
	if r := goneReason(t, tc, "key1", odd); r != "unknown" {
		t.Fatalf("a reason the broker does not know: %q, want unknown", r)
	}
}

func TestHotelAPIRestartGivesHotelRestarted(t *testing.T) {
	tc := newChain(t)
	f := tc.hotels["b"]
	f.mu.Lock()
	f.listExtra = map[string]any{"api_started_at": "2026-11-21T07:00:00+00:00"}
	f.mu.Unlock()
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	syncNow(tc, "b")
	f.mu.Lock()
	f.listExtra = map[string]any{"api_started_at": "2026-11-21T08:00:00+00:00"}
	f.mu.Unlock()
	vanish(t, tc, bid)
	if r := goneReason(t, tc, "key1", bid); r != "hotel_restarted" {
		t.Fatalf("room gone with the hotel API restart: %q, want hotel_restarted", r)
	}
}

func TestReAdoptedRoomDropsItsEndRecord(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	syncNow(tc, "b")
	f := tc.hotels["b"]
	f.mu.Lock()
	saved := append([]map[string]any(nil), f.rooms...)
	f.mu.Unlock()
	vanish(t, tc, bid)
	goneReason(t, tc, "key1", bid)
	f.mu.Lock()
	f.rooms = saved // a late list shows the room again
	f.mu.Unlock()
	syncNow(tc, "b")
	if status, doc := tc.call(t, "key1", "GET", "/v1/sandboxes/"+bid, nil); status != 200 {
		t.Fatalf("re-adopted room: %d %v, want 200", status, doc)
	}
	if status, list := endedOf(t, tc, "key1", ""); status != 200 || len(list) != 0 {
		t.Fatalf("ended after re-adoption: %d %v, want none", status, list)
	}
}

func TestRefusedCreateLeavesNoEndRecord(t *testing.T) {
	tc := newChain(t) // no hotel applies tunables: the broker reaps the room
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{
		"image": "alpine:3.20", "hotels": []string{"b"}, "tunables": coldTunables()})
	if status != 409 || errCode(doc) != "tunables_unavailable" {
		t.Fatalf("create: %d %v", status, doc)
	}
	releaseGone(t, tc, "b")
	if status, list := endedOf(t, tc, "key1", ""); status != 200 || len(list) != 0 {
		t.Fatalf("ended after a refused create: %d %v, want none", status, list)
	}
}

// Review F2 on #637: records written out of GoneAt order (rooms held back as
// deleting and freed together) still list newest first, and a live stream
// still gets the late one once.
func TestEndedListStaysNewestFirstWhenWrittenOutOfOrder(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	now := time.Now()
	seq0 := tc.b.endSeq
	for _, x := range []struct {
		id  string
		ago time.Duration
	}{{"b.sbx_mid", 2 * time.Minute}, {"b.sbx_new", time.Minute}, {"b.sbx_old", 3 * time.Minute}} {
		tc.b.mu.Lock()
		tc.b.addEnded(&endRecord{ID: x.id, Guest: "g1", Hotel: "b", GoneAt: now.Add(-x.ago), Reason: endUnknown})
		tc.b.mu.Unlock()
	}
	_, list := endedOf(t, tc, "key1", "?limit=2")
	if len(list) != 2 || list[0]["id"] != "b.sbx_new" || list[1]["id"] != "b.sbx_mid" {
		t.Fatalf("ended limit 2 = %v, want new then mid", list)
	}
	got, _ := tc.b.endedSince("g1", seq0+2)
	if len(got) != 1 || got[0]["id"] != "b.sbx_old" {
		t.Fatalf("stream after the first two records = %v, want only the late old one", got)
	}
}
