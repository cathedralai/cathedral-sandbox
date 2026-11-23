package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// AB#948: the allowance stop and the metered thaw gate.

func stopBody(issue int, reason string) map[string]any {
	b := allowanceBody(issue, 0)
	b["stop"] = map[string]any{"reason": reason}
	return b
}

func hasStopFields(v map[string]any) bool {
	_, running := v["stop_running"]
	_, last := v["last_stop"]
	return running || last
}

func hotelRoomID(bid string) string { return strings.SplitN(bid, ".", 2)[1] }

func setHotelRoomState(f *fakeHotel, id, state string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rm := range f.rooms {
		if rm["id"] == id {
			rm["state"] = state
		}
	}
}

func freezesOn(f *fakeHotel) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return sortedCopy(f.freezes)
}

// hotelSaw counts the requests "METHOD path" a lifeHotel got.
func hotelSaw(l *lifeHotel, call string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, c := range l.seen {
		if c == call {
			n++
		}
	}
	return n
}

// waitStop waits until no stop pass runs for guest and last_stop is set and
// not the one stamped after, and returns it.
func (tc *testChain) waitStop(t *testing.T, guest, after string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		v := tc.getAllowance(t, guest)
		if last, _ := v["last_stop"].(map[string]any); v["stop_running"] == false && last != nil && last["at"] != after {
			return last
		}
		if time.Now().After(deadline) {
			t.Fatalf("no finished stop for %s: %v", guest, v)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// noDeleteOrThaw fails when any hotel got a delete or a thaw.
func noDeleteOrThaw(t *testing.T, tc *testChain) {
	t.Helper()
	for id, f := range tc.hotels {
		f.mu.Lock()
		for _, c := range f.calls {
			if strings.HasPrefix(c, "DELETE ") || strings.Contains(c, "/thaw") {
				f.mu.Unlock()
				t.Fatalf("hotel %s got %s", id, c)
			}
		}
		f.mu.Unlock()
	}
}

func TestMeteredThawIsGatedByTheAllowance(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 1))
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	thaw := "POST /v1/sandboxes/" + hotelRoomID(bid) + "/thaw"
	l := lives["b"]
	// Cap 0 with the room live, then a stale lease: refused, the hotel gets nothing.
	for _, c := range []struct {
		setup func()
		code  string
	}{
		{func() { tc.putAllowance(t, "g1", allowanceBody(2, 0)) }, "allowance_exhausted"},
		{func() { tc.putAllowance(t, "g1", allowanceBody(3, 1)); tc.ageLease("g1", time.Hour) }, "allowance_lease_expired"},
	} {
		c.setup()
		for _, path := range []string{"/thaw", "/thaw;x"} {
			if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+path, nil); status != 402 || errCode(doc) != c.code {
				t.Fatalf("thaw%s (%s): %d %v", path, c.code, status, doc)
			}
		}
		if n := hotelSaw(l, thaw) + hotelSaw(l, thaw+";x"); n != 0 {
			t.Fatalf("a refused thaw reached the hotel %d times", n)
		}
	}
	// Under the cap: the thaw goes to the hotel.
	tc.putAllowance(t, "g1", allowanceBody(4, 1))
	tc.call(t, "key1", "POST", "/v1/sandboxes/"+bid+"/thaw", nil)
	if n := hotelSaw(l, thaw); n != 1 {
		t.Fatalf("thaw under the cap reached the hotel %d times, want 1", n)
	}
	// A guest that is not metered thaws as before, whatever g1's allowance.
	tc.putAllowance(t, "g1", allowanceBody(5, 0))
	bid2 := tc.room(t, "key2", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	tc.call(t, "key2", "POST", "/v1/sandboxes/"+bid2+"/thaw", nil)
	if n := hotelSaw(l, "POST /v1/sandboxes/"+hotelRoomID(bid2)+"/thaw"); n != 1 {
		t.Fatalf("g2 thaw reached the hotel %d times, want 1", n)
	}
}

func TestAllowanceStopFreezesOnlyItsGuestsRunningRooms(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	r1 := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	r2 := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	r3 := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	other := tc.room(t, "key2", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	setHotelRoomState(tc.hotels["b"], hotelRoomID(r2), "frozen")

	doc := tc.putAllowance(t, "g1", stopBody(2, "account_suspended"))
	if !reflect.DeepEqual(doc["stop"], map[string]any{"reason": "account_suspended", "started": true}) || doc["cap"] != 0.0 {
		t.Fatalf("PUT answer: %v", doc)
	}
	last := tc.waitStop(t, "g1", "")
	if last["frozen"] != 2.0 || !reflect.DeepEqual(last["failed"], map[string]any{}) || last["reason"] != "account_suspended" {
		t.Fatalf("last_stop: %v", last)
	}
	if got := freezesOn(tc.hotels["b"]); !reflect.DeepEqual(got, []string{hotelRoomID(r1)}) {
		t.Fatalf("hotel b freezes %v", got)
	}
	if got := freezesOn(tc.hotels["a"]); !reflect.DeepEqual(got, []string{hotelRoomID(r3)}) {
		t.Fatalf("hotel a freezes %v", got)
	}
	if s := hotelRoomState(tc.hotels["b"], hotelRoomID(other)); s != "running" {
		t.Fatalf("g2 room state %v, want running", s)
	}
	noDeleteOrThaw(t, tc)
}

func TestAllowanceStopRepeatFreezesNothingNew(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	r1 := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	tc.putAllowance(t, "g1", stopBody(2, "abuse"))
	first := tc.waitStop(t, "g1", "")
	if first["frozen"] != 1.0 {
		t.Fatalf("first stop: %v", first)
	}
	tc.putAllowance(t, "g1", stopBody(3, "abuse"))
	second := tc.waitStop(t, "g1", first["at"].(string))
	if second["frozen"] != 0.0 || !reflect.DeepEqual(second["failed"], map[string]any{}) {
		t.Fatalf("second stop: %v", second)
	}
	if got := freezesOn(tc.hotels["b"]); !reflect.DeepEqual(got, []string{hotelRoomID(r1)}) {
		t.Fatalf("hotel freezes after two stops %v", got)
	}
	noDeleteOrThaw(t, tc)
}

func TestAllowanceStopFreezesACreatingRoomOnALaterStop(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	f := tc.hotels["b"]
	setHotelRoomState(f, hotelRoomID(bid), "creating")
	tc.putAllowance(t, "g1", stopBody(2, "account_suspended"))
	first := tc.waitStop(t, "g1", "")
	if first["frozen"] != 0.0 || len(freezesOn(f)) != 0 {
		t.Fatalf("stop froze a creating room: %v, freezes %v", first, freezesOn(f))
	}
	setHotelRoomState(f, hotelRoomID(bid), "running")
	tc.putAllowance(t, "g1", stopBody(3, "account_suspended"))
	second := tc.waitStop(t, "g1", first["at"].(string))
	if second["frozen"] != 1.0 || hotelRoomState(f, hotelRoomID(bid)) != "frozen" {
		t.Fatalf("later stop: %v, room %v", second, hotelRoomState(f, hotelRoomID(bid)))
	}
}

func TestAllowanceStopNeedsCapZeroAndAKnownReason(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	withCap := stopBody(1, "abuse")
	withCap["cap"] = 1
	withID := stopBody(1, "abuse")
	withID["stop"] = map[string]any{"reason": "abuse", "id": "x"}
	for _, body := range []map[string]any{withCap, stopBody(1, "other"), stopBody(1, ""), withID} {
		if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", body); status != 400 {
			t.Fatalf("bad stop %v: %d %v", body, status, doc)
		}
	}
	if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g1/allowance", withCap); errCode(doc) != "invalid_stop" {
		t.Fatalf("stop with cap 1: %d %v", status, doc)
	}
	if v := tc.getAllowance(t, "g1"); v["ledger_seen_at"] != nil || hasStopFields(v) {
		t.Fatalf("a refused stop changed the guest: %v", v)
	}
}

func TestAllowanceStopOnANonMeteredGuestIs409AndFreezesNothing(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	bid := tc.room(t, "key2", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	// const is postpaid and never metered: pin that too.
	for _, postpaid := range []bool{false, true} {
		tc.b.mu.Lock()
		tc.b.guestByID("g2").limits.Postpaid = postpaid
		tc.b.mu.Unlock()
		if status, doc := tc.call(t, "operator-key", "PUT", "/v1/broker/guests/g2/allowance", stopBody(1, "account_suspended")); status != 409 || errCode(doc) != "guest_not_metered" {
			t.Fatalf("stop on g2 (postpaid %v): %d %v", postpaid, status, doc)
		}
	}
	time.Sleep(200 * time.Millisecond) // a pass, had one started, lists and freezes in milliseconds
	if got := freezesOn(tc.hotels["b"]); len(got) != 0 || hotelRoomState(tc.hotels["b"], hotelRoomID(bid)) != "running" {
		t.Fatalf("a refused stop froze %v", got)
	}
	if v := tc.getAllowance(t, "g2"); v["metered"] != false {
		t.Fatalf("g2 view: %v", v)
	}
}

func TestAllowanceStopAnswersBeforeASlowFreeze(t *testing.T) {
	tc, lives := meteredChain(t, nil)
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	l := lives["b"]
	hold, entered := make(chan struct{}), make(chan string, 4)
	var once sync.Once
	release := func() { once.Do(func() { close(hold) }) }
	defer release()
	l.mu.Lock()
	l.holdFreezes, l.freezeEntered = hold, entered
	l.mu.Unlock()

	start := time.Now()
	doc := tc.putAllowance(t, "g1", stopBody(2, "account_suspended"))
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("PUT with a stop took %v while the hotel holds the freeze", took)
	}
	if doc["stop"].(map[string]any)["started"] != true {
		t.Fatalf("PUT answer: %v", doc)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the freeze never reached the hotel")
	}
	if v := tc.getAllowance(t, "g1"); v["stop_running"] != true || v["last_stop"] != nil {
		t.Fatalf("view during the freeze: %v", v)
	}
	// A stop while one runs starts no second pass.
	start = time.Now()
	doc = tc.putAllowance(t, "g1", stopBody(3, "account_suspended"))
	if took := time.Since(start); took > 2*time.Second || doc["stop"].(map[string]any)["started"] != false {
		t.Fatalf("second PUT during the freeze: %v after %v", doc, took)
	}
	release()
	last := tc.waitStop(t, "g1", "")
	if last["frozen"] != 1.0 {
		t.Fatalf("last_stop: %v", last)
	}
	if got := freezesOn(tc.hotels["b"]); !reflect.DeepEqual(got, []string{hotelRoomID(bid)}) {
		t.Fatalf("hotel freezes %v, want one", got)
	}
}

func TestAllowanceStopResultInTheView(t *testing.T) {
	tc, _ := meteredChain(t, nil)
	// No stop yet: the view keeps the captured exchange shape.
	if v := tc.getAllowance(t, "g1"); hasStopFields(v) {
		t.Fatalf("view before any stop: %v", v)
	}
	tc.putAllowance(t, "g1", allowanceBody(1, 5))
	ok := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	bad := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	f := tc.hotels["b"]
	f.mu.Lock()
	f.freezeFail = map[string]int{hotelRoomID(bad): 502}
	f.mu.Unlock()
	var logged bytes.Buffer
	log.SetOutput(io.MultiWriter(&logged, os.Stderr))
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	before := time.Now().UTC()
	tc.putAllowance(t, "g1", stopBody(2, "abuse"))
	last := tc.waitStop(t, "g1", "")
	at, err := time.Parse(time.RFC3339Nano, last["at"].(string))
	if err != nil || at.Before(before) {
		t.Fatalf("last_stop at %v (%v), want after %v", last["at"], err, before)
	}
	if last["reason"] != "abuse" || last["frozen"] != 1.0 || !reflect.DeepEqual(last["failed"], map[string]any{bad: "freeze_failed"}) || !reflect.DeepEqual(last["hotel_errors"], []any{}) {
		t.Fatalf("last_stop: %v", last)
	}
	// AB#948: the log line names each room with its code, so a stop that froze
	// nothing says why.
	if want := "not frozen: [" + bad + "=freeze_failed]"; !strings.Contains(logged.String(), want) {
		t.Fatalf("stop log %q, want %q", logged.String(), want)
	}
	if hotelRoomState(f, hotelRoomID(ok)) != "frozen" || hotelRoomState(f, hotelRoomID(bad)) != "running" {
		t.Fatal("room states after a partial stop")
	}
}
