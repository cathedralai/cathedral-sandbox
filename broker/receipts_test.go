package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestFilterHotelReceiptsKeepsOwnedReceiptBytes(t *testing.T) {
	mine := []byte(`{"statement":{"sandbox_id":"room-a","image":"mine:1","previous_receipt_sha256":"deadbeef","target":"POST /v1/sandboxes/room-a/exec"},"signature_b64":"sig-a"}`)
	other := []byte(`{"statement":{"sandbox_id":"room-b","image":"other:9","target":"POST /v1/sandboxes/room-b/exec"},"signature_b64":"sig-b","receipt_sha256":"deadbeef"}`)
	failed := []byte(`{"statement":{"sandbox_id":null,"image":"failed-image:3","target":"POST /v1/sandboxes"},"signature_b64":"sig-c"}`)
	body := []byte(`{"binding_sha256":"bb","head":"hh","count":3,"receipts":[` + string(mine) + `,` + string(other) + `,` + string(failed) + `]}`)

	out, err := filterHotelReceipts(body, map[string]bool{"room-a": true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, mine) {
		t.Fatalf("owned receipt bytes changed: %s", out)
	}
	for _, leak := range []string{"room-b", "other:9", "failed-image:3", "sig-b", "sig-c"} {
		if bytes.Contains(out, []byte(leak)) {
			t.Fatalf("response still has %s: %s", leak, out)
		}
	}
	if !bytes.Contains(out, []byte(`"count":1`)) || !bytes.Contains(out, []byte(`"binding_sha256":"bb"`)) {
		t.Fatalf("page fields: %s", out)
	}
	if !bytes.Contains(out, []byte("deadbeef")) {
		t.Fatalf("previous hash should stay on the owned receipt: %s", out)
	}
}

func TestFilterHotelReceiptsRejectsABadChain(t *testing.T) {
	if _, err := filterHotelReceipts([]byte(`not-json`), map[string]bool{"room-a": true}); err == nil {
		t.Fatal("bad json was accepted")
	}
	if _, err := filterHotelReceipts([]byte(`{"head":"hh"}`), nil); err == nil {
		t.Fatal("missing receipts field was accepted")
	}
}

func TestRememberGuestRoomSurvivesRelease(t *testing.T) {
	b := &broker{byUUID: map[string]*room{}}
	h := &hotel{cfg: hotelConfig{ID: "sealed-1"}, rooms: map[string]*room{}}
	b.hset.Store(&hotelSet{byID: map[string]*hotel{"sealed-1": h}})
	rm := &room{h: h, hid: "room-a", id: "sealed-1.room-a", guest: "g1"}
	h.rooms[rm.hid] = rm
	b.register(rm)
	b.release(h, rm)
	if !b.guestRoomIDs("g1", "sealed-1")["room-a"] {
		t.Fatal("released room was forgotten")
	}
	if len(b.guestRoomIDs("g2", "sealed-1")) != 0 {
		t.Fatal("another guest inherited the room")
	}
}

func TestHotelReceiptChainHidesOtherGuests(t *testing.T) {
	tc := newChain(t)
	id1 := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	id2 := tc.room(t, "key2", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	_, hid1, _ := strings.Cut(id1, ".")
	_, hid2, _ := strings.Cut(id2, ".")
	mine := `{"statement":{"sandbox_id":"` + hid1 + `","image":"guest-one-image:1","previous_receipt_sha256":"deadbeef","target":"POST /v1/sandboxes"},"signature_b64":"sig-one"}`
	other := `{"statement":{"sandbox_id":"` + hid2 + `","image":"guest-two-image:9","target":"POST /v1/sandboxes/` + hid2 + `/exec"},"signature_b64":"sig-two","receipt_sha256":"deadbeef"}`
	failed := `{"statement":{"sandbox_id":null,"image":"failed-create-image:3","target":"POST /v1/sandboxes"},"signature_b64":"sig-fail"}`
	raw := []byte(`{"binding_sha256":"bb","head":"hh","count":3,"receipts":[` + mine + `,` + other + `,` + failed + `]}`)
	f := tc.hotels["a"]
	f.mu.Lock()
	f.receipts = raw
	f.mu.Unlock()

	status, page := tc.body(t, "key1", "GET", "/v1/hotels/a/receipts")
	if status != 200 || !bytes.Contains(page, []byte(mine)) {
		t.Fatalf("guest one: %d %s", status, page)
	}
	for _, leak := range []string{hid2, "guest-two-image:9", "failed-create-image:3", "sig-two", "sig-fail"} {
		if bytes.Contains(page, []byte(leak)) {
			t.Fatalf("guest one saw %s: %s", leak, page)
		}
	}

	tc.b.mu.Lock()
	h := tc.b.hotelByID("a")
	tc.b.release(h, h.rooms[hid1])
	tc.b.mu.Unlock()
	status, page = tc.body(t, "key1", "GET", "/v1/hotels/a/receipts")
	if status != 200 || !bytes.Contains(page, []byte("guest-one-image:1")) || bytes.Contains(page, []byte(hid2)) {
		t.Fatalf("deleted room receipt: %d %s", status, page)
	}

	status, page = tc.body(t, "key2", "GET", "/v1/hotels/a/receipts")
	if status != 200 || bytes.Contains(page, []byte(hid1)) || bytes.Contains(page, []byte("guest-one-image:1")) || !bytes.Contains(page, []byte(other)) {
		t.Fatalf("guest two: %d %s", status, page)
	}

	tc.b.mu.Lock()
	tc.b.guests["g1"].cfg.Ops = true
	tc.b.mu.Unlock()
	status, page = tc.body(t, "key1", "GET", "/v1/hotels/a/receipts")
	if status != 200 || !bytes.Equal(page, raw) {
		t.Fatalf("ops response was rewritten: %d %s", status, page)
	}

	f.mu.Lock()
	f.receipts = []byte("not-json")
	f.mu.Unlock()
	tc.b.mu.Lock()
	tc.b.guests["g1"].cfg.Ops = false
	tc.b.mu.Unlock()
	status, doc := tc.call(t, "key1", "GET", "/v1/hotels/a/receipts", nil)
	if status != 502 || errCode(doc) != "receipts_unreadable" {
		t.Fatalf("bad chain: %d %v", status, doc)
	}
}

func (tc *testChain) body(t *testing.T, key, method, path string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, tc.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}
