package main

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// AB#741: the room passthrough (sync exec, sealed-exec and every other room
// call) answers with the broker's split, as a create does, so a burst of execs
// can be divided into broker queue and hotel time per request.

func brokerSplit(t *testing.T, hdr http.Header) (queue, hotel float64) {
	t.Helper()
	q, errQ := strconv.ParseFloat(hdr.Get("X-Broker-Queue-Ms"), 64)
	h, errH := strconv.ParseFloat(hdr.Get("X-Broker-Hotel-Ms"), 64)
	if errQ != nil || errH != nil || q < 0 || h < 0 {
		t.Fatalf("broker split: queue %q hotel %q", hdr.Get("X-Broker-Queue-Ms"), hdr.Get("X-Broker-Hotel-Ms"))
	}
	return q, h
}

func TestExecAnswerCarriesTheBrokerSplit(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	hotelID, _, _ := strings.Cut(bid, ".")

	status, hdr, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes/"+bid+"/exec", map[string]any{"cmd": []string{"true"}})

	if status != 200 {
		t.Fatalf("exec: %d %v", status, doc)
	}
	brokerSplit(t, hdr)
	if hdr.Get("X-Broker-Hotel") != hotelID {
		t.Fatalf("X-Broker-Hotel %q, want %q", hdr.Get("X-Broker-Hotel"), hotelID)
	}
	if hdr.Get("X-Room-Receipt") != "signed-exec" {
		t.Fatalf("the hotel's receipt header was lost: %q", hdr.Get("X-Room-Receipt"))
	}
}

func TestSealedExecAnswerCarriesTheBrokerSplitAndKeepsItsBody(t *testing.T) {
	tc := newChain(t)
	bid, _ := sealedExecRoom(t, tc)
	_, hid, _ := strings.Cut(bid, ".")
	body := bytes.Replace(sealedExecRequest, []byte(`"ROOM"`), []byte(`"`+hid+`"`), 1)

	resp, out := postSealedExec(t, tc, "key1", bid, body)

	if resp.StatusCode != 200 || !bytes.Equal(out, sealedExecAnswer) {
		t.Fatalf("sealed exec: %d %s", resp.StatusCode, out)
	}
	brokerSplit(t, resp.Header)
}

func TestUnreachableHotelExecStillCarriesTheBrokerSplit(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})
	hotelID, _, _ := strings.Cut(bid, ".")
	// Nothing listens on port 1: the hotel call fails to connect.
	tc.b.hotelByID(hotelID).cfg.API = "http://127.0.0.1:1"

	status, hdr, doc := tc.rawCall(t, "key1", "POST", "/v1/sandboxes/"+bid+"/exec", map[string]any{"cmd": []string{"true"}})

	if status != 502 || errCode(doc) != "hotel_unreachable" {
		t.Fatalf("exec on a dead hotel: %d %v", status, doc)
	}
	brokerSplit(t, hdr)
	if hdr.Get("X-Broker-Hotel") != hotelID {
		t.Fatalf("X-Broker-Hotel %q, want %q", hdr.Get("X-Broker-Hotel"), hotelID)
	}
}

func TestAnswerTheBrokerRefusesCarriesNoSplit(t *testing.T) {
	tc := newChain(t)
	bid := tc.room(t, "key1", map[string]any{"image": "alpine:3.20"})

	// Another guest's room: refused by the broker, the hotel is never asked.
	status, hdr, _ := tc.rawCall(t, "key2", "POST", "/v1/sandboxes/"+bid+"/exec", map[string]any{"cmd": []string{"true"}})
	if status != 404 {
		t.Fatalf("exec on another guest's room: %d", status)
	}
	// A string cmd: refused before the hotel call.
	status2, hdr2, _ := tc.rawCall(t, "key1", "POST", "/v1/sandboxes/"+bid+"/exec", map[string]any{"cmd": "true"})
	if status2 != 400 {
		t.Fatalf("exec with a string cmd: %d", status2)
	}
	for _, h := range []http.Header{hdr, hdr2} {
		for _, k := range []string{"X-Broker-Queue-Ms", "X-Broker-Hotel-Ms", "X-Broker-Hotel"} {
			if v := h.Get(k); v != "" {
				t.Fatalf("%s %q on an answer the hotel never gave", k, v)
			}
		}
	}
}
