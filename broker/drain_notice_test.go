package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testNotice is a well-formed notice for hotel id. The broker does not check
// the sr25519 signature, so 64 zero bytes are enough here.
func testNotice(id string, drainAt, until int64, nonce byte) map[string]any {
	return map[string]any{
		"schema": drainNoticeSchema, "network": "test", "netuid": 584,
		"hotkey": minerHotkey, "hotel_id": id,
		"drain_at": drainAt, "until": until, "issued_at": time.Now().Unix(),
		"notice_id": "sha256:" + strings.Repeat(string("0123456789abcdef"[nonce%16]), 64),
		"signature": map[string]any{"algorithm": "sr25519", "value_base64": base64.StdEncoding.EncodeToString(make([]byte, 64))},
	}
}

func noticeLog(t *testing.T, dir string) []drainNoticeRecord {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, drainNoticeLog))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []drainNoticeRecord
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var rec drainNoticeRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

func TestSignedDrainNoticeDrainsAndIsRecorded(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	joinMiner(t, tc, "m1", true, 2, nil)
	admitNow(t, tc, "m1")
	if status, doc := tc.call(t, "enroller-key", "GET", "/v1/broker/hotels/m1", nil); status != 200 || doc["free_rooms"].(float64) < 1 || doc["drain_notice"] != nil {
		t.Fatalf("before notice: %d %v", status, doc)
	}
	drainAt := time.Now().Add(48 * time.Hour).Unix()
	notice := testNotice("m1", drainAt, drainAt+3600, 1)
	before := time.Now().Unix()
	status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true, "drain_notice": notice})
	if status != 200 || doc["drain"] != true || doc["free_rooms"].(float64) != 0 {
		t.Fatalf("notice did not drain at once: %d %v", status, doc)
	}
	rec := tc.b.hotelByID("m1").drainNotice()
	if rec == nil || rec.ReceivedAt < before || rec.ReceivedAt > time.Now().Unix() || rec.Notice.DrainAt != drainAt || rec.Notice.NoticeID != notice["notice_id"] {
		t.Fatalf("notice record: %+v", rec)
	}
	if dn, _ := doc["drain_notice"].(map[string]any); dn == nil || dn["received_at"].(float64) != float64(rec.ReceivedAt) {
		t.Fatalf("hotel document lacks the notice: %v", doc["drain_notice"])
	}

	// A resend keeps the first received_at and writes no second log line.
	first := rec.ReceivedAt
	time.Sleep(1100 * time.Millisecond)
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true, "drain_notice": notice}); status != 200 {
		t.Fatalf("resend: %d %v", status, doc)
	}
	if got := tc.b.hotelByID("m1").drainNotice().ReceivedAt; got != first {
		t.Fatalf("resend restamped received_at: %d, want %d", got, first)
	}
	// A different notice may not replace an open window.
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true, "drain_notice": testNotice("m1", drainAt, drainAt+60, 2)}); status != 409 || errCode(doc) != "drain_notice_active" {
		t.Fatalf("second notice over an open window: %d %v", status, doc)
	}

	// The notice survives a broker restart, and the log survives the hotel leaving.
	tc.start(t)
	if rec := tc.b.hotelByID("m1").drainNotice(); rec == nil || rec.ReceivedAt != first || !tc.b.hotelByID("m1").drain() {
		t.Fatalf("restart lost the notice: %+v", rec)
	}
	if status, doc := tc.call(t, "enroller-key", "DELETE", "/v1/broker/hotels/m1", nil); status != 204 {
		t.Fatalf("leave: %d %v", status, doc)
	}
	logged := noticeLog(t, dir)
	if len(logged) != 1 || logged[0].ReceivedAt != first || logged[0].Notice.HotelID != "m1" || logged[0].Notice.Hotkey != minerHotkey {
		t.Fatalf("notice log: %+v", logged)
	}
}

func TestDrainNoticeRefusals(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	joinMiner(t, tc, "m1", true, 1, nil)
	future := time.Now().Add(48 * time.Hour).Unix()
	mut := func(k string, v any) map[string]any {
		n := testNotice("m1", future, future+3600, 3)
		n[k] = v
		return n
	}
	for name, tcase := range map[string]struct {
		key  string
		path string
		body map[string]any
		code string
	}{
		"no drain":         {"operator-key", "m1", map[string]any{"drain_notice": testNotice("m1", future, future+1, 3)}, "invalid_drain_notice"},
		"drain false":      {"operator-key", "m1", map[string]any{"drain": false, "drain_notice": testNotice("m1", future, future+1, 3)}, "invalid_drain_notice"},
		"other hotkey":     {"enroller-key", "m1", map[string]any{"drain": true, "drain_notice": mut("hotkey", "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")}, "invalid_drain_notice"},
		"other hotel":      {"enroller-key", "m1", map[string]any{"drain": true, "drain_notice": mut("hotel_id", "m2")}, "invalid_drain_notice"},
		"window reversed":  {"enroller-key", "m1", map[string]any{"drain": true, "drain_notice": mut("until", future-1)}, "invalid_drain_notice"},
		"window ended":     {"enroller-key", "m1", map[string]any{"drain": true, "drain_notice": testNotice("m1", 100, 200, 3)}, "invalid_drain_notice"},
		"bad schema":       {"enroller-key", "m1", map[string]any{"drain": true, "drain_notice": mut("schema", "v0")}, "invalid_drain_notice"},
		"bad id":           {"enroller-key", "m1", map[string]any{"drain": true, "drain_notice": mut("notice_id", "abc")}, "invalid_drain_notice"},
		"short signature":  {"enroller-key", "m1", map[string]any{"drain": true, "drain_notice": mut("signature", map[string]any{"algorithm": "sr25519", "value_base64": "AAAA"})}, "invalid_drain_notice"},
		"unknown field":    {"enroller-key", "m1", map[string]any{"drain": true, "drain_notice": mut("extra", 1)}, "invalid_drain_notice"},
		"operator hotel":   {"operator-key", "a", map[string]any{"drain": true, "drain_notice": testNotice("a", future, future+1, 3)}, "invalid_drain_notice"},
		"enroller undrain": {"enroller-key", "m1", map[string]any{"drain": false, "drain_notice": testNotice("m1", future, future+1, 3)}, "enroller_scope"},
	} {
		status, doc := tc.call(t, tcase.key, "PATCH", "/v1/broker/hotels/"+tcase.path, tcase.body)
		if status < 400 || errCode(doc) != tcase.code {
			t.Fatalf("%s: %d %v", name, status, doc)
		}
	}
	if h := tc.b.hotelByID("m1"); h.drain() || h.drainNotice() != nil || noticeLog(t, dir) != nil {
		t.Fatal("a refused notice changed the hotel or the log")
	}
	// A join cannot carry a notice.
	_, url := newMinerHotel(t, 1, snpAttestation(t, attestOpts{chip: chipOf("m9")}))
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": "m9", "api": url, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey,
		"drain_notice": map[string]any{"notice": testNotice("m9", future, future+1, 3), "received_at": 1},
	}); status != 400 || errCode(doc) != "invalid_hotel" {
		t.Fatalf("join seeded a notice: %d %v", status, doc)
	}
}

func TestDrainNoticeFailedSaveLeavesNoNotice(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	joinMiner(t, tc, "m1", true, 1, nil)
	if err := os.Mkdir(filepath.Join(dir, runtimeHotelsFile+".tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(48 * time.Hour).Unix()
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true, "drain_notice": testNotice("m1", future, future+60, 4)}); status != 500 || errCode(doc) != "state_write_failed" {
		t.Fatalf("notice acknowledged without state save: %d %v", status, doc)
	}
	if h := tc.b.hotelByID("m1"); h.drain() || h.drainNotice() != nil {
		t.Fatal("failed save left the notice live")
	}
	tc.start(t)
	if h := tc.b.hotelByID("m1"); h.drain() || h.drainNotice() != nil {
		t.Fatal("failed save left the notice on disk")
	}
}

func TestOperatorUndrainEndsTheMaintenance(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 1, nil)
	future := time.Now().Add(48 * time.Hour).Unix()
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true, "drain_notice": testNotice("m1", future, future+60, 5)}); status != 200 {
		t.Fatalf("notice: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": false}); status != 200 || doc["drain"] != false || doc["drain_notice"] != nil {
		t.Fatalf("undrain: %d %v", status, doc)
	}
	// A plain drain (no notice) still works and records nothing.
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true}); status != 200 || doc["drain_notice"] != nil {
		t.Fatalf("plain drain: %d %v", status, doc)
	}
}
