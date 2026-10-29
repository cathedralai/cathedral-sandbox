package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Lend an idle reserved sealed hotel to the pool and reclaim it only after a
// re-seal (lend.go). Hotels as in reservedChain: "a" sealed (pool), "b" and
// "c" unsealed, "nc" and "nc2" sealed and reserved for g2 (the const shape:
// a hotel list). g1 is a pool guest that prefers sealed. No network.

// setLaunch makes hotel id serve an SEV-SNP attestation whose REPORT_ID is
// all fill: one value per SNP launch.
func setLaunch(t *testing.T, tc *testChain, id string, fill byte) {
	t.Helper()
	f := tc.hotels[id]
	f.mu.Lock()
	f.attestation = snpAttestation(t, attestOpts{chip: chipOf(id), reportID: fill})
	f.mu.Unlock()
}

func launchID(fill byte) string {
	return strings.Repeat(hex.EncodeToString([]byte{fill}), 32)
}

func lendChain(t *testing.T) *testChain {
	t.Helper()
	tc := reservedChain(t)
	addFakeHotel(t, tc, "nc2", true)
	reserve(t, tc, "nc2", "g2")
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g2", map[string]any{"hotels": []string{"nc", "nc2"}}); status != 200 {
		t.Fatalf("g2 list: %d %v", status, doc)
	}
	setLaunch(t, tc, "nc", 0x11)
	return tc
}

func lend(t *testing.T, tc *testChain, id string) map[string]any {
	t.Helper()
	status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/"+id, map[string]any{"lend": true})
	if status != 200 {
		t.Fatalf("lend %s: %d %v", id, status, doc)
	}
	return doc
}

// dropRoom is the sync loop's last step for a deleted room: the hotel no
// longer lists it, so the broker forgets it.
func dropRoom(tc *testChain, hotelID, roomID string) {
	setHotel(tc, hotelID, func(h *hotel) {
		for _, rm := range h.rooms {
			if rm.id == roomID {
				tc.b.release(h, rm)
			}
		}
	})
}

func TestReportIDIsReadAtOffset0x140(t *testing.T) {
	att := snpAttestation(t, attestOpts{reportID: 0x5a})
	var doc struct {
		Binding json.RawMessage `json:"binding"`
		SHA     string          `json:"binding_sha256"`
		Report  string          `json:"report_b64"`
	}
	if err := json.Unmarshal(att, &doc); err != nil {
		t.Fatal(err)
	}
	res, err := verifyAttestation(doc.Binding, doc.SHA, doc.Report, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.reportID != launchID(0x5a) {
		t.Fatalf("reportID %q, want the 32 bytes at 0x140", res.reportID)
	}
	// REPORT_DATA (0x50) holds the binding hash; it must not be read as REPORT_ID.
	rep, _ := base64.StdEncoding.DecodeString(doc.Report)
	if strings.Contains(res.reportID, hex.EncodeToString(rep[0x50:0x60])) {
		t.Fatalf("reportID overlaps REPORT_DATA")
	}
	if snpReportID(make([]byte, 0x4A0)) != "" {
		t.Fatalf("an all-zero REPORT_ID must read as none")
	}
}

func TestLendValidation(t *testing.T) {
	tc := lendChain(t)
	patch := func(id string, body map[string]any) (int, string) {
		status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/"+id, body)
		return status, errCode(doc)
	}
	for _, c := range []struct {
		id     string
		body   map[string]any
		status int
		code   string
	}{
		{"a", map[string]any{"lend": true}, 409, "hotel_not_reserved"},
		{"nc", map[string]any{"lend": false}, 400, "invalid_lend"},
		{"nc", map[string]any{"lend": true, "reserved_for": "g2"}, 400, "invalid_lend"},
		{"nc2", map[string]any{"lend": true}, 502, "hotel_unreachable"}, // no attestation endpoint
	} {
		if status, code := patch(c.id, c.body); status != c.status || code != c.code {
			t.Fatalf("%s %v: %d %s, want %d %s", c.id, c.body, status, code, c.status, c.code)
		}
	}
	reserve(t, tc, "b", "g2")
	if status, code := patch("b", map[string]any{"lend": true}); status != 409 || code != "hotel_not_sealed" {
		t.Fatalf("unsealed: %d %s", status, code)
	}
	setLaunch(t, tc, "nc2", 0) // a report with no REPORT_ID cannot prove a later re-seal
	if status, code := patch("nc2", map[string]any{"lend": true}); status != 422 || code != "attestation_failed" {
		t.Fatalf("zero REPORT_ID: %d %s", status, code)
	}
	if status, _ := tc.call(t, "key2", "PATCH", "/v1/broker/hotels/nc", map[string]any{"lend": true}); status != 401 {
		t.Fatalf("guest key lent a hotel: %d", status)
	}
	// A refused lend changes nothing, other fields included.
	if status, code := patch("nc2", map[string]any{"lend": true, "drain": true}); status != 422 || code != "attestation_failed" || tc.b.hotelByID("nc2").drain() {
		t.Fatalf("refused lend applied drain: %d %s", status, code)
	}
	if h := tc.b.hotelByID("nc2"); h.reservedFor() != "g2" || h.lentFrom() != "" {
		t.Fatalf("refused lend changed the hotel: %+v", h.cfg)
	}
	// Join cannot set the lend fields; a config file cannot be half lent.
	_, url := newMinerHotel(t, 5, nil)
	if status, doc := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "x", "api": url, "key": joinKey, "lent_from": "g2"}); status != 400 {
		t.Fatalf("join with lent_from: %d %v", status, doc)
	}
	for _, hc := range []hotelConfig{{LentFrom: "g2"}, {LentReportID: "ab"}, {LentFrom: "g2", LentReportID: "ab", ReservedFor: "g2"}} {
		if lendConfigError(hc) == nil {
			t.Fatalf("config %+v accepted", hc)
		}
	}
}

func TestLendRefusedWhileTheOwnerHasRooms(t *testing.T) {
	tc := lendChain(t)
	status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"nc"}})
	if status != 202 {
		t.Fatalf("owner create: %d %v", status, doc)
	}
	room := doc["id"].(string)
	status, doc = tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/nc", map[string]any{"lend": true})
	if status != 409 || errCode(doc) != "owner_rooms_active" {
		t.Fatalf("lend with an owner room: %d %v", status, doc)
	}
	if h := tc.b.hotelByID("nc"); h.reservedFor() != "g2" || h.lentFrom() != "" {
		t.Fatalf("refused lend changed the hotel: %+v", h.cfg)
	}
	// Deleting is not enough while the hotel still lists the room.
	if status, _ := tc.call(t, "key2", "DELETE", "/v1/sandboxes/"+room, nil); status != 204 {
		t.Fatalf("delete: %d", status)
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/nc", map[string]any{"lend": true}); status != 409 || errCode(doc) != "owner_rooms_active" {
		t.Fatalf("lend with a deleting owner room: %d %v", status, doc)
	}
	dropRoom(tc, "nc", room)
	doc = lend(t, tc, "nc")
	if doc["lent_from"] != "g2" || doc["reserved_for"] != nil || doc["lent_report_id"] != launchID(0x11) {
		t.Fatalf("hotel doc after lend: %v", doc)
	}
}

func TestLentHotelRefusesTheOwnerAndTakesThePool(t *testing.T) {
	tc := lendChain(t)
	lend(t, tc, "nc")

	// The owner: never on the lent hotel; its other hotel still works.
	if status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"nc"}}); status != 403 || errCode(doc) != "hotel_lent" {
		t.Fatalf("owner named the lent hotel: %d %v", status, doc)
	}
	for i := 0; i < 5; i++ {
		if h := ownerCreate(t, tc); h != "nc2" {
			t.Fatalf("owner create on %s, want nc2", h)
		}
	}
	setHotel(tc, "nc2", func(h *hotel) { h.slots = 0 }) // only the lent hotel has room
	if status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "sealed": true}); status == 202 {
		t.Fatalf("owner placed with only the lent hotel free: %v", doc)
	}
	if n := creates(tc, "nc"); n != 0 {
		t.Fatalf("lent hotel got %d owner creates", n)
	}
	// An owner whose only hotel is lent hears why.
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/guests/g2", map[string]any{"hotels": []string{"nc"}}); status != 200 {
		t.Fatalf("g2 list: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "sealed": true}); status != 403 || errCode(doc) != "hotel_lent" {
		t.Fatalf("owner with only a lent hotel: %d %v", status, doc)
	}
	if _, cat := tc.call(t, "key2", "GET", "/v1/broker/capacity", nil); listed(cat, "nc") {
		t.Fatalf("owner catalog lists its lent hotel: %v", cat)
	}

	// The pool: g1 lands on the lent hotel when it is the sealed hotel with room.
	setHotel(tc, "a", func(h *hotel) { h.slots = 0 })
	if h, tier, _ := createdOn(t, tc, map[string]any{"image": "alpine:3.20", "sealed": true}); h != "nc" || tier != "prefer" {
		t.Fatalf("pool create on %s %s, want nc prefer", h, tier)
	}
	_, cat := tc.call(t, "key1", "GET", "/v1/broker/capacity", nil)
	e, ok := catalogEntry(cat, "nc")
	if !ok || e["reserved_for"] != nil {
		t.Fatalf("pool catalog: %v", cat)
	}
	if _, has := e["lent_from"]; has {
		t.Fatalf("pool guest sees whose hotel it is: %v", e)
	}
	_, cat = tc.call(t, "operator-key", "GET", "/v1/broker/capacity", nil)
	if e, _ := catalogEntry(cat, "nc"); e["lent_from"] != "g2" {
		t.Fatalf("operator catalog: %v", e)
	}
	if e, _ := catalogEntry(cat, "a"); e["lent_from"] != nil {
		t.Fatalf("operator catalog of a pool hotel: %v", e)
	}
}

// addWSHotel adds a hotel with workspace routes (wsHotel) to the chain.
func addWSHotel(t *testing.T, tc *testChain, id string) *wsHotel {
	t.Helper()
	f := &fakeHotel{t: t, snaps: map[string]map[string]any{}}
	wh := &wsHotel{fakeHotel: f, ws: map[string]map[string]bool{}}
	hs := httptest.NewServer(wh)
	t.Cleanup(hs.Close)
	tc.hotels[id] = f
	h := newHotel(hotelConfig{ID: id, Name: id, API: hs.URL, Health: hs.URL, Concurrency: 4, Sealed: true}, "hotel-key")
	if err := tc.b.addHotel(h); err != nil {
		t.Fatal(err)
	}
	setHotel(tc, id, func(h *hotel) { h.ok, h.slots = true, 100 })
	return wh
}

func TestWorkspaceCreateSkipsALentHotel(t *testing.T) {
	tc := newChain(t)
	tc.b.hotelByID("a").cfg.Sealed = true
	setPolicy(t, tc, "g1", map[string]any{"prefer": []any{map[string]any{"class": "sealed"}}})
	lent := addWSHotel(t, tc, "nc")
	reserve(t, tc, "nc", "g2")
	setLaunch(t, tc, "nc", 0x11)
	lend(t, tc, "nc")
	setHotel(tc, "a", func(h *hotel) { h.ok = false }) // the lent hotel is the only sealed hotel up

	// A room goes there; a workspace does not, named or not.
	if h, _, _ := createdOn(t, tc, map[string]any{"image": "alpine:3.20", "sealed": true}); h != "nc" {
		t.Fatalf("pool room on %s, want nc", h)
	}
	for _, body := range []map[string]any{{"name": "w1", "sealed": true}, {"name": "w1", "hotels": []string{"nc"}}} {
		if status, doc := tc.call(t, "key1", "POST", "/v1/workspaces", body); status != 503 || errCode(doc) != "no_hotel_available" {
			t.Fatalf("workspace %v with only the lent hotel: %d %v", body, status, doc)
		}
	}
	// Another sealed pool hotel takes it.
	pool := addWSHotel(t, tc, "ws2")
	for i := 0; i < 5; i++ {
		name := "w" + string(rune('a'+i))
		status, doc := tc.call(t, "key1", "POST", "/v1/workspaces", map[string]any{"name": name, "sealed": true})
		if status != 201 || doc["hotel"] != "ws2" {
			t.Fatalf("workspace %s: %d %v, want ws2", name, status, doc)
		}
	}
	lent.wmu.Lock()
	defer lent.wmu.Unlock()
	for g, names := range lent.ws {
		if len(names) > 0 {
			t.Fatalf("lent hotel holds workspaces of %s: %v", g, names)
		}
	}
	pool.wmu.Lock()
	defer pool.wmu.Unlock()
	if len(pool.ws["g1"]) != 5 {
		t.Fatalf("pool hotel workspaces: %v", pool.ws)
	}
}

func TestReclaimNeedsNoRoomsAndANewLaunch(t *testing.T) {
	tc := lendChain(t)
	lend(t, tc, "nc")
	setHotel(tc, "a", func(h *hotel) { h.slots = 0 })
	_, _, room := createdOn(t, tc, map[string]any{"image": "alpine:3.20", "sealed": true}) // a pool room on nc
	reclaim := func() (int, map[string]any) {
		return tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/nc", map[string]any{"reserved_for": "g2", "drain": false})
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/nc", map[string]any{"reserved_for": nil}); status != 409 || errCode(doc) != "hotel_lent" {
		t.Fatalf("release of a lent hotel: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/nc", map[string]any{"drain": true}); status != 200 || doc["drain"] != true {
		t.Fatalf("drain: %d %v", status, doc)
	}
	if status, doc := reclaim(); status != 409 || errCode(doc) != "rooms_active" {
		t.Fatalf("reclaim with a pool room: %d %v", status, doc)
	}
	if status, _ := tc.call(t, "key1", "DELETE", "/v1/sandboxes/"+room, nil); status != 204 {
		t.Fatalf("delete: %d", status)
	}
	dropRoom(tc, "nc", room)
	// No rooms, but the same SNP launch: what pool guests left is still there.
	if status, doc := reclaim(); status != 409 || errCode(doc) != "reseal_required" {
		t.Fatalf("reclaim without a re-seal: %d %v", status, doc)
	}
	if h := tc.b.hotelByID("nc"); h.lentFrom() != "g2" || h.reservedFor() != "" || !h.drain() {
		t.Fatalf("refused reclaim changed the hotel: %+v", h.cfg)
	}
	if status, _ := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"nc"}}); status != 403 {
		t.Fatalf("owner create after a refused reclaim: %d", status)
	}

	setLaunch(t, tc, "nc", 0x22) // destroyed and relaunched: a new REPORT_ID
	status, doc := reclaim()
	if status != 200 || doc["reserved_for"] != "g2" || doc["lent_from"] != nil || doc["lent_report_id"] != nil || doc["drain"] != false {
		t.Fatalf("reclaim after a re-seal: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key2", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"nc"}}); status != 202 || doc["hotel"] != "nc" {
		t.Fatalf("owner create after reclaim: %d %v", status, doc)
	}
	// The pool is out again.
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"nc"}}); status != 409 || errCode(doc) != "unknown_hotel" {
		t.Fatalf("pool named the reclaimed hotel: %d %v", status, doc)
	}
	// A reserved hotel is no longer lent: reserved_for works as before.
	reserve(t, tc, "nc", nil)
}

func TestLendStateOfAJoinedHotelSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	m := joinMiner(t, tc, "m1", true, 10, map[string]any{"reserved_for": "g2"})
	m.setAttestation(snpAttestation(t, attestOpts{chip: chipOf("m1"), reportID: 0x11}))
	lend(t, tc, "m1")
	raw, _ := os.ReadFile(filepath.Join(dir, runtimeHotelsFile))
	if !strings.Contains(string(raw), `"lent_from": "g2"`) || !strings.Contains(string(raw), launchID(0x11)) {
		t.Fatalf("hotels.json: %s", raw)
	}

	tc.start(t) // restart: same config, same state_dir
	h := tc.b.hotelByID("m1")
	if h == nil || h.lentFrom() != "g2" || h.lentReportID() != launchID(0x11) || h.reservedFor() != "" {
		t.Fatalf("hotel after restart: %+v", h)
	}
	// Same launch after the restart: still no reclaim.
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"reserved_for": "g2"}); status != 409 || errCode(doc) != "reseal_required" {
		t.Fatalf("reclaim after restart: %d %v", status, doc)
	}
	admitNow(t, tc, "m1")
	if a := admissionOf(t, tc, "m1"); a["report_id"] != launchID(0x11) {
		t.Fatalf("admission doc report_id: %v", a)
	}
}
