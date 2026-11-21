package main

// Tests of the ready-room settings: config, pool guest, route and state file
// (AB#894, phase 2 work order PR 2).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// settingsChain is a broker with ready_rooms that runs no loop.
type settingsChain struct {
	t        *testing.T
	b        *broker
	srv      *httptest.Server
	cfgPath  string
	stateDir string
}

func newSettingsChain(t *testing.T) *settingsChain { return newSettingsChainWith(t, nil) }

func newSettingsChainWith(t *testing.T, mutate func(c *config)) *settingsChain {
	t.Helper()
	dir := t.TempDir()
	key := filepath.Join(dir, "hotel.key")
	if err := os.WriteFile(key, []byte("hotel-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc := &settingsChain{t: t, stateDir: filepath.Join(dir, "state"), cfgPath: filepath.Join(dir, "config.json")}
	cfg := config{StateDir: sc.stateDir, OperatorKeySHA256: sha("operator-key"), InsecureCookie: true,
		Guests:     []guestConfig{{ID: "g1", KeySHA256: sha("key1")}},
		Hotels:     []hotelConfig{{ID: "a", API: "http://127.0.0.1:1", Health: "http://127.0.0.1:1", KeyFile: key, Sealed: true}},
		ReadyRooms: &readyRoomsConfig{Guest: poolGuestID, Keys: []readyRoomKeyEntry{{Template: "node-22"}}}}
	if mutate != nil {
		mutate(&cfg)
	}
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(sc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sc.start()
	return sc
}

// start (or restart) the broker over the same config and state_dir.
func (sc *settingsChain) start() {
	sc.t.Helper()
	if sc.srv != nil {
		sc.srv.Close()
		sc.b.pool.close()
	}
	b, err := loadBroker(sc.cfgPath)
	if err != nil {
		sc.t.Fatal(err)
	}
	sc.b = b
	sc.srv = httptest.NewServer(b)
	sc.t.Cleanup(sc.srv.Close)
	sc.t.Cleanup(b.pool.close)
}

// The settings route needs the operator key, validates, writes
// ready-rooms.json before it applies, and a restart reads it back. A file
// that does not parse is kept aside and every target is 0.
func TestReadyRoomsRouteStoresTargets(t *testing.T) {
	pc := newSettingsChain(t)
	req := func(key, method string, body string) int {
		r, _ := http.NewRequest(method, pc.srv.URL+"/v1/broker/ready-rooms", strings.NewReader(body))
		if key != "" {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	good := `{"per_hotel": {"node-22": 7}, "refill_per_second": 4, "refill_during_claims": 1, "reserve_share": 0.25}`
	if st := req("", "PUT", good); st != 401 {
		t.Fatalf("no key: %d", st)
	}
	if st := req("key1", "GET", ""); st != 401 {
		t.Fatalf("guest key: %d", st)
	}
	for _, bad := range []string{
		`{"per_hotel": {"room-1x4": 1}, "refill_per_second": 4, "refill_during_claims": 1, "reserve_share": 0.25}`,
		`{"per_hotel": {"node-22": -1}, "refill_per_second": 4, "refill_during_claims": 1, "reserve_share": 0.25}`,
		`{"per_hotel": {"node-22": 1}, "refill_per_second": 4, "refill_during_claims": 5, "reserve_share": 0.25}`,
		`{"per_hotel": {"node-22": 1}, "refill_per_second": 4, "refill_during_claims": 1, "reserve_share": 1}`,
		`{"per_hotel": {"node-22": 1}, "refill_per_second": 4, "refill_during_claims": 1}`,
		`{"per_hotel": {"node-22": 1}, "refill_per_second": 4, "refill_during_claims": 1, "reserve_share": 0.25, "extra": 1}`,
	} {
		if st := req("operator-key", "PUT", bad); st != 400 {
			t.Fatalf("PUT %s: %d, want 400", bad, st)
		}
	}
	if st := req("operator-key", "PUT", good); st != 200 {
		t.Fatalf("good PUT: %d", st)
	}
	raw, err := os.ReadFile(filepath.Join(pc.stateDir, readyRoomsFile))
	if err != nil || !strings.Contains(string(raw), `"node-22": 7`) {
		t.Fatalf("ready-rooms.json %s %v", raw, err)
	}
	if fi, _ := os.Stat(filepath.Join(pc.stateDir, readyRoomsFile)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	pc.start()
	pc.b.mu.Lock()
	got := pc.b.pool.settings.target("node-22")
	maxRooms := pc.b.guests[poolGuestID].limits.MaxRooms
	pc.b.mu.Unlock()
	if got != 7 || maxRooms < 7 {
		t.Fatalf("after restart: target %d, pool guest max_rooms %d", got, maxRooms)
	}
	// A failed write changes nothing in memory.
	old := poolSyncFile
	poolSyncFile = func(*os.File) error { return os.ErrPermission }
	st := req("operator-key", "PUT", strings.Replace(good, "7", "9", 1))
	poolSyncFile = old
	pc.b.mu.Lock()
	got = pc.b.pool.settings.target("node-22")
	pc.b.mu.Unlock()
	if st != 500 || got != 7 {
		t.Fatalf("failed write: %d, target %d; want 500 and 7", st, got)
	}
	if err := os.WriteFile(filepath.Join(pc.stateDir, readyRoomsFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	pc.start()
	pc.b.mu.Lock()
	got = pc.b.pool.settings.target("node-22")
	pc.b.mu.Unlock()
	aside, _ := filepath.Glob(filepath.Join(pc.stateDir, readyRoomsFile+".corrupt-*"))
	if got != 0 || len(aside) != 1 {
		t.Fatalf("corrupt file: target %d, %d kept aside", got, len(aside))
	}
}

// The ready_rooms config is checked at load; the pool guest id is reserved.
func TestReadyRoomsConfigRefusals(t *testing.T) {
	load := func(mutate func(c *config)) error {
		dir := t.TempDir()
		key := filepath.Join(dir, "k")
		_ = os.WriteFile(key, []byte("hotel-key"), 0o600)
		c := config{Listen: "127.0.0.1:1", StateDir: filepath.Join(dir, "state"),
			Hotels:     []hotelConfig{{ID: "a", API: "http://127.0.0.1:2", Health: "http://127.0.0.1:2", KeyFile: key, Sealed: true}},
			ReadyRooms: &readyRoomsConfig{Guest: poolGuestID, Keys: []readyRoomKeyEntry{{Template: "node-22"}}}}
		mutate(&c)
		raw, _ := json.Marshal(c)
		p := filepath.Join(dir, "config.json")
		_ = os.WriteFile(p, raw, 0o600)
		b, err := loadBroker(p)
		if b != nil {
			b.pool.close()
		}
		return err
	}
	if err := load(func(c *config) {}); err != nil {
		t.Fatalf("good config refused: %v", err)
	}
	for name, mutate := range map[string]func(c *config){
		"reserved guest id":       func(c *config) { c.Guests = []guestConfig{{ID: poolGuestID, KeySHA256: sha("k")}} },
		"reserved id without":     func(c *config) { c.ReadyRooms = nil; c.Guests = []guestConfig{{ID: poolGuestID}} },
		"another guest":           func(c *config) { c.ReadyRooms.Guest = "g1" },
		"no state_dir":            func(c *config) { c.StateDir = "" },
		"no key":                  func(c *config) { c.ReadyRooms.Keys = nil },
		"unknown template":        func(c *config) { c.ReadyRooms.Keys = []readyRoomKeyEntry{{Template: "nope"}} },
		"template not pinned":     func(c *config) { c.ReadyRooms.Keys = []readyRoomKeyEntry{{Template: "room-1x4"}} },
		"key twice":               func(c *config) { c.ReadyRooms.Keys = append(c.ReadyRooms.Keys, c.ReadyRooms.Keys[0]) },
		"rig flag without pool":   func(c *config) { c.ReadyRooms = nil; c.ReadyRoomsUnsealedForTests = true },
		"rig flag, public listen": func(c *config) { c.ReadyRoomsUnsealedForTests = true; c.Listen = "0.0.0.0:1" },
		"rig flag, remote hotel": func(c *config) {
			c.ReadyRoomsUnsealedForTests = true
			c.Hotels[0].API = "http://10.0.0.1:2"
		},
	} {
		if err := load(mutate); err == nil {
			t.Fatalf("%s: loaded, want refused", name)
		}
	}
	if err := load(func(c *config) { c.ReadyRoomsUnsealedForTests = true }); err != nil {
		t.Fatalf("rig flag on loopback refused: %v", err)
	}
}

// Without ready_rooms nothing of the pool exists: no route, no journal.
func TestReadyRoomsOffChangesNothing(t *testing.T) {
	state := t.TempDir()
	tc := newChainState(t, state)
	st, doc := tc.call(t, "operator-key", "GET", "/v1/broker/ready-rooms", nil)
	if st != 404 || errCode(doc) != "ready_rooms_off" {
		t.Fatalf("GET without ready_rooms: %d %v", st, doc)
	}
	if tc.b.pool != nil || tc.b.guests[poolGuestID] != nil {
		t.Fatal("pool state without ready_rooms")
	}
	for _, name := range []string{claimJournalIDName, claimJournalDirName, readyRoomsFile} {
		if _, err := os.Stat(filepath.Join(state, name)); err == nil {
			t.Fatalf("%s exists without ready_rooms", name)
		}
	}
}

// The meter-key routes answer for the reserved pool guest as for an unknown
// guest: an external meter never lists or freezes pool rooms.
func TestMeterRoutesRefuseThePoolGuest(t *testing.T) {
	sc := newSettingsChainWith(t, func(c *config) { c.MeterKeySHA256 = sha("meter-key") })
	call := func(method, path string) (int, string) {
		r, _ := http.NewRequest(method, sc.srv.URL+path, nil)
		r.Header.Set("Authorization", "Bearer meter-key")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var doc map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&doc)
		return resp.StatusCode, errCode(doc)
	}
	for _, action := range []struct{ method, path string }{{"GET", "rooms"}, {"POST", "freeze-all"}} {
		pst, pcode := call(action.method, "/v1/broker/guests/"+poolGuestID+"/"+action.path)
		ust, ucode := call(action.method, "/v1/broker/guests/no-such-guest/"+action.path)
		if pst != 404 || pst != ust || pcode != ucode {
			t.Fatalf("%s %s for the pool guest: %d %q; for an unknown guest: %d %q", action.method, action.path, pst, pcode, ust, ucode)
		}
	}
	if st, _ := call("GET", "/v1/broker/guests/g1/rooms"); st != 200 {
		t.Fatalf("meter rooms of a configured guest: %d, want 200", st)
	}
}
