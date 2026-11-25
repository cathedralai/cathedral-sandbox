package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Reservations survive a restart and are fenced by reservation_generation
// (reservations.go, AB#982). Hotels as in newChainState: "a", "b" and "c"
// from the config file, guests g1 and g2, a state_dir.

func patchHotelDoc(t *testing.T, tc *testChain, id string, body map[string]any) (int, map[string]any) {
	t.Helper()
	return tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/"+id, body)
}

func getHotelDoc(t *testing.T, tc *testChain, id string) map[string]any {
	t.Helper()
	status, doc := tc.call(t, "operator-key", "GET", "/v1/broker/hotels/"+id, nil)
	if status != 200 {
		t.Fatalf("GET hotel %s: %d %v", id, status, doc)
	}
	return doc
}

// wantReservation checks the hotel doc's reserved_for, reservation_ref and
// reservation_generation (JSON numbers decode as float64).
func wantReservation(t *testing.T, doc map[string]any, owner, ref any, gen float64) {
	t.Helper()
	if doc["reserved_for"] != owner || doc["reservation_ref"] != ref || doc["reservation_generation"] != gen {
		t.Fatalf("want reserved_for %v ref %v generation %v; doc reserved_for %v ref %v generation %v",
			owner, ref, gen, doc["reserved_for"], doc["reservation_ref"], doc["reservation_generation"])
	}
}

func TestConfigHotelReservationSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	wantReservation(t, getHotelDoc(t, tc, "a"), nil, nil, 0)
	status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "order-1", "expect_generation": 0})
	if status != 200 {
		t.Fatalf("reserve: %d %v", status, doc)
	}
	wantReservation(t, doc, "g2", "order-1", 1)
	// The reply was lost: a read-back shows the reservation and its ref.
	wantReservation(t, getHotelDoc(t, tc, "a"), "g2", "order-1", 1)
	raw, err := os.ReadFile(filepath.Join(dir, reservationsFile))
	if err != nil || !strings.Contains(string(raw), `"order-1"`) || !strings.Contains(string(raw), `"config_reserved_for": ""`) {
		t.Fatalf("%s: %s %v", reservationsFile, raw, err)
	}

	tc.start(t) // restart: same config, same state_dir
	wantReservation(t, getHotelDoc(t, tc, "a"), "g2", "order-1", 1)
	if r := tc.b.hotelByID("a").reservedFor(); r != "g2" {
		t.Fatalf("reserved_for after restart: %q", r)
	}

	// A null release bumps the generation, clears the ref and persists.
	status, doc = patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": nil, "expect_generation": 1})
	if status != 200 {
		t.Fatalf("release: %d %v", status, doc)
	}
	wantReservation(t, doc, nil, nil, 2)
	tc.start(t)
	wantReservation(t, getHotelDoc(t, tc, "a"), nil, nil, 2)

	// An unchanged write is no change: no bump.
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": nil}); status != 200 || doc["reservation_generation"] != float64(2) {
		t.Fatalf("same release again: %d %v", status, doc)
	}
}

func TestConfigFileReservedForChangeWinsOverASavedPatch(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "order-1"}); status != 200 {
		t.Fatalf("reserve: %d %v", status, doc) // saved with config_reserved_for ""
	}
	// Someone reserves "a" for g1 in the file: the file wins, the ref goes,
	// and the generation goes on from the saved one.
	editConfig(t, tc, func(c *config) { c.Hotels[0].ReservedFor = "g1" })
	wantReservation(t, getHotelDoc(t, tc, "a"), "g1", nil, 2)
	// The file goes back to "": the old PATCH does not come back.
	editConfig(t, tc, func(c *config) { c.Hotels[0].ReservedFor = "" })
	wantReservation(t, getHotelDoc(t, tc, "a"), nil, nil, 3)
	// A restart on the same file changes nothing more.
	tc.start(t)
	wantReservation(t, getHotelDoc(t, tc, "a"), nil, nil, 3)

	// The config file cannot set the fields PATCH owns.
	raw, _ := os.ReadFile(tc.cfgPath)
	var c config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	c.Hotels[0].ReservationRef = "x"
	raw, _ = json.Marshal(c)
	if err := os.WriteFile(tc.cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBroker(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "reservation_ref") {
		t.Fatalf("config file set reservation_ref: %v", err)
	}
	if err := checkConfigFile(tc.cfgPath); err == nil || !strings.Contains(err.Error(), "reservation_ref") {
		t.Fatalf("-check-config passed reservation_ref: %v", err)
	}
}

func TestReservationGenerationMismatchChangesNothing(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	if status, _ := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "order-1"}); status != 200 {
		t.Fatal("reserve")
	}
	before, _ := os.ReadFile(filepath.Join(dir, reservationsFile))
	for _, body := range []map[string]any{
		{"reserved_for": "g1", "reservation_ref": "order-2", "expect_generation": 0},
		{"reserved_for": nil, "expect_generation": 7},
		{"drain": true, "expect_generation": 0}, // any field: the whole PATCH is fenced
	} {
		status, doc := patchHotelDoc(t, tc, "a", body)
		if status != 409 || errCode(doc) != "reservation_conflict" {
			t.Fatalf("%v: %d %v", body, status, doc)
		}
	}
	doc := getHotelDoc(t, tc, "a")
	wantReservation(t, doc, "g2", "order-1", 1)
	if doc["drain"] != false {
		t.Fatalf("a refused PATCH drained the hotel: %v", doc)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, reservationsFile)); string(after) != string(before) {
		t.Fatalf("a refused PATCH rewrote %s: %s", reservationsFile, after)
	}
	// reservation_ref needs reserved_for.
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reservation_ref": "order-3"}); status != 400 {
		t.Fatalf("ref without reserved_for: %d %v", status, doc)
	}
	if status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": strings.Repeat("x", maxReservationRef+1)}); status != 400 {
		t.Fatalf("long ref: %d %v", status, doc)
	}
	wantReservation(t, getHotelDoc(t, tc, "a"), "g2", "order-1", 1)
}

// Two orders race for the last box with the generation both read: one wins.
func TestConcurrentReservationsWithOneGenerationOneWins(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner := []string{"g1", "g2"}[i%2]
			codes[i], _ = patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": owner, "reservation_ref": "order-" + string(rune('a'+i)), "expect_generation": 0})
		}()
	}
	wg.Wait()
	won := -1
	for i, c := range codes {
		switch c {
		case 200:
			if won >= 0 {
				t.Fatalf("two PATCHes won: %v", codes)
			}
			won = i
		case 409:
		default:
			t.Fatalf("unexpected status: %v", codes)
		}
	}
	if won < 0 {
		t.Fatalf("no PATCH won: %v", codes)
	}
	wantReservation(t, getHotelDoc(t, tc, "a"), []string{"g1", "g2"}[won%2], "order-"+string(rune('a'+won)), 1)
}

func TestReservationThatCannotBeSavedChangesNothing(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	old := durableSync
	durableSync = func(f *os.File) error { return os.ErrPermission }
	t.Cleanup(func() { durableSync = old })
	status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "order-1", "expect_generation": 0})
	durableSync = old
	if status != 500 || errCode(doc) != "state_write_failed" {
		t.Fatalf("PATCH with a failing save: %d %v", status, doc)
	}
	wantReservation(t, getHotelDoc(t, tc, "a"), nil, nil, 0)
	if _, err := os.Stat(filepath.Join(dir, reservationsFile)); !os.IsNotExist(err) {
		t.Fatalf("%s left behind: %v", reservationsFile, err)
	}
	tc.start(t)
	wantReservation(t, getHotelDoc(t, tc, "a"), nil, nil, 0)
}

func TestJoinedHotelReservationSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	joinOperatorSealed(t, tc, "j1", 10)
	wantReservation(t, getHotelDoc(t, tc, "j1"), nil, nil, 0)
	if status, doc := patchHotelDoc(t, tc, "j1", map[string]any{"reserved_for": "g2", "reservation_ref": "order-9", "expect_generation": 0}); status != 200 {
		t.Fatalf("reserve: %d %v", status, doc)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, runtimeHotelsFile))
	if !strings.Contains(string(raw), `"reservation_ref": "order-9"`) || !strings.Contains(string(raw), `"reservation_generation": 1`) {
		t.Fatalf("hotels.json: %s", raw)
	}
	if _, err := os.Stat(filepath.Join(dir, reservationsFile)); !os.IsNotExist(err) {
		t.Fatalf("a joined hotel wrote %s: %v", reservationsFile, err)
	}
	tc.start(t)
	wantReservation(t, getHotelDoc(t, tc, "j1"), "g2", "order-9", 1)
	if status, doc := patchHotelDoc(t, tc, "j1", map[string]any{"reserved_for": nil, "expect_generation": 0}); status != 409 || errCode(doc) != "reservation_conflict" {
		t.Fatalf("stale release: %d %v", status, doc)
	}
	if status, doc := patchHotelDoc(t, tc, "j1", map[string]any{"reserved_for": nil, "expect_generation": 1}); status != 200 {
		t.Fatalf("release: %d %v", status, doc)
	}
	tc.start(t)
	wantReservation(t, getHotelDoc(t, tc, "j1"), nil, nil, 2)
}

// Lend and reclaim keep working; each changes reserved_for, so each bumps
// the generation, and a config file hotel keeps it across a restart.
func TestLendAndReclaimBumpTheGeneration(t *testing.T) {
	dir := t.TempDir()
	tc := configReserved(t, dir) // "a" reserved for g2 in the file
	listSync(tc, "a")
	setLaunch(t, tc, "a", 0x11)
	wantReservation(t, getHotelDoc(t, tc, "a"), "g2", nil, 0)
	if doc := lend(t, tc, "a"); doc["lent_from"] != "g2" {
		t.Fatalf("lend: %v", doc)
	}
	wantReservation(t, getHotelDoc(t, tc, "a"), nil, nil, 1)
	tc.start(t)
	if doc := getHotelDoc(t, tc, "a"); doc["lent_from"] != "g2" {
		t.Fatalf("lent hotel after restart: %v", doc)
	}
	wantReservation(t, getHotelDoc(t, tc, "a"), nil, nil, 1)
	setLaunch(t, tc, "a", 0x22)
	status, doc := patchHotelDoc(t, tc, "a", map[string]any{"reserved_for": "g2", "reservation_ref": "order-5", "expect_generation": 1})
	if status != 200 || doc["lent_from"] != nil {
		t.Fatalf("reclaim: %d %v", status, doc)
	}
	wantReservation(t, doc, "g2", "order-5", 2)
	tc.start(t)
	wantReservation(t, getHotelDoc(t, tc, "a"), "g2", "order-5", 2)
}

// A config file hotel that leaves the file and comes back by a reload keeps
// its saved reservation while the file says what it said then.
func TestReloadAddedHotelKeepsItsSavedReservation(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	h2 := reloadHotel(t, filepath.Dir(c.Hotels[0].KeyFile), "h2")
	c.Hotels = append(c.Hotels, h2)
	rg := newReloadRig(t, c)
	r := httptest.NewRequest("PATCH", "/v1/broker/hotels/h2", strings.NewReader(`{"reserved_for": "g1", "reservation_ref": "order-1", "expect_generation": 0}`))
	r.Header.Set("Authorization", "Bearer operator-key")
	w := httptest.NewRecorder()
	rg.b.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("reserve h2: %d %s", w.Code, w.Body)
	}
	// h2 leaves the file (a restart), then a reload adds it back.
	c.Hotels = c.Hotels[:1]
	rg.write(c)
	b2, err := loadBroker(rg.path)
	if err != nil {
		t.Fatal(err)
	}
	rg.b = b2
	c.Hotels = append(c.Hotels, h2)
	if code, doc := rg.reload(c, "operator-key"); code != 200 {
		t.Fatalf("reload: %d %v", code, doc)
	}
	defer rg.stopAdded()
	gen, ref := rg.b.hotelByID("h2").reservation()
	if rf := rg.b.hotelByID("h2").reservedFor(); rf != "g1" || ref != "order-1" || gen != 1 {
		t.Fatalf("reloaded h2: reserved_for %q ref %q generation %d", rf, ref, gen)
	}
}
