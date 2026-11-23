package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// reloadRig is a broker loaded from a config file in its own state dir.
type reloadRig struct {
	t    *testing.T
	dir  string
	path string
	b    *broker
}

func reloadHotel(t *testing.T, dir, id string) hotelConfig {
	t.Helper()
	kf := filepath.Join(dir, id+".key")
	if err := os.WriteFile(kf, []byte("hotel-key-"+id), 0o600); err != nil {
		t.Fatal(err)
	}
	return hotelConfig{ID: id, API: "http://127.0.0.1:1", Health: "http://127.0.0.1:1", KeyFile: kf, Sealed: true}
}

func reloadBase(t *testing.T, dir string) config {
	return config{Listen: "127.0.0.1:0", StateDir: filepath.Join(dir, "state"), OperatorKeySHA256: sha("operator-key"),
		SealedMeasurements: []string{strings.Repeat("a", 96)},
		Hotels:             []hotelConfig{reloadHotel(t, dir, "h1")},
		Guests:             []guestConfig{{ID: "g1", KeySHA256: sha("key-1")}}}
}

func newReloadRig(t *testing.T, c config) *reloadRig {
	t.Helper()
	dir := filepath.Dir(c.Hotels[0].KeyFile)
	rg := &reloadRig{t: t, dir: dir, path: filepath.Join(dir, "config.json")}
	rg.write(c)
	b, err := loadBroker(rg.path)
	if err != nil {
		t.Fatal(err)
	}
	rg.b = b
	return rg
}

func (rg *reloadRig) write(c config) string {
	rg.t.Helper()
	raw, _ := json.Marshal(c)
	if err := os.WriteFile(rg.path, raw, 0o600); err != nil {
		rg.t.Fatal(err)
	}
	return sha(string(raw))
}

// reload writes c and POSTs the reload with its sha (or with want, if set).
func (rg *reloadRig) reload(c config, key string) (int, map[string]any) {
	rg.t.Helper()
	sum := rg.write(c)
	return rg.post(sum, key)
}

func (rg *reloadRig) post(sum, key string) (int, map[string]any) {
	rg.t.Helper()
	body, _ := json.Marshal(map[string]string{"sha256": sum})
	r := httptest.NewRequest("POST", "/v1/broker/config/reload", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	rg.b.handler().ServeHTTP(w, r)
	var doc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &doc)
	return w.Code, doc
}

func (rg *reloadRig) stopAdded() {
	for _, h := range rg.b.hotelList() {
		if h.stop != nil {
			h.stop()
		}
	}
}

func rlCode(doc map[string]any) string {
	e, _ := doc["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func rlMsg(doc map[string]any) string {
	e, _ := doc["error"].(map[string]any)
	s, _ := e["message"].(string)
	return s
}

func TestReloadAddsAGuestKeyWithoutRestart(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	if rg.b.guestFromKey(keyedRequest("key-2")) != nil {
		t.Fatal("key-2 reached a guest before the reload")
	}
	g1 := rg.b.guestFromKey(keyedRequest("key-1"))
	c.Guests = append(c.Guests, guestConfig{ID: "g2", KeySHA256: sha("key-2"), guestLimits: guestLimits{MaxRooms: 7}})
	code, doc := rg.reload(c, "operator-key")
	if code != 200 {
		t.Fatalf("reload %d %v", code, doc)
	}
	if got := doc["guests_added"]; len(got.([]any)) != 1 || got.([]any)[0] != "g2" {
		t.Fatalf("guests_added %v", got)
	}
	g2 := rg.b.guestFromKey(keyedRequest("key-2"))
	if g2 == nil || g2.cfg.ID != "g2" || g2.limits.MaxRooms != 7 {
		t.Fatalf("key-2 after reload: %+v", g2)
	}
	if rg.b.guestFromKey(keyedRequest("key-1")) != g1 {
		t.Fatal("g1 is not the same guest after the reload: its counters and pending creates would be lost")
	}
	if rg.b.guestByID("g2") != g2 {
		t.Fatal("g2 not in the guest map")
	}
	if strings.Contains(string(rlJSON(doc)), sha("key-2")) {
		t.Fatal("the answer holds a key hash")
	}
}

func TestReloadRotatesAKeyAndRevokesTheOldOne(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	g1 := rg.b.guestFromKey(keyedRequest("key-1"))
	c.Guests[0].KeySHA256 = sha("key-1b")
	if code, doc := rg.reload(c, "operator-key"); code != 200 || len(doc["guest_keys_changed"].([]any)) != 1 {
		t.Fatalf("reload %d %v", code, doc)
	}
	if rg.b.guestFromKey(keyedRequest("key-1")) != nil {
		t.Fatal("the old key still works after the reload")
	}
	if rg.b.guestFromKey(keyedRequest("key-1b")) != g1 {
		t.Fatal("the new key does not reach the same guest")
	}
}

func TestReloadRefusesWhatNeedsARestartAndAppliesNothing(t *testing.T) {
	cases := map[string]struct {
		edit func(c *config)
		want string
	}{
		"guest removed": {func(c *config) { c.Guests = nil }, "guests[g1] removed"},
		"listen":        {func(c *config) { c.Listen = "127.0.0.1:1" }, "listen"},
		"guest ops":     {func(c *config) { c.Guests[0].Ops = true }, "guests[g1].ops"},
		"guest metered": {func(c *config) { c.Guests[0].Metered = true }, "guests[g1].metered"},
		"hotel api":     {func(c *config) { c.Hotels[0].API = "http://127.0.0.1:2" }, "hotels[h1].api"},
		"hotel removed": {func(c *config) { c.Hotels = nil }, "hotels[h1] removed"},
		"meter key":     {func(c *config) { c.MeterKeySHA256 = sha("meter") }, "meter_key_sha256"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := reloadBase(t, t.TempDir())
			rg := newReloadRig(t, c)
			tc.edit(&c)
			c.Guests = append(c.Guests, guestConfig{ID: "g3", KeySHA256: sha("key-3")})
			code, doc := rg.reload(c, "operator-key")
			if code != 409 || rlCode(doc) != "needs_restart" || !strings.Contains(rlMsg(doc), tc.want) {
				t.Fatalf("got %d %v, want 409 needs_restart naming %q", code, doc, tc.want)
			}
			if rg.b.guestFromKey(keyedRequest("key-3")) != nil || rg.b.guestByID("g3") != nil {
				t.Fatal("a refused reload applied the added guest")
			}
		})
	}
}

func TestReloadChecksTheFileAndItsSHA(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	c.Guests = append(c.Guests, guestConfig{ID: "g2", KeySHA256: sha("key-2")})
	rg.write(c)
	if code, doc := rg.post(sha("something else"), "operator-key"); code != 409 || rlCode(doc) != "config_changed" {
		t.Fatalf("wrong sha: %d %v", code, doc)
	}
	if code, doc := rg.post("nothex", "operator-key"); code != 400 || rlCode(doc) != "invalid_sha256" {
		t.Fatalf("bad sha: %d %v", code, doc)
	}
	bad := c
	bad.Guests = append(append([]guestConfig{}, c.Guests...), guestConfig{ID: "g4", KeySHA256: sha("key-2")}) // shares g2's key
	if code, doc := rg.reload(bad, "operator-key"); code != 400 || rlCode(doc) != "invalid_config" {
		t.Fatalf("shared key: %d %v", code, doc)
	}
	pool := c
	pool.Guests = append(append([]guestConfig{}, c.Guests...), guestConfig{ID: poolGuestID, KeySHA256: sha("key-p")})
	if code, doc := rg.reload(pool, "operator-key"); code != 400 || rlCode(doc) != "invalid_config" {
		t.Fatalf("pool guest id: %d %v", code, doc)
	}
	if rg.b.guestFromKey(keyedRequest("key-2")) != nil {
		t.Fatal("a refused reload applied a guest")
	}
	for _, key := range []string{"key-1", "wrong"} {
		if code, _ := rg.reload(c, key); code == 200 {
			t.Fatalf("key %s could reload", key)
		}
	}
}

// A runtime PATCH of a guest limit (const's, for example) stays through a
// reload that does not change that limit in the file.
func TestReloadKeepsARuntimeLimitPatch(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	r := httptest.NewRequest("PATCH", "/v1/broker/guests/g1", strings.NewReader(`{"max_rooms": 5}`))
	r.Header.Set("Authorization", "Bearer operator-key")
	w := httptest.NewRecorder()
	rg.b.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("patch %d %s", w.Code, w.Body)
	}
	c.Guests = append(c.Guests, guestConfig{ID: "g2", KeySHA256: sha("key-2")})
	if code, doc := rg.reload(c, "operator-key"); code != 200 {
		t.Fatalf("reload %d %v", code, doc)
	}
	g1 := rg.b.guestByID("g1")
	if g1.limits.MaxRooms != 5 {
		t.Fatalf("an unrelated reload reset g1's PATCHed max_rooms to %d", g1.limits.MaxRooms)
	}
	c.Guests[0].MaxCreatesPerMinute = 30
	if code, doc := rg.reload(c, "operator-key"); code != 200 || len(doc["guest_limits_changed"].([]any)) != 1 {
		t.Fatalf("reload %d %v", code, doc)
	}
	if g1.limits.MaxCreatesPerMinute != 30 || g1.limits.MaxRooms != 5 {
		t.Fatalf("limits after the second reload: %+v", g1.limits)
	}
	// The same file again changes nothing.
	if code, doc := rg.reload(c, "operator-key"); code != 200 || len(doc["guests_added"].([]any))+len(doc["guest_limits_changed"].([]any)) != 0 {
		t.Fatalf("a no-op reload: %d %v", code, doc)
	}
}

func TestReloadSwapsMeasurementsAndRefusesARemovedOne(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	m1, m2 := c.SealedMeasurements[0], strings.Repeat("b", 96)
	h := rg.b.hotelByID("h1")
	now := time.Now()
	rg.b.mu.Lock()
	h.adm = admission{attestedAt: now, checkedAt: now, measurement: m1}
	rg.b.mu.Unlock()

	// Adding m2 keeps the pass (only a new check is forced).
	c.SealedMeasurements = []string{m1, m2}
	if code, doc := rg.reload(c, "operator-key"); code != 200 || doc["sealed_measurements_added"] != 1.0 {
		t.Fatalf("add: %d %v", code, doc)
	}
	rg.b.mu.Lock()
	kept, due := !h.adm.attestedAt.IsZero(), h.adm.checkedAt.IsZero()
	rg.b.mu.Unlock()
	if !kept || !due {
		t.Fatalf("after adding a measurement: pass kept %v, check due %v; want both", kept, due)
	}
	if got := rg.b.sealedMeasurements(); len(got) != 2 {
		t.Fatalf("live list %v", got)
	}

	// Removing m1 refuses h1 at once.
	c.SealedMeasurements = []string{m2}
	if code, doc := rg.reload(c, "operator-key"); code != 200 || doc["sealed_measurements_removed"] != 1.0 {
		t.Fatalf("remove: %d %v", code, doc)
	}
	rg.b.mu.Lock()
	admitted, reason := rg.b.admitted(h, time.Now()), h.adm.reason
	rg.b.mu.Unlock()
	if admitted || !strings.Contains(reason, "no longer in sealed_measurements") {
		t.Fatalf("h1 after its measurement left: admitted %v, reason %q", admitted, reason)
	}
}

// A check that read the old lists is dropped when a reload swaps them.
func TestCheckFromBeforeAReloadIsDropped(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	h := rg.b.hotelByID("h1")
	gen := rg.b.admGen.Load()
	c.SealedMeasurements = []string{strings.Repeat("b", 96)}
	if code, doc := rg.reload(c, "operator-key"); code != 200 {
		t.Fatalf("reload %d %v", code, doc)
	}
	if rg.b.admGen.Load() == gen {
		t.Fatal("the admission generation did not move")
	}
	_ = h
}

func TestReloadAddsAHotelOnce(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	t.Cleanup(rg.stopAdded)
	c.Hotels = append(c.Hotels, reloadHotel(t, rg.dir, "h2"))
	code, doc := rg.reload(c, "operator-key")
	if code != 200 || len(doc["hotels_added"].([]any)) != 1 {
		t.Fatalf("reload %d %v", code, doc)
	}
	h2 := rg.b.hotelByID("h2")
	if h2 == nil || h2.runtime || !h2.roomsUnchecked || h2.stop == nil {
		t.Fatalf("h2 after reload: %+v", h2)
	}
	rg.b.mu.Lock()
	state := rg.b.admissionState(h2, time.Now())
	rg.b.mu.Unlock()
	if state == "admitted" {
		t.Fatal("a reloaded hotel is admitted before any attestation check")
	}
	if code, doc := rg.reload(c, "operator-key"); code != 200 || len(doc["hotels_added"].([]any)) != 0 {
		t.Fatalf("second reload %d %v", code, doc)
	}
	// An id a runtime hotel already has is refused, and nothing applies.
	rh := newHotel(reloadHotel(t, rg.dir, "joined"), "k")
	rh.runtime = true
	if err := rg.b.addHotel(rh); err != nil {
		t.Fatal(err)
	}
	c.Hotels = append(c.Hotels, reloadHotel(t, rg.dir, "joined"))
	c.Guests = append(c.Guests, guestConfig{ID: "g5", KeySHA256: sha("key-5")})
	if code, doc := rg.reload(c, "operator-key"); code != 409 || rlCode(doc) != "hotel_exists" {
		t.Fatalf("collision %d %v", code, doc)
	}
	if rg.b.guestByID("g5") != nil {
		t.Fatal("a refused reload applied a guest")
	}
}

func patchDrain(t *testing.T, b *broker, id string, drain bool) {
	t.Helper()
	body := `{"drain": false}`
	if drain {
		body = `{"drain": true}`
	}
	r := httptest.NewRequest("PATCH", "/v1/broker/hotels/"+id, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer operator-key")
	w := httptest.NewRecorder()
	b.handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("patch drain %d %s", w.Code, w.Body)
	}
}

func TestConfigHotelDrainSurvivesARestart(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	patchDrain(t, rg.b, "h1", true)
	b2, err := loadBroker(rg.path)
	if err != nil {
		t.Fatal(err)
	}
	if !b2.hotelByID("h1").drain() {
		t.Fatal("the PATCHed drain was lost at restart")
	}
	// Undrain, restart: open.
	patchDrain(t, b2, "h1", false)
	b3, err := loadBroker(rg.path)
	if err != nil {
		t.Fatal(err)
	}
	if b3.hotelByID("h1").drain() {
		t.Fatal("an undrain was lost at restart")
	}
}

func TestConfigFileDrainChangeWinsOverASavedPatch(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	patchDrain(t, rg.b, "h1", true) // saved with config_drain false
	// Someone sets drain true in the file, then false again: the file's
	// latest word wins, so the hotel is open.
	c.Hotels[0].Drain = true
	rg.write(c)
	b2, err := loadBroker(rg.path)
	if err != nil {
		t.Fatal(err)
	}
	if !b2.hotelByID("h1").drain() {
		t.Fatal("file drain true not applied")
	}
	c.Hotels[0].Drain = false
	rg.write(c)
	b3, err := loadBroker(rg.path)
	if err != nil {
		t.Fatal(err)
	}
	if b3.hotelByID("h1").drain() {
		t.Fatal("the old PATCH record came back after the file changed")
	}
}

func TestReloadAppliesOnlyAFileDrainChange(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	patchDrain(t, rg.b, "h1", true)
	// An unrelated reload keeps the PATCHed drain (the file still says false).
	c.Guests = append(c.Guests, guestConfig{ID: "g2", KeySHA256: sha("key-2")})
	if code, doc := rg.reload(c, "operator-key"); code != 200 || len(doc["hotels_drain_changed"].([]any)) != 0 {
		t.Fatalf("reload %d %v", code, doc)
	}
	if !rg.b.hotelByID("h1").drain() {
		t.Fatal("an unrelated reload reopened a drained hotel")
	}
	// The file sets drain true: no visible change, record dropped; then
	// false: the hotel opens.
	c.Hotels[0].Drain = true
	if code, doc := rg.reload(c, "operator-key"); code != 200 || len(doc["hotels_drain_changed"].([]any)) != 1 {
		t.Fatalf("reload %d %v", code, doc)
	}
	c.Hotels[0].Drain = false
	if code, _ := rg.reload(c, "operator-key"); code != 200 || rg.b.hotelByID("h1").drain() {
		t.Fatal("file drain false did not open the hotel")
	}
}

func TestCheckConfigHasNoSideEffect(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	dir := filepath.Dir(c.Hotels[0].KeyFile)
	path := filepath.Join(dir, "config.json")
	raw, _ := json.Marshal(c)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkConfigFile(path); err != nil {
		t.Fatalf("good config: %v", err)
	}
	if _, err := os.Stat(c.StateDir); !os.IsNotExist(err) {
		t.Fatalf("check-config touched state_dir: %v", err)
	}
	c.Guests = append(c.Guests, guestConfig{ID: "g1"})
	raw, _ = json.Marshal(c)
	_ = os.WriteFile(path, raw, 0o600)
	if err := checkConfigFile(path); err == nil {
		t.Fatal("a duplicate guest passed check-config")
	}
}

// Key lookups, guest map reads (sign-in, the live view) and reloads at once.
// Run with -race.
func TestReloadRacesKeyLookupsAndSignIn(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = rg.b.guestFromKey(keyedRequest("key-1"))
				r := httptest.NewRequest("POST", "/g1/live/sign-in", strings.NewReader("token=x"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				rg.b.handler().ServeHTTP(httptest.NewRecorder(), r)
				_ = rg.b.sealedMeasurements()
			}
		}()
	}
	for i := 0; i < 30; i++ {
		c.Guests = append(c.Guests, guestConfig{ID: "r" + string(rune('a'+i)), KeySHA256: sha("rk" + string(rune('a'+i)))})
		if code, doc := rg.reload(c, "operator-key"); code != 200 {
			t.Fatalf("reload %d: %d %v", i, code, doc)
		}
	}
	close(stop)
	wg.Wait()
	if rg.b.guestFromKey(keyedRequest("rk"+string(rune('a'+29)))) == nil {
		t.Fatal("last added guest missing")
	}
}

func rlJSON(v any) []byte { raw, _ := json.Marshal(v); return raw }

// A reload and -check-config refuse the allowance rules a start refuses, so a
// reload cannot install a guest the next restart would stop on (#685 review).
func TestReloadRefusesAGuestAStartWouldRefuse(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	both := c
	both.Guests = append(append([]guestConfig{}, c.Guests...), guestConfig{ID: "g6", KeySHA256: sha("key-6"), guestLimits: guestLimits{Metered: true, Postpaid: true}})
	if code, doc := rg.reload(both, "operator-key"); code != 400 || rlCode(doc) != "invalid_config" || !strings.Contains(rlMsg(doc), "metered and postpaid") {
		t.Fatalf("metered and postpaid: %d %v", code, doc)
	}
	if err := checkConfigFile(rg.path); err == nil {
		t.Fatal("-check-config passed a metered and postpaid guest")
	}
	if rg.b.guestByID("g6") != nil {
		t.Fatal("a refused reload applied a guest")
	}
	noState := c
	noState.StateDir = ""
	noState.Guests = append(append([]guestConfig{}, c.Guests...), guestConfig{ID: "g7", KeySHA256: sha("key-7"), guestLimits: guestLimits{Metered: true}})
	raw, _ := json.Marshal(noState)
	_ = os.WriteFile(rg.path, raw, 0o600)
	if err := checkConfigFile(rg.path); err == nil || !strings.Contains(err.Error(), "needs state_dir") {
		t.Fatalf("-check-config on a metered guest with no state_dir: %v", err)
	}
}

// A hotel added by a reload stops with the sync loops main cancels at SIGTERM.
func TestReloadedHotelStopsWithTheLoops(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	ctx, stopLoops := context.WithCancel(context.Background())
	defer stopLoops()
	rg.b.loopsCtx.Store(&ctx)
	c.Hotels = append(c.Hotels, reloadHotel(t, rg.dir, "h2"))
	if code, doc := rg.reload(c, "operator-key"); code != 200 {
		t.Fatalf("reload %d %v", code, doc)
	}
	h2 := rg.b.hotelByID("h2")
	stopLoops()
	select {
	case <-h2.syncDone:
	case <-time.After(5 * time.Second):
		t.Fatal("a reloaded hotel's sync loop ran on after the loops were cancelled")
	}
}

// A drains file that does not parse is kept aside before a PATCH can
// overwrite it, and the broker still starts (#685 review).
func TestCorruptDrainsFileIsKeptAside(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	patchDrain(t, rg.b, "h1", true)
	path := filepath.Join(c.StateDir, drainsFile)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	b2, err := loadBroker(rg.path)
	if err != nil {
		t.Fatalf("a corrupt drains file stopped the start: %v", err)
	}
	aside, _ := filepath.Glob(path + ".corrupt-*")
	if len(aside) != 1 {
		t.Fatalf("corrupt drains file not kept aside: %v", aside)
	}
	if raw, _ := os.ReadFile(aside[0]); string(raw) != "{not json" {
		t.Fatalf("kept aside %q", raw)
	}
	patchDrain(t, b2, "h1", true)
	if raw, _ := os.ReadFile(aside[0]); string(raw) != "{not json" {
		t.Fatal("a PATCH overwrote the kept copy")
	}
}
