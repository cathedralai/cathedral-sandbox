package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func restartCheckCall(t *testing.T, b *broker, id, key string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest("GET", "/v1/broker/hotels/"+id+"/restart-check", nil)
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	b.handler().ServeHTTP(w, r)
	var doc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &doc)
	return w.Code, doc
}

func restartMsg(doc map[string]any) string {
	e, _ := doc["error"].(map[string]any)
	if e == nil || e["code"] != "restart_refused" {
		return ""
	}
	m, _ := e["message"].(string)
	return m
}

// A restart goes only on a drained hotel with a known count of 0 rooms,
// creates (queued, in flight, pool) and pool claims (AB#875).
func TestRestartCheckNeedsDrainAndZeroRooms(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	b := rg.b
	h := b.hotelByID("h1")
	set := func(f func()) { b.mu.Lock(); f(); b.mu.Unlock() }
	set(func() { h.roomsUnchecked, h.listOK = false, true })

	if code, doc := restartCheckCall(t, b, "h1", "operator-key"); code != 409 || !strings.Contains(restartMsg(doc), "not drained") {
		t.Fatalf("undrained hotel: %d %v", code, doc)
	}
	patchDrain(t, b, "h1", true)
	if code, doc := restartCheckCall(t, b, "h1", "operator-key"); code != 200 || doc["restart_ok"] != true {
		t.Fatalf("drained empty hotel: %d %v", code, doc)
	}

	for _, tc := range []struct {
		name string
		on   func()
		off  func()
		want string
	}{
		{"room", func() { h.rooms["r1"] = &room{} }, func() { delete(h.rooms, "r1") }, "1 room(s) on the hotel"},
		{"creating", func() { h.creating = 1 }, func() { h.creating = 0 }, "1 create(s) in flight"},
		{"queued", func() { h.queued = 2 }, func() { h.queued = 0 }, "2 create(s) queued"},
		{"pool claim", func() { b.pool.hotel("h1").claims = 1 }, func() { b.pool.hotel("h1").claims = 0 }, "1 pool claim(s) in flight"},
		{"unreaped", func() { h.unreaped = map[string]*unreapedBatch{"x": {}} }, func() { h.unreaped = nil }, "1 unreaped"},
		{"hotel count", func() { h.apiRunning = 1 }, func() { h.apiRunning = 0 }, "1 room(s) running by the hotel's own count"},
		{"list failed", func() { h.listOK = false }, func() { h.listOK = true }, "room count is not known"},
		{"never listed", func() { h.roomsUnchecked = true }, func() { h.roomsUnchecked = false }, "room count is not known"},
	} {
		if tc.name == "pool claim" && b.pool == nil {
			b.pool = &readyRooms{hotels: map[string]*poolHotel{}}
		}
		set(tc.on)
		code, doc := restartCheckCall(t, b, "h1", "operator-key")
		set(tc.off)
		if code != 409 || !strings.Contains(restartMsg(doc), tc.want) {
			t.Fatalf("%s: %d %v", tc.name, code, doc)
		}
	}
	if code, _ := restartCheckCall(t, b, "h1", "operator-key"); code != 200 {
		t.Fatalf("back to empty: %d", code)
	}
	if code, _ := restartCheckCall(t, b, "nope", "operator-key"); code != 404 {
		t.Fatalf("unknown hotel: %d", code)
	}
	if code, _ := restartCheckCall(t, b, "h1", "key-1"); code != 401 {
		t.Fatalf("guest key: %d", code)
	}
}

// An operator undrain of a hotel the config file drains is not undone by the
// next restart or an unrelated reload while the file still says drain
// (AB#875).
func TestOperatorUndrainOutlivesConfigDrain(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	c.Hotels[0].Drain = true
	rg := newReloadRig(t, c)
	if !rg.b.hotelByID("h1").drain() {
		t.Fatal("config drain not applied")
	}
	patchDrain(t, rg.b, "h1", false)
	c.Guests = append(c.Guests, guestConfig{ID: "g2", KeySHA256: sha("key-2")})
	if code, _ := rg.reload(c, "operator-key"); code != 200 || rg.b.hotelByID("h1").drain() {
		t.Fatal("an unrelated reload undid the operator undrain")
	}
	b2, err := loadBroker(rg.path)
	if err != nil {
		t.Fatal(err)
	}
	if b2.hotelByID("h1").drain() {
		t.Fatal("a restart undid the operator undrain")
	}
}

// The drains file and hotels.json are fsynced, file and directory, before
// the PATCH answers (AB#875).
func TestDrainSavesAreSynced(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	var synced []string
	old := durableSync
	durableSync = func(f *os.File) error { synced = append(synced, filepath.Base(f.Name())); return f.Sync() }
	t.Cleanup(func() { durableSync = old })
	patchDrain(t, rg.b, "h1", true)
	want := []string{drainsFile + ".tmp", filepath.Base(c.StateDir)}
	if strings.Join(synced, ",") != strings.Join(want, ",") {
		t.Fatalf("synced %v, want %v", synced, want)
	}
	if fi, err := os.Stat(filepath.Join(c.StateDir, drainsFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("drains file: %v %v", fi, err)
	}
	synced = nil
	rg.b.hotelsMutationMu.Lock()
	rg.b.mu.Lock()
	err := rg.b.saveRuntimeHotelsLocked()
	rg.b.mu.Unlock()
	rg.b.hotelsMutationMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	want = []string{runtimeHotelsFile + ".tmp", filepath.Base(c.StateDir)}
	if strings.Join(synced, ",") != strings.Join(want, ",") {
		t.Fatalf("hotels.json synced %v, want %v", synced, want)
	}
	// A failed sync fails the PATCH: nothing changes.
	durableSync = func(f *os.File) error { return os.ErrPermission }
	r := httptest.NewRequest("PATCH", "/v1/broker/hotels/h1", strings.NewReader(`{"drain": false}`))
	r.Header.Set("Authorization", "Bearer operator-key")
	w := httptest.NewRecorder()
	rg.b.handler().ServeHTTP(w, r)
	if w.Code != 500 || !rg.b.hotelByID("h1").drain() {
		t.Fatalf("failed sync: %d drain=%v", w.Code, rg.b.hotelByID("h1").drain())
	}
}

// A directory sync that fails after the rename puts the old file back: the
// PATCH answers 500 and keeps the old drain in memory, so a restart must
// read the old drain too (#693 Codex P1).
func TestFailedDirSyncPutsTheOldDrainsFileBack(t *testing.T) {
	c := reloadBase(t, t.TempDir())
	rg := newReloadRig(t, c)
	patchDrain(t, rg.b, "h1", true)
	old := durableSync
	durableSync = func(f *os.File) error {
		if fi, err := f.Stat(); err == nil && fi.IsDir() {
			return os.ErrPermission
		}
		return f.Sync()
	}
	t.Cleanup(func() { durableSync = old })
	r := httptest.NewRequest("PATCH", "/v1/broker/hotels/h1", strings.NewReader(`{"drain": false}`))
	r.Header.Set("Authorization", "Bearer operator-key")
	w := httptest.NewRecorder()
	rg.b.handler().ServeHTTP(w, r)
	if w.Code != 500 || !rg.b.hotelByID("h1").drain() {
		t.Fatalf("dir sync failure: %d drain=%v", w.Code, rg.b.hotelByID("h1").drain())
	}
	durableSync = old
	b2, err := loadBroker(rg.path)
	if err != nil {
		t.Fatal(err)
	}
	if !b2.hotelByID("h1").drain() {
		t.Fatal("a failed undrain reopened the hotel at restart")
	}
	// A first save that fails the same way leaves no file behind.
	c2 := reloadBase(t, t.TempDir())
	rg2 := newReloadRig(t, c2)
	durableSync = func(f *os.File) error {
		if fi, err := f.Stat(); err == nil && fi.IsDir() {
			return os.ErrPermission
		}
		return f.Sync()
	}
	r = httptest.NewRequest("PATCH", "/v1/broker/hotels/h1", strings.NewReader(`{"drain": true}`))
	r.Header.Set("Authorization", "Bearer operator-key")
	w = httptest.NewRecorder()
	rg2.b.handler().ServeHTTP(w, r)
	if _, err := os.Stat(filepath.Join(c2.StateDir, drainsFile)); w.Code != 500 || !os.IsNotExist(err) {
		t.Fatalf("first save: %d, file %v", w.Code, err)
	}
}
