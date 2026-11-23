package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIncompleteClaimJournalDoesNotRestoreCustomerUUIDToPool(t *testing.T) {
	for _, broken := range []string{"segment", "tail"} {
		t.Run(broken, func(t *testing.T) {
			pc, _ := newMappedChain(t, 1)
			run, _ := mappedRestart(t, pc, time.Now().Add(-time.Minute), broken)
			pc.up("a")
			pc.sync("a")
			pc.b.mu.Lock()
			rm := pc.b.hotelByID("a").rooms["sbx-1"]
			if rm == nil || rm.guest != poolGuestID || rm.uuid == run || pc.b.byUUID[run] != nil {
				pc.b.mu.Unlock()
				t.Fatalf("set-aside pool room retained customer UUID %s: %+v", run, rm)
			}
			pc.b.mu.Unlock()
		})
	}
}

func TestSavedPoolIdentityRequiresPoolOwner(t *testing.T) {
	for _, tc := range []struct {
		name, guest, savedOwner string
		keep                    bool
	}{
		{"pool", poolGuestID, poolGuestID, true},
		{"customer_claim", poolGuestID, "g1", false},
		{"legacy_pool", poolGuestID, "", false},
		{"legacy_customer", "g1", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := newUUID()
			b := &broker{byUUID: map[string]*room{}, savedUUIDs: map[string]string{"a.r": old}, savedUUIDGuests: map[string]string{"a.r": tc.savedOwner}}
			rm := &room{id: "a.r", guest: tc.guest}
			b.register(rm)
			if (rm.uuid == old) != tc.keep || rm.uuid == "" {
				t.Fatalf("identity reuse=%v, want %v", rm.uuid == old, tc.keep)
			}
			if !tc.keep && b.byUUID[old] != nil {
				t.Fatal("rejected identity entered index")
			}
			if _, ok := b.savedUUIDGuests[rm.id]; ok {
				t.Fatal("consumed owner remains pending")
			}
		})
	}
}

func TestUnclaimedPoolIdentitySurvivesSaveBeforeFirstSync(t *testing.T) {
	pc, _ := newMappedChain(t, 1)
	pc.sync("a")
	pc.b.mu.Lock()
	old := pc.b.hotelByID("a").rooms["sbx-1"].uuid
	pc.b.mu.Unlock()
	if err := pc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	pc.start()
	// An intervening save must preserve the pending identity's owner too.
	if err := pc.b.saveCompat(); err != nil {
		t.Fatal(err)
	}
	pc.start()
	pc.up("a")
	pc.sync("a")
	pc.b.mu.Lock()
	defer pc.b.mu.Unlock()
	rm := pc.b.hotelByID("a").rooms["sbx-1"]
	if rm == nil || rm.uuid != old || rm.guest != poolGuestID {
		t.Fatalf("unclaimed pool identity changed: %+v", rm)
	}
}

func TestPoolIdentityWithoutReadableOwnerMetadataRotates(t *testing.T) {
	for _, kind := range []string{"legacy", "invalid"} {
		t.Run(kind, func(t *testing.T) {
			pc, _ := newMappedChain(t, 1)
			pc.sync("a")
			pc.b.mu.Lock()
			old := pc.b.hotelByID("a").rooms["sbx-1"].uuid
			pc.b.mu.Unlock()
			if err := pc.b.saveCompat(); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(pc.stateDir, stateFile)
			raw, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			var st map[string]json.RawMessage
			if err := json.Unmarshal(raw, &st); err != nil {
				t.Fatal(err)
			}
			if kind == "legacy" {
				delete(st, "uuid_guests")
			} else {
				st["uuid_guests"] = json.RawMessage(`false`)
			}
			raw, err = json.Marshal(st)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(name, raw, 0600); err != nil {
				t.Fatal(err)
			}
			pc.start()
			pc.up("a")
			pc.sync("a")
			pc.b.mu.Lock()
			defer pc.b.mu.Unlock()
			rm := pc.b.hotelByID("a").rooms["sbx-1"]
			if rm == nil || rm.uuid == old || pc.b.byUUID[old] != nil {
				t.Fatalf("unverified saved pool identity restored: %+v", rm)
			}
		})
	}
}
