// Runtime drains of config file hotels survive a restart (AB#946).
//
// A joined hotel keeps its drain in state_dir/hotels.json. A config file
// hotel's PATCH {"drain": ...} used to live in memory only, so a restart
// reopened a drained hotel (22 Nov 2026: two Escape rooms lost). Now that
// PATCH is kept in state_dir/hotel-drains.json with the file's own drain at
// the time (config_drain). At start, and when a reload changes the file's
// drain, a saved drain applies only while the file still says config_drain:
// once someone changed the file, the file wins and the record is dropped.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const drainsFile = "hotel-drains.json"

// drainRecord is one config file hotel's PATCHed drain.
type drainRecord struct {
	Drain       bool `json:"drain"`
	ConfigDrain bool `json:"config_drain"` // the file's drain when the PATCH came
}

// noteConfigDrainLocked records h's drain after a PATCH changed it. Caller
// holds b.mu and hotelsMutationMu.
func (b *broker) noteConfigDrainLocked(h *hotel) {
	if b.drains == nil {
		b.drains = map[string]drainRecord{}
	}
	if d := h.drain(); d == h.fileDrain {
		delete(b.drains, h.cfg.ID) // back to what the file says: nothing to keep
	} else {
		b.drains[h.cfg.ID] = drainRecord{Drain: d, ConfigDrain: h.fileDrain}
	}
}

// saveConfigDrainsLocked writes state_dir/hotel-drains.json. Caller holds
// b.mu and hotelsMutationMu.
func (b *broker) saveConfigDrainsLocked() error {
	if b.cfg.StateDir == "" {
		return errors.New("no state_dir")
	}
	out := map[string]drainRecord{}
	for id, r := range b.drains {
		out[id] = r
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(b.cfg.StateDir, drainsFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(b.cfg.StateDir, drainsFile))
}

// loadConfigDrains applies state_dir/hotel-drains.json to the config file
// hotels at start. A record whose config_drain is no longer the file's drain,
// or whose hotel left the file, is dropped. A file that does not read keeps
// the config file's drains and is logged: it is never a reason not to start.
func (b *broker) loadConfigDrains() {
	b.drains = map[string]drainRecord{}
	for _, h := range b.hotelList() {
		if !h.runtime {
			h.fileDrain = h.cfg.Drain
		}
	}
	if b.cfg.StateDir == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(b.cfg.StateDir, drainsFile))
	if os.IsNotExist(err) {
		return
	}
	var saved map[string]drainRecord
	if err == nil {
		err = json.Unmarshal(raw, &saved)
	}
	if err != nil {
		// Starting is right (const must not wait on this file), but the
		// PATCHed drains are lost: keep the file aside before the next PATCH
		// overwrites it, and tell ops which drains to set again.
		path := filepath.Join(b.cfg.StateDir, drainsFile)
		aside := path + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
		kept := "the old file was not kept aside"
		if werr := os.WriteFile(aside, raw, 0o600); werr == nil {
			kept = "the old file is kept at " + aside
		}
		b.alerts.send("OPS-ALERT", b.alerts.opsChat, fmt.Sprintf("DRAINS NOT LOADED: %s: %v; config file drains apply, so a hotel drained by PATCH is open again; %s. Re-drain by PATCH.", drainsFile, err, kept), nil, nil)
		return
	}
	dropped := false
	for id, r := range saved {
		h := b.hotelByID(id)
		switch {
		case h == nil || h.runtime:
			dropped = true
		case r.ConfigDrain != h.fileDrain:
			log.Printf("hotel %s: saved drain %v dropped: the config file's drain changed since (file wins)", id, r.Drain)
			dropped = true
		default:
			h.cfg.Drain = r.Drain
			b.drains[id] = r
			log.Printf("hotel %s: drain %v kept from before the restart (%s)", id, r.Drain, drainsFile)
		}
	}
	if dropped {
		if err := b.saveConfigDrainsLocked(); err != nil {
			log.Printf("%s not rewritten: %v", drainsFile, err)
		}
	}
}
