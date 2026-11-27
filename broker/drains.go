// Runtime drains of config file hotels survive a restart (AB#946).
//
// A joined hotel keeps its drain in state_dir/hotels.json. A config file
// hotel's PATCH {"drain": ...} used to live in memory only, so a restart
// reopened a drained hotel (22 Nov 2026: two Escape rooms lost). Now that
// PATCH is kept in state_dir/hotel-drains.json with the file's own drain at
// the time (config_drain). At start, and when a reload changes the file's
// drain, a saved drain applies only while the file still says config_drain:
// once someone changed the file, the file wins and the record is dropped.
//
// AB#875: the drains file and hotels.json (joined hotels' drains) are
// written with fsync on the file and its directory, so a drain the PATCH
// answered 200 for is on disk before the answer, and a power loss or a
// crash right after cannot reopen the hotel.
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
	if d := h.cfgDrain(); d == h.fileDrain { // the hold's forced drain is not saved here
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
	return writeFileDurable(filepath.Join(b.cfg.StateDir, drainsFile), raw)
}

// writeFileDurable replaces name with raw (mode 0600) through a synced temp
// file and a rename, then syncs the directory: the rename is durable only
// once the directory is.
//
// A caller treats any error as "not saved" and keeps its old state in
// memory. So when the directory sync fails after the rename, the old file
// is put back (best effort): a restart then reads what memory holds, not a
// change the caller reported as failed.
func writeFileDurable(name string, raw []byte) error {
	old, oldErr := os.ReadFile(name)
	tmp := name + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil { // a leftover tmp file keeps its old mode
		f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := durableSync(f); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		return err
	}
	err = syncDir(filepath.Dir(name))
	if err != nil {
		switch {
		case oldErr == nil:
			if werr := os.WriteFile(tmp, old, 0o600); werr == nil {
				_ = os.Rename(tmp, name)
			}
		case os.IsNotExist(oldErr):
			_ = os.Remove(name)
		}
	}
	return err
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := durableSync(d); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

// durableSync is f.Sync; a variable so a test can see the calls or make one fail.
var durableSync = func(f *os.File) error { return f.Sync() }

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
