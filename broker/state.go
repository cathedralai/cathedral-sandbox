// Durable client state (#290). With state_dir set, the broker keeps in
// state_dir/client-state.json:
//   - the client id (UUID) of each room, so an id still works after a restart;
//   - finished Idempotency-Key answers, so a repeated create after a restart
//     returns the first answer and starts no new room;
//   - deleted-room tombstones;
//   - imported and built images. A build context is a separate file in
//     state_dir/build-contexts.
//
// The file has no registry login: the broker never stores one. It holds the
// answers that the guests got, so it is written with mode 0600.
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	stateFile      = "client-state.json"
	contextsDir    = "build-contexts"
	stateKeep      = 48 * time.Hour // idempotency answers and tombstones
	stateSaveEvery = time.Second
)

type savedIdem struct {
	Status int       `json:"status"`
	Body   []byte    `json:"body"`
	At     time.Time `json:"at"`
}

type savedTomb struct {
	BID string    `json:"bid"`
	At  time.Time `json:"at"`
}

type savedState struct {
	UUIDs      map[string]string                     `json:"uuids"` // client id -> broker room id
	Idem       map[string]savedIdem                  `json:"idempotency"`
	Tombs      map[string]savedTomb                  `json:"tombstones"`
	Images     map[string]*compatImage               `json:"images"`
	GuestRooms map[string]map[string]map[string]bool `json:"guest_rooms"` // guest -> hotel -> room id
}

func (b *broker) markDirty() { b.dirty.Store(true) }

func (b *broker) saveLoop(ctx context.Context) {
	if b.cfg.StateDir == "" {
		return
	}
	t := time.NewTicker(stateSaveEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if b.dirty.Swap(false) {
				if err := b.saveCompat(); err != nil {
					b.markDirty()
					log.Printf("client state not saved: %v", err)
				}
			}
		}
	}
}

// saveCompat writes the client state file. It drops entries older than stateKeep.
func (b *broker) saveCompat() error {
	if b.cfg.StateDir == "" {
		return nil
	}
	st := savedState{
		UUIDs: map[string]string{}, Idem: map[string]savedIdem{}, Tombs: map[string]savedTomb{},
		Images: map[string]*compatImage{}, GuestRooms: map[string]map[string]map[string]bool{},
	}
	b.mu.Lock()
	for u, rm := range b.byUUID {
		if rm.id != "" {
			st.UUIDs[u] = rm.id
		}
	}
	for guest, byHotel := range b.guestRooms {
		outHotel := map[string]map[string]bool{}
		for hotel, ids := range byHotel {
			outIDs := map[string]bool{}
			for id := range ids {
				outIDs[id] = true
			}
			if len(outIDs) > 0 {
				outHotel[hotel] = outIDs
			}
		}
		if len(outHotel) > 0 {
			st.GuestRooms[guest] = outHotel
		}
	}
	b.mu.Unlock()
	now := time.Now()
	b.compat.mu.Lock()
	for k, e := range b.compat.idem {
		select {
		case <-e.done:
		default:
			continue // still running
		}
		if now.Sub(e.at) > stateKeep {
			delete(b.compat.idem, k)
			continue
		}
		st.Idem[k] = savedIdem{Status: e.status, Body: e.body, At: e.at}
	}
	for u, t := range b.compat.tombs {
		if now.Sub(t.at) > stateKeep {
			delete(b.compat.tombs, u)
			continue
		}
		st.Tombs[u] = savedTomb{BID: t.bid, At: t.at}
	}
	for id, img := range b.compat.images {
		st.Images[id] = img
	}
	raw, err := json.Marshal(st)
	b.compat.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.cfg.StateDir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(b.cfg.StateDir, stateFile+".tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(b.cfg.StateDir, stateFile))
}

// saveBuildContext writes a build context file. Caller holds b.compat.mu.
func (b *broker) saveBuildContext(img *compatImage) {
	if b.cfg.StateDir == "" || len(img.buildCtx) == 0 {
		return
	}
	dir := filepath.Join(b.cfg.StateDir, contextsDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("build context not saved: %v", err)
		return
	}
	// Write and rename, so a crash leaves the old file or the whole new one.
	final := filepath.Join(dir, img.ID+".tar.gz")
	if err := os.WriteFile(final+".tmp", img.buildCtx, 0o600); err != nil {
		log.Printf("build context not saved: %v", err)
		return
	}
	if err := os.Rename(final+".tmp", final); err != nil {
		log.Printf("build context not saved: %v", err)
	}
}

// loadCompat reads the client state file, if there is one.
func (b *broker) loadCompat() error {
	if b.cfg.StateDir == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(b.cfg.StateDir, stateFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var st savedState
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	b.mu.Lock()
	b.savedUUIDs = map[string]string{}
	for u, bid := range st.UUIDs {
		b.savedUUIDs[bid] = u
	}
	if len(st.GuestRooms) > 0 {
		b.guestRooms = map[string]map[string]map[string]struct{}{}
		for guest, byHotel := range st.GuestRooms {
			outHotel := map[string]map[string]struct{}{}
			for hotel, ids := range byHotel {
				outIDs := map[string]struct{}{}
				for id, ok := range ids {
					if ok && id != "" {
						outIDs[id] = struct{}{}
					}
				}
				if len(outIDs) > 0 {
					outHotel[hotel] = outIDs
				}
			}
			if len(outHotel) > 0 {
				b.guestRooms[guest] = outHotel
			}
		}
	}
	b.mu.Unlock()
	b.compat.mu.Lock()
	defer b.compat.mu.Unlock()
	for k, e := range st.Idem {
		done := make(chan struct{})
		close(done)
		b.compat.idem[k] = &idemEntry{done: done, status: e.Status, body: e.Body, at: e.At}
	}
	for u, t := range st.Tombs {
		b.compat.tombs[u] = compatTomb{bid: t.BID, at: t.At}
	}
	for id, img := range st.Images {
		if img == nil {
			continue
		}
		img.ID = id
		if img.Build {
			ctx, err := os.ReadFile(filepath.Join(b.cfg.StateDir, contextsDir, id+".tar.gz"))
			switch {
			case err == nil:
				img.buildCtx = ctx
			case os.IsNotExist(err):
				// A build with no context file had an empty context.
			default:
				img.ctxMissing = true
			}
			img.builds = map[string]*buildHotel{} // the hotels are asked again
		}
		b.compat.images[id] = img
	}
	return nil
}
