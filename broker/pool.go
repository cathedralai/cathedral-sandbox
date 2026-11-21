// Ready rooms (AB#894, phase 2 PR 2): the pool of rooms made ahead of time
// for claims. Settings and the pool guest: pool_settings.go.
package main

import (
	"errors"
	"log"
	"sync"
)

type readyRooms struct {
	keys    []poolKey
	guest   *guestState
	saveMu  sync.Mutex // one settings write at a time
	journal *claimJournal
	// journalState is "complete", "incomplete" or "unavailable".
	journalState, journalWhy string
	// Guarded by b.mu.
	settings readyRoomsSettings
}

// openJournal opens the claim journal. The manager creates and deletes
// rooms only while it is open and complete.
func (p *readyRooms) openJournal(stateDir string) {
	j, _, err := openClaimJournal(stateDir)
	p.journal = j
	switch {
	case err == nil:
		p.journalState = "complete"
	case errors.Is(err, errClaimJournalIncomplete):
		p.journalState, p.journalWhy = "incomplete", err.Error()
		log.Printf("ready rooms: %v; the pool manager creates and deletes nothing until a person looks", err)
	default:
		p.journalState, p.journalWhy = "unavailable", err.Error()
		log.Printf("ready rooms: claim journal not opened: %v; the pool manager creates and deletes nothing", err)
	}
}

// close stops the journal's writer. Safe on nil.
func (p *readyRooms) close() {
	if p != nil && p.journal != nil {
		_ = p.journal.close()
	}
}
