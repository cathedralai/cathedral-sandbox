package main

import (
	"context"
	"sync"
	"time"
)

// Bounds for compat background execs (AB#752). The compat /execs route keeps
// its results in compat.execs, apart from the native map, and had no bound.
// Finished results now take the native rules and limits (AB#748), counted
// over this map: by count and by output bytes, per guest and for the broker,
// older evicted first and a guest's newest last. An evicted result keeps its
// state, exit code and other fields; only stdout and stderr are dropped, and
// it says so. Finished results still go after execKeep (one hour).
//
// While an answer is read from the hotel, its bytes are reserved in an
// answerPool (per guest and broker-wide) for every compat exec read: sync
// /exec, background /execs and the files-through-exec scripts. A read waits
// for room in the pool rather than failing, until its call times out.
// There is no new running cap: compat clients (Harbor, ctcli) may run many
// commands at once, and the pool bounds what those commands' answers hold.

// Pool sizes. Each is at least execAnswerMaxBytes, so one answer always fits.
var (
	answerPoolGuestBytes int64 = 256 << 20
	answerPoolTotalBytes int64 = 512 << 20
)

// answerPool is the bytes of hotel answers being read, per owner and in all.
type answerPool struct {
	mu    sync.Mutex
	used  int64
	owner map[string]int64
	wake  chan struct{} // closed and replaced whenever bytes are given back
}

func newAnswerPool() *answerPool {
	return &answerPool{owner: map[string]int64{}, wake: make(chan struct{})}
}

// reserve takes n bytes for owner, waiting while the owner's share or the
// broker's total would pass its size. All or nothing, so two waiting reads
// never each hold part of what the other needs. The release it returns gives
// the bytes back once.
func (p *answerPool) reserve(ctx context.Context, owner string, n int64) (func(), error) {
	if n > answerPoolGuestBytes || n > answerPoolTotalBytes {
		return nil, errAnswerTooLarge // it could never fit
	}
	for {
		p.mu.Lock()
		if p.owner[owner]+n <= answerPoolGuestBytes && p.used+n <= answerPoolTotalBytes {
			p.owner[owner] += n
			p.used += n
			p.mu.Unlock()
			var once sync.Once
			return func() { once.Do(func() { p.give(owner, n) }) }, nil
		}
		wake := p.wake
		p.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (p *answerPool) give(owner string, n int64) {
	p.mu.Lock()
	p.owner[owner] -= n
	if p.owner[owner] <= 0 {
		delete(p.owner, owner)
	}
	p.used -= n
	close(p.wake)
	p.wake = make(chan struct{})
	p.mu.Unlock()
}

// pruneExecsLocked applies execKeep, then the native count and byte bounds
// (nativeExecs.pruneLocked) to the compat results. The caller holds c.mu.
//
// The native rules run on a stand-in map that shares each result map, so the
// two routes evict by one algorithm. Removals and evictions are copied back.
func (c *compatState) pruneExecsLocked(now time.Time) {
	stand := &nativeExecs{execs: make(map[string]*nativeExec, len(c.execs))}
	for id, ex := range c.execs {
		if ex.state != "running" && !ex.doneAt.IsZero() && now.Sub(ex.doneAt) > execKeep {
			delete(c.execs, id)
			continue
		}
		state, doneAt := ex.state, ex.doneAt
		if state != "running" && doneAt.IsZero() {
			doneAt = now // ended without a finish time: count it as the newest, never as ancient
		}
		stand.execs[id] = &nativeExec{ID: id, Guest: ex.guest, State: state, DoneAt: doneAt, Result: ex.result}
	}
	stand.pruneLocked(now)
	for id, ex := range c.execs {
		kept, ok := stand.execs[id]
		if !ok {
			delete(c.execs, id)
			continue
		}
		if kept.Result != nil && kept.Result["evicted"] == true && ex.result["evicted"] != true {
			delete(kept.Result, "receipt_covers") // a compat result keeps no receipt
			ex.result = kept.Result
		}
	}
}
