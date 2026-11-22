// Hotel data connections (AB#819, const load test 18 Nov 2026).
//
// Every room call to a hotel (create, exec, files, delete...) goes through
// doHeadersMax and holds one of the hotel's data connections for its whole
// run: an exec holds one for up to its timeout plus 60 s. The pool size is the
// hotel's "data_conns" (default concurrency + 64, as before). Before AB#819 a
// call past the cap waited inside the HTTP transport with no log and no limit
// of its own, so a 900 s command could wait 900 s and never reach the hotel.
//
// Now a call that finds no free connection is counted and logged ("waiting for
// hotel connection"), and gives up after "data_conn_wait_seconds" (default
// 10 s) with errHotelBusy. The caller answers 503 sold_out with Retry-After:
// nothing was sent to the hotel, so a retry is safe. The call's own deadline
// (exec, create) is unchanged and still applies while it waits. -1 keeps the
// old behaviour: wait until that deadline. Background cleanup (room reap,
// orphan removal) always waits until its deadline: it retries, and a delete
// that gave up would leave a room running.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// errHotelBusy: every data connection to the hotel stayed in use for the whole
// bounded wait. The call never reached the hotel.
var errHotelBusy = errors.New("no free hotel connection")

const (
	defaultDataConnWait = 10 * time.Second
	maxDataConns        = 4096
	maxDataConnWaitSecs = 600
	// hotelBusyRetryAfter is the Retry-After (seconds) of a 503 for errHotelBusy.
	hotelBusyRetryAfter = 5
	// connWaitLogEvery bounds the wait log to one line per hotel per period:
	// at the cap hundreds of calls wait at once.
	connWaitLogEvery = 10 * time.Second
)

// connGate is one hotel's data connection slots.
type connGate struct {
	slots   chan struct{}
	wait    time.Duration // < 0: no bound of its own (the call's deadline only)
	waiting atomic.Int64  // calls waiting for a slot now
	waits   atomic.Int64  // calls that had to wait, since start
	refused atomic.Int64  // calls that gave up after the bound (errHotelBusy), since start
	lastLog atomic.Int64  // unix ns of the last wait log line
}

// dataConns is the hotel's data pool size: "data_conns", or concurrency + 64.
func dataConns(hc hotelConfig) int {
	if hc.DataConns > 0 {
		return hc.DataConns
	}
	return hc.Concurrency + 64
}

func newConnGate(hc hotelConfig) *connGate {
	wait := defaultDataConnWait
	switch {
	case hc.DataConnWaitSeconds < 0:
		wait = -1
	case hc.DataConnWaitSeconds > 0:
		wait = time.Duration(hc.DataConnWaitSeconds) * time.Second
	}
	return &connGate{slots: make(chan struct{}, dataConns(hc)), wait: wait}
}

// checkDataConnConfig validates the two pool fields of a config or join.
func checkDataConnConfig(hc hotelConfig) error {
	if hc.DataConns < 0 || hc.DataConns > maxDataConns {
		return fmt.Errorf("data_conns must be 0 (concurrency + 64) to %d", maxDataConns)
	}
	if hc.DataConnWaitSeconds < -1 || hc.DataConnWaitSeconds > maxDataConnWaitSecs {
		return fmt.Errorf("data_conn_wait_seconds must be -1 (until the call's deadline), 0 (10 s) or up to %d", maxDataConnWaitSecs)
	}
	return nil
}

type connWaitKey struct{}

// waitForConnUntilDeadline marks ctx so its hotel calls wait for a data
// connection until the call's own deadline, without the bounded wait.
func waitForConnUntilDeadline(ctx context.Context) context.Context {
	return context.WithValue(ctx, connWaitKey{}, true)
}

// acquire takes a data connection slot. release gives it back; call it once,
// after the answer body is read and closed.
func (g *connGate) acquire(ctx context.Context, hotelID string) (release func(), err error) {
	release = func() { <-g.slots }
	select {
	case g.slots <- struct{}{}:
		return release, nil
	default:
	}
	g.waits.Add(1)
	g.waiting.Add(1)
	defer g.waiting.Add(-1)
	g.logWait(hotelID, false)
	var bound <-chan time.Time
	if g.wait >= 0 && ctx.Value(connWaitKey{}) == nil {
		t := time.NewTimer(g.wait)
		defer t.Stop()
		bound = t.C
	}
	// A create's own deadline (create_timeout_seconds, AB#862) also ends
	// the wait; the create was not sent.
	var deadline <-chan time.Time
	if d, ok := ctx.Value(createDeadlineKey{}).(time.Time); ok && !d.IsZero() {
		t := time.NewTimer(time.Until(d))
		defer t.Stop()
		deadline = t.C
	}
	select {
	case g.slots <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-bound:
		g.refused.Add(1)
		g.logWait(hotelID, true)
		return nil, errHotelBusy
	case <-deadline:
		return nil, errCreateDeadline
	}
}

func (g *connGate) logWait(hotelID string, refused bool) {
	now := time.Now().UnixNano()
	last := g.lastLog.Load()
	if now-last < int64(connWaitLogEvery) || !g.lastLog.CompareAndSwap(last, now) {
		return
	}
	what := "waiting for hotel connection"
	if refused {
		what = "no hotel connection after " + g.wait.String() + ", answered 503 sold_out"
	}
	log.Printf("hotel %s: %s (pool %d, in use %d, waiting %d, waits %d, refused %d)",
		hotelID, what, cap(g.slots), len(g.slots), g.waiting.Load(), g.waits.Load(), g.refused.Load())
}

// stats is the gate's part of /v1/broker/stats.
func (g *connGate) stats() map[string]any {
	return map[string]any{"data_conns": cap(g.slots), "conns_in_use": len(g.slots), "conns_waiting": g.waiting.Load(),
		"conn_waits": g.waits.Load(), "conn_refused": g.refused.Load()}
}

const hotelBusyMessage = " has no free connection; nothing was sent to it, retry shortly"

// writeHotelErr answers a failed hotel call on the native API: 503 sold_out
// with Retry-After when the call never got a connection, else 502.
func writeHotelErr(w http.ResponseWriter, h *hotel, err error) {
	if errors.Is(err, errHotelBusy) {
		w.Header().Set("Retry-After", fmt.Sprint(hotelBusyRetryAfter))
		writeErr(w, 503, "sold_out", "hotel "+h.cfg.ID+hotelBusyMessage)
		return
	}
	writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
}

// compatHotelErr is writeHotelErr for the compat API envelope; msg is the 502 message.
func compatHotelErr(w http.ResponseWriter, err error, msg string) {
	if errors.Is(err, errHotelBusy) {
		compatErr(w, 503, "sold_out", "the hotel"+hotelBusyMessage, hotelBusyRetryAfter)
		return
	}
	compatErr(w, 502, "hotel_unreachable", msg, 5)
}

// hotelAPIErr is writeHotelErr for callers that return an *apiErr.
func hotelAPIErr(h *hotel, err error) *apiErr {
	if errors.Is(err, errHotelBusy) {
		return busyAPIErr("hotel " + h.cfg.ID)
	}
	return &apiErr{502, "hotel_unreachable", "hotel " + h.cfg.ID + " did not answer"}
}

func busyAPIErr(who string) *apiErr {
	return &apiErr{503, "sold_out", who + hotelBusyMessage}
}

// busyHotelsErr answers a fan-out lookup that found nothing while some hotels
// were busy: those were never asked, so the answer is "retry", not "not found".
func busyHotelsErr(ids []string) *apiErr {
	sort.Strings(ids)
	if len(ids) == 1 {
		return busyAPIErr("hotel " + ids[0])
	}
	return &apiErr{503, "sold_out", "hotels " + strings.Join(ids, ", ") + " have no free connection; nothing was sent to them, retry shortly"}
}

// writeAPIErr writes an *apiErr. A busy hotel's 503 sold_out carries
// Retry-After, as writeHotelErr sets it on the same condition.
func writeAPIErr(w http.ResponseWriter, e *apiErr) {
	if e.status == 503 && e.code == "sold_out" {
		w.Header().Set("Retry-After", fmt.Sprint(hotelBusyRetryAfter))
	}
	writeErr(w, e.status, e.code, e.msg)
}
