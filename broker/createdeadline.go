package main

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"
)

// create_timeout_seconds (AB#862): how long a create may wait on the broker
// for a hotel create slot (the per-hotel concurrency, waitSlot). A burst then
// fails fast with 503 create_timeout and Retry-After instead of queueing
// until the client gives up. A create already sent to a hotel runs to that
// hotel's answer: cutting it would read as a hotel failure, rest a healthy
// hotel and leave a room to reap.

// maxCreateTimeoutSeconds is the hotel create call bound (hotelCreateTimeout).
const maxCreateTimeoutSeconds = 720

// createTimeoutRetryAfter is the Retry-After (seconds) of a 503 create_timeout.
const createTimeoutRetryAfter = 5

// createDeadline reads create_timeout_seconds from a create body and removes
// it, so it never reaches a hotel. Zero time: the create sets none (or null).
func createDeadline(payload map[string]any, now time.Time) (time.Time, *apiErr) {
	v, ok := payload["create_timeout_seconds"]
	if !ok {
		return time.Time{}, nil
	}
	delete(payload, "create_timeout_seconds")
	if v == nil {
		return time.Time{}, nil
	}
	f, ok := v.(float64)
	if !ok || f != math.Trunc(f) || f < 1 || f > maxCreateTimeoutSeconds {
		return time.Time{}, &apiErr{400, "invalid_create_timeout", "create_timeout_seconds must be a whole number of seconds from 1 to " + strconv.Itoa(maxCreateTimeoutSeconds)}
	}
	return now.Add(time.Duration(f) * time.Second), nil
}

// createDeadlinePassed: the create has a deadline and it is over.
func createDeadlinePassed(pl placement) bool {
	return !pl.deadline.IsZero() && !time.Now().Before(pl.deadline)
}

// createTimedOut is the answer to a create whose deadline passed before any
// hotel started it. Nothing was sent to a hotel, so no room exists.
func createTimedOut() createResult {
	return createResult{status: 503, header: http.Header{"Retry-After": {strconv.Itoa(createTimeoutRetryAfter)}},
		doc: errDoc("create_timeout", "no hotel create slot came free within create_timeout_seconds; no room was started. Retry after Retry-After seconds, or send fewer creates at once")}
}

// createDeadlineKey carries a create's deadline to the hotel call, so the wait
// for a free data connection (hotelconns.go) ends at it too.
type createDeadlineKey struct{}

// errCreateDeadline: the create's deadline passed while it waited for a data
// connection. Nothing was sent to the hotel.
var errCreateDeadline = errors.New("create deadline passed before the create was sent")

// withCreateDeadline marks ctx with pl's deadline (none: ctx unchanged).
func withCreateDeadline(ctx context.Context, pl placement) context.Context {
	if pl.deadline.IsZero() {
		return ctx
	}
	return context.WithValue(ctx, createDeadlineKey{}, pl.deadline)
}
