package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// usage_meter_min_second (design 8.4, AB#894). The setting is read from a
// real config file, as the broker reads it, and the meter is then driven with
// the fake clock of the other meter tests.

// minSecondMeter loads a broker from a config with a state_dir plus extra
// and returns its usage meter and usage directory.
func minSecondMeter(t *testing.T, extra string) (*usageMeter, string) {
	t.Helper()
	state := t.TempDir()
	dirJSON, _ := json.Marshal(state)
	b, err := loadBroker(writeBrokerConfig(t, `,"state_dir":`+string(dirJSON)+extra))
	if err != nil {
		t.Fatal(err)
	}
	if b.usageMeter == nil {
		t.Fatal("no usage meter with a state_dir")
	}
	return b.usageMeter, filepath.Join(state, usageDirName)
}

func msAt(n int64) time.Time { return usageMeterT0.Add(time.Duration(n) * time.Millisecond) }

// minSecondRooms drives sub-second and multi-second rooms of hotel h1 (the
// config's hotel) through the create, delete and sync hooks:
//
//	h1.sub     created at 0, deleted (204) at 0.2 s: 0.2 s observed
//	h1.one     created at 0, deleted (204) at 1.0 s: 1.0 s
//	h1.onetwo  created at 0, deleted (204) at 1.2 s: 1.2 s
//	h1.gone    created at 0, delete answered 404 at 0.5 s: 0 s
//	h1.failed  a failed create's room (not billable), deleted at 0.2 s: 0.2 s
//	h1.multi   created at 0.3 s, listed at 2 and 4 s, deleted at 4.7 s: 4.4 s
//	h1.long    created at 0, listed every 2 s to 64 s, gone at 66 s: 64 s
//	h1.open    created at 0, listed at 1.2 s, still running at the stop
//
// h1.long gets a running reading at 60 s (usage_meter_every_seconds 60), and
// h1.open a running reading at the stop checkpoint (1.2 s observed).
func minSecondRooms(t *testing.T, m *usageMeter) {
	t.Helper()
	// pass is one sync pass of h1: its list shows listed; the room map holds
	// listed and h1.open, which no list shows after 1.2 s.
	pass := func(when time.Time, listed ...string) {
		var ss []usageSighting
		present := map[string]bool{"h1.open": true}
		for _, run := range listed {
			ss = append(ss, sighting(run))
			present[run] = true
		}
		m.hotelPass("h1", ss, present, when, true, true, false)
	}
	failed := sighting("h1.failed")
	failed.billable = false
	for _, run := range []string{"h1.sub", "h1.one", "h1.onetwo", "h1.gone", "h1.long", "h1.open"} {
		m.seen(sighting(run), msAt(0))
	}
	m.seen(failed, msAt(0))
	m.end("h1.sub", msAt(200), true)
	m.end("h1.failed", msAt(200), true)
	m.seen(sighting("h1.multi"), msAt(300))
	m.end("h1.gone", msAt(500), false)
	m.end("h1.one", msAt(1000), true)
	m.end("h1.onetwo", msAt(1200), true)
	m.sightRuns([]string{"h1.open"}, msAt(1200))
	pass(msAt(2000), "h1.multi", "h1.long")
	pass(msAt(4000), "h1.multi", "h1.long")
	m.end("h1.multi", msAt(4700), true)
	for p := int64(6000); p <= 64000; p += 2000 {
		pass(msAt(p), "h1.long")
	}
	pass(msAt(66000))
	m.checkpoint(msAt(66000))
	mustFlush(t, m)
}

// rawUsageLines is every line of the usage log in dir, in file order.
func rawUsageLines(t *testing.T, dir string) []string {
	t.Helper()
	files, err := (&usageMeter{dir: dir}).files()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range files {
		raw, err := os.ReadFile(f.path)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.SplitAfter(string(raw), "\n") {
			if line != "" {
				out = append(out, line)
			}
		}
	}
	return out
}

// lastSeconds is the seconds of the last reading of each run with state.
func lastSeconds(rs []usageReading, state string) map[string]int64 {
	out := map[string]int64{}
	for _, r := range rs {
		if r.State == state {
			out[r.Run] = r.Seconds
		}
	}
	return out
}

// Off, the setting changes nothing: a config with
// "usage_meter_min_second": false writes the same log, byte for byte, as a
// config without the field, and that log is today's truncation (a room used
// and deleted within one observed second ends at 0).
func TestMinSecondOffChangesNothing(t *testing.T) {
	without, withoutDir := minSecondMeter(t, "")
	off, offDir := minSecondMeter(t, `,"usage_meter_min_second":false`)
	minSecondRooms(t, without)
	minSecondRooms(t, off)
	want, got := rawUsageLines(t, withoutDir), rawUsageLines(t, offDir)
	if len(want) == 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("setting off wrote\n%s\nwithout the field\n%s", strings.Join(got, ""), strings.Join(want, ""))
	}
	all := logReadings(t, offDir)
	wantSeqs(t, all, 17)
	ended := lastSeconds(all, "ended")
	for run, s := range map[string]int64{"h1.sub": 0, "h1.one": 1, "h1.onetwo": 1, "h1.gone": 0, "h1.failed": 0, "h1.multi": 4, "h1.long": 64} {
		if ended[run] != s {
			t.Fatalf("%s ended at %d s, want %d (truncated); ended %v", run, ended[run], s, ended)
		}
	}
	if len(ended) != 7 {
		t.Fatalf("ended runs %v", ended)
	}
}

// On, the ended reading of a billable run rounds up to the next whole
// second, at least 1: 0.2 s ends as 1, 1.0 stays 1, 1.2 becomes 2, 4.4
// becomes 5, a delete answered 404 with no observed time ends as 1, and 64
// stays 64. A failed create's room (billable false) stays at 0. No running
// reading is rounded: every first reading stays 0, h1.long's 60 s reading
// stays 60 and h1.open's stop checkpoint at 1.2 s stays 1. Every reading
// keeps the shape it has with the setting off; only seconds differ.
func TestMinSecondOnRoundsTheEndUp(t *testing.T) {
	on, onDir := minSecondMeter(t, `,"usage_meter_min_second":true`)
	off, offDir := minSecondMeter(t, "")
	minSecondRooms(t, on)
	minSecondRooms(t, off)
	all := logReadings(t, onDir)
	wantSeqs(t, all, 17)
	ended := lastSeconds(all, "ended")
	for run, s := range map[string]int64{"h1.sub": 1, "h1.one": 1, "h1.onetwo": 2, "h1.gone": 1, "h1.failed": 0, "h1.multi": 5, "h1.long": 64} {
		if ended[run] != s {
			t.Fatalf("%s ended at %d s, want %d; ended %v", run, ended[run], s, ended)
		}
	}
	if len(ended) != 7 {
		t.Fatalf("ended runs %v", ended)
	}
	for _, r := range all {
		if r.State != "running" {
			continue
		}
		want := int64(0)
		switch {
		case r.Run == "h1.long" && r.At == msAt(60000).Unix():
			want = 60
		case r.Run == "h1.open" && r.At == msAt(66000).Unix():
			want = 1
		}
		if r.Seconds != want {
			t.Fatalf("running reading rounded: %+v, want %d s", r, want)
		}
	}
	onLines, offLines := rawUsageLines(t, onDir), rawUsageLines(t, offDir)
	if len(onLines) != len(offLines) {
		t.Fatalf("%d lines on, %d off", len(onLines), len(offLines))
	}
	for i := range onLines {
		var a, b map[string]any
		if json.Unmarshal([]byte(onLines[i]), &a) != nil || json.Unmarshal([]byte(offLines[i]), &b) != nil {
			t.Fatalf("line %d is not JSON: %q %q", i, onLines[i], offLines[i])
		}
		delete(a, "seconds")
		delete(b, "seconds")
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("line %d differs beyond seconds:\non  %s\noff %s", i, onLines[i], offLines[i])
		}
	}
}

// On, a run that is not billable is never rounded, whatever its seconds:
// not billable from its first reading (a cancelled or failed create's room)
// or turned not billable later (the orphan cleanup took it back). Later
// provisional and pool runs rely on this: they stay not billable, so the
// setting never rounds them.
func TestMinSecondOnNeverRoundsANotBillableRun(t *testing.T) {
	m, dir := minSecondMeter(t, `,"usage_meter_min_second":true`)
	notBillable := func(run string) usageSighting {
		s := sighting(run)
		s.billable = false
		return s
	}
	m.seen(notBillable("h1.reaped"), msAt(0))
	m.seen(notBillable("h1.cancelled"), msAt(0))
	m.seen(sighting("h1.turned"), msAt(0))
	m.seen(sighting("h1.billable"), msAt(0))
	m.end("h1.reaped", msAt(200), true)
	m.seen(notBillable("h1.turned"), msAt(500)) // the orphan cleanup lists it
	m.end("h1.cancelled", msAt(1200), true)
	m.end("h1.turned", msAt(1200), true)
	m.end("h1.billable", msAt(1200), true) // the control: rounded
	mustFlush(t, m)
	all := logReadings(t, dir)
	for run, s := range map[string]int64{"h1.reaped": 0, "h1.cancelled": 1, "h1.turned": 1, "h1.billable": 2} {
		got := readingsOf(all, run)
		end := got[len(got)-1]
		if end.State != "ended" || end.Seconds != s {
			t.Fatalf("%s: %+v, want ended at %d s", run, got, s)
		}
		if notB := end.Billable != nil && !*end.Billable; notB != (run != "h1.billable") {
			t.Fatalf("%s: ended reading billable field %v", run, end.Billable)
		}
	}
}
