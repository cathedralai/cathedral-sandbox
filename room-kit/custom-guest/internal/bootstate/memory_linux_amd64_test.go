package bootstate

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type memEntry struct {
	kind       string
	start, end uint64
}

func writeMemmap(t *testing.T, entries []memEntry) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "memmap")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for i, e := range entries {
		d := filepath.Join(dir, fmt.Sprint(i))
		if err := os.Mkdir(d, 0700); err != nil {
			t.Fatal(err)
		}
		for name, value := range map[string]string{
			"type": e.kind + "\n", "start": fmt.Sprintf("0x%x\n", e.start), "end": fmt.Sprintf("0x%x\n", e.end),
		} {
			if err := os.WriteFile(filepath.Join(d, name), []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return dir
}

const gib = uint64(1) << 30

// ramOf builds one System RAM entry of exactly size bytes plus reserved noise.
func ramOf(size uint64) []memEntry {
	return []memEntry{
		{"System RAM", 0x1000, 0x1000 + size - 1},
		{"Reserved", 0xfe000000, 0xfeffffff},
	}
}

func TestCheckMemory(t *testing.T) {
	const deficit = 5872026 // 5.6 MiB, measured on an 8 GiB guest
	for _, tc := range []struct {
		name    string
		entries []memEntry
		gib     int64
		ok      bool
	}{
		{"8 GiB with measured deficit", ramOf(8*gib - deficit), 8, true},
		{"exact", ramOf(8 * gib), 8, true},
		{"lowest accepted", ramOf(8*gib - 128<<20), 8, true},
		{"one byte below tolerance", ramOf(8*gib - 128<<20 - 1), 8, false},
		{"one byte above signed size", ramOf(8*gib + 1), 8, false},
		{"host shrank guest", ramOf(4 * gib), 8, false},
		{"split RAM entries sum", []memEntry{
			{"System RAM", 0, 3*gib - 1}, {"System RAM", 4 * gib, 9*gib - deficit - 1}}, 8, true},
		{"overlapping RAM", []memEntry{
			{"System RAM", 0, 5*gib - 1}, {"System RAM", 4 * gib, 8*gib - 1}}, 8, false},
		{"touching is overlap", []memEntry{
			{"System RAM", 0, 4*gib - 1}, {"System RAM", 4*gib - 1, 8*gib - 2}}, 8, false},
		{"adjacent is fine", []memEntry{
			{"System RAM", 0, 4*gib - 1}, {"System RAM", 4 * gib, 8*gib - 1}}, 8, true},
		{"type must be exact", []memEntry{{"System RAM (hotplug)", 0, 8*gib - 1}}, 8, false},
		{"reserved never counts", []memEntry{
			{"System RAM", 0, 4*gib - 1}, {"Reserved", 4 * gib, 8*gib - 1}}, 8, false},
		{"inverted range", []memEntry{{"System RAM", 8 * gib, 0}}, 8, false},
		{"zero signed size", ramOf(gib), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMemory(writeMemmap(t, tc.entries), tc.gib)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
		})
	}
}

func TestCheckMemoryUnreadable(t *testing.T) {
	if checkMemory(filepath.Join(t.TempDir(), "absent"), 8) == nil {
		t.Fatal("missing memmap accepted")
	}
	if checkMemory(writeMemmap(t, nil), 8) == nil {
		t.Fatal("empty memmap accepted")
	}
	for _, drop := range []string{"type", "start", "end"} {
		dir := writeMemmap(t, ramOf(8*gib))
		if err := os.Remove(filepath.Join(dir, "0", drop)); err != nil {
			t.Fatal(err)
		}
		if checkMemory(dir, 8) == nil {
			t.Fatalf("missing %s accepted", drop)
		}
	}
	for _, bad := range []string{"1000", "0x", "0xzz", "0x1ffffffffffffffff", "-1"} {
		dir := writeMemmap(t, ramOf(8*gib))
		if err := os.WriteFile(filepath.Join(dir, "0", "start"), []byte(bad+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if checkMemory(dir, 8) == nil {
			t.Fatalf("start %q accepted", bad)
		}
	}
	// An unparseable entry is refused even when it is not RAM.
	dir := writeMemmap(t, ramOf(8*gib))
	if err := os.WriteFile(filepath.Join(dir, "1", "end"), []byte("garbage\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if checkMemory(dir, 8) == nil {
		t.Fatal("unparseable reserved entry accepted")
	}
}
