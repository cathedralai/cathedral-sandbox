//go:build vmcuttest

package vmdisk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
)

// T5 (spec r3 13.1): first-boot cuts. A boot runs in a subprocess built
// with the vmcuttest hook and dies by SIGKILL at one point; the test powers
// off (mappings removed, loop detached), may craft the torn state a cut
// inside a step leaves, then boots again with no cut.

// TestHelperBoot is the subprocess boot; it does nothing in a normal run.
func TestHelperBoot(t *testing.T) {
	path := os.Getenv("VMDISK_HELPER")
	if path == "" {
		t.Skip("the T5 subprocess boot")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg helperConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	id, err := vmidentity.Parse([]byte(cfg.Identity))
	if err != nil {
		t.Fatal(err)
	}
	pass, _ := hex.DecodeString(cfg.Pass)
	var meas [48]byte
	m, _ := hex.DecodeString(cfg.Measurement)
	copy(meas[:], m)
	tool, err := os.ReadFile(cfg.Tool)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := os.OpenFile(cfg.Journal, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	disk, err := os.OpenFile(cfg.Disk, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Run(context.Background(), Config{Disk: disk, DiskBytes: testDisk, Identity: id, Passphrase: pass,
		Measurement: meas, Cryptsetup: Tool{Path: cfg.Tool, SHA256: sha256.Sum256(tool), Name: "cryptsetup"},
		Names: cfg.Names, Setup: fakeSetup{},
		Log: func(s string) { fmt.Fprintln(journal, s); journal.Sync() }})
	if err != nil {
		t.Fatal(err)
	}
	if out.Ready {
		fmt.Fprintf(journal, "switch_root after meta %s\n", out.Meta.State)
	}
}

// cutBoot boots d in a subprocess that must die at point.
func (h *harness) cutBoot(d *disk, id vmidentity.Identity, k key, point string, env ...string) {
	h.t.Helper()
	d.attach().Close()
	defer func() { h.powerOff(); d.detach() }()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperBoot$", "-test.v")
	cmd.Env = append(append(os.Environ(), "VMDISK_HELPER="+h.helperConfig(d, id, k), "CATHEDRAL_VMCUT="+point), env...)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		h.t.Fatalf("the cut at %s was not reached (%v):\n%s", point, err, out)
	}
}

// finishBoot is the boot after the cuts: it must end ready, run luksFormat
// only from new or resume, and leave the T5 end state on the disk.
func (h *harness) finishBoot(d *disk, id vmidentity.Identity, k key, want State) {
	h.t.Helper()
	out, err, lines := h.boot(d, id, k)
	log := strings.Join(lines, "\n")
	if err != nil || !out.Ready || out.State != want || out.Meta.State != StateReady {
		h.t.Fatalf("after the cut: state %s ready %v meta %s err %v, want %s\n%s", out.State, out.Ready, out.Meta.State, err, want, log)
	}
	if strings.Contains(log, "F3 luksFormat") && out.State != StateNew && out.State != StateResume {
		h.t.Fatalf("luksFormat ran from %s", out.State)
	}
	h.checkReady(d, id, k)
	if strings.Contains(h.journal(), "switch_root") {
		h.t.Fatal("a cut boot reached switch_root")
	}
}

func TestCutAtEveryPointEndsReady(t *testing.T) {
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	for _, c := range []struct {
		point string
		next  State
	}{
		{"f1", StateNew},
		{"f2-torn", StateNew},
		{"f2", StateResume},
		{"f3-format", StateResume},
		{"f3-open", StateResume},
		{"f4-torn", StateResume},
		{"f4", StateOpen},
		{"f5-torn", StateOpen},
		{"f5", StateOpen},
		{"4.1", StateOpen},
		{"copy", StateOpen},
		{"resize2fs", StateOpen},
		{"recovery-file", StateOpen},
		{"4.4", StateOpen},
		{"4.5-torn", StateOpen},
		{"4.5", StateOpen},
	} {
		t.Run(c.point, func(t *testing.T) {
			h := rootHarness(t)
			d := h.newDisk(testDisk)
			h.cutBoot(d, id, k, c.point)
			h.finishBoot(d, id, k, c.next)
		})
	}
}

func TestCutInsideHelpers(t *testing.T) {
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	for _, point := range []string{"f3-kill", "add-kill"} {
		for _, ms := range []int{0, 2, 5, 10, 20, 50, 100} {
			t.Run(fmt.Sprintf("%s-%dms", point, ms), func(t *testing.T) {
				h := rootHarness(t)
				d := h.newDisk(testDisk)
				h.cutBoot(d, id, k, point, fmt.Sprintf("CATHEDRAL_VMCUT_DELAY_MS=%d", ms))
				out, err, lines := h.boot(d, id, k)
				if err != nil || !out.Ready {
					// r3 7.2 cost: a header listing a keyslot whose material is not
					// written is broken. cryptsetup writing a keyslot's area before
					// the header that lists it is what this run measures.
					t.Fatalf("a killed %s left state %s (err %v): cryptsetup's keyslot write order\n%s",
						point, out.State, err, strings.Join(lines, "\n"))
				}
				h.checkReady(d, id, k)
			})
		}
	}
}

// A cut on the boot after a cut. The second point is one the resumed boot
// passes again: F2 and F4 are not rerun (resume starts at F3, an F4 meta
// makes the disk open), so they pair with the next step that is.
func TestCutTwiceEndsReady(t *testing.T) {
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	for _, c := range []struct {
		first, second string
		next          State
	}{
		{"f2", "f3-format", StateResume},
		{"f3-format", "f3-format", StateResume},
		{"f3-open", "f4-torn", StateResume},
		{"f4-torn", "f4-torn", StateResume},
		{"f4", "4.1", StateOpen},
		{"f5", "copy", StateOpen},
		{"4.4", "4.4", StateOpen},
		{"4.4", "4.1", StateOpen}, // the stray recovery slot removed, then cut
		{"4.5-torn", "4.5-torn", StateOpen},
	} {
		t.Run(c.first+" then "+c.second, func(t *testing.T) {
			h := rootHarness(t)
			d := h.newDisk(testDisk)
			h.cutBoot(d, id, k, c.first)
			h.cutBoot(d, id, k, c.second)
			h.finishBoot(d, id, k, c.next)
		})
	}
}

func TestCutThenBundleChange(t *testing.T) {
	id, k1, k2 := testID(t, "vm-0123456789ab"), newKey(1), newKey(2)
	t.Run("before a header exists, the new bundle resumes", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.cutBoot(d, id, k1, "f2")
		h.finishBoot(d, id, k2, StateResume)
	})
	t.Run("after F3, broken until the old bundle is restored", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.cutBoot(d, id, k1, "f3-format")
		h.mustRefuse(d, id, k2, StateBroken)
		h.finishBoot(d, id, k1, StateResume)
	})
	t.Run("after F4, broken for the new bundle while the intent stands", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.cutBoot(d, id, k1, "f4")
		h.mustRefuse(d, id, k2, StateBroken)
		h.finishBoot(d, id, k1, StateOpen)
	})
	t.Run("after F5, locked for the new bundle, ready for the old", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.cutBoot(d, id, k1, "f5")
		h.mustRefuse(d, id, k2, StateLocked)
		h.finishBoot(d, id, k1, StateOpen)
	})
}

func TestCutCraftedHeaders(t *testing.T) {
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	t.Run("a header with no keyslot resumes", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.cutBoot(d, id, k, "f3-format")
		h.cryptsetupOn(d, nil, "luksErase", "--batch-mode", "DEV")
		h.finishBoot(d, id, k, StateResume)
	})
	t.Run("only the primary header copy resumes", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.cutBoot(d, id, k, "f3-format")
		d.writeAt(16384, make([]byte, 16384)) // the secondary copy of a 16 KiB header
		h.finishBoot(d, id, k, StateResume)
	})
	t.Run("a keyslot with no key material is broken", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.cutBoot(d, id, k, "f3-format")
		// Slot 0's area (luksDump: offset 32768, 258048 bytes) never written.
		d.writeAt(32768, make([]byte, 258048))
		h.mustRefuse(d, id, k, StateBroken)
	})
}
