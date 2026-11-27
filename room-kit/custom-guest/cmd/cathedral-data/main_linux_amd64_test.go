package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/datavolume"
)

const goodPin = "0202020202020202020202020202020202020202020202020202020202020202"
const secret = "owner passphrase 91c2"

type fakeDisk struct {
	datavolume.LockedCandidate
	closed int
}

func (f *fakeDisk) Close() error { f.closed++; return nil }

type harness struct {
	d        deps
	unlocked [][]byte
	opened   []int64
	disk     *fakeDisk
}

func newHarness(t *testing.T, stdin *os.File) *harness {
	h := &harness{disk: &fakeDisk{}}
	h.d = deps{
		stdin: stdin, euid: 0, pin: goodPin, readLimit: time.Second,
		isTerminal: func(*os.File) bool { return false },
		launch: func() (bootstrap.Launch, error) {
			var l bootstrap.Launch
			l.Manifest.DataDiskGiB = 8
			return l, nil
		},
		open: func(gib int64, _ [32]byte) (candidate, error) {
			h.opened = append(h.opened, gib)
			return h.disk, nil
		},
		unlock: func(_ context.Context, _ datavolume.LockedCandidate, p []byte) error {
			h.unlocked = append(h.unlocked, append([]byte(nil), p...))
			return nil
		},
	}
	return h
}

func pipeWith(t *testing.T, data []byte, closeWriter bool) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	go func() {
		w.Write(data)
		if closeWriter {
			w.Close()
		}
	}()
	return r
}

func TestUnlockPassesExactBytesAndHidesThem(t *testing.T) {
	h := newHarness(t, pipeWith(t, []byte(secret+"\n"), true))
	out, err := run([]string{"unlock"}, h.d)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.unlocked) != 1 || string(h.unlocked[0]) != secret+"\n" {
		t.Fatalf("passphrase altered: %q", h.unlocked)
	}
	if len(h.opened) != 1 || h.opened[0] != 8 || h.disk.closed != 1 {
		t.Fatalf("opened=%v closed=%d", h.opened, h.disk.closed)
	}
	printed, _ := json.Marshal(out)
	if strings.Contains(string(printed), secret) || out["status"] != "unlocked" {
		t.Fatalf("output %s", printed)
	}
}

func TestUnlockFailureClosesDiskAndNamesNoSecret(t *testing.T) {
	h := newHarness(t, pipeWith(t, []byte(secret), true))
	h.d.unlock = func(context.Context, datavolume.LockedCandidate, []byte) error {
		return errors.New("data volume unlock failed")
	}
	_, err := run([]string{"unlock"}, h.d)
	if err == nil || strings.Contains(err.Error(), secret) || h.disk.closed != 1 {
		t.Fatalf("err=%v closed=%d", err, h.disk.closed)
	}
}

func TestOnlyUnlockWithNoExtraArguments(t *testing.T) {
	for _, args := range [][]string{nil, {}, {"unlock", "extra"}, {"unlock", "--passphrase=" + secret},
		{"--passphrase", secret}, {"format"}, {"lock"}, {"unlock "}} {
		h := newHarness(t, pipeWith(t, []byte(secret), true))
		if _, err := run(args, h.d); err == nil {
			t.Fatalf("%q accepted", args)
		}
		if len(h.unlocked) != 0 || len(h.opened) != 0 {
			t.Fatalf("%q reached the disk", args)
		}
	}
}

func TestNotRootRefusedBeforeReadingStdin(t *testing.T) {
	in := pipeWith(t, []byte(secret), true)
	h := newHarness(t, in)
	h.d.euid = 1000
	if _, err := run([]string{"unlock"}, h.d); err == nil {
		t.Fatal("non-root accepted")
	}
	// Nothing was consumed: the secret is still in the pipe.
	buf := make([]byte, 64)
	n, _ := in.Read(buf)
	if string(buf[:n]) != secret {
		t.Fatalf("stdin consumed before the root check: %q", buf[:n])
	}
}

func TestMissingOrBadPinRefused(t *testing.T) {
	for _, pin := range []string{"", strings.Repeat("0", 64), goodPin[:62], strings.Repeat("AB", 32)} {
		h := newHarness(t, pipeWith(t, []byte(secret), true))
		h.d.pin = pin
		if _, err := run([]string{"unlock"}, h.d); err == nil || len(h.opened) != 0 {
			t.Fatalf("pin %q accepted", pin)
		}
	}
}

// openPTY returns the slave side of a fresh pseudo-terminal.
func openPTY(t *testing.T) *os.File {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() { master.Close() })
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), 0x40045431, uintptr(unsafe.Pointer(&unlock))); e != 0 { // TIOCSPTLCK
		t.Skipf("pty unlock: %v", e)
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, master.Fd(), 0x80045430, uintptr(unsafe.Pointer(&n))); e != 0 { // TIOCGPTN
		t.Skipf("pty number: %v", e)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("pty slave: %v", err)
	}
	t.Cleanup(func() { slave.Close() })
	return slave
}

func TestTerminalStdinRefused(t *testing.T) {
	tty := openPTY(t)
	if !isTerminal(tty) {
		t.Fatal("a pty slave was not recognised as a terminal")
	}
	pipe, _, _ := os.Pipe()
	if isTerminal(pipe) {
		t.Fatal("a pipe was taken for a terminal")
	}
	h := newHarness(t, tty)
	h.d.isTerminal = isTerminal
	if _, err := run([]string{"unlock"}, h.d); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Fatalf("err=%v", err)
	}
	if len(h.opened) != 0 || len(h.unlocked) != 0 {
		t.Fatal("terminal session reached the disk")
	}
}

func TestPassphraseSizeBounds(t *testing.T) {
	for name, tc := range map[string]struct {
		size int
		ok   bool
	}{"empty": {0, false}, "one": {1, true}, "4096": {4096, true}, "4097": {4097, false}, "huge": {1 << 20, false}} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, pipeWith(t, bytes.Repeat([]byte("p"), tc.size), true))
			_, err := run([]string{"unlock"}, h.d)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v", err)
			}
			if !tc.ok && (len(h.opened) != 0 || len(h.unlocked) != 0) {
				t.Fatal("refused passphrase reached the disk")
			}
		})
	}
}

func TestStdinThatNeverClosesTimesOut(t *testing.T) {
	h := newHarness(t, pipeWith(t, []byte(secret), false))
	h.d.readLimit = 100 * time.Millisecond
	start := time.Now()
	if _, err := run([]string{"unlock"}, h.d); err == nil {
		t.Fatal("unterminated passphrase accepted")
	}
	if time.Since(start) > 5*time.Second || len(h.opened) != 0 {
		t.Fatal("did not time out cleanly")
	}
}

func TestNoDataDiskOrBadLaunchRefused(t *testing.T) {
	for _, gib := range []int64{0, -1, 401} {
		h := newHarness(t, pipeWith(t, []byte(secret), true))
		h.d.launch = func() (bootstrap.Launch, error) {
			var l bootstrap.Launch
			l.Manifest.DataDiskGiB = gib
			return l, nil
		}
		if _, err := run([]string{"unlock"}, h.d); err == nil || len(h.opened) != 0 {
			t.Fatalf("data_disk_gib %d accepted", gib)
		}
	}
	h := newHarness(t, pipeWith(t, []byte(secret), true))
	h.d.launch = func() (bootstrap.Launch, error) { return bootstrap.Launch{}, errors.New("unbound") }
	if _, err := run([]string{"unlock"}, h.d); err == nil || len(h.opened) != 0 {
		t.Fatal("unbound launch accepted")
	}
}
