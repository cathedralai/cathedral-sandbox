// Command cathedral-data is the owner's data volume unlock (spec 5.6, "Data
// disk"). It runs inside the verified guest, over the owner-bound SSH session,
// after the owner's report check has passed:
//
//	printf '%s' "$PASSPHRASE" | ssh guest cathedral-data unlock
//
// The passphrase arrives on stdin only. It is never an argument, never in the
// environment, and a terminal is refused rather than echoed. The first run on a
// blank signed disk formats LUKS2/XTS/HMAC and ext4; every later run opens it.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"syscall"
	"time"
	"unsafe"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/datavolume"
)

// pinCryptsetupSHA256 is linked in by scripts/build_custom_guest_helper.py
// (-X main.pinCryptsetupSHA256=...). An unlinked build refuses to run.
var pinCryptsetupSHA256 string

const (
	passphraseTimeout = 30 * time.Second
	// The integrity wipe on first format dominates; 400 GiB is the signed cap.
	unlockTimeout = 6 * time.Hour
)

type candidate interface {
	datavolume.LockedCandidate
	Close() error
}

type deps struct {
	stdin      *os.File
	euid       int
	pin        string
	readLimit  time.Duration
	isTerminal func(*os.File) bool
	launch     func() (bootstrap.Launch, error)
	open       func(gib int64, pin [32]byte) (candidate, error)
	unlock     func(context.Context, datavolume.LockedCandidate, []byte) error
}

func isTerminal(f *os.File) bool {
	var termios [64]byte
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0x5401, uintptr(unsafe.Pointer(&termios[0]))) // TCGETS
	return errno == 0
}

// readSecret bounds the wait as well as the size: a session that never sends
// or never closes stdin cannot hold the disk lock.
func readSecret(f *os.File, limit time.Duration) ([]byte, error) {
	type outcome struct {
		secret []byte
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		secret, err := datavolume.ReadPassphrase(f)
		done <- outcome{secret, err}
	}()
	select {
	case o := <-done:
		return o.secret, o.err
	case <-time.After(limit):
		return nil, errors.New("passphrase not received in time; close stdin after sending it")
	}
}

func run(args []string, d deps) (map[string]any, error) {
	if len(args) != 1 || args[0] != "unlock" {
		return nil, errors.New("usage: cathedral-data unlock  (passphrase on stdin)")
	}
	if d.euid != 0 {
		return nil, errors.New("root required")
	}
	raw, err := hex.DecodeString(d.pin)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != d.pin || [32]byte(raw) == [32]byte{} {
		return nil, errors.New("cryptsetup pin missing or invalid")
	}
	pin := [32]byte(raw)
	if d.isTerminal(d.stdin) {
		return nil, errors.New("passphrase must be piped on stdin, not typed on a terminal")
	}
	secret, err := readSecret(d.stdin, d.readLimit)
	if err != nil {
		return nil, err
	}
	// Unlock clears the secret on every return. This covers the paths before it.
	launch, err := d.launch()
	if err != nil {
		clear(secret)
		return nil, err
	}
	gib := launch.Manifest.DataDiskGiB
	if gib < 1 || gib > 400 {
		clear(secret)
		return nil, errors.New("signed launch has no data disk")
	}
	disk, err := d.open(gib, pin)
	if err != nil {
		clear(secret)
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), unlockTimeout)
	defer cancel()
	err = d.unlock(ctx, disk, secret)
	// Release the descriptors and lock. A successful mapping and mount persist.
	closeErr := disk.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, errors.New("data disk release failed")
	}
	return map[string]any{"status": "unlocked", "mount": datavolume.MountPoint, "data_disk_gib": gib}, nil
}

func main() {
	out, err := run(os.Args[1:], deps{
		stdin: os.Stdin, euid: os.Geteuid(), pin: pinCryptsetupSHA256,
		readLimit: passphraseTimeout, isTerminal: isTerminal, launch: bootstrap.ReadBoundLaunch,
		open: func(gib int64, pin [32]byte) (candidate, error) {
			d, err := datavolume.OpenData(gib, pin)
			if err != nil {
				return nil, err
			}
			return d, nil
		},
		unlock: datavolume.Unlock,
	})
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": "custom_guest_data_failed", "reason": err.Error()})
		os.Exit(1)
	}
	if err = json.NewEncoder(os.Stdout).Encode(out); err != nil {
		os.Exit(1)
	}
}
