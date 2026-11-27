// Command cathedral-init is the measured PID1 of the dedicated custom guest
// (spec 5.6). It runs the fixed boot stages and then execs the verified root's
// /sbin/init. Every failure, including a panic, powers the guest off: there is
// no retry, fallback root or shell.
package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstate"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

// Pins are linked into the measured binary by scripts/build_custom_guest_helper.py
// (-X main.pinVeritySHA256=... and main.pinReportSHA256=...). They are never read
// from the host, the command line or the root disk. An unlinked build has empty
// pins and refuses to boot.
var (
	pinVeritySHA256 string
	pinReportSHA256 string
)

// stages is the injectable surface of the boot sequence. Production wires the
// real bootstate/bootstrap calls; tests wire fakes to prove stage ordering.
type stages struct {
	views    func() error
	launch   func() (bootstrap.Launch, error)
	memory   func(bootstrap.Launch) error
	prepare  func(bootstrap.Launch, [32]byte, [32]byte) (execer, error)
	poweroff func()
	logf     func(format string, args ...any)
}

// execer is the consumed hand-off token. Exec never returns on success.
type execer interface{ Exec() error }

func pin(name, value string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != value || [32]byte(raw) == out {
		return out, fmt.Errorf("%s pin missing or invalid", name)
	}
	copy(out[:], raw)
	return out, nil
}

// boot runs the stages in order. It returns only after poweroff has been
// requested: a successful Exec replaces the process, so any return from Exec
// is a failure.
func boot(s stages, verity, report string) {
	defer func() {
		if r := recover(); r != nil {
			s.logf("cathedral-init: panic in boot stage")
			s.poweroff()
		}
	}()
	fail := func(stage string, err error) {
		s.logf("cathedral-init: %s: %v", stage, err)
		s.poweroff()
	}
	verityPin, err := pin("verity", verity)
	if err != nil {
		fail("pins", err)
		return
	}
	reportPin, err := pin("report", report)
	if err != nil {
		fail("pins", err)
		return
	}
	if err = s.views(); err != nil {
		fail("kernel views", err)
		return
	}
	launch, err := s.launch()
	if err != nil {
		fail("launch documents", err)
		return
	}
	if err = s.memory(launch); err != nil {
		fail("memory", err)
		return
	}
	ready, err := s.prepare(launch, verityPin, reportPin)
	if err != nil {
		fail("verified root", err)
		return
	}
	if ready == nil {
		fail("verified root", errors.New("no hand-off token"))
		return
	}
	// Exec only returns on failure; the token is consumed either way. A nil
	// return is impossible in production and is treated as failure too.
	err = ready.Exec()
	if err == nil {
		err = errors.New("exec returned")
	}
	fail("exec", err)
}

func production() stages {
	return stages{
		views:  bootstate.PrepareKernelViews,
		launch: bootstrap.ReadBoundLaunch,
		memory: bootstate.CheckMemory,
		prepare: func(l bootstrap.Launch, verity, report [32]byte) (execer, error) {
			ready, err := bootstate.PrepareVerifiedRuntime(l, verity, report)
			if err != nil {
				return nil, err
			}
			return ready, nil
		},
		poweroff: poweroff,
		logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	}
}

// poweroff syncs and powers the guest off. The measured launch runs QEMU with
// -no-reboot, so even a failed request ends in a kernel panic when PID1 exits.
func poweroff() {
	syscall.Sync()
	_ = syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	os.Exit(1)
}

func main() {
	boot(production(), pinVeritySHA256, pinReportSHA256)
	// Reached only if boot returned without exec (poweroff injected as a no-op).
	os.Exit(1)
}
