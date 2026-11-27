//go:build vmcuttest

package vmdisk

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// The T5 cut hook (spec r3 13.1): a test build only. The environment
// variable CATHEDRAL_VMCUT names one point; the process dies by SIGKILL
// there, as a power cut would stop it, and the test makes the next boot.
//   <point>       after that step's write and flush
//   <point>-torn  a record write of which only a prefix lands
//   <point>-kill  a helper killed CATHEDRAL_VMCUT_DELAY_MS after its start

const CutHook = true

func vmcuttestArmed(point string) bool { return os.Getenv("CATHEDRAL_VMCUT") == point }

func vmcuttestDie() {
	syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {}
}

func cutAfter(point string) {
	if vmcuttestArmed(point) {
		vmcuttestDie()
	}
}

// tornWrite gives the bytes a cut mid-write leaves: the first part of the
// record's meaningful bytes over what the area held before.
func tornWrite(point string, old, write []byte) ([]byte, bool) {
	if !vmcuttestArmed(point + "-torn") {
		return write, false
	}
	n := 64
	if s, err := strconv.Atoi(os.Getenv("CATHEDRAL_VMCUT_BYTES")); err == nil && s > 0 && s < len(write) {
		n = s
	}
	out := append([]byte(nil), old...)
	copy(out[:n], write[:n])
	return out, true
}

func runWithCut(point string, cmd *exec.Cmd) error {
	if !vmcuttestArmed(point + "-kill") {
		return cmd.Run()
	}
	delay, _ := strconv.Atoi(os.Getenv("CATHEDRAL_VMCUT_DELAY_MS"))
	if err := cmd.Start(); err != nil {
		return err
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
	cmd.Process.Signal(syscall.SIGKILL)
	cmd.Wait()
	vmcuttestDie()
	return nil
}
