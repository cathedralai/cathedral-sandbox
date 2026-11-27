//go:build !vmcuttest

package vmdisk

import "os/exec"

// The published init has no cut hook: these are the identities the
// vmcuttest build replaces (cut_vmcuttest.go). A test proves the untagged
// binary carries none of the hook's names.

func cutAfter(string) {}

func tornWrite(_ string, _, write []byte) ([]byte, bool) { return write, false }

func runWithCut(_ string, cmd *exec.Cmd) error { return cmd.Run() }

// CutHook reports whether this build has the test cut hook.
const CutHook = false
