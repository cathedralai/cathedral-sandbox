package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// The cut hook (internal/vmdisk cut_vmcuttest.go) is compiled in only by
// the vmcuttest tag. Build the init as build-vm-initrd.py does (PR C:
// static, -trimpath, stripped, no tags) and require that neither the tag
// nor the hook's environment name is in the bytes; the tagged build is the
// positive control that the search finds them.
func TestUntaggedInitHasNoCutHook(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the init twice")
	}
	goTool := "go"
	if root := runtime.GOROOT(); root != "" {
		goTool = filepath.Join(root, "bin", "go")
	}
	build := func(tags string) []byte {
		out := filepath.Join(t.TempDir(), "init")
		cmd := exec.Command(goTool, "build", "-trimpath", "-buildvcs=false", "-tags="+tags,
			"-ldflags=-s -w -buildid=", "-o", out, ".")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOFLAGS=-mod=readonly")
		if msg, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build -tags=%q: %v\n%s", tags, err, msg)
		}
		raw, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	markers := [][]byte{[]byte("vmcuttest"), []byte("CATHEDRAL_VMCUT")}
	plain := build("")
	for _, m := range markers {
		if bytes.Contains(plain, m) {
			t.Errorf("the untagged init contains %q", m)
		}
	}
	tagged := build("vmcuttest")
	for _, m := range markers {
		if !bytes.Contains(tagged, m) {
			t.Errorf("the vmcuttest init lacks %q: the search would miss the hook", m)
		}
	}
}
