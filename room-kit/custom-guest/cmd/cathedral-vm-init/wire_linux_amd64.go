package main

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmmailbox"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmroot"
)

// The tools the root setup runs or binds, named as in the initrd closure
// (room-kit/vm/vm_initrd_closure.json). The pins come from the measured
// usr/lib/cathedral/vm-closure.json, never from the host or the root disk.
const (
	verityName  = "usr/lib/cathedral/veritysetup"
	resizeName  = "usr/lib/cathedral/resize2fs"
	attestName  = "usr/lib/cathedral/cathedral-vm-attest"
	vmToolName  = "usr/lib/cathedral/cathedral-vm"
	attestAs    = "cathedral-attest"
	vmToolAs    = "cathedral-vm"
	newRootPath = "" // vmroot's default, /newroot
)

// rootAdapter is the Root seam over internal/vmroot. A manifest that lacks a pin gives an adapter
// whose every call refuses: nothing runs on a root whose tools are not pinned.
type rootAdapter struct {
	release string
	verity  vmroot.Tool
	resize  vmroot.Tool
	binds   []vmroot.Bind
	err     error
}

func newRootAdapter(m manifest) rootAdapter {
	a := rootAdapter{release: m.KernelRelease}
	for name, dst := range map[string]*vmroot.Tool{verityName: &a.verity, resizeName: &a.resize} {
		t, err := m.tool(name, name[strings.LastIndex(name, "/")+1:])
		if err != nil {
			a.err = err
			return a
		}
		*dst = vmroot.Tool{Path: t.Path, SHA256: t.SHA256}
	}
	// The two tools the customer runs are bound from the initrd, which is measured. Their pins must
	// still be in the manifest, so a closure that drops one is refused here.
	for _, name := range []string{attestName, vmToolName} {
		if _, ok := m.Executables[name]; !ok {
			a.err = errors.New("initrd manifest pins no " + name)
			return a
		}
	}
	a.binds = []vmroot.Bind{{Source: "/" + attestName, Name: attestAs}, {Source: "/" + vmToolName, Name: vmToolAs}}
	return a
}

func (a rootAdapter) CheckLink(raw []byte) error {
	if a.err != nil {
		return a.err
	}
	_, err := vmroot.ParseLink(raw)
	return err
}

// FirstBoot is r3 7.2 steps 4.2 and 4.3. vmroot leaves the root mounted for the step that follows
// it in the init; the disk package adds the keyslot (4.4) and writes meta ready on an unmounted fs
// area and reopens it for step 5, so the mount ends here.
func (a rootAdapter) FirstBoot(ctx context.Context, fsArea *os.File, base Base, id vmidentity.Identity, cut func(string) error) ([32]byte, error) {
	var zero [32]byte
	if a.err != nil {
		return zero, a.err
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	m, rec, err := vmroot.FirstBoot(vmroot.FirstBootConfig{
		Verity: a.verity, Resize2fs: a.resize, FS: fsArea,
		Base: vmroot.Base{File: base.File, DiskBytes: base.DiskBytes, DataBytes: base.DataBytes, RootHash: base.RootHash},
		Tree: vmroot.TreeOptions{
			Identity: vmroot.Identity{VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), SSHPublicKey: id.SSHPublicKey},
			Random:   rand.Reader, Cut: cut,
		},
	})
	if err != nil {
		return zero, err
	}
	if err := m.UnmountStrict(); err != nil {
		return zero, err
	}
	return rec.Key, nil
}

// Start is step 5: mount, then the runtime binds, network file and cloud-init marker, then ready (the
// status record) and switch_root. vmroot calls ready first and moves nothing unless it returns nil.
func (a rootAdapter) Start(ctx context.Context, fsArea *os.File, link []byte, ready func() error) error {
	if a.err != nil {
		return a.err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m, err := vmroot.Mount(fsArea, newRootPath)
	if err != nil {
		return err
	}
	if err := m.Finish(vmroot.FinishConfig{Link: link, KernelRelease: a.release, Tools: a.binds}); err != nil {
		return err
	}
	return m.SwitchRoot(ready)
}

// mailboxAdapter is the Mailbox seam over internal/vmmailbox. f is the mailbox disk the init opened
// with O_DIRECT (mailboxFlags) after proving the node is the block device sysfs names; vmmailbox.New
// checks its size, and every read and write is an aligned 64 KiB slot. The offer slot is zeroed on
// this boot, which is not waiting for an answer (r3 7.5), then the status is written.
type mailboxAdapter struct{}

func (mailboxAdapter) WriteStatus(f *os.File, size int64, state, keyID string, report []byte) error {
	m, err := vmmailbox.New(f, size)
	if err != nil {
		return err
	}
	if err := m.ZeroOffer(); err != nil {
		return err
	}
	return m.WriteStatus(vmmailbox.Status{State: state, KeyID: keyID, Report: report})
}
