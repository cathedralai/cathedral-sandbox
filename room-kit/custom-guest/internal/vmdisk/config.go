package vmdisk

import (
	"context"
	"errors"
	"io"
	"os"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
)

// Tool is a helper binary pinned by sha256 in measured code (the VM
// initrd's closure), never chosen by the host or a disk.
type Tool struct {
	Path   string
	SHA256 [32]byte
	Name   string // argv[0]
}

// Names are the device-mapper names the init owns. A boot refuses to start
// if any of them already exists.
type Names struct {
	LUKS  string // dm-linear: the LUKS device, root.raw from 0 without the intent area
	Probe string // the read-only crypt mapping the classifier reads meta through
	Crypt string // the read-write crypt mapping of the volume
	FS    string // dm-linear: the file system area, the volume from 16 MiB
}

var DefaultNames = Names{LUKS: "cathedral-vm-luks", Probe: "cathedral-vm-probe", Crypt: "cathedral-vm-crypt", FS: "cathedral-vm-fs"}

func (n Names) all() []string { return []string{n.FS, n.Crypt, n.Probe, n.LUKS} }

// Setup is spec r3 7.2 steps 4.2 and 4.3 on the file system area (vmroot,
// PR C): copy the verified base image, resize2fs, user cathedral, host
// keys, cloud-init off, sync; then write the recovery key file; sync. It
// calls cut after each of its own steps.
type Setup interface {
	FirstBoot(ctx context.Context, fsArea *os.File, recovery []byte, cut func(string) error) error
}

// Config is one boot's disk inputs.
type Config struct {
	Disk        *os.File // the whole root.raw block device, O_RDWR, held for the boot
	DiskBytes   int64
	Identity    vmidentity.Identity
	Passphrase  []byte   // this boot's key (vmkey); the caller clears it after Run
	Measurement [48]byte // this boot's MEASUREMENT, from its checked report
	Cryptsetup  Tool
	Names       Names
	Setup       Setup
	Random      io.Reader // the recovery key R
	Log         func(string)
}

// Outcome is the result of one boot's disk work. Ready means the volume is
// open with meta ready and FSArea is the file system area; only then may
// the caller mount it and switch_root.
type Outcome struct {
	State  State
	Why    string
	Slot   int
	Ready  bool
	Meta   Meta
	FSArea *os.File
}

func (c Config) check() error {
	switch {
	case c.Disk == nil, len(c.Passphrase) != 32, c.Measurement == [48]byte{}, c.Setup == nil, c.Random == nil,
		c.Log == nil, c.Identity.VMID == "":
		return errors.New("disk config incomplete")
	}
	for _, name := range c.Names.all() {
		if name == "" || len(name) > 127 {
			return errors.New("disk mapping names invalid")
		}
	}
	return nil
}
