package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/snp"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmdisk"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmkey"
)

// Devices are the three virtio disks the launcher attaches, by serial
// (launch-vm.py:145; errata 27 Nov 14:44Z).
type Devices struct {
	Root        *os.File
	RootBytes   int64
	Base        *os.File
	BaseBytes   int64
	Mailbox     *os.File
	MailboxSize int64
}

// Root is the VM root setup (internal/vmroot, PR C), behind this seam until
// the wiring commit.
type Root interface {
	// CheckLink refuses a malformed fw_cfg link before any disk is opened.
	CheckLink(raw []byte) error
	// FirstBoot is r3 7.2 steps 4.2 and 4.3 (vmroot.FirstBoot): it returns R
	// with nothing left mounted on fsArea.
	FirstBoot(ctx context.Context, fsArea *os.File, base Base, id vmidentity.Identity, cut func(string) error) ([32]byte, error)
	// Start is step 5 (vmroot Mount, Finish, SwitchRoot): it calls ready,
	// which writes the status record, before anything moves, and does not
	// return on success.
	Start(ctx context.Context, fsArea *os.File, link []byte, ready func() error) error
}

// Base is the read-only base disk and the identity's pin on it.
type Base struct {
	File      *os.File
	DiskBytes int64
	DataBytes int64
	RootHash  string
}

// Mailbox writes the status record (internal/vmmailbox, PR C).
type Mailbox interface {
	WriteStatus(f *os.File, size int64, state, keyID string, report []byte) error
}

// platform is everything a boot touches. linuxPlatform is the real one; the
// tests use a fake that records what ran, in order.
type platform interface {
	LoadModules() error
	PrepareKernel() error
	Firmware() (identity, link []byte, err error)
	Cmdline() (string, error)
	Entropy([]byte) error
	Report(data [64]byte) ([]byte, error)
	DeriveKey(hostData [32]byte) (vmkey.Material, error)
	CryptsetupFloor() error
	Devices() (Devices, error)
	Disk(ctx context.Context, cfg vmdisk.Config) (vmdisk.Outcome, error)
	Root() Root
	Mailbox() Mailbox
	Log(string)
}

// AMD SEV-SNP ABI report offsets (snp.CheckLocal checks HOST_DATA at 0xc0).
const reportMeasurement = 0x90

// rootSetup adapts Root to vmdisk.Setup with this boot's base disk.
type rootSetup struct {
	root Root
	base Base
	id   vmidentity.Identity
}

func (s rootSetup) FirstBoot(ctx context.Context, fsArea *os.File, cut func(string) error) ([32]byte, error) {
	return s.root.FirstBoot(ctx, fsArea, s.base, s.id, cut)
}

// boot is r3 7.2 in order. It returns only an error, after which main powers
// off: on success Root().Start does not return. A disk that may not boot
// (locked, tampered, broken) gets its status record first.
func boot(ctx context.Context, p platform) error {
	if err := p.LoadModules(); err != nil {
		return fmt.Errorf("modules: %w", err)
	}
	if err := p.PrepareKernel(); err != nil {
		return fmt.Errorf("kernel views: %w", err)
	}

	// Step 1: the identity against the cmdline and HOST_DATA, before any disk.
	identityRaw, link, err := p.Firmware()
	if err != nil {
		return fmt.Errorf("fw_cfg: %w", err)
	}
	line, err := p.Cmdline()
	if err != nil {
		return fmt.Errorf("cmdline: %w", err)
	}
	id, err := vmidentity.Check(identityRaw, line)
	if err != nil {
		return err
	}
	if err := p.Root().CheckLink(link); err != nil {
		return err
	}
	var nonce [32]byte
	if err := p.Entropy(nonce[:]); err != nil {
		return fmt.Errorf("boot entropy: %w", err)
	}
	data := snp.BootData(nonce)
	report, err := p.Report(data)
	if err != nil {
		return fmt.Errorf("boot report: %w", err)
	}
	hostData := id.HostData()
	if err := snp.CheckLocal(report, data, &hostData); err != nil {
		return fmt.Errorf("boot report: %w", err)
	}
	var measurement [48]byte
	copy(measurement[:], report[reportMeasurement:reportMeasurement+48])
	p.Log("vm-init: identity " + id.SHA256Hex() + " matches the cmdline and HOST_DATA; measurement " +
		hex.EncodeToString(measurement[:]))

	// Step 2: the key.
	key, err := p.DeriveKey(hostData)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	defer key.Clear()
	if err := p.CryptsetupFloor(); err != nil {
		return err
	}

	// Steps 3 and 4: the root disk.
	devices, err := p.Devices()
	if err != nil {
		return fmt.Errorf("devices: %w", err)
	}
	base := Base{File: devices.Base, DiskBytes: devices.BaseBytes, DataBytes: id.BaseRootDataBytes, RootHash: id.BaseRootVerity}
	out, err := p.Disk(ctx, vmdisk.Config{Disk: devices.Root, DiskBytes: devices.RootBytes, Identity: id,
		Passphrase: key.Passphrase[:], Measurement: measurement, Names: vmdisk.DefaultNames,
		Setup: rootSetup{root: p.Root(), base: base, id: id}, Log: p.Log})
	key.Clear()
	if err != nil {
		return fmt.Errorf("root disk: %w", err)
	}
	status, err := p.Report([64]byte{})
	if err != nil {
		return fmt.Errorf("status report: %w", err)
	}
	writeStatus := func() error {
		return p.Mailbox().WriteStatus(devices.Mailbox, devices.MailboxSize, out.State.HostState(), key.KeyID, status)
	}
	if !out.Ready {
		// locked, tampered or broken, and untouched. The re-wrap of a locked
		// disk (r3 7.5, VM6) is not in this init yet: the host reads the
		// state and the VM stays off.
		if err := writeStatus(); err != nil {
			return fmt.Errorf("status: %w", err)
		}
		return fmt.Errorf("root disk %s: %s", out.State, out.Why)
	}
	if out.Meta.State != vmdisk.StateReady || out.FSArea == nil {
		return errors.New("root disk not ready")
	}

	// Step 5: the root, the status record, switch_root.
	p.Log("vm-init: root disk " + out.State.String() + ", meta ready; starting the root")
	return p.Root().Start(ctx, out.FSArea, link, func() error {
		if out.Meta.State != vmdisk.StateReady {
			return errors.New("root disk not ready")
		}
		if err := writeStatus(); err != nil {
			return fmt.Errorf("status: %w", err)
		}
		p.Log("vm-init: status " + out.State.HostState() + " written; switch_root")
		return nil
	})
}
