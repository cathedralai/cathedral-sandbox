package main

// The VM initrd disk check (vm-bundle-build.yml, job initrd-check). This test binary runs as PID 1
// of a plain QEMU guest (no SNP), booted from the bundle's kernel and the built VM initrd, with
// the binary appended to the initrd as one more cpio. From there it drives the real platform: the
// initrd's closure and module list, its pinned cryptsetup, the init's /run, and vmdisk's first
// boot on virtio disks (F1 to F5: luksFormat, open, the meta copies and luksAddKey), in the
// initramfs the init itself boots in. B2's boot 2 powered off at F3 because that initramfs had no
// /run for cryptsetup's LUKS2 lock. The other tests run the tools on a runner, where /run exists.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmdisk"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
)

// initrdCheckPass is the line the workflow looks for on the guest's serial console.
const initrdCheckPass = "INITRD-CHECK: PASS"

func TestInitrdDiskCheck(t *testing.T) {
	if os.Getpid() != 1 || os.Getenv("CATHEDRAL_INITRD_CHECK") != "1" {
		t.Skip("PID 1 of the initrd check VM (vm-bundle-build.yml)")
	}
	// The mounts bootstate.PrepareKernelViews makes. Its SNP device and configfs steps need SNP.
	const readonly = syscall.MS_RDONLY | syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC
	for _, m := range []struct {
		path, kind, data string
		flags            uintptr
	}{
		{"/proc", "proc", "", readonly},
		{"/sys", "sysfs", "", readonly},
		{"/dev", "devtmpfs", "mode=0755", syscall.MS_NOSUID | syscall.MS_NOEXEC},
	} {
		if err := os.Mkdir(m.path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
		if err := syscall.Mount(m.kind, m.path, m.kind, m.flags, m.data); err != nil {
			t.Fatalf("mount %s: %v", m.path, err)
		}
	}
	// The check starts where the init does: the initrd has no /run until Disk makes it.
	if _, err := os.Lstat(lockParent); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists before Disk (%v): the check no longer matches the init's start", lockParent, err)
	}

	// LoadModules as the init runs it, except that sev-guest finds no SNP device here.
	p := &linuxPlatform{}
	raw, err := readBounded(closurePath, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if p.manifest, err = parseManifest(raw); err != nil {
		t.Fatal(err)
	}
	if got := kernelRelease(); got != p.manifest.KernelRelease {
		t.Fatalf("kernel %q is not the initrd's %q", got, p.manifest.KernelRelease)
	}
	if p.cryptsetup, err = p.manifest.tool(cryptsetupName, "cryptsetup"); err != nil {
		t.Fatal(err)
	}
	if raw, err = readBounded(modulesListPath, 64<<10); err != nil {
		t.Fatal(err)
	}
	list, err := parseModules(raw, p.manifest.KernelRelease)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range list {
		err := loadModule("/" + m)
		if strings.Contains(m, "/sev-guest/") && errors.Is(err, syscall.ENODEV) {
			t.Logf("%s: no SNP device in this guest (%v)", m, err)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("loaded %s", m)
	}
	if err := p.CryptsetupFloor(); err != nil {
		t.Fatal(err)
	}

	devices, err := p.Devices()
	if err != nil {
		t.Fatal(err)
	}
	id, err := vmidentity.Parse(identityDoc("vm-0123456789ab"))
	if err != nil {
		t.Fatal(err)
	}
	var pass [32]byte
	if _, err := rand.Read(pass[:]); err != nil {
		t.Fatal(err)
	}
	var measurement [48]byte
	measurement[0], measurement[47] = 0xaa, 0xbb
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	out, err := p.Disk(ctx, vmdisk.Config{Disk: devices.Root, DiskBytes: devices.RootBytes, Identity: id,
		Passphrase: pass[:], Measurement: measurement, Names: vmdisk.DefaultNames, Setup: checkSetup{},
		Log: func(s string) { t.Log(s) }})
	if err != nil {
		t.Fatalf("Disk: %v", err)
	}
	if out.State != vmdisk.StateNew || !out.Ready || out.FSArea == nil {
		t.Fatalf("first boot: state %v, ready %v, file system area %v", out.State, out.Ready, out.FSArea != nil)
	}
	if fi, err := os.Lstat(lockParent + "/cryptsetup"); err != nil || !fi.IsDir() {
		t.Fatalf("cryptsetup's lock directory: %v", err)
	}
	t.Logf("first boot: state %v, slot %d, ready", out.State, out.Slot)
	if t.Failed() {
		return
	}
	fmt.Println(initrdCheckPass)
	syscall.Sync()
	time.Sleep(time.Second) // let the serial console drain before the power-off
	syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
}

// checkSetup stands in for vmroot, whose base image copy needs the real base root: as vmdisk's
// fakeSetup, it writes one block of the file system area and returns a new recovery key.
type checkSetup struct{}

func (checkSetup) FirstBoot(_ context.Context, fs *os.File, _ func(string) error) ([32]byte, error) {
	var recovery [32]byte
	block := make([]byte, 4096)
	copy(block, "CVM-INITRD-CHECK")
	if _, err := fs.WriteAt(block, 0); err != nil {
		return recovery, err
	}
	if err := fs.Sync(); err != nil {
		return recovery, err
	}
	_, err := rand.Read(recovery[:])
	return recovery, err
}
