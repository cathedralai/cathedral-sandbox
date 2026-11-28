package main

// The VM initrd check (vm-bundle-build.yml, job initrd-check). This test binary runs as PID 1 of a
// plain QEMU guest (no SNP), booted from the bundle's kernel and the built VM initrd, with the
// binary appended to the initrd as one more cpio. From there it drives the real platform: the
// initrd's closure and module list, its pinned cryptsetup, the init's /run, vmdisk's first boot on
// virtio disks (F1 to F5: luksFormat, open, the meta copies and luksAddKey), then step 5 as the
// init runs it (mount, Finish and vmroot's switch_root) into a check root whose /sbin/init is this
// binary again. There it checks the kernel views the customer's systemd needs.
//
// B2's boot 2 powered off at F3 because the initramfs had no /run for cryptsetup's LUKS2 lock. B3
// booted Ubuntu with /proc and /sys read-only, so every unit with OOMScoreAdjust= failed and the
// guest got no network. B4 then ran the root setup under the init's umask 0077, so /run/systemd was
// root-only and every non-root service failed. The other tests run the tools on a runner, where
// none of this can happen.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmdisk"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
)

const (
	// initrdCheckPass is the line the workflow looks for on the guest's serial console. Only the
	// check root's /sbin/init prints it, after switch_root.
	initrdCheckPass = "INITRD-CHECK: PASS"
	// checkRootInit is how vmroot's SwitchRoot executes the root's init: this argv, nothing else.
	checkRootInit = "/sbin/init"
	// checkLink is the link the check gives Finish (RFC 1918, one /30).
	checkLink = "10.0.0.1 10.0.0.2"
	// probeEnv runs the binary as the unprivileged probe the check root's init starts.
	probeEnv = "CATHEDRAL_INITRD_CHECK_PROBE"
	// nobody is the uid and gid the probe drops to, as a non-root service runs.
	nobody = 65534
)

// TestMain is the check root's /sbin/init when the binary is PID 1 with vmroot's fixed argv: the
// switch_root passes no test flags and no environment beyond PATH, LANG and TERM.
func TestMain(m *testing.M) {
	if os.Getenv(probeEnv) == "1" && os.Getuid() == nobody {
		os.Exit(probeAsNobody())
	}
	if os.Getpid() == 1 && len(os.Args) == 1 && os.Args[0] == checkRootInit {
		afterSwitchRoot()
	}
	os.Exit(m.Run())
}

func TestInitrdDiskCheck(t *testing.T) {
	if os.Getpid() != 1 || os.Getenv("CATHEDRAL_INITRD_CHECK") != "1" {
		t.Skip("PID 1 of the initrd check VM (vm-bundle-build.yml)")
	}
	// The umask and mounts bootstate.PrepareKernelViews makes. Its SNP device and configfs steps
	// need SNP. The init keeps the umask for every later step, the root setup included.
	syscall.Umask(0o077)
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
		Passphrase: pass[:], Measurement: measurement, Names: vmdisk.DefaultNames,
		Setup: checkSetup{base: devices.Base, size: devices.BaseBytes},
		Log:   func(s string) { t.Log(s) }})
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

	// Step 5 as boot_linux_amd64.go runs it, with the status record left out: the platform's own
	// Root mounts the file system area, runs Finish and switches into it. Success never returns.
	err = p.Root().Start(ctx, out.FSArea, []byte(checkLink), func() error {
		t.Log("switch_root into the check root")
		return nil
	})
	t.Fatalf("switch_root returned: %v", err)
}

// checkSetup stands in for vmroot's first boot, whose verity copy needs a real base root. It copies
// the base disk (the check root the workflow built) into the file system area, as vmroot copies the
// base root, and returns a new recovery key.
type checkSetup struct {
	base *os.File
	size int64
}

func (s checkSetup) FirstBoot(_ context.Context, fs *os.File, _ func(string) error) ([32]byte, error) {
	var recovery [32]byte
	if _, err := io.Copy(io.NewOffsetWriter(fs, 0), io.NewSectionReader(s.base, 0, s.size)); err != nil {
		return recovery, fmt.Errorf("copy the check root: %w", err)
	}
	if err := fs.Sync(); err != nil {
		return recovery, err
	}
	_, err := rand.Read(recovery[:])
	return recovery, err
}

// afterSwitchRoot is the check root's init. It prints the pass line only if the kernel views it was
// handed work as systemd uses them, then powers off either way.
func afterSwitchRoot() {
	if err := checkKernelViews(); err != nil {
		fmt.Println("INITRD-CHECK: FAIL after switch_root:", err)
	} else {
		fmt.Println(initrdCheckPass)
	}
	syscall.Sync()
	time.Sleep(time.Second) // let the serial console drain before the power-off
	syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	os.Exit(1)
}

func checkKernelViews() error {
	// systemd writes OOMScoreAdjust= (journald -250, dbus -900) here and fails the unit on EROFS.
	if err := writeKernelFile("/proc/self/oom_score_adj", "-250\n"); err != nil {
		return err
	}
	got, err := os.ReadFile("/proc/self/oom_score_adj")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(got)) != "-250" {
		return fmt.Errorf("oom_score_adj reads %q after writing -250", got)
	}
	// udev's coldplug writes add or change to every device's uevent file; networkd waits for udev.
	if err := writeKernelFile("/sys/devices/virtual/mem/null/uevent", "change\n"); err != nil {
		return err
	}
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	if err := mountsWritable(info, map[string]string{"/proc": "proc", "/sys": "sysfs"}); err != nil {
		return err
	}
	// networkd, resolved, timesyncd and dbus run as their own users and reach /run/systemd (the
	// notify socket, their runtime directories) and networkd reads /run/systemd/network.
	probe := exec.Command(checkRootInit)
	probe.Env = []string{probeEnv + "=1"}
	probe.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: nobody, Gid: nobody, Groups: []uint32{}}}
	if out, err := probe.CombinedOutput(); err != nil {
		return fmt.Errorf("uid %d: %v: %s", nobody, err, strings.TrimSpace(string(out)))
	}
	// The root's own init starts with the usual umask, not the init's 0077.
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	if !strings.Contains(string(status), "\nUmask:\t0022\n") {
		return fmt.Errorf("the root's init does not start with umask 0022: %q", umaskLine(status))
	}
	return nil
}

// probeAsNobody is the probe: it reaches what a non-root service reaches under /run/systemd.
func probeAsNobody() int {
	if _, err := os.Stat("/run/systemd"); err != nil {
		fmt.Println(err)
		return 1
	}
	dir, err := os.Open("/run/systemd/network")
	if err == nil {
		_, err = dir.Readdirnames(-1)
		dir.Close()
	}
	if err != nil {
		fmt.Println(err)
		return 1
	}
	return 0
}

func umaskLine(status []byte) string {
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Umask:") {
			return line
		}
	}
	return ""
}

// writeKernelFile writes value as systemd writes a kernel file: an existing file, write-only.
func writeKernelFile(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	_, err = f.WriteString(value)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// mountsWritable requires each mount point in want to be mounted with its file system type, and
// read-write both as a mount and as a superblock, in /proc/self/mountinfo.
func mountsWritable(mountinfo []byte, want map[string]string) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(mountinfo), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		kind, ok := want[f[4]]
		if !ok {
			continue
		}
		sep := slices.Index(f, "-")
		if sep < 6 || sep+3 >= len(f) {
			return fmt.Errorf("mountinfo line %q", line)
		}
		if f[sep+1] != kind {
			return fmt.Errorf("%s is %s, want %s", f[4], f[sep+1], kind)
		}
		mount, super := strings.Split(f[5], ",")[0], strings.Split(f[sep+3], ",")[0]
		if mount != "rw" || super != "rw" {
			return fmt.Errorf("%s is mounted %s with superblock %s, want rw for both", f[4], f[5], f[sep+3])
		}
		seen[f[4]] = true
	}
	for path, kind := range want {
		if !seen[path] {
			return fmt.Errorf("no %s mount at %s", kind, path)
		}
	}
	return nil
}

func TestMountsWritable(t *testing.T) {
	want := map[string]string{"/proc": "proc", "/sys": "sysfs"}
	const rw = "22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n" +
		"23 1 0:22 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw\n" +
		"24 23 0:23 / /sys/kernel/config rw,nosuid,nodev,noexec,relatime shared:5 - configfs configfs rw\n"
	if err := mountsWritable([]byte(rw), want); err != nil {
		t.Fatal(err)
	}
	for name, info := range map[string]string{
		// B3: PrepareKernelViews' read-only mounts, moved unchanged.
		"read-only as moved":   strings.Replace(rw, "/proc rw,", "/proc ro,", 1),
		"read-only superblock": strings.Replace(rw, "sysfs sysfs rw", "sysfs sysfs ro", 1),
		"no sysfs":             "22 1 0:21 / /proc rw,nosuid - proc proc rw\n",
		"wrong type":           strings.Replace(rw, "- proc proc rw", "- tmpfs tmpfs rw", 1),
		"short line":           "22 1 0:21 / /proc rw,nosuid proc proc rw x\n",
	} {
		if err := mountsWritable([]byte(info), want); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
