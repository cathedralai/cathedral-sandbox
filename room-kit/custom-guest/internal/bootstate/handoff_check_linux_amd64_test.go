package bootstate

// The reference hand-off check (reference-build.yml, job handoff-check). This test binary runs as
// PID 1 of a plain QEMU guest (no SNP), booted from the reference kernel and the reference initrd
// the same run built, with the binary added to the initrd as one more cpio. It makes
// cathedral-init's kernel views with their real directories and mounts, builds a read-only check
// root at the verified root's path, as PrepareVerifiedRuntime leaves it, and hands off with the
// real ReadyRoot.Exec. The check root's /sbin/init is this binary again. There it checks the
// kernel views an owner's systemd needs (AB#1027): the VM init's B3 boot gave Ubuntu read-only
// /proc and /sys, and cathedral-init hands off the same way.

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	// handoffCheckPass is the line the workflow looks for on the guest's serial console. Only the
	// check root's /sbin/init prints it, after the hand-off.
	handoffCheckPass = "HANDOFF-CHECK: PASS"
	// handoffCheckInit is how Exec runs the root's init: this argv, nothing else.
	handoffCheckInit = "/sbin/init"
)

// TestMain is the check root's /sbin/init when the binary is PID 1 with Exec's fixed argv: the
// hand-off passes no test flags and no environment beyond PATH, LANG and TERM.
func TestMain(m *testing.M) {
	if os.Getpid() == 1 && len(os.Args) == 1 && os.Args[0] == handoffCheckInit {
		afterHandoff()
	}
	os.Exit(m.Run())
}

func TestReferenceHandoffCheck(t *testing.T) {
	if os.Getpid() != 1 || os.Getenv("CATHEDRAL_HANDOFF_CHECK") != "1" {
		t.Skip("PID 1 of the reference hand-off check VM (reference-build.yml)")
	}
	// PrepareKernelViews with its real directories and mounts. The SNP report device and the TSM
	// report directory exist only under SNP, so those two restrictions are left out here.
	syscall.Umask(0077)
	if err := prepareKernelViews(kernelOperations{directory: bootDirectory, mount: syscall.Mount,
		report: func() error { return nil }, config: func() error { return nil }}); err != nil {
		t.Fatal(err)
	}
	if err := makeCheckRoot(); err != nil {
		t.Fatal(err)
	}
	// As TestRuntimeIsolatedHandoff, the token is made here: this checks the hand-off, not verity.
	t.Log("hand off into the check root")
	err := (&ReadyRoot{ready: true}).Exec()
	t.Fatalf("hand-off returned: %v", err)
}

// makeCheckRoot stands in for MountVerifiedRoot and the runtime step: a tmpfs at the verified
// root's path with dev, proc, sys, a runtime /run and this binary as sbin/init, then made
// read-only with the verity root's flags.
func makeCheckRoot() error {
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return err
	}
	if err := os.Mkdir(verifiedRoot, 0o700); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", verifiedRoot, "tmpfs", syscall.MS_NODEV|syscall.MS_NOSUID, "mode=0755,size=64m"); err != nil {
		return fmt.Errorf("mount the check root: %w", err)
	}
	for _, name := range []string{"dev", "proc", "sys", "run", "sbin"} {
		if err := os.Mkdir(verifiedRoot+"/"+name, 0o755); err != nil {
			return err
		}
		if err := os.Chmod(verifiedRoot+"/"+name, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(verifiedRoot+"/sbin/init", self, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(verifiedRoot+"/sbin/init", 0o755); err != nil {
		return err
	}
	run, err := os.Open(verifiedRoot + "/run")
	if err != nil {
		return err
	}
	err = mountRuntime(run)
	run.Close()
	if err != nil {
		return fmt.Errorf("mount the check root's /run: %w", err)
	}
	if err := syscall.Mount("", verifiedRoot, "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NODEV|syscall.MS_NOSUID, ""); err != nil {
		return fmt.Errorf("make the check root read-only: %w", err)
	}
	return nil
}

// afterHandoff is the check root's init. It prints the pass line only if the kernel views it was
// handed work as systemd uses them, then powers off either way.
func afterHandoff() {
	if err := checkHandoffViews(); err != nil {
		fmt.Println("HANDOFF-CHECK: FAIL after the hand-off:", err)
	} else {
		fmt.Println(handoffCheckPass)
	}
	syscall.Sync()
	time.Sleep(time.Second) // let the serial console drain before the power-off
	syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	os.Exit(1)
}

func checkHandoffViews() error {
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
	return mountsWritable(info, map[string]string{"/proc": "proc", "/sys": "sysfs"})
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

func TestHandoffMountsWritable(t *testing.T) {
	want := map[string]string{"/proc": "proc", "/sys": "sysfs"}
	const rw = "22 1 0:21 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n" +
		"23 1 0:22 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw\n" +
		"24 23 0:23 / /sys/kernel/config rw,nosuid,nodev,noexec,relatime shared:5 - configfs configfs rw\n"
	if err := mountsWritable([]byte(rw), want); err != nil {
		t.Fatal(err)
	}
	for name, info := range map[string]string{
		// PrepareKernelViews' read-only mounts, moved unchanged.
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
