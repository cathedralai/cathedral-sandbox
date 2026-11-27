package datavolume

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These tests drive real losetup, cryptsetup, dm-crypt, dm-integrity, mke2fs and
// mount. They need root, so CI runs them in a dedicated job with
// CATHEDRAL_ROOT_TESTS=1; elsewhere they skip. They share the fixed mapper name
// and must not run in parallel.

const loopSize = 128 << 20

func rootLoop(t *testing.T) {
	t.Helper()
	if os.Getenv("CATHEDRAL_ROOT_TESTS") != "1" {
		t.Skip("set CATHEDRAL_ROOT_TESTS=1 as root with cryptsetup, e2fsprogs and loop devices")
	}
	if os.Geteuid() != 0 {
		t.Fatal("CATHEDRAL_ROOT_TESTS=1 requires root")
	}
}

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return strings.TrimSpace(string(out))
}

type loopFixture struct {
	t       *testing.T
	image   string
	device  string
	tools   *tools
	mounted string
}

// teardown is deliberately independent of the code under test.
func (l *loopFixture) teardown() {
	_ = syscall.Unmount(l.tools.mountTarget, 0)
	for _, n := range []string{mapperName, mapperName + "_dif"} {
		if _, err := os.Lstat("/dev/mapper/" + n); err == nil {
			_ = exec.Command(l.tools.helperPath, "close", n).Run()
		}
	}
}

func newLoop(t *testing.T) *loopFixture {
	t.Helper()
	rootLoop(t)
	dir := t.TempDir()
	image := filepath.Join(dir, "disk.img")
	f, err := os.Create(image)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(loopSize); err != nil {
		t.Fatal(err)
	}
	f.Close()
	device := sh(t, "losetup", "--find", "--show", image)
	t.Cleanup(func() { _ = exec.Command("losetup", "-d", device).Run() })
	helper, err := exec.LookPath("cryptsetup")
	if err != nil {
		t.Fatal(err)
	}
	helper, err = filepath.EvalSymlinks(helper)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	mke2fs, err := exec.LookPath("mke2fs")
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "mnt")
	l := &loopFixture{t: t, image: image, device: device}
	l.tools = &tools{helperPath: helper, helperSHA: sha256.Sum256(raw), mke2fs: mke2fs, mapperDir: "/dev/mapper",
		sys: "/sys", mountinfo: "/proc/self/mountinfo", mountTarget: target}
	base := l.tools.execute
	l.tools.exec = func(ctx context.Context, c command) (result, error) {
		res, err := base(ctx, c)
		if err != nil {
			t.Logf("helper %v failed; stderr: %s", c.args, res.stderr)
		}
		return res, err
	}
	t.Cleanup(l.teardown)
	return l
}

// held opens the loop device the way OpenData would hold the real disk.
func (l *loopFixture) held() *HeldDevice {
	l.t.Helper()
	fd, err := syscall.Open(l.device, syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		l.t.Fatal(err)
	}
	dev, err := devNumber(l.device)
	if err != nil {
		l.t.Fatal(err)
	}
	d := &HeldDevice{file: os.NewFile(uintptr(fd), l.device), size: loopSize, dev: dev, tools: l.tools}
	l.t.Cleanup(func() { d.Close() })
	return d
}

func (l *loopFixture) sha() [32]byte {
	l.t.Helper()
	raw, err := os.ReadFile(l.image)
	if err != nil {
		l.t.Fatal(err)
	}
	return sha256.Sum256(raw)
}

func (l *loopFixture) unlock(c LockedCandidate, pass string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return Unlock(ctx, c, []byte(pass))
}

func (l *loopFixture) mapperPresent() bool {
	_, err := os.Lstat("/dev/mapper/" + mapperName)
	return err == nil
}

type spy struct {
	*HeldDevice
	formats int
	opens   int
	mkfs    error // injected MakeFilesystem failure: a power cut at that step
}

func (s *spy) Format(ctx context.Context, p []byte) error {
	s.formats++
	return s.HeldDevice.Format(ctx, p)
}

type cutMapping struct {
	OwnedMapping
	err error
}

func (c cutMapping) MakeFilesystem(context.Context) error { return c.err }

func (s *spy) Open(ctx context.Context, p []byte) (OwnedMapping, error) {
	s.opens++
	m, err := s.HeldDevice.Open(ctx, p)
	if m != nil && s.mkfs != nil {
		return cutMapping{m, s.mkfs}, err
	}
	return m, err
}

func TestLoopBlankDiskFormatsAndMountsRestricted(t *testing.T) {
	l := newLoop(t)
	s := &spy{HeldDevice: l.held()}
	if err := l.unlock(s, testSecret); err != nil {
		t.Fatal(err)
	}
	if s.formats != 1 {
		t.Fatalf("formatted %d times", s.formats)
	}
	// The header the adapter wrote is the policy the checker accepts.
	header, err := l.held().Header(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckHeaderPolicy(header); err != nil {
		t.Fatalf("own header refused: %v", err)
	}
	// Mounted with all three restrictions: a script on it cannot be executed.
	script := filepath.Join(l.tools.mountTarget, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(script).Run(); err == nil {
		t.Fatal("executed a file on the data mount")
	}
	entries, err := mounts(l.tools.mountinfo, l.tools.mountTarget)
	if err != nil || len(entries) != 1 {
		t.Fatalf("%v %v", entries, err)
	}
	for _, o := range []string{"nosuid", "nodev", "noexec"} {
		if !strings.Contains(entries[0].options, o) {
			t.Fatalf("mount options %q lack %s", entries[0].options, o)
		}
	}
}

func TestLoopRerunOpensWithoutFormat(t *testing.T) {
	l := newLoop(t)
	if err := l.unlock(&spy{HeldDevice: l.held()}, testSecret); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.tools.mountTarget, "keep"), []byte("kept"), 0600); err != nil {
		t.Fatal(err)
	}
	l.teardown()
	s := &spy{HeldDevice: l.held()}
	if err := l.unlock(s, testSecret); err != nil {
		t.Fatal(err)
	}
	if s.formats != 0 {
		t.Fatal("second run formatted an existing volume")
	}
	got, err := os.ReadFile(filepath.Join(l.tools.mountTarget, "keep"))
	if err != nil || string(got) != "kept" {
		t.Fatalf("data lost: %q %v", got, err)
	}
}

func TestLoopWrongPassphraseNeverFormats(t *testing.T) {
	l := newLoop(t)
	if err := l.unlock(&spy{HeldDevice: l.held()}, testSecret); err != nil {
		t.Fatal(err)
	}
	l.teardown()
	before := l.sha()
	s := &spy{HeldDevice: l.held()}
	if err := l.unlock(s, "not the passphrase"); err == nil {
		t.Fatal("wrong passphrase unlocked")
	}
	if s.formats != 0 || l.sha() != before || l.mapperPresent() {
		t.Fatalf("formats=%d changed=%v mapper=%v", s.formats, l.sha() != before, l.mapperPresent())
	}
}

func TestLoopNonzeroByteWithoutLUKSRefused(t *testing.T) {
	l := newLoop(t)
	f, err := os.OpenFile(l.image, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte{1}, loopSize-4097); err != nil {
		t.Fatal(err)
	}
	f.Close()
	before := l.sha()
	s := &spy{HeldDevice: l.held()}
	if err := l.unlock(s, testSecret); err == nil {
		t.Fatal("nonblank unmarked disk accepted")
	}
	if s.formats != 0 || s.opens != 0 || l.sha() != before || l.mapperPresent() {
		t.Fatal("refused run touched the disk or left a mapping")
	}
}

// A power cut after luksFormat and before mkfs: the next run sees LUKS with no
// filesystem, refuses, and does not format again.
func TestLoopCutBeforeMkfsRefusesNextRun(t *testing.T) {
	l := newLoop(t)
	cut := &spy{HeldDevice: l.held(), mkfs: errors.New("power cut")}
	if err := l.unlock(cut, testSecret); err == nil {
		t.Fatal("cut run reported success")
	}
	if cut.formats != 1 {
		t.Fatalf("formats=%d", cut.formats)
	}
	if l.mapperPresent() {
		t.Fatal("cut run left a mapping open")
	}
	before := l.sha()
	next := &spy{HeldDevice: l.held()}
	err := l.unlock(next, testSecret)
	if err == nil || !strings.Contains(err.Error(), "not formatting") {
		t.Fatalf("next run: %v", err)
	}
	if next.formats != 0 {
		t.Fatal("next run formatted again")
	}
	if l.sha() != before {
		t.Fatal("refused run changed the disk")
	}
	if l.mapperPresent() {
		t.Fatal("refused run left a mapping open")
	}
}

// A header with a null cipher passes cryptsetup's own checks. The policy
// refuses it before Open ever runs.
func TestLoopNullCipherHeaderRefusedBeforeOpen(t *testing.T) {
	l := newLoop(t)
	cmd := exec.Command(l.tools.helperPath, "luksFormat", "--type", "luks2", "--cipher", "cipher_null-ecb",
		"--key-size", "0", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--batch-mode", "--key-file=-", l.device)
	cmd.Stdin = strings.NewReader(testSecret)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("could not create the null-cipher fixture: %v\n%s", err, out)
	}
	before := l.sha()
	s := &spy{HeldDevice: l.held()}
	err := l.unlock(s, testSecret)
	if err == nil || !strings.Contains(err.Error(), "policy mismatch") {
		t.Fatalf("err=%v", err)
	}
	if s.opens != 0 || s.formats != 0 || l.sha() != before || l.mapperPresent() {
		t.Fatalf("opens=%d formats=%d", s.opens, s.formats)
	}
}

// Verify must compare the backing device, not just the name.
func TestLoopVerifyRefusesWrongBackingDisk(t *testing.T) {
	l := newLoop(t)
	if err := l.unlock(&spy{HeldDevice: l.held()}, testSecret); err != nil {
		t.Fatal(err)
	}
	m := &mapping{dev: "7:255", size: loopSize, tools: l.tools}
	if err := m.Verify(context.Background()); err == nil {
		t.Fatal("mapping verified against a different backing device")
	}
	m = &mapping{dev: l.held().dev, size: loopSize, tools: l.tools}
	if err := m.Verify(context.Background()); err != nil {
		t.Fatalf("own mapping refused: %v", err)
	}
	m.size = 4096
	if err := m.Verify(context.Background()); err == nil {
		t.Fatal("mapping larger than the held disk verified")
	}
}

// A plain dm-crypt mapping under our name is not LUKS2 with integrity.
func TestLoopVerifyRefusesPlainMapping(t *testing.T) {
	l := newLoop(t)
	cmd := exec.Command(l.tools.helperPath, "open", "--type", "plain", "--cipher", "aes-xts-plain64",
		"--key-size", "512", "--batch-mode", "--key-file=-", l.device, mapperName)
	cmd.Stdin = strings.NewReader(testSecret)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	m := &mapping{dev: l.held().dev, size: loopSize, tools: l.tools}
	if err := m.Verify(context.Background()); err == nil {
		t.Fatal("plain mapping verified")
	}
}

func TestLoopMountTargetInUseRefused(t *testing.T) {
	l := newLoop(t)
	if err := os.Mkdir(l.tools.mountTarget, 0700); err != nil {
		t.Fatal(err)
	}
	sh(t, "mount", "-t", "tmpfs", "tmpfs", l.tools.mountTarget)
	s := &spy{HeldDevice: l.held()}
	if err := l.unlock(s, testSecret); err == nil {
		t.Fatal("mounted over an occupied target")
	}
	if l.mapperPresent() {
		t.Fatal("mapping left open after a refused mount")
	}
}
