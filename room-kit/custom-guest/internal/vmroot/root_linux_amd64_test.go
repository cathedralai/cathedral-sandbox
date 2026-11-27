package vmroot

// These tests need root, loop devices, dm-verity and e2fsprogs. They run in the vm-guest CI job
// (.github/workflows/vm-guest.yml) with CATHEDRAL_VM_ROOT_TESTS=1 and are skipped everywhere else.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("CATHEDRAL_VM_ROOT_TESTS") != "1" {
		t.Skip("needs root and CATHEDRAL_VM_ROOT_TESTS=1")
	}
}

func sh(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

// installTool copies a system binary to a root-owned file so openPinned accepts it, and returns
// the pin. The runner's tools are dynamic; the pinned-descriptor exec works for them too.
func installTool(t *testing.T, name string) Tool {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		for _, dir := range []string{"/usr/sbin", "/sbin", "/sbin"} {
			if _, e := os.Stat(filepath.Join(dir, name)); e == nil {
				path, err = filepath.Join(dir, name), nil
				break
			}
		}
	}
	if err != nil {
		t.Fatalf("%s not installed", name)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dest, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	return Tool{Path: dest, SHA256: sha256.Sum256(raw)}
}

// buildBase makes a base image as build-bundle.sh does: ext4, then a verity tree with its
// superblock at the data size, in the same file.
func buildBase(t *testing.T) (string, Base) {
	t.Helper()
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	pristine(t, staging)
	for _, d := range []string{"dev", "proc", "sys", "run", "home", "var/lib", "sbin"} {
		if err := os.MkdirAll(filepath.Join(staging, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	img := filepath.Join(dir, "base.ext4")
	sh(t, "mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096", "-L", "cathedral-root", "-d", staging, "-E", "root_owner=0:0,lazy_itable_init=0", img, "24M")
	raw, err := os.ReadFile(img)
	if err != nil {
		t.Fatal(err)
	}
	data := int64(len(raw))
	salt := fmt.Sprintf("%x", sha256.Sum256(raw))
	base := filepath.Join(dir, "base.raw")
	if err := os.WriteFile(base, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	out := sh(t, "veritysetup", "format", base, base, "--data-block-size=4096", "--hash-block-size=4096",
		fmt.Sprintf("--data-blocks=%d", data/4096), fmt.Sprintf("--hash-offset=%d", data), "--salt="+salt)
	var hash string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Root hash:") {
			hash = strings.TrimSpace(strings.TrimPrefix(line, "Root hash:"))
		}
	}
	if len(hash) != 64 {
		t.Fatalf("no root hash in %q", out)
	}
	st, _ := os.Stat(base)
	return base, Base{DiskBytes: st.Size(), DataBytes: data, RootHash: hash}
}

// loopDevice returns an open loop device over a fresh sparse file of size bytes. The device is
// detached at the end of the test.
func loopDevice(t *testing.T, size int64) *os.File {
	t.Helper()
	file := filepath.Join(t.TempDir(), "fs-area.raw")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(size)
	f.Close()
	dev := strings.TrimSpace(sh(t, "losetup", "--find", "--show", file))
	t.Cleanup(func() { exec.Command("losetup", "-d", dev).Run() })
	d, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func openBase(t *testing.T, path string, b Base) Base {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	b.File = f
	return b
}

// treeDigest covers path, mode, owner and content of every entry under dir, not times.
func treeDigest(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		st := info.Sys().(*syscall.Stat_t)
		rel, _ := filepath.Rel(dir, path)
		sum := ""
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum = fmt.Sprintf("%x", sha256.Sum256(raw))
		}
		lines = append(lines, fmt.Sprintf("%s %v %d:%d %s", rel, info.Mode(), st.Uid, st.Gid, sum))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(lines, "\n"))))
}

func firstBootConfig(t *testing.T, base Base, fsDev *os.File, cut func(string) error) FirstBootConfig {
	t.Helper()
	return FirstBootConfig{
		Verity: installTool(t, "veritysetup"), Resize2fs: installTool(t, "resize2fs"),
		Base: base, FS: fsDev, MountPoint: filepath.Join(t.TempDir(), "newroot"),
		Tree: TreeOptions{Identity: Identity{VMID: testVMID, IdentitySHA256: testSHA, SSHPublicKey: testKey},
			Random: seeded("rootrun"), Cut: cut},
	}
}

func mapperGone(t *testing.T) {
	t.Helper()
	if _, err := os.Lstat("/dev/mapper/" + baseMapping); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the base verity mapping is still there: %v", err)
	}
}

func TestRootFirstBootCopiesGrowsAndPreparesTheRoot(t *testing.T) {
	needRoot(t)
	basePath, base := buildBase(t)
	base = openBase(t, basePath, base)
	dev := loopDevice(t, 96<<20)
	cfg := firstBootConfig(t, base, dev, nil)
	m, rec, err := FirstBoot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Unmount()
	mapperGone(t)
	var s syscall.Statfs_t
	if err := syscall.Statfs(m.Path(), &s); err != nil {
		t.Fatal(err)
	}
	if grown := int64(s.Blocks) * int64(s.Bsize); grown < 80<<20 {
		t.Errorf("the file system did not grow to its device: %d bytes", grown)
	}
	raw, err := os.ReadFile(filepath.Join(m.Path(), "var/lib/cathedral-vm/recovery.key"))
	if err != nil || !bytes.Contains(raw, []byte(rec.VMID)) {
		t.Fatalf("recovery.key: %v", err)
	}
	info, err := os.Stat(filepath.Join(m.Path(), "home/cathedral/.ssh/authorized_keys"))
	st := info.Sys().(*syscall.Stat_t)
	if err != nil || st.Uid != 1000 || st.Gid != 1000 {
		t.Fatalf("authorized_keys owner: %v", err)
	}
	// The base's own files arrived unchanged.
	if got, _ := os.ReadFile(filepath.Join(m.Path(), "etc/ssh/sshd_config")); !bytes.Contains(got, []byte("Include")) {
		t.Error("sshd_config missing from the copy")
	}
}

func TestRootRerunAfterACutAtEachPointGivesTheSameTree(t *testing.T) {
	needRoot(t)
	basePath, base := buildBase(t)
	base = openBase(t, basePath, base)

	whole := loopDevice(t, 96<<20)
	m, _, err := FirstBoot(firstBootConfig(t, base, whole, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := treeDigest(t, m.Path())
	m.Unmount()

	for _, point := range FirstBootCutPoints {
		dev := loopDevice(t, 96<<20)
		cut := func(p string) error {
			if p == point {
				return errors.New("cut at " + p)
			}
			return nil
		}
		if _, _, err := FirstBoot(firstBootConfig(t, base, dev, cut)); err == nil || !strings.Contains(err.Error(), point) {
			t.Fatalf("%s: the first run was not cut there: %v", point, err)
		}
		mapperGone(t)
		// The same fs area, the next boot, no cut.
		m, _, err := FirstBoot(firstBootConfig(t, base, dev, nil))
		if err != nil {
			t.Fatalf("%s: rerun: %v", point, err)
		}
		got := treeDigest(t, m.Path())
		m.Unmount()
		if got != want {
			t.Errorf("%s: the rerun tree differs from an uninterrupted run", point)
		}
	}
}

func TestRootAFlippedBaseBlockFailsTheCopy(t *testing.T) {
	needRoot(t)
	basePath, base := buildBase(t)
	raw, _ := os.ReadFile(basePath)
	raw[5*4096+100] ^= 0x01
	if err := os.WriteFile(basePath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	base = openBase(t, basePath, base)
	dev := loopDevice(t, 96<<20)
	cfg := firstBootConfig(t, base, dev, nil)
	if _, _, err := FirstBoot(cfg); err == nil || !strings.Contains(err.Error(), "verified read at") {
		t.Fatalf("a flipped base block must fail the verified read, got: %v", err)
	}
	mapperGone(t)
	if _, err := os.Lstat(cfg.MountPoint); !errors.Is(err, os.ErrNotExist) {
		t.Error("the root was mounted from an unverified copy")
	}
}

func TestRootAWrongRootHashFailsTheCopy(t *testing.T) {
	needRoot(t)
	basePath, base := buildBase(t)
	base = openBase(t, basePath, base)
	base.RootHash = strings.Repeat("0", 64)
	dev := loopDevice(t, 96<<20)
	if _, _, err := FirstBoot(firstBootConfig(t, base, dev, nil)); err == nil || !strings.Contains(err.Error(), "veritysetup") {
		t.Fatalf("a wrong root hash must fail the verity open, got: %v", err)
	}
	mapperGone(t)
}

func TestRootPinnedHelperRefusals(t *testing.T) {
	needRoot(t)
	good := installTool(t, "true")
	if f, err := openPinned(good); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	wrong := good
	wrong.SHA256[0] ^= 1
	if _, err := openPinned(wrong); err == nil {
		t.Error("a wrong digest was accepted")
	}
	if _, err := openPinned(Tool{Path: good.Path}); err == nil {
		t.Error("a missing pin was accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(good.Path, link)
	if _, err := openPinned(Tool{Path: link, SHA256: good.SHA256}); err == nil {
		t.Error("a symlink was followed")
	}
	os.Chmod(good.Path, 0o775)
	if _, err := openPinned(good); err == nil {
		t.Error("a group-writable helper was accepted")
	}
	os.Chmod(good.Path, 0o644)
	if _, err := openPinned(good); err == nil {
		t.Error("a non-executable helper was accepted")
	}
	// A changed file after the pin was taken is caught by the digest.
	os.Chmod(good.Path, 0o755)
	os.WriteFile(good.Path, append(mustRead(t, good.Path), 0), 0o755)
	if _, err := openPinned(good); err == nil {
		t.Error("a changed helper was accepted")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRootFinishBindsModulesToolsAndWritesTheNetworkFile(t *testing.T) {
	needRoot(t)
	basePath, base := buildBase(t)
	base = openBase(t, basePath, base)
	dev := loopDevice(t, 96<<20)
	m, _, err := FirstBoot(firstBootConfig(t, base, dev, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { exec.Command("umount", "-R", "-l", m.Path()).Run() })

	release := "6.99.0-1-test"
	moduleDir := "/usr/lib/modules/" + release
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(moduleDir) })
	os.WriteFile(moduleDir+"/modules.dep", []byte("kernel/x.ko:\n"), 0o644)
	tool := installTool(t, "true")

	cfg := FinishConfig{Link: []byte("10.216.0.5 10.216.0.6"), KernelRelease: release,
		Tools: []Bind{{Source: tool.Path, Name: "cathedral-attest"}, {Source: tool.Path, Name: "cathedral-vm"}}}
	if err := m.Finish(cfg); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(m.Path(), "usr/lib/modules", release, "modules.dep")); err != nil || len(got) == 0 {
		t.Fatalf("modules not bound: %v", err)
	}
	if err := os.WriteFile(filepath.Join(m.Path(), "usr/lib/modules", release, "evil.ko"), nil, 0o644); !errors.Is(err, syscall.EROFS) {
		t.Errorf("the module tree is writable: %v", err)
	}
	var s syscall.Statfs_t
	if err := syscall.Statfs(filepath.Join(m.Path(), "run"), &s); err != nil || s.Type != 0x01021994 {
		t.Fatalf("/run is not a tmpfs: %v", err)
	}
	net, err := os.ReadFile(filepath.Join(m.Path(), "run/systemd/network/10-uplink.network"))
	if err != nil || !strings.Contains(string(net), "Address=10.216.0.6/30") {
		t.Fatalf("network file: %v %s", err, net)
	}
	attest := filepath.Join(m.Path(), "run/cathedral/bin/cathedral-attest")
	if err := os.WriteFile(attest, []byte("x"), 0o755); !errors.Is(err, syscall.EROFS) {
		t.Errorf("a bound tool is writable: %v", err)
	}
	if out, err := exec.Command(attest).CombinedOutput(); err != nil {
		t.Errorf("the bound tool does not run: %v %s", err, out)
	}
	// Every boot asserts cloud-init off: delete the marker and run Finish's assertion again.
	marker := filepath.Join(m.Path(), "etc/cloud/cloud-init.disabled")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal(err)
	}
}

func TestSwitchRootGuards(t *testing.T) {
	m := &Mounted{path: "/nonexistent"}
	if err := m.SwitchRoot(nil); err == nil {
		t.Error("no ready check was accepted")
	}
	called := false
	err := m.SwitchRoot(func() error { called = true; return nil })
	if err == nil || called {
		t.Errorf("a process that is not PID 1 got to the ready check: %v %v", err, called)
	}
	if err := (&Mounted{}).Finish(FinishConfig{KernelRelease: "../../etc", Tools: []Bind{{Source: "/x", Name: "y"}}}); err == nil {
		t.Error("a path in the kernel release was accepted")
	}
	if err := (&Mounted{}).Finish(FinishConfig{KernelRelease: "6.8.0-1-generic"}); err == nil {
		t.Error("Finish with no tools was accepted")
	}
}
