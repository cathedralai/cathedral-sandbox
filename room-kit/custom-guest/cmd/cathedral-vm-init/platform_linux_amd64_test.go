package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const release = "6.8.0-90-generic"

func goodManifest() string {
	return `{"boot_modules":["sev-guest","dm-crypt"],"executables":{"init":"` + strings.Repeat("a", 64) +
		`","usr/lib/cathedral/cryptsetup":"` + strings.Repeat("b", 64) + `"},"kernel_release":"` + release +
		`","schema":"cathedral.vm.initrd-manifest/v1"}`
}

func TestManifest(t *testing.T) {
	m, err := parseManifest([]byte(goodManifest()))
	if err != nil {
		t.Fatal(err)
	}
	tool, err := m.tool(cryptsetupName, "cryptsetup")
	if err != nil || tool.Path != "/usr/lib/cathedral/cryptsetup" || tool.SHA256[0] != 0xbb || tool.Name != "cryptsetup" {
		t.Fatalf("tool %+v %v", tool, err)
	}
	for name, edit := range map[string]func(string) string{
		"unknown field":   func(s string) string { return strings.Replace(s, `{"boot_modules"`, `{"extra":1,"boot_modules"`, 1) },
		"other schema":    func(s string) string { return strings.Replace(s, "manifest/v1", "manifest/v2", 1) },
		"bad release":     func(s string) string { return strings.Replace(s, release, "6.8.0", 1) },
		"no modules":      func(s string) string { return strings.Replace(s, `["sev-guest","dm-crypt"]`, `[]`, 1) },
		"short pin":       func(s string) string { return strings.Replace(s, strings.Repeat("b", 64), strings.Repeat("b", 63), 1) },
		"upper-case pin":  func(s string) string { return strings.Replace(s, strings.Repeat("b", 64), strings.Repeat("B", 64), 1) },
		"no cryptsetup":   func(s string) string { return strings.Replace(s, "lib/cathedral/cryptsetup", "lib/cathedral/other", 1) },
		"trailing record": func(s string) string { return s + "{}" },
	} {
		if _, err := parseManifest([]byte(edit(goodManifest()))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestModuleList(t *testing.T) {
	p := "usr/lib/modules/" + release + "/"
	good := p + "kernel/drivers/virt/coco/sev-guest/sev-guest.ko.zst\n" + p + "kernel/drivers/md/dm-crypt.ko\n"
	if _, err := parseModules([]byte(many(p, 256)), release); err != nil {
		t.Fatalf("256 modules: %v", err)
	}
	list, err := parseModules([]byte(good), release)
	if err != nil || len(list) != 2 || list[1] != p+"kernel/drivers/md/dm-crypt.ko" {
		t.Fatalf("%v %v", list, err)
	}
	for name, raw := range map[string]string{
		"empty":            "",
		"no final newline": strings.TrimSuffix(good, "\n"),
		"other release":    strings.Replace(good, release, "6.8.0-91-generic", 1),
		"dot dot":          p + "kernel/../../../../bin/sh.ko\n",
		"absolute":         "/" + good,
		"not a module":     p + "kernel/drivers/md/dm-crypt.so\n",
		"blank line":       good + "\n",
		"duplicate":        good + p + "kernel/drivers/md/dm-crypt.ko\n",
		"double slash":     p + "kernel//dm-crypt.ko\n",
		"257 modules":      many(p, 257),
		"no prefix":        "kernel/drivers/md/dm-crypt.ko\n",
	} {
		if _, err := parseModules([]byte(raw), release); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func many(prefix string, n int) string {
	var b strings.Builder
	for i := range n {
		b.WriteString(prefix + "kernel/m" + strconv.Itoa(i) + ".ko\n")
	}
	return b.String()
}

func writeEntry(t *testing.T, dir, name string, raw []byte, size int) {
	t.Helper()
	d := filepath.Join(dir, fwCfgDir, name)
	if err := os.MkdirAll(d, 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "raw"), raw, 0600)
	os.WriteFile(filepath.Join(d, "size"), []byte(strconv.Itoa(size)+"\n"), 0600)
}

func TestFwCfg(t *testing.T) {
	doc := identityDoc("vm-0123456789ab")
	link := []byte("10.0.0.1 10.0.0.2")
	setup := func(t *testing.T) string {
		dir := t.TempDir()
		writeEntry(t, dir, identityName, doc, len(doc))
		writeEntry(t, dir, linkName, link, len(link))
		return dir
	}
	id, l, err := readFwCfg(setup(t))
	if err != nil || string(id) != string(doc) || string(l) != string(link) {
		t.Fatalf("%q %q %v", id, l, err)
	}
	for name, edit := range map[string]func(t *testing.T, dir string){
		"a third name":   func(t *testing.T, dir string) { writeEntry(t, dir, "extra", []byte("x"), 1) },
		"no link":        func(t *testing.T, dir string) { os.RemoveAll(filepath.Join(dir, fwCfgDir, linkName)) },
		"size mismatch":  func(t *testing.T, dir string) { writeEntry(t, dir, linkName, link, len(link)+1) },
		"oversized link": func(t *testing.T, dir string) { writeEntry(t, dir, linkName, make([]byte, 65), 65) },
		"oversized identity": func(t *testing.T, dir string) {
			writeEntry(t, dir, identityName, make([]byte, 16385), 16385)
		},
		"empty identity": func(t *testing.T, dir string) { writeEntry(t, dir, identityName, nil, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := setup(t)
			edit(t, dir)
			if _, _, err := readFwCfg(dir); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestFindDisks(t *testing.T) {
	setup := func(t *testing.T, disks map[string]string) string {
		dir := t.TempDir()
		for name, serial := range disks {
			os.MkdirAll(filepath.Join(dir, name), 0700)
			os.WriteFile(filepath.Join(dir, name, "serial"), []byte(serial+"\n"), 0600)
		}
		os.MkdirAll(filepath.Join(dir, "loop0"), 0700)
		return dir
	}
	good := map[string]string{"vda": serialRoot, "vdb": serialBase, "vdc": serialMailbox}
	got, err := findDisks(setup(t, good))
	if err != nil || got[serialRoot] != "vda" || got[serialBase] != "vdb" || got[serialMailbox] != "vdc" {
		t.Fatalf("%v %v", got, err)
	}
	for name, disks := range map[string]map[string]string{
		"duplicate serial": {"vda": serialRoot, "vdb": serialRoot, "vdc": serialMailbox},
		"missing mailbox":  {"vda": serialRoot, "vdb": serialBase},
		"a fourth disk":    {"vda": serialRoot, "vdb": serialBase, "vdc": serialMailbox, "vdd": "other"},
		"renamed root":     {"vda": "virtio-vm-root", "vdb": serialBase, "vdc": serialMailbox},
	} {
		if _, err := findDisks(setup(t, disks)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// B2 boot 2 powered off at F3: the initrd has no /run, so cryptsetup's LUKS2
// lock (/run/cryptsetup) failed luksFormat. Disk makes /run first.
func TestLockParent(t *testing.T) {
	if lockParent != "/run" {
		t.Fatalf("lock parent %q: cryptsetup 2.8.4 locks in /run/cryptsetup", lockParent)
	}
	dir := filepath.Join(t.TempDir(), "run")
	for i := 0; i < 2; i++ {
		if err := makeLockParent(dir); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		fi, err := os.Lstat(dir)
		if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755&^umask() {
			t.Fatalf("call %d: %v %v", i, fi, err)
		}
	}
	file := filepath.Join(t.TempDir(), "run")
	os.WriteFile(file, nil, 0600)
	if err := makeLockParent(file); err == nil {
		t.Fatal("a file at the lock parent was accepted")
	}
	link := filepath.Join(t.TempDir(), "run")
	os.Symlink(t.TempDir(), link)
	if err := makeLockParent(link); err == nil {
		t.Fatal("a link at the lock parent was accepted")
	}
}

func umask() os.FileMode {
	old := syscall.Umask(0)
	syscall.Umask(old)
	return os.FileMode(old)
}

func TestOpenDiskRefusesANonBlockNode(t *testing.T) {
	sys, dev := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(dev, "vda"), make([]byte, 4096), 0600)
	os.Symlink(filepath.Join(dev, "vda"), filepath.Join(dev, "vdb"))
	// 0:0 is a regular file's st_rdev, so only the file type check refuses it.
	for _, name := range []string{"vda", "vdb"} {
		for _, num := range []string{"253:0", "0:0"} {
			os.MkdirAll(filepath.Join(sys, name), 0700)
			os.WriteFile(filepath.Join(sys, name, "dev"), []byte(num+"\n"), 0600)
			if f, _, err := openDisk(sys, dev, name, os.O_RDONLY); err == nil {
				f.Close()
				t.Fatalf("%s (%s), not a block device, was opened as the disk", name, num)
			}
		}
	}
}

// As root (vm-init.yml), on a loop device: the right major:minor opens,
// another one is refused.
func TestOpenDiskChecksTheDeviceNumber(t *testing.T) {
	if os.Getenv("VMDISK_ROOT_TESTS") != "1" || os.Geteuid() != 0 {
		t.Skip("root loop-device test (vm-init.yml)")
	}
	img := filepath.Join(t.TempDir(), "disk.raw")
	os.WriteFile(img, nil, 0600)
	os.Truncate(img, 1<<20)
	out, err := exec.Command("losetup", "--find", "--show", img).Output()
	if err != nil {
		t.Fatal(err)
	}
	loop := strings.TrimSpace(string(out))
	defer exec.Command("losetup", "--detach", loop).Run()
	name := filepath.Base(loop)
	devNum, err := os.ReadFile("/sys/block/" + name + "/dev")
	if err != nil {
		t.Fatal(err)
	}
	sys := t.TempDir()
	os.MkdirAll(filepath.Join(sys, name), 0700)
	os.WriteFile(filepath.Join(sys, name, "dev"), devNum, 0600)
	f, size, err := openDisk(sys, "/dev", name, os.O_RDONLY)
	if err != nil || size != 1<<20 {
		t.Fatalf("the loop device: %d %v", size, err)
	}
	f.Close()
	// The mailbox open reads the device, not the page cache (vmmailbox).
	f, _, err = openDisk(sys, "/dev", name, mailboxFlags)
	if err != nil {
		t.Fatalf("the mailbox open: %v", err)
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFL, 0)
	f.Close()
	if errno != 0 || flags&syscall.O_DIRECT == 0 || flags&syscall.O_ACCMODE != syscall.O_RDWR {
		t.Fatalf("the mailbox is not open O_RDWR|O_DIRECT: %#x %v", flags, errno)
	}
	// A link to the right device is refused too: the init opens no link.
	dev := t.TempDir()
	os.Symlink(loop, filepath.Join(dev, name))
	if f, _, err := openDisk(sys, dev, name, os.O_RDONLY); err == nil {
		f.Close()
		t.Fatal("a link to the device was followed")
	}
	var major, minor int
	fmt.Sscanf(strings.TrimSpace(string(devNum)), "%d:%d", &major, &minor)
	os.WriteFile(filepath.Join(sys, name, "dev"), []byte(fmt.Sprintf("%d:%d\n", major, minor+1)), 0600)
	if f, _, err := openDisk(sys, "/dev", name, os.O_RDONLY); err == nil {
		f.Close()
		t.Fatal("a node of another device number was opened")
	}
}
