package main

// The wired path on loop devices: the real vmdisk (real cryptsetup and device-mapper) and the real
// vmroot adapter, with the SNP-bound parts faked as in boot_linux_amd64_test.go. Needs root: run by
// the vm-guest CI job with CATHEDRAL_VM_ROOT_TESTS=1. switch_root cannot run in a test, so the
// hybrid's Start does everything the real one does up to it, calls ready (the status record), and
// stops there with the root still mounted for inspection.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmdisk"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmmailbox"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmroot"
)

var errStopped = errors.New("stopped before switch_root (test)")

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("CATHEDRAL_VM_ROOT_TESTS") != "1" {
		t.Skip("needs root and CATHEDRAL_VM_ROOT_TESTS=1")
	}
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func pinnedCopy(t *testing.T, name string) vmroot.Tool {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		path = "/usr/sbin/" + name
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dest, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	return vmroot.Tool{Path: dest, SHA256: sha256.Sum256(raw)}
}

// image is the world of one test: a base image with its verity root hash, three backing files.
type image struct {
	t                                 *testing.T
	dir                               string
	base, root, mailbox               string
	dataBytes                         int64
	rootHash                          string
	identity                          []byte
	cmdline                           string
	names                             vmdisk.Names
	release                           string
	attest, vmTool, mounts, newrootAt string
}

func newImage(t *testing.T) *image {
	t.Helper()
	im := &image{t: t, dir: t.TempDir(), release: "6.99.0-1-test"}
	staging := filepath.Join(im.dir, "staging")
	files := map[string]string{
		"etc/passwd": "root:x:0:0:root:/root:/bin/bash\n", "etc/group": "root:x:0:\nsudo:x:27:\n",
		"etc/shadow": "root:*:20000:0:99999:7:::\n", "etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\n",
	}
	for name, data := range files {
		p := filepath.Join(staging, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(data), 0o644)
	}
	for _, d := range []string{"dev", "proc", "sys", "run", "home", "var/lib", "sbin"} {
		os.MkdirAll(filepath.Join(staging, d), 0o755)
	}
	img := filepath.Join(im.dir, "base.ext4")
	run(t, "mke2fs", "-q", "-F", "-t", "ext4", "-b", "4096", "-d", staging, "-E", "root_owner=0:0,lazy_itable_init=0", img, "24M")
	raw, _ := os.ReadFile(img)
	im.dataBytes = int64(len(raw))
	im.base = filepath.Join(im.dir, "base.raw")
	os.WriteFile(im.base, raw, 0o644)
	out := run(t, "veritysetup", "format", im.base, im.base, "--data-block-size=4096", "--hash-block-size=4096",
		fmt.Sprintf("--data-blocks=%d", im.dataBytes/4096), fmt.Sprintf("--hash-offset=%d", im.dataBytes),
		fmt.Sprintf("--salt=%x", sha256.Sum256(raw)))
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Root hash:") {
			im.rootHash = strings.TrimSpace(strings.TrimPrefix(line, "Root hash:"))
		}
	}
	if len(im.rootHash) != 64 {
		t.Fatalf("no root hash: %q", out)
	}
	im.root = filepath.Join(im.dir, "root.raw")
	f, _ := os.Create(im.root)
	f.Truncate(96 << 20)
	f.Close()
	im.mailbox = filepath.Join(im.dir, "mailbox.raw")
	os.WriteFile(im.mailbox, make([]byte, vmmailbox.MailboxBytes), 0o600)

	id := fmt.Sprintf(`{"base_root_data_bytes":%d,"base_root_verity":"%s","salt_hex":"000102030405060708090a0b0c0d0e0f",`+
		`"schema":"cathedral.vm.identity/v1","ssh_public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/",`+
		`"version":1,"vm_id":"vm-0123456789ab"}`, im.dataBytes, im.rootHash)
	im.identity = []byte(id)
	im.cmdline = cmdlineFor(t, im.identity)
	var tag [3]byte
	copy(tag[:], im.rootHash[:3])
	prefix := "cvmw" + hex.EncodeToString(tag[:])
	im.names = vmdisk.Names{LUKS: prefix + "-luks", Probe: prefix + "-probe", Crypt: prefix + "-crypt", FS: prefix + "-fs"}

	// What the initrd provides at the paths the adapter binds from.
	im.mounts = "/usr/lib/modules/" + im.release
	os.MkdirAll(im.mounts, 0o755)
	os.WriteFile(im.mounts+"/modules.dep", []byte("x\n"), 0o644)
	os.MkdirAll("/usr/lib/cathedral", 0o755)
	im.attest, im.vmTool = "/"+attestName, "/"+vmToolName
	for _, p := range []string{im.attest, im.vmTool} {
		os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	}
	t.Cleanup(func() {
		os.RemoveAll(im.mounts)
		os.Remove(im.attest)
		os.Remove(im.vmTool)
	})
	return im
}

func attachLoop(t *testing.T, path string, flags int) (*os.File, int64) {
	t.Helper()
	dev := strings.TrimSpace(run(t, "losetup", "--find", "--show", path))
	t.Cleanup(func() { exec.Command("losetup", "-d", dev).Run() })
	f, err := os.OpenFile(dev, flags, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	size, err := f.Seek(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	return f, size
}

// hybrid is the fake platform with the real disk and root.
type hybrid struct {
	*fake
	im      *image
	tool    vmdisk.Tool
	verity  vmroot.Tool
	resize  vmroot.Tool
	mountAt string
	dropPin string // a manifest entry to leave out, to prove the adapter refuses
	devices Devices
	fsArea  *os.File // what the disk package handed to Start, closed at power off
}

func (h *hybrid) Devices() (Devices, error) { h.call("devices"); return h.devices, nil }
func (h *hybrid) Disk(ctx context.Context, cfg vmdisk.Config) (vmdisk.Outcome, error) {
	h.call("disk")
	cfg.Cryptsetup, cfg.Names = h.tool, h.im.names
	return vmdisk.Run(ctx, cfg)
}
func (h *hybrid) Root() Root {
	m := manifest{KernelRelease: h.im.release, Executables: map[string]string{}}
	for _, n := range []string{verityName, resizeName, attestName, vmToolName} {
		if n != h.dropPin {
			m.Executables[n] = strings.Repeat("a", 64)
		}
	}
	a := newRootAdapter(m)
	if a.err == nil {
		a.verity, a.resize = h.verity, h.resize
	}
	return hybridRoot{rootAdapter: a, h: h}
}
func (h *hybrid) Mailbox() Mailbox { return mailboxAdapter{} }

type hybridRoot struct {
	rootAdapter
	h *hybrid
}

func (r hybridRoot) Start(ctx context.Context, fsArea *os.File, link []byte, ready func() error) error {
	if r.err != nil {
		return r.err
	}
	r.h.fsArea = fsArea
	m, err := vmroot.Mount(fsArea, r.h.mountAt)
	if err != nil {
		return err
	}
	if err := m.Finish(vmroot.FinishConfig{Link: link, KernelRelease: r.release, Tools: r.binds}); err != nil {
		return err
	}
	if err := ready(); err != nil { // the status record, as the real SwitchRoot calls it first
		return err
	}
	return errStopped
}

func (im *image) boot(t *testing.T, dropPin string) (*hybrid, error) {
	t.Helper()
	f := newFake(t)
	// newFake wraps fd 0 in an os.File for its fake disk; its finalizer would close fd 0 under a later
	// open. This test uses the real disk, so drop it.
	f.outcome = vmdisk.Outcome{}
	f.identity, f.cmdline, f.link = im.identity, im.cmdline, []byte("10.216.0.5 10.216.0.6")
	rootFile, rootSize := attachLoop(t, im.root, os.O_RDWR)
	baseFile, baseSize := attachLoop(t, im.base, os.O_RDONLY)
	mailFile, mailSize := attachLoop(t, im.mailbox, os.O_RDWR|syscall.O_DIRECT)
	h := &hybrid{fake: f, im: im, tool: vmdisk.Tool{Path: pinnedCopy(t, "cryptsetup").Path, Name: "cryptsetup"},
		verity: pinnedCopy(t, "veritysetup"), resize: pinnedCopy(t, "resize2fs"),
		mountAt: filepath.Join(im.dir, "newroot"), dropPin: dropPin,
		devices: Devices{Root: rootFile, RootBytes: rootSize, Base: baseFile, BaseBytes: baseSize, Mailbox: mailFile, MailboxSize: mailSize}}
	raw, _ := os.ReadFile(h.tool.Path)
	h.tool.SHA256 = sha256.Sum256(raw)
	t.Cleanup(func() { im.powerOff(h) })
	return h, boot(context.Background(), h)
}

// powerOff does what a real power cycle does: nothing survives it. It releases the root mount (and its
// binds), every descriptor the boot held, then each mapping, and fails the test if one is left. The
// init itself closes nothing on the way down; the VM halts, so this is the test's job.
func (im *image) powerOff(h *hybrid) {
	exec.Command("umount", "-R", "-l", h.mountAt).Run()
	os.Remove(h.mountAt)
	if h.fsArea != nil {
		h.fsArea.Close()
		h.fsArea = nil
	}
	for _, name := range []string{im.names.FS, im.names.Crypt, im.names.Probe, im.names.LUKS} {
		if out, err := exec.Command("dmsetup", "remove", "--force", "--retry", name).CombinedOutput(); err != nil &&
			!strings.Contains(string(out), "No such device") && !strings.Contains(string(out), "not exist") {
			im.t.Logf("dmsetup remove %s: %v %s", name, err, out)
		}
	}
	if out, _ := exec.Command("dmsetup", "ls").CombinedOutput(); strings.Contains(string(out), im.names.FS) {
		im.t.Errorf("mapping %s survived the power off:\n%s", im.names.FS, out)
	}
}

func (im *image) read(h *hybrid, rel string) []byte {
	im.t.Helper()
	raw, err := os.ReadFile(filepath.Join(h.mountAt, rel))
	if err != nil {
		im.t.Fatal(err)
	}
	return raw
}

func (im *image) status(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.OpenFile(im.mailbox, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := vmmailbox.New(readerOnly{f}, vmmailbox.MailboxBytes)
	if err != nil {
		t.Fatal(err)
	}
	doc, ok := m.ReadStatus()
	if !ok {
		t.Fatal("no status record in the mailbox")
	}
	return doc
}

type readerOnly struct{ *os.File }

func (readerOnly) WriteAt([]byte, int64) (int, error) { return 0, errors.New("read only") }
func (readerOnly) Sync() error                        { return nil }

func TestRootWiredBlankFirstBootThenRebootThenReadyBoot(t *testing.T) {
	needRoot(t)
	im := newImage(t)

	h1, err := im.boot(t, "")
	if !errors.Is(err, errStopped) {
		t.Fatalf("first boot: %v", err)
	}
	hostKey := im.read(h1, "etc/ssh/ssh_host_ed25519_key.pub")
	privKey := im.read(h1, "etc/ssh/ssh_host_ed25519_key")
	recovery := im.read(h1, "var/lib/cathedral-vm/recovery.key")
	if !bytes.Contains(recovery, []byte("vm-0123456789ab")) || !bytes.HasPrefix(hostKey, []byte("ssh-ed25519 ")) {
		t.Fatalf("first boot files: %s %s", hostKey, recovery)
	}
	if st := im.status(t); st["state"] != "new" || st["key_id"] == "" {
		t.Fatalf("first boot status: %v", st)
	}
	if got := im.read(h1, "run/systemd/network/10-uplink.network"); !bytes.Contains(got, []byte("Address=10.216.0.6/30")) {
		t.Fatalf("network file: %s", got)
	}
	if _, err := os.Stat(filepath.Join(h1.mountAt, "etc/cloud/cloud-init.disabled")); err != nil {
		t.Fatal("cloud-init is not off")
	}
	// The tools the customer runs are the bound, read-only measured copies.
	attest := filepath.Join(h1.mountAt, "run/cathedral/bin/cathedral-attest")
	if err := os.WriteFile(attest, []byte("x"), 0o755); !errors.Is(err, syscall.EROFS) {
		t.Fatalf("the bound attest tool is writable: %v", err)
	}
	im.powerOff(h1)

	// Reboot: the same disk, a ready boot.
	h2, err := im.boot(t, "")
	if !errors.Is(err, errStopped) {
		t.Fatalf("ready boot: %v", err)
	}
	if got := im.read(h2, "etc/ssh/ssh_host_ed25519_key.pub"); !bytes.Equal(got, hostKey) {
		t.Error("the host key changed across a reboot")
	}
	if got := im.read(h2, "etc/ssh/ssh_host_ed25519_key"); !bytes.Equal(got, privKey) {
		t.Error("the private host key changed across a reboot")
	}
	if got := im.read(h2, "var/lib/cathedral-vm/recovery.key"); !bytes.Equal(got, recovery) {
		t.Error("the recovery record changed across a reboot")
	}
	if st := im.status(t); st["state"] != "open" {
		t.Fatalf("ready boot status: %v", st)
	}
	for _, c := range h2.calls {
		if c == "firstboot" {
			t.Error("a ready boot ran the first boot again")
		}
	}
}

// The deliberate breaks: each must stop the boot and leave the root disk as it was, or at least
// never reach a started root.
func TestRootWiredRefusals(t *testing.T) {
	needRoot(t)
	t.Run("an unpinned attest tool is refused before any disk", func(t *testing.T) {
		im := newImage(t)
		before := sha256File(t, im.root)
		_, err := im.boot(t, attestName)
		if err == nil || errors.Is(err, errStopped) || !strings.Contains(err.Error(), attestName) {
			t.Fatalf("got %v", err)
		}
		if sha256File(t, im.root) != before {
			t.Error("the root disk changed")
		}
	})
	t.Run("a flipped base block never reaches a started root", func(t *testing.T) {
		im := newImage(t)
		raw, _ := os.ReadFile(im.base)
		raw[3*4096+10] ^= 1
		os.WriteFile(im.base, raw, 0o644)
		h, err := im.boot(t, "")
		if err == nil || errors.Is(err, errStopped) {
			t.Fatalf("got %v", err)
		}
		if _, statErr := os.Stat(h.mountAt); statErr == nil {
			t.Error("a root was mounted from an unverified base")
		}
		// The next boot with a good base resumes the format and reaches ready.
		raw[3*4096+10] ^= 1
		os.WriteFile(im.base, raw, 0o644)
		if _, err := im.boot(t, ""); !errors.Is(err, errStopped) {
			t.Fatalf("recovery boot: %v", err)
		}
	})
	t.Run("a bad link is refused before any disk", func(t *testing.T) {
		im := newImage(t)
		before := sha256File(t, im.root)
		f := newFake(t)
		f.outcome = vmdisk.Outcome{}
		f.identity, f.cmdline, f.link = im.identity, im.cmdline, []byte("192.0.2.1 192.0.2.2")
		h := &hybrid{fake: f, im: im}
		err := boot(context.Background(), h)
		if err == nil || h.disked() {
			t.Fatalf("got %v, disked %v", err, h.disked())
		}
		if sha256File(t, im.root) != before {
			t.Error("the root disk changed")
		}
	})
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
