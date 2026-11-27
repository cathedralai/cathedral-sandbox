package vmroot

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmrecovery"
)

const (
	testVMID = "vm-0123456789ab"
	testSHA  = "64bd36bb2a9075d85cf238131b45a58c82f3959b47438ab379de56c71981fc89"
	testKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHoDtpqWFYgHInGUaI+YzF7+kVPelQqOMZroOCQpu3bE"
)

// pristine writes the part of the base root the steps touch, as the verified base copy leaves it.
func pristine(t *testing.T, dir string) {
	t.Helper()
	files := map[string]string{
		"etc/passwd":                   "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
		"etc/group":                    "root:x:0:\nsudo:x:27:\n",
		"etc/shadow":                   "root:*:20000:0:99999:7:::\n",
		"etc/gshadow":                  "root:*::\n",
		"etc/ssh/ssh_host_rsa_key":     "BASE SHIPPED KEY",
		"etc/ssh/ssh_host_rsa_key.pub": "BASE SHIPPED KEY",
		"etc/ssh/sshd_config":          "Include /etc/ssh/sshd_config.d/*.conf\n",
	}
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// seeded is a reproducible byte stream for key and recovery generation.
func seeded(label string) *bytes.Reader {
	var out []byte
	for i := 0; len(out) < 4096; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", label, i)))
		out = append(out, sum[:]...)
	}
	return bytes.NewReader(out)
}

type chownLog struct{ entries []string }

func (c *chownLog) chown(_ *os.Root, name string, uid, gid int) error {
	c.entries = append(c.entries, fmt.Sprintf("%s=%d:%d", name, uid, gid))
	return nil
}

// digest is a stable summary of the tree: path, type, mode and content hash of every entry.
func digest(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		info, err := d.Info()
		if err != nil {
			return err
		}
		sum := ""
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			h := sha256.Sum256(raw)
			sum = hex.EncodeToString(h[:])
		}
		lines = append(lines, fmt.Sprintf("%s %v %s", rel, info.Mode(), sum))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	all := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(all[:])
}

func opts(chown *chownLog, cut func(string) error) TreeOptions {
	return TreeOptions{Identity: Identity{VMID: testVMID, IdentitySHA256: testSHA, SSHPublicKey: testKey},
		Random: seeded("tree"), Chown: chown.chown, Cut: cut}
}

func runAll(t *testing.T, dir string, o TreeOptions) (vmrecovery.Record, error) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := PrepareTree(root, o); err != nil {
		return vmrecovery.Record{}, err
	}
	return WriteRecovery(root, o)
}

func TestPrepareTreeMakesUserKeysAndCloudInitOff(t *testing.T) {
	dir := t.TempDir()
	pristine(t, dir)
	log := &chownLog{}
	rec, err := runAll(t, dir, opts(log, nil))
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	if !strings.HasSuffix(read("etc/passwd"), "cathedral:x:1000:1000:Cathedral VM user:/home/cathedral:/bin/bash\n") ||
		!strings.Contains(read("etc/group"), "cathedral:x:1000:\n") || !strings.Contains(read("etc/shadow"), "cathedral:*:") ||
		!strings.Contains(read("etc/gshadow"), "cathedral:!::") {
		t.Fatal("user files")
	}
	if read("home/cathedral/.ssh/authorized_keys") != testKey+"\n" {
		t.Fatal("authorized_keys")
	}
	for name, mode := range map[string]os.FileMode{
		"home/cathedral/.ssh/authorized_keys": 0o600, "home/cathedral": 0o700 | os.ModeDir,
		"etc/sudoers.d/90-cathedral": 0o440, "etc/ssh/ssh_host_ed25519_key": 0o600,
		"etc/ssh/ssh_host_ed25519_key.pub": 0o644, "etc/cloud/cloud-init.disabled": 0o644,
		"var/lib/cathedral-vm/recovery.key": 0o600, "var/lib/cathedral-vm": 0o700 | os.ModeDir,
	} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode() != mode {
			t.Errorf("%s: %v %v", name, info, err)
		}
	}
	if read("etc/sudoers.d/90-cathedral") != "cathedral ALL=(ALL) NOPASSWD:ALL\n" {
		t.Error("sudoers")
	}
	for _, want := range []string{"home/cathedral=1000:1000", "home/cathedral/.ssh=1000:1000", "home/cathedral/.ssh/authorized_keys=1000:1000"} {
		found := false
		for _, e := range log.entries {
			found = found || e == want
		}
		if !found {
			t.Errorf("no chown %s in %v", want, log.entries)
		}
	}
	// The base's own host keys are gone: one key per VM, never a shared one.
	if _, err := os.Stat(filepath.Join(dir, "etc/ssh/ssh_host_rsa_key")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("a host key the base shipped survived")
	}
	if !strings.Contains(read("etc/ssh/sshd_config.d/10-cathedral-vm.conf"), "HostKey /etc/ssh/ssh_host_ed25519_key") {
		t.Error("sshd drop-in")
	}
	// The recovery file is what vmrecovery reads, and names this identity.
	back, err := vmrecovery.Parse([]byte(read("var/lib/cathedral-vm/recovery.key")))
	if err != nil || back != rec || !back.IdentityMatches(testVMID, testSHA) {
		t.Fatalf("recovery record: %v", err)
	}
}

// The private key must be a file OpenSSH itself reads and whose public half is the .pub line.
func TestHostKeyIsAnOpenSSHKeyFile(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not installed")
	}
	private, public, blob, err := openSSHEd25519(seeded("hostkey"), "cathedral-vm")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, private, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(keygen, "-y", "-f", path).Output()
	if err != nil {
		t.Fatalf("ssh-keygen -y: %v", err)
	}
	if got := strings.Fields(string(out)); got[0] != "ssh-ed25519" || got[1] != strings.Fields(string(public))[1] {
		t.Fatalf("public half differs: %s vs %s", out, public)
	}
	fp, err := exec.Command(keygen, "-l", "-f", path).Output()
	if err != nil || !strings.Contains(string(fp), HostKeyFingerprint(blob)) {
		t.Fatalf("fingerprint %s vs %s (%v)", fp, HostKeyFingerprint(blob), err)
	}
	// The .pub line is what cathedral-attest hashes; its blob decodes to the same bytes.
	raw, _ := base64.StdEncoding.DecodeString(strings.Fields(string(public))[1])
	if !bytes.Equal(raw, blob) {
		t.Fatal("blob")
	}
}

// 7.2 step 4: a cut leaves a partial tree and the next boot copies the base again, so a rerun on
// a fresh copy with the same inputs must give the tree of an uninterrupted run, whichever point
// the first run was cut at.
func TestRerunAfterCutAtEachPointGivesTheSameTree(t *testing.T) {
	whole := t.TempDir()
	pristine(t, whole)
	if _, err := runAll(t, whole, opts(&chownLog{}, nil)); err != nil {
		t.Fatal(err)
	}
	want := digest(t, whole)
	for _, point := range []string{CutUser, CutHostKey, CutCloudInit, CutRecovery} {
		dir := t.TempDir()
		pristine(t, dir)
		cutHere := func(p string) error {
			if p == point {
				return errors.New("cut")
			}
			return nil
		}
		if _, err := runAll(t, dir, opts(&chownLog{}, cutHere)); err == nil {
			t.Fatalf("%s: the cut did not stop the run", point)
		}
		// The partial tree must not silently pass a second run in place (O_EXCL): it is thrown away.
		if point != CutUser {
			if _, err := runAll(t, dir, opts(&chownLog{}, nil)); err == nil {
				t.Errorf("%s: a rerun in place on a partial tree succeeded", point)
			}
		}
		fresh := t.TempDir()
		pristine(t, fresh)
		if _, err := runAll(t, fresh, opts(&chownLog{}, nil)); err != nil {
			t.Fatal(err)
		}
		if got := digest(t, fresh); got != want {
			t.Errorf("%s: the rerun tree differs", point)
		}
	}
}

func TestPrepareTreeRefusals(t *testing.T) {
	cases := map[string]func(t *testing.T, dir string, o *TreeOptions){
		"a bad ssh key": func(t *testing.T, dir string, o *TreeOptions) {
			o.Identity.SSHPublicKey = "ssh-ed25519 AAAA\nssh-rsa BBBB"
		},
		"a key with a comment": func(t *testing.T, dir string, o *TreeOptions) { o.Identity.SSHPublicKey = testKey + " me@host" },
		"an existing user": func(t *testing.T, dir string, o *TreeOptions) {
			os.WriteFile(filepath.Join(dir, "etc/passwd"), []byte("root:x:0:0::/root:/bin/sh\ncathedral:x:5:5::/h:/bin/sh\n"), 0o644)
		},
		"uid 1000 taken": func(t *testing.T, dir string, o *TreeOptions) {
			os.WriteFile(filepath.Join(dir, "etc/passwd"), []byte("ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n"), 0o644)
		},
		"gid 1000 taken": func(t *testing.T, dir string, o *TreeOptions) {
			os.WriteFile(filepath.Join(dir, "etc/group"), []byte("ubuntu:x:1000:\n"), 0o644)
		},
		"a sudoers file already there": func(t *testing.T, dir string, o *TreeOptions) {
			os.MkdirAll(filepath.Join(dir, "etc/sudoers.d"), 0o750)
			os.WriteFile(filepath.Join(dir, "etc/sudoers.d/90-cathedral"), []byte("x"), 0o440)
		},
		"no entropy": func(t *testing.T, dir string, o *TreeOptions) { o.Random = bytes.NewReader(make([]byte, 10)) },
	}
	for why, mutate := range cases {
		dir := t.TempDir()
		pristine(t, dir)
		o := opts(&chownLog{}, nil)
		mutate(t, dir, &o)
		if _, err := runAll(t, dir, o); err == nil {
			t.Errorf("%s: accepted", why)
		}
	}
}

func TestAssertCloudInitOffReplacesALinkAndKeepsAMarker(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "etc/cloud"), 0o755)
	marker := filepath.Join(dir, "etc/cloud/cloud-init.disabled")
	os.WriteFile(filepath.Join(dir, "elsewhere"), []byte("x"), 0o644)
	if err := os.Symlink("../../elsewhere", marker); err != nil {
		t.Fatal(err)
	}
	root, _ := os.OpenRoot(dir)
	defer root.Close()
	if err := AssertCloudInitOff(root); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		t.Fatalf("marker: %v %v", info, err)
	}
	// Every boot calls it again; a good marker stays.
	if err := AssertCloudInitOff(root); err != nil {
		t.Fatal(err)
	}
	// A non-empty file is replaced by the empty marker.
	os.WriteFile(marker, []byte("junk"), 0o644)
	if err := AssertCloudInitOff(root); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Lstat(marker); info.Size() != 0 {
		t.Fatal("junk marker kept")
	}
}

func TestSymlinkInTheBaseCannotEscapeTheRoot(t *testing.T) {
	outside := t.TempDir()
	dir := t.TempDir()
	pristine(t, dir)
	// etc/ssh -> an absolute path outside the new root: os.Root must refuse to follow it.
	os.RemoveAll(filepath.Join(dir, "etc/ssh"))
	if err := os.Symlink(outside, filepath.Join(dir, "etc/ssh")); err != nil {
		t.Fatal(err)
	}
	if _, err := runAll(t, dir, opts(&chownLog{}, nil)); err == nil {
		t.Fatal("a link out of the root was followed")
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("wrote outside the root: %v", entries)
	}
}

func TestWriteNetworkAndLink(t *testing.T) {
	good := []byte("10.216.0.5 10.216.0.6")
	link, err := ParseLink(good)
	if err != nil || link.Guest.String() != "10.216.0.6" {
		t.Fatal(err)
	}
	for why, raw := range map[string]string{
		"public":         "192.0.2.1 192.0.2.2",
		"not a /30 pair": "10.216.0.5 10.216.0.7",
		"host not first": "10.216.0.6 10.216.0.7",
		"swapped":        "10.216.0.6 10.216.0.5",
		"leading zero":   "10.216.0.05 10.216.0.6",
		"ipv6":           "fd00::1 fd00::2",
		"newline":        "10.216.0.5 10.216.0.6\n",
		"three fields":   "10.216.0.5 10.216.0.6 10.216.0.7",
		"empty":          "",
		"172.32":         "172.32.0.1 172.32.0.2", // leak-guard: allow (just outside 172.16.0.0/12)
	} {
		if _, err := ParseLink([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", why)
		}
	}
	for _, ok := range []string{"172.16.0.1 172.16.0.2", "172.31.255.1 172.31.255.2", "192.168.7.5 192.168.7.6"} {
		if _, err := ParseLink([]byte(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	run := t.TempDir()
	root, _ := os.OpenRoot(run)
	defer root.Close()
	if err := WriteNetwork(root, good); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(run, "systemd/network/10-uplink.network"))
	if !strings.Contains(string(raw), "Address=10.216.0.6/30\nGateway=10.216.0.5\n") {
		t.Fatalf("network file: %s", raw)
	}
	// A rerun replaces the file; a bad link writes nothing new.
	if err := WriteNetwork(root, good); err != nil {
		t.Fatal(err)
	}
	if err := WriteNetwork(root, []byte("198.51.100.1 198.51.100.2")); err == nil {
		t.Fatal("bad link accepted")
	}
}
