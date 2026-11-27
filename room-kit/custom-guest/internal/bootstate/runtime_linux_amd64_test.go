package bootstate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

// Opt-in: the runner must give this test a scratch directory inside a private
// mount namespace. It mounts only newly created test directories, never /run.
func TestRuntimeMountCapacity(t *testing.T) {
	parent := os.Getenv("GUEST_RUNTIME_MOUNT_TEST_DIR")
	if parent == "" || os.Geteuid() != 0 {
		t.Skip("requires the private mount-namespace test runner")
	}
	path, err := os.MkdirTemp(parent, "runtime-mount-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })
	target, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if err := mountRuntime(target); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(path, 0); err != nil {
			t.Error(err)
		}
	})
	run, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	if err := writeRuntime(run, runtimeLaunch(t), "eth0", rand.Reader); err != nil {
		t.Fatal(err)
	}
	// Exercise capacity beyond the old 256-inode cap using zero-byte entries.
	// This models runtime state, not a full systemd boot.
	for i := range 512 {
		f, err := run.OpenFile(fmt.Sprintf("unit-%d", i), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatalf("runtime inode %d: %v", i, err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// systemd's PID1 re-execution alone needs 16 MiB free. Verify that it fits
	// after other runtime contents rather than only checking statfs capacity.
	f, err := run.OpenFile("reexec-state", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	block := make([]byte, 1<<20)
	for range 17 {
		if n, err := f.Write(block); err != nil || n != len(block) {
			t.Fatalf("runtime space: wrote %d: %v", n, err)
		}
	}
}

func runtimeLaunch(t *testing.T) bootstrap.Launch {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := func(v []byte) []byte {
		b := make([]byte, 4, 4+len(v))
		binary.BigEndian.PutUint32(b, uint32(len(v)))
		return append(b, v...)
	}
	key := append(wire([]byte("ssh-ed25519")), wire(public)...)
	return bootstrap.Launch{Bootstrap: bootstrap.Bootstrap{
		SSHPublicKey: "ssh-ed25519 " + base64.StdEncoding.EncodeToString(key),
		Network:      bootstrap.Network{GuestIP: "10.217.0.2", HostIP: "10.217.0.1", Prefix: 30},
	}}
}

func runtimeRAM(t *testing.T) (*os.Root, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root ownership required")
	}
	parent := os.Getenv("GUEST_RUNTIME_TEST_TMPFS")
	if parent == "" {
		parent = "/dev/shm"
	}
	var fs syscall.Statfs_t
	const flags = syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC
	if err := syscall.Statfs(parent, &fs); err != nil || fs.Type != tmpfsMagic || fs.Flags&flags != flags {
		t.Skip("requires a private nosuid,nodev,noexec tmpfs; tests never mount host paths")
	}
	path, err := os.MkdirTemp(parent, "guest-runtime-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(path) }) // Only this test's private RAM directory.
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root, path
}

type runtimeEntropy struct{ called bool }

func (r *runtimeEntropy) Read([]byte) (int, error) {
	r.called = true
	return 0, errors.New("test entropy failure")
}

func TestRuntimeRAMFilesAndFreshKeys(t *testing.T) {
	launch := runtimeLaunch(t)
	var previous []byte
	for range 2 {
		root, path := runtimeRAM(t)
		if err := writeRuntime(root, launch, "eth0", rand.Reader); err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(path, "cathedral")
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0700 {
			t.Fatal("runtime directory permissions")
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 4 {
			t.Fatal("unexpected runtime file count")
		}
		for _, name := range []string{"ssh_host_ed25519_key", "ssh_host_ed25519_key.pub", "authorized_keys", "network.env"} {
			p := filepath.Join(dir, name)
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != 0 {
				t.Fatal("runtime file ownership or permissions")
			}
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "ssh_host_ed25519_key":
				block, rest := pem.Decode(data)
				if block == nil || block.Type != "OPENSSH PRIVATE KEY" || len(block.Bytes) == 0 || len(rest) != 0 {
					t.Fatal("private key encoding")
				}
			case "ssh_host_ed25519_key.pub":
				if bytes.Equal(previous, data) {
					t.Fatal("host key reused")
				}
				previous = bytes.Clone(data)
			case "authorized_keys":
				if string(data) != launch.Bootstrap.SSHPublicKey+"\n" {
					t.Fatal("wrong authorized owner")
				}
			case "network.env":
				if string(data) != "CATHEDRAL_INTERFACE=eth0\nCATHEDRAL_GUEST_CIDR=10.217.0.2/30\nCATHEDRAL_GATEWAY=10.217.0.1\n" {
					t.Fatal("wrong network settings")
				}
			}
			clear(data)
		}
		entropy := &runtimeEntropy{}
		if err := writeRuntime(root, launch, "eth0", entropy); err == nil || entropy.called {
			t.Fatal("reused runtime directory accepted or entropy read")
		}
	}
}

func TestRuntimeRefusesUnsafeStorageBeforeEntropy(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	entropy := &runtimeEntropy{}
	if err := writeRuntime(root, runtimeLaunch(t), "eth0", entropy); err == nil || entropy.called {
		t.Fatal("unsafe storage reached entropy")
	}
	if _, err := root.Stat("cathedral"); !os.IsNotExist(err) {
		t.Fatal("unsafe storage was modified")
	}
}

func TestRuntimeRefusesWritableRAM(t *testing.T) {
	root, path := runtimeRAM(t)
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	entropy := &runtimeEntropy{}
	if err := writeRuntime(root, runtimeLaunch(t), "eth0", entropy); err == nil || entropy.called {
		t.Fatal("public runtime accepted")
	}
}

func TestRuntimeRejectsAliasesAndInvalidInput(t *testing.T) {
	for _, mode := range []string{"existing", "symlink", "entropy", "interface", "owner"} {
		t.Run(mode, func(t *testing.T) {
			root, path := runtimeRAM(t)
			launch := runtimeLaunch(t)
			iface := "eth0"
			switch mode {
			case "existing":
				if err := os.Mkdir(filepath.Join(path, "cathedral"), 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(".", filepath.Join(path, "cathedral")); err != nil {
					t.Fatal(err)
				}
			case "interface":
				iface = "eth0\nBAD=1"
			case "owner":
				launch.Bootstrap.SSHPublicKey += "\nforeign"
			}
			entropy := &runtimeEntropy{}
			if err := writeRuntime(root, launch, iface, entropy); err == nil {
				t.Fatal("invalid runtime accepted")
			}
			if entropy.called != (mode == "entropy") {
				t.Fatal("wrong entropy ordering")
			}
			entries, err := os.ReadDir(filepath.Join(path, "cathedral"))
			if err != nil {
				t.Fatal(err)
			}
			if mode != "symlink" && len(entries) != 0 {
				t.Fatal("files written on failure")
			}
		})
	}
}

func TestRuntimeMountTargetsRejectAliases(t *testing.T) {
	path := t.TempDir()
	if err := os.Mkdir(filepath.Join(path, "dev"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("dev", filepath.Join(path, "sys")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "proc"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, err := rootDirectory(root, "dev")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, name := range []string{"sys", "proc", "missing"} {
		if f, err := rootDirectory(root, name); err == nil || f != nil {
			t.Fatal("invalid mount target accepted")
		}
	}
}

func TestRuntimeCannotExecuteOutsideVerifiedPID1(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("test must not run as PID1")
	}
	if root, err := PrepareVerifiedRuntime(bootstrap.Launch{}, [32]byte{}, [32]byte{}); err == nil || root != nil || !strings.Contains(err.Error(), "PID1") {
		t.Fatal("preparation allowed outside PID1")
	}
	for _, root := range []*ReadyRoot{nil, {}, {ready: true}} {
		if err := root.Exec(); err == nil {
			t.Fatal("handoff allowed outside PID1")
		}
	}
}

// Opt-in integration probe. Run only in an empty private mount/PID namespace
// rooted at a synthetic initramfs. The runner supplies a harmless /sbin/init
// that checks the moved mounts. It does not use a customer root or any secrets.
func TestRuntimeIsolatedHandoff(t *testing.T) {
	if os.Getenv("GUEST_RUNTIME_HANDOFF_PROBE") != "1" {
		t.Skip("isolated PID1 integration runner only")
	}
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		t.Fatal("probe requires isolated root PID1")
	}
	// Deliberately bypass preparation only in this test: this proves the mount
	// handoff, not verity validation or the full authenticated boot chain.
	root := &ReadyRoot{ready: true}
	if err := root.Exec(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("handoff returned")
}
