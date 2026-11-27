package bootstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

func verityFixture() ([]byte, bootstrap.Manifest) {
	m := bootstrap.Manifest{RootDataBytes: 4096 * 129, RootVerity: strings.Repeat("a", 64), Bytes: map[string]int64{"root.raw": 4096 * 133}}
	raw := make([]byte, m.Bytes["root.raw"])
	sb := raw[m.RootDataBytes:]
	copy(sb, "verity\x00\x00")
	binary.LittleEndian.PutUint32(sb[8:], 1)
	binary.LittleEndian.PutUint32(sb[12:], 1)
	copy(sb[32:], "sha256")
	binary.LittleEndian.PutUint32(sb[64:], 4096)
	binary.LittleEndian.PutUint32(sb[68:], 4096)
	binary.LittleEndian.PutUint64(sb[72:], 129)
	binary.LittleEndian.PutUint16(sb[80:], 32)
	copy(sb[88:], bytes.Repeat([]byte{0x53}, 32))
	return raw, m
}

func TestVerityExplicitParameters(t *testing.T) {
	raw, m := verityFixture()
	args, err := verityArgs(bytes.NewReader(raw), m)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, must := range []string{"--no-superblock", "--format=1", "--hash=sha256", "--data-blocks=129", "--hash-offset=532480", "--salt=" + strings.Repeat("53", 32), "--panic-on-corruption", "open /proc/self/fd/4 cathedral-root /proc/self/fd/4 " + m.RootVerity} {
		if !strings.Contains(joined, must) {
			t.Errorf("missing %s", must)
		}
	}
	if strings.Contains(joined, "ignore") || strings.Contains(joined, "restart") {
		t.Fatal("unsafe error policy")
	}
}

func TestVerityRefusesChangedGeometry(t *testing.T) {
	for _, offset := range []int{0, 8, 12, 32, 63, 64, 68, 72, 80} {
		t.Run(string(rune('a'+offset)), func(t *testing.T) {
			raw, m := verityFixture()
			raw[int(m.RootDataBytes)+offset] ^= 1
			if args, err := verityArgs(bytes.NewReader(raw), m); err == nil || args != nil {
				t.Fatalf("accepted changed byte %d", offset)
			}
		})
	}
	for _, mode := range []string{"short-header", "short-tree", "unaligned", "hash", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			raw, m := verityFixture()
			switch mode {
			case "short-header":
				raw = raw[:m.RootDataBytes+511]
			case "short-tree":
				m.Bytes["root.raw"] -= 4096
			case "unaligned":
				m.RootDataBytes++
			case "hash":
				m.RootVerity = strings.Repeat("A", 64)
			case "overflow":
				m.RootDataBytes = 1 << 62
			}
			if args, err := verityArgs(bytes.NewReader(raw), m); err == nil || args != nil {
				t.Fatal("accepted invalid geometry")
			}
		})
	}
}

func TestPinnedVerityHelper(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("positive helper owner check requires root")
	}
	p := filepath.Join(t.TempDir(), "helper")
	raw := []byte("\x7fELFfixture: never executed")
	if err := os.WriteFile(p, raw, 0755); err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(raw)
	f, err := openPinnedHelper(p, pin)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for _, mode := range []string{"pin", "missing-pin", "writable", "nonexec", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			path := p
			expected := pin
			if err := os.Chmod(p, 0755); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "pin":
				expected[0] ^= 1
			case "missing-pin":
				expected = [32]byte{}
			case "writable":
				os.Chmod(p, 0777)
			case "nonexec":
				os.Chmod(p, 0644)
			case "symlink":
				path = filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(p, path); err != nil {
					t.Fatal(err)
				}
			}
			if f, err := openPinnedHelper(path, expected); err == nil || f != nil {
				t.Fatal("accepted invalid helper")
			}
		})
	}
}

func TestMountRefusesOutsideInit(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("test must not be PID1")
	}
	root, err := MountVerifiedRoot(bootstrap.Launch{}, [32]byte{})
	if err == nil || root != "" || errors.Is(err, os.ErrNotExist) {
		t.Fatal("mount attempted outside init")
	}
}
