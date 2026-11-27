package bootstrap

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/snp"
)

type firmwareFixture struct {
	dir, cmdline string
	launch       Launch
}

func firmwareFixtureFor(t *testing.T) firmwareFixture {
	t.Helper()
	v := vector(t)
	sig, err := hex.DecodeString(v["signature_hex"])
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err = json.Unmarshal([]byte(v["manifest_utf8"]), &m); err != nil {
		t.Fatal(err)
	}
	line := "initrd=initrd " + m.Cmdline + "\n"
	launch, err := Validate([]byte(v["manifest_utf8"]), []byte(v["bootstrap_utf8"]), sig, line)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fw := filepath.Join(dir, "by_name/opt/cathedral")
	if err = os.MkdirAll(fw, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"manifest.json": []byte(v["manifest_utf8"]), "bootstrap.json": []byte(v["bootstrap_utf8"]), "bootstrap.sig": sig} {
		// The kernel's by_name tree ends in directory symlinks to by_key.
		key := filepath.Join(dir, "by_key", name)
		if err = os.MkdirAll(key, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(key, "raw"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Symlink(key, filepath.Join(fw, name)); err != nil {
			t.Fatal(err)
		}
	}
	cmdline := filepath.Join(dir, "cmdline")
	if err = os.WriteFile(cmdline, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	return firmwareFixture{fw, cmdline, launch}
}

func localReport(data [64]byte, launch Launch) []byte {
	r := make([]byte, snp.ReportBytes)
	binary.LittleEndian.PutUint32(r, 5)
	binary.LittleEndian.PutUint64(r[8:], 0x30000)
	copy(r[0x50:0x90], data[:])
	copy(r[0xc0:0xe0], launch.HostData[:])
	return r
}

func TestFirmwareLaunchIsBoundToFreshNativeReport(t *testing.T) {
	f := firmwareFixtureFor(t)
	var seen [][64]byte
	for _, nonce := range []byte{0x31, 0x32} {
		got, err := readBoundLaunch(f.dir, f.cmdline, bytes.NewReader(bytes.Repeat([]byte{nonce}, 32)), func(data [64]byte) ([]byte, error) {
			seen = append(seen, data)
			var n [32]byte
			copy(n[:], bytes.Repeat([]byte{nonce}, 32))
			if data != snp.BootData(n) {
				t.Fatal("not the boot-check domain")
			}
			return localReport(data, f.launch), nil
		})
		if err != nil || !reflect.DeepEqual(got, f.launch) {
			t.Fatalf("bound launch: %v", err)
		}
	}
	if seen[0] == seen[1] {
		t.Fatal("boot report reused its challenge")
	}
}

func TestInvalidFirmwareNeverRequestsAReport(t *testing.T) {
	for _, name := range []string{"missing", "extra", "manifest_big", "bootstrap_big", "signature_big", "signature_short", "bad_signature", "changed_cmdline", "cmdline_big", "raw_symlink", "fifo", "empty"} {
		t.Run(name, func(t *testing.T) {
			f := firmwareFixtureFor(t)
			manifest := filepath.Join(f.dir, "manifest.json/raw")
			write := func(path string, raw []byte) {
				t.Helper()
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "missing":
				if err := os.Remove(filepath.Join(f.dir, "bootstrap.sig")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				write(filepath.Join(f.dir, "extra"), []byte("untrusted"))
			case "manifest_big":
				write(manifest, bytes.Repeat([]byte("x"), documentLimit+1))
			case "bootstrap_big":
				write(filepath.Join(f.dir, "bootstrap.json/raw"), bytes.Repeat([]byte("x"), documentLimit+1))
			case "signature_big":
				write(filepath.Join(f.dir, "bootstrap.sig/raw"), make([]byte, 65))
			case "signature_short":
				write(filepath.Join(f.dir, "bootstrap.sig/raw"), make([]byte, 63))
			case "bad_signature":
				write(filepath.Join(f.dir, "bootstrap.sig/raw"), make([]byte, 64))
			case "changed_cmdline":
				write(f.cmdline, []byte("initrd=initrd "+f.launch.Manifest.Cmdline+" quiet\n"))
			case "cmdline_big":
				write(f.cmdline, []byte(strings.Repeat("x", 2049)))
			case "raw_symlink", "fifo":
				if err := os.Remove(manifest); err != nil {
					t.Fatal(err)
				}
				var err error
				if name == "fifo" {
					err = syscall.Mkfifo(manifest, 0600)
				} else {
					err = os.Symlink(f.cmdline, manifest)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "empty":
				write(manifest, nil)
			}
			got, err := readBoundLaunch(f.dir, f.cmdline, bytes.NewReader(make([]byte, 32)), func([64]byte) ([]byte, error) { t.Fatal("report requested for invalid input"); return nil, nil })
			if err == nil || !reflect.DeepEqual(got, Launch{}) {
				t.Fatal("invalid input returned launch fields")
			}
		})
	}
}

func TestFailedNativeBindingReturnsNoLaunchFields(t *testing.T) {
	for _, name := range []string{"entropy", "driver", "host_data", "challenge", "policy", "vmpl", "short_report", "unknown_version", "masked_chip"} {
		t.Run(name, func(t *testing.T) {
			f := firmwareFixtureFor(t)
			nonce := make([]byte, 32)
			if name == "entropy" {
				nonce = nonce[:31]
			}
			got, err := readBoundLaunch(f.dir, f.cmdline, bytes.NewReader(nonce), func(data [64]byte) ([]byte, error) {
				if name == "entropy" {
					t.Fatal("report called despite failed entropy")
				}
				if name == "driver" {
					return nil, errors.New("driver failed")
				}
				r := localReport(data, f.launch)
				switch name {
				case "host_data":
					r[0xc0] ^= 1
				case "challenge":
					r[0x50] ^= 1
				case "policy":
					r[8] ^= 1
				case "vmpl":
					r[0x30] = 1
				case "short_report":
					r = r[:100]
				case "unknown_version":
					r[0] = 6
				case "masked_chip":
					r[0x48] = 2
				}
				return r, nil
			})
			if err == nil || !reflect.DeepEqual(got, Launch{}) {
				t.Fatal("failed binding returned launch fields")
			}
		})
	}
}
