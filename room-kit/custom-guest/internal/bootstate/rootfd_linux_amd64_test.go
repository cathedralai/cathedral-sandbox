package bootstate

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRootHandleKeepsSelectedFile(t *testing.T) {
	sys, launch := fixture(t, true)
	put(t, sys, "block/vdb/dev", "252:16\n")
	dev := t.TempDir()
	put(t, dev, "vdb", "selected")
	// No vda node: optional data must never be opened.
	f, err := openRootDevice(launch, sys, dev, func(f *os.File, number uint64, size int64) error {
		if number != 0xfc10 || size != launch.Manifest.Bytes["root.raw"] {
			t.Fatal("wrong device identity")
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFL, 0)
		if errno != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY {
			t.Fatal("root opened writable")
		}
		if err := os.Rename(filepath.Join(dev, "vdb"), filepath.Join(dev, "old")); err != nil {
			t.Fatal(err)
		}
		put(t, dev, "vdb", "replacement")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil || string(raw) != "selected" {
		t.Fatalf("lost pinned descriptor: %q %v", raw, err)
	}
}

func TestRootOpenFailuresCloseDescriptor(t *testing.T) {
	for _, mode := range []string{"inspection", "inventory-change", "regular-file"} {
		t.Run(mode, func(t *testing.T) {
			sys, launch := fixture(t, false)
			put(t, sys, "block/vdb/dev", "252:16\n")
			dev := t.TempDir()
			put(t, dev, "vdb", "not a block device")
			var captured *os.File
			f, err := openRootDevice(launch, sys, dev, func(f *os.File, number uint64, size int64) error {
				captured = f
				switch mode {
				case "inspection":
					return errors.New("ioctl failed")
				case "inventory-change":
					put(t, sys, "block/vdb/ro", "0\n")
					return nil
				default:
					return inspectRootDescriptor(f, number, size)
				}
			})
			if err == nil || f != nil || captured == nil {
				t.Fatal("failure returned a device")
			}
			if _, err := captured.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatal("failed descriptor leaked")
			}
		})
	}
}

func TestRootOpenRejectsSymlink(t *testing.T) {
	sys, launch := fixture(t, false)
	put(t, sys, "block/vdb/dev", "252:16\n")
	dev := t.TempDir()
	put(t, dev, "target", "bad")
	if err := os.Symlink("target", filepath.Join(dev, "vdb")); err != nil {
		t.Fatal(err)
	}
	f, err := openRootDevice(launch, sys, dev, func(*os.File, uint64, int64) error { t.Fatal("symlink followed"); return nil })
	if err == nil || f != nil {
		t.Fatal("symlink accepted")
	}
}

func TestDeviceNumber(t *testing.T) {
	for _, raw := range []string{"", "1", "1:2:3", "-1:2", "01:2", "1:02", "4294967296:1", "1:4294967296", "1:2\n"} {
		if _, err := deviceNumber(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for raw, want := range map[string]uint64{"0:0": 0, "252:16": 0xfc10, "4095:255": 0xfffff, "4096:256": 0x100000100000} {
		got, err := deviceNumber(raw)
		if err != nil || got != want {
			t.Errorf("%s: %x != %x (%v)", raw, got, want, err)
		}
	}
}
