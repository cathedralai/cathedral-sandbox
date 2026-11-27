package datavolume

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type diskFixture struct{ root, sys, dev, run, mounts string }

func put(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T) diskFixture {
	t.Helper()
	r := t.TempDir()
	f := diskFixture{r, filepath.Join(r, "sys"), filepath.Join(r, "dev"), filepath.Join(r, "run"), filepath.Join(r, "mountinfo")}
	for _, p := range []string{f.dev, f.run} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	f.disk(t, "vdb", "custom-data", "252:16")
	f.disk(t, "vda", "custom-root", "252:0")
	put(t, f.mounts, "25 1 0:1 / / rw - tmpfs tmpfs rw\n")
	return f
}
func (f diskFixture) disk(t *testing.T, name, serial, dev string) {
	t.Helper()
	b := filepath.Join(f.sys, "block", name)
	for k, v := range map[string]string{"serial": serial, "size": "2097152", "ro": "0", "dev": dev} {
		put(t, filepath.Join(b, k), v+"\n")
	}
	if err := os.Mkdir(filepath.Join(b, "holders"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(b, "device"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/sys/bus/virtio/drivers/virtio_blk", filepath.Join(b, "device/driver")); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(f.dev, name), "original")
}
func (f diskFixture) attr(t *testing.T, k, v string) {
	t.Helper()
	put(t, filepath.Join(f.sys, "block/vdb", k), v)
}
func (f diskFixture) open(inspect func(*os.File, diskIdentity) error) (*HeldDevice, error) {
	return openData(1, f.sys, f.dev, f.run, f.mounts, inspect)
}
func noInspect(*os.File, diskIdentity) error { return nil }

func TestDataSelection(t *testing.T) {
	f := fixture(t)
	got, err := selectedData(f.sys, 1<<30)
	if err != nil || got.name != "vdb" || got.dev != "252:16" || got.size != 1<<30 {
		t.Fatalf("selection: %+v %v", got, err)
	}
	// A post-boot verity mapping is expected; do not confuse it with the data disk.
	if err := os.Mkdir(filepath.Join(f.sys, "block/dm-0"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := selectedData(f.sys, 1<<30); err != nil {
		t.Fatal(err)
	}
}
func TestDataSelectionRefusals(t *testing.T) {
	cases := map[string]func(*testing.T, diskFixture){
		"absent":            func(t *testing.T, f diskFixture) { f.attr(t, "serial", "other") },
		"duplicate":         func(t *testing.T, f diskFixture) { f.disk(t, "vdc", "custom-data", "252:32") },
		"wrong-size":        func(t *testing.T, f diskFixture) { f.attr(t, "size", "2097151") },
		"noncanonical-size": func(t *testing.T, f diskFixture) { f.attr(t, "size", "02097152") },
		"readonly":          func(t *testing.T, f diskFixture) { f.attr(t, "ro", "1") },
		"device-number":     func(t *testing.T, f diskFixture) { f.attr(t, "dev", "252:016") },
		"overflow-number":   func(t *testing.T, f diskFixture) { f.attr(t, "dev", "4294967296:16") },
		"claimed":           func(t *testing.T, f diskFixture) { f.attr(t, "holders/dm-1", "") },
		"partition":         func(t *testing.T, f diskFixture) { f.attr(t, "vdb1/partition", "1") },
		"unreadable-serial": func(t *testing.T, f diskFixture) {
			if err := os.Rename(filepath.Join(f.sys, "block/vdb/serial"), filepath.Join(f.root, "serial.old")); err != nil {
				t.Fatal(err)
			}
		},
		"wrong-driver": func(t *testing.T, f diskFixture) {
			p := filepath.Join(f.sys, "block/vdb/device/driver")
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/sys/bus/scsi/drivers/sd", p); err != nil {
				t.Fatal(err)
			}
		},
		"serial-symlink": func(t *testing.T, f diskFixture) {
			p := filepath.Join(f.sys, "block/vdb/serial")
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".old", p); err != nil {
				t.Fatal(err)
			}
		},
		"serial-fifo": func(t *testing.T, f diskFixture) {
			p := filepath.Join(f.sys, "block/vdb/serial")
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(p, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"oversized-attribute": func(t *testing.T, f diskFixture) { f.attr(t, "serial", strings.Repeat("x", 4097)) },
		"embedded-newline":    func(t *testing.T, f diskFixture) { f.attr(t, "serial", "custom-data\n\n") },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			change(t, f)
			if got, err := selectedData(f.sys, 1<<30); err == nil {
				t.Fatalf("accepted %+v", got)
			}
		})
	}
}
func rootTest(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("private root-owned lock tests require uid 0; never access real devices")
	}
}
func TestHeldDataDescriptorAndLock(t *testing.T) {
	rootTest(t)
	f := fixture(t)
	d, err := f.open(noInspect)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.Size() != 1<<30 {
		t.Fatal("wrong size")
	}
	if second, err := f.open(noInspect); err == nil {
		second.Close()
		t.Fatal("concurrent unlock accepted")
	}
	path := filepath.Join(f.dev, "vdb")
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	put(t, path, "replaced")
	buf := make([]byte, 8)
	if _, err := d.ReadAt(buf, 0); err != nil || string(buf) != "original" {
		t.Fatalf("descriptor replaced: %q %v", buf, err)
	}
	for _, off := range []int64{-1, 1 << 30, (1 << 30) - 7} {
		if _, err := d.ReadAt(buf, off); err == nil {
			t.Fatal("out-of-range read accepted")
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadAt(buf, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed read: %v", err)
	}
	next, err := f.open(noInspect)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}
func TestOpenDataRefusals(t *testing.T) {
	rootTest(t)
	cases := map[string]func(*testing.T, diskFixture){
		"mounted":          func(t *testing.T, f diskFixture) { put(t, f.mounts, "25 1 252:16 / /data rw - ext4 /dev/vdb rw\n") },
		"mount-read-error": func(t *testing.T, f diskFixture) { put(t, f.mounts, "malformed\n") },
		"runtime-permissions": func(t *testing.T, f diskFixture) {
			if err := os.Chmod(f.run, 0755); err != nil {
				t.Fatal(err)
			}
		},
		"runtime-symlink": func(t *testing.T, f diskFixture) {
			if err := os.Rename(f.run, f.run+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(f.run+".old", f.run); err != nil {
				t.Fatal(err)
			}
		},
		"lock-permissions": func(t *testing.T, f diskFixture) {
			p := filepath.Join(f.run, "data.lock")
			put(t, p, "")
			if err := os.Chmod(p, 0644); err != nil {
				t.Fatal(err)
			}
		},
		"lock-hardlink": func(t *testing.T, f diskFixture) {
			p := filepath.Join(f.run, "data.lock")
			put(t, p, "")
			if err := os.Link(p, filepath.Join(f.root, "lock-alias")); err != nil {
				t.Fatal(err)
			}
		},
		"lock-symlink": func(t *testing.T, f diskFixture) {
			p := filepath.Join(f.root, "lock-target")
			put(t, p, "")
			if err := os.Symlink(p, filepath.Join(f.run, "data.lock")); err != nil {
				t.Fatal(err)
			}
		},
		"lock-fifo": func(t *testing.T, f diskFixture) {
			if err := syscall.Mkfifo(filepath.Join(f.run, "data.lock"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"data-symlink": func(t *testing.T, f diskFixture) {
			p := filepath.Join(f.dev, "vdb")
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".old", p); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			change(t, f)
			calls := 0
			d, err := f.open(func(*os.File, diskIdentity) error { calls++; return nil })
			if err == nil {
				d.Close()
				t.Fatal("unsafe device accepted")
			}
			if calls != 0 {
				t.Fatal("descriptor inspection reached after failed precondition")
			}
		})
	}
}
func TestOpenDataRechecksAndCloses(t *testing.T) {
	rootTest(t)
	for _, kind := range []string{"inspect", "number", "size", "holder", "mounted"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			var seen *os.File
			d, err := f.open(func(file *os.File, want diskIdentity) error {
				seen = file
				switch kind {
				case "inspect":
					return errors.New("bad descriptor")
				case "number":
					f.attr(t, "dev", "252:32")
				case "size":
					f.attr(t, "size", "4096")
				case "holder":
					f.attr(t, "holders/dm-3", "")
				case "mounted":
					put(t, f.mounts, "25 1 252:16 / /data rw - ext4 /dev/vdb rw\n")
				}
				return nil
			})
			if err == nil {
				d.Close()
				t.Fatal("racing device change accepted")
			}
			if seen == nil {
				t.Fatal("inspection not reached")
			}
			if _, err := seen.Stat(); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("descriptor leaked: %v", err)
			}
			// Failure must release the helper lock even if later inventory is invalid.
			lock, err := os.OpenFile(filepath.Join(f.run, "data.lock"), os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
				t.Fatal("failed open leaked lock", err)
			}
		})
	}
}
func TestDataGeometryRefusesRegularFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "not-device")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := inspectData(f, diskIdentity{size: 1 << 30}); err == nil {
		t.Fatal("regular file accepted as block device")
	}
}
func TestDataSizeBoundsBeforeIO(t *testing.T) {
	for _, n := range []int64{-1, 0, 401, 1 << 40} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			if d, err := openData(n, "missing", "missing", "missing", "missing", noInspect); err == nil {
				d.Close()
				t.Fatal("invalid signed size accepted")
			}
		})
	}
}
func TestMountInventory(t *testing.T) {
	for name, raw := range map[string]string{"empty": "", "oversize": strings.Repeat("x", (1<<20)+1), "bad": "1 2 3 4 5 6 7 8 9 10\n", "mounted": "25 1 252:16 / /data rw - ext4 /dev/vdb rw\n"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "mountinfo")
			put(t, p, raw)
			if err := notMounted(p, "252:16"); err == nil {
				t.Fatal("unsafe mount inventory accepted")
			}
		})
	}
}
