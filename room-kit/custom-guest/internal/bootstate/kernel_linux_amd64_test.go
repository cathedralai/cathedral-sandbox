package bootstate

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestKernelViewsRequirePID1(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("must not run setup in a host PID namespace")
	}
	if err := PrepareKernelViews(); err == nil {
		t.Fatal("kernel setup allowed outside PID1")
	}
}

func TestKernelViewOrderAndStopOnFailure(t *testing.T) {
	expected := []string{"private", "dir:/proc", "mount:proc", "dir:/sys", "mount:sysfs", "dir:/dev", "mount:devtmpfs", "restrict:device", "dir:/sys/kernel/config", "mount:configfs", "restrict:config"}
	for failAt := -1; failAt < len(expected); failAt++ {
		var calls []string
		step := func(s string) error {
			calls = append(calls, s)
			if len(calls)-1 == failAt {
				return errors.New("injected failure")
			}
			return nil
		}
		ops := kernelOperations{
			directory: func(p string) error { return step("dir:" + p) },
			report:    func() error { return step("restrict:device") },
			config:    func() error { return step("restrict:config") },
			mount: func(source, target, kind string, flags uintptr, data string) error {
				if target == "/" {
					if flags != syscall.MS_PRIVATE|syscall.MS_REC || source != "" || kind != "" || data != "" {
						t.Fatal("mount propagation contract")
					}
					return step("private")
				}
				if source != kind || flags&syscall.MS_NOSUID == 0 || flags&syscall.MS_NOEXEC == 0 {
					t.Fatal("unsafe kernel mount")
				}
				switch kind {
				case "proc", "sysfs":
					if flags&syscall.MS_RDONLY == 0 || flags&syscall.MS_NODEV == 0 || data != "" {
						t.Fatal("kernel view not read-only")
					}
				case "devtmpfs":
					if target != "/dev" || flags&syscall.MS_NODEV != 0 || data != "mode=0755" {
						t.Fatal("invalid device filesystem")
					}
				case "configfs":
					if target != "/sys/kernel/config" || flags&syscall.MS_NODEV == 0 || flags&syscall.MS_RDONLY != 0 {
						t.Fatal("invalid report config mount")
					}
				default:
					t.Fatal("unexpected mount")
				}
				return step("mount:" + kind)
			},
		}
		err := prepareKernelViews(ops)
		want := expected
		if failAt >= 0 {
			want = expected[:failAt+1]
			if err == nil {
				t.Fatal("failure was ignored")
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("wrong order after failure %d: %v", failAt, calls)
		}
	}
}

func TestReportDeviceRestriction(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership and mknod required")
	}
	parent := os.Getenv("GUEST_DEVICE_TEST_TMPFS")
	if parent == "" {
		parent = os.TempDir()
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(parent, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Flags&syscall.MS_NODEV != 0 {
		t.Skip("private fixture mount must permit synthetic device inodes")
	}
	dir, err := os.MkdirTemp(parent, "guest-device-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "synthetic-null")
	number, err := deviceNumber("1:3")
	if err != nil {
		t.Fatal(err)
	}
	// This creates a new private inode with the null driver's device number.
	// It never changes /dev/null or opens the real SNP device.
	if err := syscall.Mknod(path, syscall.S_IFCHR|0666, int(number)); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("mknod unavailable")
		}
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := restrictReportDevice(path, number+1); err == nil {
		t.Fatal("wrong device identity accepted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0666 {
		t.Fatal("wrong device was modified")
	}
	if err := restrictReportDevice(path, number); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if info.Mode().Perm() != 0600 || st.Uid != 0 || st.Gid != 0 {
		t.Fatal("device is not root-only")
	}
}

func TestReportDeviceRefusesFilesAndAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	alias := path + "-alias"
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, alias, path + "-missing"} {
		if err := restrictReportDevice(p, 0); err == nil {
			t.Fatal("non-device accepted")
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatal("invalid target changed")
	}
}

func TestConfigRootRestrictionAndAliasRefusal(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership required")
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	alias := path + "-alias"
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := restrictConfigDirectory(alias); err == nil {
		t.Fatal("config alias accepted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatal("alias target modified")
	}
	if err := restrictConfigDirectory(path); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if info.Mode().Perm() != 0700 || st.Uid != 0 || st.Gid != 0 {
		t.Fatal("config not root-only")
	}
}

func TestBootDirectoryRefusesAliasAndWritableTarget(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership required")
	}
	path := filepath.Join(t.TempDir(), "boot")
	if err := bootDirectory(path); err != nil {
		t.Fatal(err)
	}
	alias := path + "-alias"
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := bootDirectory(alias); err == nil {
		t.Fatal("mount directory alias accepted")
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if err := bootDirectory(path); err == nil {
		t.Fatal("public mount directory accepted")
	}
}
