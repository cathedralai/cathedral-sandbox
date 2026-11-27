package bootstate

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// PrepareKernelViews is the first stage of the measured root PID1. It installs
// fresh kernel views, then restricts both native report interfaces before any
// launch input is read. It must never be called in a host/container rehearsal:
// devtmpfs and configfs can expose kernel-global objects even in a mount namespace.
// Any error requires the guest PID1 to power off; there is no reuse/fallback path.
func PrepareKernelViews() error {
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		return errors.New("measured root PID1 required")
	}
	syscall.Umask(0077)
	return prepareKernelViews(kernelOperations{
		directory: bootDirectory,
		mount:     syscall.Mount,
		report: func() error {
			raw, err := attribute("/sys/class/misc/sev-guest/dev")
			if err != nil {
				return err
			}
			number, err := deviceNumber(raw)
			if err != nil {
				return err
			}
			return restrictReportDevice("/dev/sev-guest", number)
		},
		config: func() error { return restrictConfigDirectory("/sys/kernel/config") },
	})
}

type kernelOperations struct {
	directory func(string) error
	mount     func(string, string, string, uintptr, string) error
	report    func() error
	config    func() error
}

func prepareKernelViews(ops kernelOperations) error {
	// No mount propagation into another tree. No owner process runs during this
	// stage, and the initrd archive admits no symlink or device entries.
	if err := ops.mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("private boot mounts: %w", err)
	}
	const readonly = syscall.MS_RDONLY | syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC
	for _, m := range []struct {
		path, kind, data string
		flags            uintptr
	}{
		{"/proc", "proc", "", readonly},
		{"/sys", "sysfs", "", readonly},
		{"/dev", "devtmpfs", "mode=0755", syscall.MS_NOSUID | syscall.MS_NOEXEC},
	} {
		if err := ops.directory(m.path); err != nil {
			return err
		}
		if err := ops.mount(m.kind, m.path, m.kind, m.flags, m.data); err != nil {
			return fmt.Errorf("mount %s: %w", m.path, err)
		}
	}
	if err := ops.report(); err != nil {
		return fmt.Errorf("restrict SNP device: %w", err)
	}
	// The target exists in the freshly mounted sysfs. Mounting configfs here
	// does not require making sysfs writable. The root directory gates TSM.
	if err := ops.directory("/sys/kernel/config"); err != nil {
		return err
	}
	if err := ops.mount("configfs", "/sys/kernel/config", "configfs",
		syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount report configfs: %w", err)
	}
	return ops.config()
}

func bootDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0755); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !ok ||
		st.Uid != 0 || st.Gid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("boot mount target must be a plain root-owned directory")
	}
	return nil
}

func restrictReportDevice(path string, number uint64) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFCHR || st.Rdev != number {
		return errors.New("report node does not match kernel device identity")
	}
	if err := syscall.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err := syscall.Fchmod(fd, 0600); err != nil {
		return err
	}
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != 0 || st.Gid != 0 || st.Mode&07777 != 0600 {
		return errors.New("report node remains accessible outside root")
	}
	return nil
}

func restrictConfigDirectory(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err := syscall.Fchown(fd, 0, 0); err != nil {
		return err
	}
	if err := syscall.Fchmod(fd, 0700); err != nil {
		return err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != 0 || st.Gid != 0 || st.Mode&07777 != 0700 {
		return errors.New("report config remains accessible outside root")
	}
	return nil
}
