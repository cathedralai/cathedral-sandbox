package bootstate

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

// OpenRootDevice repeats device selection and holds the selected root open
// read-only. The returned descriptor, not its pathname, must be passed to the
// verity helper. It never opens the optional data disk. This is not a verity
// check or permission to execute the root. Call only from measured init with
// fresh kernel sysfs/devtmpfs; the caller owns the descriptor on success.
func OpenRootDevice(launch bootstrap.Launch) (*os.File, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root required")
	}
	return openRootDevice(launch, "/sys", "/dev", inspectRootDescriptor)
}

func deviceNumber(raw string) (uint64, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return 0, errors.New("invalid device number")
	}
	var n [2]uint64
	for i, part := range parts {
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(value, 10) != part {
			return 0, errors.New("invalid device number")
		}
		n[i] = value
	}
	// Linux dev_t encoding, including large major/minor numbers.
	return (n[0]&0xfff)<<8 | (n[0]&0xfffff000)<<32 | n[1]&0xff | (n[1]&0xffffff00)<<12, nil
}

func openRootDevice(launch bootstrap.Launch, sys, dev string, inspect func(*os.File, uint64, int64) error) (*os.File, error) {
	selected, err := checkDevices(sys, launch)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(selected.Root)
	raw, err := attribute(filepath.Join(sys, "block", name, "dev"))
	if err != nil {
		return nil, err
	}
	number, err := deviceNumber(raw)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open(filepath.Join(dev, name), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), selected.Root)
	if err := inspect(f, number, launch.Manifest.Bytes["root.raw"]); err != nil {
		f.Close()
		return nil, err
	}
	// Refuse changes in the inventory while the device was being opened.
	again, err := checkDevices(sys, launch)
	if err != nil || again != selected {
		f.Close()
		return nil, errors.New("device selection changed during open")
	}
	return f, nil
}

func inspectRootDescriptor(f *os.File, number uint64, expectedSize int64) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFBLK || st.Rdev != number {
		return errors.New("root descriptor is not the selected block device")
	}
	var readonly int32
	// linux/fs.h BLKROGET and BLKGETSIZE64, Linux amd64 ABI.
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0x125e, uintptr(unsafe.Pointer(&readonly))); errno != 0 {
		return errno
	}
	var size uint64
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0x80081272, uintptr(unsafe.Pointer(&size))); errno != 0 {
		return errno
	}
	if readonly != 1 || expectedSize <= 0 || size != uint64(expectedSize) {
		return errors.New("root descriptor read-only status or size differs")
	}
	return nil
}
