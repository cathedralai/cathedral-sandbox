package datavolume

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// HeldDevice is the descriptor/serialization portion of the Linux unlock
// adapter. Its zero value is invalid. It never formats or mounts anything.
// Close releases only this helper's descriptors, never a device-mapper mapping.
type HeldDevice struct {
	file, lock *os.File
	size       int64
	number     uint64
	name       string
	dev        string // "major:minor" of the held disk, as the kernel reports it
	tools      *tools // set by OpenData; nil in descriptor-only tests
	// header is the snapshot the last Header call dumped; Open uses only it.
	header, headerDir string
}

func (d *HeldDevice) Size() int64 { return d.size }
func (d *HeldDevice) ReadAt(p []byte, off int64) (int, error) {
	if d.file == nil {
		return 0, os.ErrClosed
	}
	if off < 0 || off > d.size || int64(len(p)) > d.size-off {
		return 0, io.ErrUnexpectedEOF
	}
	return d.file.ReadAt(p, off)
}
func (d *HeldDevice) Close() error {
	var err error
	if d.file != nil {
		err = d.file.Close()
		d.file = nil
	}
	if d.lock != nil {
		err = errors.Join(err, d.lock.Close())
		d.lock = nil
	}
	if d.headerDir != "" {
		err = errors.Join(err, os.RemoveAll(d.headerDir))
		d.headerDir, d.header = "", ""
	}
	return err
}

var dataDeviceName = regexp.MustCompile(`^vd[a-z]+$`)

func kernelAttribute(path string) (string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return "", errors.New("invalid kernel attribute")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return "", errors.New("unreadable kernel attribute")
	}
	s := strings.TrimSuffix(string(raw), "\n")
	if strings.ContainsAny(s, "\x00\r\n") {
		return "", errors.New("invalid kernel attribute")
	}
	return s, nil
}
func unsigned(raw string) (uint64, error) {
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != raw {
		return 0, errors.New("invalid kernel integer")
	}
	return n, nil
}
func linuxNumber(raw string) (uint64, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return 0, errors.New("invalid device number")
	}
	major, e1 := unsigned(parts[0])
	minor, e2 := unsigned(parts[1])
	if e1 != nil || e2 != nil || major > 0xffffffff || minor > 0xffffffff {
		return 0, errors.New("invalid device number")
	}
	return (major&0xfff)<<8 | (major&0xfffff000)<<32 | minor&0xff | (minor&0xffffff00)<<12, nil
}

type diskIdentity struct {
	name, dev string
	number    uint64
	size      int64
}

func selectedData(sys string, size int64) (diskIdentity, error) {
	var got diskIdentity
	entries, err := os.ReadDir(filepath.Join(sys, "block"))
	if err != nil || len(entries) > 128 {
		return got, errors.New("block inventory unreadable")
	}
	for _, entry := range entries {
		name := entry.Name()
		if !dataDeviceName.MatchString(name) {
			continue
		}
		base := filepath.Join(sys, "block", name)
		serial, err := kernelAttribute(filepath.Join(base, "serial"))
		if err != nil {
			return diskIdentity{}, err
		}
		if serial != "custom-data" {
			continue
		}
		if got.name != "" {
			return diskIdentity{}, errors.New("multiple data disks")
		}
		driver, err := os.Readlink(filepath.Join(base, "device/driver"))
		if err != nil || filepath.Base(driver) != "virtio_blk" {
			return diskIdentity{}, errors.New("wrong data driver")
		}
		raw, err := kernelAttribute(filepath.Join(base, "size"))
		if err != nil {
			return diskIdentity{}, err
		}
		sectors, err := unsigned(raw)
		if err != nil || sectors != uint64(size/512) {
			return diskIdentity{}, errors.New("data size differs from signed launch")
		}
		ro, err := kernelAttribute(filepath.Join(base, "ro"))
		if err != nil || ro != "0" {
			return diskIdentity{}, errors.New("data is not writable")
		}
		dev, err := kernelAttribute(filepath.Join(base, "dev"))
		if err != nil {
			return diskIdentity{}, err
		}
		number, err := linuxNumber(dev)
		if err != nil {
			return diskIdentity{}, err
		}
		holders, err := os.ReadDir(filepath.Join(base, "holders"))
		if err != nil || len(holders) != 0 {
			return diskIdentity{}, errors.New("data disk already claimed or unreadable")
		}
		children, err := os.ReadDir(base)
		if err != nil {
			return diskIdentity{}, err
		}
		for _, child := range children {
			if child.IsDir() || child.Type()&os.ModeSymlink != 0 {
				_, err := os.Stat(filepath.Join(base, child.Name(), "partition"))
				if err == nil || !errors.Is(err, os.ErrNotExist) {
					return diskIdentity{}, errors.New("partitioned data disk refused")
				}
			}
		}
		got = diskIdentity{name: name, dev: dev, number: number, size: size}
	}
	if got.name == "" {
		return got, errors.New("signed data disk absent")
	}
	return got, nil
}
func notMounted(path, dev string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return errors.New("mount inventory unreadable")
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || !strings.Contains(line, " - ") {
			return errors.New("invalid mount inventory")
		}
		if fields[2] == dev {
			return errors.New("data disk already mounted")
		}
	}
	return nil
}
func inspectData(f *os.File, want diskIdentity) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFBLK || st.Rdev != want.number {
		return errors.New("descriptor is not the selected data disk")
	}
	var ro int32
	var size uint64
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0x125e, uintptr(unsafe.Pointer(&ro))); e != 0 {
		return e
	}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), 0x80081272, uintptr(unsafe.Pointer(&size))); e != 0 {
		return e
	}
	if ro != 0 || size != uint64(want.size) {
		return errors.New("data descriptor geometry differs")
	}
	return nil
}

// OpenData holds only the signed custom-data disk after boot. Call from the
// owner unlock command after ReadBoundLaunch, never from boot preparation.
// expectedGiB must come from the validated, natively bound launch manifest.
// /run/cathedral must be the measured boot's private runtime directory.
// The lock serializes this helper; it does not restrict an owner with root from
// deliberately accessing their disk through other programs.
//
// cryptsetupSHA256 pins the static helper at /usr/lib/cathedral/cryptsetup; it
// must be linked into the calling command, never read from the root or host.
// The result implements LockedCandidate.
func OpenData(expectedGiB int64, cryptsetupSHA256 [32]byte) (*HeldDevice, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root required")
	}
	if cryptsetupSHA256 == [32]byte{} {
		return nil, errors.New("cryptsetup pin missing")
	}
	d, err := openData(expectedGiB, "/sys", "/dev", "/run/cathedral", "/proc/self/mountinfo", inspectData)
	if err != nil {
		return nil, err
	}
	d.tools = productionTools(cryptsetupSHA256)
	return d, nil
}
func openData(gib int64, sys, dev, run, mounts string, inspect func(*os.File, diskIdentity) error) (*HeldDevice, error) {
	if gib < 1 || gib > 400 {
		return nil, errors.New("no valid signed data disk")
	}
	// Hold the runtime directory itself so no later path resolution can redirect
	// the serialization lock. Both directory and lock are root-owned and private.
	fd, err := syscall.Open(run, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err = syscall.Fstat(fd, &st); err != nil || st.Uid != 0 || st.Mode&07777 != 0700 {
		return nil, errors.New("runtime directory must be root-owned 0700")
	}
	lockfd, err := syscall.Openat(fd, "data.lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	d := &HeldDevice{lock: os.NewFile(uintptr(lockfd), "data.lock"), size: gib << 30}
	fail := func(err error) (*HeldDevice, error) { d.Close(); return nil, err }
	if err = syscall.Fstat(lockfd, &st); err != nil || st.Uid != 0 || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 {
		return fail(errors.New("invalid data lock"))
	}
	if err = syscall.Flock(lockfd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(errors.New("data unlock already in progress"))
	}
	before, err := selectedData(sys, d.size)
	if err != nil {
		return fail(err)
	}
	if err = notMounted(mounts, before.dev); err != nil {
		return fail(err)
	}
	datafd, err := syscall.Open(filepath.Join(dev, before.name), syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	d.file = os.NewFile(uintptr(datafd), "custom-data")
	if err = inspect(d.file, before); err != nil {
		return fail(err)
	}
	after, err := selectedData(sys, d.size)
	if err != nil || after != before {
		return fail(errors.New("data selection changed during open"))
	}
	if err = notMounted(mounts, before.dev); err != nil {
		return fail(err)
	}
	d.name = before.name
	d.number = before.number
	d.dev = before.dev
	return d, nil
}
