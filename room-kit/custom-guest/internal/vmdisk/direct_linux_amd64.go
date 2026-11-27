package vmdisk

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

// Every record write is O_DIRECT and flushed before the next step (spec r3
// 7.2 "Format"), and every read that decides a state is O_DIRECT, so a
// state is read from the device, never from a cache that a host or an
// earlier boot left behind.

const (
	blkGetSize64 = 0x80081272
	blkROGet     = 0x125e
	directAlign  = 4096
)

// alignedBuffer is page-aligned memory for O_DIRECT. free unmaps it.
type alignedBuffer struct{ b []byte }

func newAligned(n int) (*alignedBuffer, error) {
	if n <= 0 || n%directAlign != 0 {
		return nil, errors.New("aligned buffer size invalid")
	}
	b, err := syscall.Mmap(-1, 0, n, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	return &alignedBuffer{b: b}, nil
}

func (a *alignedBuffer) free() {
	if a != nil && a.b != nil {
		clear(a.b)
		syscall.Munmap(a.b)
		a.b = nil
	}
}

// setDirect turns on O_DIRECT for an open block device.
func setDirect(f *os.File) error {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFL, 0)
	if errno != 0 {
		return errno
	}
	if _, _, errno = syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_SETFL, flags|syscall.O_DIRECT); errno != 0 {
		return errno
	}
	flags, _, errno = syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFL, 0)
	if errno != 0 || flags&syscall.O_DIRECT == 0 {
		return errors.New("O_DIRECT not set")
	}
	return nil
}

// blockDevice checks f is a block device of exactly size bytes and returns
// its device number. writable requires the kernel's read-only flag off.
func blockDevice(f *os.File, size int64, writable bool) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return 0, errors.New("not a block device")
	}
	var got uint64
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), blkGetSize64, uintptr(unsafe.Pointer(&got))); e != 0 {
		return 0, e
	}
	if got != uint64(size) {
		return 0, fmt.Errorf("block device is %d bytes, want %d", got, size)
	}
	if writable {
		var ro int32
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), blkROGet, uintptr(unsafe.Pointer(&ro))); e != 0 {
			return 0, e
		}
		if ro != 0 {
			return 0, errors.New("block device is read-only")
		}
	}
	return st.Rdev, nil
}

// readDirect reads n bytes at off into a fresh copy.
func readDirect(f *os.File, off int64, n int) ([]byte, error) {
	buf, err := newAligned(n)
	if err != nil {
		return nil, err
	}
	defer buf.free()
	if err := fullRead(f, buf.b, off); err != nil {
		return nil, err
	}
	return append([]byte(nil), buf.b...), nil
}

func fullRead(f *os.File, b []byte, off int64) error {
	for done := 0; done < len(b); {
		n, err := f.ReadAt(b[done:], off+int64(done))
		done += n
		if done == len(b) {
			return nil
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

// writeDirect writes data at off, flushes the device, and reads it back.
func writeDirect(f *os.File, off int64, data []byte) error {
	buf, err := newAligned(len(data))
	if err != nil {
		return err
	}
	defer buf.free()
	copy(buf.b, data)
	n, err := f.WriteAt(buf.b, off)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err := syscall.Fdatasync(int(f.Fd())); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	back, err := readDirect(f, off, len(data))
	if err != nil {
		return err
	}
	for i := range back {
		if back[i] != data[i] {
			return errors.New("read back differs from the write")
		}
	}
	return nil
}

// allZero reads [0, size) and reports whether every byte is zero (spec r3
// 7.2 F1, sealed-data.sh:155-180). A device that cannot be read to its end
// is not proven blank: false, with the reason.
func allZero(f *os.File, size int64) (bool, string) {
	const chunk = 8 * MiB
	buf, err := newAligned(chunk)
	if err != nil {
		return false, err.Error()
	}
	defer buf.free()
	zero := make([]byte, chunk) // compared with memequal: a 2 TiB read stays I/O bound
	for off := int64(0); off < size; {
		n := int64(chunk)
		if size-off < n {
			n = size - off
		}
		block := buf.b[:n]
		if err := fullRead(f, block, off); err != nil {
			return false, "the LUKS device could not be read to its end"
		}
		if !bytes.Equal(block, zero[:n]) {
			return false, "a nonzero byte"
		}
		off += n
	}
	return true, ""
}
