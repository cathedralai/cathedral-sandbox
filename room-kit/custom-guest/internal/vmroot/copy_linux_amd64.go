package vmroot

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"time"
)

func fileSize(f *os.File) (int64, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if st.Mode().IsRegular() {
		return st.Size(), nil
	}
	return f.Seek(0, io.SeekEnd) // a block device reports its size by seeking
}

// CopyBase opens the base with dm-verity and copies the verified ext4 image into the start of the
// file-system area (7.2 step 4.2). The disk package passes fs open read-write; this function never
// closes it. Every data block is read through the mapping, so a flipped block fails the copy with
// EIO and nothing is left mapped. It is a pure function of the base and the pin: a rerun after a
// cut at any point writes the same bytes from offset 0.
func CopyBase(verity Tool, b Base, fs *os.File, cut func(string) error) (err error) {
	if cut == nil {
		cut = func(string) error { return nil }
	}
	diskSize, err := fileSize(b.File)
	if err != nil || diskSize != b.DiskBytes {
		return errors.New("base disk size differs from the one given")
	}
	fsSize, err := fileSize(fs)
	if err != nil {
		return err
	}
	if fsSize < b.DataBytes {
		return errors.New("the file system area is smaller than the base image")
	}
	args, err := verityArgs(b.File, b)
	if err != nil {
		return err
	}
	if _, err := os.Lstat("/dev/mapper/" + baseMapping); !errors.Is(err, os.ErrNotExist) {
		return errors.New("base mapper path already exists or is unreadable")
	}
	if err := cut(CutCopyStart); err != nil {
		return err
	}
	if err := verity.run(30*time.Second, []*os.File{b.File}, args...); err != nil {
		return err
	}
	defer func() {
		cerr := verity.run(30*time.Second, nil, "close", baseMapping)
		if err == nil {
			err = cerr
		}
		if err == nil {
			err = cut(CutVerityClosed)
		}
	}()
	return copyVerified("/dev/mapper/"+baseMapping, b.DataBytes, fs, cut)
}

// copyVerified reads exactly size bytes of the mapping into fs from offset 0, flushes, and checks
// that the mapping is a block device of that size.
func copyVerified(path string, size int64, fs *os.File, cut func(string) error) error {
	path, err := resolveMapper(path)
	if err != nil {
		return err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	src := os.NewFile(uintptr(fd), path)
	defer src.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return errors.New("the verity mapping is not a block device")
	}
	if got, err := fileSize(src); err != nil || got != size {
		return errors.New("the verity mapping has another size than the identity names")
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	buf := make([]byte, copyChunk)
	for off := int64(0); off < size; {
		n := min(int64(len(buf)), size-off)
		if _, err := io.ReadFull(src, buf[:n]); err != nil {
			return fmt.Errorf("verified read at %d: %w", off, err)
		}
		if _, err := fs.WriteAt(buf[:n], off); err != nil {
			return err
		}
		off += n
	}
	if err := fs.Sync(); err != nil {
		return err
	}
	return cut(CutCopyDone)
}

// resolveMapper returns the device node of a mapping. In the guest, devtmpfs and libdevmapper make
// /dev/mapper/<name> a node. Where udev runs (the CI runner) it is a link to /dev/dm-N: that one
// link is followed, and only to a dm node directly under /dev.
func resolveMapper(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if !regexp.MustCompile(`^/dev/dm-[0-9]+$`).MatchString(target) {
		return "", errors.New("the verity mapping links outside /dev/dm-N")
	}
	return target, nil
}
