package vmmailbox

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// OpenDevice opens the mailbox disk read-write with O_DIRECT, so a poll sees what the host wrote
// and not an old page, and checks that it is exactly 1 MiB. path is the guest's
// /dev/disk/by-id/virtio-cathedral-mailbox (the launcher's serial, spec r3 errata).
func OpenDevice(path string) (*Mailbox, *os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_DIRECT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	m, err := New(f, size)
	if err != nil {
		f.Close()
		return nil, nil, errors.New("mailbox device: " + err.Error())
	}
	return m, f, nil
}
