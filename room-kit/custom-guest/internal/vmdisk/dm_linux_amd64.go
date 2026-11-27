package vmdisk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

// The VM initrd ships no dmsetup (spec r3 7.1 maps the LUKS device and the
// file system area with dm-linear), so the init talks to device-mapper
// through its ioctl ABI (linux/dm-ioctl.h, interface version 4).

const (
	dmHeaderBytes   = 312
	dmTargetBytes   = 40
	dmNameMax       = 127
	dmControl       = "/dev/mapper/control"
	cmdDevCreate    = 3
	cmdDevRemove    = 4
	cmdDevSuspend   = 6
	cmdDevStatus    = 7
	cmdTableLoad    = 9
	cmdTableStatus  = 12
	flagReadonly    = 1 << 0
	flagStatusTable = 1 << 4
	flagBufferFull  = 1 << 8
	flagSecureData  = 1 << 15
)

func dmIoctlNumber(cmd uintptr) uintptr { return 3<<30 | dmHeaderBytes<<16 | 0xfd<<8 | cmd }

type dm struct{ control *os.File }

func openDM() (*dm, error) {
	fd, err := syscall.Open(dmControl, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("device-mapper control: %w", err)
	}
	f := os.NewFile(uintptr(fd), dmControl)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		f.Close()
		return nil, errors.New("device-mapper control is not a character device")
	}
	return &dm{control: f}, nil
}

func (d *dm) close() { d.control.Close() }

// call issues one DM ioctl with an optional payload after the header and
// returns the whole buffer. A status call sized too small is retried larger.
func (d *dm) call(cmd uintptr, name string, flags, targets uint32, payload []byte, size int) ([]byte, error) {
	if len(name) == 0 || len(name) > dmNameMax {
		return nil, errors.New("device-mapper name invalid")
	}
	for {
		if size < dmHeaderBytes+len(payload) {
			size = dmHeaderBytes + len(payload)
		}
		buf := make([]byte, size)
		le := binary.LittleEndian
		le.PutUint32(buf[0:], 4) // interface version 4.0.0
		le.PutUint32(buf[12:], uint32(size))
		le.PutUint32(buf[16:], dmHeaderBytes)
		le.PutUint32(buf[20:], targets)
		le.PutUint32(buf[28:], flags)
		copy(buf[48:48+dmNameMax], name)
		copy(buf[dmHeaderBytes:], payload)
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, d.control.Fd(), dmIoctlNumber(cmd), uintptr(unsafe.Pointer(&buf[0])))
		if errno != 0 {
			clear(buf)
			return nil, errno
		}
		if le.Uint32(buf[28:])&flagBufferFull != 0 && size < 1<<20 {
			clear(buf)
			size *= 4
			continue
		}
		return buf, nil
	}
}

// devStatus returns the device number of a mapping, or ENXIO if none.
func (d *dm) devStatus(name string) (dev uint64, readonly bool, err error) {
	buf, err := d.call(cmdDevStatus, name, 0, 0, nil, 0)
	if err != nil {
		return 0, false, err
	}
	le := binary.LittleEndian
	return le.Uint64(buf[40:]), le.Uint32(buf[28:])&flagReadonly != 0, nil
}

// exists reports whether a mapping of that name is present.
func (d *dm) exists(name string) (bool, error) {
	_, _, err := d.devStatus(name)
	if errors.Is(err, syscall.ENXIO) {
		return false, nil
	}
	return err == nil, err
}

func linearTarget(start, length uint64, under uint64, offset uint64) []byte {
	params := deviceString(under) + " " + strconv.FormatUint(offset, 10)
	return target("linear", start, length, params)
}

func target(kind string, start, length uint64, params string) []byte {
	n := dmTargetBytes + len(params) + 1
	n = (n + 7) &^ 7
	out := make([]byte, n)
	le := binary.LittleEndian
	le.PutUint64(out[0:], start)
	le.PutUint64(out[8:], length)
	le.PutUint32(out[20:], uint32(n)) // next
	copy(out[24:24+15], kind)
	copy(out[dmTargetBytes:], params)
	return out
}

// deviceString is the "major:minor" form a dm table names a device by.
func deviceString(dev uint64) string {
	return strconv.FormatUint(devMajor(dev), 10) + ":" + strconv.FormatUint(devMinor(dev), 10)
}

func devMajor(dev uint64) uint64 { return (dev>>8)&0xfff | (dev>>32)&^0xfff }
func devMinor(dev uint64) uint64 { return dev&0xff | (dev>>12)&^0xff }

// load replaces the inactive table and resumes the mapping onto it.
func (d *dm) load(name string, readonly bool, table []byte) error {
	var flags uint32
	if readonly {
		flags = flagReadonly
	}
	if _, err := d.call(cmdTableLoad, name, flags, 1, table, 0); err != nil {
		return fmt.Errorf("load %s: %w", name, err)
	}
	if _, err := d.call(cmdDevSuspend, name, 0, 0, nil, 0); err != nil {
		return fmt.Errorf("resume %s: %w", name, err)
	}
	return nil
}

// createLinear makes a new dm-linear mapping and returns its device number.
// A mapping of that name must not exist: the init owns every mapping it uses.
func (d *dm) createLinear(name string, readonly bool, under, offset, length uint64) (uint64, error) {
	if ok, err := d.exists(name); err != nil || ok {
		return 0, fmt.Errorf("mapping %s already exists or is unreadable", name)
	}
	if _, err := d.call(cmdDevCreate, name, 0, 0, nil, 0); err != nil {
		return 0, fmt.Errorf("create %s: %w", name, err)
	}
	if err := d.load(name, readonly, linearTarget(0, length, under, offset)); err != nil {
		d.remove(name)
		return 0, err
	}
	dev, ro, err := d.devStatus(name)
	if err != nil || ro != readonly {
		d.remove(name)
		return 0, fmt.Errorf("mapping %s did not come up as requested", name)
	}
	return dev, nil
}

// remove deletes a mapping, retrying while a closing holder still has it.
func (d *dm) remove(name string) error {
	var err error
	for i := 0; i < 50; i++ {
		_, err = d.call(cmdDevRemove, name, 0, 0, nil, 0)
		if err == nil || errors.Is(err, syscall.ENXIO) {
			return nil
		}
		if !errors.Is(err, syscall.EBUSY) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("remove %s: %w", name, err)
}

// Target is one line of an active table. Params may hold key material: the
// caller clears it with Clear.
type Target struct {
	Type          string
	Start, Length uint64
	Params        []byte
}

func (t *Target) Clear() { clear(t.Params) }

// table reads the active table of a mapping.
func (d *dm) table(name string) ([]Target, error) {
	buf, err := d.call(cmdTableStatus, name, flagStatusTable|flagSecureData, 0, nil, 16384)
	if err != nil {
		return nil, err
	}
	defer clear(buf)
	le := binary.LittleEndian
	count := le.Uint32(buf[20:])
	start := int(le.Uint32(buf[16:]))
	size := int(le.Uint32(buf[12:]))
	if count == 0 || count > 16 || start != dmHeaderBytes || size > len(buf) {
		return nil, errors.New("table status invalid")
	}
	var out []Target
	at := start
	for i := uint32(0); i < count; i++ {
		if at+dmTargetBytes > size {
			return nil, errors.New("table status truncated")
		}
		spec := buf[at : at+dmTargetBytes]
		kind := spec[24:40]
		if n := indexZero(kind); n >= 0 {
			kind = kind[:n]
		}
		rest := buf[at+dmTargetBytes : size]
		end := indexZero(rest)
		if end < 0 {
			return nil, errors.New("table params unterminated")
		}
		out = append(out, Target{Type: string(kind), Start: le.Uint64(spec[0:]), Length: le.Uint64(spec[8:]),
			Params: append([]byte(nil), rest[:end]...)})
		next := int(le.Uint32(spec[20:]))
		if i+1 < count && (next <= at-start || start+next > size) {
			return nil, errors.New("table status links invalid")
		}
		at = start + next
	}
	return out, nil
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// openMapped opens /dev/dm-<minor> for a mapping and proves the node is
// that device. devtmpfs makes the node when the first table loads.
func openMapped(dev uint64, flags int) (*os.File, error) {
	path := "/dev/dm-" + strconv.FormatUint(devMinor(dev), 10)
	var lastErr error
	for i := 0; i < 40; i++ {
		fd, err := syscall.Open(path, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err == nil {
			f := os.NewFile(uintptr(fd), path)
			var st syscall.Stat_t
			if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFBLK || st.Rdev != dev {
				f.Close()
				return nil, fmt.Errorf("%s is not the mapped device", path)
			}
			return f, nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("open %s: %w", path, lastErr)
}
