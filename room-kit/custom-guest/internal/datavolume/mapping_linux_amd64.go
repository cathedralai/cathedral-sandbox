package datavolume

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// mapping is this invocation's LUKS2 mapping over the held disk. It owns the
// mapper node, and the mount once Mount has succeeded.
type mapping struct {
	dev     string // "major:minor" of the held disk
	size    int64
	header  string // the checked header snapshot it was opened with; "" reads the disk
	tools   *tools
	mounted bool
}

// dmLink is udev's form of /dev/mapper/<name>: a relative link to the dm-N node
// one directory up. No other link is followed.
var dmLink = regexp.MustCompile(`^\.\./dm-[0-9]+$`)

// node returns the mapping's block device node. Without udev, libdevmapper
// makes /dev/mapper/cathedral-data itself; with udev (a systemd guest, the CI
// runner) it is a link to ../dm-N. Only that exact form is followed, one level.
// Callers still require a block device, and Verify ties its device number to
// our dm name and uuid through sysfs.
func (m *mapping) node() (string, error) {
	path := m.tools.mapperDir + "/" + mapperName
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if st.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}
	target, err := os.Readlink(path)
	if err != nil || !dmLink.MatchString(target) {
		return "", errors.New("unexpected mapper link")
	}
	return filepath.Join(filepath.Dir(m.tools.mapperDir), strings.TrimPrefix(target, "../")), nil
}

// devNumber returns the kernel's "major:minor" for a block device node.
func devNumber(path string) (string, error) {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return "", err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return "", errors.New("not a block device")
	}
	major := (st.Rdev>>8)&0xfff | (st.Rdev>>32)&^uint64(0xfff)
	minor := st.Rdev&0xff | (st.Rdev>>12)&^uint64(0xff)
	return strconv.FormatUint(major, 10) + ":" + strconv.FormatUint(minor, 10), nil
}

func sysAttr(sys, dev, name string) (string, error) {
	return kernelAttribute(filepath.Join(sys, "dev/block", dev, name))
}

// slaves lists the device numbers directly beneath a block device.
func slaves(sys, dev string) ([]string, error) {
	dir := filepath.Join(sys, "dev/block", dev, "slaves")
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > 8 {
		return nil, errors.New("device stack unreadable")
	}
	var result []string
	for _, e := range entries {
		n, err := kernelAttribute(filepath.Join(dir, e.Name(), "dev"))
		if err != nil {
			return nil, err
		}
		result = append(result, n)
	}
	return result, nil
}

// status parses `cryptsetup status` "key: value" lines.
func parseStatus(raw []byte) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, dup := fields[k]; dup || k == "" {
			fields[k] = "\x00duplicate"
			continue
		}
		fields[k] = v
	}
	return fields
}

// statusPolicy checks `cryptsetup status` output in the format of cryptsetup
// 2.8.4, the pinned helper (2.7.x prints "768 bits" and a bare sector size, and
// is refused rather than guessed at). `status` cannot name the LUKS type here (it
// may print "n/a" without the header device); the dm uuid prefix in Verify
// carries that. 768 bits is the 64-byte XTS key plus the 32-byte HMAC key.
func statusPolicy(raw []byte) error {
	f := parseStatus(raw)
	want := []struct{ key, value string }{
		{"cipher", "aes-xts-plain64"},
		{"keysize", "768 [bits]"},
		{"integrity", "hmac(sha256)"},
		{"integrity keysize", "256 [bits]"},
		{"sector size", "4096 [bytes]"},
		{"mode", "read/write"},
	}
	for _, w := range want {
		if f[w.key] != w.value {
			return errors.New("data mapping policy mismatch: status " + w.key)
		}
	}
	if strings.Contains(f["flags"], "discards") {
		return errors.New("data mapping policy mismatch: status flags")
	}
	return nil
}

// Verify reads back the live stack instead of trusting that a passphrase worked.
// It requires, from the kernel and from the helper:
//   - /dev/mapper/cathedral-data is a block device whose dm name and LUKS2 uuid match;
//   - exactly one layer beneath it, a dm-integrity device, which itself sits on
//     exactly one device: the held disk, by device number;
//   - aes-xts-plain64, 4096-byte sectors, hmac(sha256) integrity with its
//     32-byte key, read/write, no discards;
//   - the usable size is positive and not larger than the held disk.
//
// Each refusal names the check that failed; none carries secret material.
func (m *mapping) Verify(ctx context.Context) error {
	fail := func(what string) error { return errors.New("data mapping policy mismatch: " + what) }
	node, err := m.node()
	if err != nil {
		return fail("mapper node")
	}
	crypt, err := devNumber(node)
	if err != nil {
		return fail("mapper node")
	}
	if name, err := sysAttr(m.tools.sys, crypt, "dm/name"); err != nil || name != mapperName {
		return fail("dm name")
	}
	if uuid, err := sysAttr(m.tools.sys, crypt, "dm/uuid"); err != nil || !strings.HasPrefix(uuid, "CRYPT-LUKS2-") {
		return fail("dm uuid")
	}
	if s, err := sysAttr(m.tools.sys, crypt, "dm/suspended"); err != nil || s != "0" {
		return fail("suspended")
	}
	sectors, err := sysAttr(m.tools.sys, crypt, "size")
	if err != nil {
		return fail("size")
	}
	n, err := unsigned(sectors)
	if err != nil || n == 0 || n > uint64(m.size/512) {
		return fail("size")
	}
	below, err := slaves(m.tools.sys, crypt)
	if err != nil || len(below) != 1 {
		return fail("crypt layer")
	}
	if uuid, err := sysAttr(m.tools.sys, below[0], "dm/uuid"); err != nil || !strings.HasPrefix(uuid, "CRYPT-INTEGRITY-") {
		return fail("integrity layer")
	}
	disks, err := slaves(m.tools.sys, below[0])
	if err != nil || len(disks) != 1 || disks[0] != m.dev {
		return fail("backing disk")
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	args := []string{"status", mapperName}
	if m.header != "" {
		args = []string{"status", "--header", m.header, mapperName}
	}
	res, err := m.tools.exec(cctx, command{args: args})
	if err != nil {
		return fail("status unavailable")
	}
	return statusPolicy(res.stdout)
}

// Filesystem probes the plaintext side read-only. "ext4" requires the ext
// superblock magic, revision 1 and the extents feature, which separates ext4
// from ext2/ext3. An all-zero first block is "empty". Anything else is
// "unknown"; Unlock refuses to mount or format all but "ext4".
func (m *mapping) Filesystem(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	node, err := m.node()
	if err != nil {
		return "", err
	}
	fd, err := syscall.Open(node, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), "data-plaintext")
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFBLK {
		return "", errors.New("mapping node is not a block device")
	}
	block := make([]byte, 4096)
	if n, err := f.ReadAt(block, 0); n != len(block) || err != nil {
		return "", errors.New("filesystem probe unreadable")
	}
	if bytes.Equal(block, make([]byte, len(block))) {
		return "empty", nil
	}
	sb := block[1024:2048]
	const incompatExtents = 0x40
	if binary.LittleEndian.Uint16(sb[56:]) == 0xEF53 && binary.LittleEndian.Uint32(sb[0x4C:]) == 1 &&
		binary.LittleEndian.Uint32(sb[0x18:]) <= 6 && binary.LittleEndian.Uint32(sb[0x60:])&incompatExtents != 0 {
		return "ext4", nil
	}
	return "unknown", nil
}

// MakeFilesystem runs mke2fs on the mapping node. Unlock calls it only after
// Format created this volume in the same invocation and Filesystem probed it
// "empty", so -F never overwrites anything.
func (m *mapping) MakeFilesystem(ctx context.Context) error {
	node, err := m.node()
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	_, err = m.tools.exec(cctx, command{program: m.tools.mke2fs,
		args: []string{"-t", "ext4", "-F", "-q", "-L", mapperName, node}})
	if err != nil {
		return errors.New("mke2fs failed")
	}
	return nil
}

type mountEntry struct {
	dev, point, options, fstype string
}

// mounts returns every mountinfo entry at point. mountinfo escapes space, tab,
// newline and backslash as octal, none of which appear in the fixed target.
func mounts(path, point string) ([]mountEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errors.New("mount inventory unreadable")
	}
	var found []mountEntry
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		fields := strings.Fields(line)
		dash := -1
		for i, f := range fields {
			if f == "-" {
				dash = i
				break
			}
		}
		if len(fields) < 10 || dash < 6 || dash+2 >= len(fields) {
			return nil, errors.New("invalid mount inventory")
		}
		if fields[4] == point {
			found = append(found, mountEntry{fields[2], fields[4], fields[5], fields[dash+1]})
		}
	}
	return found, nil
}

// Mount attaches the plaintext at the fixed target with nosuid,nodev,noexec and
// reads the result back from mountinfo. The root user can still interpret the
// data as code; these are mount restrictions only.
func (m *mapping) Mount(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target := m.tools.mountTarget
	if st, err := os.Lstat(target); err == nil {
		if !st.IsDir() {
			return errors.New("mount target is not a plain directory")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(target, 0700); err != nil {
			return err
		}
	} else {
		return err
	}
	if before, err := mounts(m.tools.mountinfo, target); err != nil || len(before) != 0 {
		return errors.New("mount target already in use")
	}
	node, err := m.node()
	if err != nil {
		return err
	}
	crypt, err := devNumber(node)
	if err != nil {
		return err
	}
	if err := syscall.Mount(node, target, "ext4", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return err
	}
	m.mounted = true
	after, err := mounts(m.tools.mountinfo, target)
	if err != nil || len(after) != 1 || after[0].dev != crypt || after[0].fstype != "ext4" {
		return errors.New("mount did not take the expected form")
	}
	have := map[string]bool{}
	for _, o := range strings.Split(after[0].options, ",") {
		have[o] = true
	}
	if !have["rw"] || !have["nosuid"] || !have["nodev"] || !have["noexec"] {
		return errors.New("mount is missing a restriction")
	}
	return nil
}

// Close unmounts, then closes only this invocation's mapping. Cleanup problems
// are reported, never swallowed.
func (m *mapping) Close(ctx context.Context) error {
	var errs []error
	if m.mounted {
		if err := syscall.Unmount(m.tools.mountTarget, 0); err != nil {
			errs = append(errs, errors.New("unmount failed"))
		} else {
			m.mounted = false
		}
	}
	if len(errs) == 0 {
		// A failed open can leave only the integrity layer; close whichever exists.
		for _, n := range []string{mapperName, mapperName + "_dif"} {
			present, err := exists(m.tools.mapperDir + "/" + n)
			if err != nil {
				errs = append(errs, errors.New("mapper node unreadable"))
				continue
			}
			if !present {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			_, err = m.tools.exec(cctx, command{args: []string{"close", n}})
			cancel()
			if err != nil {
				errs = append(errs, errors.New("cryptsetup close failed"))
			}
		}
	}
	return errors.Join(errs...)
}
