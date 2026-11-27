package bootstrap

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/snp"
)

const firmwareDirectory = "/sys/firmware/qemu_fw_cfg/by_name/opt/cathedral"

// ReadBoundLaunch reads the fixed firmware inputs and measured command line,
// validates the owner's signature, then checks their HOST_DATA against a fresh
// native SNP report. Call from measured init after mounting fresh proc/sysfs and
// restricting /dev/sev-guest to root. No input path or report backend is selectable.
//
// This establishes local document binding only. The caller must still check
// observed resources, verity and the root contract before using launch fields
// to configure networking, generate keys or execute owner code. This is not an
// owner-side certificate verification or a complete boot approval.
func ReadBoundLaunch() (Launch, error) {
	if os.Geteuid() != 0 {
		return Launch{}, errors.New("root required")
	}
	return readBoundLaunch(firmwareDirectory, "/proc/cmdline", rand.Reader, snp.Collect)
}

// readBootFile bounds the read itself: sysfs attributes need not report their
// actual byte count in stat. Intermediate kernel-created by_name symlinks are
// intentional; the raw attribute itself must be a regular file, never a FIFO,
// device or symlink. Only freshly mounted proc/sysfs may supply these paths.
func readBootFile(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("boot input is not a regular attribute")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || int64(len(raw)) > limit {
		return nil, errors.New("boot input size invalid")
	}
	return raw, nil
}

func readBoundLaunch(firmware, cmdline string, random io.Reader, collect func([64]byte) ([]byte, error)) (Launch, error) {
	fail := func(err error) (Launch, error) { return Launch{}, err }
	entries, err := os.ReadDir(firmware)
	if err != nil {
		return fail(fmt.Errorf("firmware inventory: %w", err))
	}
	if len(entries) != 3 || entries[0].Name() != "bootstrap.json" || entries[1].Name() != "bootstrap.sig" || entries[2].Name() != "manifest.json" {
		return fail(errors.New("firmware must contain exactly the three launch inputs"))
	}
	read := func(name string, limit int64) ([]byte, error) {
		return readBootFile(filepath.Join(firmware, name, "raw"), limit)
	}
	manifest, err := read("manifest.json", documentLimit)
	if err != nil {
		return fail(fmt.Errorf("manifest input: %w", err))
	}
	bootstrap, err := read("bootstrap.json", documentLimit)
	if err != nil {
		return fail(fmt.Errorf("bootstrap input: %w", err))
	}
	signature, err := read("bootstrap.sig", 64)
	if err != nil {
		return fail(fmt.Errorf("signature input: %w", err))
	}
	line, err := readBootFile(cmdline, 2048) // 2047 measured bytes and proc's newline
	if err != nil {
		return fail(fmt.Errorf("cmdline input: %w", err))
	}
	launch, err := Validate(manifest, bootstrap, signature, string(line))
	if err != nil {
		return fail(err)
	}
	var nonce [32]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return fail(fmt.Errorf("boot entropy: %w", err))
	}
	data := snp.BootData(nonce)
	report, err := collect(data)
	if err != nil {
		return fail(err)
	}
	if err = snp.CheckLocal(report, data, &launch.HostData); err != nil {
		return fail(err)
	}
	return launch, nil
}
