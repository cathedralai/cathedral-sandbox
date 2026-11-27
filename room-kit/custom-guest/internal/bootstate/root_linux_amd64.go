package bootstate

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// rootPath resolves guest absolute symlinks relative to the guest root. The
// verified root must already be mounted read-only and contain no submounts.
// os.Root still confines each operation if an unexpected path changes.
func rootPath(root *os.Root, name string) (string, error) {
	pending := strings.Split(name, "/")
	var done []string
	links := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(done) == 0 {
				return "", errors.New("root path escapes")
			}
			done = done[:len(done)-1]
			continue
		}
		if len(part) > 255 || strings.IndexByte(part, 0) >= 0 || len(done)+len(pending) > 256 {
			return "", errors.New("invalid root path")
		}
		candidate := strings.Join(append(append([]string{}, done...), part), "/")
		info, err := root.Lstat(candidate)
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > 40 {
				return "", errors.New("root symlink loop")
			}
			target, err := root.Readlink(candidate)
			if err != nil {
				return "", err
			}
			if len(target) == 0 || len(target) > 4096 {
				return "", errors.New("invalid root symlink")
			}
			if strings.HasPrefix(target, "/") {
				done = nil
			}
			pending = append(strings.Split(target, "/"), pending...)
			continue
		}
		if len(pending) > 0 && !info.IsDir() {
			return "", errors.New("root path parent is not a directory")
		}
		done = append(done, part)
	}
	if len(done) == 0 {
		return "", errors.New("root file path empty")
	}
	return strings.Join(done, "/"), nil
}

func fullExecutable(root *os.Root, name string) ([32]byte, error) {
	var empty [32]byte
	path, err := rootPath(root, name)
	if err != nil {
		return empty, err
	}
	// Stat before opening to avoid blocking on a FIFO or touching a device. This
	// is safe only on the immutable verity mount specified by CheckRoot's contract.
	info, err := root.Lstat(path)
	if err != nil {
		return empty, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 ||
		info.Size() < 4 || info.Size() > 64<<20 {
		return empty, errors.New("invalid root executable")
	}
	f, err := root.Open(path)
	if err != nil {
		return empty, err
	}
	defer f.Close()
	infoAfter, err := f.Stat()
	if err != nil {
		return empty, err
	}
	if !os.SameFile(info, infoAfter) {
		return empty, errors.New("root executable changed")
	}
	hash := sha256.New()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return empty, err
	}
	if !bytes.Equal(magic[:], []byte{0x7f, 'E', 'L', 'F'}) {
		return empty, errors.New("root executable is not ELF")
	}
	hash.Write(magic[:])
	n, err := io.Copy(hash, io.LimitReader(f, (64<<20)+1))
	if err != nil {
		return empty, err
	}
	if n+4 != info.Size() {
		return empty, errors.New("root executable size changed")
	}
	copy(empty[:], hash.Sum(nil))
	return empty, nil
}

type RootFiles struct {
	HelperSHA256 [32]byte
	InitSHA256   [32]byte
	SSHDSHA256   [32]byte
}

// CheckRoot is spec5.6 step4 only. The caller must first establish the read-only
// dm-verity mount with the owner-signed hash; this function does not mount or
// establish verity. helperSHA comes from the measured init's pinned build, never
// from the root being inspected or host-supplied launch documents. All paths
// are within that root, including absolute guest symlinks.
// No program is executed. A successful result is not permission to boot: the
// remaining launch, hardware, report and volatile-key gates still apply.
func CheckRoot(directory string, helperSHA [32]byte) (RootFiles, error) {
	fail := func(err error) (RootFiles, error) { return RootFiles{}, err }
	if helperSHA == [32]byte{} {
		return fail(errors.New("report helper pin missing"))
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fail(err)
	}
	defer root.Close()
	marker, markerErr := rootPath(root, "etc/cloud/cloud-init.disabled")
	if markerErr == nil {
		info, err := root.Lstat(marker)
		if err != nil {
			return fail(err)
		}
		if !info.Mode().IsRegular() {
			return fail(errors.New("cloud-init disable marker invalid"))
		}
	} else {
		if !errors.Is(markerErr, os.ErrNotExist) {
			return fail(markerErr)
		}
		// Supported root recipes install cloud-init in one of these paths. Unknown
		// owner software is not attested as safe merely by satisfying this contract.
		for _, path := range []string{"usr/bin/cloud-init", "usr/local/bin/cloud-init", "usr/sbin/cloud-init"} {
			_, err := rootPath(root, path)
			if err == nil {
				return fail(errors.New("cloud-init is not disabled"))
			}
			if !errors.Is(err, os.ErrNotExist) {
				return fail(err)
			}
		}
	}
	var result RootFiles
	result.HelperSHA256, err = fullExecutable(root, "usr/bin/cathedral-attest")
	if err != nil {
		return fail(fmt.Errorf("report helper: %w", err))
	}
	if result.HelperSHA256 != helperSHA {
		return fail(errors.New("report helper digest differs"))
	}
	result.InitSHA256, err = fullExecutable(root, "sbin/init")
	if err != nil {
		return fail(fmt.Errorf("init: %w", err))
	}
	result.SSHDSHA256, err = fullExecutable(root, "usr/sbin/sshd")
	if err != nil {
		return fail(fmt.Errorf("sshd: %w", err))
	}
	return result, nil
}
