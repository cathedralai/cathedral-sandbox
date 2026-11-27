package bootstate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

const verityHelper = "/usr/lib/cathedral/veritysetup"
const rootMapping = "cathedral-root"
const verifiedRoot = "/newroot"

// verityArgs freezes all mapping parameters. The superblock is outside the
// launch measurement; only its salt is used, and the signed root hash binds
// that salt cryptographically. Passing --no-superblock prevents a second
// metadata read from changing the geometry after validation.
func verityArgs(root io.ReaderAt, m bootstrap.Manifest) ([]string, error) {
	size := m.RootDataBytes
	if size <= 0 || size%4096 != 0 || size > 200<<30 || m.Bytes["root.raw"] <= size {
		return nil, errors.New("invalid signed verity geometry")
	}
	hash, err := hex.DecodeString(m.RootVerity)
	if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != m.RootVerity {
		return nil, errors.New("invalid signed root hash")
	}
	var sb [512]byte
	if _, err := root.ReadAt(sb[:], size); err != nil {
		return nil, fmt.Errorf("verity header: %w", err)
	}
	var algorithm [32]byte
	copy(algorithm[:], "sha256")
	if !bytes.Equal(sb[:8], []byte("verity\x00\x00")) || binary.LittleEndian.Uint32(sb[8:12]) != 1 ||
		binary.LittleEndian.Uint32(sb[12:16]) != 1 || !bytes.Equal(sb[32:64], algorithm[:]) ||
		binary.LittleEndian.Uint32(sb[64:68]) != 4096 || binary.LittleEndian.Uint32(sb[68:72]) != 4096 ||
		binary.LittleEndian.Uint64(sb[72:80]) != uint64(size/4096) || binary.LittleEndian.Uint16(sb[80:82]) != 32 {
		return nil, errors.New("verity header differs from reference geometry")
	}
	// A v1 SHA256 tree packs 128 hashes per 4 KiB block. One data block
	// needs no tree level; otherwise include each level through its root.
	blocks, tree := size/4096, int64(0)
	for blocks > 1 {
		blocks = (blocks + 127) / 128
		tree += blocks
	}
	if m.Bytes["root.raw"] < size+(1+tree)*4096 {
		return nil, errors.New("verity hash area truncated")
	}
	return []string{"--no-superblock", "--format=1", "--hash=sha256", "--data-block-size=4096",
		"--hash-block-size=4096", "--data-blocks=" + strconv.FormatInt(size/4096, 10),
		"--hash-offset=" + strconv.FormatInt(size+4096, 10), "--salt=" + hex.EncodeToString(sb[88:120]),
		"--panic-on-corruption", "open", "/proc/self/fd/4", rootMapping, "/proc/self/fd/4", m.RootVerity}, nil
}

func openPinnedHelper(path string, expected [32]byte) (*os.File, error) {
	if expected == [32]byte{} {
		return nil, errors.New("verity helper pin missing")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	fail := func(err error) (*os.File, error) { f.Close(); return nil, err }
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fail(err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0111 == 0 || st.Mode&0022 != 0 ||
		st.Uid != 0 || st.Size < 4 || st.Size > 32<<20 {
		return fail(errors.New("invalid verity helper file"))
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, (32<<20)+1))
	if err != nil {
		return fail(err)
	}
	if n != st.Size || !bytes.Equal(hash.Sum(nil), expected[:]) {
		return fail(errors.New("verity helper digest differs"))
	}
	return f, nil
}

func runVerity(helper, root *os.File, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Args[0] = verityHelper
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{helper, root}
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("verity mapping failed: %w", err)
	}
	return nil
}

// MountVerifiedRoot is only usable as root PID1 in the measured reference
// initrd. Before calling, complete launch/HOST_DATA and observed-resource gates,
// mount fresh proc/sysfs/devtmpfs and make the mount tree private. helperSHA
// must be pinned in measured code, never supplied by the host or root disk.
// Any error requires poweroff; there is no raw-root or read-write fallback.
// A success still requires CheckRoot, RAM keys and the remaining handoff gates.
func MountVerifiedRoot(launch bootstrap.Launch, helperSHA [32]byte) (string, error) {
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		return "", errors.New("measured root PID1 required")
	}
	root, err := OpenRootDevice(launch)
	if err != nil {
		return "", err
	}
	defer root.Close()
	args, err := verityArgs(root, launch.Manifest)
	if err != nil {
		return "", err
	}
	helper, err := openPinnedHelper(verityHelper, helperSHA)
	if err != nil {
		return "", err
	}
	defer helper.Close()
	// Existing paths are refused. Early init owns both this mapping and mount.
	if _, err := os.Lstat("/dev/mapper/" + rootMapping); !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("root mapper path already exists or is unreadable")
	}
	if err := os.Mkdir(verifiedRoot, 0700); err != nil {
		return "", err
	}
	if err := runVerity(helper, root, args); err != nil {
		return "", err
	}
	if err := syscall.Mount("/dev/mapper/"+rootMapping, verifiedRoot, "squashfs",
		syscall.MS_RDONLY|syscall.MS_NODEV|syscall.MS_NOSUID, ""); err != nil {
		return "", err
	}
	return verifiedRoot, nil
}
