package vmroot

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
)

// Base is the read-only base disk (7.3): the ext4 image of DataBytes, then the dm-verity
// superblock block and tree. RootHash and DataBytes come from the identity, which the disk
// package has already tied to the measured cmdline.
type Base struct {
	File      *os.File
	DiskBytes int64
	DataBytes int64
	RootHash  string
}

const (
	baseMapping = "cathedral-base"
	copyChunk   = 1 << 20
	// CutCopyStart and CutCopyDone bracket the data copy; CutVerityClosed follows the mapping close.
	CutCopyStart    = "vmroot:copy-start"
	CutCopyDone     = "vmroot:copy-done"
	CutVerityClosed = "vmroot:verity-closed"
	// maxBaseBytes bounds the image: a base root is a few GiB.
	maxBaseBytes = 64 << 30
)

// verityArgs freezes all mapping parameters, as bootstate.verityArgs does for the dedicated root
// (copied from verity_linux_amd64.go:24-64). The superblock is outside the launch measurement;
// only its salt is used, and the root hash from the identity binds that salt cryptographically.
// --no-superblock stops a second metadata read from changing the geometry after validation.
// There is no --panic-on-corruption here: a bad block must fail the copy with EIO, and the init
// then powers off, rather than panic the guest.
func verityArgs(base io.ReaderAt, b Base) ([]string, error) {
	size := b.DataBytes
	if size <= 0 || size%4096 != 0 || size > maxBaseBytes || b.DiskBytes <= size {
		return nil, errors.New("invalid base geometry")
	}
	hash, err := hex.DecodeString(b.RootHash)
	if err != nil || len(hash) != 32 || hex.EncodeToString(hash) != b.RootHash {
		return nil, errors.New("invalid base root hash")
	}
	var sb [512]byte
	if _, err := base.ReadAt(sb[:], size); err != nil {
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
	// A v1 SHA256 tree packs 128 hashes per 4 KiB block; include each level through its root.
	blocks, tree := size/4096, int64(0)
	for blocks > 1 {
		blocks = (blocks + 127) / 128
		tree += blocks
	}
	if b.DiskBytes < size+(1+tree)*4096 {
		return nil, errors.New("verity hash area truncated")
	}
	return []string{"--no-superblock", "--format=1", "--hash=sha256", "--data-block-size=4096",
		"--hash-block-size=4096", "--data-blocks=" + strconv.FormatInt(size/4096, 10),
		"--hash-offset=" + strconv.FormatInt(size+4096, 10), "--salt=" + hex.EncodeToString(sb[88:120]),
		"open", "/proc/self/fd/4", baseMapping, "/proc/self/fd/4", b.RootHash}, nil
}
