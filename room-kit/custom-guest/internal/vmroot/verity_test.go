package vmroot

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

const rootHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeBase is a disk image of dataBlocks of data, a verity superblock, and enough tree blocks.
func fakeBase(dataBlocks int64) (*bytes.Reader, Base) {
	data := dataBlocks * 4096
	disk := make([]byte, data+(1+dataBlocks)*4096) // generous tree area
	sb := disk[data:]
	copy(sb, "verity\x00\x00")
	binary.LittleEndian.PutUint32(sb[8:], 1)
	binary.LittleEndian.PutUint32(sb[12:], 1)
	copy(sb[32:], "sha256")
	binary.LittleEndian.PutUint32(sb[64:], 4096)
	binary.LittleEndian.PutUint32(sb[68:], 4096)
	binary.LittleEndian.PutUint64(sb[72:], uint64(dataBlocks))
	binary.LittleEndian.PutUint16(sb[80:], 32)
	copy(sb[88:], bytes.Repeat([]byte{0xab}, 32))
	return bytes.NewReader(disk), Base{DiskBytes: int64(len(disk)), DataBytes: data, RootHash: rootHash}
}

func TestVerityArgsFreezeTheGeometry(t *testing.T) {
	r, b := fakeBase(300)
	args, err := verityArgs(r, b)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--no-superblock", "--data-blocks=300", "--salt=" + strings.Repeat("ab", 32), "open /proc/self/fd/4 cathedral-base /proc/self/fd/4 " + rootHash} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %s", want, joined)
		}
	}
	// 300 data blocks: hash offset is data + one superblock block.
	if !strings.Contains(joined, "--hash-offset=1232896") {
		t.Errorf("hash offset: %s", joined)
	}
	// No panic-on-corruption: a bad block must fail the copy, not panic the guest.
	if strings.Contains(joined, "panic") {
		t.Error("panic-on-corruption present")
	}
}

func TestVerityArgsRefuseWhatDiffersFromTheReference(t *testing.T) {
	mutate := map[string]func(disk []byte, b *Base){
		"bad magic":        func(d []byte, b *Base) { d[b.DataBytes] = 'X' },
		"version 2":        func(d []byte, b *Base) { binary.LittleEndian.PutUint32(d[b.DataBytes+8:], 2) },
		"hash type 2":      func(d []byte, b *Base) { binary.LittleEndian.PutUint32(d[b.DataBytes+12:], 2) },
		"another algo":     func(d []byte, b *Base) { copy(d[b.DataBytes+32:], "sha512") },
		"data block 512":   func(d []byte, b *Base) { binary.LittleEndian.PutUint32(d[b.DataBytes+64:], 512) },
		"hash block 1024":  func(d []byte, b *Base) { binary.LittleEndian.PutUint32(d[b.DataBytes+68:], 1024) },
		"blocks differ":    func(d []byte, b *Base) { binary.LittleEndian.PutUint64(d[b.DataBytes+72:], 299) },
		"salt size 16":     func(d []byte, b *Base) { binary.LittleEndian.PutUint16(d[b.DataBytes+80:], 16) },
		"short root hash":  func(d []byte, b *Base) { b.RootHash = b.RootHash[:62] },
		"upper-case hash":  func(d []byte, b *Base) { b.RootHash = strings.ToUpper(b.RootHash) },
		"unaligned data":   func(d []byte, b *Base) { b.DataBytes += 512 },
		"zero data":        func(d []byte, b *Base) { b.DataBytes = 0 },
		"truncated hashes": func(d []byte, b *Base) { b.DiskBytes = b.DataBytes + 4096 },
		"disk not larger":  func(d []byte, b *Base) { b.DiskBytes = b.DataBytes },
		"too large":        func(d []byte, b *Base) { b.DataBytes = maxBaseBytes + 4096 },
	}
	for why, f := range mutate {
		r, b := fakeBase(300)
		disk := make([]byte, r.Len())
		r.ReadAt(disk, 0)
		f(disk, &b)
		if _, err := verityArgs(bytes.NewReader(disk), b); err == nil {
			t.Errorf("%s: accepted", why)
		}
	}
}
