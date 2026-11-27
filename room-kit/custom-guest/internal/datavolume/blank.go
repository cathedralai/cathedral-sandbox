// Package datavolume contains preservation checks for owner-unlocked storage.
// Nothing in this package opens a disk, obtains a key, formats or mounts it.
package datavolume

import (
	"context"
	"errors"
	"io"
)

const maxDiskBytes int64 = 400 << 30
const scanChunk = 1 << 20

// CheckBlank reads the entire held candidate before first-use initialization.
// A zero header alone is never sufficient: later ciphertext may be recoverable
// with a header backup. The caller must hold the selected disk's identity and
// exclusive-use gate across this check and any subsequent format operation.
// This result alone does not authorize formatting, or authenticate host storage.
func CheckBlank(ctx context.Context, disk io.ReaderAt, size int64) error {
	if size <= 0 || size > maxDiskBytes || size%4096 != 0 {
		return errors.New("invalid candidate size")
	}
	buf := make([]byte, scanChunk)
	defer clear(buf)
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		next := int64(len(buf))
		if size-offset < next {
			next = size - offset
		}
		block := buf[:int(next)]
		n, err := disk.ReadAt(block, offset)
		if n != len(block) || err != nil {
			return errors.New("candidate could not be read completely")
		}
		for _, b := range block {
			if b != 0 {
				return errors.New("candidate contains existing data; initialization refused")
			}
		}
		offset += next
	}
	return ctx.Err()
}
