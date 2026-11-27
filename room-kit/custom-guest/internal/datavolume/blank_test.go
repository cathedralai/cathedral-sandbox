package datavolume

import (
	"context"
	"errors"
	"io"
	"testing"
)

type scanReader struct {
	nonzero int64
	read    int64
	short   bool
	err     error
	cancel  context.CancelFunc
}

func (r *scanReader) ReadAt(p []byte, off int64) (int, error) {
	clear(p)
	if off != r.read {
		panic("non-contiguous read")
	}
	r.read += int64(len(p))
	if r.nonzero >= off && r.nonzero < r.read {
		p[r.nonzero-off] = 1
	}
	if r.cancel != nil {
		r.cancel()
	}
	if r.short {
		return len(p) - 1, io.EOF
	}
	return len(p), r.err
}
func TestBlankWholeCandidate(t *testing.T) {
	size := int64(3*scanChunk + 4096)
	r := &scanReader{nonzero: -1}
	if err := CheckBlank(context.Background(), r, size); err != nil || r.read != size {
		t.Errorf("read=%d err=%v", r.read, err)
	}
	for _, pos := range []int64{0, scanChunk - 1, scanChunk, 2*scanChunk + 1, size - 1} {
		r := &scanReader{nonzero: pos}
		if CheckBlank(context.Background(), r, size) == nil {
			t.Fatalf("accepted data at %d", pos)
		}
	}
}
func TestBlankReadFailures(t *testing.T) {
	for _, r := range []*scanReader{{nonzero: -1, short: true}, {nonzero: -1, err: errors.New("read failed")}} {
		if CheckBlank(context.Background(), r, 4096) == nil {
			t.Fatal("accepted unreadable candidate")
		}
	}
	for _, size := range []int64{-1, 0, 4095, maxDiskBytes + 4096} {
		r := &scanReader{nonzero: -1}
		if CheckBlank(context.Background(), r, size) == nil || r.read != 0 {
			t.Fatalf("size %d read", size)
		}
	}
}
func TestBlankCancellation(t *testing.T) {
	for _, before := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if before {
			cancel()
		}
		r := &scanReader{nonzero: -1, cancel: cancel}
		err := CheckBlank(ctx, r, 4096)
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("accepted cancellation: %v", err)
		}
		if before && r.read != 0 {
			t.Fatal("read after cancellation")
		}
	}
}
