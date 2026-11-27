package datavolume

import (
	"errors"
	"io"
)

// ReadPassphrase consumes at most 4097 bytes from an already-bounded reader.
// Input is raw bytes, including any newline: callers must not silently strip
// password bytes. The eventual command must provide a timeout and refuse a TTY
// rather than accepting an echoed secret. This function does not close r.
// The caller owns and must clear the returned buffer; Unlock consumes it.
func ReadPassphrase(r io.Reader) ([]byte, error) {
	// Fixed allocation avoids leaving growth copies of the secret in memory.
	b := make([]byte, 4097)
	n, err := io.ReadFull(r, b)
	if (err != io.EOF && err != io.ErrUnexpectedEOF) || n == 0 || n > 4096 {
		clear(b)
		return nil, errors.New("passphrase input invalid or too large")
	}
	return b[:n], nil
}
