package vmdisk

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// cryptsetup runs the pinned cryptsetup on one LUKS device path. Keys reach
// it only through pipes (Tool.run); it never sees a key in argv or env, and
// its output is never logged beyond one stderr line.
//
// hdr, when set, is this boot's in-memory copy of the header and keyslot
// area (run.snapshot). Every read (dump, key test, open) passes it as
// --header, so each reads the header the classifier checked, not the disk
// again: the host cannot swap the header between a check and an open. The
// writes (luksFormat, luksAddKey, luksKillSlot) change the header on the
// device and take no --header; the caller snapshots again after each.
type cryptsetup struct {
	tool Tool
	dev  string
	hdr  *os.File
}

// read runs a header read with the snapshot, when there is one, as the
// file after the secret pipes.
func (c cryptsetup) read(ctx context.Context, point string, secrets [][]byte, args ...string) (toolResult, error) {
	if c.hdr == nil {
		return c.tool.run(ctx, point, quick, secrets, args...)
	}
	// The verb stays first; --header goes right after it.
	with := append([]string{args[0], "--header", secretPath(len(secrets))}, args[1:]...)
	return c.tool.runFiles(ctx, point, quick, secrets, []*os.File{c.hdr}, with...)
}

const (
	quick = 60 * time.Second
	// The format and slot writes have their own bound: the keyslot area
	// wipe is 16 MiB, and pbkdf2 at 1000 iterations is instant.
	slow = 5 * time.Minute
)

// keyArgs read exactly 32 bytes of a key from the n-th secret pipe.
func keyArgs(n int) []string {
	return []string{"--key-file", secretPath(n), "--keyfile-size", "32"}
}

func (c cryptsetup) dump(ctx context.Context) (toolResult, error) {
	return c.read(ctx, "dump", nil, "luksDump", "--dump-json-metadata", c.dev)
}

// passphraseRefused is cryptsetup's exit code for "no key available with
// this passphrase" (EPERM).
const passphraseRefused = 2

// opens reports whether key opens slot (any slot when slot < 0). Only exit 2
// means "does not open". Any other nonzero exit (a header it cannot load, a
// device it cannot read, a bad argument) is an error, so a failure of the
// tool never classifies a disk as locked.
func (c cryptsetup) opens(ctx context.Context, key []byte, slot int) (bool, error) {
	args := []string{"open", "--test-passphrase", "--type", "luks2", "--disable-external-tokens"}
	if slot >= 0 {
		args = append(args, "--key-slot", strconv.Itoa(slot))
	}
	args = append(append(args, keyArgs(0)...), c.dev)
	r, err := c.read(ctx, "test", [][]byte{key}, args...)
	if err != nil {
		return false, err
	}
	switch r.Exit {
	case 0:
		return true, nil
	case passphraseRefused:
		return false, nil
	}
	return false, fmt.Errorf("cryptsetup open --test-passphrase exit %d: %s", r.Exit, r.Stderr)
}

// open maps the volume as name, read-only or read-write, with one slot.
func (c cryptsetup) open(ctx context.Context, key []byte, slot int, name string, readonly bool) error {
	args := []string{"open", "--type", "luks2", "--disable-external-tokens"}
	if readonly {
		args = append(args, "--readonly")
	}
	if slot >= 0 {
		args = append(args, "--key-slot", strconv.Itoa(slot))
	}
	args = append(append(args, keyArgs(0)...), c.dev, name)
	r, err := c.read(ctx, "open", [][]byte{key}, args...)
	if err != nil {
		return err
	}
	if r.Exit != 0 {
		return fmt.Errorf("cryptsetup open exit %d: %s", r.Exit, r.Stderr)
	}
	return nil
}

func (c cryptsetup) close(ctx context.Context, name string) error {
	r, err := c.tool.run(ctx, "close", quick, nil, "close", name)
	if err != nil {
		return err
	}
	if r.Exit != 0 {
		return fmt.Errorf("cryptsetup close exit %d: %s", r.Exit, r.Stderr)
	}
	return nil
}

// format is F3: the data volume settings (sealed-data.sh:211) with the 16
// MiB data offset the header rules pin. It rewrites the whole header and
// keyslot area and makes a new volume key.
func (c cryptsetup) format(ctx context.Context, key []byte) error {
	args := []string{"luksFormat", "--type", "luks2", "--batch-mode", "--cipher", cipher, "--key-size", "512",
		"--sector-size", strconv.Itoa(sectorSize), "--offset", strconv.Itoa(LUKSDataOffset / sectorBytes),
		"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--hash", "sha256", "--label", "cathedral-vm-root"}
	args = append(append(args, keyArgs(0)...), c.dev)
	r, err := c.tool.run(ctx, "f3", slow, [][]byte{key}, args...)
	if err != nil {
		return err
	}
	if r.Exit != 0 {
		return fmt.Errorf("cryptsetup luksFormat exit %d: %s", r.Exit, r.Stderr)
	}
	return nil
}

// addKey adds newKey as a slot, authorized by key. cryptsetup picks the
// slot; the caller finds it by the header diff.
func (c cryptsetup) addKey(ctx context.Context, key, newKey []byte) error {
	args := []string{"luksAddKey", "--batch-mode", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
		"--hash", "sha256"}
	args = append(append(args, keyArgs(0)...), "--new-keyfile-size", "32", c.dev, secretPath(1))
	r, err := c.tool.run(ctx, "add", slow, [][]byte{key, newKey}, args...)
	if err != nil {
		return err
	}
	if r.Exit != 0 {
		return fmt.Errorf("cryptsetup luksAddKey exit %d: %s", r.Exit, r.Stderr)
	}
	return nil
}

// killSlot removes one slot. Batch mode needs no passphrase; the caller
// only ever names a slot outside the meta table.
func (c cryptsetup) killSlot(ctx context.Context, slot int) error {
	r, err := c.tool.run(ctx, "kill", slow, nil, "luksKillSlot", "--batch-mode", c.dev, strconv.Itoa(slot))
	if err != nil {
		return err
	}
	if r.Exit != 0 {
		return fmt.Errorf("cryptsetup luksKillSlot %d exit %d: %s", slot, r.Exit, r.Stderr)
	}
	return nil
}

// header dumps and strictly parses the header. A dump that fails is an
// error here: callers that classify use dump directly.
func (c cryptsetup) header(ctx context.Context) (Header, error) {
	r, err := c.dump(ctx)
	if err != nil {
		return Header{}, err
	}
	if r.Exit != 0 {
		return Header{}, errors.New("the LUKS2 header does not read")
	}
	return ParseHeader(r.Stdout), nil
}

// Version returns `cryptsetup --version`'s first line, for the floor check.
func (t Tool) Version(ctx context.Context) (string, error) {
	r, err := t.run(ctx, "version", quick, nil, "--version")
	if err != nil {
		return "", err
	}
	if r.Exit != 0 {
		return "", errors.New("cryptsetup --version failed")
	}
	return firstLine(string(r.Stdout)), nil
}
