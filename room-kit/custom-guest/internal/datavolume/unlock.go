package datavolume

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNotLUKS is reserved for a completed probe that found no LUKS header.
// Timeouts, I/O errors and invalid LUKS metadata must not return this sentinel.
var ErrNotLUKS = errors.New("candidate has no LUKS header")

// LockedCandidate is an authenticated data disk held exclusively by the caller.
// The eventual Linux adapter must hold its descriptor identity and serialization
// lock until Unlock returns, refuse an already-mounted/claimed device, bound all
// helper I/O, and never substitute a pathname selected from untrusted metadata.
// This interface is an execution contract, not proof that an adapter meets it.
// Header is a read-only cryptsetup LUKS2 JSON probe; Format creates the required
// LUKS2/XTS/HMAC layout and must not create a filesystem or print the passphrase.
// Open must unlock with exactly the header the last Header call returned, never
// a fresh read of the disk, so the header the policy checked is the one used.
// Open must return a non-nil owned mapping even on failure if it allocated one;
// it must never return an existing mapping belonging to another invocation.
// Methods must not retain the passphrase after returning.
type LockedCandidate interface {
	io.ReaderAt
	Size() int64
	Header(context.Context) ([]byte, error)
	Format(context.Context, []byte) error
	Open(context.Context, []byte) (OwnedMapping, error)
}

// OwnedMapping belongs to this invocation. Verify must read back the active
// encrypted/integrity stack, its complete backing-device identity and geometry;
// a successful passphrase or metadata check alone is insufficient. Filesystem
// probes read-only and returns a specific type, or an error if unknown/unreadable.
// MakeFilesystem creates ext4, and is called only after Format succeeded here
// and Filesystem reported "empty".
// Mount must use a fixed safe target and nosuid,nodev,noexec, and verify the
// resulting mount before returning success. Close must unmount any partial mount
// and close only this invocation's mappings, reporting cleanup failures.
type OwnedMapping interface {
	Verify(context.Context) error
	Filesystem(context.Context) (string, error)
	MakeFilesystem(context.Context) error
	Mount(context.Context) error
	Close(context.Context) error
}

// Unlock executes the preservation-sensitive ordering shared by the future
// owner command and its adapter tests. It is not wired to a CLI or Linux adapter
// yet. Call only after owner-bound SSH verification and authenticated launch /
// disk selection. The caller retains the exclusive disk hold throughout.
//
// The supplied passphrase is consumed and cleared on every return. It is never
// included in an error. A failed or interrupted first use is NOT retried with
// filesystem creation in a later invocation: that invocation sees an existing
// nonblank volume and must preserve it for deliberate recovery.
func Unlock(ctx context.Context, disk LockedCandidate, passphrase []byte) (err error) {
	defer clear(passphrase)
	if len(passphrase) == 0 || len(passphrase) > 4096 {
		return errors.New("passphrase size invalid")
	}
	if disk == nil || disk.Size() <= 0 || disk.Size() > maxDiskBytes || disk.Size()%4096 != 0 {
		return errors.New("invalid candidate")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	header, err := disk.Header(ctx)
	created := false
	if errors.Is(err, ErrNotLUKS) {
		if err = CheckBlank(ctx, disk, disk.Size()); err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = disk.Format(ctx, passphrase); err != nil {
			return errors.New("data volume initialization failed; preserve for recovery")
		}
		created = true
		if err = ctx.Err(); err != nil {
			return err
		}
		header, err = disk.Header(ctx)
	}
	if err != nil {
		return errors.New("data volume header unavailable; left locked")
	}
	if err = CheckHeaderPolicy(header); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	mapping, openErr := disk.Open(ctx, passphrase)
	clear(passphrase) // No later operation needs the owner secret.
	// An adapter can return a partial mapping with its failure. Always attempt
	// cleanup with a fresh bounded context, even if the operation was cancelled.
	mounted := false
	if mapping != nil {
		defer func() {
			if !mounted {
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if closeErr := mapping.Close(cleanup); closeErr != nil {
					err = errors.Join(err, errors.New("data mapping cleanup failed; manual recovery required"))
				}
			}
		}()
	}
	if openErr != nil || mapping == nil {
		return errors.New("data volume unlock failed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = mapping.Verify(ctx); err != nil {
		return errors.New("active data mapping policy mismatch")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if created {
		// mke2fs -F overwrites whatever it finds, so it runs only on a plaintext
		// that probes as all zero, which is what a fresh format leaves.
		fs, err := mapping.Filesystem(ctx)
		if err != nil || fs != "empty" {
			return errors.New("new data volume is not empty; preserve for recovery")
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = mapping.MakeFilesystem(ctx); err != nil {
			return errors.New("filesystem initialization failed; preserve for recovery")
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	fs, err := mapping.Filesystem(ctx)
	if err != nil || fs != "ext4" {
		return errors.New("existing filesystem is unknown or unsupported; not formatting")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Recheck after filesystem probing/creation and before mounting. A mapping
	// that changed in the meantime never gets a mount through this path.
	if err = mapping.Verify(ctx); err != nil {
		return errors.New("active data mapping changed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = mapping.Mount(ctx); err != nil {
		return errors.New("restricted data mount failed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	mounted = true
	return nil
}
