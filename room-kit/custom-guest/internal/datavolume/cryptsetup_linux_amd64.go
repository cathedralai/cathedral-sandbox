package datavolume

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Fixed names. Nothing here is selectable from launch documents or the host.
const (
	cryptsetupPath = "/usr/lib/cathedral/cryptsetup"
	mke2fsPath     = "/usr/sbin/mke2fs"
	mapperName     = "cathedral-data"
	mountTarget    = "/mnt/cathedral-data"
	// The held disk is always descriptor 4 in a helper (3 is the helper itself),
	// so no path chosen later can redirect cryptsetup to another device.
	diskFD = "/proc/self/fd/4"
)

// MountPoint is where a successful Unlock leaves the plaintext, mounted
// nosuid,nodev,noexec.
const MountPoint = mountTarget

// tools is everything the adapter touches outside the held descriptor. Tests
// replace paths and the exec seam; production uses productionTools.
type tools struct {
	helperPath, mke2fs, mapperDir, sys, mountinfo, mountTarget string
	scratch                                                    string // parent of the private header snapshot directory
	helperSHA                                                  [32]byte
	exec                                                       func(context.Context, command) (result, error)
}

type command struct {
	program string // empty means the pinned cryptsetup
	args    []string
	stdin   []byte
	disk    *os.File // becomes descriptor 4 of the pinned helper
}

type result struct{ stdout, stderr []byte }

func productionTools(helperSHA [32]byte) *tools {
	t := &tools{helperPath: cryptsetupPath, mke2fs: mke2fsPath, mapperDir: "/dev/mapper", sys: "/sys",
		mountinfo: "/proc/self/mountinfo", mountTarget: mountTarget, scratch: "/run", helperSHA: helperSHA}
	t.exec = t.execute
	return t
}

// openPinnedHelper is copied from bootstate/verity_linux_amd64.go (openPinnedHelper):
// the digest is checked on the descriptor that is then executed, so a swap of the
// path after the check cannot change the program. Consolidated in a follow-up PR.
func openPinnedHelper(path string, expected [32]byte) (*os.File, error) {
	if expected == [32]byte{} {
		return nil, errors.New("helper pin missing")
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
		st.Uid != 0 || st.Size < 4 || st.Size > 64<<20 {
		return fail(errors.New("invalid helper file"))
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, (64<<20)+1))
	if err != nil {
		return fail(err)
	}
	if n != st.Size || !bytes.Equal(hash.Sum(nil), expected[:]) {
		return fail(errors.New("helper digest differs"))
	}
	return f, nil
}

// boundedBuffer fails the writer instead of growing without limit.
type boundedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.limit {
		return 0, errors.New("helper output too large")
	}
	return b.buf.Write(p)
}

func (t *tools) execute(ctx context.Context, c command) (result, error) {
	var out, errOut boundedBuffer
	out.limit, errOut.limit = 1<<20, 64<<10
	var cmd *exec.Cmd
	if c.program == "" {
		helper, err := openPinnedHelper(t.helperPath, t.helperSHA)
		if err != nil {
			return result{}, err
		}
		defer helper.Close()
		cmd = exec.CommandContext(ctx, "/proc/self/fd/3", c.args...)
		cmd.Args[0] = t.helperPath
		cmd.ExtraFiles = []*os.File{helper}
		if c.disk != nil {
			cmd.ExtraFiles = append(cmd.ExtraFiles, c.disk)
		}
	} else {
		cmd = exec.CommandContext(ctx, c.program, c.args...)
	}
	// Empty environment: nothing secret can ride in it and nothing ambient
	// (LD_*, CRYPTSETUP_*) can change the helper's behavior.
	cmd.Env = []string{}
	if len(c.stdin) > 0 {
		cmd.Stdin = bytes.NewReader(c.stdin)
	}
	cmd.Stdout, cmd.Stderr = &out, &errOut
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	res := result{out.buf.Bytes(), errOut.buf.Bytes()}
	if err != nil {
		// stderr is returned to the caller for tests; it is never put in errors.
		return res, fmt.Errorf("helper failed: %w", exitOnly(err))
	}
	return res, nil
}

// exitOnly keeps the exit status and drops everything else the exec package
// could attach.
func exitOnly(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("exit status %d", ee.ExitCode())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.New("could not run")
}

// LUKS2 primary header magic at 0, secondary header magic at each of the fixed
// secondary offsets. Any of them present means "LUKS", so a damaged primary is
// never mistaken for a blank disk.
var luksPrimary = []byte("LUKS\xba\xbe")
var luksSecondary = []byte("SKUL\xba\xbe")
var secondaryOffsets = []int64{0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000}

func (d *HeldDevice) ready() error {
	if d == nil || d.file == nil || d.tools == nil || d.dev == "" {
		return errors.New("data device adapter not initialized")
	}
	return nil
}

func (d *HeldDevice) run(ctx context.Context, timeout time.Duration, c command) (result, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if c.disk == nil {
		c.disk = d.file
	}
	return d.tools.exec(ctx, c)
}

// Header returns luksDump's JSON metadata, or ErrNotLUKS only when neither the
// primary nor any secondary LUKS magic is present. Every other failure is an
// error that Unlock treats as "unavailable; leave locked".
func (d *HeldDevice) Header(ctx context.Context) ([]byte, error) {
	if err := d.ready(); err != nil {
		return nil, err
	}
	d.header = "" // until this call has a fresh snapshot, Open has nothing to use
	found := false
	probe := make([]byte, 6)
	for _, off := range append([]int64{0}, secondaryOffsets...) {
		if off+6 > d.size {
			continue
		}
		if n, err := d.ReadAt(probe, off); n != 6 || err != nil {
			return nil, errors.New("data header probe unreadable")
		}
		want := luksSecondary
		if off == 0 {
			want = luksPrimary
		}
		if bytes.Equal(probe, want) {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrNotLUKS
	}
	snapshot, err := d.snapshotHeader(ctx)
	if err != nil {
		return nil, errors.New("LUKS header backup failed")
	}
	res, err := d.run(ctx, 30*time.Second, command{args: []string{"luksDump", "--dump-json-metadata", snapshot}})
	if err != nil || len(res.stdout) == 0 {
		return nil, errors.New("LUKS metadata unreadable")
	}
	return res.stdout, nil
}

// snapshotHeader copies the LUKS header off the held disk once, into a private
// directory. Header dumps this copy and Open unlocks with it (--header), so the
// header the policy checked is the header that unlocks: a host that rewrites the
// on-disk header between the two cannot substitute its own keyslots. Each call
// replaces the previous snapshot; Close removes it.
func (d *HeldDevice) snapshotHeader(ctx context.Context) (string, error) {
	if d.headerDir == "" {
		dir, err := os.MkdirTemp(d.tools.scratch, "cathedral-data-")
		if err != nil {
			return "", err
		}
		d.headerDir = dir
	}
	path := filepath.Join(d.headerDir, "luks-header")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if _, err := d.run(ctx, 30*time.Second, command{args: []string{
		"luksHeaderBackup", diskFD, "--header-backup-file", path}}); err != nil {
		return "", err
	}
	d.header = path
	return path, nil
}

// Format creates LUKS2 with aes-xts-plain64, 4096-byte sectors and hmac-sha256
// integrity, reading the passphrase from the helper's stdin only. cryptsetup
// wipes the integrity area by default, which is slow on a large disk: the
// caller's context is the only bound.
func (d *HeldDevice) Format(ctx context.Context, passphrase []byte) error {
	if err := d.ready(); err != nil {
		return err
	}
	_, err := d.run(ctx, 0, command{stdin: passphrase, args: []string{
		"luksFormat", "--type", "luks2", "--cipher", "aes-xts-plain64", "--key-size", "512",
		"--sector-size", "4096", "--integrity", "hmac-sha256", "--hash", "sha256",
		"--pbkdf", "argon2id", "--pbkdf-memory", "262144",
		"--batch-mode", "--key-file=-", diskFD}})
	if err != nil {
		return errors.New("luksFormat failed")
	}
	return nil
}

func exists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// Open creates this invocation's mapping from the header snapshot the last
// Header call checked, never from a fresh read of the disk. Existing mapper
// nodes under either name are refused, so it can never adopt another
// invocation's mapping. If the
// helper fails after creating a node, the partial mapping is returned so the
// caller can close it.
func (d *HeldDevice) Open(ctx context.Context, passphrase []byte) (OwnedMapping, error) {
	if err := d.ready(); err != nil {
		return nil, err
	}
	if d.header == "" {
		return nil, errors.New("no checked LUKS header to open with")
	}
	for _, n := range []string{mapperName, mapperName + "_dif"} {
		present, err := exists(d.tools.mapperDir + "/" + n)
		if err != nil || present {
			return nil, errors.New("data mapping already exists or is unreadable")
		}
	}
	m := &mapping{dev: d.dev, size: d.size, header: d.header, tools: d.tools}
	_, err := d.run(ctx, 5*time.Minute, command{stdin: passphrase, args: []string{
		"open", "--type", "luks2", "--header", d.header, "--batch-mode", "--key-file=-", diskFD, mapperName}})
	if err != nil {
		for _, n := range []string{mapperName, mapperName + "_dif"} {
			if present, _ := exists(d.tools.mapperDir + "/" + n); present {
				return m, errors.New("luksOpen failed")
			}
		}
		return nil, errors.New("luksOpen failed")
	}
	return m, nil
}
