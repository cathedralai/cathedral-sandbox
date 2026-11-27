package vmdisk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// openPinned is internal/bootstate/verity_linux_amd64.go openPinnedHelper
// (copied, not imported, until the consolidation PR): a root-owned regular
// executable, not group or world writable, whose bytes hash to the pin.
func openPinned(path string, expected [32]byte) (*os.File, error) {
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
		st.Uid != 0 || st.Size < 4 || st.Size > 32<<20 {
		return fail(errors.New("invalid helper file"))
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, (32<<20)+1))
	if err != nil {
		return fail(err)
	}
	if n != st.Size || !bytes.Equal(hash.Sum(nil), expected[:]) {
		return fail(errors.New("helper digest differs"))
	}
	return f, nil
}

// toolResult is one finished run. Exit is the process exit code; a run
// that did not exit normally (a signal, the timeout) is an error instead.
type toolResult struct {
	Exit   int
	Stdout []byte
	Stderr string
}

// run executes the pinned tool by descriptor (/proc/self/fd/3, as runVerity
// in internal/bootstate). Each secret goes through its own pipe, at
// /proc/self/fd/4, /proc/self/fd/5, ... in order, never argv or env; the
// args may name those paths. point names the run for the cut hook.
func (t Tool) run(ctx context.Context, point string, timeout time.Duration, secrets [][]byte, args ...string) (toolResult, error) {
	return t.runFiles(ctx, point, timeout, secrets, nil, args...)
}

// runFiles is run with open files passed after the secret pipes: the first
// at /proc/self/fd/(4+len(secrets)), then in order.
func (t Tool) runFiles(ctx context.Context, point string, timeout time.Duration, secrets [][]byte, extra []*os.File, args ...string) (toolResult, error) {
	helper, err := openPinned(t.Path, t.SHA256)
	if err != nil {
		return toolResult{}, fmt.Errorf("%s: %w", t.Name, err)
	}
	defer helper.Close()
	files := []*os.File{helper}
	for _, secret := range secrets {
		r, w, err := os.Pipe()
		if err != nil {
			return toolResult{}, err
		}
		defer r.Close()
		// A pipe holds 64 KiB; a 32-byte secret never blocks the write.
		_, werr := w.Write(secret)
		cerr := w.Close()
		if werr != nil || cerr != nil {
			return toolResult{}, errors.New("secret pipe failed")
		}
		files = append(files, r)
	}
	files = append(files, extra...)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Args[0] = t.Name
	// No udev in the initrd: libdevmapper makes its own nodes (sealed-data.sh:53).
	cmd.Env = []string{"DM_DISABLE_UDEV=1", "LC_ALL=C"}
	cmd.ExtraFiles = files
	cmd.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limited{w: &stdout, n: 4 << 20}
	cmd.Stderr = &limited{w: &stderr, n: 64 << 10}
	if err := runWithCut(point, cmd); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.Exited() && ctx.Err() == nil {
			return toolResult{Exit: exit.ExitCode(), Stdout: stdout.Bytes(), Stderr: firstLine(stderr.String())}, nil
		}
		return toolResult{}, fmt.Errorf("%s did not finish: %w", t.Name, err)
	}
	return toolResult{Stdout: stdout.Bytes(), Stderr: firstLine(stderr.String())}, nil
}

// limited keeps at most n bytes and drops the rest, so a hostile header
// cannot grow the init's memory through a dump.
type limited struct {
	w io.Writer
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	keep := len(p)
	if keep > l.n {
		keep = l.n
	}
	if keep > 0 {
		l.w.Write(p[:keep])
		l.n -= keep
	}
	return len(p), nil
}

func firstLine(s string) string {
	if i := bytes.IndexByte([]byte(s), '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// secretPath is the path a run's n-th secret is read from.
func secretPath(n int) string { return "/proc/self/fd/" + strconv.Itoa(4+n) }
