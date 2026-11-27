package vmroot

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// Tool is a pinned static helper from the measured initrd. The digest is a constant in the init,
// never read from the host or the root disk.
type Tool struct {
	Path   string
	SHA256 [32]byte
}

// openPinned is a copy of bootstate.openPinnedHelper (room-kit/custom-guest/internal/bootstate/
// verity_linux_amd64.go:66-107). The builders of the VM and dedicated inits may not share files
// until all three PRs land; one consolidation PR merges the copies. Keep the two in step.
func openPinned(t Tool) (*os.File, error) {
	if t.SHA256 == [32]byte{} {
		return nil, errors.New("helper pin missing")
	}
	fd, err := syscall.Open(t.Path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), t.Path)
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
	if n != st.Size || !bytes.Equal(hash.Sum(nil), t.SHA256[:]) {
		return fail(errors.New("helper digest differs"))
	}
	return f, nil
}

// boundedWriter keeps the first bytes of a helper's output for an error message.
type boundedWriter struct{ buf bytes.Buffer }

func (w *boundedWriter) Write(p []byte) (int, error) {
	if room := 512 - w.buf.Len(); room > 0 {
		w.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// run executes the verified descriptor, not the path: after the digest check the path can change
// without effect. The helper's fds are 3 (itself) then the files passed, from 4. The environment
// is empty and the time bounded.
func (t Tool) run(timeout time.Duration, files []*os.File, args ...string) error {
	helper, err := openPinned(t)
	if err != nil {
		return err
	}
	defer helper.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	cmd.Args[0] = t.Path
	cmd.Env = []string{}
	cmd.ExtraFiles = append([]*os.File{helper}, files...)
	out := &boundedWriter{}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w: %s", t.Path, err, bytes.TrimSpace(out.buf.Bytes()))
	}
	return nil
}
