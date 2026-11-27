package vmroot

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmrecovery"
)

const (
	newRoot = "/newroot"
	// Cut points of the mount, resize and sync steps. Together with the CutCopy*, CutVerityClosed
	// and tree cut points, FirstBootCutPoints lists every one in the order it runs.
	CutMounted = "vmroot:mounted"
	CutResized = "vmroot:resized"
	CutSynced  = "vmroot:synced"
	CutRecSync = "vmroot:recovery-synced"
)

// FirstBootCutPoints is every point FirstBoot reports to its cut function, in order. A test reruns
// the whole first boot after a cut at each.
var FirstBootCutPoints = []string{CutCopyStart, CutCopyDone, CutVerityClosed, CutMounted, CutResized,
	CutUser, CutHostKey, CutCloudInit, CutSynced, CutRecovery, CutRecSync}

var releaseRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[a-z0-9]+$`)

// Mounted is the customer's root file system, mounted read-write at its path.
type Mounted struct {
	path string
	fs   *os.File
}

// Path is where the root is mounted.
func (m *Mounted) Path() string { return m.path }

func descriptorPath(f *os.File) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10)
}

// Mount mounts the ext4 file system area at path (default /newroot). nodev only: the customer's
// root needs setuid binaries (sudo). It refuses an existing path, as the dedicated init does.
func Mount(fs *os.File, path string) (*Mounted, error) {
	if path == "" {
		path = newRoot
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("the new root path already exists or is unreadable")
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, err
	}
	// The kernel records the source string in /proc/mounts, and resize2fs finds a mounted file system
	// there by device. So a device opened by its /dev path is mounted by that path; the descriptor
	// path is only a fallback and cannot be resized online.
	source := descriptorPath(fs)
	if name := fs.Name(); strings.HasPrefix(name, "/dev/") && !strings.Contains(name, "..") {
		source = name
	}
	if err := syscall.Mount(source, path, "ext4", syscall.MS_NODEV, ""); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("mount root: %w", err)
	}
	return &Mounted{path: path, fs: fs}, nil
}

// Unmount detaches the root after a failure, so a test (or a retry) can start again. The init
// powers off on any error and does not need it.
func (m *Mounted) Unmount() error {
	err := syscall.Unmount(m.path, syscall.MNT_DETACH)
	if err == nil {
		err = os.Remove(m.path)
	}
	return err
}

// UnmountStrict unmounts without detaching and removes the mount point. A busy root fails loudly:
// the init hands the file-system area to the disk package next, which must not see a lazy mount.
func (m *Mounted) UnmountStrict() error {
	if err := syscall.Unmount(m.path, 0); err != nil {
		return err
	}
	return os.Remove(m.path)
}

// Resize grows the file system to its device, online (resize2fs refuses an unmounted file system
// that was not checked, and the tools carry no e2fsck).
func (m *Mounted) Resize(t Tool) error {
	// resize2fs opens the device itself and finds the mount from it. A device the disk package opened
	// by its /dev path is named so; anything else falls back to the descriptor.
	if name := m.fs.Name(); strings.HasPrefix(name, "/dev/") && !strings.Contains(name, "..") {
		return t.run(5*time.Minute, nil, name)
	}
	return t.run(5*time.Minute, []*os.File{m.fs}, "/proc/self/fd/4")
}

func (m *Mounted) Root() (*os.Root, error) { return os.OpenRoot(m.path) }

// FirstBootConfig is step 4.2 and 4.3 of the spec.
type FirstBootConfig struct {
	Verity, Resize2fs Tool
	Base              Base
	FS                *os.File
	Tree              TreeOptions
	// MountPoint is /newroot unless a test says otherwise.
	MountPoint string
}

func cutOf(f func(string) error) func(string) error {
	if f == nil {
		return func(string) error { return nil }
	}
	return f
}

// FirstBoot copies the verified base root, grows it, makes the user, host key and cloud-init
// marker, flushes, writes the recovery record and flushes (7.2 step 4.2 and 4.3). It returns the
// root still mounted and the record whose key the disk package adds as a keyslot (4.4). On any
// error the root is unmounted again. A cut at any point leaves a state the next boot discards by
// copying the base again from offset 0, so the result of a rerun never depends on the cut.
func FirstBoot(cfg FirstBootConfig) (m *Mounted, rec vmrecovery.Record, err error) {
	cut := cutOf(cfg.Tree.Cut)
	if err = CopyBase(cfg.Verity, cfg.Base, cfg.FS, cut); err != nil {
		return nil, rec, err
	}
	if m, err = Mount(cfg.FS, cfg.MountPoint); err != nil {
		return nil, rec, err
	}
	defer func() {
		if err != nil {
			m.Unmount()
			m = nil
		}
	}()
	if err = cut(CutMounted); err != nil {
		return
	}
	if err = m.Resize(cfg.Resize2fs); err != nil {
		return
	}
	if err = cut(CutResized); err != nil {
		return
	}
	root, err := m.Root()
	if err != nil {
		return
	}
	defer root.Close()
	if err = PrepareTree(root, cfg.Tree); err != nil {
		return
	}
	syscall.Sync()
	if err = cut(CutSynced); err != nil {
		return
	}
	if rec, err = WriteRecovery(root, cfg.Tree); err != nil {
		return
	}
	syscall.Sync()
	err = cut(CutRecSync)
	return
}

// Bind is one measured file from the initrd that appears in the customer's root.
type Bind struct {
	Source string // a path in the initrd
	Name   string // the file name under /run/cathedral/bin
}

// FinishConfig is step 5 of the spec, after the disk package has written the meta.
type FinishConfig struct {
	Link          []byte
	KernelRelease string // the module tree in the initrd at /usr/lib/modules/<release>
	Tools         []Bind
}

const runtimeMountOptions = "mode=0755,size=20%,nr_inodes=800k"

func plainDirectory(root *os.Root, name string) (*os.File, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is not a plain directory", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) {
		f.Close()
		return nil, fmt.Errorf("%s changed", name)
	}
	return f, nil
}

// bindReadOnly binds src over name in root, then remounts the new mount read-only. The remount
// must name the bind mount, not the directory under it: a descriptor opened before the bind still
// points at the old mount, so name is opened again after the bind.
func bindReadOnly(src string, root *os.Root, name string, extra uintptr) error {
	before, err := root.Open(name)
	if err != nil {
		return err
	}
	err = syscall.Mount(src, descriptorPath(before), "", syscall.MS_BIND, "")
	before.Close()
	if err != nil {
		return fmt.Errorf("bind %s: %w", src, err)
	}
	after, err := root.Open(name)
	if err != nil {
		return err
	}
	defer after.Close()
	// A bind mount takes its flags from the source; read-only and the rest need a second call.
	if err := syscall.Mount("", descriptorPath(after), "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|extra, ""); err != nil {
		return fmt.Errorf("remount %s read-only: %w", src, err)
	}
	return nil
}

// Finish is what every boot does after the disk is ready (7.2 step 5), except the status record:
// a fresh tmpfs on the root's /run, the module tree and the tools bound read-only into it, the
// network file from the link under /run (never /etc), and cloud-init off again. The tools are
// bound as files at /run/cathedral/bin/<name>, so the customer's `sudo cathedral-attest` runs the
// measured copy.
func (m *Mounted) Finish(cfg FinishConfig) error {
	if !releaseRe.MatchString(cfg.KernelRelease) {
		return errors.New("kernel release is not a release string")
	}
	if len(cfg.Tools) == 0 {
		return errors.New("no tools to bind")
	}
	root, err := m.Root()
	if err != nil {
		return err
	}
	defer root.Close()
	if err := AssertCloudInitOff(root); err != nil {
		return err
	}
	// Modules: /usr/lib/modules/<release> of the initrd, read-only, at the same path in the root.
	// The root's /lib is a link to usr/lib on a usrmerged Ubuntu, so one path serves both.
	dir := "usr/lib/modules/" + cfg.KernelRelease
	if err := root.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	modules, err := plainDirectory(root, dir)
	if err != nil {
		return err
	}
	modules.Close()
	if err := bindReadOnly("/usr/lib/modules/"+cfg.KernelRelease, root, dir, syscall.MS_NOEXEC); err != nil {
		return fmt.Errorf("bind modules: %w", err)
	}
	// /run: a tmpfs the same size as systemd's own, which keeps an inherited /run mount.
	run, err := plainDirectory(root, "run")
	if err != nil {
		return err
	}
	err = syscall.Mount("tmpfs", descriptorPath(run), "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, runtimeMountOptions)
	run.Close()
	if err != nil {
		return fmt.Errorf("mount /run: %w", err)
	}
	runRoot, err := root.OpenRoot("run")
	if err != nil {
		return err
	}
	defer runRoot.Close()
	if err := WriteNetwork(runRoot, cfg.Link); err != nil {
		return err
	}
	if err := runRoot.MkdirAll("cathedral/bin", 0o755); err != nil {
		return err
	}
	for _, tool := range cfg.Tools {
		dest := "cathedral/bin/" + tool.Name
		if err := writeNew(runRoot, dest, nil, 0o755); err != nil {
			return err
		}
		if err := bindReadOnly(tool.Source, runRoot, dest, 0); err != nil {
			return fmt.Errorf("bind %s: %w", tool.Name, err)
		}
	}
	return nil
}

// SwitchRoot moves the kernel mounts into the root, makes it the root and executes /sbin/init.
// It copies bootstate.(*ReadyRoot).Exec (runtime_linux_amd64.go:177-233), with the dedicated
// token replaced by ready: a function that returns nil only when the disk package has read the
// meta as ready. Nothing moves before it returns nil. It never returns on success.
func (m *Mounted) SwitchRoot(ready func() error) error {
	if ready == nil {
		return errors.New("switch_root needs a ready check")
	}
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		return errors.New("verified PID1 required")
	}
	if err := ready(); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	root, err := os.OpenRoot(m.path)
	if err != nil {
		return err
	}
	defer root.Close()
	targets := make([]*os.File, 0, 3)
	defer func() {
		for _, f := range targets {
			f.Close()
		}
	}()
	for _, name := range []string{"dev", "sys", "proc"} {
		f, err := plainDirectory(root, name)
		if err != nil {
			return err
		}
		targets = append(targets, f)
	}
	base, err := root.Open(".")
	if err != nil {
		return err
	}
	defer base.Close()
	// proc moves last: descriptorPath itself uses procfs in the old root.
	for i, name := range []string{"dev", "sys", "proc"} {
		if err := syscall.Mount("/"+name, descriptorPath(targets[i]), "", syscall.MS_MOVE, ""); err != nil {
			return fmt.Errorf("move %s: %w", name, err)
		}
	}
	if err := base.Chdir(); err != nil {
		return err
	}
	if err := syscall.Mount(".", "/", "", syscall.MS_MOVE, ""); err != nil {
		return err
	}
	if err := syscall.Chroot("."); err != nil {
		return err
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	for _, f := range targets {
		f.Close()
	}
	base.Close()
	root.Close()
	return syscall.Exec("/sbin/init", []string{"/sbin/init"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "TERM=linux"})
}
