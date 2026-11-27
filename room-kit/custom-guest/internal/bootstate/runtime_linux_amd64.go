package bootstate

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"syscall"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootkeys"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstrap"
)

const tmpfsMagic = 0x01021994

// The reference root uses systemd 252, which keeps an inherited /run mount.
// Match its bounded runtime capacity instead of sizing /run for our four files.
// https://github.com/systemd/systemd/blob/v252/src/shared/mount-util.h
const runtimeMountOptions = "mode=0755,size=20%,nr_inodes=800k"

func mountRuntime(run *os.File) error {
	return syscall.Mount("tmpfs", descriptorPath(run), "tmpfs",
		syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, runtimeMountOptions)
}

// ReadyRoot is produced only after the verity root and runtime files pass.
// Its zero value cannot hand off to owner code.
type ReadyRoot struct{ ready bool }

func rootDirectory(root *os.Root, name string) (*os.File, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	// These are fixed direct children of the reference root. Refuse aliases
	// rather than allowing two mount targets to resolve to one directory.
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("runtime mount target is not a plain directory")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(info, after) {
		f.Close()
		return nil, errors.New("runtime directory changed")
	}
	return f, nil
}

func descriptorPath(f *os.File) string {
	return "/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10)
}

func writeRuntime(run *os.Root, launch bootstrap.Launch, iface string, random io.Reader) error {
	f, err := run.Open(".")
	if err != nil {
		return err
	}
	var fs syscall.Statfs_t
	err = syscall.Fstatfs(int(f.Fd()), &fs)
	info, statErr := f.Stat()
	f.Close()
	if statErr != nil {
		return statErr
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("runtime directory must be root-owned and not writable by others")
	}
	if err != nil {
		return err
	}
	const restrictions = syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC
	if fs.Type != tmpfsMagic || fs.Flags&restrictions != restrictions {
		return errors.New("runtime storage is not restricted tmpfs")
	}
	if err := run.Mkdir("cathedral", 0700); err != nil {
		return err
	}
	dir, err := run.OpenRoot("cathedral")
	if err != nil {
		return err
	}
	defer dir.Close()
	files, err := bootkeys.Files(launch, iface, random)
	if err != nil {
		return err
	}
	defer func() {
		for _, value := range files {
			clear(value)
		}
	}()
	for _, name := range []string{"ssh_host_ed25519_key", "ssh_host_ed25519_key.pub", "authorized_keys", "network.env"} {
		value, ok := files[name]
		if !ok || len(value) == 0 {
			return errors.New("runtime file missing")
		}
		f, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		n, writeErr := f.Write(value)
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if n != len(value) {
			return io.ErrShortWrite
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// PrepareVerifiedRuntime performs the verity/root-contract/RAM-key stages in
// order. Call only after signed launch, observed resources (including memory)
// and native HOST_DATA gates pass, in measured PID1 with private mounts.
// Failure requires poweroff; no partially prepared root may be executed.
func PrepareVerifiedRuntime(launch bootstrap.Launch, veritySHA, reportSHA [32]byte) (*ReadyRoot, error) {
	if os.Getpid() != 1 || os.Geteuid() != 0 {
		return nil, errors.New("measured root PID1 required")
	}
	devices, err := CheckDevices(launch)
	if err != nil {
		return nil, err
	}
	path, err := MountVerifiedRoot(launch, veritySHA)
	if err != nil {
		return nil, err
	}
	if _, err := CheckRoot(path, reportSHA); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	for _, name := range []string{"dev", "proc", "sys"} {
		f, err := rootDirectory(root, name)
		if err != nil {
			return nil, err
		}
		f.Close()
	}
	run, err := rootDirectory(root, "run")
	if err != nil {
		return nil, err
	}
	err = mountRuntime(run)
	run.Close()
	if err != nil {
		return nil, err
	}
	ram, err := root.OpenRoot("run")
	if err != nil {
		return nil, err
	}
	defer ram.Close()
	if err := writeRuntime(ram, launch, devices.Interface, rand.Reader); err != nil {
		return nil, err
	}
	return &ReadyRoot{ready: true}, nil
}

// Exec moves kernel mounts, switches to the verified root and executes only
// /sbin/init with a fixed argument/environment set. It never returns on success.
// This consumes the token even on failure. The caller must power off on error.
func (r *ReadyRoot) Exec() error {
	if r == nil || !r.ready || os.Getpid() != 1 || os.Geteuid() != 0 {
		return errors.New("verified PID1 runtime required")
	}
	r.ready = false
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	root, err := os.OpenRoot(verifiedRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	// Retain all target descriptors before moving /proc. It must move last,
	// since descriptorPath itself uses procfs in the old root.
	targets := make([]*os.File, 0, 3)
	defer func() {
		for _, f := range targets {
			f.Close()
		}
	}()
	for _, name := range []string{"dev", "sys", "proc"} {
		f, err := rootDirectory(root, name)
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
	// Explicitly close every root/mount descriptor before owner code begins.
	for _, f := range targets {
		f.Close()
	}
	base.Close()
	root.Close()
	return syscall.Exec("/sbin/init", []string{"/sbin/init"}, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "TERM=linux"})
}
