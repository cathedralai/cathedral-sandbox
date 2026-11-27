package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/bootstate"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/snp"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmdisk"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmkey"
)

// The initrd's generated files (room-kit/vm/build-vm-initrd.py, PR C). They
// are inside the measured initrd, so their pins are measured code.
const (
	closurePath     = "/usr/lib/cathedral/vm-closure.json"
	modulesListPath = "/usr/lib/cathedral/vm-modules.list"
	manifestSchema  = "cathedral.vm.initrd-manifest/v1"
	cryptsetupName  = "usr/lib/cathedral/cryptsetup"

	fwCfgRoot    = "/sys/firmware/qemu_fw_cfg/by_name"
	fwCfgDir     = "opt/cathedral"
	identityName = "vm-identity.json"
	linkName     = "link"
	linkMax      = 64

	sysBlock      = "/sys/block"
	serialRoot    = "cathedral-root"
	serialBase    = "cathedral-base"
	serialMailbox = "cathedral-mailbox"
	diskWait      = 15 * time.Second
)

var (
	releaseRe = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[a-z0-9]+$`)
	hex64Re   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	moduleRe  = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*\.ko(\.zst|\.xz|\.gz)?$`)
	vdRe      = regexp.MustCompile(`^vd[a-z]{1,2}$`)
)

// manifest is usr/lib/cathedral/vm-closure.json: build-vm-initrd.py
// generated_files.
type manifest struct {
	Schema        string            `json:"schema"`
	KernelRelease string            `json:"kernel_release"`
	Executables   map[string]string `json:"executables"`
	BootModules   []string          `json:"boot_modules"`
}

func parseManifest(raw []byte) (manifest, error) {
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil || dec.More() {
		return manifest{}, errors.New("initrd manifest unreadable")
	}
	if m.Schema != manifestSchema || !releaseRe.MatchString(m.KernelRelease) || len(m.BootModules) == 0 {
		return manifest{}, errors.New("initrd manifest invalid")
	}
	for name, sum := range m.Executables {
		if !hex64Re.MatchString(sum) || name == "" {
			return manifest{}, errors.New("initrd manifest pin invalid")
		}
	}
	if _, ok := m.Executables[cryptsetupName]; !ok {
		return manifest{}, errors.New("initrd manifest pins no cryptsetup")
	}
	return m, nil
}

func (m manifest) tool(name, argv0 string) (vmdisk.Tool, error) {
	sum, err := hex.DecodeString(m.Executables[name])
	if err != nil || len(sum) != 32 {
		return vmdisk.Tool{}, errors.New("no pin for " + name)
	}
	t := vmdisk.Tool{Path: "/" + name, Name: argv0}
	copy(t.SHA256[:], sum)
	return t, nil
}

// parseModules is usr/lib/cathedral/vm-modules.list: one path per line, in
// load order, each under usr/lib/modules/<release>/.
func parseModules(raw []byte, release string) ([]string, error) {
	bad := errors.New("module list invalid")
	if len(raw) == 0 || len(raw) > 64<<10 || raw[len(raw)-1] != '\n' {
		return nil, bad
	}
	prefix := "usr/lib/modules/" + release + "/"
	var out []string
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		rel, ok := strings.CutPrefix(line, prefix)
		if !ok || !moduleRe.MatchString(rel) || slices.Contains(out, line) {
			return nil, bad
		}
		out = append(out, line)
	}
	if len(out) > 256 {
		return nil, bad
	}
	return out, nil
}

// readBounded reads a whole small file, refusing more than max bytes.
func readBounded(path string, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return raw, nil
}

// readFwCfg reads the two names, and refuses any other under opt/cathedral.
func readFwCfg(root string) (identity, link []byte, err error) {
	dir := root + "/" + fwCfgDir
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{linkName, identityName}) {
		return nil, nil, fmt.Errorf("%s holds %v, not exactly the two names", fwCfgDir, names)
	}
	entry := func(name string, max int) ([]byte, error) {
		sizeRaw, err := readBounded(dir+"/"+name+"/size", 32)
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(strings.TrimSpace(string(sizeRaw)))
		if err != nil || size < 1 || size > max {
			return nil, fmt.Errorf("fw_cfg %s size invalid", name)
		}
		raw, err := readBounded(dir+"/"+name+"/raw", max)
		if err != nil {
			return nil, err
		}
		if len(raw) != size {
			return nil, fmt.Errorf("fw_cfg %s short read", name)
		}
		return raw, nil
	}
	if identity, err = entry(identityName, vmidentity.DocMax); err != nil {
		return nil, nil, err
	}
	if link, err = entry(linkName, linkMax); err != nil {
		return nil, nil, err
	}
	return identity, link, nil
}

// findDisks maps each serial to its block device name. There must be
// exactly the launcher's three virtio disks, one per serial.
func findDisks(root string) (map[string]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	count := 0
	for _, e := range entries {
		if !vdRe.MatchString(e.Name()) {
			continue
		}
		count++
		raw, err := readBounded(root+"/"+e.Name()+"/serial", 64)
		if err != nil {
			return nil, err
		}
		serial := strings.TrimSpace(string(raw))
		if _, dup := out[serial]; dup {
			return nil, fmt.Errorf("two disks with serial %q", serial)
		}
		out[serial] = e.Name()
	}
	for _, s := range []string{serialRoot, serialBase, serialMailbox} {
		if _, ok := out[s]; !ok {
			return nil, fmt.Errorf("no disk with serial %s", s)
		}
	}
	if count != 3 {
		return nil, fmt.Errorf("%d virtio disks, want exactly 3", count)
	}
	return out, nil
}

const blkGetSize64 = 0x80081272

// openDisk opens /dev/<name> and requires it to be the block device sysfs
// names, so a stale or planted node is refused.
func openDisk(name string, flags int) (*os.File, int64, error) {
	raw, err := readBounded(sysBlock+"/"+name+"/dev", 32)
	if err != nil {
		return nil, 0, err
	}
	var major, minor uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(raw)), "%d:%d", &major, &minor); err != nil {
		return nil, 0, fmt.Errorf("%s dev unreadable", name)
	}
	f, err := os.OpenFile("/dev/"+name, flags|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFBLK ||
		uint64(st.Rdev) != ((minor&0xff)|(major<<8)|((minor&^0xff)<<12)) {
		f.Close()
		return nil, 0, fmt.Errorf("/dev/%s is not the block device sysfs names", name)
	}
	var size uint64
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), blkGetSize64, uintptr(unsafe.Pointer(&size))); errno != 0 {
		f.Close()
		return nil, 0, errno
	}
	return f, int64(size), nil
}

const (
	sysFinitModule           = 313 // x86_64
	moduleInitCompressedFile = 4   // MODULE_INIT_COMPRESSED_FILE: the kernel decompresses
)

func loadModule(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var flags uintptr
	if !strings.HasSuffix(path, ".ko") {
		flags = moduleInitCompressedFile
	}
	params := []byte{0}
	_, _, errno := syscall.Syscall(sysFinitModule, uintptr(fd), uintptr(unsafe.Pointer(&params[0])), flags)
	if errno != 0 && errno != syscall.EEXIST {
		return fmt.Errorf("%s: %w", path, errno)
	}
	return nil
}

func kernelRelease() string {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return ""
	}
	var b []byte
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// linuxPlatform is the real boot.
type linuxPlatform struct {
	manifest   manifest
	cryptsetup vmdisk.Tool
}

func (p *linuxPlatform) LoadModules() error {
	raw, err := readBounded(closurePath, 1<<20)
	if err != nil {
		return err
	}
	if p.manifest, err = parseManifest(raw); err != nil {
		return err
	}
	if got := kernelRelease(); got != p.manifest.KernelRelease {
		return fmt.Errorf("kernel %q is not the initrd's %q", got, p.manifest.KernelRelease)
	}
	if p.cryptsetup, err = p.manifest.tool(cryptsetupName, "cryptsetup"); err != nil {
		return err
	}
	raw, err = readBounded(modulesListPath, 64<<10)
	if err != nil {
		return err
	}
	list, err := parseModules(raw, p.manifest.KernelRelease)
	if err != nil {
		return err
	}
	for _, m := range list {
		if err := loadModule("/" + m); err != nil {
			return err
		}
	}
	return nil
}

func (p *linuxPlatform) PrepareKernel() error { return bootstate.PrepareKernelViews() }

func (p *linuxPlatform) Firmware() ([]byte, []byte, error) { return readFwCfg(fwCfgRoot) }

func (p *linuxPlatform) Cmdline() (string, error) {
	raw, err := readBounded("/proc/cmdline", 4096)
	return string(raw), err
}

func (p *linuxPlatform) Entropy(b []byte) error { _, err := rand.Read(b); return err }

func (p *linuxPlatform) Report(data [64]byte) ([]byte, error) { return snp.Collect(data) }

func (p *linuxPlatform) DeriveKey(hostData [32]byte) (vmkey.Material, error) {
	return vmkey.Derive(hostData)
}

func (p *linuxPlatform) CryptsetupFloor() error {
	out, err := p.cryptsetup.Version(context.Background())
	if err != nil {
		return err
	}
	return vmdisk.CheckCryptsetupVersion(out)
}

func (p *linuxPlatform) Devices() (Devices, error) {
	var names map[string]string
	var err error
	for start := time.Now(); ; time.Sleep(100 * time.Millisecond) {
		if names, err = findDisks(sysBlock); err == nil || time.Since(start) > diskWait {
			break
		}
	}
	if err != nil {
		return Devices{}, err
	}
	var d Devices
	if d.Root, d.RootBytes, err = openDisk(names[serialRoot], os.O_RDWR); err != nil {
		return Devices{}, err
	}
	if d.Base, d.BaseBytes, err = openDisk(names[serialBase], os.O_RDONLY); err != nil {
		return Devices{}, err
	}
	if d.Mailbox, d.MailboxSize, err = openDisk(names[serialMailbox], os.O_RDWR); err != nil {
		return Devices{}, err
	}
	return d, nil
}

func (p *linuxPlatform) Disk(ctx context.Context, cfg vmdisk.Config) (vmdisk.Outcome, error) {
	cfg.Cryptsetup = p.cryptsetup
	return vmdisk.Run(ctx, cfg)
}

func (p *linuxPlatform) Root() Root       { return unwired{} }
func (p *linuxPlatform) Mailbox() Mailbox { return unwired{} }
func (p *linuxPlatform) Log(s string)     { fmt.Fprintln(os.Stderr, s) }

// unwired stands where vmroot and vmmailbox (PR C) go in the wiring commit.
// It refuses at the first call, so this build never touches a disk.
type unwired struct{}

var errUnwired = errors.New("the VM root setup (PR C) is not wired into this build")

func (unwired) CheckLink([]byte) error { return errUnwired }
func (unwired) FirstBoot(context.Context, *os.File, Base, vmidentity.Identity, func(string) error) ([32]byte, error) {
	return [32]byte{}, errUnwired
}
func (unwired) Start(context.Context, *os.File, []byte, func() error) error { return errUnwired }
func (unwired) WriteStatus(*os.File, int64, string, string, []byte) error   { return errUnwired }

func powerOff() {
	syscall.Sync()
	syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
	// PID1 must not exit: that panics the kernel.
	for {
		time.Sleep(time.Hour)
	}
}

func main() {
	// Only PID1 of the VM may power off: run anywhere else, it just exits.
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "vm-init: not PID1")
		os.Exit(1)
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "vm-init: panic; power off")
		}
		powerOff()
	}()
	err := boot(context.Background(), &linuxPlatform{})
	if err == nil {
		err = errors.New("the root returned")
	}
	fmt.Fprintln(os.Stderr, "vm-init: "+err.Error()+"; power off")
}
