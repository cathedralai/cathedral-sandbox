package vmdisk

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
)

// The root tests (T3 here, T5 in cut_linux_amd64_test.go) run on loop
// devices with the real kernel device-mapper and a real cryptsetup, as
// root, in .github/workflows/vm-init.yml. Every "boot" attaches a fresh
// loop device and every "power off" removes the mappings and detaches it,
// so no cache or mapping survives from one boot to the next.

const testDisk = 64 * MiB

type harness struct {
	t     *testing.T
	tool  Tool
	names Names
	dir   string
}

func rootHarness(t *testing.T) *harness {
	t.Helper()
	if os.Getenv("VMDISK_ROOT_TESTS") != "1" {
		t.Skip("root loop-device tests: set VMDISK_ROOT_TESTS=1 as root (vm-init.yml)")
	}
	if os.Geteuid() != 0 {
		t.Fatal("VMDISK_ROOT_TESTS needs root")
	}
	path := os.Getenv("VMDISK_CRYPTSETUP")
	if path == "" {
		path = "/usr/sbin/cryptsetup"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tag [3]byte
	rand.Read(tag[:])
	prefix := "cvmt" + hex.EncodeToString(tag[:])
	h := &harness{t: t, tool: Tool{Path: path, SHA256: sha256.Sum256(raw), Name: "cryptsetup"}, dir: t.TempDir(),
		names: Names{LUKS: prefix + "-luks", Probe: prefix + "-probe", Crypt: prefix + "-crypt", FS: prefix + "-fs"}}
	t.Cleanup(h.powerOff)
	return h
}

// key is one bundle's chip-derived key and measurement, as a test sees it.
type key struct {
	pass []byte
	meas [48]byte
}

func newKey(seed byte) key {
	k := key{pass: bytes.Repeat([]byte{seed}, 32)}
	k.meas[0], k.meas[47] = seed, 0x5a
	return k
}

func testID(t *testing.T, vmID string) vmidentity.Identity { return testIdentity(t, vmID) }

// disk is one sparse root.raw.
type disk struct {
	h    *harness
	path string
	loop string
}

func (h *harness) newDisk(size int64) *disk {
	p := filepath.Join(h.dir, "root-"+hex.EncodeToString([]byte(h.t.Name()))[:8]+"-"+randomHex(4)+".raw")
	f, err := os.Create(p)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		h.t.Fatal(err)
	}
	f.Close()
	return &disk{h: h, path: p}
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (d *disk) attach() *os.File {
	d.h.t.Helper()
	out, err := exec.Command("losetup", "--find", "--show", d.path).Output()
	if err != nil {
		d.h.t.Fatalf("losetup: %v", err)
	}
	d.loop = strings.TrimSpace(string(out))
	f, err := os.OpenFile(d.loop, os.O_RDWR, 0)
	if err != nil {
		d.h.t.Fatal(err)
	}
	return f
}

func (d *disk) detach() {
	if d.loop == "" {
		return
	}
	for i := 0; i < 50; i++ {
		if exec.Command("losetup", "--detach", d.loop).Run() == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	d.loop = ""
}

func (d *disk) sha() string {
	d.h.t.Helper()
	f, err := os.Open(d.path)
	if err != nil {
		d.h.t.Fatal(err)
	}
	defer f.Close()
	s := sha256.New()
	io.Copy(s, f)
	return hex.EncodeToString(s.Sum(nil))
}

func (d *disk) writeAt(off int64, data []byte) {
	d.h.t.Helper()
	f, err := os.OpenFile(d.path, os.O_RDWR, 0)
	if err != nil {
		d.h.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt(data, off); err != nil {
		d.h.t.Fatal(err)
	}
	f.Sync()
}

func (d *disk) readAt(off int64, n int) []byte {
	d.h.t.Helper()
	f, err := os.Open(d.path)
	if err != nil {
		d.h.t.Fatal(err)
	}
	defer f.Close()
	b := make([]byte, n)
	if _, err := f.ReadAt(b, off); err != nil {
		d.h.t.Fatal(err)
	}
	return b
}

func (d *disk) intentArea() []byte { return d.readAt(testDisk-IntentAreaBytes, IntentAreaBytes) }

// powerOff removes every mapping of this harness, as a reboot does.
func (h *harness) powerOff() {
	ctl, err := openDM()
	if err != nil {
		return
	}
	defer ctl.close()
	cs := cryptsetup{tool: h.tool}
	for _, name := range h.names.all() {
		if ok, _ := ctl.exists(name); ok {
			if name == h.names.Crypt || name == h.names.Probe {
				if cs.close(context.Background(), name) == nil {
					continue
				}
			}
			ctl.remove(name)
		}
	}
}

// fakeSetup stands in for vmroot (PR C): it writes markers over the file
// system area, makes R and writes it where the recovery key file would
// hold it, with the step 4.2 and 4.3 cut points between.
type fakeSetup struct{}

const fsMarker = "CVM-TEST-FS-MARKER"

func (fakeSetup) FirstBoot(_ context.Context, fs *os.File, cut func(string) error) ([32]byte, error) {
	var recovery [32]byte
	block := make([]byte, 4096)
	copy(block, fsMarker+" copy")
	if _, err := fs.WriteAt(block, 0); err != nil {
		return recovery, err
	}
	fs.Sync()
	cut("copy")
	copy(block, fsMarker+" grown")
	if _, err := fs.WriteAt(block, MiB); err != nil {
		return recovery, err
	}
	fs.Sync()
	cut("resize2fs")
	if _, err := rand.Read(recovery[:]); err != nil {
		return recovery, err
	}
	clear(block)
	copy(block, recovery[:])
	if _, err := fs.WriteAt(block, 2*MiB); err != nil {
		return recovery, err
	}
	fs.Sync()
	cut("recovery-file")
	return recovery, nil
}

// boot runs one boot of d in this process and powers off after it.
func (h *harness) boot(d *disk, id vmidentity.Identity, k key) (Outcome, error, []string) {
	h.t.Helper()
	return h.bootWith(d, id, k, h.tool, fakeSetup{})
}

func (h *harness) bootWith(d *disk, id vmidentity.Identity, k key, tool Tool, setup Setup) (Outcome, error, []string) {
	h.t.Helper()
	f := d.attach()
	defer func() { f.Close(); h.powerOff(); d.detach() }()
	var lines []string
	out, err := Run(context.Background(), Config{Disk: f, DiskBytes: testDisk, Identity: id, Passphrase: k.pass,
		Measurement: k.meas, Cryptsetup: tool, Names: h.names, Setup: setup,
		Log: func(s string) { lines = append(lines, s) }})
	if out.FSArea != nil {
		out.FSArea.Close()
	}
	return out, err, lines
}

// mustReady boots and requires a ready outcome of state want.
func (h *harness) mustReady(d *disk, id vmidentity.Identity, k key, want State) Outcome {
	h.t.Helper()
	out, err, lines := h.boot(d, id, k)
	if err != nil || !out.Ready || out.State != want {
		h.t.Fatalf("boot: state %s ready %v err %v\n%s", out.State, out.Ready, err, strings.Join(lines, "\n"))
	}
	return out
}

// mustRefuse boots and requires a non-ready state with the disk unchanged.
func (h *harness) mustRefuse(d *disk, id vmidentity.Identity, k key, want State) {
	h.t.Helper()
	before := d.sha()
	out, err, lines := h.boot(d, id, k)
	if err != nil || out.Ready || out.State != want {
		h.t.Fatalf("boot: state %s ready %v err %v, want %s\n%s", out.State, out.Ready, err, want, strings.Join(lines, "\n"))
	}
	if d.sha() != before {
		h.t.Fatalf("a %s disk changed", want)
	}
}

// report is what a finished disk holds, read with a key.
type report struct {
	keyslots []int
	meta     Current
	copies   [2]Meta // each meta copy as parsed
	valid    [2]bool // whether each copy parsed
	fs       []byte  // the first 3 MiB of the file system area
}

func (h *harness) inspect(d *disk, k key) report {
	h.t.Helper()
	f := d.attach()
	f.Close()
	defer func() { h.powerOff(); d.detach() }()
	ctl, err := openDM()
	if err != nil {
		h.t.Fatal(err)
	}
	defer ctl.close()
	st, err := os.Stat(d.loop)
	if err != nil {
		h.t.Fatal(err)
	}
	dev := st.Sys().(*syscall.Stat_t).Rdev
	luksDev, err := ctl.createLinear(h.names.LUKS, true, dev, 0, uint64((testDisk-IntentAreaBytes)/sectorBytes))
	if err != nil {
		h.t.Fatal(err)
	}
	luks, err := openMapped(luksDev, syscall.O_RDONLY)
	if err != nil {
		h.t.Fatal(err)
	}
	cs := cryptsetup{tool: h.tool, dev: luks.Name()}
	luks.Close()
	hdr, err := cs.header(context.Background())
	if err != nil || !hdr.RulesOK {
		h.t.Fatalf("header: %+v %v", hdr, err)
	}
	var rep report
	rep.keyslots = hdr.Keyslots
	if err := cs.open(context.Background(), k.pass, -1, h.names.Probe, true); err != nil {
		h.t.Fatal(err)
	}
	pdev, _, _ := ctl.devStatus(h.names.Probe)
	vol, err := openMapped(pdev, syscall.O_RDONLY|syscall.O_DIRECT)
	if err != nil {
		h.t.Fatal(err)
	}
	defer vol.Close()
	if rep.meta, err = readMeta(vol); err != nil {
		h.t.Fatal(err)
	}
	for i, off := range MetaOffsets() {
		rec, err := readDirect(vol, off, RecordBytes)
		if err != nil {
			h.t.Fatal(err)
		}
		rep.copies[i], rep.valid[i] = ParseMeta(rec)
	}
	if rep.fs, err = readDirect(vol, MetaAreaBytes, 3*MiB); err != nil {
		h.t.Fatal(err)
	}
	return rep
}

// opensSlot tests a passphrase on one slot of d.
func (h *harness) opensSlot(d *disk, pass []byte, slot int) bool {
	h.t.Helper()
	d.attach().Close()
	defer d.detach()
	cs := cryptsetup{tool: h.tool, dev: d.loop}
	// The loop device is the whole root.raw; cryptsetup reads only the header.
	ok, err := cs.opens(context.Background(), pass, slot)
	if err != nil {
		h.t.Fatal(err)
	}
	return ok
}

// checkReady is the T5 end state: ready, exactly one measurement slot for
// k and one recovery slot, both meta copies ready with that table, R opens
// its slot, and an all-zero intent area.
func (h *harness) checkReady(d *disk, id vmidentity.Identity, k key) report {
	h.t.Helper()
	rep := h.inspect(d, k)
	m := rep.meta
	if !m.Valid || m.Meta.State != StateReady || !m.Meta.Names(id) || len(m.Meta.Slots) != 2 || len(rep.keyslots) != 2 {
		h.t.Fatalf("not ready with two slots: %+v keyslots %v", m, rep.keyslots)
	}
	measured, recovery := -1, -1
	for slot, role := range m.Meta.Slots {
		switch role {
		case RoleRecovery:
			recovery = slot
		case MeasurementRole(k.meas):
			measured = slot
		}
	}
	if measured < 0 || recovery < 0 || !sameSlots(rep.keyslots, m.Meta.Slots) {
		h.t.Fatalf("table %v keyslots %v", m.Meta.Slots, rep.keyslots)
	}
	for i := range rep.copies {
		c := rep.copies[i]
		if !rep.valid[i] || c.State != StateReady || !c.Names(id) || !reflect.DeepEqual(c.Slots, m.Meta.Slots) {
			h.t.Fatalf("meta copy %d is not a ready copy of the table: valid %v %+v", i, rep.valid[i], c)
		}
	}
	if !h.opensSlot(d, k.pass, measured) || h.opensSlot(d, k.pass, recovery) {
		h.t.Fatal("the measurement slot does not open with the key, or the recovery slot does")
	}
	if !h.opensSlot(d, rep.fs[2*MiB:2*MiB+32], recovery) {
		h.t.Fatal("R from the recovery file does not open the recovery slot")
	}
	if !bytes.Equal(d.intentArea(), make([]byte, IntentAreaBytes)) {
		h.t.Fatal("the intent area is not zero")
	}
	if !bytes.HasPrefix(rep.fs, []byte(fsMarker+" copy")) {
		h.t.Fatal("the file system area lost the first-boot copy")
	}
	return rep
}

// helperConfig is what a subprocess boot (T5) gets.
type helperConfig struct {
	Disk        string `json:"disk"`
	Identity    string `json:"identity"`
	Pass        string `json:"pass"`
	Measurement string `json:"measurement"`
	Tool        string `json:"tool"`
	Names       Names  `json:"names"`
	Journal     string `json:"journal"`
}

func (h *harness) helperConfig(d *disk, id vmidentity.Identity, k key) string {
	cfg := helperConfig{Disk: d.loop, Identity: string(id.Raw), Pass: hex.EncodeToString(k.pass),
		Measurement: hex.EncodeToString(k.meas[:]), Tool: h.tool.Path, Names: h.names,
		Journal: filepath.Join(h.dir, "journal")}
	raw, _ := json.Marshal(cfg)
	p := filepath.Join(h.dir, "helper-"+randomHex(4)+".json")
	if err := os.WriteFile(p, raw, 0600); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *harness) journal() string {
	raw, _ := os.ReadFile(filepath.Join(h.dir, "journal"))
	return string(raw)
}
