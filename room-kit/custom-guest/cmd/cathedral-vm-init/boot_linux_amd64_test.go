package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/snp"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmdisk"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmkey"
)

const ovmf = "initrd=initrd "

func identityDoc(vmID string) []byte {
	return []byte(`{"base_root_data_bytes":8192,"base_root_verity":"1111111111111111111111111111111111111111111111111111111111111111",` +
		`"salt_hex":"000102030405060708090a0b0c0d0e0f","schema":"cathedral.vm.identity/v1",` +
		`"ssh_public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/","version":1,"vm_id":"` + vmID + `"}`)
}

func cmdlineFor(t *testing.T, doc []byte) string {
	t.Helper()
	id, err := vmidentity.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	line, err := vmidentity.Cmdline(id.SHA256Hex())
	if err != nil {
		t.Fatal(err)
	}
	return ovmf + line + "\n"
}

// fakeReport is an SNP report CheckLocal accepts for data and hostData.
func fakeReport(data [64]byte, hostData [32]byte, measurement [48]byte) []byte {
	r := make([]byte, snp.ReportBytes)
	binary.LittleEndian.PutUint32(r[0:4], 3)
	binary.LittleEndian.PutUint64(r[8:16], 0x30000)
	copy(r[0x50:0x90], data[:])
	copy(r[0x90:0xc0], measurement[:])
	copy(r[0xc0:0xe0], hostData[:])
	return r
}

type fake struct {
	t        *testing.T
	calls    []string
	identity []byte
	link     []byte
	cmdline  string
	// hostData is what the chip reports; it equals the identity's unless a test changes it.
	hostData    *[32]byte
	reportData  func([64]byte) [64]byte
	measurement [48]byte
	key         vmkey.Material
	floorErr    error
	linkErr     error
	outcome     vmdisk.Outcome
	diskErr     error
	gotConfig   vmdisk.Config
	status      []string
	startErr    error
	statusErr   error
}

func newFake(t *testing.T) *fake {
	doc := identityDoc("vm-0123456789ab")
	f := &fake{t: t, identity: doc, link: []byte("10.0.0.1 10.0.0.2"), cmdline: cmdlineFor(t, doc),
		key: vmkey.Material{KeyID: "0123456789abcdef"}}
	for i := range f.key.Passphrase {
		f.key.Passphrase[i] = byte(i + 1)
	}
	f.measurement[0], f.measurement[47] = 0xaa, 0xbb
	f.outcome = vmdisk.Outcome{State: vmdisk.StateNew, Ready: true, Meta: vmdisk.Meta{State: vmdisk.StateReady},
		FSArea: os.NewFile(0, "fs-area")}
	return f
}

func (f *fake) call(s string) { f.calls = append(f.calls, s) }

func (f *fake) LoadModules() error   { f.call("modules"); return nil }
func (f *fake) PrepareKernel() error { f.call("kernel"); return nil }
func (f *fake) Firmware() ([]byte, []byte, error) {
	f.call("fw_cfg")
	return f.identity, f.link, nil
}
func (f *fake) Cmdline() (string, error) { f.call("cmdline"); return f.cmdline, nil }
func (f *fake) Entropy(b []byte) error {
	f.call("entropy")
	for i := range b {
		b[i] = 0x42
	}
	return nil
}
func (f *fake) Report(data [64]byte) ([]byte, error) {
	if data == ([64]byte{}) {
		f.call("report-zero")
	} else {
		f.call("report-boot")
	}
	id, err := vmidentity.Parse(f.identity)
	hostData := [32]byte{}
	if err == nil {
		hostData = id.HostData()
	}
	if f.hostData != nil {
		hostData = *f.hostData
	}
	if f.reportData != nil {
		data = f.reportData(data)
	}
	return fakeReport(data, hostData, f.measurement), nil
}
func (f *fake) DeriveKey(hostData [32]byte) (vmkey.Material, error) {
	f.call("derive")
	return f.key, nil
}
func (f *fake) CryptsetupFloor() error { f.call("floor"); return f.floorErr }
func (f *fake) Devices() (Devices, error) {
	f.call("devices")
	return Devices{Root: os.NewFile(0, "root"), RootBytes: 64 << 20, Base: os.NewFile(0, "base"), BaseBytes: 1 << 20,
		Mailbox: os.NewFile(0, "mailbox"), MailboxSize: 1 << 20}, nil
}
func (f *fake) Disk(_ context.Context, cfg vmdisk.Config) (vmdisk.Outcome, error) {
	f.call("disk")
	f.gotConfig = cfg
	// What the disk saw, before boot clears the key.
	f.calls = append(f.calls, "key:"+string(rune('0'+cfg.Passphrase[0])))
	return f.outcome, f.diskErr
}
func (f *fake) Root() Root       { return fakeRoot{f} }
func (f *fake) Mailbox() Mailbox { return fakeRoot{f} }
func (f *fake) Log(string)       {}

type fakeRoot struct{ f *fake }

func (r fakeRoot) CheckLink(raw []byte) error { r.f.call("link"); return r.f.linkErr }
func (r fakeRoot) FirstBoot(context.Context, *os.File, Base, vmidentity.Identity, func(string) error) ([32]byte, error) {
	r.f.call("firstboot")
	return [32]byte{1}, nil
}
func (r fakeRoot) Start(_ context.Context, fs *os.File, link []byte, ready func() error) error {
	r.f.call("start")
	if r.f.startErr != nil {
		return r.f.startErr
	}
	if err := ready(); err != nil {
		return err
	}
	r.f.call("switch_root")
	return errors.New("switch_root returned (fake)")
}
func (r fakeRoot) WriteStatus(_ *os.File, size int64, state, keyID string, report []byte) error {
	r.f.call("status:" + state)
	if size != 1<<20 || keyID != r.f.key.KeyID || !bytes.Equal(report[0x50:0x90], make([]byte, 64)) {
		r.f.t.Errorf("status record: size %d key %q", size, keyID)
	}
	return r.f.statusErr
}

func (f *fake) disked() bool {
	return slices.ContainsFunc(f.calls, func(s string) bool { return s == "devices" || s == "disk" || s == "derive" })
}

func TestBootReadyOrder(t *testing.T) {
	f := newFake(t)
	err := boot(context.Background(), f)
	if err == nil || !strings.Contains(err.Error(), "switch_root returned (fake)") {
		t.Fatalf("boot: %v", err)
	}
	want := []string{"modules", "kernel", "fw_cfg", "cmdline", "link", "entropy", "report-boot", "derive", "floor",
		"devices", "disk", "key:" + string(rune('0'+1)), "report-zero", "start", "status:new", "switch_root"}
	if !slices.Equal(f.calls, want) {
		t.Fatalf("calls\n got %v\nwant %v", f.calls, want)
	}
	cfg := f.gotConfig
	id, _ := vmidentity.Parse(f.identity)
	if cfg.Measurement != f.measurement || cfg.Identity.SHA256Hex() != id.SHA256Hex() || cfg.DiskBytes != 64<<20 ||
		cfg.Names != vmdisk.DefaultNames || cfg.Setup == nil {
		t.Fatalf("disk config %+v", cfg)
	}
	if !bytes.Equal(cfg.Passphrase, make([]byte, 32)) {
		t.Fatal("the passphrase was not cleared after the disk")
	}
	setup := cfg.Setup.(rootSetup)
	if setup.base.DataBytes != 8192 || setup.base.RootHash != strings.Repeat("1", 64) || setup.base.DiskBytes != 1<<20 {
		t.Fatalf("base %+v", setup.base)
	}
}

func TestBootRefusesBeforeAnyDisk(t *testing.T) {
	other := identityDoc("vm-ba9876543210")
	cases := map[string]func(f *fake){
		"identity is not the cmdline's": func(f *fake) { f.identity = other },
		"cmdline is not v1":             func(f *fake) { f.cmdline = strings.Replace(f.cmdline, "console=", "consolf=", 1) },
		"cmdline has an extra word":     func(f *fake) { f.cmdline = strings.TrimSuffix(f.cmdline, "\n") + " init=/bin/sh\n" },
		"HOST_DATA is not the identity's": func(f *fake) {
			id, _ := vmidentity.Parse(other)
			h := id.HostData()
			f.hostData = &h
		},
		"REPORT_DATA is not this boot's": func(f *fake) { f.reportData = func(d [64]byte) [64]byte { d[0] ^= 1; return d } },
		"link refused":                   func(f *fake) { f.linkErr = errors.New("bad link") },
		"identity unparsable":            func(f *fake) { f.identity = append([]byte(" "), f.identity...) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			mutate(f)
			if err := boot(context.Background(), f); err == nil {
				t.Fatal("boot went on")
			}
			if f.disked() {
				t.Fatalf("a key or disk step ran: %v", f.calls)
			}
		})
	}
}

func TestBootFloorBeforeDevices(t *testing.T) {
	f := newFake(t)
	f.floorErr = errors.New("cryptsetup 2.7.0")
	if err := boot(context.Background(), f); err == nil || slices.Contains(f.calls, "devices") {
		t.Fatalf("devices opened under an old cryptsetup: %v %v", err, f.calls)
	}
}

func TestBootNotReadyWritesStatusAndStops(t *testing.T) {
	for _, st := range []vmdisk.State{vmdisk.StateLocked, vmdisk.StateTampered, vmdisk.StateBroken} {
		t.Run(st.String(), func(t *testing.T) {
			f := newFake(t)
			f.outcome = vmdisk.Outcome{State: st, Why: "test"}
			err := boot(context.Background(), f)
			if err == nil || !strings.Contains(err.Error(), st.String()) {
				t.Fatalf("boot: %v", err)
			}
			if slices.Contains(f.calls, "start") || f.calls[len(f.calls)-1] != "status:"+st.String() {
				t.Fatalf("calls %v", f.calls)
			}
		})
	}
}

func TestBootNeverStartsWithoutReadyMeta(t *testing.T) {
	cases := map[string]func(f *fake){
		"meta initializing": func(f *fake) { f.outcome.Meta.State = vmdisk.StateInitializing },
		"no fs area":        func(f *fake) { f.outcome.FSArea = nil },
		"disk error":        func(f *fake) { f.diskErr = errors.New("cryptsetup failed") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			mutate(f)
			if err := boot(context.Background(), f); err == nil || slices.Contains(f.calls, "start") {
				t.Fatalf("root started: %v %v", err, f.calls)
			}
			if !bytes.Equal(f.gotConfig.Passphrase, make([]byte, 32)) {
				t.Fatal("the passphrase was not cleared")
			}
		})
	}
}

func TestBootStatusFailureStopsSwitchRoot(t *testing.T) {
	f := newFake(t)
	f.statusErr = errors.New("mailbox write failed")
	if err := boot(context.Background(), f); err == nil || slices.Contains(f.calls, "switch_root") {
		t.Fatalf("switch_root without a status record: %v %v", err, f.calls)
	}
}

func TestBootResumeReportsNew(t *testing.T) {
	f := newFake(t)
	f.outcome.State = vmdisk.StateResume
	boot(context.Background(), f)
	if !slices.Contains(f.calls, "status:new") {
		t.Fatalf("resume status %v", f.calls)
	}
}
