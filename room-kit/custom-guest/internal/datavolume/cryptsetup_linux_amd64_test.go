package datavolume

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testSecret = "correct horse battery staple 7f3a"

// recording builds an adapter whose helper calls are recorded, not run.
type recording struct {
	calls []command
	reply func(command) (result, error)
}

func (r *recording) tools(t *testing.T) *tools {
	t.Helper()
	root := t.TempDir()
	mapper := filepath.Join(root, "mapper")
	if err := os.Mkdir(mapper, 0700); err != nil {
		t.Fatal(err)
	}
	return &tools{helperPath: "unused", mke2fs: "unused", mapperDir: mapper, sys: filepath.Join(root, "sys"),
		mountinfo: filepath.Join(root, "mountinfo"), mountTarget: filepath.Join(root, "mnt"), scratch: root,
		exec: func(_ context.Context, c command) (result, error) {
			r.calls = append(r.calls, c)
			if r.reply != nil {
				return r.reply(c)
			}
			return result{}, nil
		}}
}

// fileDisk is a regular file standing in for the held descriptor. ReadAt and
// the adapter's offsets behave the same; no device is touched.
func fileDisk(t *testing.T, size int64, tl *tools) *HeldDevice {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "disk")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return &HeldDevice{file: f, size: size, dev: "7:0", tools: tl}
}

func poke(t *testing.T, d *HeldDevice, off int64, b []byte) {
	t.Helper()
	if _, err := d.file.WriteAt(b, off); err != nil {
		t.Fatal(err)
	}
}

func TestPassphraseOnlyOnStdin(t *testing.T) {
	r := &recording{}
	d := fileDisk(t, 1<<30, r.tools(t))
	if err := d.Format(context.Background(), []byte(testSecret)); err != nil {
		t.Fatal(err)
	}
	format := r.calls[0]
	// Header's backup and dump carry no secret; only Format and Open are checked.
	r.reply = func(command) (result, error) { return result{stdout: []byte("{}")}, nil }
	checked(t, d)
	r.calls = []command{format}
	m, err := d.Open(context.Background(), []byte(testSecret))
	if err != nil || m == nil {
		t.Fatal(err)
	}
	if len(r.calls) != 2 {
		t.Fatalf("%d helper calls", len(r.calls))
	}
	for _, c := range r.calls {
		if string(c.stdin) != testSecret {
			t.Fatal("passphrase did not travel on stdin")
		}
		if strings.Contains(c.program+strings.Join(c.args, "\x00"), testSecret) {
			t.Fatal("passphrase in argv")
		}
		if !strings.Contains(strings.Join(c.args, " "), "--key-file=-") {
			t.Fatal("helper not told to read the key from stdin")
		}
	}
	// The format layout is what CheckHeaderPolicy accepts.
	got := strings.Join(r.calls[0].args, " ")
	for _, want := range []string{"luksFormat", "--type luks2", "--cipher aes-xts-plain64", "--sector-size 4096",
		"--integrity hmac-sha256", "--key-size 512", diskFD} {
		if !strings.Contains(got, want) {
			t.Fatalf("format args lack %q: %s", want, got)
		}
	}
}

// The real exec path: empty environment, stdin delivery, and no stderr in
// errors even when the helper echoes the secret there.
func TestExecuteDoesNotLeakSecret(t *testing.T) {
	tl := productionTools([32]byte{1})
	res, err := tl.execute(context.Background(), command{program: "/usr/bin/env"})
	if err != nil || len(bytes.TrimSpace(res.stdout)) != 0 {
		t.Fatalf("environment not empty: %q %v", res.stdout, err)
	}
	res, err = tl.execute(context.Background(), command{program: "/bin/sh", stdin: []byte(testSecret),
		args: []string{"-c", "cat >&2; exit 3"}})
	if err == nil {
		t.Fatal("exit 3 reported as success")
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Fatal("secret in error text")
	}
	if !strings.Contains(string(res.stderr), testSecret) {
		t.Fatal("test helper did not echo to stderr; the check above proved nothing")
	}
}

func TestExecuteBoundsOutput(t *testing.T) {
	tl := productionTools([32]byte{1})
	_, err := tl.execute(context.Background(), command{program: "/bin/sh",
		args: []string{"-c", "head -c 2000000 /dev/zero"}})
	if err == nil {
		t.Fatal("2 MB of helper output accepted")
	}
}

func TestPinnedHelperRefusals(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "helper")
	if err := os.WriteFile(good, []byte("\x7fELF----"), 0755); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		// Root-owned in CI: digest mismatch must refuse, empty pin must refuse.
		if f, err := openPinnedHelper(good, [32]byte{9}); err == nil {
			f.Close()
			t.Fatal("wrong digest accepted")
		}
	}
	if f, err := openPinnedHelper(good, [32]byte{}); err == nil {
		f.Close()
		t.Fatal("empty pin accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openPinnedHelper(link, [32]byte{9}); err == nil {
		f.Close()
		t.Fatal("symlink accepted")
	}
}

func TestHeaderProbe(t *testing.T) {
	json := []byte(`{"keyslots":{}}`)
	r := &recording{reply: func(command) (result, error) { return result{stdout: json}, nil }}
	for name, tc := range map[string]struct {
		off   int64
		magic string
		luks  bool
	}{
		"blank":             {0, "", false},
		"primary":           {0, "LUKS\xba\xbe", true},
		"secondary at 16K":  {0x4000, "SKUL\xba\xbe", true},
		"secondary at 4M":   {0x400000, "SKUL\xba\xbe", true},
		"primary magic bad": {0, "LUKS\xba\xbf", false},
		"secondary wrong":   {0x4000, "LUKS\xba\xbe", false},
	} {
		t.Run(name, func(t *testing.T) {
			r.calls = nil
			d := fileDisk(t, 64<<20, r.tools(t))
			if tc.magic != "" {
				poke(t, d, tc.off, []byte(tc.magic))
			}
			got, err := d.Header(context.Background())
			if !tc.luks {
				if !errors.Is(err, ErrNotLUKS) || len(r.calls) != 0 {
					t.Fatalf("err=%v calls=%d", err, len(r.calls))
				}
				return
			}
			// One backup of the header off the disk, then the dump reads that copy.
			if err != nil || !bytes.Equal(got, json) || len(r.calls) != 2 {
				t.Fatalf("err=%v calls=%d", err, len(r.calls))
			}
			backup, dump := r.calls[0].args, r.calls[1].args
			if strings.Join(backup[:2], " ") != "luksHeaderBackup "+diskFD || backup[2] != "--header-backup-file" ||
				strings.Join(dump, " ") != "luksDump --dump-json-metadata "+backup[3] || d.header != backup[3] {
				t.Fatalf("backup=%v dump=%v", backup, dump)
			}
		})
	}
}

// A helper failure on a disk that does carry LUKS magic must not look blank,
// or Unlock would scan and could format over a damaged volume.
func TestHeaderFailureIsNeverNotLUKS(t *testing.T) {
	r := &recording{reply: func(command) (result, error) { return result{}, errors.New("exit status 1") }}
	d := fileDisk(t, 64<<20, r.tools(t))
	poke(t, d, 0, []byte("LUKS\xba\xbe"))
	if _, err := d.Header(context.Background()); err == nil || errors.Is(err, ErrNotLUKS) {
		t.Fatalf("err=%v", err)
	}
	// An unreadable probe is also not blank.
	d = fileDisk(t, 64<<20, r.tools(t))
	d.file.Close()
	if _, err := d.Header(context.Background()); err == nil || errors.Is(err, ErrNotLUKS) {
		t.Fatalf("closed disk: err=%v", err)
	}
}

// checked runs Header on a disk with LUKS magic, so it holds a header snapshot.
func checked(t *testing.T, d *HeldDevice) {
	t.Helper()
	poke(t, d, 0, []byte("LUKS\xba\xbe"))
	if _, err := d.Header(context.Background()); err != nil || d.header == "" {
		t.Fatalf("header snapshot: %v", err)
	}
}

// Open unlocks with the snapshot Header checked, never a fresh read of the disk:
// without one it refuses, and with one it passes exactly that file as --header.
func TestOpenUsesOnlyTheCheckedHeader(t *testing.T) {
	r := &recording{reply: func(command) (result, error) { return result{stdout: []byte("{}")}, nil }}
	d := fileDisk(t, 1<<30, r.tools(t))
	if m, err := d.Open(context.Background(), []byte(testSecret)); err == nil || m != nil || len(r.calls) != 0 {
		t.Fatalf("opened without a checked header: %v %v %d", m, err, len(r.calls))
	}
	checked(t, d)
	snapshot := d.header
	r.calls = nil
	m, err := d.Open(context.Background(), []byte(testSecret))
	if err != nil || m == nil || len(r.calls) != 1 {
		t.Fatalf("%v %v %d", m, err, len(r.calls))
	}
	want := "open --type luks2 --header " + snapshot + " --batch-mode --key-file=- " + diskFD + " " + mapperName
	if got := strings.Join(r.calls[0].args, " "); got != want {
		t.Fatalf("open args %q", got)
	}
	if m.(*mapping).header != snapshot {
		t.Fatal("mapping does not carry the snapshot for status")
	}
	// A later Header that finds no LUKS leaves nothing to open with.
	poke(t, d, 0, make([]byte, 6))
	if _, err := d.Header(context.Background()); !errors.Is(err, ErrNotLUKS) || d.header != "" {
		t.Fatalf("stale snapshot kept: %v %q", err, d.header)
	}
	dir := d.headerDir
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot directory left behind: %v", err)
	}
}

func TestOpenRefusesExistingMapping(t *testing.T) {
	for _, name := range []string{mapperName, mapperName + "_dif"} {
		r := &recording{reply: func(command) (result, error) { return result{stdout: []byte("{}")}, nil }}
		tl := r.tools(t)
		d := fileDisk(t, 1<<30, tl)
		checked(t, d)
		r.calls = nil
		if err := os.WriteFile(filepath.Join(tl.mapperDir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if m, err := d.Open(context.Background(), []byte(testSecret)); err == nil || m != nil || len(r.calls) != 0 {
			t.Fatalf("%s: adopted or ran helper: %v %v %d", name, m, err, len(r.calls))
		}
	}
}

func TestOpenFailureReturnsPartialMappingOnlyIfNodeExists(t *testing.T) {
	var tl *tools
	r := &recording{reply: func(command) (result, error) { return result{stdout: []byte("{}")}, nil }}
	tl = r.tools(t)
	d := fileDisk(t, 1<<30, tl)
	checked(t, d)
	r.reply = func(command) (result, error) {
		return result{}, errors.New("exit status 2")
	}
	if m, err := d.Open(context.Background(), []byte(testSecret)); err == nil || m != nil {
		t.Fatalf("clean failure returned a mapping: %v %v", m, err)
	}
	r.reply = func(command) (result, error) {
		_ = os.WriteFile(filepath.Join(tl.mapperDir, mapperName+"_dif"), nil, 0600)
		return result{}, errors.New("exit status 2")
	}
	if m, err := d.Open(context.Background(), []byte(testSecret)); err == nil || m == nil {
		t.Fatalf("partial mapping not handed back for cleanup: %v %v", m, err)
	}
}

func TestAdapterRefusesUninitialized(t *testing.T) {
	var d HeldDevice
	if _, err := d.Header(context.Background()); err == nil {
		t.Fatal("zero device produced a header")
	}
	if d.Format(context.Background(), []byte("x")) == nil {
		t.Fatal("zero device formatted")
	}
	if _, err := d.Open(context.Background(), []byte("x")); err == nil {
		t.Fatal("zero device opened")
	}
}

func TestOpenDataRequiresPin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("OpenData checks root first")
	}
	if _, err := OpenData(1, [32]byte{}); err == nil {
		t.Fatal("empty cryptsetup pin accepted")
	}
}

func TestFilesystemAndMountParsing(t *testing.T) {
	dir := t.TempDir()
	info := filepath.Join(dir, "mountinfo")
	put(t, info, "36 1 8:1 / / rw - ext4 /dev/x rw\n"+
		"40 36 254:0 / /mnt/cathedral-data rw,nosuid,nodev,noexec - ext4 /dev/mapper/cathedral-data rw\n"+
		"41 36 0:5 / /mnt/other rw - tmpfs tmpfs rw\n")
	got, err := mounts(info, "/mnt/cathedral-data")
	if err != nil || len(got) != 1 || got[0].dev != "254:0" || got[0].fstype != "ext4" ||
		got[0].options != "rw,nosuid,nodev,noexec" {
		t.Fatalf("%+v %v", got, err)
	}
	if got, err := mounts(info, "/mnt/none"); err != nil || len(got) != 0 {
		t.Fatalf("%+v %v", got, err)
	}
	put(t, info, "garbage\n")
	if _, err := mounts(info, "/x"); err == nil {
		t.Fatal("garbage inventory accepted")
	}
	f := parseStatus([]byte("/dev/mapper/x is active.\n  type:    LUKS2\n  cipher:  aes-xts-plain64\n  sector size:  4096\n"))
	if f["type"] != "LUKS2" || f["sector size"] != "4096" {
		t.Fatalf("%v", f)
	}
	dup := parseStatus([]byte("type: LUKS2\ntype: PLAIN\n"))
	if dup["type"] == "LUKS2" || dup["type"] == "PLAIN" {
		t.Fatal("duplicate status key not poisoned")
	}
}

// status2_8_4 is `cryptsetup status` from the pinned helper (2.8.4) over this
// adapter's own mapping on a loop device.
const status2_8_4 = `/dev/mapper/cathedral-data is active.
  type:    LUKS2
  cipher:  aes-xts-plain64
  keysize: 768 [bits]
  key location: keyring
  integrity: hmac(sha256)
  integrity keysize: 256 [bits]
  integrity tag size: 32 [bytes]
  device:  /dev/loop0
  loop:    /tmp/disk.img
  sector size:  4096 [bytes]
  offset:  0 [512-byte units] (0 [bytes])
  size:    225728 [512-byte units] (115572736 [bytes])
  mode:    read/write
`

func TestStatusPolicy(t *testing.T) {
	if err := statusPolicy([]byte(status2_8_4)); err != nil {
		t.Fatalf("pinned helper's own status refused: %v", err)
	}
	refuse := map[string][2]string{
		"2.7 keysize format": {"keysize: 768 [bits]", "keysize: 768 bits"},
		"2.7 sector format":  {"sector size:  4096 [bytes]", "sector size:  4096"},
		"xts-256":            {"keysize: 768 [bits]", "keysize: 512 [bits]"},
		"no integrity key":   {"  integrity keysize: 256 [bits]\n", ""},
		"512-byte sectors":   {"4096 [bytes]\n  offset", "512 [bytes]\n  offset"},
		"cbc":                {"aes-xts-plain64", "aes-cbc-essiv:sha256"},
		"hmac-sha1":          {"integrity: hmac(sha256)", "integrity: hmac(sha1)"},
		"readonly":           {"read/write", "readonly"},
		"suspended":          {"read/write", "read/write (suspended)"},
		"discards":           {"mode:    read/write\n", "mode:    read/write\n  flags:   discards \n"},
		"duplicate cipher":   {"  key location", "  cipher:  aes-xts-plain64\n  key location"},
	}
	for name, edit := range refuse {
		if !strings.Contains(status2_8_4, edit[0]) {
			t.Fatalf("%s: fixture lacks %q", name, edit[0])
		}
		if err := statusPolicy([]byte(strings.Replace(status2_8_4, edit[0], edit[1], 1))); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// udev makes /dev/mapper/<name> a link to ../dm-N. Only that form is followed.
func TestMapperNodeFollowsOnlyUdevLink(t *testing.T) {
	tl := (&recording{}).tools(t)
	m := &mapping{tools: tl}
	link := filepath.Join(tl.mapperDir, mapperName)
	if _, err := m.node(); err == nil {
		t.Fatal("missing node resolved")
	}
	if err := os.WriteFile(link, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := m.node(); err != nil || got != link {
		t.Fatalf("plain node: %q %v", got, err)
	}
	for target, ok := range map[string]bool{
		"../dm-3": true, "../dm-12": true, "dm-3": false, "/dev/dm-3": false, "../sda": false,
		"../../dm-3": false, "../dm-3/x": false, "../dm-": false, "../loop0": false,
	} {
		os.Remove(link)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		got, err := m.node()
		if ok && (err != nil || got != filepath.Join(filepath.Dir(tl.mapperDir), target[3:])) {
			t.Fatalf("%s: %q %v", target, got, err)
		}
		if !ok && err == nil {
			t.Fatalf("%s followed to %q", target, got)
		}
	}
}
