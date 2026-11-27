package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const release = "6.8.0-90-generic"

func goodManifest() string {
	return `{"boot_modules":["sev-guest","dm-crypt"],"executables":{"init":"` + strings.Repeat("a", 64) +
		`","usr/lib/cathedral/cryptsetup":"` + strings.Repeat("b", 64) + `"},"kernel_release":"` + release +
		`","schema":"cathedral.vm.initrd-manifest/v1"}`
}

func TestManifest(t *testing.T) {
	m, err := parseManifest([]byte(goodManifest()))
	if err != nil {
		t.Fatal(err)
	}
	tool, err := m.tool(cryptsetupName, "cryptsetup")
	if err != nil || tool.Path != "/usr/lib/cathedral/cryptsetup" || tool.SHA256[0] != 0xbb || tool.Name != "cryptsetup" {
		t.Fatalf("tool %+v %v", tool, err)
	}
	for name, edit := range map[string]func(string) string{
		"unknown field":   func(s string) string { return strings.Replace(s, `{"boot_modules"`, `{"extra":1,"boot_modules"`, 1) },
		"other schema":    func(s string) string { return strings.Replace(s, "manifest/v1", "manifest/v2", 1) },
		"bad release":     func(s string) string { return strings.Replace(s, release, "6.8.0", 1) },
		"no modules":      func(s string) string { return strings.Replace(s, `["sev-guest","dm-crypt"]`, `[]`, 1) },
		"short pin":       func(s string) string { return strings.Replace(s, strings.Repeat("b", 64), strings.Repeat("b", 63), 1) },
		"upper-case pin":  func(s string) string { return strings.Replace(s, strings.Repeat("b", 64), strings.Repeat("B", 64), 1) },
		"no cryptsetup":   func(s string) string { return strings.Replace(s, "lib/cathedral/cryptsetup", "lib/cathedral/other", 1) },
		"trailing record": func(s string) string { return s + "{}" },
	} {
		if _, err := parseManifest([]byte(edit(goodManifest()))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestModuleList(t *testing.T) {
	p := "usr/lib/modules/" + release + "/"
	good := p + "kernel/drivers/virt/coco/sev-guest/sev-guest.ko.zst\n" + p + "kernel/drivers/md/dm-crypt.ko\n"
	list, err := parseModules([]byte(good), release)
	if err != nil || len(list) != 2 || list[1] != p+"kernel/drivers/md/dm-crypt.ko" {
		t.Fatalf("%v %v", list, err)
	}
	for name, raw := range map[string]string{
		"empty":            "",
		"no final newline": strings.TrimSuffix(good, "\n"),
		"other release":    strings.Replace(good, release, "6.8.0-91-generic", 1),
		"dot dot":          p + "kernel/../../../../bin/sh.ko\n",
		"absolute":         "/" + good,
		"not a module":     p + "kernel/drivers/md/dm-crypt.so\n",
		"blank line":       good + "\n",
		"duplicate":        good + p + "kernel/drivers/md/dm-crypt.ko\n",
		"double slash":     p + "kernel//dm-crypt.ko\n",
	} {
		if _, err := parseModules([]byte(raw), release); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func writeEntry(t *testing.T, dir, name string, raw []byte, size int) {
	t.Helper()
	d := filepath.Join(dir, fwCfgDir, name)
	if err := os.MkdirAll(d, 0700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(d, "raw"), raw, 0600)
	os.WriteFile(filepath.Join(d, "size"), []byte(strconv.Itoa(size)+"\n"), 0600)
}

func TestFwCfg(t *testing.T) {
	doc := identityDoc("vm-0123456789ab")
	link := []byte("10.0.0.1 10.0.0.2")
	setup := func(t *testing.T) string {
		dir := t.TempDir()
		writeEntry(t, dir, identityName, doc, len(doc))
		writeEntry(t, dir, linkName, link, len(link))
		return dir
	}
	id, l, err := readFwCfg(setup(t))
	if err != nil || string(id) != string(doc) || string(l) != string(link) {
		t.Fatalf("%q %q %v", id, l, err)
	}
	for name, edit := range map[string]func(t *testing.T, dir string){
		"a third name":   func(t *testing.T, dir string) { writeEntry(t, dir, "extra", []byte("x"), 1) },
		"no link":        func(t *testing.T, dir string) { os.RemoveAll(filepath.Join(dir, fwCfgDir, linkName)) },
		"size mismatch":  func(t *testing.T, dir string) { writeEntry(t, dir, linkName, link, len(link)+1) },
		"oversized link": func(t *testing.T, dir string) { writeEntry(t, dir, linkName, make([]byte, 65), 65) },
		"oversized identity": func(t *testing.T, dir string) {
			writeEntry(t, dir, identityName, make([]byte, 16385), 16385)
		},
		"empty identity": func(t *testing.T, dir string) { writeEntry(t, dir, identityName, nil, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := setup(t)
			edit(t, dir)
			if _, _, err := readFwCfg(dir); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestFindDisks(t *testing.T) {
	setup := func(t *testing.T, disks map[string]string) string {
		dir := t.TempDir()
		for name, serial := range disks {
			os.MkdirAll(filepath.Join(dir, name), 0700)
			os.WriteFile(filepath.Join(dir, name, "serial"), []byte(serial+"\n"), 0600)
		}
		os.MkdirAll(filepath.Join(dir, "loop0"), 0700)
		return dir
	}
	good := map[string]string{"vda": serialRoot, "vdb": serialBase, "vdc": serialMailbox}
	got, err := findDisks(setup(t, good))
	if err != nil || got[serialRoot] != "vda" || got[serialBase] != "vdb" || got[serialMailbox] != "vdc" {
		t.Fatalf("%v %v", got, err)
	}
	for name, disks := range map[string]map[string]string{
		"duplicate serial": {"vda": serialRoot, "vdb": serialRoot, "vdc": serialMailbox},
		"missing mailbox":  {"vda": serialRoot, "vdb": serialBase},
		"a fourth disk":    {"vda": serialRoot, "vdb": serialBase, "vdc": serialMailbox, "vdd": "other"},
		"renamed root":     {"vda": "virtio-vm-root", "vdb": serialBase, "vdc": serialMailbox},
	} {
		if _, err := findDisks(setup(t, disks)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
