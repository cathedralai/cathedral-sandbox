package bootstate

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func executable(t *testing.T, root, name string, body []byte) {
	t.Helper()
	put(t, root, name, string(body))
	if err := os.Chmod(filepath.Join(root, name), 0755); err != nil {
		t.Fatal(err)
	}
}
func link(t *testing.T, root, name, target string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}
func away(t *testing.T, root, name string) {
	t.Helper()
	if err := os.Rename(filepath.Join(root, name), filepath.Join(root, "away")); err != nil {
		t.Fatal(err)
	}
}
func rootFixture(t *testing.T) (string, [32]byte) {
	t.Helper()
	root := t.TempDir()
	helper := []byte("\x7fELFsynthetic test helper")
	executable(t, root, "usr/bin/cathedral-attest", helper)
	executable(t, root, "usr/lib/systemd/systemd", []byte("\x7fELFsynthetic init"))
	executable(t, root, "usr/sbin/sshd", []byte("\x7fELFsynthetic sshd"))
	link(t, root, "sbin", "usr/sbin")
	link(t, root, "lib", "usr/lib")
	link(t, root, "usr/sbin/init", "/lib/systemd/systemd")
	return root, sha256.Sum256(helper)
}
func TestRootGuestAbsoluteSymlinks(t *testing.T) {
	root, pin := rootFixture(t)
	got, err := CheckRoot(root, pin)
	if err != nil {
		t.Fatal(err)
	}
	if got.HelperSHA256 != pin || got.InitSHA256 != sha256.Sum256([]byte("\x7fELFsynthetic init")) || got.SSHDSHA256 != sha256.Sum256([]byte("\x7fELFsynthetic sshd")) {
		t.Fatalf("wrong files read: %+v", got)
	}
}
func TestRootCloudInit(t *testing.T) {
	root, pin := rootFixture(t)
	executable(t, root, "usr/bin/cloud-init", []byte("test"))
	if _, err := CheckRoot(root, pin); err == nil {
		t.Fatal("enabled cloud-init accepted")
	}
	put(t, root, "etc/cloud/cloud-init.disabled", "")
	if _, err := CheckRoot(root, pin); err != nil {
		t.Fatal(err)
	}
}
func TestRootRefusals(t *testing.T) {
	cases := map[string]func(*testing.T, string, *[32]byte){
		"no-pin":    func(t *testing.T, r string, p *[32]byte) { *p = [32]byte{} },
		"wrong-pin": func(t *testing.T, r string, p *[32]byte) { p[0] ^= 1 },
		"changed-helper": func(t *testing.T, r string, p *[32]byte) {
			executable(t, r, "usr/bin/cathedral-attest", []byte("\x7fELFchanged"))
		},
		"missing-init": func(t *testing.T, r string, p *[32]byte) { away(t, r, "usr/lib/systemd/systemd") },
		"script-init": func(t *testing.T, r string, p *[32]byte) {
			executable(t, r, "usr/lib/systemd/systemd", []byte("#!/bin/sh\nexit 0"))
		},
		"missing-sshd": func(t *testing.T, r string, p *[32]byte) { away(t, r, "usr/sbin/sshd") },
		"non-executable": func(t *testing.T, r string, p *[32]byte) {
			if err := os.Chmod(filepath.Join(r, "usr/sbin/sshd"), 0644); err != nil {
				t.Fatal(err)
			}
		},
		"writable-helper": func(t *testing.T, r string, p *[32]byte) {
			if err := os.Chmod(filepath.Join(r, "usr/bin/cathedral-attest"), 0777); err != nil {
				t.Fatal(err)
			}
		},
		"fifo-sshd": func(t *testing.T, r string, p *[32]byte) {
			away(t, r, "usr/sbin/sshd")
			if err := syscall.Mkfifo(filepath.Join(r, "usr/sbin/sshd"), 0755); err != nil {
				t.Fatal(err)
			}
		},
		"symlink-loop": func(t *testing.T, r string, p *[32]byte) {
			away(t, r, "usr/sbin/init")
			link(t, r, "usr/sbin/init", "/sbin/init")
		},
		"path-escape": func(t *testing.T, r string, p *[32]byte) {
			away(t, r, "usr/sbin/init")
			link(t, r, "usr/sbin/init", "../../../outside")
		},
		"host-absolute": func(t *testing.T, r string, p *[32]byte) {
			away(t, r, "usr/sbin/init")
			other := t.TempDir()
			executable(t, other, "init", []byte("\x7fELFhost"))
			link(t, r, "usr/sbin/init", filepath.Join(other, "init"))
		},
		"bad-disable-marker": func(t *testing.T, r string, p *[32]byte) {
			if err := os.MkdirAll(filepath.Join(r, "etc/cloud/cloud-init.disabled"), 0755); err != nil {
				t.Fatal(err)
			}
		},
		"local-cloud-init": func(t *testing.T, r string, p *[32]byte) {
			executable(t, r, "usr/local/bin/cloud-init", []byte("test"))
		},
		"oversized-init": func(t *testing.T, r string, p *[32]byte) {
			f, err := os.OpenFile(filepath.Join(r, "usr/lib/systemd/systemd"), os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if err = f.Truncate((64 << 20) + 1); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r, p := rootFixture(t)
			change(t, r, &p)
			got, err := CheckRoot(r, p)
			if err == nil || got != (RootFiles{}) {
				t.Fatalf("bad root accepted: %+v %v", got, err)
			}
		})
	}
}
