package vmmailbox

// Needs root and a loop device: run by the vm-guest CI job with CATHEDRAL_VM_ROOT_TESTS=1.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootOpenDeviceDoesDirectAlignedIO(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("CATHEDRAL_VM_ROOT_TESTS") != "1" {
		t.Skip("needs root and CATHEDRAL_VM_ROOT_TESTS=1")
	}
	file := filepath.Join(t.TempDir(), "mailbox.raw")
	if err := os.WriteFile(file, make([]byte, MailboxBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("losetup", "--find", "--show", file).CombinedOutput()
	if err != nil {
		t.Fatalf("losetup: %v %s", err, out)
	}
	dev := strings.TrimSpace(string(out))
	t.Cleanup(func() { exec.Command("losetup", "-d", dev).Run() })

	m, f, err := OpenDevice(dev)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := m.WriteStatus(sampleStatus()); err != nil {
		t.Fatal(err)
	}
	if doc, ok := m.ReadStatus(); !ok || doc["state"] != "open" {
		t.Fatalf("status did not read back through O_DIRECT: %v", doc)
	}
	if _, err := m.WriteOffer(sampleOffer()); err != nil {
		t.Fatal(err)
	}
	if err := m.ZeroOffer(); err != nil {
		t.Fatal(err)
	}
	// The host writes the answer through the backing file, not through this descriptor: a direct read
	// must see it without any cache flush on our side.
	ans := answerSlotFor(t, Answer{OfferSHA256: strings.Repeat("a", 64), EPK: [32]byte{1}, Nonce: [12]byte{2}, CT: [48]byte{3}})
	host, err := os.OpenFile(file, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := host.WriteAt(ans, AnswerOffset); err != nil {
		t.Fatal(err)
	}
	host.Close()
	if _, ok := m.AnswerFor(strings.Repeat("a", 64)); !ok {
		t.Fatal("the host's answer was not seen")
	}
	// A device that is not 1 MiB is refused.
	small := filepath.Join(t.TempDir(), "small.raw")
	os.WriteFile(small, bytes.Repeat([]byte{0}, 4096), 0o600)
	if _, _, err := OpenDevice(small); err == nil {
		t.Error("a mailbox of the wrong size was accepted")
	}
}
