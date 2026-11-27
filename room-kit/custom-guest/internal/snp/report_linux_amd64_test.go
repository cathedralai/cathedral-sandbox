package snp

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

func validReport(data [64]byte) []byte {
	raw := make([]byte, ReportBytes)
	binary.LittleEndian.PutUint32(raw[:4], 3)
	binary.LittleEndian.PutUint64(raw[8:16], 0x30000)
	copy(raw[0x50:0x90], data[:])
	return raw
}

func TestPublishedPythonVector(t *testing.T) {
	raw, err := os.ReadFile("../../../../tests/fixtures/custom_guest_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]any
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	var challenge [32]byte
	for i := range challenge {
		challenge[i] = byte(64 + i)
	}
	blob := append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), make([]byte, 32)...)
	for i := 0; i < 32; i++ {
		blob[len(blob)-32+i] = byte(32 + i)
	}
	data, err := ReportData(challenge, blob)
	if err != nil {
		t.Fatal(err)
	}
	boot := BootData(challenge)
	if hex.EncodeToString(data[:]) != vector["report_data_hex"] {
		t.Fatal("Python report domain differs")
	}
	if hex.EncodeToString(boot[:]) != vector["bootcheck_data_hex"] {
		t.Fatal("Python boot domain differs")
	}
	if data == boot {
		t.Fatal("domains overlap")
	}
	blob[len(blob)-1] ^= 1
	changed, _ := ReportData(challenge, blob)
	if data == changed {
		t.Fatal("SSH key not bound")
	}
}

func TestABIAndRequest(t *testing.T) {
	if unsafe.Sizeof(guestRequest{}) != 32 || unsafe.Offsetof(guestRequest{}.Request) != 8 ||
		unsafe.Offsetof(guestRequest{}.Response) != 16 || unsafe.Offsetof(guestRequest{}.ExitInfo) != 24 ||
		unsafe.Sizeof(reportRequest{}) != 96 || unsafe.Offsetof(reportRequest{}.KeySelect) != 0x44 {
		t.Fatal("Linux/AMD ABI drift")
	}
	data := BootData([32]byte{1})
	report, err := collectWith(data, func(req *reportRequest, resp *[4000]byte) (uint64, error) {
		if req.Data != data || req.VMPL != 0 || req.KeySelect != 1 || req.Reserved != [24]byte{} {
			t.Fatal("request data/VMPL/VCEK/reserved incorrect")
		}
		binary.LittleEndian.PutUint32(resp[4:8], ReportBytes)
		copy(resp[32:], validReport(data))
		return 0, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(report, validReport(data)) {
		t.Fatal("wrong extracted report")
	}
	env := EnvelopeFor(report)
	if env.Verification != "not_checked" || env.LocalBinding != "" || env.Chain != nil {
		t.Fatal("collection asserted verification")
	}
}

func TestFirmwareErrorsNeverReturnReport(t *testing.T) {
	for _, name := range []string{"ioctl", "exit", "status", "size", "report"} {
		t.Run(name, func(t *testing.T) {
			data := BootData([32]byte{})
			got, err := collectWith(data, func(req *reportRequest, resp *[4000]byte) (uint64, error) {
				binary.LittleEndian.PutUint32(resp[4:8], ReportBytes)
				copy(resp[32:], validReport(data))
				switch name {
				case "ioctl":
					return 0, errors.New("driver failure")
				case "exit":
					return 1 << 32, nil
				case "status":
					resp[0] = 1
				case "size":
					resp[4] = 0
				case "report":
					resp[32+0x50] ^= 1
				}
				return 0, nil
			})
			if err == nil || got != nil {
				t.Fatal("firmware failure accepted")
			}
		})
	}
}

func TestLocalBindingRefusesMismatches(t *testing.T) {
	data := BootData([32]byte{1})
	for _, name := range []string{"length", "version", "policy", "vmpl", "masked", "vlek", "reserved", "challenge", "host_data"} {
		t.Run(name, func(t *testing.T) {
			report := validReport(data)
			var host [32]byte
			switch name {
			case "length":
				report = report[:100]
			case "version":
				report[0] = 4
			case "policy":
				report[8] ^= 1
			case "vmpl":
				report[0x30] = 1
			case "masked":
				report[0x48] = 2
			case "vlek":
				report[0x48] = 4
			case "reserved":
				report[0x49] = 1
			case "challenge":
				report[0x50] ^= 1
			case "host_data":
				host[0] = 1
			}
			if err := CheckLocal(report, data, &host); err == nil {
				t.Fatal("mismatched report accepted")
			}
		})
	}
	for _, version := range []byte{2, 3} {
		report := validReport(data)
		report[0] = version
		if err := CheckLocal(report, data, &[32]byte{}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPublicKeyFileChecks(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership tests")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "host.pub")
	blob := append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), make([]byte, 32)...)
	text := []byte("ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " test\n")
	if err := os.WriteFile(path, text, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := PublicKey(path)
	if err != nil || !bytes.Equal(blob, got) {
		t.Fatalf("valid key: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = PublicKey(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err = os.Chmod(path, 0620); err != nil {
		t.Fatal(err)
	}
	if _, err = PublicKey(path); err == nil {
		t.Fatal("writable key accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, bytes.Repeat([]byte("x"), 4097), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = PublicKey(path); err == nil {
		t.Fatal("oversized key accepted")
	}
	if _, err = PublicKey(dir); err == nil {
		t.Fatal("directory accepted")
	}
}
