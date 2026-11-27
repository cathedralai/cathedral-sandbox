// Package snp collects a report from the native Linux SNP guest driver.
// Collection and local binding checks are not owner-side certificate verification.
package snp

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const ReportBytes = 1184
const device = "/dev/sev-guest"
const HostKeyPath = "/run/cathedral/ssh_host_ed25519_key.pub"
const reportDomain = "cathedral-custom-guest-report/v1\x00"
const bootDomain = "cathedral-custom-guest-bootcheck/v1\x00"
const getReport = uintptr(0xc0205300)

// Layout follows the Linux snp_guest_request_ioctl ABI on amd64.
type guestRequest struct {
	Version  uint8
	_        [7]byte
	Request  uint64
	Response uint64
	ExitInfo uint64
}

// KEY_SEL=1 at offset 0x44 requests VCEK in AMD MSG_REPORT_REQ.
// Linux's older UAPI spells that part of the payload reserved; the driver
// forwards the firmware payload. Firmware rejection is fatal, no VLEK fallback.
type reportRequest struct {
	Data      [64]byte
	VMPL      uint32
	KeySelect uint32
	Reserved  [24]byte
}

type Envelope struct {
	Schema       string `json:"schema"`
	Verification string `json:"verification"`
	Source       string `json:"source"`
	Report       string `json:"report_b64"`
	Chain        any    `json:"cert_chain"`
	LocalBinding string `json:"local_boot_binding,omitempty"`
}

func EnvelopeFor(report []byte) Envelope {
	return Envelope{Schema: "cathedral.snp.guest-report/v1", Verification: "not_checked",
		Source: "SNP_GET_REPORT", Report: base64.StdEncoding.EncodeToString(report)}
}

func ReportData(challenge [32]byte, blob []byte) ([64]byte, error) {
	prefix := []byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20")
	if len(blob) != len(prefix)+32 || !bytes.HasPrefix(blob, prefix) {
		return [64]byte{}, errors.New("host key must be wire-format Ed25519")
	}
	hash := sha256.Sum256(blob)
	input := append([]byte(reportDomain), challenge[:]...)
	return sha512.Sum512(append(input, hash[:]...)), nil
}

func BootData(nonce [32]byte) [64]byte {
	return sha512.Sum512(append([]byte(bootDomain), nonce[:]...))
}

func PublicKey(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var meta syscall.Stat_t
	if err = syscall.Fstat(fd, &meta); err != nil {
		return nil, err
	}
	if meta.Mode&syscall.S_IFMT != syscall.S_IFREG || meta.Uid != 0 || meta.Mode&0022 != 0 {
		return nil, errors.New("host public key must be a root-owned regular file without group/other write")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return nil, err
	}
	if len(raw) > 4096 {
		return nil, errors.New("host key too large")
	}
	parts := strings.Fields(string(raw))
	if (len(parts) != 2 && len(parts) != 3) || parts[0] != "ssh-ed25519" {
		return nil, errors.New("host key invalid")
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil || base64.StdEncoding.EncodeToString(blob) != parts[1] {
		return nil, errors.New("host key encoding invalid")
	}
	if _, err = ReportData([32]byte{}, blob); err != nil {
		return nil, err
	}
	return blob, nil
}

func Collect(data [64]byte) ([]byte, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root required")
	}
	return collectWith(data, nativeCall)
}

// collectWith is a unit-test seam only. No command line selects a fake device,
// a supplied report, a socket, configfs or an emulated backend.
func collectWith(data [64]byte, call func(*reportRequest, *[4000]byte) (uint64, error)) ([]byte, error) {
	request := &reportRequest{Data: data, KeySelect: 1}
	response := new([4000]byte)
	exit, err := call(request, response)
	if err != nil {
		return nil, fmt.Errorf("SNP_GET_REPORT: %w", err)
	}
	if exit != 0 {
		return nil, errors.New("SNP firmware or VMM error")
	}
	if binary.LittleEndian.Uint32(response[:4]) != 0 {
		return nil, errors.New("SNP report status failed")
	}
	if binary.LittleEndian.Uint32(response[4:8]) != ReportBytes {
		return nil, errors.New("SNP report size invalid")
	}
	report := append([]byte(nil), response[32:32+ReportBytes]...)
	if err := CheckLocal(report, data, nil); err != nil {
		return nil, err
	}
	return report, nil
}

func nativeCall(request *reportRequest, response *[4000]byte) (uint64, error) {
	if unsafe.Sizeof(guestRequest{}) != 32 || unsafe.Sizeof(reportRequest{}) != 96 {
		return 0, errors.New("unsupported SNP ABI")
	}
	fd, err := syscall.Open(device, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	var meta syscall.Stat_t
	if err = syscall.Fstat(fd, &meta); err != nil {
		return 0, err
	}
	if meta.Mode&syscall.S_IFMT != syscall.S_IFCHR || meta.Uid != 0 || meta.Mode&0077 != 0 {
		return 0, errors.New("SNP device must be a root-only character device")
	}
	command := new(guestRequest)
	// Embedded addresses are integers to match the UAPI. Pin all pointed-to
	// storage explicitly for the synchronous kernel call, and retain it afterwards.
	var pin runtime.Pinner
	pin.Pin(request)
	pin.Pin(response)
	pin.Pin(command)
	defer pin.Unpin()
	command.Version = 1
	command.Request = uint64(uintptr(unsafe.Pointer(request)))
	command.Response = uint64(uintptr(unsafe.Pointer(response)))
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), getReport, uintptr(unsafe.Pointer(command)))
	runtime.KeepAlive(request)
	runtime.KeepAlive(response)
	runtime.KeepAlive(command)
	if errno != 0 {
		return command.ExitInfo, errno
	}
	return command.ExitInfo, nil
}

// CheckLocal checks fields from an ioctl response in this guest. It does not
// validate an AMD certificate, signature, firmware floor or remote guest.
func CheckLocal(report []byte, data [64]byte, hostData *[32]byte) error {
	if len(report) != ReportBytes {
		return errors.New("report length invalid")
	}
	version := binary.LittleEndian.Uint32(report[:4])
	if version != 2 && version != 3 {
		return errors.New("report version invalid")
	}
	if binary.LittleEndian.Uint64(report[8:16]) != 0x30000 {
		return errors.New("report policy invalid")
	}
	if binary.LittleEndian.Uint32(report[0x30:0x34]) != 0 {
		return errors.New("report VMPL must be zero")
	}
	if binary.LittleEndian.Uint32(report[0x48:0x4c]) & ^uint32(1) != 0 {
		return errors.New("report must use unmasked VCEK")
	}
	if !bytes.Equal(report[0x50:0x90], data[:]) {
		return errors.New("REPORT_DATA mismatch")
	}
	if hostData != nil && !bytes.Equal(report[0xc0:0xe0], hostData[:]) {
		return errors.New("HOST_DATA mismatch")
	}
	return nil
}
