// Package vmattest is the logic of the VM's in-guest attest tool (spec r3 6.4). Pure Go except
// for the report collection, which the caller passes in, so the REPORT_DATA formula and the host
// key parsing are tested on any machine.
//
// REPORT_DATA = sha512("cathedral-vm-report/v1\0" || challenge[32] || sha256(host_key_blob)),
// where host_key_blob is the ssh-ed25519 WIRE BLOB of /etc/ssh/ssh_host_ed25519_key.pub (the
// base64-decoded second field). That is exactly what room-kit/vm/verify_vm.py reads from the SSH
// handshake. It is NOT the dedicated guest's /run/cathedral path or domain.
package vmattest

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

const (
	// HostKeyPath is the VM's persistent host key, made at first boot on the encrypted root.
	HostKeyPath  = "/etc/ssh/ssh_host_ed25519_key.pub"
	reportDomain = "cathedral-vm-report/v1\x00"
	reportBytes  = 1184
)

var blobPrefix = []byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20")

// HostKeyBlob parses one ssh-ed25519 public key line (a trailing comment is allowed) and returns
// its wire blob. Anything else is refused.
func HostKeyBlob(line []byte) ([]byte, error) {
	if len(line) == 0 || len(line) > 4096 {
		return nil, errors.New("host key file size invalid")
	}
	parts := strings.Fields(string(line))
	if (len(parts) != 2 && len(parts) != 3) || parts[0] != "ssh-ed25519" {
		return nil, errors.New("host key is not one ssh-ed25519 line")
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil || base64.StdEncoding.EncodeToString(blob) != parts[1] {
		return nil, errors.New("host key encoding invalid")
	}
	if len(blob) != len(blobPrefix)+32 || !bytes.HasPrefix(blob, blobPrefix) {
		return nil, errors.New("host key must be a wire-format Ed25519 blob")
	}
	return blob, nil
}

// ReportData is the 64 bytes the VM puts in REPORT_DATA for this challenge on this host key.
func ReportData(challenge [32]byte, blob []byte) ([64]byte, error) {
	if len(blob) != len(blobPrefix)+32 || !bytes.HasPrefix(blob, blobPrefix) {
		return [64]byte{}, errors.New("host key must be a wire-format Ed25519 blob")
	}
	hash := sha256.Sum256(blob)
	input := append([]byte(reportDomain), challenge[:]...)
	return sha512.Sum512(append(input, hash[:]...)), nil
}

func challengeFrom(arg string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(arg)
	if err != nil || len(raw) != 32 || strings.ToLower(arg) != arg {
		return out, errors.New("challenge must be 32 bytes of lowercase hex")
	}
	copy(out[:], raw)
	return out, nil
}

// Answer is the one JSON object printed on stdout. verify_vm.py reads only report_b64; the other
// members are labels, not evidence.
type Answer struct {
	Schema       string `json:"schema"`
	Verification string `json:"verification"`
	Source       string `json:"source"`
	Report       string `json:"report_b64"`
}

// Run checks args and the caller's uid, reads the host key, and collects the report. A report of
// the wrong size, or one whose REPORT_DATA is not the requested value, is refused.
func Run(args []string, uid int, readKey func() ([]byte, error), collect func([64]byte) ([]byte, error)) (Answer, error) {
	if uid != 0 {
		return Answer{}, errors.New("root required")
	}
	if len(args) != 1 {
		return Answer{}, errors.New("usage: cathedral-attest CHALLENGE_HEX")
	}
	challenge, err := challengeFrom(args[0])
	if err != nil {
		return Answer{}, err
	}
	raw, err := readKey()
	if err != nil {
		return Answer{}, err
	}
	blob, err := HostKeyBlob(raw)
	if err != nil {
		return Answer{}, err
	}
	data, err := ReportData(challenge, blob)
	if err != nil {
		return Answer{}, err
	}
	report, err := collect(data)
	if err != nil {
		return Answer{}, err
	}
	if len(report) != reportBytes || !bytes.Equal(report[0x50:0x90], data[:]) {
		return Answer{}, errors.New("report does not carry the requested REPORT_DATA")
	}
	return Answer{Schema: "cathedral.vm.guest-report/v1", Verification: "not_checked", Source: "SNP_GET_REPORT",
		Report: base64.StdEncoding.EncodeToString(report)}, nil
}

// Encode is the stdout bytes of an answer: one JSON object and a newline.
func Encode(a Answer) ([]byte, error) {
	raw, err := json.Marshal(a)
	return append(raw, '\n'), err
}
