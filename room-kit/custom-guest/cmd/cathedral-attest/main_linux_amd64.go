// The static endpoint can also be called by the reference init for its local
// boot report. A successful local check is never an owner-side PASS verdict.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/snp"
)

func hex32(value string) ([32]byte, error) {
	var result [32]byte
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 32 || strings.ToLower(value) != value {
		return result, errors.New("expected 32 bytes of lowercase hex")
	}
	copy(result[:], raw)
	return result, nil
}

func run(args []string, uid int, random io.Reader, public func() ([]byte, error), collect func([64]byte) ([]byte, error)) (snp.Envelope, error) {
	var empty snp.Envelope
	if uid != 0 {
		return empty, errors.New("root required")
	}
	var data [64]byte
	var hostData *[32]byte
	if len(args) == 2 && args[0] == "--boot-host-data" {
		expected, err := hex32(args[1])
		if err != nil {
			return empty, err
		}
		var nonce [32]byte
		if _, err = io.ReadFull(random, nonce[:]); err != nil {
			return empty, fmt.Errorf("boot entropy: %w", err)
		}
		data = snp.BootData(nonce)
		hostData = &expected
	} else if len(args) == 1 {
		challenge, err := hex32(args[0])
		if err != nil {
			return empty, err
		}
		key, err := public()
		if err != nil {
			return empty, err
		}
		data, err = snp.ReportData(challenge, key)
		if err != nil {
			return empty, err
		}
	} else {
		return empty, errors.New("usage: cathedral-attest CHALLENGE_HEX | --boot-host-data EXPECTED_HOST_DATA_HEX")
	}
	report, err := collect(data)
	if err != nil {
		return empty, err
	}
	if err = snp.CheckLocal(report, data, hostData); err != nil {
		return empty, err
	}
	result := snp.EnvelopeFor(report)
	if hostData != nil {
		result.LocalBinding = "checked"
	}
	return result, nil
}

func main() {
	result, err := run(os.Args[1:], os.Geteuid(), rand.Reader,
		func() ([]byte, error) { return snp.PublicKey(snp.HostKeyPath) }, snp.Collect)
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": "custom_guest_report_failed", "reason": err.Error()})
		os.Exit(1)
	}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
}
