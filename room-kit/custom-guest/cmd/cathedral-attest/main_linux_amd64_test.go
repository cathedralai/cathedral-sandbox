package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/snp"
)

func key() ([]byte, error) {
	return append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), make([]byte, 32)...), nil
}
func report(data [64]byte) ([]byte, error) {
	raw := make([]byte, snp.ReportBytes)
	binary.LittleEndian.PutUint32(raw[:4], 3)
	binary.LittleEndian.PutUint64(raw[8:16], 0x30000)
	copy(raw[0x50:0x90], data[:])
	return raw, nil
}

func TestNativeEndpointAndBootCheck(t *testing.T) {
	env, err := run([]string{strings.Repeat("00", 32)}, 0, nil, key, report)
	if err != nil {
		t.Fatal(err)
	}
	if env.LocalBinding != "" || env.Verification != "not_checked" {
		t.Fatal("endpoint asserted trust")
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("PASS")) {
		t.Fatal("helper must not assert PASS")
	}
	for _, b := range []byte{1, 2} {
		nonce := bytes.Repeat([]byte{b}, 32)
		expected := snp.BootData([32]byte(nonce))
		env, err = run([]string{"--boot-host-data", strings.Repeat("00", 32)}, 0, bytes.NewReader(nonce),
			func() ([]byte, error) { t.Fatal("boot must not read SSH key"); return nil, nil },
			func(data [64]byte) ([]byte, error) {
				if data != expected {
					t.Fatal("boot nonce/domain differs")
				}
				return report(data)
			})
		if err != nil {
			t.Fatal(err)
		}
		if env.LocalBinding != "checked" || env.Verification != "not_checked" {
			t.Fatal("boot result overclaims")
		}
	}
}

func TestNoIOOnRejectedInput(t *testing.T) {
	failKey := func() ([]byte, error) { t.Fatal("unexpected key read"); return nil, nil }
	failCollect := func([64]byte) ([]byte, error) { t.Fatal("unexpected device access"); return nil, nil }
	for _, args := range [][]string{nil, {"--device", "other"}, {"bad"}, {strings.Repeat("AA", 32)}, {"--boot-host-data", "short"}, {"--emulated"}} {
		if _, err := run(args, 0, nil, failKey, failCollect); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	if _, err := run([]string{strings.Repeat("00", 32)}, 1, nil, failKey, failCollect); err == nil {
		t.Fatal("non-root accepted")
	}
	if _, err := run([]string{"--boot-host-data", strings.Repeat("00", 32)}, 0, bytes.NewReader(nil), failKey, failCollect); err == nil {
		t.Fatal("entropy failure accepted")
	}
	if _, err := run([]string{strings.Repeat("00", 32)}, 0, nil, func() ([]byte, error) { return nil, errors.New("bad key") }, failCollect); err == nil {
		t.Fatal("key failure accepted")
	}
}

func TestBootHostDataMismatchAndDeviceFailure(t *testing.T) {
	zero := strings.Repeat("00", 32)
	wrong := hex.EncodeToString(bytes.Repeat([]byte{1}, 32))
	if _, err := run([]string{"--boot-host-data", wrong}, 0, bytes.NewReader(make([]byte, 32)), key, report); err == nil {
		t.Fatal("wrong HOST_DATA accepted")
	}
	if _, err := run([]string{zero}, 0, nil, key, func([64]byte) ([]byte, error) { return nil, errors.New("SNP missing") }); err == nil {
		t.Fatal("missing SNP accepted")
	}
}
