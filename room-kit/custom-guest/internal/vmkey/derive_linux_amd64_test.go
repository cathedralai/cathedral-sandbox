package vmkey

import (
	"encoding/hex"
	"os"
	"testing"
)

func fakeChip(chip [32]byte, status uint32, exit uint64, err error, seen *derivedKeyRequest) func(*derivedKeyRequest, *[64]byte) (uint64, error) {
	return func(req *derivedKeyRequest, resp *[64]byte) (uint64, error) {
		*seen = *req
		resp[0] = byte(status)
		copy(resp[32:], chip[:])
		return exit, err
	}
}

func TestDeriveSendsTheHotelRequestAndMixesHostData(t *testing.T) {
	v := load(t)
	c := v.Cases[0]
	var req derivedKeyRequest
	m, err := deriveWith(hex32(t, c.HostDataHex), fakeChip(hex32(t, c.ChipKeyHex), 0, 0, nil, &req))
	if err != nil {
		t.Fatal(err)
	}
	if req != (derivedKeyRequest{RootKeySelect: 0, GuestFieldSelect: 0x9, VMPL: 0}) {
		t.Fatalf("request %+v: want VCEK root, select 0x9, VMPL 0, no SVN or TCB", req)
	}
	if hex.EncodeToString(m.Passphrase[:]) != c.PassphraseHex || m.KeyID != c.KeyID {
		t.Fatal("derived material differs from the vectors")
	}
	m.Clear()
	if m.Passphrase != [32]byte{} {
		t.Fatal("Clear left key bytes")
	}
	if getDerivedKey != 0xc0205301 {
		t.Fatalf("ioctl number %#x", getDerivedKey)
	}
}

func TestDeriveRefusesFirmwareErrorsAndAZeroKey(t *testing.T) {
	var req derivedKeyRequest
	chip := [32]byte{1}
	for name, call := range map[string]func(*derivedKeyRequest, *[64]byte) (uint64, error){
		"status":   fakeChip(chip, 0x16, 0, nil, &req),
		"exitinfo": fakeChip(chip, 0, 7, nil, &req),
		"errno":    fakeChip(chip, 0, 7, os.ErrInvalid, &req),
		"zero key": fakeChip([32]byte{}, 0, 0, nil, &req),
	} {
		if _, err := deriveWith([32]byte{}, call); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
