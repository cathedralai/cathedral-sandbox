// Package vmkey makes the sealed VM root disk key (spec r3 7.2 step 2): the
// chip's derived key for this guest (MSG_KEY_REQ, VCEK root, field select
// POLICY|MEASUREMENT, VMPL 0), then HKDF-SHA256 with HOST_DATA.
//
// This is room-kit/sealed/sealed_data_key.py:49-58, :103-129 and :151-173
// with the VM salt. sealed_data_key.py ships in the measured kit image, so
// it is never edited for this: scripts/make_vm_root_key_vectors.py imports
// its hkdf read-only and tests/fixtures/vm_root_key_v1.json holds the
// vectors both sides must give.
package vmkey

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

const (
	// Salt is the VM root salt; the hotel data volume uses
	// "cathedral-sealed-data-v1".
	Salt = "cathedral-vm-root-v1"
	// FieldSelect is GUEST_FIELD_SELECT POLICY (bit 0) | MEASUREMENT (bit 3).
	// TCB_VERSION is not selected, so a firmware update keeps the key
	// (sealed_data_key.py:14-17); FAMILY_ID and IMAGE_ID are host-chosen.
	FieldSelect uint64 = 1<<0 | 1<<3
	// RootKeyVCEK and VMPL are the request's root key and level.
	RootKeyVCEK uint32 = 0
	VMPL        uint32 = 0
)

// context is sealed_data_key._context: field select as 8 bytes little
// endian, then the 32 HOST_DATA bytes.
func context(fieldSelect uint64, hostData [32]byte) []byte {
	out := binary.LittleEndian.AppendUint64(nil, fieldSelect)
	return append(out, hostData[:]...)
}

func derive(chipKey []byte, label string, fieldSelect uint64, hostData [32]byte, n int) []byte {
	info := append([]byte(label), context(fieldSelect, hostData)...)
	// hkdf.Key fails only for a length above 255 hash blocks.
	out, err := hkdf.Key(sha256.New, chipKey, []byte(Salt), string(info), n)
	if err != nil {
		panic(err)
	}
	return out
}

// Passphrase is the LUKS2 passphrase: 32 bytes, as volume_key with the VM
// salt. The caller clears it when done.
func Passphrase(chipKey [32]byte, fieldSelect uint64, hostData [32]byte) [32]byte {
	var out [32]byte
	key := derive(chipKey[:], "luks2-passphrase\x00", fieldSelect, hostData, 32)
	copy(out[:], key)
	clear(key)
	return out
}

// KeyID is a public label of the key (sealed_data_key.key_id with the VM
// salt): equal labels mean equal keys, and it reveals nothing of the key.
func KeyID(chipKey [32]byte, fieldSelect uint64, hostData [32]byte) string {
	return hex.EncodeToString(derive(chipKey[:], "key-id\x00", fieldSelect, hostData, 8))
}
