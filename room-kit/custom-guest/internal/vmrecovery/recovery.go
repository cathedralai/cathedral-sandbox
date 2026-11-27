// Package vmrecovery is the recovery key record of a sealed VM (spec r3 7.2 step 4.3 and 7.5).
// The first boot writes it to /var/lib/cathedral-vm/recovery.key on the encrypted root; the
// customer reads it once with `sudo cathedral-vm recovery show` and pins it. It is never on the
// host and no LUKS token names it. Pure Go so the record and the printed form are portable.
package vmrecovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
)

const (
	// Path is where the guest keeps the record (root only, on the encrypted file system).
	Path       = "/var/lib/cathedral-vm/recovery.key"
	KeyBytes   = 32
	ChipBytes  = 64
	fileSchema = "cathedral.vm.recovery-key/v1"
	maxFile    = 1024
)

var (
	vmIDRe = regexp.MustCompile(`^vm-[0-9a-f]{12}$`)
	hexRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Record is the content of recovery.key.
type Record struct {
	VMID           string
	IdentitySHA256 string
	Key            [KeyBytes]byte
}

// Generate makes a record with 256 random bits. The reader is crypto/rand in the init; tests pass
// a fixed stream.
func Generate(random io.Reader, vmID, identitySHA256 string) (Record, error) {
	rec := Record{VMID: vmID, IdentitySHA256: identitySHA256}
	if _, err := io.ReadFull(random, rec.Key[:]); err != nil {
		return Record{}, err
	}
	if _, err := rec.Encode(); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Encode is the file content: canonical JSON (sorted keys, no spaces) and one newline.
func (r Record) Encode() ([]byte, error) {
	if !vmIDRe.MatchString(r.VMID) || !hexRe.MatchString(r.IdentitySHA256) {
		return nil, errors.New("recovery record: invalid vm_id or identity_sha256")
	}
	if r.Key == [KeyBytes]byte{} {
		return nil, errors.New("recovery record: the key is all zero")
	}
	return []byte(`{"identity_sha256":"` + r.IdentitySHA256 + `","recovery_key":"` +
		base64.StdEncoding.EncodeToString(r.Key[:]) + `","schema":"` + fileSchema + `","vm_id":"` + r.VMID + "\"}\n"), nil
}

// Parse reads a record file strictly: it must be exactly what Encode makes from its fields.
func Parse(raw []byte) (Record, error) {
	var rec Record
	if len(raw) == 0 || len(raw) > maxFile {
		return rec, errors.New("recovery record: size")
	}
	const (
		a = `{"identity_sha256":"`
		b = `","recovery_key":"`
		c = `","schema":"` + fileSchema + `","vm_id":"`
	)
	body, ok := bytes.CutSuffix(raw, []byte("\"}\n"))
	if !ok || !bytes.HasPrefix(body, []byte(a)) {
		return rec, errors.New("recovery record: shape")
	}
	body = body[len(a):]
	idEnd := bytes.Index(body, []byte(b))
	if idEnd < 0 {
		return rec, errors.New("recovery record: shape")
	}
	rec.IdentitySHA256 = string(body[:idEnd])
	body = body[idEnd+len(b):]
	keyEnd := bytes.Index(body, []byte(c))
	if keyEnd < 0 {
		return rec, errors.New("recovery record: shape")
	}
	key, err := base64.StdEncoding.Strict().DecodeString(string(body[:keyEnd]))
	if err != nil || len(key) != KeyBytes {
		return rec, errors.New("recovery record: key")
	}
	copy(rec.Key[:], key)
	rec.VMID = string(body[keyEnd+len(c):])
	again, err := rec.Encode()
	if err != nil || !bytes.Equal(again, raw) {
		return Record{}, errors.New("recovery record: not canonical")
	}
	return rec, nil
}

// Show is the one line `cathedral-vm recovery show` prints: R, vm_id, identity_sha256 and CHIP_ID,
// as canonical JSON with exactly the members verify_vm.py RECOVERY_FIELDS names
// (recovery_key_b64, vm_id, identity_sha256, chip_id), no others. chipID is the 64 bytes of the report's CHIP_ID field.
func Show(rec Record, chipID [ChipBytes]byte) ([]byte, error) {
	if _, err := rec.Encode(); err != nil {
		return nil, err
	}
	if chipID == [ChipBytes]byte{} {
		return nil, errors.New("recovery show: CHIP_ID is all zero")
	}
	return []byte(`{"chip_id":"` + hex.EncodeToString(chipID[:]) + `","identity_sha256":"` + rec.IdentitySHA256 +
		`","recovery_key_b64":"` + base64.StdEncoding.EncodeToString(rec.Key[:]) +
		`","vm_id":"` + rec.VMID + "\"}\n"), nil
}

// IdentityMatches reports whether a record names this identity: the init checks it against the
// identity it was given before it trusts a file on the root.
func (r Record) IdentityMatches(vmID, identitySHA256 string) bool {
	return r.VMID == vmID && r.IdentitySHA256 == identitySHA256
}

// IdentitySHA256 is sha256 over the identity document bytes, as 64 lowercase hex.
func IdentitySHA256(doc []byte) string {
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:])
}
