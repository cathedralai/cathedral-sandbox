package vmdisk

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
)

// Both on-disk records share one frame (spec r3 7.2 "Intent record"):
// an 8-byte magic, a 4-byte big-endian body length, the canonical JSON body,
// the sha256 of every byte before it, then zero padding to 4 KiB. The meta
// copies use the same frame with their own magic (spec r3 7.2 "Meta" names
// only "with its sha256"; this is the byte layout).
const (
	intentMagic = "CVMINT01"
	metaMagic   = "CVMMETA1"
	frameHead   = 8 + 4
	bodyMax     = RecordBytes - frameHead - sha256.Size

	IntentSchema = "cathedral.vm.format-intent/v1"
	MetaSchema   = "cathedral.vm.meta/v1"

	StateInitializing = "initializing"
	StateReady        = "ready"
	RoleRecovery      = "recovery"
)

var (
	vmIDRE        = regexp.MustCompile(`^vm-[0-9a-f]{12}$`)
	hex64RE       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	measurementRE = regexp.MustCompile(`^m:[0-9a-f]{96}$`)
)

func frame(magic string, body []byte) ([RecordBytes]byte, error) {
	var out [RecordBytes]byte
	if len(body) == 0 || len(body) > bodyMax {
		return out, errors.New("record body too large")
	}
	copy(out[:], magic)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(body)))
	copy(out[frameHead:], body)
	end := frameHead + len(body)
	sum := sha256.Sum256(out[:end])
	copy(out[end:], sum[:])
	return out, nil
}

// unframe returns the body of a valid frame, or nil. Every byte of the 4 KiB
// is checked: the magic, the length bound, the sha256 and zero padding.
func unframe(magic string, rec []byte) []byte {
	if len(rec) < RecordBytes || string(rec[:8]) != magic {
		return nil
	}
	n := binary.BigEndian.Uint32(rec[8:12])
	if n == 0 || n > bodyMax {
		return nil
	}
	end := frameHead + int(n)
	sum := sha256.Sum256(rec[:end])
	if !bytes.Equal(sum[:], rec[end:end+sha256.Size]) {
		return nil
	}
	for _, b := range rec[end+sha256.Size : RecordBytes] {
		if b != 0 {
			return nil
		}
	}
	return rec[frameHead:end]
}

// IntentStatus is what the first 4 KiB of the intent area holds.
type IntentStatus int

const (
	IntentNone    IntentStatus = iota // not a valid record: zero, garbage or torn
	IntentForeign                     // a valid record for another identity or disk size: ignored
	IntentValid                       // a valid record for this identity and disk size
)

func (s IntentStatus) String() string {
	return [...]string{"none", "foreign", "valid"}[s]
}

// EncodeIntent is the record F2 writes.
func EncodeIntent(id vmidentity.Identity, diskBytes int64) ([RecordBytes]byte, error) {
	body, err := vmidentity.Canonical(vmidentity.Object{
		"schema": IntentSchema, "vm_id": id.VMID, "identity_sha256": id.SHA256Hex(), "disk_bytes": diskBytes,
	})
	if err != nil {
		return [RecordBytes]byte{}, err
	}
	return frame(intentMagic, body)
}

// ParseIntent reads the first 4 KiB of the intent area. A record is valid
// only if every field parses and vm_id, identity_sha256 and disk_bytes equal
// this boot's identity and root.raw's size (spec r3 7.2).
func ParseIntent(rec []byte, id vmidentity.Identity, diskBytes int64) IntentStatus {
	body := unframe(intentMagic, rec)
	if body == nil {
		return IntentNone
	}
	doc, err := vmidentity.ParseCanonical(body, 1)
	if err != nil || !vmidentity.Fields(doc, "schema", "vm_id", "identity_sha256", "disk_bytes") {
		return IntentNone
	}
	schema, _ := vmidentity.String(doc, "schema")
	vmID, ok1 := vmidentity.String(doc, "vm_id")
	identity, ok2 := vmidentity.String(doc, "identity_sha256")
	size, ok3 := vmidentity.Int(doc, "disk_bytes")
	if schema != IntentSchema || !ok1 || !ok2 || !ok3 || !vmIDRE.MatchString(vmID) ||
		!hex64RE.MatchString(identity) || size <= 0 {
		return IntentNone
	}
	if vmID != id.VMID || identity != id.SHA256Hex() || size != diskBytes {
		return IntentForeign
	}
	return IntentValid
}

// Meta is one meta copy (spec r3 7.2 "Meta"). Slots maps a LUKS keyslot
// number to its role: "m:<measurement hex>" or "recovery".
type Meta struct {
	Seq            int64
	VMID           string
	IdentitySHA256 string
	State          string
	Slots          map[int]string
}

// MeasurementRole is the slot table role of a slot keyed by measurement m.
func MeasurementRole(m [48]byte) string { return "m:" + hex.EncodeToString(m[:]) }

// Names reports whether the meta names this identity.
func (m Meta) Names(id vmidentity.Identity) bool {
	return m.VMID == id.VMID && m.IdentitySHA256 == id.SHA256Hex()
}

func (m Meta) check() error {
	bad := errors.New("meta invalid")
	if m.Seq < 1 || !vmIDRE.MatchString(m.VMID) || !hex64RE.MatchString(m.IdentitySHA256) || len(m.Slots) == 0 || len(m.Slots) > 32 {
		return bad
	}
	measured, recovery := 0, 0
	for slot, role := range m.Slots {
		switch {
		case slot < 0 || slot > 31:
			return bad
		case role == RoleRecovery:
			recovery++
		case measurementRE.MatchString(role):
			measured++
		default:
			return bad
		}
	}
	// Until ready the table holds only the M slot (spec r3 7.2 step 4.1);
	// ready has the recovery slot and at least one measurement slot.
	switch m.State {
	case StateInitializing:
		if measured != 1 || recovery != 0 {
			return bad
		}
	case StateReady:
		if measured < 1 || recovery != 1 {
			return bad
		}
	default:
		return bad
	}
	return nil
}

// EncodeMeta is the 4 KiB copy written to one of the two meta offsets.
func EncodeMeta(m Meta) ([RecordBytes]byte, error) {
	if err := m.check(); err != nil {
		return [RecordBytes]byte{}, err
	}
	slots := vmidentity.Object{}
	for slot, role := range m.Slots {
		slots[strconv.Itoa(slot)] = role
	}
	body, err := vmidentity.Canonical(vmidentity.Object{
		"schema": MetaSchema, "seq": m.Seq, "vm_id": m.VMID, "identity_sha256": m.IdentitySHA256,
		"state": m.State, "slots": slots,
	})
	if err != nil {
		return [RecordBytes]byte{}, err
	}
	return frame(metaMagic, body)
}

// ParseMeta returns a copy's meta, or false if the copy is not valid.
func ParseMeta(rec []byte) (Meta, bool) {
	body := unframe(metaMagic, rec)
	if body == nil {
		return Meta{}, false
	}
	doc, err := vmidentity.ParseCanonical(body, 2)
	if err != nil || !vmidentity.Fields(doc, "schema", "seq", "vm_id", "identity_sha256", "state", "slots") {
		return Meta{}, false
	}
	schema, _ := vmidentity.String(doc, "schema")
	var m Meta
	var ok [4]bool
	m.Seq, ok[0] = vmidentity.Int(doc, "seq")
	m.VMID, ok[1] = vmidentity.String(doc, "vm_id")
	m.IdentitySHA256, ok[2] = vmidentity.String(doc, "identity_sha256")
	m.State, ok[3] = vmidentity.String(doc, "state")
	table, isObject := doc["slots"].(vmidentity.Object)
	if schema != MetaSchema || ok != [4]bool{true, true, true, true} || !isObject {
		return Meta{}, false
	}
	m.Slots = map[int]string{}
	for key, value := range table {
		slot, err := strconv.Atoi(key)
		role, isString := value.(string)
		if err != nil || strconv.Itoa(slot) != key || !isString {
			return Meta{}, false
		}
		m.Slots[slot] = role
	}
	if m.check() != nil {
		return Meta{}, false
	}
	return m, true
}

// Current is the winning meta of the two copies and where the next write goes.
type Current struct {
	Meta  Meta
	Copy  int // the copy that holds Meta
	Valid bool
}

// NextCopy is where the next meta write goes: the other copy than the
// current one, so a cut always leaves one valid copy (spec r3 7.2).
func (c Current) NextCopy() int { return 1 - c.Copy }

// ChooseMeta picks the valid copy with the higher seq. Two valid copies with
// one seq but different bytes never come from the write order, so neither
// is trusted.
func ChooseMeta(copy0, copy1 []byte) Current {
	m0, ok0 := ParseMeta(copy0)
	m1, ok1 := ParseMeta(copy1)
	switch {
	case ok0 && ok1 && m0.Seq == m1.Seq:
		if bytes.Equal(copy0[:RecordBytes], copy1[:RecordBytes]) {
			return Current{Meta: m0, Copy: 0, Valid: true}
		}
		return Current{}
	case ok0 && (!ok1 || m0.Seq > m1.Seq):
		return Current{Meta: m0, Copy: 0, Valid: true}
	case ok1:
		return Current{Meta: m1, Copy: 1, Valid: true}
	}
	return Current{}
}
