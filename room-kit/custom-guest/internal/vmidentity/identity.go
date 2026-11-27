// Package vmidentity checks the sealed VM identity (spec r3 6.3, 6.5) before
// the VM init reads any disk: the identity document from fw_cfg, the measured
// cmdline that names its sha256, and the HOST_DATA the launch must carry.
// It is the Go port of room-kit/vm/vm_measure.py (identity, cmdline,
// HOST_DATA); tests/fixtures/vm_measure_v1.json holds the shared vectors.
package vmidentity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
)

const (
	Schema = "cathedral.vm.identity/v1"
	// HostDataDomain is the VM's own domain (spec r3 6.3, Q3), so a VM
	// report never reads as a dedicated owner launch (cathedral-dedicated-v2\0).
	HostDataDomain = "cathedral-vm-v1\x00"
	// DocMax bounds every canonical document (vm_measure.DOC_MAX).
	DocMax = 16384
	// fileMax bounds base_root_data_bytes (vm_measure.FILE_MAX).
	fileMax = 64 << 30
	// identityPlaceholder is where the template names the identity.
	identityPlaceholder = "{identity_sha256}"
	// ovmfPrefix is what OVMF puts in front of the measured bytes in
	// /proc/cmdline (vm_measure.CMDLINE_MAX comment, bootstrap.Validate).
	ovmfPrefix = "initrd=initrd "
)

// CmdlineTemplateV1 must equal vm_measure.CMDLINE_TEMPLATE_V1 byte for byte;
// the vector test pins it against the fixture.
const CmdlineTemplateV1 = "console=ttyS0 loglevel=4 panic=-1 systemd.import_credentials=no" +
	" systemd.getty_auto=0" +
	" systemd.mask=getty@.service systemd.mask=serial-getty@.service" +
	" systemd.mask=autovt@.service systemd.mask=console-getty.service" +
	" systemd.mask=emergency.service systemd.mask=rescue.service" +
	" systemd.mask=debug-shell.service" +
	" systemd.mask=qemu-guest-agent.service" +
	" cathedral.vm=" + identityPlaceholder

// keyTypes must equal vm_measure.KEY_TYPES.
var keyTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"ssh-rsa":                            true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

var (
	vmIDRE  = regexp.MustCompile(`^vm-[0-9a-f]{12}$`)
	hex32RE = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex64RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Identity is a parsed vm-identity.json. Raw keeps the exact bytes, since
// the sha256 and HOST_DATA are over them.
type Identity struct {
	Raw               []byte
	VMID              string
	SaltHex           string
	SSHPublicKey      string
	BaseRootVerity    string
	BaseRootDataBytes int64
}

// SHA256 is the sha256 of the identity bytes, the value cathedral.vm= names.
func (id Identity) SHA256() [32]byte { return sha256.Sum256(id.Raw) }

// SHA256Hex is SHA256 as 64 lowercase hex.
func (id Identity) SHA256Hex() string {
	h := id.SHA256()
	return hex.EncodeToString(h[:])
}

// HostData is sha256("cathedral-vm-v1\0" || sha256(vm-identity.json)).
func (id Identity) HostData() [32]byte {
	h := id.SHA256()
	return sha256.Sum256(append([]byte(HostDataDomain), h[:]...))
}

// Parse refuses anything vm_measure.parse_identity refuses.
func Parse(raw []byte) (Identity, error) {
	fail := func(msg string) (Identity, error) { return Identity{}, errors.New("identity: " + msg) }
	if len(raw) == 0 || len(raw) > DocMax {
		return fail("must be 1 to 16384 bytes")
	}
	doc, err := ParseCanonical(raw, 1)
	if err != nil {
		return fail("not canonical JSON")
	}
	if !Fields(doc, "version", "schema", "vm_id", "salt_hex", "ssh_public_key", "base_root_verity", "base_root_data_bytes") {
		return fail("missing or unknown field")
	}
	version, ok := Int(doc, "version")
	schema, _ := String(doc, "schema")
	if !ok || version != 1 || schema != Schema {
		return fail("unsupported version or schema")
	}
	id := Identity{Raw: bytes.Clone(raw)}
	if id.VMID, ok = String(doc, "vm_id"); !ok || !vmIDRE.MatchString(id.VMID) {
		return fail("vm_id invalid")
	}
	if id.SaltHex, ok = String(doc, "salt_hex"); !ok || !hex32RE.MatchString(id.SaltHex) {
		return fail("salt_hex invalid")
	}
	if id.SSHPublicKey, ok = String(doc, "ssh_public_key"); !ok || CheckSSHKey(id.SSHPublicKey) != nil {
		return fail("ssh_public_key must be 'type base64' with no comment")
	}
	if id.BaseRootVerity, ok = String(doc, "base_root_verity"); !ok || !hex64RE.MatchString(id.BaseRootVerity) {
		return fail("base_root_verity invalid")
	}
	id.BaseRootDataBytes, ok = Int(doc, "base_root_data_bytes")
	if !ok || id.BaseRootDataBytes < 4096 || id.BaseRootDataBytes > fileMax || id.BaseRootDataBytes%4096 != 0 {
		return fail("base_root_data_bytes invalid")
	}
	return id, nil
}

// CheckSSHKey accepts exactly "type base64" (vm_measure.ssh_public_key with
// the comment dropped): a known type, canonical standard base64, and a blob
// whose first string is that type.
func CheckSSHKey(key string) error {
	bad := errors.New("ssh key invalid")
	parts := strings.Split(key, " ")
	if len(parts) != 2 || !keyTypes[parts[0]] {
		return bad
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil || base64.StdEncoding.EncodeToString(blob) != parts[1] || len(blob) < 4 {
		return bad
	}
	n := binary.BigEndian.Uint32(blob[:4])
	if n == 0 || uint64(n) >= uint64(len(blob)-4) || string(blob[4:4+n]) != parts[0] {
		return bad
	}
	return nil
}

// Cmdline is the exact measured cmdline (vm_measure.cmdline) for an identity.
func Cmdline(identityHex string) (string, error) {
	if !hex64RE.MatchString(identityHex) {
		return "", errors.New("identity sha256 invalid")
	}
	return strings.Replace(CmdlineTemplateV1, identityPlaceholder, identityHex, 1), nil
}

// IdentityFromProcCmdline returns the identity sha256 that /proc/cmdline
// names. It refuses any byte other than OVMF's prefix, the v1 cmdline and
// the one newline procfs adds.
func IdentityFromProcCmdline(proc string) (string, error) {
	bad := errors.New("measured cmdline differs from the v1 VM cmdline")
	line, ok := strings.CutPrefix(strings.TrimSuffix(proc, "\n"), ovmfPrefix)
	head := strings.TrimSuffix(CmdlineTemplateV1, identityPlaceholder)
	if !ok || len(line) != len(head)+64 || !strings.HasPrefix(line, head) {
		return "", bad
	}
	identityHex := line[len(head):]
	want, err := Cmdline(identityHex)
	if err != nil || want != line {
		return "", bad
	}
	return identityHex, nil
}

// Check is spec r3 7.2 step 1 without the report: the identity parses and
// its sha256 is the one the measured cmdline names. The caller then checks
// HostData() against a fresh boot-check report before any disk read.
func Check(identityRaw []byte, procCmdline string) (Identity, error) {
	id, err := Parse(identityRaw)
	if err != nil {
		return Identity{}, err
	}
	named, err := IdentityFromProcCmdline(procCmdline)
	if err != nil {
		return Identity{}, err
	}
	if id.SHA256Hex() != named {
		return Identity{}, errors.New("identity sha256 differs from cathedral.vm")
	}
	return id, nil
}
