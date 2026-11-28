package vmidentity

import (
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strings"
)

// RewrapKeyMax bounds the key blob: every key within it signs a re-wrap answer of at most 4096
// bytes (spec r4 erratum 2.5, AB#1022).
const RewrapKeyMax = 1100

// RewrapKeyError is a key the re-wrap cannot use; its text is the code
// tests/fixtures/vm_ssh_key_shapes_v1.json names.
type RewrapKeyError string

func (e RewrapKeyError) Error() string { return string(e) }

var ecPointBytes = map[string]int{"nistp256": 65, "nistp384": 97, "nistp521": 133}

// CheckRewrapKey is vm_measure.rewrap_key_shape: nil if the identity's key can sign a re-wrap
// answer the guest verifies within 4096 bytes. key is CheckSSHKey's "type base64".
//
// It is not part of CheckSSHKey or Parse, which every boot runs: a VM made before the create
// check must keep booting. The init calls it on the re-wrap path only, before it writes an
// offer (PR C), and an out-of-shape key ends that path with rewrap_key_unsupported.
func CheckRewrapKey(key string) error {
	kind, text, ok := strings.Cut(key, " ")
	blob, err := base64.StdEncoding.Strict().DecodeString(text)
	if !ok || err != nil {
		return RewrapKeyError("key_format")
	}
	// The checks run in rewrap_key_shape's order, so both give the same code for any key.
	if len(blob) > RewrapKeyMax {
		return RewrapKeyError("key_blob_too_long")
	}
	r := &keyReader{data: blob}
	if name, ok := r.str(); !ok || !keyTypes[kind] || string(name) != kind {
		return RewrapKeyError("key_format")
	}
	switch {
	case kind == "ssh-ed25519" || kind == "sk-ssh-ed25519@openssh.com":
		if raw, ok := r.str(); !ok {
			return RewrapKeyError("key_format")
		} else if len(raw) != 32 {
			return RewrapKeyError("ed25519_key")
		}
	case kind == "ssh-rsa":
		e, ok := r.mpint()
		if !ok {
			return RewrapKeyError("rsa_exponent")
		}
		n, ok := r.mpint()
		if !ok {
			return RewrapKeyError("key_format")
		}
		if e.Bit(0) == 0 || e.Cmp(big.NewInt(3)) < 0 || e.BitLen() > 31 {
			return RewrapKeyError("rsa_exponent")
		}
		if bits := n.BitLen(); bits < 2048 || bits > 8192 {
			return RewrapKeyError("rsa_modulus_bits")
		}
	default: // ECDSA and sk-ECDSA
		curve := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(kind, "sk-"), "ecdsa-sha2-"), "@openssh.com")
		name, ok := r.str()
		if !ok {
			return RewrapKeyError("key_format")
		}
		if string(name) != curve {
			return RewrapKeyError("ecdsa_curve")
		}
		point, ok := r.str()
		if !ok {
			return RewrapKeyError("key_format")
		}
		if len(point) != ecPointBytes[curve] || point[0] != 4 {
			return RewrapKeyError("ecdsa_point")
		}
	}
	if strings.HasPrefix(kind, "sk-") {
		if _, ok := r.str(); !ok { // the application
			return RewrapKeyError("key_format")
		}
	}
	if len(r.data) != 0 {
		return RewrapKeyError("key_trailing")
	}
	return nil
}

type keyReader struct{ data []byte }

func (r *keyReader) str() ([]byte, bool) {
	if len(r.data) < 4 {
		return nil, false
	}
	n := binary.BigEndian.Uint32(r.data)
	if uint64(n) > uint64(len(r.data)-4) {
		return nil, false
	}
	out := r.data[4 : 4+n]
	r.data = r.data[4+n:]
	return out, true
}

// mpint reads a positive, minimally encoded SSH mpint.
func (r *keyReader) mpint() (*big.Int, bool) {
	raw, ok := r.str()
	if !ok || len(raw) == 0 || raw[0]&0x80 != 0 || (raw[0] == 0 && (len(raw) == 1 || raw[1]&0x80 == 0)) {
		return nil, false
	}
	return new(big.Int).SetBytes(raw), true
}
