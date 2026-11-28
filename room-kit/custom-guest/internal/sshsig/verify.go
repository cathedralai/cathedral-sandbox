// Package sshsig verifies one OpenSSH SSHSIG signature (PROTOCOL.sshsig) by a VM identity's
// ssh_public_key, with the standard library only (spec r3 7.5, r4 erratum 2.4, AB#1022). It is
// the guest's half of the signed re-wrap answer: the host writes the answer, so every byte here
// is untrusted, and the key is the one the measured identity names.
//
// The rules are narrower than OpenSSH's on purpose: hash sha512 only, rsa-sha2-512 only for RSA,
// a full-length RSA signature, minimal mpints, and the user-present bit for sk keys.
// tests/fixtures/vm_rewrap_answer_v2.json holds a case for each refusal.
package sshsig

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"math/big"
	"strings"
)

// Error is a refusal; its text is the code the shared vectors name.
type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrKey               = Error("key_format")
	ErrFormat            = Error("sshsig_format")
	ErrVersion           = Error("sshsig_version")
	ErrPublicKey         = Error("publickey_mismatch")
	ErrNamespace         = Error("namespace")
	ErrReserved          = Error("reserved")
	ErrHash              = Error("hash_algorithm")
	ErrSignatureType     = Error("signature_type")
	ErrSignatureEncoding = Error("signature_encoding")
	ErrUserPresence      = Error("sk_user_presence")
	ErrSignature         = Error("signature_invalid")
)

const (
	hashName    = "sha512"
	userPresent = 0x01
	skEd25519   = "sk-ssh-ed25519@openssh.com"
	skECDSA     = "sk-ecdsa-sha2-nistp256@openssh.com"
)

type curve struct {
	name  string
	curve elliptic.Curve
	hash  func() hash.Hash
}

var (
	p256 = curve{"nistp256", elliptic.P256(), sha256.New}
	p384 = curve{"nistp384", elliptic.P384(), sha512.New384}
	p521 = curve{"nistp521", elliptic.P521(), sha512.New}
)

// keyTypes must equal vmidentity's keyTypes: each key type with the one signature type it may use.
var keyTypes = map[string]struct {
	sigType string
	curve   *curve
}{
	"ssh-ed25519":         {"ssh-ed25519", nil},
	"ecdsa-sha2-nistp256": {"ecdsa-sha2-nistp256", &p256},
	"ecdsa-sha2-nistp384": {"ecdsa-sha2-nistp384", &p384},
	"ecdsa-sha2-nistp521": {"ecdsa-sha2-nistp521", &p521},
	"ssh-rsa":             {"rsa-sha2-512", nil},
	skEd25519:             {skEd25519, nil},
	skECDSA:               {skECDSA, &p256},
}

// reader takes SSH wire fields. A short read returns nil (or ok false) and empties the reader.
type reader struct {
	data []byte
}

func (r *reader) take(n int) []byte {
	if n < 0 || n > len(r.data) {
		r.data = nil
		return nil
	}
	out := r.data[:n]
	r.data = r.data[n:]
	return out
}

func (r *reader) uint32() (uint32, bool) {
	b := r.take(4)
	if b == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(b), true
}

// str reads one SSH string. ok is false on a short read.
func (r *reader) str() ([]byte, bool) {
	n, ok := r.uint32()
	if !ok || uint64(n) > uint64(len(r.data)) {
		r.data = nil
		return nil, false
	}
	return r.take(int(n)), true
}

// mpint reads a positive, minimally encoded SSH mpint: no leading zero byte unless the next
// byte's top bit is set, and never zero (an empty mpint).
func mpint(r *reader) (*big.Int, bool) {
	raw, ok := r.str()
	if !ok || len(raw) == 0 || raw[0]&0x80 != 0 || (raw[0] == 0 && (len(raw) == 1 || raw[1]&0x80 == 0)) {
		return nil, false
	}
	return new(big.Int).SetBytes(raw), true
}

func sshString(b []byte) []byte {
	out := binary.BigEndian.AppendUint32(nil, uint32(len(b)))
	return append(out, b...)
}

// SignedData is SSHSIG's signed data for message in namespace, with hash sha512.
func SignedData(namespace string, message []byte) []byte {
	digest := sha512.Sum512(message)
	out := []byte("SSHSIG")
	out = append(out, sshString([]byte(namespace))...)
	out = append(out, sshString(nil)...)
	out = append(out, sshString([]byte(hashName))...)
	return append(out, sshString(digest[:])...)
}

type publicKey struct {
	kind        string
	ed25519     ed25519.PublicKey
	ecdsa       *ecdsa.PublicKey
	rsa         *rsa.PublicKey
	application []byte
}

// parseKey reads a key line "type base64" (vmidentity.CheckSSHKey's form) into its blob and key.
func parseKey(line string) ([]byte, publicKey, error) {
	kind, text, ok := strings.Cut(line, " ")
	spec, known := keyTypes[kind]
	if !ok || !known {
		return nil, publicKey{}, ErrKey
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, publicKey{}, ErrKey
	}
	r := &reader{data: blob}
	if name, ok := r.str(); !ok || string(name) != kind {
		return nil, publicKey{}, ErrKey
	}
	key := publicKey{kind: kind}
	switch {
	case kind == "ssh-ed25519" || kind == skEd25519:
		raw, ok := r.str()
		if !ok || len(raw) != ed25519.PublicKeySize {
			return nil, publicKey{}, ErrKey
		}
		key.ed25519 = ed25519.PublicKey(bytes.Clone(raw))
	case spec.curve != nil:
		name, ok := r.str()
		point, ok2 := r.str()
		if !ok || !ok2 || string(name) != spec.curve.name {
			return nil, publicKey{}, ErrKey
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(spec.curve.curve, point)
		if err != nil { // also refuses a point that is not on the curve
			return nil, publicKey{}, ErrKey
		}
		key.ecdsa = pub
	default: // ssh-rsa
		e, ok := mpint(r)
		n, ok2 := mpint(r)
		if !ok || !ok2 || !e.IsInt64() || e.Int64() > 1<<31-1 || e.Bit(0) == 0 || e.Int64() < 3 {
			return nil, publicKey{}, ErrKey
		}
		if bits := n.BitLen(); bits < 2048 || bits > 8192 {
			return nil, publicKey{}, ErrKey
		}
		key.rsa = &rsa.PublicKey{N: n, E: int(e.Int64())}
	}
	if kind == skEd25519 || kind == skECDSA {
		app, ok := r.str()
		if !ok {
			return nil, publicKey{}, ErrKey
		}
		key.application = bytes.Clone(app)
	}
	if len(r.data) != 0 {
		return nil, publicKey{}, ErrKey
	}
	return blob, key, nil
}

// Verify returns nil only if blob is an SSHSIG by keyLine's key over message in namespace. The
// checks run in a fixed order, and the first failure is the result: the blob's form, then the
// public key it names (byte for byte the identity's, before any arithmetic), then the namespace,
// reserved field and hash, then the signature's own form, then the signature.
func Verify(keyLine, namespace string, message, blob []byte) error {
	identity, key, err := parseKey(keyLine)
	if err != nil {
		return err
	}
	r := &reader{data: blob}
	if magic := r.take(6); magic == nil || string(magic) != "SSHSIG" {
		return ErrFormat
	}
	version, ok := r.uint32()
	if !ok {
		return ErrFormat
	}
	if version != 1 {
		return ErrVersion
	}
	var fields [5][]byte
	for i := range fields {
		if fields[i], ok = r.str(); !ok {
			return ErrFormat
		}
	}
	if len(r.data) != 0 {
		return ErrFormat
	}
	pubBlob, ns, reserved, hashAlg, signature := fields[0], fields[1], fields[2], fields[3], fields[4]
	switch {
	case !bytes.Equal(pubBlob, identity):
		return ErrPublicKey
	case string(ns) != namespace:
		return ErrNamespace
	case len(reserved) != 0:
		return ErrReserved
	case string(hashAlg) != hashName:
		return ErrHash
	}
	return verifySignature(key, SignedData(namespace, message), signature)
}

func verifySignature(key publicKey, d, signature []byte) error {
	spec := keyTypes[key.kind]
	r := &reader{data: signature}
	sigType, ok := r.str()
	if !ok {
		return ErrSignatureEncoding
	}
	if string(sigType) != spec.sigType {
		return ErrSignatureType
	}
	inner, ok := r.str()
	if !ok {
		return ErrSignatureEncoding
	}
	// The inner signature's own form first, as the reference verifier orders it.
	var rr, ss *big.Int
	switch {
	case key.ed25519 != nil:
		if len(inner) != ed25519.SignatureSize {
			return ErrSignatureEncoding
		}
	case key.ecdsa != nil:
		ir := &reader{data: inner}
		var ok2 bool
		rr, ok = mpint(ir)
		ss, ok2 = mpint(ir)
		order := key.ecdsa.Curve.Params().N
		if !ok || !ok2 || len(ir.data) != 0 || rr.Cmp(order) >= 0 || ss.Cmp(order) >= 0 {
			return ErrSignatureEncoding
		}
	}
	data := d
	if key.kind == skEd25519 || key.kind == skECDSA {
		// The authenticator signs sha256(application) || flags || counter || sha256(D).
		tail := r.take(5)
		if tail == nil {
			return ErrSignatureEncoding
		}
		if tail[0]&userPresent == 0 {
			return ErrUserPresence
		}
		app, msg := sha256.Sum256(key.application), sha256.Sum256(d)
		data = append(append(append([]byte{}, app[:]...), tail...), msg[:]...)
	}
	if len(r.data) != 0 {
		return ErrSignatureEncoding
	}
	switch {
	case key.ed25519 != nil:
		if !ed25519.Verify(key.ed25519, data, inner) {
			return ErrSignature
		}
	case key.ecdsa != nil:
		h := spec.curve.hash
		if key.kind == skECDSA {
			h = sha256.New
		}
		digest := h()
		digest.Write(data)
		if !ecdsa.Verify(key.ecdsa, digest.Sum(nil), rr, ss) {
			return ErrSignature
		}
	default:
		if len(inner) != key.rsa.Size() {
			return ErrSignatureEncoding
		}
		digest := sha512.Sum512(data)
		if rsa.VerifyPKCS1v15(key.rsa, crypto.SHA512, digest[:], inner) != nil {
			return ErrSignature
		}
	}
	return nil
}
