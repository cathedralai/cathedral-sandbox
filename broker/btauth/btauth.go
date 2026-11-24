// Package btauth verifies btauth/1 requests signed by a Bittensor hotkey.
//
// It mirrors polariscomputer primitives/btauth.py (the API's verifier) check for
// check and in the same order: header shape, receiver, freshness, scheme,
// signature, replay. The signed bytes are the same eight lines, so a request
// the API accepts is accepted here and one it refuses is refused here. The
// shared vectors in testdata/btauth_vectors.json were signed on the Python side.
//
// Not wired into any route yet: this package only verifies.
package btauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ChainSafe/go-schnorrkel"
	"golang.org/x/crypto/blake2b"
)

const (
	Protocol = "btauth/1"
	Version  = "1"

	HeaderVersion   = "X-Bittensor-Version"
	HeaderHotkey    = "X-Bittensor-Hotkey"
	HeaderReceiver  = "X-Bittensor-Receiver"
	HeaderNonce     = "X-Bittensor-Nonce"
	HeaderCrypto    = "X-Bittensor-Crypto"
	HeaderSignature = "X-Bittensor-Signature"

	SR25519 = "sr25519"
	ED25519 = "ed25519"

	MaxAge          = 10 * time.Second
	AllowedSkew     = 2 * time.Second
	NonceRetention  = 30 * time.Second
	maxNonceDigits  = 25
	signatureLength = 64
)

// Error kinds, named as in btauth.py so the broker and the API refuse alike.
var (
	ErrMalformed       = errors.New("malformed_auth")
	ErrWrongReceiver   = errors.New("wrong_receiver")
	ErrStale           = errors.New("stale_request")
	ErrReplayed        = errors.New("replayed_request")
	ErrBadSignature    = errors.New("bad_signature")
	ErrUnsupported     = errors.New("unsupported_scheme")
	ErrProtectedSender = errors.New("protected_sender")
)

// AuthError carries the kind (for errors.Is) and a human message.
type AuthError struct {
	Kind    error
	Message string
}

func (e *AuthError) Error() string { return e.Kind.Error() + ": " + e.Message }
func (e *AuthError) Unwrap() error { return e.Kind }

func fail(kind error, msg string) error { return &AuthError{Kind: kind, Message: msg} }

// Caller is a verified sender.
type Caller struct {
	Hotkey   string
	Receiver string
	NonceNS  int64
	Scheme   string
}

// NonceStore remembers accepted (hotkey, nonce) pairs. CheckAndStore returns
// false when the pair was already accepted.
type NonceStore interface {
	CheckAndStore(hotkey string, nonceNS int64) bool
}

// MemoryNonceStore is a process-local store. A restart forgets it; the 10 s
// freshness window bounds what a restart can let through.
type MemoryNonceStore struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	retention time.Duration
	now       func() time.Time
}

func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{seen: map[string]time.Time{}, retention: NonceRetention, now: time.Now}
}

func (s *MemoryNonceStore) CheckAndStore(hotkey string, nonceNS int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, at := range s.seen {
		if now.Sub(at) > s.retention {
			delete(s.seen, k)
		}
	}
	key := hotkey + "\x00" + strconv.FormatInt(nonceNS, 10)
	if _, ok := s.seen[key]; ok {
		return false
	}
	s.seen[key] = now
	return true
}

// Verifier checks requests for a fixed set of receiving hotkeys.
type Verifier struct {
	Receivers map[string]bool
	Nonces    NonceStore
	// IsProtected reports whether the chain protects the sender from classical
	// signatures (btauth.py is_protected). Nil means no sender is protected.
	IsProtected func(hotkey string) (bool, error)
	Now         func() time.Time
}

// BuildPayload returns the exact signed bytes (btauth.py build_payload).
func BuildPayload(scheme, method, path string, body []byte, nonceNS int64, sender, receiver string) []byte {
	sum := sha256.Sum256(body)
	if receiver == "" {
		receiver = "-"
	}
	return []byte(strings.Join([]string{
		Protocol, scheme, strings.ToUpper(method), path, hex.EncodeToString(sum[:]),
		strconv.FormatInt(nonceNS, 10), sender, receiver,
	}, "\n"))
}

// Verify authenticates one request. path is the request target as received:
// the percent-encoded path plus "?" and the raw query when there is one.
func (v *Verifier) Verify(h http.Header, body []byte, method, path string) (*Caller, error) {
	if h.Get(HeaderVersion) != Version {
		return nil, fail(ErrMalformed, "missing or unsupported "+HeaderVersion)
	}
	sender := h.Get(HeaderHotkey)
	if sender == "" {
		return nil, fail(ErrMalformed, "missing "+HeaderHotkey)
	}
	rawNonce, hasNonce := header(h, HeaderNonce)
	if !hasNonce || !isDecimal(rawNonce) || len(rawNonce) > maxNonceDigits {
		return nil, fail(ErrMalformed, HeaderNonce+" is not a decimal integer")
	}
	nonce, err := strconv.ParseInt(rawNonce, 10, 64)
	if err != nil {
		// Python accepts any length up to 25 digits; a nonce past int64 is
		// centuries away and fails freshness there. Refuse it as stale here.
		return nil, fail(ErrStale, "nonce is more than 2s in the future")
	}
	scheme := SR25519
	if raw, ok := header(h, HeaderCrypto); ok {
		scheme = strings.ToLower(strings.TrimSpace(raw))
	}
	if scheme == "hashed" || scheme == "hashed-ed25519" {
		return nil, fail(ErrUnsupported, "hashed signature schemes are not accepted yet")
	}
	if scheme != SR25519 && scheme != ED25519 {
		return nil, fail(ErrMalformed, "unsupported "+HeaderCrypto)
	}
	rawSig, hasSig := header(h, HeaderSignature)
	if !hasSig {
		return nil, fail(ErrMalformed, "missing "+HeaderSignature)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(rawSig, "0x"))
	if err != nil {
		return nil, fail(ErrMalformed, HeaderSignature+" is not hex")
	}

	receiver := h.Get(HeaderReceiver)
	if receiver == "" {
		return nil, fail(ErrWrongReceiver, "missing "+HeaderReceiver)
	}
	if !v.Receivers[receiver] {
		return nil, fail(ErrWrongReceiver, "request was signed for a different receiving hotkey")
	}

	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	nowNS := now().UnixNano()
	if nowNS-nonce > int64(MaxAge) {
		return nil, fail(ErrStale, "nonce is older than the 10s window")
	}
	if nonce-nowNS > int64(AllowedSkew) {
		return nil, fail(ErrStale, "nonce is more than 2s in the future")
	}

	pub, err := SS58PublicKey(sender)
	if err != nil {
		return nil, fail(ErrMalformed, "invalid hotkey address")
	}
	if len(sig) != signatureLength {
		return nil, fail(ErrMalformed, "invalid signature encoding")
	}
	payload := BuildPayload(scheme, method, path, body, nonce, sender, receiver)
	ok, err := verifySignature(scheme, payload, sig, pub)
	if err != nil {
		return nil, fail(ErrMalformed, "invalid signature encoding")
	}
	if !ok {
		return nil, fail(ErrBadSignature, "signature does not verify against the claimed hotkey")
	}

	// After the signature, so an unsigned caller cannot make us read the chain;
	// before replay, so a protected sender's nonces are never stored.
	if v.IsProtected != nil {
		protected, err := v.IsProtected(sender)
		if err != nil {
			return nil, err
		}
		if protected {
			return nil, fail(ErrProtectedSender, "this hotkey only accepts hashed signatures")
		}
	}
	if v.Nonces == nil || !v.Nonces.CheckAndStore(sender, nonce) {
		return nil, fail(ErrReplayed, "this nonce was already accepted from this hotkey")
	}
	return &Caller{Hotkey: sender, Receiver: receiver, NonceNS: nonce, Scheme: scheme}, nil
}

func header(h http.Header, name string) (string, bool) {
	vals, ok := h[http.CanonicalHeaderKey(name)]
	if !ok || len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func verifySignature(scheme string, payload, sig []byte, pub [32]byte) (bool, error) {
	switch scheme {
	case SR25519:
		pk, err := schnorrkel.NewPublicKey(pub)
		if err != nil {
			return false, err
		}
		var sb [64]byte
		copy(sb[:], sig)
		s := new(schnorrkel.Signature)
		if err := s.Decode(sb); err != nil {
			return false, err
		}
		// The Substrate signing context, as sp_core and the Python sr25519 module use.
		return pk.Verify(s, schnorrkel.NewSigningContext([]byte("substrate"), payload))
	case ED25519:
		return ed25519.Verify(ed25519.PublicKey(pub[:]), payload, sig), nil
	}
	return false, fail(ErrUnsupported, "unsupported signature scheme")
}

const maxSS58Length = 50

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// SS58PublicKey decodes a 32-byte account address and checks its checksum
// (blake2b-512 over "SS58PRE" + prefix + key, first two bytes).
func SS58PublicKey(addr string) ([32]byte, error) {
	var key [32]byte
	// A 32-byte account is at most 50 Base58 characters (2-byte prefix). Refuse
	// longer input before decoding: Base58 decoding is quadratic in length.
	if len(addr) > maxSS58Length {
		return key, errors.New("address too long")
	}
	raw, err := base58Decode(addr)
	if err != nil {
		return key, err
	}
	prefixLen := 1
	if len(raw) > 0 && raw[0]&0x40 != 0 {
		prefixLen = 2
	}
	if len(raw) != prefixLen+32+2 {
		return key, errors.New("not a 32-byte account")
	}
	h, _ := blake2b.New512(nil)
	h.Write([]byte("SS58PRE"))
	h.Write(raw[:prefixLen+32])
	sum := h.Sum(nil)
	if sum[0] != raw[prefixLen+32] || sum[1] != raw[prefixLen+33] {
		return key, errors.New("bad ss58 checksum")
	}
	copy(key[:], raw[prefixLen:prefixLen+32])
	return key, nil
}

func base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty address")
	}
	out := []byte{}
	for _, c := range []byte(s) {
		idx := strings.IndexByte(base58Alphabet, c)
		if idx < 0 {
			return nil, errors.New("invalid base58")
		}
		carry := idx
		for i := len(out) - 1; i >= 0; i-- {
			carry += int(out[i]) * 58
			out[i] = byte(carry)
			carry >>= 8
		}
		for carry > 0 {
			out = append([]byte{byte(carry)}, out...)
			carry >>= 8
		}
	}
	for _, c := range []byte(s) {
		if c != '1' {
			break
		}
		out = append([]byte{0}, out...)
	}
	return out, nil
}
