package vmmailbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// rewrapInfo is the HKDF info of the re-wrap envelope (spec r3 errata, 27 Nov 14:44Z). The AAD,
// and the HKDF salt, is the offer's sha256 as 64 lowercase hex ASCII bytes.
const rewrapInfo = "cathedral.vm-rewrap.v1"

var errOpen = errors.New("vmmailbox: the answer does not open")

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.Strict().DecodeString(s) }

func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	prk := hmac.New(sha256.New, salt)
	prk.Write(ikm)
	key := prk.Sum(nil)
	var out, block []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, key)
		mac.Write(block)
		mac.Write(info)
		mac.Write([]byte{counter})
		block = mac.Sum(nil)
		out = append(out, block...)
	}
	return out[:length]
}

// wrappingKey follows room_receipts._wrapping_key (and broker/escape_nonce.go sealX25519Envelope):
// HKDF-SHA256, salt = AAD, info = info || ephemeral || recipient.
func wrappingKey(shared, aad, ephemeral, recipient []byte) []byte {
	info := append(append([]byte(rewrapInfo), ephemeral...), recipient...)
	return hkdfSHA256(shared, aad, info, 32)
}

// OpenAnswer opens the answer envelope with the offer's X25519 private key. It returns the 32
// byte recovery key R only if the tag verifies under this offer's sha256 as AAD. A forged ct,
// another epk or another offer gives an error and no bytes.
func OpenAnswer(private *ecdh.PrivateKey, offerSHA256 string, ans Answer) ([]byte, error) {
	if !hex64Re.MatchString(offerSHA256) || ans.OfferSHA256 != offerSHA256 {
		return nil, errOpen
	}
	epk, err := ecdh.X25519().NewPublicKey(ans.EPK[:])
	if err != nil {
		return nil, errOpen
	}
	shared, err := private.ECDH(epk)
	if err != nil { // crypto/ecdh refuses an all-zero shared secret (a low-order point)
		return nil, errOpen
	}
	aad := []byte(offerSHA256)
	key := wrappingKey(shared, aad, ans.EPK[:], private.PublicKey().Bytes())
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errOpen
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errOpen
	}
	plain, err := aead.Open(nil, ans.Nonce[:], ans.CT[:], aad)
	if err != nil || len(plain) != 32 {
		return nil, errOpen
	}
	return plain, nil
}

// sealAnswer is the customer tool's half, kept here only so tests can check both halves agree.
func sealAnswer(recipient []byte, ephemeral *ecdh.PrivateKey, nonce [12]byte, offerSHA256 string, secret []byte) (Answer, error) {
	pub, err := ecdh.X25519().NewPublicKey(recipient)
	if err != nil {
		return Answer{}, err
	}
	shared, err := ephemeral.ECDH(pub)
	if err != nil {
		return Answer{}, err
	}
	aad := []byte(offerSHA256)
	rawEph := ephemeral.PublicKey().Bytes()
	block, err := aes.NewCipher(wrappingKey(shared, aad, rawEph, recipient))
	if err != nil {
		return Answer{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Answer{}, err
	}
	ans := Answer{OfferSHA256: offerSHA256, Nonce: nonce}
	copy(ans.EPK[:], rawEph)
	copy(ans.CT[:], aead.Seal(nil, nonce[:], secret, aad))
	return ans, nil
}
