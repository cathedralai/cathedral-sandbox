package vmmailbox

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type envelopeCase struct {
	VMPrivateHex       string `json:"vm_private_hex"`
	VMPublicB64        string `json:"vm_public_b64"`
	CustomerPrivateHex string `json:"customer_private_hex"`
	OfferSHA256        string `json:"offer_sha256"`
	RecoveryKeyHex     string `json:"recovery_key_hex"`
	SharedHex          string `json:"shared_hex"`
	WrappingKeyHex     string `json:"wrapping_key_hex"`
	Answer             map[string]string
}

// The fixture is this repo's own contract (scripts/make_vm_rewrap_envelope_vectors.py); it is
// committed, so a missing file is a failure.
func loadEnvelope(t *testing.T) []envelopeCase {
	t.Helper()
	raw, err := os.ReadFile("../../../../tests/fixtures/vm_rewrap_envelope_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		HKDFInfo string         `json:"hkdf_info"`
		Cases    []envelopeCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.HKDFInfo != rewrapInfo || len(f.Cases) < 2 {
		t.Fatal("fixture info or case count")
	}
	return f.Cases
}

func answerOf(t *testing.T, c envelopeCase) Answer {
	t.Helper()
	doc := map[string]string{"schema": AnswerSchema, "offer_sha256": c.Answer["offer_sha256"], "epk": c.Answer["epk"],
		"nonce": c.Answer["nonce"], "ct": c.Answer["ct"]}
	parsed, err := ParseBody(canonical(doc), KindAnswer)
	if err != nil {
		t.Fatal(err)
	}
	ans, ok := answerFrom(parsed)
	if !ok {
		t.Fatal("answer fields")
	}
	return ans
}

func TestEnvelopeOpensEveryPythonVector(t *testing.T) {
	for i, c := range loadEnvelope(t) {
		priv, err := ecdh.X25519().NewPrivateKey(mustHex(t, c.VMPrivateHex))
		if err != nil {
			t.Fatal(err)
		}
		if b64(priv.PublicKey().Bytes()) != c.VMPublicB64 {
			t.Fatalf("case %d: public key differs", i)
		}
		got, err := OpenAnswer(priv, c.OfferSHA256, answerOf(t, c))
		if err != nil || hex.EncodeToString(got) != c.RecoveryKeyHex {
			t.Fatalf("case %d: Python's envelope did not open: %v", i, err)
		}
	}
}

// The Go seal and the Python generator must produce the same bytes from the same keys, so the
// customer tool and the guest cannot drift apart in either direction.
func TestEnvelopeEqualsThePythonGenerator(t *testing.T) {
	for i, c := range loadEnvelope(t) {
		vm, _ := ecdh.X25519().NewPrivateKey(mustHex(t, c.VMPrivateHex))
		customer, _ := ecdh.X25519().NewPrivateKey(mustHex(t, c.CustomerPrivateHex))
		want := answerOf(t, c)
		got, err := sealAnswer(vm.PublicKey().Bytes(), customer, want.Nonce, c.OfferSHA256, mustHex(t, c.RecoveryKeyHex))
		if err != nil || got != want {
			t.Fatalf("case %d: Go seal differs from the Python generator", i)
		}
	}
}

func TestEnvelopeWrongAADOrEPKGivesNoKey(t *testing.T) {
	cases := loadEnvelope(t)
	a, b := cases[0], cases[1]
	priv, _ := ecdh.X25519().NewPrivateKey(mustHex(t, a.VMPrivateHex))
	ans := answerOf(t, a)
	// AAD of another offer: the answer names it, so the check passes the name and the tag fails.
	swapped := ans
	swapped.OfferSHA256 = b.OfferSHA256
	if k, err := OpenAnswer(priv, b.OfferSHA256, swapped); err == nil || k != nil {
		t.Fatal("another offer's AAD opened")
	}
	// Another case's epk.
	other := ans
	other.EPK = answerOf(t, b).EPK
	if k, err := OpenAnswer(priv, a.OfferSHA256, other); err == nil || k != nil {
		t.Fatal("a wrong epk opened")
	}
	// A forged ct.
	forged := ans
	forged.CT[47] ^= 0x80
	if k, err := OpenAnswer(priv, a.OfferSHA256, forged); err == nil || k != nil {
		t.Fatal("a forged ct opened")
	}
	// Any single flipped bit of ct or nonce is refused.
	for bit := 0; bit < 48*8; bit += 7 {
		m := ans
		m.CT[bit/8] ^= 1 << (bit % 8)
		if _, err := OpenAnswer(priv, a.OfferSHA256, m); err == nil {
			t.Fatalf("ct bit %d accepted", bit)
		}
	}
	m := ans
	m.Nonce[0] ^= 1
	if _, err := OpenAnswer(priv, a.OfferSHA256, m); err == nil {
		t.Fatal("a flipped nonce accepted")
	}
	// Salt sanity: the wrapping key of the fixture is reproduced from its shared secret.
	shared := mustHex(t, a.SharedHex)
	key := wrappingKey(shared, []byte(a.OfferSHA256), ans.EPK[:], priv.PublicKey().Bytes())
	if !bytes.Equal(key, mustHex(t, a.WrappingKeyHex)) {
		t.Fatal("the HKDF output differs from Python's")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
