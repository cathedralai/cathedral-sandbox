package snpverify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func loadReceipts(t testing.TB, name string) ([]Receipt, string) {
	t.Helper()
	rcs, head, err := ParseReceipts(readFile(t, "testdata/"+name))
	if err != nil {
		t.Fatal(err)
	}
	return rcs, head
}

func TestReceiptHashCrossCheck(t *testing.T) {
	for _, name := range []string{"receipts-first5.json", "openenv-echo.receipts.json"} {
		rcs, _ := loadReceipts(t, name)
		if len(rcs) == 0 {
			t.Fatalf("%s: no receipts", name)
		}
		for _, rc := range rcs {
			canon, err := Canonical(rc.Statement)
			if err != nil {
				t.Fatal(err)
			}
			if got := sha256Hex(canon); got != rc.ReceiptSHA256 {
				t.Fatalf("%s: recomputed %s, stored %s", name, got, rc.ReceiptSHA256)
			}
		}
	}
}

func TestVerifyReceiptsPositive(t *testing.T) {
	// The library file holds one room's receipts, cut from a longer chain: they
	// verify one by one but are neither contiguous nor start at 1.
	tests := []struct {
		receipts, att string
		wholeFromOne  bool
	}{
		{"receipts-first5.json", "attestation-proof.json", true},
		{"openenv-echo.receipts.json", "attestation-library.json", false},
	}
	for _, tc := range tests {
		t.Run(tc.receipts, func(t *testing.T) {
			rcs, _ := loadReceipts(t, tc.receipts)
			att := loadAtt(t, tc.att)
			res, err := VerifyReceipts(att, rcs, "")
			if err != nil {
				t.Fatal(err)
			}
			if res.Receipts != len(rcs) || res.SignaturesOK != len(rcs) {
				t.Fatalf("unexpected %+v", res)
			}
			if !tc.wholeFromOne {
				if res.Contiguous {
					t.Fatalf("expected a gapped slice, got %+v", res)
				}
				return
			}
			if !res.Contiguous || *res.First != 1 || res.LinksChecked != len(rcs) {
				t.Fatalf("unexpected %+v", res)
			}
			if _, err := VerifyReceipts(att, rcs, rcs[len(rcs)-1].ReceiptSHA256); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifyReceiptsFailures(t *testing.T) {
	att := loadAtt(t, "attestation-proof.json")
	t.Run("statement field changed", func(t *testing.T) {
		rcs, _ := loadReceipts(t, "receipts-first5.json")
		rcs[2].Statement["action"] = "delete"
		_, err := VerifyReceipts(att, rcs, "")
		wantCode(t, err, CodeReceiptHashMismatch)
	})
	t.Run("signature byte flipped", func(t *testing.T) {
		rcs, _ := loadReceipts(t, "receipts-first5.json")
		sig, _ := base64.StdEncoding.DecodeString(rcs[1].SignatureB64)
		sig[10] ^= 1
		rcs[1].SignatureB64 = base64.StdEncoding.EncodeToString(sig)
		_, err := VerifyReceipts(att, rcs, "")
		wantCode(t, err, CodeReceiptSignature)
	})
	t.Run("receipts of another binding", func(t *testing.T) {
		rcs, _ := loadReceipts(t, "receipts-first5.json")
		other := rebind(t, loadAtt(t, "attestation-proof.json"), func(b map[string]any) { b["hotel"] = "other" }, nil)
		_, err := VerifyReceipts(other, rcs, "")
		wantCode(t, err, CodeReceiptBindingMismatch)
	})
	t.Run("receipt 3 removed with a head", func(t *testing.T) {
		rcs, _ := loadReceipts(t, "receipts-first5.json")
		head := rcs[4].ReceiptSHA256
		cut := append(append([]Receipt{}, rcs[:2]...), rcs[3:]...)
		_, err := VerifyReceipts(att, cut, head)
		wantCode(t, err, CodeChainGap)
	})
	t.Run("receipt 3 removed without a head is not contiguous", func(t *testing.T) {
		rcs, _ := loadReceipts(t, "receipts-first5.json")
		cut := append(append([]Receipt{}, rcs[:2]...), rcs[3:]...)
		res, err := VerifyReceipts(att, cut, "")
		if err != nil || res.Contiguous {
			t.Fatalf("err %v contiguous %v", err, res.Contiguous)
		}
	})
	t.Run("chain does not end at head", func(t *testing.T) {
		rcs, _ := loadReceipts(t, "receipts-first5.json")
		_, err := VerifyReceipts(att, rcs, rcs[3].ReceiptSHA256)
		wantCode(t, err, CodeChainHead)
	})
	t.Run("chain not starting at 1 with a head", func(t *testing.T) {
		rcs, _ := loadReceipts(t, "receipts-first5.json")
		_, err := VerifyReceipts(att, rcs[1:], rcs[4].ReceiptSHA256)
		wantCode(t, err, CodeChainGap)
	})
	t.Run("empty chain, head is not the binding", func(t *testing.T) {
		_, err := VerifyReceipts(att, nil, "abc")
		wantCode(t, err, CodeChainHead)
	})
	t.Run("empty chain, head is the binding", func(t *testing.T) {
		if _, err := VerifyReceipts(att, nil, att.BindingSHA256); err != nil {
			t.Fatal(err)
		}
	})
}

// signedChain builds a chain with a throwaway key: links cannot be broken
// on the real fixtures without the hotel's private key.
func signedChain(t *testing.T, links func(i int, prevHash string) string) (Attestation, []Receipt) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	binding := map[string]any{"receipt_key_ed25519_b64": base64.StdEncoding.EncodeToString(pub), "schema": SealedBindingSchema}
	canon, _ := Canonical(binding)
	att := Attestation{Binding: binding, BindingSHA256: sha256Hex(canon)}
	prev := att.BindingSHA256
	var rcs []Receipt
	for i := 1; i <= 3; i++ {
		st := map[string]any{
			"action": "exec", "binding_sha256": att.BindingSHA256, "sequence": json.Number(string(rune('0' + i))),
			"previous_receipt_sha256": links(i, prev),
		}
		c, _ := Canonical(st)
		rc := Receipt{Statement: st, ReceiptSHA256: sha256Hex(c), SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, c))}
		rcs = append(rcs, rc)
		prev = rc.ReceiptSHA256
	}
	return att, rcs
}

func TestSyntheticChain(t *testing.T) {
	good := func(i int, prev string) string { return prev }
	att, rcs := signedChain(t, good)
	res, err := VerifyReceipts(att, rcs, rcs[2].ReceiptSHA256)
	if err != nil || res.LinksChecked != 3 || !res.Contiguous {
		t.Fatalf("good chain: %v %+v", err, res)
	}
	att, rcs = signedChain(t, func(i int, prev string) string {
		if i == 2 {
			return "00"
		}
		return prev
	})
	_, err = VerifyReceipts(att, rcs, "")
	wantCode(t, err, CodeChainLink)
	att, rcs = signedChain(t, func(i int, prev string) string {
		if i == 1 {
			return "00"
		}
		return prev
	})
	_, err = VerifyReceipts(att, rcs, "")
	wantCode(t, err, CodeChainLink)
	// Duplicate sequence: the later receipt wins in the map, as in Python.
	att, rcs = signedChain(t, good)
	if _, err = VerifyReceipts(att, append(rcs, rcs[2]), ""); err != nil {
		t.Fatal(err)
	}
	// Malformed: no integer sequence.
	rcs[0].Statement["sequence"] = "1"
	_, err = VerifyReceipts(att, rcs, "")
	wantCode(t, err, CodeReceiptMalformed)
}

func TestDecodeReceiptHeader(t *testing.T) {
	rcs, _ := loadReceipts(t, "receipts-first5.json")
	rc := rcs[0]
	canon, err := Canonical(map[string]any{"statement": rc.Statement, "receipt_sha256": rc.ReceiptSHA256, "signature_b64": rc.SignatureB64})
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{base64.URLEncoding.EncodeToString(canon), base64.RawURLEncoding.EncodeToString(canon)} {
		got, err := DecodeReceiptHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyReceipts(loadAtt(t, "attestation-proof.json"), []Receipt{got}, ""); err != nil {
			t.Fatal(err)
		}
	}
	_, err = DecodeReceiptHeader("!!!")
	wantCode(t, err, CodeReceiptMalformed)
}

func jsonNumber(s string) json.Number { return json.Number(s) }
