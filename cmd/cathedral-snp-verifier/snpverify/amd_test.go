package snpverify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestRequireP384(t *testing.T) {
	gen := func(c elliptic.Curve) *ecdsa.PublicKey {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return &k.PublicKey
	}
	if err := requireP384(gen(elliptic.P384()), true); err != nil {
		t.Fatal(err)
	}
	wantCode(t, requireP384(gen(elliptic.P256()), true), CodeReportSignature)
	wantCode(t, requireP384(nil, false), CodeReportSignature)
}
