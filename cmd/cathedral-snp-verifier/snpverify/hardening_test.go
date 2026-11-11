package snpverify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestHasDebugFlag(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"\u001ccathedral.debug=1", true},
		{"a\u001fcathedral.debug=1 b", true},
		{"x cathedral.debug=1", true},
		{"x cathedral.debug=1", true},
		{"x cathedral.debug=1", true},
		{"cathedral.debug=1", true},
		{"cathedral.debug=10", false},
		{"xcathedral.debug=1", false},
		{"cathedral.debug=0", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := hasDebugFlag(tc.in); got != tc.want {
			t.Errorf("%q: got %v want %v", tc.in, got, tc.want)
		}
	}
}

func TestKernelCmdlineRules(t *testing.T) {
	t.Run("not a string", func(t *testing.T) {
		for _, v := range []any{nil, true, []any{}, map[string]any{}} {
			att := rebind(t, loadAtt(t, "attestation.json"), func(b map[string]any) { b["kernel_cmdline"] = v }, nil)
			_, err := VerifyAttestation(att, goodOpts(t))
			wantCode(t, err, CodeBadInput)
		}
	})
	t.Run("debug after a Python-only separator", func(t *testing.T) {
		att := rebind(t, loadAtt(t, "attestation.json"), func(b map[string]any) { b["kernel_cmdline"] = "a\u001fcathedral.debug=1" }, nil)
		_, err := VerifyAttestation(att, goodOpts(t))
		wantCode(t, err, CodeDebugEnabled)
	})
}

func setReport(t *testing.T, att Attestation, mut func([]byte)) Attestation {
	t.Helper()
	r, _ := base64.StdEncoding.DecodeString(att.ReportB64)
	mut(r)
	att.ReportB64 = base64.StdEncoding.EncodeToString(r)
	return att
}

func TestProduct(t *testing.T) {
	v2 := func(r []byte) { binary.LittleEndian.PutUint32(r[0:4], 2) }
	t.Run("version 2 report without product fails", func(t *testing.T) {
		att := setReport(t, loadAtt(t, "attestation.json"), v2)
		_, err := VerifyAttestation(att, goodOpts(t))
		wantCode(t, err, CodeUnsupportedProduct)
	})
	t.Run("version 2 report with product proceeds", func(t *testing.T) {
		att := setReport(t, loadAtt(t, "attestation.json"), v2)
		o := goodOpts(t)
		o.Product = "Genoa"
		_, err := VerifyAttestation(att, o)
		// Past the product check; the body edit then breaks the signature.
		wantCode(t, err, CodeReportSignature)
	})
	t.Run("unknown product string", func(t *testing.T) {
		o := goodOpts(t)
		o.Product = "Turin"
		_, err := VerifyAttestation(loadAtt(t, "attestation.json"), o)
		wantCode(t, err, CodeUnsupportedProduct)
	})
	t.Run("unknown family", func(t *testing.T) {
		att := setReport(t, loadAtt(t, "attestation.json"), func(r []byte) { r[0x188] = 0x17 })
		_, err := VerifyAttestation(att, goodOpts(t))
		wantCode(t, err, CodeUnsupportedProduct)
	})
	t.Run("lower case product is not accepted", func(t *testing.T) {
		_, err := product(Report{}, "genoa")
		wantCode(t, err, CodeUnsupportedProduct)
	})
	t.Run("family and model map", func(t *testing.T) {
		for _, c := range []struct {
			fam, mod uint8
			want     string
		}{{0x19, 0x10, "Genoa"}, {0x19, 0x11, "Genoa"}, {0x19, 0x01, "Milan"}, {0x19, 0x0f, "Milan"}} {
			got, err := product(Report{HasCPUID: true, Family: c.fam, Model: c.mod}, "")
			if err != nil || got != c.want {
				t.Fatalf("%x/%x: %q %v", c.fam, c.mod, got, err)
			}
		}
	})
	t.Run("real report reads as Genoa", func(t *testing.T) {
		res, err := VerifyAttestation(loadAtt(t, "attestation.json"), goodOpts(t))
		if err != nil || res.AMD.Product != "Genoa" {
			t.Fatalf("%v %+v", err, res.AMD)
		}
	})
}

func TestCorruptARKSignature(t *testing.T) {
	o := goodOpts(t)
	ark := append([]byte(nil), o.ARK...)
	ark[len(ark)-1] ^= 1
	o.ARK = ark
	_, err := VerifyAttestation(loadAtt(t, "attestation.json"), o)
	wantCode(t, err, CodeARKSignature)
}

func TestParseReceiptsDocumentShapes(t *testing.T) {
	good := string(readFile(t, "testdata/receipts-first5.json"))
	inner := good[len(`{"receipts":`) : len(good)-2] // the array text
	tests := []struct {
		name, doc, code string
	}{
		{"number", `{"receipts":123}`, CodeReceiptMalformed},
		{"string", `"x"`, CodeReceiptMalformed},
		{"null", `null`, CodeReceiptMalformed},
		{"object without receipts", `{}`, CodeReceiptMalformed},
		{"receipts null", `{"receipts":null}`, CodeReceiptMalformed},
		{"head empty string", `{"head":"","receipts":[]}`, CodeReceiptMalformed},
		{"head number", `{"head":7,"receipts":[]}`, CodeReceiptMalformed},
		{"head null", `{"head":null,"receipts":[]}`, CodeReceiptMalformed},
		{"filtered not boolean", `{"filtered":"yes","receipts":[]}`, CodeReceiptMalformed},
		{"filtered null", `{"filtered":null,"receipts":[]}`, CodeReceiptMalformed},
		{"head bad even when filtered", `{"filtered":true,"head":"","receipts":[]}`, CodeReceiptMalformed},
		{"receipt not an object", `[1]`, CodeReceiptMalformed},
		{"statement missing", `[{"receipt_sha256":"a","signature_b64":"b"}]`, CodeReceiptMalformed},
		{"receipt_sha256 number", `[{"receipt_sha256":1,"signature_b64":"b","statement":{}}]`, CodeReceiptMalformed},
		{"signature missing", `[{"receipt_sha256":"a","statement":{}}]`, CodeReceiptMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseReceipts([]byte(tc.doc))
			wantCode(t, err, tc.code)
		})
	}
	t.Run("list and head semantics", func(t *testing.T) {
		rcs, head, err := ParseReceipts([]byte(inner))
		if err != nil || len(rcs) != 5 || head != "" {
			t.Fatalf("%v %d %q", err, len(rcs), head)
		}
		_, head, err = ParseReceipts([]byte(`{"head":"abc","receipts":[]}`))
		if err != nil || head != "abc" {
			t.Fatalf("%v %q", err, head)
		}
		_, head, err = ParseReceipts([]byte(`{"filtered":true,"head":"abc","receipts":[]}`))
		if err != nil || head != "" {
			t.Fatalf("filtered must drop the head: %v %q", err, head)
		}
	})
}

func TestStatementFieldTypes(t *testing.T) {
	att := loadAtt(t, "attestation.json")
	mutate := map[string]func(map[string]any){
		"binding_sha256 number": func(s map[string]any) { s["binding_sha256"] = 1 },
		"previous missing":      func(s map[string]any) { delete(s, "previous_receipt_sha256") },
		"previous null":         func(s map[string]any) { s["previous_receipt_sha256"] = nil },
		"action number":         func(s map[string]any) { s["action"] = 5 },
		"sequence missing":      func(s map[string]any) { delete(s, "sequence") },
		"sequence zero":         func(s map[string]any) { s["sequence"] = jsonNumber("0") },
		"sequence negative":     func(s map[string]any) { s["sequence"] = jsonNumber("-1") },
		"sequence float":        func(s map[string]any) { s["sequence"] = jsonNumber("1.0") },
		"sequence beyond int64": func(s map[string]any) { s["sequence"] = jsonNumber("9223372036854775808") },
		"sequence string":       func(s map[string]any) { s["sequence"] = "1" },
	}
	for name, mut := range mutate {
		t.Run(name, func(t *testing.T) {
			rcs, _ := loadReceipts(t, "receipts-first5.json")
			mut(rcs[0].Statement)
			_, err := VerifyReceipts(att, rcs, "")
			wantCode(t, err, CodeReceiptMalformed)
		})
	}
	t.Run("empty binding sha", func(t *testing.T) {
		rcs, _ := loadReceipts(t, "receipts-first5.json")
		empty := att
		empty.BindingSHA256 = ""
		_, err := VerifyReceipts(empty, rcs, "")
		wantCode(t, err, CodeBadInput)
	})
}

func TestReceiptHeaderAlphabet(t *testing.T) {
	rcs, _ := loadReceipts(t, "receipts-first5.json")
	canon, _ := Canonical(map[string]any{"statement": rcs[0].Statement, "receipt_sha256": rcs[0].ReceiptSHA256, "signature_b64": rcs[0].SignatureB64})
	padded := base64.URLEncoding.EncodeToString(canon)
	unpadded := strings.TrimRight(padded, "=")
	for _, h := range []string{padded, unpadded} {
		if _, err := DecodeReceiptHeader(h); err != nil {
			t.Fatalf("valid header refused: %v", err)
		}
	}
	bad := map[string]string{
		"leading space":    " " + unpadded,
		"trailing space":   unpadded + " ",
		"trailing newline": unpadded + "\n",
		"inner newline":    unpadded[:8] + "\n" + unpadded[8:],
		"non ascii":        unpadded[:8] + "é" + unpadded[8:],
		"plus":             unpadded[:8] + "+" + unpadded[8:],
		"slash":            unpadded[:8] + "/" + unpadded[8:],
		"padding mid":      unpadded[:8] + "=" + unpadded[8:],
		"three pads":       "QQ===",
		"pad wrong length": unpadded + "=",
	}
	for name, h := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeReceiptHeader(h)
			wantCode(t, err, CodeReceiptMalformed)
		})
	}
}

// Python parses 1E5 as the float 100000.0 and prints it that way; this
// checker keeps the literal, so such a receipt fails here (stricter, by design).
func TestNumberSpellingsPythonRewrites(t *testing.T) {
	v, err := ParseKeepingNumbers([]byte(`[1e5,1.50,1E5]`))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Canonical(v)
	if string(got) != `[1e5,1.50,1E5]` {
		t.Fatalf("literals changed: %s", got)
	}
	att := loadAtt(t, "attestation.json")
	b := att.BindingSHA256
	// Python canonical: {"action":"exec",...,"m":1.5,"n":100000.0,...} computed with python3 json.dumps.
	const pythonHash = "ac88fd58dc1baf908f44697b07e6e67d5f3f550cc21741b7506856b8c72a8e28"
	doc := `[{"receipt_sha256":"` + pythonHash + `","signature_b64":"AA==","statement":{"action":"exec","binding_sha256":"` + b +
		`","m":1.50,"n":1E5,"previous_receipt_sha256":"` + b + `","sequence":1}}]`
	rcs, _, err := ParseReceipts([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyReceipts(att, rcs, "")
	wantCode(t, err, CodeReceiptHashMismatch)
	// Sanity: the stored hash really is sha256 of the Python bytes.
	py := `{"action":"exec","binding_sha256":"` + b + `","m":1.5,"n":100000.0,"previous_receipt_sha256":"` + b + `","sequence":1}`
	sum := sha256.Sum256([]byte(py))
	if hex.EncodeToString(sum[:]) != pythonHash {
		t.Fatal("python hash literal does not match the python bytes")
	}
}
