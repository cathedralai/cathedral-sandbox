package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cathedralai/cathedralconfidential/cmd/cathedral-snp-verifier/snpverify"
)

const (
	genoaPin = "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1"
	milanPin = "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd"
)

func cliArgs(extra ...string) []string {
	base := []string{"--attestation", "snpverify/testdata/attestation-proof.json", "--ark", "snpverify/testdata/amd/ark.der",
		"--ask", "snpverify/testdata/amd/ask.der", "--vcek", "snpverify/testdata/amd/vcek.der"}
	return append(base, extra...)
}

func TestCLI(t *testing.T) {
	var out, errb bytes.Buffer
	code := run(cliArgs("--ark-sha256", genoaPin, "--receipts", "snpverify/testdata/receipts-first5.json"), &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	var v struct {
		Verdict  string
		Receipts int
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || v.Verdict != "PASS" || v.Receipts != 5 {
		t.Fatalf("%v %s", err, out.String())
	}

	out.Reset()
	code = run(cliArgs("--ark-sha256", milanPin), &out, &errb)
	var f struct{ Verdict, Code string }
	json.Unmarshal(out.Bytes(), &f)
	if code != 1 || f.Verdict != "FAIL" || f.Code != snpverify.CodeARKNotPinned {
		t.Fatalf("exit %d %s", code, out.String())
	}

	out.Reset()
	code = run(cliArgs(), &out, &errb) // no pin
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if run([]string{"--bogus"}, &out, &errb) != 2 {
		t.Fatal("unknown flag must exit 2")
	}
}

func TestCLIPositionalAndFlags(t *testing.T) {
	var out, errb bytes.Buffer
	args := cliArgs("--ark-sha256", genoaPin, "--receipts", "snpverify/testdata/receipts-first5.json")
	// A stray word stops flag parsing: the wrong measurement after it must not be silently dropped.
	code := run(append(append([]string{}, args...), "junk", "--expected-measurement", "00"), &out, &errb)
	if code != 2 || out.Len() != 0 {
		t.Fatalf("exit %d out %s", code, out.String())
	}

	out.Reset()
	code = run(args, &out, &errb)
	var v struct {
		Verdict            string
		MeasurementChecked *bool `json:"measurement_checked"`
		ReceiptsChecked    *bool `json:"receipts_checked"`
	}
	json.Unmarshal(out.Bytes(), &v)
	if code != 0 || v.MeasurementChecked == nil || *v.MeasurementChecked || v.ReceiptsChecked == nil || !*v.ReceiptsChecked {
		t.Fatalf("exit %d %s", code, out.String())
	}

	out.Reset()
	code = run(cliArgs("--ark-sha256", genoaPin, "--require-measurement"), &out, &errb)
	var f struct{ Verdict, Code string }
	json.Unmarshal(out.Bytes(), &f)
	if code != 1 || f.Code != snpverify.CodeNoExpectedMeasurement {
		t.Fatalf("exit %d %s", code, out.String())
	}

	out.Reset()
	code = run(cliArgs("--ark-sha256", genoaPin, "--expected-measurement", "00"), &out, &errb)
	json.Unmarshal(out.Bytes(), &f)
	if code != 1 || f.Code != snpverify.CodeMeasurementNotAllowed {
		t.Fatalf("exit %d %s", code, out.String())
	}

	out.Reset()
	code = run(cliArgs("--ark-sha256", genoaPin, "--product", "Turin"), &out, &errb)
	json.Unmarshal(out.Bytes(), &f)
	if code != 1 || f.Code != snpverify.CodeUnsupportedProduct {
		t.Fatalf("exit %d %s", code, out.String())
	}
}

func TestCLIMeasurementFlags(t *testing.T) {
	const good = "631d0410eace72dcdd26cf086f5e03715cefdcb871e0ed8cdb9dcff364db9d572ebb571b71e68264b183386ee4992dfc"
	bad := strings.Repeat("0", 96)
	pin := cliArgs("--ark-sha256", genoaPin)
	type verdictOut struct {
		Verdict            string
		Code               string
		MeasurementChecked bool `json:"measurement_checked"`
	}
	runWith := func(extra ...string) (int, verdictOut, string) {
		var out, errb bytes.Buffer
		code := run(append(append([]string{}, pin...), extra...), &out, &errb)
		var v verdictOut
		json.Unmarshal(out.Bytes(), &v)
		return code, v, errb.String()
	}
	if code, _, _ := runWith("--expected-measurement", good, "--expected-measurement", bad); code != 2 {
		t.Fatalf("a repeated --expected-measurement must exit 2, got %d", code)
	}
	if code, _, _ := runWith("--expected-measurement", bad, "--expected-measurement", good); code != 2 {
		t.Fatalf("a repeated --expected-measurement must exit 2, got %d", code)
	}
	if code, v, _ := runWith("--expected-measurement", good); code != 0 || !v.MeasurementChecked {
		t.Fatalf("%d %+v", code, v)
	}
	if code, v, _ := runWith("--allowed-measurement", bad, "--allowed-measurement", good); code != 0 || !v.MeasurementChecked {
		t.Fatalf("%d %+v", code, v)
	}
	if code, v, _ := runWith("--allowed-measurement", bad); code != 1 || v.Code != snpverify.CodeMeasurementNotAllowed {
		t.Fatalf("%d %+v", code, v)
	}
	if code, v, _ := runWith("--require-measurement", "--allowed-measurement", good); code != 0 || !v.MeasurementChecked {
		t.Fatalf("%d %+v", code, v)
	}
	if code, _, _ := runWith("--expected-measurement", good, "--allowed-measurement", good); code != 2 {
		t.Fatalf("both flags must exit 2, got %d", code)
	}
	if code, _, _ := runWith("--head", good); code != 2 {
		t.Fatalf("--head no longer exists, got %d", code)
	}
}
