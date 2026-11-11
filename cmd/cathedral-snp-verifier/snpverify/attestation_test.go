package snpverify

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
)

const (
	genoaPin = "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1" // from amd-verify.mjs
	milanPin = "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd" // from amd-verify.mjs
)

func readFile(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadAtt(t testing.TB, name string) Attestation {
	t.Helper()
	att, err := ParseAttestation(readFile(t, "testdata/"+name))
	if err != nil {
		t.Fatal(err)
	}
	return att
}

func goodOpts(t testing.TB) Options {
	t.Helper()
	ark := readFile(t, "testdata/amd/ark.der")
	return Options{
		ARK: ark, ASK: readFile(t, "testdata/amd/ask.der"), VCEK: readFile(t, "testdata/amd/vcek.der"),
		ARKPins: []string{sha256Hex(ark)},
	}
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("want code %s, got %v", code, err)
	}
	if ve.Code() != code {
		t.Fatalf("want code %s, got %s (%s)", code, ve.Code(), ve.Detail)
	}
}

// rebind mutates the binding and the report, then recomputes binding_sha256 and
// REPORT_DATA so the early checks pass and the mutated field is the one that fails.
func rebind(t *testing.T, att Attestation, mutBinding func(map[string]any), mutReport func([]byte)) Attestation {
	t.Helper()
	report, err := base64.StdEncoding.DecodeString(att.ReportB64)
	if err != nil {
		t.Fatal(err)
	}
	if mutBinding != nil {
		mutBinding(att.Binding)
	}
	if mutReport != nil {
		mutReport(report)
	}
	canon, err := Canonical(att.Binding)
	if err != nil {
		t.Fatal(err)
	}
	att.BindingSHA256 = sha256Hex(canon)
	raw, _ := hex.DecodeString(att.BindingSHA256)
	copy(report[0x50:0x90], raw)
	for i := 0x70; i < 0x90; i++ {
		report[i] = 0
	}
	att.ReportB64 = base64.StdEncoding.EncodeToString(report)
	return att
}

func flipReport(t *testing.T, att Attestation, offset int) Attestation {
	t.Helper()
	report, _ := base64.StdEncoding.DecodeString(att.ReportB64)
	report[offset] ^= 0x01
	att.ReportB64 = base64.StdEncoding.EncodeToString(report)
	return att
}

func TestARKPinIsKnownAMDRoot(t *testing.T) {
	pin := sha256Hex(readFile(t, "testdata/amd/ark.der"))
	if pin != genoaPin && pin != milanPin {
		t.Fatalf("ark.der sha256 %s is neither the Genoa nor the Milan pin", pin)
	}
}

func TestVerifyAttestationPositive(t *testing.T) {
	for _, name := range []string{"attestation.json", "attestation-library.json"} {
		t.Run(name, func(t *testing.T) {
			att := loadAtt(t, name)
			opts := goodOpts(t)
			opts.RequireMeasurement = true
			opts.ExpectedMeasurements = []string{att.Binding["measurement"].(string)}
			res, err := VerifyAttestation(att, opts)
			if err != nil {
				t.Fatal(err)
			}
			if res.AMD == nil || res.AMD.ARKSHA256 != opts.ARKPins[0] || res.Measurement != att.Binding["measurement"] {
				t.Fatalf("unexpected result %+v", res)
			}
		})
	}
}

func TestVerifyAttestationFailures(t *testing.T) {
	genuine := "attestation.json"
	tests := []struct {
		name string
		code string
		prep func(t *testing.T) (Attestation, Options)
	}{
		{"flipped byte in report body", CodeReportSignature, func(t *testing.T) (Attestation, Options) {
			return flipReport(t, loadAtt(t, genuine), 0x100), goodOpts(t)
		}},
		{"flipped byte in report signature", CodeReportSignature, func(t *testing.T) (Attestation, Options) {
			return flipReport(t, loadAtt(t, genuine), 0x2A0+3), goodOpts(t)
		}},
		{"report data flipped", CodeReportData, func(t *testing.T) (Attestation, Options) {
			return flipReport(t, loadAtt(t, genuine), 0x50), goodOpts(t)
		}},
		{"binding field changed", CodeBindingHashMismatch, func(t *testing.T) (Attestation, Options) {
			att := loadAtt(t, genuine)
			att.Binding["hotel"] = "other"
			return att, goodOpts(t)
		}},
		{"wrong ARK pin", CodeARKNotPinned, func(t *testing.T) (Attestation, Options) {
			o := goodOpts(t)
			o.ARKPins = []string{milanPin}
			return loadAtt(t, genuine), o
		}},
		{"no ARK pin", CodeARKNotPinned, func(t *testing.T) (Attestation, Options) {
			o := goodOpts(t)
			o.ARKPins = nil
			return loadAtt(t, genuine), o
		}},
		{"ARK not self-signed (VCEK as ARK)", CodeARKSignature, func(t *testing.T) (Attestation, Options) {
			o := goodOpts(t)
			o.ARK = o.VCEK
			return loadAtt(t, genuine), o
		}},
		{"ASK not signed by ARK (VCEK as ASK)", CodeASKSignature, func(t *testing.T) (Attestation, Options) {
			o := goodOpts(t)
			o.ASK = o.VCEK
			return loadAtt(t, genuine), o
		}},
		{"ASK swapped for ARK", CodeVCEKSignature, func(t *testing.T) (Attestation, Options) {
			o := goodOpts(t)
			o.ASK = o.ARK
			return loadAtt(t, genuine), o
		}},
		{"measurement not in list", CodeMeasurementNotAllowed, func(t *testing.T) (Attestation, Options) {
			o := goodOpts(t)
			o.ExpectedMeasurements = []string{hex.EncodeToString(make([]byte, 48))}
			return loadAtt(t, genuine), o
		}},
		{"measurement required but empty", CodeNoExpectedMeasurement, func(t *testing.T) (Attestation, Options) {
			o := goodOpts(t)
			o.RequireMeasurement = true
			return loadAtt(t, genuine), o
		}},
		{"level 1 binding", CodeNotSealed, func(t *testing.T) (Attestation, Options) {
			att := rebind(t, loadAtt(t, genuine), func(b map[string]any) {
				b["schema"] = hotelBindingSchema
				b["level"] = "hotel"
			}, nil)
			return att, goodOpts(t)
		}},
		{"other schema", CodeNotSealed, func(t *testing.T) (Attestation, Options) {
			att := rebind(t, loadAtt(t, genuine), func(b map[string]any) { b["schema"] = "x" }, nil)
			return att, goodOpts(t)
		}},
		{"binding measurement differs from report", CodeReportField, func(t *testing.T) (Attestation, Options) {
			att := rebind(t, loadAtt(t, genuine), func(b map[string]any) { b["measurement"] = hex.EncodeToString(make([]byte, 48)) }, nil)
			return att, goodOpts(t)
		}},
		{"binding host_data differs from report", CodeReportField, func(t *testing.T) (Attestation, Options) {
			att := rebind(t, loadAtt(t, genuine), func(b map[string]any) { b["host_data"] = hex.EncodeToString(make([]byte, 32)) }, nil)
			return att, goodOpts(t)
		}},
		{"binding policy differs from report", CodeReportField, func(t *testing.T) (Attestation, Options) {
			att := rebind(t, loadAtt(t, genuine), func(b map[string]any) { b["policy"] = "0x30001" }, nil)
			return att, goodOpts(t)
		}},
		{"debug bit in policy", CodeDebugEnabled, func(t *testing.T) (Attestation, Options) {
			att := rebind(t, loadAtt(t, genuine),
				func(b map[string]any) { b["policy"] = fmt.Sprintf("0x%x", uint64(0x30000)|1<<19) },
				func(r []byte) { binary.LittleEndian.PutUint64(r[8:16], 0x30000|1<<19) })
			return att, goodOpts(t)
		}},
		{"debug kernel cmdline", CodeDebugEnabled, func(t *testing.T) (Attestation, Options) {
			att := rebind(t, loadAtt(t, genuine), func(b map[string]any) {
				b["kernel_cmdline"] = "console=ttyS0 cathedral.debug=1"
			}, nil)
			return att, goodOpts(t)
		}},
		{"VCEK chip id differs", CodeVCEKMismatch, func(t *testing.T) (Attestation, Options) {
			att := rebind(t, loadAtt(t, genuine), func(b map[string]any) {
				id := b["chip_id"].(string)
				b["chip_id"] = "00" + id[2:]
			}, func(r []byte) { r[0x1A0] = 0 })
			return att, goodOpts(t)
		}},
		{"VCEK TCB differs", CodeVCEKMismatch, func(t *testing.T) (Attestation, Options) {
			att := rebind(t, loadAtt(t, genuine), func(b map[string]any) {
				b["reported_tcb"] = "0d00000000001b58"
			}, func(r []byte) { r[0x180] = 0x0d })
			return att, goodOpts(t)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			att, opts := tc.prep(t)
			_, err := VerifyAttestation(att, opts)
			wantCode(t, err, tc.code)
		})
	}
}

func TestParseReportRejectsShort(t *testing.T) {
	_, err := ParseReport(make([]byte, 0x4A0-1))
	wantCode(t, err, CodeBadInput)
}

func TestBindingHashCrossCheck(t *testing.T) {
	for _, name := range []string{"attestation.json", "attestation-library.json"} {
		att := loadAtt(t, name)
		canon, err := Canonical(att.Binding)
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256Hex(canon); got != att.BindingSHA256 {
			t.Fatalf("%s: recomputed %s, stored %s", name, got, att.BindingSHA256)
		}
	}
}
