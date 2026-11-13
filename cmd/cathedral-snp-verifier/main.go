// Command cathedral-snp-verifier checks a Cathedral sealed-hotel attestation
// (AMD SEV-SNP) and its signed receipts offline. It is a second implementation
// of room-kit/verify_receipts.py and never touches the network.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/cathedralai/cathedralconfidential/cmd/cathedral-snp-verifier/snpverify"
	"io"
	"os"
	"strings"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// onceFlag takes one value; a second use is a usage error, because Python keeps
// only the last one and a repeat must not silently widen the check.
type onceFlag struct {
	value string
	set   bool
}

func (o *onceFlag) String() string { return o.value }
func (o *onceFlag) Set(v string) error {
	if o.set {
		return errors.New("given more than once")
	}
	o.value, o.set = v, true
	return nil
}

type verdict struct {
	Verdict            string                             `json:"verdict"`
	Code               string                             `json:"code,omitempty"`
	Detail             string                             `json:"detail,omitempty"`
	Measurement        string                             `json:"measurement,omitempty"`
	MeasurementChecked *bool                              `json:"measurement_checked,omitempty"`
	ReceiptsChecked    *bool                              `json:"receipts_checked,omitempty"`
	Receipts           *int                               `json:"receipts,omitempty"`
	Attestation        *snpverify.Result                  `json:"attestation,omitempty"`
	Chain              *snpverify.ReceiptsResult          `json:"chain,omitempty"`
	PolicyTimeline     map[string][]snpverify.PolicyEvent `json:"policy_timeline,omitempty"`
	RoomTunables       map[string]string                  `json:"room_tunables,omitempty"`
	RoomLinks          map[string]string                  `json:"room_links,omitempty"`
	Checked            string                             `json:"checked,omitempty"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cathedral-snp-verifier", flag.ContinueOnError)
	fs.SetOutput(stderr)
	attFile := fs.String("attestation", "", "attestation JSON file")
	recFile := fs.String("receipts", "", "receipts JSON file (object with receipts, or a list)")
	arkFile := fs.String("ark", "", "AMD ARK certificate (DER)")
	askFile := fs.String("ask", "", "AMD ASK certificate (DER)")
	vcekFile := fs.String("vcek", "", "VCEK certificate (DER)")
	product := fs.String("product", "", "Genoa or Milan (default: from the report CPUID, version 3 and later)")
	requireMeasurement := fs.Bool("require-measurement", false, "fail unless --expected-measurement is given")
	var headers, pins, allowed multiFlag
	var expected onceFlag
	fs.Var(&headers, "receipt-header", "X-Room-Receipt header value (repeatable)")
	fs.Var(&pins, "ark-sha256", "pinned sha256 of the ARK DER (repeatable, required)")
	fs.Var(&expected, "expected-measurement", "expected measurement hex (at most once, as in the Python tool)")
	fs.Var(&allowed, "allowed-measurement", "approved measurement hex, any match passes (repeatable; no Python counterpart)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	usage := func(msg string) int {
		fmt.Fprintln(stderr, "usage error:", msg)
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "usage error: unexpected argument %q (flags only)\n", fs.Arg(0))
		return 2
	}
	if *attFile == "" || *arkFile == "" || *askFile == "" || *vcekFile == "" {
		return usage("--attestation, --ark, --ask and --vcek are required")
	}
	if expected.set && len(allowed) > 0 {
		return usage("use --expected-measurement or --allowed-measurement, not both")
	}
	measurements := []string(allowed)
	if expected.set {
		measurements = []string{expected.value}
	}
	if len(pins) == 0 {
		return usage("at least one --ark-sha256 is required")
	}
	out := func(v verdict, code int) int {
		b, _ := json.Marshal(v)
		fmt.Fprintln(stdout, string(b))
		return code
	}
	failed := func(err error) int {
		var ve *snpverify.VerifyError
		if !errors.As(err, &ve) {
			ve = snpverify.NewError(snpverify.CodeBadInput, err.Error())
		}
		return out(verdict{Verdict: "FAIL", Code: ve.Code(), Detail: ve.Detail}, 1)
	}
	read := func(path string) ([]byte, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, snpverify.NewError(snpverify.CodeBadInput, err.Error())
		}
		return b, nil
	}

	attData, err := read(*attFile)
	if err != nil {
		return failed(err)
	}
	ark, err := read(*arkFile)
	if err != nil {
		return failed(err)
	}
	ask, err := read(*askFile)
	if err != nil {
		return failed(err)
	}
	vcek, err := read(*vcekFile)
	if err != nil {
		return failed(err)
	}
	att, err := snpverify.ParseAttestation(attData)
	if err != nil {
		return failed(err)
	}
	var receipts []snpverify.Receipt
	docHead := ""
	if *recFile != "" {
		recData, err := read(*recFile)
		if err != nil {
			return failed(err)
		}
		if receipts, docHead, err = snpverify.ParseReceipts(recData); err != nil {
			return failed(err)
		}
	}
	for _, h := range headers {
		rc, err := snpverify.DecodeReceiptHeader(h)
		if err != nil {
			return failed(err)
		}
		receipts = append(receipts, rc)
	}
	// Python only trusts the file's own head for a whole chain with no extra headers.
	wantHead := ""
	if len(headers) == 0 {
		wantHead = docHead
	}

	all, err := snpverify.VerifyAll(att, receipts, wantHead, snpverify.Options{
		ExpectedMeasurements: measurements, RequireMeasurement: *requireMeasurement, Product: *product,
		ARK: ark, ASK: ask, VCEK: vcek, ARKPins: pins,
	})
	if err != nil {
		return failed(err)
	}
	res, chain := all.Attestation, all.Chain
	checked := "each receipt; not that none are missing"
	if wantHead != "" {
		checked = "whole chain to the head the server named"
	}
	n := chain.Receipts
	measChecked, recChecked := len(measurements) > 0, len(receipts) > 0
	return out(verdict{Verdict: "PASS", Measurement: res.Measurement, Receipts: &n, MeasurementChecked: &measChecked, ReceiptsChecked: &recChecked,
		Attestation: &res, Chain: &chain, PolicyTimeline: all.PolicyTimeline,
		RoomTunables: all.RoomTunables, RoomLinks: all.RoomLinks, Checked: checked}, 0)
}
