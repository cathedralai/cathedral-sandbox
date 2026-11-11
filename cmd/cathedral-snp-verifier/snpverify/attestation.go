package snpverify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

const (
	SealedBindingSchema = "cathedral_sealed_hotel_binding_v1"
	SealedReceiptSchema = "cathedral_sealed_hotel_receipt_v1"
	hotelBindingSchema  = "cathedral_hotel_binding_v1"
	debugPolicyBit      = uint64(1) << 19
)

// Attestation is the document from GET /room/attestation. Binding keeps the
// parsed tree (numbers as literals) so Canonical gives back the signed bytes.
type Attestation struct {
	Binding       map[string]any
	BindingSHA256 string
	ReportB64     string
}

// Options for VerifyAttestation. The certificates are DER and supplied by the caller.
type Options struct {
	ExpectedMeasurements []string
	// RequireMeasurement makes an empty ExpectedMeasurements an error: the approved
	// image list is the caller's, and "no list" must be a choice, not a default.
	RequireMeasurement bool
	ARK, ASK, VCEK     []byte
	ARKPins            []string
	// Product ("Genoa" or "Milan") overrides the product read from the report
	// CPUID, which only reports of version 3 and later carry.
	Product string
}

// Result is what a passing attestation check reports.
type Result struct {
	BindingSHA256 string   `json:"binding_sha256"`
	Measurement   string   `json:"measurement"`
	ChipID        string   `json:"chip_id"`
	Policy        string   `json:"policy"`
	HostData      string   `json:"host_data"`
	ReportVersion uint32   `json:"report_version"`
	KernelCmdline string   `json:"kernel_cmdline"`
	AMD           *AMDInfo `json:"amd,omitempty"`
}

// pySpace is Python's str.isspace set: Go's unicode.IsSpace plus U+001C to U+001F.
func pySpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

// hasDebugFlag splits like Python str.split() so a separator Go's Fields would
// not treat as space cannot hide the flag from one checker and not the other.
func hasDebugFlag(cmdline string) bool {
	for _, w := range strings.FieldsFunc(cmdline, pySpace) {
		if w == "cathedral.debug=1" {
			return true
		}
	}
	return false
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// ParseAttestation reads {binding, binding_sha256, report_b64}.
func ParseAttestation(data []byte) (Attestation, error) {
	var att Attestation
	v, err := ParseKeepingNumbers(data)
	if err != nil {
		return att, fail(CodeBadInput, "attestation: %v", err)
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return att, fail(CodeBadInput, "attestation is not a JSON object")
	}
	binding, ok := doc["binding"].(map[string]any)
	if !ok {
		return att, fail(CodeBadInput, "attestation has no binding object")
	}
	att.Binding = binding
	att.BindingSHA256, _ = doc["binding_sha256"].(string)
	att.ReportB64, _ = doc["report_b64"].(string)
	return att, nil
}

func bindingString(b map[string]any, key string) (string, bool) {
	s, ok := b[key].(string)
	return s, ok
}

// VerifyAttestation runs the sealed checks in the order of verify_attestation()
// in verify_receipts.py.
func VerifyAttestation(att Attestation, opts Options) (Result, error) {
	var res Result
	canon, err := Canonical(att.Binding)
	if err != nil {
		return res, fail(CodeBadInput, "binding cannot be canonicalised: %v", err)
	}
	bsha := sha256Hex(canon)
	if bsha != att.BindingSHA256 {
		return res, fail(CodeBindingHashMismatch, "binding_sha256 does not match the binding")
	}
	level, _ := bindingString(att.Binding, "level")
	schema, _ := bindingString(att.Binding, "schema")
	if level == "hotel" || schema == hotelBindingSchema {
		return res, fail(CodeNotSealed, "level 1 (unsealed) binding: an SEV-SNP attestation is required")
	}
	if schema != SealedBindingSchema {
		return res, fail(CodeNotSealed, "binding schema %q is not %s", schema, SealedBindingSchema)
	}
	report, err := base64.StdEncoding.DecodeString(att.ReportB64)
	if err != nil {
		return res, fail(CodeBadInput, "report_b64 is not base64: %v", err)
	}
	rep, err := ParseReport(report)
	if err != nil {
		return res, err
	}
	bshaRaw, _ := hex.DecodeString(bsha)
	want := append(bshaRaw, make([]byte, 32)...)
	if !bytes.Equal(rep.ReportData[:], want) {
		return res, fail(CodeReportData, "REPORT_DATA does not commit to the binding")
	}
	for _, c := range []struct{ key, got, name string }{
		{"measurement", rep.MeasurementHex(), "measurement"},
		{"chip_id", rep.ChipIDHex(), "chip id"},
		{"reported_tcb", rep.TCBHex(), "TCB"},
		{"host_data", rep.HostDataHex(), "HOST_DATA"},
		{"policy", fmt.Sprintf("0x%x", rep.Policy), "policy"},
	} {
		if v, ok := bindingString(att.Binding, c.key); !ok || v != c.got {
			return res, fail(CodeReportField, "report %s differs from the binding", c.name)
		}
	}
	if rep.Policy&debugPolicyBit != 0 {
		return res, fail(CodeDebugEnabled, "guest policy allows debug")
	}
	// A debug build keeps the same policy but gives the host root SSH into the guest;
	// the flag sits on the measured kernel command line.
	cmdline := ""
	if raw, present := att.Binding["kernel_cmdline"]; present {
		c, ok := raw.(string)
		if !ok {
			return res, fail(CodeBadInput, "binding kernel_cmdline is not a string")
		}
		cmdline = c
	}
	if hasDebugFlag(cmdline) {
		return res, fail(CodeDebugEnabled, "debug build: the host can log in to this guest")
	}
	if opts.RequireMeasurement && len(opts.ExpectedMeasurements) == 0 {
		return res, fail(CodeNoExpectedMeasurement, "an expected measurement list is required")
	}
	if len(opts.ExpectedMeasurements) > 0 {
		ok := false
		for _, m := range opts.ExpectedMeasurements {
			if strings.ToLower(m) == rep.MeasurementHex() {
				ok = true
			}
		}
		if !ok {
			return res, fail(CodeMeasurementNotAllowed, "measurement %s is not in the expected list", rep.MeasurementHex())
		}
	}
	amd, err := VerifyAMDChain(report, rep, opts.ARK, opts.ASK, opts.VCEK, opts.ARKPins, opts.Product)
	if err != nil {
		return res, err
	}
	return Result{
		BindingSHA256: bsha, Measurement: rep.MeasurementHex(), ChipID: rep.ChipIDHex()[:16] + "...",
		Policy: fmt.Sprintf("0x%x", rep.Policy), HostData: rep.HostDataHex(), ReportVersion: rep.Version,
		KernelCmdline: cmdline, AMD: &amd,
	}, nil
}
