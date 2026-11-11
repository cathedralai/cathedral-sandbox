package snpverify

import "fmt"

// Stable failure codes. Each check has exactly one; callers and the CLI key on them.
const (
	CodeBadInput               = "bad_input"
	CodeBindingHashMismatch    = "binding_hash_mismatch"
	CodeNotSealed              = "not_sealed"
	CodeReportData             = "report_data_mismatch"
	CodeReportField            = "report_field_mismatch"
	CodeDebugEnabled           = "debug_enabled"
	CodeMeasurementNotAllowed  = "measurement_not_allowed"
	CodeNoExpectedMeasurement  = "no_expected_measurement"
	CodeUnsupportedProduct     = "unsupported_product"
	CodeARKNotPinned           = "ark_not_pinned"
	CodeARKSignature           = "ark_signature"
	CodeASKSignature           = "ask_signature"
	CodeVCEKSignature          = "vcek_signature"
	CodeVCEKMismatch           = "vcek_mismatch"
	CodeReportSignature        = "report_signature"
	CodeReceiptMalformed       = "receipt_malformed"
	CodeReceiptBindingMismatch = "receipt_binding_mismatch"
	CodeReceiptHashMismatch    = "receipt_hash_mismatch"
	CodeReceiptSignature       = "receipt_signature"
	CodeChainLink              = "chain_link"
	CodeChainGap               = "chain_gap"
	CodeChainHead              = "chain_head"
)

// VerifyError carries one stable code and a human detail.
type VerifyError struct {
	code   string
	Detail string
}

// Code returns the stable failure code, one of the Code constants.
func (e *VerifyError) Code() string { return e.code }

func (e *VerifyError) Error() string { return e.code + ": " + e.Detail }

// NewError builds a VerifyError for callers that wrap their own failures.
func NewError(code, detail string) *VerifyError { return &VerifyError{code: code, Detail: detail} }

func fail(code, format string, args ...any) error {
	return &VerifyError{code: code, Detail: fmt.Sprintf(format, args...)}
}
