package snpverify

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Set CATHEDRAL_DIFF_OUT to a directory and the parity tests write every case they
// run there, with the verdict of this checker. scripts/differential_receipts.py runs
// the Python checker over the same files and fails on any case Go passes and Python
// rejects. Without the variable nothing is written.

type diffCase struct {
	Name    string          `json:"name"`
	Kind    string          `json:"kind"`
	Go      string          `json:"go"`
	Payload json.RawMessage `json:"payload"`
}

var diffCases []diffCase

func TestMain(m *testing.M) {
	code := m.Run()
	if dir := os.Getenv("CATHEDRAL_DIFF_OUT"); dir != "" && code == 0 {
		b, err := json.MarshalIndent(diffCases, "", " ")
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, "cases.json"), b, 0o600)
		}
		if err != nil {
			os.Stderr.WriteString("differential output: " + err.Error() + "\n")
			code = 1
		}
	}
	os.Exit(code)
}

func verdictOf(err error) string {
	if err == nil {
		return "PASS"
	}
	return "FAIL"
}

func canonText(v any) json.RawMessage {
	b, err := Canonical(v)
	if err != nil {
		panic(err)
	}
	return b
}

var nameClean = regexp.MustCompile(`[^A-Za-z0-9_./-]+`)

func recordCase(t *testing.T, att Attestation, rcs []Receipt, head string, list *ListDoc, err error) {
	t.Helper()
	var items []any
	for _, rc := range rcs {
		items = append(items, map[string]any{"statement": rc.Statement, "receipt_sha256": rc.ReceiptSHA256, "signature_b64": rc.SignatureB64})
	}
	doc := map[string]any{"binding": att.Binding, "binding_sha256": att.BindingSHA256, "head": head, "receipts": []any{}}
	if items != nil {
		doc["receipts"] = items
	}
	if list != nil {
		l := map[string]any{}
		if list.HasCount {
			l["count"] = list.Count
		}
		if list.HasRoomHead {
			l["room_head"] = list.RoomHead
		}
		doc["list"] = l
	}
	push(t, "receipts", doc, err)
}

func recordAttestation(t *testing.T, att Attestation, err error) {
	t.Helper()
	push(t, "attestation", map[string]any{"binding": att.Binding, "binding_sha256": att.BindingSHA256, "report_b64": att.ReportB64}, err)
}

func push(t *testing.T, kind string, doc map[string]any, err error) {
	t.Helper()
	// Canonical rejects nothing the tests build; a Go-only type such as explicitNull never reaches here.
	var buf bytes.Buffer
	buf.Write(canonText(doc))
	diffCases = append(diffCases, diffCase{Name: nameClean.ReplaceAllString(t.Name(), "_"), Kind: kind, Go: verdictOf(err), Payload: buf.Bytes()})
}
