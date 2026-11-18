package snpverify

import (
	"strings"
	"testing"
)

// Each case here is an input room-kit/verify_receipts.py rejects. The Go checker
// must reject it too; the test names the Python check it mirrors.

func TestRepeatedSequenceIsRefused(t *testing.T) { // verify_receipts: "sequence appears more than once"
	s := newSynth(t, nil)
	rcs := s.chain(t, map[string]any{}, map[string]any{})
	_, err := VerifyReceipts(s.att, append(rcs, rcs[1]), "")
	wantCode(t, err, CodeReceiptSequenceRepeat)
}

func TestReceiptSchemaIsChecked(t *testing.T) { // verify_receipts: "not a cathedral_sealed_hotel_receipt_v1 statement"
	s := newSynth(t, nil)
	for name, schema := range map[string]any{
		"absent":      nil,
		"hotel level": "cathedral_hotel_receipt_v1",
		"other":       "x",
		"not string":  num("1"),
	} {
		t.Run(name, func(t *testing.T) {
			rcs := s.chain(t, map[string]any{"schema": schema})
			_, err := VerifyReceipts(s.att, rcs, "")
			wantCode(t, err, CodeReceiptSchema)
		})
	}
}

func TestStartCommandRule(t *testing.T) { // check_start_commands
	s := newSynth(t, nil)
	cmd := []any{"python", "-m", "http.server"}
	sum, err := sha256Canonical(cmd)
	if err != nil {
		t.Fatal(err)
	}
	create := func(extra map[string]any) []Receipt {
		extra["action"] = "create"
		return s.chain(t, extra)
	}
	if _, err := VerifyReceipts(s.att, create(map[string]any{"start_command": cmd, "start_command_sha256": sum}), ""); err != nil {
		t.Fatalf("matching hash: %v", err)
	}
	if _, err := VerifyReceipts(s.att, create(map[string]any{"start_command": explicitNull{}}), ""); err != nil {
		t.Fatalf("null command, no hash: %v", err)
	}
	if _, err := VerifyReceipts(s.att, create(map[string]any{"start_command": explicitNull{}, "start_command_sha256": explicitNull{}}), ""); err != nil {
		t.Fatalf("null command, null hash: %v", err)
	}
	bad := map[string]map[string]any{
		"wrong hash":         {"start_command": cmd, "start_command_sha256": strings.Repeat("0", 64)},
		"missing hash":       {"start_command": cmd},
		"null hash":          {"start_command": cmd, "start_command_sha256": explicitNull{}},
		"hash for null cmd":  {"start_command": explicitNull{}, "start_command_sha256": sum},
		"command not a list": {"start_command": "sleep", "start_command_sha256": sum},
		"non-string part":    {"start_command": []any{"a", num("1")}, "start_command_sha256": sum},
		"empty list, no sum": {"start_command": []any{}},
	}
	for name, extra := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyReceipts(s.att, create(extra), "")
			wantCode(t, err, CodeStartCommand)
		})
	}
}

func TestAttestationShapeRule(t *testing.T) { // check_attestation_shape
	att := loadAtt(t, "attestation-proof.json")
	good := att.ReportB64
	mutate := map[string]func(*Attestation){
		"report with a newline":    func(a *Attestation) { a.ReportB64 = good[:100] + "\n" + good[100:] },
		"report with a space":      func(a *Attestation) { a.ReportB64 = good[:100] + " " + good[100:] },
		"report with a stray byte": func(a *Attestation) { a.ReportB64 = good[:100] + "!" + good[100:] },
		"report url alphabet":      func(a *Attestation) { a.ReportB64 = strings.NewReplacer("+", "-", "/", "_").Replace(good) },
		"report empty":             func(a *Attestation) { a.ReportB64 = "" },
		"receipt key short": func(a *Attestation) {
			a.Binding = cloneBinding(a.Binding)
			a.Binding["receipt_key_ed25519_b64"] = "AAAA"
		},
		"receipt key with newline": func(a *Attestation) {
			k := a.Binding["receipt_key_ed25519_b64"].(string)
			a.Binding = cloneBinding(a.Binding)
			a.Binding["receipt_key_ed25519_b64"] = k[:4] + "\n" + k[4:]
		},
		"receipt key not a string": func(a *Attestation) {
			a.Binding = cloneBinding(a.Binding)
			a.Binding["receipt_key_ed25519_b64"] = num("1")
		},
		"policy not a string": func(a *Attestation) {
			a.Binding = cloneBinding(a.Binding)
			a.Binding["policy"] = num("1")
		},
	}
	for name, mut := range mutate {
		t.Run(name, func(t *testing.T) {
			a := att
			mut(&a)
			if _, err := VerifyAttestation(a, goodOpts(t)); err == nil {
				t.Fatal("expected a failure")
			}
			if _, err := VerifyReceipts(a, nil, ""); err == nil && strings.Contains(name, "receipt key") {
				t.Fatal("VerifyReceipts accepted the key")
			}
		})
	}
}

func cloneBinding(b map[string]any) map[string]any {
	out := make(map[string]any, len(b))
	for k, v := range b {
		out[k] = v
	}
	return out
}
