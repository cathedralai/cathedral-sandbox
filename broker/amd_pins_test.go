package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ARK SHA-256 (DER) of the AMD roots (amd_chain.go).
const (
	arkMilan = "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd"
	arkGenoa = "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1"
	arkTurin = "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a"
)

func loadAMDConfig(t *testing.T, amd string) (*broker, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "broker.json")
	raw := `{"state_dir": "` + t.TempDir() + `", "amd_verifier": {"command": ["python3", "v.py"], "ark_sha256": ` + amd + `}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadBroker(path)
}

func TestAMDVerifierARKPinForms(t *testing.T) {
	b, err := loadAMDConfig(t, `"`+strings.ToUpper(arkGenoa)+`"`)
	if err != nil {
		t.Fatalf("string pin: %v", err)
	}
	if got := b.cfg.AMDVerifier.ARKSHA256; len(got) != 1 || !strings.EqualFold(got[0], arkGenoa) {
		t.Fatalf("string pin: %v", got)
	}
	b, err = loadAMDConfig(t, `["`+arkMilan+`", "`+arkGenoa+`", "`+arkTurin+`"]`)
	if err != nil {
		t.Fatalf("list of pins: %v", err)
	}
	if got := b.cfg.AMDVerifier.ARKSHA256; len(got) != 3 || got[1] != arkGenoa {
		t.Fatalf("list of pins: %v", got)
	}
	for _, bad := range []string{
		`["` + arkGenoa + `", "zz` + arkMilan[2:] + `"]`, // invalid hex in the list
		`["` + arkGenoa + `", "abc"]`,                    // short pin in the list
		`[]`,                                             // no pin
		`""`,
		`null`,
		`42`,
		`["` + arkGenoa + `", 7]`,
	} {
		if _, err := loadAMDConfig(t, bad); err == nil || !strings.Contains(err.Error(), "ark_sha256") {
			t.Fatalf("ark_sha256 %s: %v", bad, err)
		}
	}
}

// TestAMDVerifierRunsOnceWithEveryPin: the verifier gets every pin in one
// run, and a FAIL is final (no second run with another pin).
func TestAMDVerifierRunsOnceWithEveryPin(t *testing.T) {
	dir := fakeAMDVerifier(t)
	b := &broker{cfg: config{StateDir: t.TempDir(), AMDVerifier: &amdVerifierConfig{
		Command: []string{"/bin/sh", filepath.Join(dir, "verify.sh")}, ARKSHA256: arkPins{arkMilan, strings.ToUpper(arkGenoa), arkTurin}}}}
	if _, err := b.verifyAMDChain(context.Background(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	calls := amdCalls(dir)
	want := "--ark-sha256 " + arkMilan + " --ark-sha256 " + arkGenoa + " --ark-sha256 " + arkTurin
	if len(calls) != 1 || !strings.Contains(calls[0], want) {
		t.Fatalf("calls %q, want one with %q", calls, want)
	}
	setAMDVerdict(t, dir, `{"verdict": "FAIL", "reason": "report signature does not verify with the VCEK"}`)
	if _, err := b.verifyAMDChain(context.Background(), []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("FAIL: %v", err)
	}
	if n := len(amdCalls(dir)); n != 2 {
		t.Fatalf("a FAIL ran the verifier %d times, want once", n-1)
	}
}
