package vmattest

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type vectorCase struct {
	ChallengeHex   string `json:"challenge_hex"`
	HostKeyLine    string `json:"host_key_line"`
	HostKeyBlobHex string `json:"host_key_blob_hex"`
	ReportDataHex  string `json:"report_data_hex"`
}

// The vectors come from verify_vm.report_data (Python), so a drift in either language fails here.
func vectors(t *testing.T) []vectorCase {
	t.Helper()
	raw, err := os.ReadFile("../../../../tests/fixtures/vm_attest_report_data_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Cases []vectorCase }
	if err := json.Unmarshal(raw, &f); err != nil || len(f.Cases) < 3 {
		t.Fatalf("fixture: %v", err)
	}
	return f.Cases
}

func TestReportDataEqualsVerifyVM(t *testing.T) {
	for i, c := range vectors(t) {
		blob, err := HostKeyBlob([]byte(c.HostKeyLine + "\n"))
		if err != nil || hex.EncodeToString(blob) != c.HostKeyBlobHex {
			t.Fatalf("case %d: blob: %v", i, err)
		}
		var challenge [32]byte
		copy(challenge[:], mustHex(t, c.ChallengeHex))
		got, err := ReportData(challenge, blob)
		if err != nil || hex.EncodeToString(got[:]) != c.ReportDataHex {
			t.Fatalf("case %d: REPORT_DATA differs from verify_vm.py", i)
		}
	}
}

func TestHostKeyRefusals(t *testing.T) {
	good := vectors(t)[0].HostKeyLine
	parts := strings.Fields(good)
	bad := map[string]string{
		"rsa":              "ssh-rsa " + parts[1],
		"two keys":         good + "\n" + good,
		"truncated base64": "ssh-ed25519 " + parts[1][:len(parts[1])-1],
		"short blob":       "ssh-ed25519 " + base64.StdEncoding.EncodeToString([]byte("x")),
		"empty":            "",
		"too many fields":  good + " a b",
	}
	for why, line := range bad {
		if _, err := HostKeyBlob([]byte(line)); err == nil {
			t.Errorf("%s: parsed", why)
		}
	}
	var challenge [32]byte
	blob, _ := HostKeyBlob([]byte(good))
	if _, err := ReportData(challenge, blob[:10]); err == nil {
		t.Error("a short blob must be refused")
	}
}

func fakeCollect(data [64]byte) ([]byte, error) {
	report := make([]byte, reportBytes)
	copy(report[0x50:], data[:])
	return report, nil
}

func TestRunBindsTheChallengeAndTheKey(t *testing.T) {
	c := vectors(t)[1]
	var got [64]byte
	collect := func(data [64]byte) ([]byte, error) { got = data; return fakeCollect(data) }
	ans, err := Run([]string{c.ChallengeHex}, 0, func() ([]byte, error) { return []byte(c.HostKeyLine), nil }, collect)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got[:]) != c.ReportDataHex {
		t.Fatal("collected with another REPORT_DATA")
	}
	raw, _ := base64.StdEncoding.DecodeString(ans.Report)
	if len(raw) != reportBytes || ans.Schema != "cathedral.vm.guest-report/v1" {
		t.Fatalf("answer: %+v", ans)
	}
	out, _ := Encode(ans)
	var back map[string]string
	if err := json.Unmarshal(out, &back); err != nil || back["report_b64"] != ans.Report {
		t.Fatal("stdout is one JSON object with report_b64")
	}
}

func TestRunRefusals(t *testing.T) {
	c := vectors(t)[0]
	key := func() ([]byte, error) { return []byte(c.HostKeyLine), nil }
	if _, err := Run([]string{c.ChallengeHex}, 1000, key, fakeCollect); err == nil {
		t.Error("non-root")
	}
	for _, args := range [][]string{nil, {}, {c.ChallengeHex, "x"}, {strings.ToUpper(c.ChallengeHex)}, {"abcd"}, {"zz" + c.ChallengeHex[2:]}} {
		if _, err := Run(args, 0, key, fakeCollect); err == nil {
			t.Errorf("args %v accepted", args)
		}
	}
	if _, err := Run([]string{c.ChallengeHex}, 0, func() ([]byte, error) { return nil, errors.New("gone") }, fakeCollect); err == nil {
		t.Error("an unreadable key")
	}
	// A report that does not carry the requested REPORT_DATA, or has the wrong size, is refused.
	wrong := func(data [64]byte) ([]byte, error) { data[0] ^= 1; return fakeCollect(data) }
	if _, err := Run([]string{c.ChallengeHex}, 0, key, wrong); err == nil {
		t.Error("a report with other REPORT_DATA")
	}
	short := func(data [64]byte) ([]byte, error) { return bytes.Repeat([]byte{0}, 100), nil }
	if _, err := Run([]string{c.ChallengeHex}, 0, key, short); err == nil {
		t.Error("a short report")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
