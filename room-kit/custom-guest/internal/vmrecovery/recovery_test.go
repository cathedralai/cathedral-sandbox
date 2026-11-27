package vmrecovery

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const (
	id  = "vm-0123456789ab"
	sha = "64bd36bb2a9075d85cf238131b45a58c82f3959b47438ab379de56c71981fc89"
)

func sample(t *testing.T) Record {
	t.Helper()
	rec, err := Generate(bytes.NewReader(bytes.Repeat([]byte{0x5a}, 64)), id, sha)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestRecordRoundTripsAndIsCanonical(t *testing.T) {
	rec := sample(t)
	raw, err := rec.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(raw)
	if err != nil || back != rec {
		t.Fatalf("round trip: %v", err)
	}
	var doc map[string]string
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc) != 4 {
		t.Fatalf("not four JSON members: %v", err)
	}
}

func TestParseRefusesAnythingNotCanonical(t *testing.T) {
	raw, _ := sample(t).Encode()
	cases := map[string][]byte{
		"empty":         nil,
		"no newline":    bytes.TrimSuffix(raw, []byte("\n")),
		"a space":       bytes.Replace(raw, []byte(`":"`), []byte(`": "`), 1),
		"extra member":  bytes.Replace(raw, []byte(`{"`), []byte(`{"a":"b","`), 1),
		"bad vm id":     bytes.Replace(raw, []byte(id), []byte("vm-zz"), 1),
		"short key":     bytes.Replace(raw, []byte(`"recovery_key":"`), []byte(`"recovery_key":"AA`), 1),
		"another sch":   bytes.Replace(raw, []byte("recovery-key/v1"), []byte("recovery-key/v2"), 1),
		"trailing junk": append(append([]byte(nil), raw...), 'x'),
		"too large":     bytes.Repeat([]byte("a"), maxFile+1),
	}
	for why, c := range cases {
		if _, err := Parse(c); err == nil {
			t.Errorf("%s: parsed", why)
		}
	}
}

func TestGenerateRefusesShortEntropyAndZeroKey(t *testing.T) {
	if _, err := Generate(bytes.NewReader(make([]byte, 10)), id, sha); err == nil {
		t.Error("short entropy")
	}
	if _, err := Generate(bytes.NewReader(make([]byte, 32)), id, sha); err == nil {
		t.Error("an all-zero key")
	}
	if _, err := Generate(bytes.NewReader(bytes.Repeat([]byte{1}, 32)), "bad", sha); err == nil {
		t.Error("a bad vm_id")
	}
}

func TestShowPrintsKeyIdentityAndChip(t *testing.T) {
	rec := sample(t)
	var chip [ChipBytes]byte
	for i := range chip {
		chip[i] = byte(i + 1)
	}
	out, err := Show(rec, chip)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]string
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["schema"] != ShowSchema || doc["vm_id"] != id || doc["identity_sha256"] != sha || len(doc["chip_id"]) != 128 ||
		doc["recovery_key"] == "" || !strings.HasSuffix(string(out), "\n") || bytes.Count(out, []byte("\n")) != 1 {
		t.Fatalf("show: %s", out)
	}
	if _, err := Show(rec, [ChipBytes]byte{}); err == nil {
		t.Error("an all-zero CHIP_ID must be refused")
	}
	if !rec.IdentityMatches(id, sha) || rec.IdentityMatches(id, strings.Repeat("0", 64)) || rec.IdentityMatches("vm-ffffffffffff", sha) {
		t.Error("IdentityMatches")
	}
}
