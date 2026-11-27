package vmkey

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type keyVectors struct {
	SaltUTF8    string `json:"salt_utf8"`
	FieldSelect uint64 `json:"field_select"`
	Cases       []struct {
		Identity      string `json:"identity"`
		HostDataHex   string `json:"host_data_hex"`
		ChipKeyHex    string `json:"chip_key_hex"`
		FieldSelect   uint64 `json:"field_select"`
		PassphraseHex string `json:"passphrase_hex"`
		KeyID         string `json:"key_id"`
	} `json:"cases"`
}

func load(t *testing.T) keyVectors {
	t.Helper()
	raw, err := os.ReadFile("../../../../tests/fixtures/vm_root_key_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v keyVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) != 4 {
		t.Fatalf("fixture has %d cases", len(v.Cases))
	}
	return v
}

func hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad hex %q", s)
	}
	var out [32]byte
	copy(out[:], raw)
	return out
}

// T2: the passphrase equals sealed_data_key.py's HKDF with the VM salt, on
// fake chip keys, for both identities of vm_measure_v1.json.
func TestPassphraseEqualsPythonVectors(t *testing.T) {
	v := load(t)
	if v.SaltUTF8 != Salt || v.FieldSelect != FieldSelect || FieldSelect != 0x9 {
		t.Fatal("salt or field select differs from the vectors")
	}
	seen := map[string]bool{}
	for _, c := range v.Cases {
		chip, hd := hex32(t, c.ChipKeyHex), hex32(t, c.HostDataHex)
		got := Passphrase(chip, c.FieldSelect, hd)
		if hex.EncodeToString(got[:]) != c.PassphraseHex {
			t.Fatalf("identity %s: passphrase differs", c.Identity)
		}
		if KeyID(chip, c.FieldSelect, hd) != c.KeyID {
			t.Fatalf("identity %s: key_id differs", c.Identity)
		}
		seen[c.Identity] = true
	}
	if !seen["a"] || !seen["b"] {
		t.Fatal("both identities must be covered")
	}
}
