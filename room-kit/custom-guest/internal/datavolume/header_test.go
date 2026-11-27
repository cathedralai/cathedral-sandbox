package datavolume

import (
	"encoding/json"
	"strings"
	"testing"
)

// Synthetic policy fixture, not a complete or checksummed LUKS header.
const policyFixture = `{"segments":{"0":{"type":"crypt","encryption":"aes-xts-plain64","sector_size":4096,"iv_tweak":"0","integrity":{"type":"hmac(sha256)","journal_encryption":"none","journal_integrity":"none"}}},"keyslots":{"0":{"type":"luks2","key_size":96,"area":{"type":"raw","encryption":"aes-xts-plain64","key_size":64}}},"config":{}}`

func TestHeaderPolicy(t *testing.T) {
	if err := CheckHeaderPolicy([]byte(policyFixture)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]any){
		"missing integrity":   func(h map[string]any) { delete(object(object(h["segments"])["0"]), "integrity") },
		"plain cipher":        func(h map[string]any) { object(object(h["segments"])["0"])["encryption"] = "cipher_null" },
		"sector size":         func(h map[string]any) { object(object(h["segments"])["0"])["sector_size"] = 512 },
		"extra segment":       func(h map[string]any) { object(h["segments"])["1"] = object(h["segments"])["0"] },
		"reencrypt segment":   func(h map[string]any) { object(object(h["segments"])["0"])["flags"] = []string{"in-reencryption"} },
		"crc integrity":       func(h map[string]any) { object(object(object(h["segments"])["0"])["integrity"])["type"] = "crc32c" },
		"wrong integrity key": func(h map[string]any) { object(object(object(h["segments"])["0"])["integrity"])["key_size"] = 16 },
		"null slot":           func(h map[string]any) { object(h["keyslots"])["0"] = nil },
		"no slots":            func(h map[string]any) { h["keyslots"] = map[string]any{} },
		"null slot cipher": func(h map[string]any) {
			object(object(object(h["keyslots"])["0"])["area"])["encryption"] = "cipher_null"
		},
		"short volume key":   func(h map[string]any) { object(object(h["keyslots"])["0"])["key_size"] = 64 },
		"short wrapping key": func(h map[string]any) { object(object(object(h["keyslots"])["0"])["area"])["key_size"] = 32 },
		"bad slot id":        func(h map[string]any) { s := object(h["keyslots"]); s["00"] = s["0"]; delete(s, "0") },
		"bypass integrity":   func(h map[string]any) { object(h["config"])["flags"] = []string{"integrity-no-journal"} },
		"mandatory extension": func(h map[string]any) {
			object(h["config"])["requirements"] = map[string]any{"mandatory": []string{"online-reencrypt-v2"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var h map[string]any
			if err := json.Unmarshal([]byte(policyFixture), &h); err != nil {
				t.Fatal(err)
			}
			mutate(h)
			raw, err := json.Marshal(h)
			if err != nil {
				t.Fatal(err)
			}
			if CheckHeaderPolicy(raw) == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}
func TestHeaderEncodingRefusals(t *testing.T) {
	for _, raw := range []string{"", "null", "[]", policyFixture + "{}", strings.Repeat("[", 18) + strings.Repeat("]", 18), strings.Repeat(" ", 1<<20+1), strings.Replace(policyFixture, `"type":"crypt"`, `"type":"crypt","type":"crypt"`, 1), strings.Replace(policyFixture, `4096`, `"4096"`, 1), strings.Replace(policyFixture, `"segments"`, `"Segments"`, 1)} {
		if CheckHeaderPolicy([]byte(raw)) == nil {
			t.Fatal("malformed metadata accepted")
		}
	}
}
func TestExplicitIntegrityKey(t *testing.T) {
	raw := strings.Replace(policyFixture, `"type":"hmac(sha256)"`, `"type":"hmac(sha256)","key_size":32`, 1)
	if err := CheckHeaderPolicy([]byte(raw)); err != nil {
		t.Fatal(err)
	}
}
