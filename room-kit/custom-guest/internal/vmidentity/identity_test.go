package vmidentity

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type measureVectors struct {
	CmdlineTemplate   string `json:"cmdline_template"`
	HostDataDomainHex string `json:"host_data_domain_hex"`
	Identities        map[string]struct {
		Cmdline        string `json:"cmdline"`
		HostDataHex    string `json:"host_data_hex"`
		IdentitySHA256 string `json:"identity_sha256"`
		IdentityUTF8   string `json:"identity_utf8"`
		SaltHex        string `json:"salt_hex"`
		SSHKeyLine     string `json:"ssh_key_line"`
		VMID           string `json:"vm_id"`
	} `json:"identities"`
}

func loadVectors(t *testing.T) measureVectors {
	t.Helper()
	raw, err := os.ReadFile("../../../../tests/fixtures/vm_measure_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v measureVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Identities) < 2 {
		t.Fatal("fixture lost its identities")
	}
	return v
}

func TestVectorsEqualVMMeasure(t *testing.T) {
	v := loadVectors(t)
	if v.CmdlineTemplate != CmdlineTemplateV1 {
		t.Fatalf("template differs from vm_measure.CMDLINE_TEMPLATE_V1:\n%q\n%q", v.CmdlineTemplate, CmdlineTemplateV1)
	}
	if v.HostDataDomainHex != hex.EncodeToString([]byte(HostDataDomain)) {
		t.Fatal("HOST_DATA domain differs")
	}
	for name, want := range v.Identities {
		id, err := Parse([]byte(want.IdentityUTF8))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if id.SHA256Hex() != want.IdentitySHA256 || id.VMID != want.VMID || id.SaltHex != want.SaltHex {
			t.Fatalf("%s: identity fields differ", name)
		}
		if !strings.HasPrefix(want.SSHKeyLine, id.SSHPublicKey+" ") {
			t.Fatalf("%s: key differs from the key line", name)
		}
		hd := id.HostData()
		if hex.EncodeToString(hd[:]) != want.HostDataHex {
			t.Fatalf("%s: HOST_DATA differs", name)
		}
		line, err := Cmdline(id.SHA256Hex())
		if err != nil || line != want.Cmdline {
			t.Fatalf("%s: cmdline differs", name)
		}
		got, err := Check(id.Raw, "initrd=initrd "+want.Cmdline+"\n")
		if err != nil || got.SHA256Hex() != want.IdentitySHA256 {
			t.Fatalf("%s: check failed: %v", name, err)
		}
	}
}

func TestCheckRefusesAnIdentityTheCmdlineDoesNotName(t *testing.T) {
	v := loadVectors(t)
	a, b := v.Identities["a"], v.Identities["b"]
	if _, err := Check([]byte(a.IdentityUTF8), "initrd=initrd "+b.Cmdline+"\n"); err == nil {
		t.Fatal("identity a booted under b's cmdline")
	}
}

func TestProcCmdlineRefusesEveryOtherByte(t *testing.T) {
	v := loadVectors(t)
	good := v.Identities["a"].Cmdline
	upper := strings.TrimSuffix(good, v.Identities["a"].IdentitySHA256) + strings.ToUpper(v.Identities["a"].IdentitySHA256)
	for name, proc := range map[string]string{
		"no OVMF prefix":     good + "\n",
		"two newlines":       "initrd=initrd " + good + "\n\n",
		"extra token":        "initrd=initrd " + good + " init=/bin/sh\n",
		"token in front":     "initrd=initrd single " + good + "\n",
		"uppercase identity": "initrd=initrd " + upper + "\n",
		"short identity":     "initrd=initrd " + good[:len(good)-1] + "\n",
		"empty":              "",
	} {
		if _, err := IdentityFromProcCmdline(proc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := IdentityFromProcCmdline("initrd=initrd " + good); err != nil {
		t.Fatalf("no trailing newline: %v", err)
	}
}

func TestParseRefusesWhatParseIdentityRefuses(t *testing.T) {
	v := loadVectors(t)
	good := v.Identities["a"].IdentityUTF8
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/"
	cases := map[string]string{
		"space after colon": strings.Replace(good, `"version":1`, `"version": 1`, 1),
		"version 2":         strings.Replace(good, `"version":1`, `"version":2`, 1),
		"version string":    strings.Replace(good, `"version":1`, `"version":"1"`, 1),
		"other schema":      strings.Replace(good, `identity/v1`, `identity/v2`, 1),
		"uppercase vm_id":   strings.Replace(good, `vm-0123456789ab`, `vm-0123456789AB`, 1),
		"short salt":        strings.Replace(good, `000102030405060708090a0b0c0d0e0f`, `000102030405060708090a0b0c0d0e`, 1),
		"key comment":       strings.Replace(good, key, key+" me@x", 1),
		"key type unknown":  strings.Replace(good, `ssh-ed25519 `, `ssh-dss `, 1),
		"key blob mismatch": strings.Replace(good, `"ssh-ed25519 AAAAC3`, `"ecdsa-sha2-nistp256 AAAAC3`, 1),
		"key noncanonical":  strings.Replace(good, `PT4/`, `PT4_`, 1),
		"verity short":      strings.Replace(good, strings.Repeat("1", 64), strings.Repeat("1", 63), 1),
		"data bytes odd":    strings.Replace(good, `"base_root_data_bytes":8192`, `"base_root_data_bytes":8193`, 1),
		"data bytes small":  strings.Replace(good, `"base_root_data_bytes":8192`, `"base_root_data_bytes":0`, 1),
		"unknown field":     strings.Replace(good, `{"base_root_data_bytes"`, `{"a":1,"base_root_data_bytes"`, 1),
		"missing field":     strings.Replace(good, `"salt_hex":"000102030405060708090a0b0c0d0e0f",`, ``, 1),
		"unsorted keys":     strings.Replace(good, `{"base_root_data_bytes":8192,"base_root_verity":"`+strings.Repeat("1", 64)+`"`, `{"base_root_verity":"`+strings.Repeat("1", 64)+`","base_root_data_bytes":8192`, 1),
		"unicode escape":    strings.Replace(good, `vm-0123456789ab`, "vm-0123456789a"+string(rune(92))+"u0062", 1),
		"trailing newline":  good + "\n",
		"nested object":     strings.Replace(good, `"version":1`, `"version":{"a":1}`, 1),
		"empty":             "",
		"oversize":          good + strings.Repeat(" ", DocMax),
	}
	for name, raw := range cases {
		if raw == good {
			t.Fatalf("%s: the mutation did not apply", name)
		}
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCanonicalGrammar(t *testing.T) {
	for _, ok := range []string{`{}`, `{"a":-5}`, `{"a":0,"b":"x\"y\\z"}`, `{"a":{"b":"c"}}`} {
		depth := 2
		if _, err := ParseCanonical([]byte(ok), depth); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`{"a":01}`, `{"a":-0}`, `{"a":1.0}`, `{"a":1e3}`, `{"a":true}`, `{"a":null}`, `{"a":[1]}`,
		`{"a":"\n"}`, `{"a":"\/"}`, `{"b":1,"a":2}`, `{"a":1,"a":1}`, `{"a":1} `, ` {"a":1}`,
		`{"a":99999999999999999999}`, `{"a":{"b":{"c":1}}}`, `{"a":"` + "\x7f" + `"}`, `{"a":1,}`, `{`,
	} {
		if _, err := ParseCanonical([]byte(bad), 2); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
	// A deep body is refused at the depth bound, without recursion past it.
	deep := strings.Repeat(`{"a":`, 30000) + "1" + strings.Repeat("}", 30000)
	if _, err := ParseCanonical([]byte(deep), 2); err == nil {
		t.Fatal("deep nesting accepted")
	}
}
