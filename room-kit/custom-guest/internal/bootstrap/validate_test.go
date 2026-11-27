package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func vector(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../../../tests/fixtures/custom_guest_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]json.RawMessage
	if err = json.Unmarshal(raw, &values); err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for name, value := range values {
		var s string
		if json.Unmarshal(value, &s) == nil {
			result[name] = s
		}
	}
	return result
}
func jsonBytes(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
func signed(t *testing.T, m, b map[string]any) ([]byte, []byte, []byte, string) {
	t.Helper()
	mr := jsonBytes(m)
	hash := sha256.Sum256(mr)
	b["manifest_sha256"] = hex.EncodeToString(hash[:])
	br := jsonBytes(b)
	bh := sha256.Sum256(br)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), append([]byte(signatureDomain), bh[:]...))
	return mr, br, sig, "initrd=initrd " + m["cmdline"].(string) + "\n"
}
func documents(t *testing.T) (map[string]any, map[string]any) {
	v := vector(t)
	var m, b map[string]any
	if err := json.Unmarshal([]byte(v["manifest_utf8"]), &m); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(v["bootstrap_utf8"]), &b); err != nil {
		t.Fatal(err)
	}
	return m, b
}

func TestPythonLaunchVectorAndOmittedDataDisk(t *testing.T) {
	v := vector(t)
	sig, err := hex.DecodeString(v["signature_hex"])
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err = json.Unmarshal([]byte(v["manifest_utf8"]), &m); err != nil {
		t.Fatal(err)
	}
	got, err := Validate([]byte(v["manifest_utf8"]), []byte(v["bootstrap_utf8"]), sig, "initrd=initrd "+m.Cmdline+"\n")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got.HostData[:]) != v["host_data_hex"] || hex.EncodeToString(got.Owner[:]) != v["owner_public_hex"] {
		t.Fatal("Python HOST_DATA/owner differs")
	}
	md, bd := documents(t)
	delete(md, "data_disk_gib")
	got, err = Validate(signed(t, md, bd))
	if err != nil || got.Manifest.DataDiskGiB != 0 {
		t.Fatalf("omitted optional field: %v", err)
	}
}

func TestCanonicalDocumentRejections(t *testing.T) {
	for _, raw := range []string{`{"a":true}`, `{"a":null}`, `{"a":1.0}`, `{"a":-0}`, `{"a":1e1}`, `{"a":9223372036854775808}`, `{"a":1,"a":1}`, `{"a":1} `, `{"a":"\u0061"}`, `{"a":"\n"}`, `{"a":"é"}`, `{"b":1,"a":2}`, `[]`, `{`} {
		var target map[string]any
		if err := decode([]byte(raw), &target); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	var target map[string]any
	if err := decode([]byte(`{"a":"<>&"}`), &target); err != nil {
		t.Fatal("HTML characters must match Python canonical encoding", err)
	}
	if err := decode(bytes.Repeat([]byte(" "), documentLimit+1), &target); err == nil {
		t.Fatal("oversized document accepted")
	}
}

func TestSignedFieldNamesAreCaseSensitive(t *testing.T) {
	for _, object := range []string{"manifest", "bootstrap", "network", "port"} {
		for _, duplicate := range []bool{false, true} {
			t.Run(object+map[bool]string{false: "-renamed", true: "-duplicate"}[duplicate], func(t *testing.T) {
				m, b := documents(t)
				var target map[string]any
				var key string
				switch object {
				case "manifest":
					target, key = m, "version"
				case "bootstrap":
					target, key = b, "hotel"
				case "network":
					target, key = b["network"].(map[string]any), "prefix"
				case "port":
					target, key = b["ports"].([]any)[0].(map[string]any), "guest"
				}
				target[strings.ToUpper(key)] = target[key]
				if !duplicate {
					delete(target, key)
				}
				if _, err := Validate(signed(t, m, b)); err == nil {
					t.Fatal("signed case-variant field accepted")
				}
			})
		}
	}
}

func TestSignedInvalidManifestRejectedBeforeUse(t *testing.T) {
	for _, name := range []string{"version", "unknown", "missing", "file_digest", "file_size", "extra_file", "vcpus", "memory", "disk", "cpu", "policy", "qemu", "measure", "initrd", "root_hash", "root_offset", "cmdline_digest"} {
		t.Run(name, func(t *testing.T) {
			m, b := documents(t)
			switch name {
			case "version":
				m["version"] = 2
			case "unknown":
				m["unsafe"] = 1
			case "missing":
				delete(m, "kind")
			case "file_digest":
				m["sha256"].(map[string]any)["vmlinuz"] = "bad"
			case "file_size":
				m["bytes"].(map[string]any)["root.raw"] = 0
			case "extra_file":
				m["bytes"].(map[string]any)["extra"] = 1
			case "vcpus":
				m["vcpus"] = 57
			case "memory":
				m["mem_gib"] = 0
			case "disk":
				m["data_disk_gib"] = 401
			case "cpu":
				m["cpu_model"] = "host"
			case "policy":
				m["policy"] = "0xb0000"
			case "qemu":
				m["qemu_version"] = "other"
			case "measure":
				m["sev_snp_measure"] = "other"
			case "initrd":
				m["reference_initrd"] = "../anything"
			case "root_hash":
				m["root_verity"] = strings.Repeat("ff", 32)
			case "root_offset":
				m["root_data_bytes"] = 0
			case "cmdline_digest":
				m["sha256"].(map[string]any)["cmdline"] = strings.Repeat("ff", 32)
			}
			if _, err := Validate(signed(t, m, b)); err == nil {
				t.Fatal("signed invalid manifest accepted")
			}
		})
	}
}

func TestSignedInvalidBootstrapRejectedBeforeUse(t *testing.T) {
	for _, name := range []string{"version", "unknown", "launch", "hotel", "scope", "owner", "nonce", "ssh_type", "ssh_blob", "port_public", "port_guest", "port_repeat", "port_first", "proto", "network_prefix", "network_subnet", "network_equal", "network_broadcast", "network_v6", "mac", "nested_unknown"} {
		t.Run(name, func(t *testing.T) {
			m, b := documents(t)
			port := b["ports"].([]any)[0].(map[string]any)
			network := b["network"].(map[string]any)
			switch name {
			case "version":
				b["version"] = 2
			case "unknown":
				b["extra"] = 1
			case "launch":
				b["launch_id"] = "bad"
			case "hotel":
				b["hotel"] = "UPPER"
			case "scope":
				b["owner_scope"] = "user:------------------------------------"
			case "owner":
				b["owner_ed25519_b64"] = "bad"
			case "nonce":
				b["launch_nonce_hex"] = "bad"
			case "ssh_type":
				b["ssh_public_key"] = "ssh-dss AAAA"
			case "ssh_blob":
				b["ssh_public_key"] = "ssh-ed25519 AAAA"
			case "port_public":
				port["public"] = 22
			case "port_guest":
				port["guest"] = 65536
			case "port_repeat":
				b["ports"] = []any{port, map[string]any{"guest": 80, "public": port["public"], "proto": "tcp"}}
			case "port_first":
				port["guest"] = 80
			case "proto":
				port["proto"] = "udp"
			case "network_prefix":
				network["prefix"] = 24
			case "network_subnet":
				network["guest_ip"] = "10.218.0.2"
			case "network_equal":
				network["guest_ip"] = network["host_ip"]
			case "network_broadcast":
				network["guest_ip"] = "10.217.0.3"
			case "network_v6":
				network["public_host"] = "::1"
			case "mac":
				network["guest_mac"] = "00:00:00:00:00:00"
			case "nested_unknown":
				network["extra"] = 1
			}
			if _, err := Validate(signed(t, m, b)); err == nil {
				t.Fatal("signed invalid bootstrap accepted")
			}
		})
	}
}

func TestCmdlineAllowlistAndMeasuredAnchor(t *testing.T) {
	m, b := documents(t)
	line := m["cmdline"].(string)
	for _, bad := range []string{" " + line, line + " ", line + "  quiet", line + " init=/bin/sh", line + " root=/dev/vda", line + " systemd.import_credentials=yes", line + " quiet=1", line + " panic=3601", line + " loglevel=8", line + " cathedral.owner=x"} {
		if _, err := Cmdline(bad, 8192); err == nil {
			t.Fatal("cmdline override accepted")
		}
	}
	mr, br, sig, proc := signed(t, m, b)
	for _, bad := range []string{proc + "\n", strings.TrimPrefix(proc, "initrd=initrd "), proc + "extra", proc[:len(proc)-2]} {
		if _, err := Validate(mr, br, sig, bad); err == nil {
			t.Fatal("different measured cmdline accepted")
		}
	}
	sig[0] ^= 1
	if _, err := Validate(mr, br, sig, proc); err == nil {
		t.Fatal("invalid owner signature accepted")
	}
}
