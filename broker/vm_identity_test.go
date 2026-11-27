package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The customer's identity document (spec r2 6.3) reaches them byte for byte: create's 201,
// GET /vms/{id} and GET /vms carry the host's answer as host_status, identity_document included.
// verify_vm.py hashes it, so one changed byte would fail every customer check.
func TestVMsCreateAndGetPassTheIdentityDocumentThrough(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "tests", "fixtures", "vm_measure_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Identities map[string]struct {
			Text   string `json:"identity_utf8"`
			SHA256 string `json:"identity_sha256"`
		} `json:"identities"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil || len(vectors.Identities) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	for label, id := range vectors.Identities {
		if sum := sha256.Sum256([]byte(id.Text)); hex.EncodeToString(sum[:]) != id.SHA256 {
			t.Fatalf("%s: the vector's text is not its identity_sha256", label)
		}
		tb := newVMTestBroker(t, true)
		answer := func(name string) map[string]any {
			return map[string]any{"name": name, "state": "created", "identity_document": id.Text, "identity_sha256": id.SHA256}
		}
		tb.host.answer = func(args []string) ([]byte, int, error) {
			var doc any = map[string]any{"ok": true}
			switch args[0] {
			case "create", "status":
				doc = answer(args[1])
			case "list":
				doc = map[string]any{"vms": []any{answer(tb.host.lastOf("create")[2])}}
			}
			out, _ := json.Marshal(doc)
			return append(out, '\n'), 0, nil
		}
		created := tb.create(t, nil)
		vmID := created["id"].(string)
		st, got := tb.call(t, "operator-key", "GET", "/v1/broker/vms/"+vmID, nil)
		if st != 200 {
			t.Fatalf("%s: get: %d %v", label, st, got)
		}
		st, all := tb.call(t, "operator-key", "GET", "/v1/broker/vms", nil)
		if st != 200 {
			t.Fatalf("%s: list: %d %v", label, st, all)
		}
		listed := all["vms"].([]any)[0].(map[string]any)
		for where, v := range map[string]map[string]any{"create": created, "get": got, "list": listed} {
			hs, ok := v["host_status"].(map[string]any)
			if !ok {
				t.Fatalf("%s %s: no host_status: %v", label, where, v)
			}
			if hs["identity_document"] != id.Text || hs["identity_sha256"] != id.SHA256 {
				t.Fatalf("%s %s: identity_document changed: %q", label, where, hs["identity_document"])
			}
		}
	}
}
