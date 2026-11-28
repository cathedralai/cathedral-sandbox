package vmidentity

import (
	"encoding/json"
	"os"
	"testing"
)

// TestRewrapKeyShapeVectors: CheckRewrapKey gives each case of the shared key-shape vectors the
// code vm_measure.rewrap_key_shape gives it, and CheckSSHKey, which every boot runs, still
// accepts every one of them (spec r4 erratum 2.5: the shape is checked at create only).
func TestRewrapKeyShapeVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../../tests/fixtures/vm_ssh_key_shapes_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		KeyBlobMax int `json:"key_blob_max_bytes"`
		Cases      []struct {
			Name    string  `json:"name"`
			Key     string  `json:"ssh_public_key"`
			Refusal *string `json:"refusal"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.KeyBlobMax != RewrapKeyMax || len(f.Cases) < 20 {
		t.Fatalf("fixture: blob max %d, %d cases", f.KeyBlobMax, len(f.Cases))
	}
	allowed := 0
	for _, c := range f.Cases {
		err := CheckRewrapKey(c.Key)
		switch {
		case c.Refusal == nil && err != nil:
			t.Errorf("%s: refused as %v", c.Name, err)
		case c.Refusal == nil:
			allowed++
		case err == nil || err.Error() != *c.Refusal:
			t.Errorf("%s: want %s, got %v", c.Name, *c.Refusal, err)
		}
		if err := CheckSSHKey(c.Key); err != nil {
			t.Errorf("%s: CheckSSHKey refuses it, so an existing VM with this key would not boot", c.Name)
		}
	}
	if allowed != 9 {
		t.Fatalf("%d allowed shapes", allowed)
	}
	for _, bad := range []string{"", "ssh-ed25519", "ssh-dss AAAAB3NzaC1kc3M=", "ssh-ed25519 !!!!"} {
		if err := CheckRewrapKey(bad); err == nil || err.Error() != "key_format" {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
