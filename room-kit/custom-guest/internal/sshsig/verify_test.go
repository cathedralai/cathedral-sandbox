package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

const fixture = "../../../../tests/fixtures/vm_rewrap_answer_v2.json"

type vectorCase struct {
	Name       string  `json:"name"`
	Identity   string  `json:"identity_ssh_public_key"`
	Body       string  `json:"body"`
	Refusal    *string `json:"refusal"`
	MessageHex string  `json:"message_hex"`
}

type vectors struct {
	Namespace string       `json:"namespace"`
	Cases     []vectorCase `json:"cases"`
}

func load(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Namespace != "vm-rewrap-answer-v2@cathedral.computer" || len(v.Cases) < 25 {
		t.Fatalf("unexpected fixture: namespace %q, %d cases", v.Namespace, len(v.Cases))
	}
	return v
}

// The answer-level refusals belong to the mailbox parser (vmmailbox), not to this package.
var answerLevel = map[string]bool{"answer_schema": true, "answer_too_long": true, "sig_encoding": true,
	"sig_too_long": true}

// TestVectors: every case of the shared fixture that reaches the signature gets exactly the
// fixture's result: nil for the valid answer of each key type, its refusal code otherwise.
func TestVectors(t *testing.T) {
	v := load(t)
	valid, refused := 0, 0
	for _, c := range v.Cases {
		if c.Refusal != nil && answerLevel[*c.Refusal] {
			continue
		}
		var body struct {
			Sig string `json:"sig"`
		}
		if err := json.Unmarshal([]byte(c.Body), &body); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		blob, err := base64.StdEncoding.Strict().DecodeString(body.Sig)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		message, err := hex.DecodeString(c.MessageHex)
		if err != nil || len(message) != 154 {
			t.Fatalf("%s: message %d bytes, %v", c.Name, len(message), err)
		}
		err = Verify(c.Identity, v.Namespace, message, blob)
		switch {
		case c.Refusal == nil && err != nil:
			t.Errorf("%s: want valid, got %v", c.Name, err)
		case c.Refusal == nil:
			valid++
		case err == nil || err.Error() != *c.Refusal:
			t.Errorf("%s: want %s, got %v", c.Name, *c.Refusal, err)
		default:
			refused++
		}
	}
	if valid != 8 || refused < 15 {
		t.Fatalf("checked %d valid and %d refused cases", valid, refused)
	}
}

// TestEveryKeyTypeIsCovered: the fixture's valid answers use every type vmidentity allows.
func TestEveryKeyTypeIsCovered(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range load(t).Cases {
		if c.Refusal == nil {
			kind, _, _ := bytes.Cut([]byte(c.Identity), []byte(" "))
			seen[string(kind)] = true
		}
	}
	for kind := range keyTypes {
		if !seen[kind] {
			t.Errorf("no valid vector for %s", kind)
		}
	}
	if len(seen) != len(keyTypes) {
		t.Errorf("vector key types %v", seen)
	}
}

// TestAnyChangeIsRefused: one valid answer per key type, with each byte of its message and of its
// blob changed in turn. Nothing but the original verifies.
func TestAnyChangeIsRefused(t *testing.T) {
	v := load(t)
	for _, c := range v.Cases {
		if c.Refusal != nil {
			continue
		}
		var body struct {
			Sig string `json:"sig"`
		}
		_ = json.Unmarshal([]byte(c.Body), &body)
		blob, _ := base64.StdEncoding.DecodeString(body.Sig)
		message, _ := hex.DecodeString(c.MessageHex)
		for i := range message {
			message[i] ^= 0x01
			if Verify(c.Identity, v.Namespace, message, blob) == nil {
				t.Fatalf("%s: message byte %d changed, still valid", c.Name, i)
			}
			message[i] ^= 0x01
		}
		step := 1
		if len(blob) > 1200 {
			step = 7 // RSA 8192: a sample of positions keeps the test fast
		}
		for i := 0; i < len(blob); i += step {
			blob[i] ^= 0x01
			if Verify(c.Identity, v.Namespace, message, blob) == nil {
				t.Fatalf("%s: blob byte %d changed, still valid", c.Name, i)
			}
			blob[i] ^= 0x01
		}
		if err := Verify(c.Identity, v.Namespace, message, blob); err != nil {
			t.Fatalf("%s: the restored answer fails: %v", c.Name, err)
		}
	}
}

// TestRefusesBeforeArithmetic: a blob that names another key is refused as publickey_mismatch
// whatever its signature holds, and a key line the identity rules refuse never reaches the blob.
func TestRefusesBeforeArithmetic(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	other, _, _ := ed25519.GenerateKey(nil)
	key := func(p ed25519.PublicKey) []byte {
		return append(sshString([]byte("ssh-ed25519")), sshString(p)...)
	}
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(key(pub))
	msg := []byte("m")
	sign := func(signer ed25519.PrivateKey, named []byte, ns string) []byte {
		sig := append(sshString([]byte("ssh-ed25519")), sshString(ed25519.Sign(signer, SignedData(ns, msg)))...)
		out := append([]byte("SSHSIG"), 0, 0, 0, 1)
		for _, f := range [][]byte{named, []byte(ns), nil, []byte("sha512"), sig} {
			out = append(out, sshString(f)...)
		}
		return out
	}
	const ns = "vm-rewrap-answer-v2@cathedral.computer"
	if err := Verify(line, ns, msg, sign(priv, key(pub), ns)); err != nil {
		t.Fatalf("own signature: %v", err)
	}
	if err := Verify(line, ns, msg, sign(priv, key(other), ns)); !errors.Is(err, ErrPublicKey) {
		t.Fatalf("other key named: %v", err)
	}
	if err := Verify(line, ns, msg, sign(priv, key(pub), "file")); !errors.Is(err, ErrNamespace) {
		t.Fatalf("namespace file: %v", err)
	}
	for _, bad := range []string{"", "ssh-ed25519", "ssh-dss AAAA", "ssh-ed25519 !!!!", line + " comment"} {
		if err := Verify(bad, ns, msg, sign(priv, key(pub), ns)); !errors.Is(err, ErrKey) {
			t.Errorf("key line %q: %v", bad, err)
		}
	}
}

// TestEveryAllowedKeyShapeParses: every key VM create allows (tests/fixtures/
// vm_ssh_key_shapes_v1.json) is one the verifier reads, so no allowed key is stranded at re-wrap.
func TestEveryAllowedKeyShapeParses(t *testing.T) {
	raw, err := os.ReadFile("../../../../tests/fixtures/vm_ssh_key_shapes_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []struct {
			Name    string  `json:"name"`
			Key     string  `json:"ssh_public_key"`
			Refusal *string `json:"refusal"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	allowed := 0
	for _, c := range f.Cases {
		if c.Refusal != nil {
			continue
		}
		if _, _, err := parseKey(c.Key); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
		allowed++
	}
	if allowed != 9 {
		t.Fatalf("%d allowed shapes", allowed)
	}
}
