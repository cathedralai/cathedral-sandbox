package snpverify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"
)

// synth is a throwaway hotel: a fixed test seed (not a secret), a binding that
// names its public key, and signed receipts. The AMD part is not involved, so
// every rule can be broken alone and the rest stays correctly signed.
type synth struct {
	priv ed25519.PrivateKey
	att  Attestation
}

func newSynth(t *testing.T, mutBinding func(map[string]any)) *synth {
	t.Helper()
	priv := ed25519.NewKeyFromSeed([]byte("cathedral-snp-verifier-test-seed"))
	binding := map[string]any{
		"receipt_key_ed25519_b64": base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		"schema":                  SealedBindingSchema,
	}
	if mutBinding != nil {
		mutBinding(binding)
	}
	canon, err := Canonical(binding)
	if err != nil {
		t.Fatal(err)
	}
	return &synth{priv: priv, att: Attestation{Binding: binding, BindingSHA256: sha256Hex(canon)}}
}

// signBytes signs and hashes the given statement bytes, whatever canonical form they are in.
func (s *synth) signBytes(t *testing.T, statementJSON string, canonBytes string) Receipt {
	t.Helper()
	v, err := ParseKeepingNumbers([]byte(statementJSON))
	if err != nil {
		t.Fatal(err)
	}
	return Receipt{
		Statement:     v.(map[string]any),
		ReceiptSHA256: sha256Hex([]byte(canonBytes)),
		SignatureB64:  base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, []byte(canonBytes))),
	}
}

// chain builds receipts 1..len(extras); extras[i] is merged into statement i+1.
func (s *synth) chain(t *testing.T, extras ...map[string]any) []Receipt {
	t.Helper()
	var out []Receipt
	prev := s.att.BindingSHA256
	for i, extra := range extras {
		st := map[string]any{
			"action": "exec", "binding_sha256": s.att.BindingSHA256,
			"sequence": json.Number(strconv.Itoa(i + 1)), "previous_receipt_sha256": prev,
		}
		for k, v := range extra {
			if _, isNull := v.(explicitNull); isNull {
				st[k] = nil
			} else if v == nil {
				delete(st, k)
			} else {
				st[k] = v
			}
		}
		c, err := Canonical(st)
		if err != nil {
			t.Fatal(err)
		}
		rc := Receipt{Statement: st, ReceiptSHA256: sha256Hex(c), SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, c))}
		out = append(out, rc)
		prev = rc.ReceiptSHA256
	}
	return out
}

// runChecks is VerifyAll without the AMD part, in the same order.
func runChecks(att Attestation, rcs []Receipt, head string) error {
	if err := verifyGuestTLS(att); err != nil {
		return err
	}
	if _, err := VerifyReceipts(att, rcs, head); err != nil {
		return err
	}
	if _, err := policyTimeline(rcs); err != nil {
		return err
	}
	if _, err := roomTunables(rcs); err != nil {
		return err
	}
	_, err := roomLinks(rcs)
	return err
}

func policyHash(t *testing.T, p any) string {
	t.Helper()
	h, err := sha256Canonical(p)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// explicitNull puts a JSON null in the statement; a nil value deletes the key.
type explicitNull struct{}

func num(s string) json.Number { return json.Number(s) }

func TestPythonCanonicalNumbersInReceipts(t *testing.T) {
	s := newSynth(t, nil)
	b := s.att.BindingSHA256
	// The statement as the hotel sent it carries 1E5. Python loads that as the
	// float 100000.0 and hashes and verifies the bytes below.
	text := `{"action":"exec","binding_sha256":"` + b + `","n":1E5,"previous_receipt_sha256":"` + b + `","sequence":1}`
	pythonBytes := `{"action":"exec","binding_sha256":"` + b + `","n":100000.0,"previous_receipt_sha256":"` + b + `","sequence":1}`
	literalBytes := `{"action":"exec","binding_sha256":"` + b + `","n":1E5,"previous_receipt_sha256":"` + b + `","sequence":1}`

	t.Run("signed over the Python bytes passes", func(t *testing.T) {
		rc := s.signBytes(t, text, pythonBytes)
		if _, err := VerifyReceipts(s.att, []Receipt{rc}, ""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("signed over the literal bytes fails", func(t *testing.T) {
		rc := s.signBytes(t, text, literalBytes)
		_, err := VerifyReceipts(s.att, []Receipt{rc}, "")
		wantCode(t, err, CodeReceiptHashMismatch)
	})
}

func TestNetworkPolicyRule(t *testing.T) {
	s := newSynth(t, nil)
	policy := map[string]any{"mode": "allowlist", "allow": []any{"example.com"}}
	good := map[string]any{"sandbox_id": "sbx1", "action": "create", "status": num("200"), "issued_at": num("5"),
		"network_policy": policy, "network_policy_sha256": policyHash(t, policy)}
	if err := runChecks(s.att, s.chain(t, good), ""); err != nil {
		t.Fatal(err)
	}
	tl, _ := policyTimeline(s.chain(t, good, map[string]any{"sandbox_id": "sbx1", "action": "delete", "status": num("200"), "issued_at": num("6")}))
	if len(tl["sbx1"]) != 2 || tl["sbx1"][1].Action != "delete" {
		t.Fatalf("timeline %+v", tl)
	}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		m[k] = v
		return m
	}
	bad := map[string]map[string]any{
		"hash wrong":        with("network_policy_sha256", strings.Repeat("0", 64)),
		"hash missing":      with("network_policy_sha256", nil),
		"policy changed":    with("network_policy", map[string]any{"mode": "open", "allow": []any{}}),
		"policy not object": with("network_policy", "x"),
		"issued_at missing": with("issued_at", nil),
		"status missing":    with("status", nil),
		"room is a list":    with("sandbox_id", []any{"a"}),
	}
	for name, st := range bad {
		t.Run(name, func(t *testing.T) {
			wantCode(t, runChecks(s.att, s.chain(t, st), ""), CodeNetworkPolicyMismatch)
		})
	}
	t.Run("no sandbox id is skipped", func(t *testing.T) {
		st := with("sandbox_id", nil)
		st["network_policy_sha256"] = strings.Repeat("0", 64)
		if err := runChecks(s.att, s.chain(t, st), ""); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("delete event without status", func(t *testing.T) {
		rcs := s.chain(t, good, map[string]any{"sandbox_id": "sbx1", "action": "delete", "issued_at": num("6")})
		wantCode(t, runChecks(s.att, rcs, ""), CodeNetworkPolicyMismatch)
	})
}

func TestTunablesRule(t *testing.T) {
	s := newSynth(t, nil)
	tun := map[string]any{"cpu": num("2"), "x": []any{true, nil}}
	good := map[string]any{"action": "create", "sandbox_id": "sbx1", "tunables": tun, "tunables_sha256": policyHash(t, tun)}
	if err := runChecks(s.att, s.chain(t, good), ""); err != nil {
		t.Fatal(err)
	}
	rooms, _ := roomTunables(s.chain(t, good))
	if rooms["sbx1"] != policyHash(t, tun) {
		t.Fatalf("%v", rooms)
	}
	badHash := map[string]any{"action": "create", "sandbox_id": "sbx1", "tunables": tun, "tunables_sha256": strings.Repeat("1", 64)}
	wantCode(t, runChecks(s.att, s.chain(t, badHash), ""), CodeTunablesMismatch)
	missing := map[string]any{"action": "create", "tunables": tun}
	wantCode(t, runChecks(s.att, s.chain(t, missing), ""), CodeTunablesMismatch)
	listRoom := map[string]any{"action": "create", "sandbox_id": []any{"a"}, "tunables": tun, "tunables_sha256": policyHash(t, tun)}
	// The policy check runs first and refuses such a room too; roomTunables alone does the same.
	_, err := roomTunables(s.chain(t, listRoom))
	wantCode(t, err, CodeTunablesMismatch)
	wantCode(t, runChecks(s.att, s.chain(t, listRoom), ""), CodeNetworkPolicyMismatch)
	// Only create receipts are read.
	notCreate := map[string]any{"action": "exec", "tunables": tun, "tunables_sha256": strings.Repeat("1", 64)}
	if err := runChecks(s.att, s.chain(t, notCreate), ""); err != nil {
		t.Fatal(err)
	}
}

func TestSandboxLinkRule(t *testing.T) {
	s := newSynth(t, nil)
	const id = "0123abcd-4567-89ab-cdef-0123456789ab"
	good := map[string]any{"action": "create", "sandbox_id": "sbx1", "status": num("201"), "cathedral_sandbox_id": id}
	if err := runChecks(s.att, s.chain(t, good), ""); err != nil {
		t.Fatal(err)
	}
	links, _ := roomLinks(s.chain(t, good))
	if links["sbx1"] != id {
		t.Fatalf("%v", links)
	}
	failed := map[string]any{"action": "create", "sandbox_id": "sbx1", "status": num("500"), "cathedral_sandbox_id": id}
	if l, err := roomLinks(s.chain(t, failed)); err != nil || len(l) != 0 {
		t.Fatalf("a failed create must not link: %v %v", l, err)
	}
	for name, link := range map[string]any{
		"upper case": strings.ToUpper(id), "trailing newline": id + "\n", "short": id[:35], "number": num("5"),
		"null": explicitNull{}, "no dashes": strings.ReplaceAll(id, "-", ""), "non hex": strings.Replace(id, "0", "g", 1),
	} {
		t.Run(name, func(t *testing.T) {
			st := map[string]any{"action": "create", "sandbox_id": "sbx1", "status": num("200"), "cathedral_sandbox_id": link}
			// A JSON null is "present" for Python's `in` test, so it must be refused too.
			wantCode(t, runChecks(s.att, s.chain(t, st), ""), CodeSandboxLinkMalformed)
		})
	}
	t.Run("status that is not an integer", func(t *testing.T) {
		st := map[string]any{"action": "create", "sandbox_id": "sbx1", "status": "ok", "cathedral_sandbox_id": id}
		wantCode(t, runChecks(s.att, s.chain(t, st), ""), CodeSandboxLinkMalformed)
	})
	t.Run("float status is truncated like int()", func(t *testing.T) {
		st := map[string]any{"action": "create", "sandbox_id": "sbx1", "status": num("299.9"), "cathedral_sandbox_id": id}
		l, err := roomLinks(s.chain(t, st))
		if err != nil || l["sbx1"] != id {
			t.Fatalf("%v %v", l, err)
		}
	})
}

func TestGuestTLSRule(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	good := func(b map[string]any) {
		b["tls_spki_sha256"] = strings.Repeat("a", 64)
		b["hotel_key_install_x25519_b64"] = key
		b["hotel_key_install_signers_ed25519_b64"] = []any{key}
		b["hotel_key_source"] = "install"
	}
	if err := verifyGuestTLS(newSynth(t, good).att); err != nil {
		t.Fatal(err)
	}
	if err := verifyGuestTLS(newSynth(t, nil).att); err != nil {
		t.Fatalf("a binding with no TLS key passes: %v", err)
	}
	if err := verifyGuestTLS(newSynth(t, func(b map[string]any) { b["tls_spki_sha256"] = nil }).att); err != nil {
		t.Fatalf("a null TLS key is the same as none: %v", err)
	}
	bad := map[string]func(map[string]any){
		"tls upper case":      func(b map[string]any) { b["tls_spki_sha256"] = strings.Repeat("A", 64) },
		"tls short":           func(b map[string]any) { b["tls_spki_sha256"] = strings.Repeat("a", 63) },
		"tls not a string":    func(b map[string]any) { b["tls_spki_sha256"] = num("1") },
		"install key missing": func(b map[string]any) { delete(b, "hotel_key_install_x25519_b64") },
		"install key short": func(b map[string]any) {
			b["hotel_key_install_x25519_b64"] = base64.StdEncoding.EncodeToString(make([]byte, 31))
		},
		"install key newline": func(b map[string]any) { b["hotel_key_install_x25519_b64"] = key[:8] + "\n" + key[8:] },
		"install key no pad":  func(b map[string]any) { b["hotel_key_install_x25519_b64"] = strings.TrimRight(key, "=") },
		"signers missing":     func(b map[string]any) { delete(b, "hotel_key_install_signers_ed25519_b64") },
		"signers empty":       func(b map[string]any) { b["hotel_key_install_signers_ed25519_b64"] = []any{} },
		"signer bad":          func(b map[string]any) { b["hotel_key_install_signers_ed25519_b64"] = []any{key, "AAAA"} },
		"signer not a string": func(b map[string]any) { b["hotel_key_install_signers_ed25519_b64"] = []any{num("1")} },
		"source not install":  func(b map[string]any) { b["hotel_key_source"] = "generated" },
		"source missing":      func(b map[string]any) { delete(b, "hotel_key_source") },
	}
	for name, mut := range bad {
		t.Run(name, func(t *testing.T) {
			wantCode(t, verifyGuestTLS(newSynth(t, func(b map[string]any) { good(b); mut(b) }).att), CodeGuestTLSMalformed)
		})
	}
}

func TestSequenceSpanLimit(t *testing.T) {
	s := newSynth(t, nil)
	first := s.chain(t, map[string]any{})
	far := map[string]any{"action": "exec", "binding_sha256": s.att.BindingSHA256, "sequence": num(strconv.FormatInt(math.MaxInt64, 10)),
		"previous_receipt_sha256": "x"}
	c, _ := Canonical(far)
	last := Receipt{Statement: far, ReceiptSHA256: sha256Hex(c), SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, c))}
	_, err := VerifyReceipts(s.att, []Receipt{first[0], last}, "")
	wantCode(t, err, CodeChainGap)
	// A span at the limit is still checked, not refused.
	near := map[string]any{"action": "exec", "binding_sha256": s.att.BindingSHA256, "sequence": num("10000001"), "previous_receipt_sha256": "x"}
	c, _ = Canonical(near)
	nearRc := Receipt{Statement: near, ReceiptSHA256: sha256Hex(c), SignatureB64: base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, c))}
	if res, err := VerifyReceipts(s.att, []Receipt{first[0], nearRc}, ""); err != nil || res.Contiguous {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestHugeIntegerInDocuments(t *testing.T) {
	digits := strings.Repeat("9", 5000)
	good := string(readFile(t, "testdata/attestation-proof.json"))
	envelope := "{\"pad\":" + digits + "," + strings.TrimPrefix(strings.TrimSpace(good), "{")
	if _, err := ParseAttestation([]byte(envelope)); err == nil {
		t.Fatal("expected refusal")
	} else {
		wantCode(t, err, CodeBadInput)
	}
	ok := "{\"pad\":" + strings.Repeat("9", 4300) + "," + strings.TrimPrefix(strings.TrimSpace(good), "{")
	if _, err := ParseAttestation([]byte(ok)); err != nil {
		t.Fatalf("4300 digits is allowed: %v", err)
	}
	_, _, err := ParseReceipts([]byte("[" + digits + "]"))
	wantCode(t, err, CodeBadInput)
}

func TestProductOverrideCannotContradictReport(t *testing.T) {
	att := loadAtt(t, "attestation-proof.json")
	o := goodOpts(t)
	o.Product = "Milan"
	_, err := VerifyAttestation(att, o)
	wantCode(t, err, CodeUnsupportedProduct)
	o.Product = "Genoa"
	res, err := VerifyAttestation(att, o)
	if err != nil || res.AMD.Product != "Genoa" {
		t.Fatalf("%v", err)
	}
}

func TestVerifyAllOnRealFixtures(t *testing.T) {
	rcs, _ := loadReceipts(t, "receipts-first5.json")
	all, err := VerifyAll(loadAtt(t, "attestation-proof.json"), rcs, "", goodOpts(t))
	if err != nil {
		t.Fatal(err)
	}
	if all.Chain.Receipts != 5 || len(all.PolicyTimeline) == 0 {
		t.Fatalf("the policy check did not run: %+v", all.PolicyTimeline)
	}
	// An attestation failure stops VerifyAll before the receipts.
	bad := goodOpts(t)
	bad.ARKPins = []string{milanPin}
	_, err = VerifyAll(loadAtt(t, "attestation-proof.json"), rcs, "", bad)
	wantCode(t, err, CodeARKNotPinned)
}
