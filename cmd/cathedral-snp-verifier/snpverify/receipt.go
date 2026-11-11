package snpverify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

// Receipt is one signed statement. Statement keeps parsed numbers as literals.
type Receipt struct {
	ReceiptSHA256 string
	SignatureB64  string
	Statement     map[string]any
}

// ReceiptsResult mirrors the "chain" object of verify_receipts.py.
type ReceiptsResult struct {
	Receipts     int            `json:"receipts"`
	SignaturesOK int            `json:"signatures_ok"`
	LinksChecked int            `json:"links_checked"`
	Contiguous   bool           `json:"contiguous"`
	First        *int64         `json:"first"`
	Last         *int64         `json:"last"`
	Actions      map[string]int `json:"actions"`
}

func receiptFromValue(v any) (Receipt, error) {
	var rc Receipt
	m, ok := v.(map[string]any)
	if !ok {
		return rc, fail(CodeReceiptMalformed, "receipt is not an object")
	}
	st, ok := m["statement"].(map[string]any)
	if !ok {
		return rc, fail(CodeReceiptMalformed, "receipt statement is missing or not an object")
	}
	if rc.ReceiptSHA256, ok = m["receipt_sha256"].(string); !ok {
		return rc, fail(CodeReceiptMalformed, "receipt_sha256 is missing or not a string")
	}
	if rc.SignatureB64, ok = m["signature_b64"].(string); !ok {
		return rc, fail(CodeReceiptMalformed, "signature_b64 is missing or not a string")
	}
	rc.Statement = st
	return rc, validateReceipt(rc)
}

// validateReceipt checks the field types the verifier reads. A missing or
// mistyped field is a failure: Python would crash on it, and a default would let it pass.
func validateReceipt(rc Receipt) error {
	st := rc.Statement
	if st == nil {
		return fail(CodeReceiptMalformed, "receipt statement is missing")
	}
	for _, k := range []string{"binding_sha256", "previous_receipt_sha256", "action"} {
		if _, ok := st[k].(string); !ok {
			return fail(CodeReceiptMalformed, "statement %s is missing or not a string", k)
		}
	}
	if seq, ok := sequenceOf(st); !ok || seq < 1 {
		return fail(CodeReceiptMalformed, "statement sequence is missing or not an integer of 1 or more")
	}
	// Fixed JSON types for every field a later check reads. Python would accept
	// true, 1.0 or "200" in several of these and treat them alike; refusing them
	// here keeps the checks below free of that guesswork.
	for _, f := range []struct {
		key  string
		kind fieldKind
	}{
		{"sandbox_id", kindStringOrNull}, {"cathedral_sandbox_id", kindStringOrNull},
		{"network_policy_sha256", kindStringOrNull}, {"tunables_sha256", kindStringOrNull},
		{"network_policy", kindObjectOrNull}, {"tunables", kindObjectOrNull},
		{"status", kindIntOrNull}, {"issued_at", kindInt},
	} {
		v, present := st[f.key]
		if !present {
			continue
		}
		if !f.kind.ok(v) {
			return fail(CodeReceiptMalformed, "statement %s must be %s", f.key, f.kind.describe())
		}
	}
	return nil
}

type fieldKind int

const (
	kindStringOrNull fieldKind = iota
	kindObjectOrNull
	kindIntOrNull
	kindInt
)

func (k fieldKind) describe() string {
	return [...]string{"a string or null", "an object or null", "an integer or null", "an integer"}[k]
}

func isInt64(v any) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	_, err := strconv.ParseInt(string(n), 10, 64)
	return err == nil
}

func (k fieldKind) ok(v any) bool {
	switch k {
	case kindStringOrNull:
		_, isStr := v.(string)
		return v == nil || isStr
	case kindObjectOrNull:
		_, isObj := v.(map[string]any)
		return v == nil || isObj
	case kindIntOrNull:
		return v == nil || isInt64(v)
	}
	return isInt64(v)
}

// isBase64URL accepts only the URL-safe alphabet with optional trailing "=".
func isBase64URL(s string) bool {
	body := strings.TrimRight(s, "=")
	pad := len(s) - len(body)
	if pad > 2 || (pad > 0 && len(s)%4 != 0) {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// DecodeReceiptHeader reads an X-Room-Receipt header: base64url of canonical JSON.
// Python's decoder also drops stray bytes and takes "+" and "/"; this one refuses them.
func DecodeReceiptHeader(b64 string) (Receipt, error) {
	if !isBase64URL(b64) {
		return Receipt{}, fail(CodeReceiptMalformed, "receipt header is not base64url")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(b64, "="))
	if err != nil {
		return Receipt{}, fail(CodeReceiptMalformed, "receipt header is not base64url: %v", err)
	}
	v, err := ParseKeepingNumbers(raw)
	if err != nil {
		return Receipt{}, fail(CodeReceiptMalformed, "receipt header: %v", err)
	}
	return receiptFromValue(v)
}

// ParseReceipts reads the receipts file: a list, or an object whose "receipts" is a list.
// head is the document's "head" when the document is not marked filtered (a
// filtered chain has gaps by design); it is empty otherwise. A "head" or
// "filtered" of the wrong type is an error, never a skipped check.
func ParseReceipts(data []byte) (receipts []Receipt, head string, err error) {
	v, err := ParseKeepingNumbers(data)
	if err != nil {
		return nil, "", fail(CodeBadInput, "receipts: %v", err)
	}
	var list []any
	switch d := v.(type) {
	case map[string]any:
		l, ok := d["receipts"].([]any)
		if !ok {
			return nil, "", fail(CodeReceiptMalformed, "receipts document has no receipts list")
		}
		list = l
		filtered := false
		if raw, present := d["filtered"]; present {
			if filtered, ok = raw.(bool); !ok {
				return nil, "", fail(CodeReceiptMalformed, "receipts document filtered is not a boolean")
			}
		}
		if raw, present := d["head"]; present {
			h, ok := raw.(string)
			if !ok || h == "" {
				return nil, "", fail(CodeReceiptMalformed, "receipts document head is not a non-empty string")
			}
			if !filtered {
				head = h
			}
		}
	case []any:
		list = d
	default:
		return nil, "", fail(CodeReceiptMalformed, "receipts document is neither an object nor a list")
	}
	for _, e := range list {
		rc, err := receiptFromValue(e)
		if err != nil {
			return nil, "", err
		}
		receipts = append(receipts, rc)
	}
	return receipts, head, nil
}

func sequenceOf(st map[string]any) (int64, bool) {
	n, ok := st["sequence"].(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

const maxSequenceSpan = 10_000_000

// VerifyReceipts mirrors verify_receipts() in verify_receipts.py. head is the
// hotel's head as the server named it: not signed, so it proves no completeness.
// Pass "" for "check each receipt only".
func VerifyReceipts(att Attestation, receipts []Receipt, head string) (ReceiptsResult, error) {
	var res ReceiptsResult
	if att.BindingSHA256 == "" {
		return res, fail(CodeBadInput, "attestation has no binding_sha256")
	}
	keyB64, _ := att.Binding["receipt_key_ed25519_b64"].(string)
	keyRaw, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(keyRaw) != ed25519.PublicKeySize {
		return res, fail(CodeBadInput, "binding receipt_key_ed25519_b64 is not a base64 32-byte key")
	}
	key := ed25519.PublicKey(keyRaw)
	bsha := att.BindingSHA256

	bySeq := map[int64]Receipt{}
	var order []int64 // first-insertion order, as a Python dict iterates
	for _, rc := range receipts {
		if err := validateReceipt(rc); err != nil {
			return res, err
		}
		st := rc.Statement
		seq, _ := sequenceOf(st)
		if b, _ := st["binding_sha256"].(string); b != bsha {
			return res, fail(CodeReceiptBindingMismatch, "receipt %d names another binding", seq)
		}
		canon, err := Canonical(st)
		if err != nil {
			return res, fail(CodeReceiptMalformed, "receipt %d: %v", seq, err)
		}
		if rc.ReceiptSHA256 != sha256Hex(canon) {
			return res, fail(CodeReceiptHashMismatch, "receipt %d: receipt_sha256 mismatch", seq)
		}
		sig, err := base64.StdEncoding.DecodeString(rc.SignatureB64)
		if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, canon, sig) {
			return res, fail(CodeReceiptSignature, "receipt %d: signature does not verify", seq)
		}
		if _, seen := bySeq[seq]; !seen {
			order = append(order, seq)
		}
		bySeq[seq] = rc
	}
	links := 0
	for _, seq := range order {
		rc := bySeq[seq]
		prev, _ := rc.Statement["previous_receipt_sha256"].(string)
		if seq == 1 {
			if prev != bsha {
				return res, fail(CodeChainLink, "receipt 1 does not link to the binding")
			}
			links++
		} else if before, ok := bySeq[seq-1]; ok {
			if prev != before.ReceiptSHA256 {
				return res, fail(CodeChainLink, "receipt %d does not link to receipt %d", seq, seq-1)
			}
			links++
		}
	}
	seqs := append([]int64(nil), order...)
	for i := 1; i < len(seqs); i++ { // insertion sort: lists are short or already ordered
		for j := i; j > 0 && seqs[j] < seqs[j-1]; j-- {
			seqs[j], seqs[j-1] = seqs[j-1], seqs[j]
		}
	}
	// Python builds list(range(first, last+1)) here and runs out of memory on a huge span.
	if len(seqs) > 0 && seqs[len(seqs)-1]-seqs[0] > maxSequenceSpan {
		return res, fail(CodeChainGap, "receipt sequences span more than %d", maxSequenceSpan)
	}
	contiguous := len(seqs) > 0
	for i := 1; i < len(seqs); i++ {
		if seqs[i] != seqs[i-1]+1 {
			contiguous = false
		}
	}
	if head != "" && len(seqs) == 0 { // a fresh hotel: the head is the binding itself
		if head != bsha {
			return res, fail(CodeChainHead, "the chain is empty but the head is not the binding")
		}
	} else if head != "" {
		if seqs[0] != 1 || !contiguous {
			return res, fail(CodeChainGap, "the chain has a gap or does not start at receipt 1")
		}
		if bySeq[seqs[len(seqs)-1]].ReceiptSHA256 != head {
			return res, fail(CodeChainHead, "the chain does not end at the hotel's head")
		}
	}
	res.Receipts = len(receipts)
	res.SignaturesOK = len(receipts)
	res.LinksChecked = links
	res.Contiguous = contiguous
	res.Actions = map[string]int{}
	if len(seqs) > 0 {
		f, l := seqs[0], seqs[len(seqs)-1]
		res.First, res.Last = &f, &l
	}
	for _, rc := range receipts {
		a, _ := rc.Statement["action"].(string)
		res.Actions[a]++
	}
	return res, nil
}
