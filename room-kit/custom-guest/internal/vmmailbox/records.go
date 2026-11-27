// Package vmmailbox is the guest side of the sealed VM mailbox (VM runtime spec r3 7.5): the
// 1 MiB raw disk the host and the guest share. The layout, record and body shapes must agree
// byte for byte with room-kit/vm/vm_mailbox.py and tests/fixtures/vm_mailbox_v1.json.
//
// Everything in the mailbox is untrusted input, including what this guest wrote earlier: the
// host can rewrite any byte. A reader checks the header, then a bounded depth-1 pre-scan, then a
// strict parse. Any failure of any kind reads as an empty slot, never as an error that stops boot.
//
// The package is pure Go with no build tag so its parsing is testable on any machine.
package vmmailbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"regexp"
	"sort"
)

const (
	MailboxBytes = 1 << 20
	SlotBytes    = 64 << 10
	StatusOffset = 0
	OfferOffset  = 64 << 10
	AnswerOffset = 128 << 10
	HeaderBytes  = 45
	AnswerMax    = 4096
	ReportBytes  = 1184 // an SEV-SNP attestation report
)

var magic = [8]byte{'C', 'V', 'M', 'M', 'B', 'X', '1', 0}

type Kind uint8

const (
	KindStatus Kind = 1
	KindOffer  Kind = 2
	KindAnswer Kind = 3
)

const (
	StatusSchema = "cathedral.vm.status/v1"
	OfferSchema  = "cathedral.vm.rewrap-offer/v1"
	AnswerSchema = "cathedral.vm.rewrap-answer/v1"
)

var (
	// ErrTorn is a header or sha256 that does not check: the other side may be mid-write.
	ErrTorn    = errors.New("vmmailbox: torn or invalid record")
	ErrInvalid = errors.New("vmmailbox: invalid body")
)

func bodyMax(kind Kind) int {
	switch kind {
	case KindStatus, KindOffer:
		return SlotBytes - HeaderBytes
	case KindAnswer:
		return AnswerMax
	}
	return 0
}

// field is one schema member: a fixed string, a regexp, or the padded base64 of n bytes.
type field struct {
	fixed string
	re    *regexp.Regexp
	b64   int
}

var (
	hex64Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	stateRe = regexp.MustCompile(`^[a-z]{1,16}$`)
	keyIDRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	vmIDRe  = regexp.MustCompile(`^vm-[0-9a-f]{12}$`)
)

var schemas = map[Kind]map[string]field{
	KindStatus: {"schema": {fixed: StatusSchema}, "state": {re: stateRe}, "key_id": {re: keyIDRe}, "report": {b64: ReportBytes}},
	KindOffer: {"schema": {fixed: OfferSchema}, "vm_id": {re: vmIDRe}, "pubkey": {b64: 32}, "nonce": {b64: 32},
		"report": {b64: ReportBytes}},
	KindAnswer: {"schema": {fixed: AnswerSchema}, "offer_sha256": {re: hex64Re}, "epk": {b64: 32}, "nonce": {b64: 12},
		"ct": {b64: 48}},
}

// EncodeSlot returns the whole 64 KiB slot holding one record: what a writer writes in one call.
func EncodeSlot(kind Kind, body []byte) ([]byte, error) {
	if len(body) == 0 || len(body) > bodyMax(kind) {
		return nil, ErrInvalid
	}
	slot := make([]byte, SlotBytes)
	copy(slot, magic[:])
	slot[8] = byte(kind)
	binary.BigEndian.PutUint32(slot[9:13], uint32(len(body)))
	sum := sha256.Sum256(body)
	copy(slot[13:HeaderBytes], sum[:])
	copy(slot[HeaderBytes:], body)
	return slot, nil
}

// DecodeSlot returns the body of the slot's record. A nil body and nil error is an empty slot (the
// header is all zero). Anything else that does not check is ErrTorn.
func DecodeSlot(slot []byte, kind Kind) ([]byte, error) {
	if len(slot) != SlotBytes {
		return nil, ErrTorn
	}
	if bytes.Equal(slot[:HeaderBytes], make([]byte, HeaderBytes)) {
		return nil, nil
	}
	if !bytes.Equal(slot[:8], magic[:]) || Kind(slot[8]) != kind {
		return nil, ErrTorn
	}
	length := int(binary.BigEndian.Uint32(slot[9:13]))
	if length <= 0 || length > bodyMax(kind) {
		return nil, ErrTorn
	}
	body := slot[HeaderBytes : HeaderBytes+length]
	sum := sha256.Sum256(body)
	if !bytes.Equal(sum[:], slot[13:HeaderBytes]) {
		return nil, ErrTorn
	}
	return body, nil
}

// Prescan walks a body once, never past limit, before any parser sees it. It requires one flat
// object: strings are printable ASCII with escapes tracked, and outside a string there is no '['
// or '{' after the opening brace and nothing after the closing one. So a 60 KB nested body is
// refused in one linear pass and the parser never recurses.
func Prescan(body []byte, limit int) error {
	if len(body) == 0 || len(body) > limit || body[0] != '{' {
		return ErrInvalid
	}
	inString, escaped := false, false
	end := len(body) - 1
	for i := 1; i < len(body); i++ {
		c := body[i]
		if inString {
			if c < 0x20 || c > 0x7e {
				return ErrInvalid
			}
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '[', '{':
			return ErrInvalid
		case '}':
			if i != end {
				return ErrInvalid
			}
		}
	}
	if inString || body[end] != '}' {
		return ErrInvalid
	}
	return nil
}

// ParseBody parses a canonical body of kind after the pre-scan. The keys must be exactly the
// schema's, each a string of the right shape. Canonical means sorted keys, no spaces, no escapes:
// every value the schemas allow is free of quotes and backslashes, so the parser rejects escapes.
func ParseBody(body []byte, kind Kind) (map[string]string, error) {
	schema, ok := schemas[kind]
	if !ok {
		return nil, ErrInvalid
	}
	if err := Prescan(body, bodyMax(kind)); err != nil {
		return nil, err
	}
	doc := map[string]string{}
	pos := 1
	last := ""
	for {
		key, next, ok := readString(body, pos)
		if !ok || next >= len(body) || body[next] != ':' {
			return nil, ErrInvalid
		}
		value, next, ok := readString(body, next+1)
		if !ok {
			return nil, ErrInvalid
		}
		if _, dup := doc[key]; dup || key <= last {
			return nil, ErrInvalid // a repeated key, or keys out of canonical order
		}
		doc[key], last = value, key
		if next >= len(body) {
			return nil, ErrInvalid
		}
		if body[next] == '}' && next == len(body)-1 {
			break
		}
		if body[next] != ',' {
			return nil, ErrInvalid
		}
		pos = next + 1
	}
	if len(doc) != len(schema) {
		return nil, ErrInvalid
	}
	for key, rule := range schema {
		value, present := doc[key]
		if !present {
			return nil, ErrInvalid
		}
		switch {
		case rule.fixed != "":
			if value != rule.fixed {
				return nil, ErrInvalid
			}
		case rule.re != nil:
			if !rule.re.MatchString(value) {
				return nil, ErrInvalid
			}
		default:
			raw, err := base64.StdEncoding.Strict().DecodeString(value)
			if err != nil || len(raw) != rule.b64 || base64.StdEncoding.EncodeToString(raw) != value {
				return nil, ErrInvalid
			}
		}
	}
	return doc, nil
}

// readString reads one JSON string with no escapes at pos. A backslash is a refusal.
func readString(body []byte, pos int) (string, int, bool) {
	if pos >= len(body) || body[pos] != '"' {
		return "", 0, false
	}
	for i := pos + 1; i < len(body); i++ {
		switch body[i] {
		case '\\':
			return "", 0, false
		case '"':
			return string(body[pos+1 : i]), i + 1, true
		}
	}
	return "", 0, false
}

// canonical writes doc as canonical JSON (sorted keys, no spaces). Values must already be free
// of quotes and backslashes; ParseBody on the result enforces it.
func canonical(doc map[string]string) []byte {
	keys := make([]string, 0, len(doc))
	for key := range doc {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out bytes.Buffer
	out.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			out.WriteByte(',')
		}
		out.WriteString(`"` + key + `":"` + doc[key] + `"`)
	}
	out.WriteByte('}')
	return out.Bytes()
}

// BodySHA256 is an offer's name: the sha256 of its body as 64 lowercase hex.
func BodySHA256(body []byte) string {
	sum := sha256.Sum256(body)
	const digits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range sum {
		out[2*i], out[2*i+1] = digits[b>>4], digits[b&15]
	}
	return string(out)
}

func b64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
