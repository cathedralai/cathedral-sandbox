package vmidentity

import (
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Canonical JSON (spec D 8.1, vm_measure.canonical): sorted keys, no
// whitespace, printable ASCII strings with only '"' and '\' escaped, decimal
// integers, objects. ParseCanonical accepts exactly that grammar, so a value
// it returns re-encodes to the same bytes. Every record the VM init reads from
// a host-reachable disk or firmware input goes through it.

var errCanonical = errors.New("not canonical JSON")

// Object is a parsed canonical object. Values are string, int64 or Object.
type Object map[string]any

// ParseCanonical parses one canonical object, nesting at most depth levels
// (1 is a flat object). Input bytes outside the grammar are refused.
func ParseCanonical(raw []byte, depth int) (Object, error) {
	p := parser{raw: raw}
	v, err := p.object(depth)
	if err != nil {
		return nil, err
	}
	if p.pos != len(raw) {
		return nil, errCanonical
	}
	// The grammar already forces canonical bytes; the round trip keeps that
	// true if the grammar and the encoder ever drift apart.
	again, err := Canonical(v)
	if err != nil || string(again) != string(raw) {
		return nil, errCanonical
	}
	return v, nil
}

type parser struct {
	raw []byte
	pos int
}

func (p *parser) next() (byte, bool) {
	if p.pos >= len(p.raw) {
		return 0, false
	}
	return p.raw[p.pos], true
}

func (p *parser) expect(c byte) error {
	b, ok := p.next()
	if !ok || b != c {
		return errCanonical
	}
	p.pos++
	return nil
}

func (p *parser) object(depth int) (Object, error) {
	if depth < 1 {
		return nil, errCanonical
	}
	if err := p.expect('{'); err != nil {
		return nil, err
	}
	out := Object{}
	if b, ok := p.next(); ok && b == '}' {
		p.pos++
		return out, nil
	}
	previous := ""
	for first := true; ; first = false {
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		// Strictly increasing keys: sorted, and no duplicate can alias a field.
		if !first && key <= previous {
			return nil, errCanonical
		}
		previous = key
		if err := p.expect(':'); err != nil {
			return nil, err
		}
		b, ok := p.next()
		if !ok {
			return nil, errCanonical
		}
		switch {
		case b == '"':
			out[key], err = p.str()
		case b == '{':
			out[key], err = p.object(depth - 1)
		case b == '-' || (b >= '0' && b <= '9'):
			out[key], err = p.integer()
		default:
			err = errCanonical
		}
		if err != nil {
			return nil, err
		}
		b, ok = p.next()
		if !ok {
			return nil, errCanonical
		}
		p.pos++
		if b == '}' {
			return out, nil
		}
		if b != ',' {
			return nil, errCanonical
		}
	}
}

func (p *parser) str() (string, error) {
	if err := p.expect('"'); err != nil {
		return "", err
	}
	var b strings.Builder
	for {
		c, ok := p.next()
		if !ok || c < 0x20 || c > 0x7e {
			return "", errCanonical
		}
		p.pos++
		switch c {
		case '"':
			return b.String(), nil
		case '\\':
			e, ok := p.next()
			if !ok || (e != '"' && e != '\\') {
				return "", errCanonical
			}
			p.pos++
			b.WriteByte(e)
		default:
			b.WriteByte(c)
		}
	}
}

func (p *parser) integer() (int64, error) {
	start := p.pos
	if b, _ := p.next(); b == '-' {
		p.pos++
	}
	digits := p.pos
	for {
		b, ok := p.next()
		if !ok || b < '0' || b > '9' {
			break
		}
		p.pos++
	}
	text := string(p.raw[start:p.pos])
	if p.pos == digits || (p.raw[digits] == '0' && p.pos-digits > 1) || text == "-0" {
		return 0, errCanonical
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, errCanonical
	}
	return n, nil
}

// Canonical encodes an Object (values string, int64, int or Object).
func Canonical(v Object) ([]byte, error) {
	var b strings.Builder
	if err := encode(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func encode(b *strings.Builder, v Object) error {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := encodeString(b, k); err != nil {
			return err
		}
		b.WriteByte(':')
		switch value := v[k].(type) {
		case string:
			if err := encodeString(b, value); err != nil {
				return err
			}
		case int64:
			b.WriteString(strconv.FormatInt(value, 10))
		case int:
			b.WriteString(strconv.Itoa(value))
		case Object:
			if err := encode(b, value); err != nil {
				return err
			}
		default:
			return errors.New("only integers, strings and objects are allowed")
		}
	}
	b.WriteByte('}')
	return nil
}

func encodeString(b *strings.Builder, s string) error {
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			return errors.New("strings must be printable ASCII")
		}
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	b.WriteByte('"')
	return nil
}

// Fields checks that o has exactly the given keys.
func Fields(o Object, keys ...string) bool {
	if len(o) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := o[k]; !ok {
			return false
		}
	}
	return true
}

// String returns o[k] when it is a string.
func String(o Object, k string) (string, bool) {
	s, ok := o[k].(string)
	return s, ok
}

// Int returns o[k] when it is an integer.
func Int(o Object, k string) (int64, bool) {
	n, ok := o[k].(int64)
	return n, ok
}
