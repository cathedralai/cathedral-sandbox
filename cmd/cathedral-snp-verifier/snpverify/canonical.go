package snpverify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ParseKeepingNumbers parses JSON into map[string]any, []any, string, bool, nil
// and json.Number. Numbers stay as the literal text received, so a re-emit
// cannot change them. Duplicate object keys and invalid UTF-8 are errors:
// two parsers that disagree on which duplicate wins would disagree on the hash.
func ParseKeepingNumbers(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("input is not valid UTF-8")
	}
	if err := checkSurrogates(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

// maxDepth is far below Python's recursion limit, so a document this parser
// accepts cannot make json.loads or json.dumps fail there.
const maxDepth = 100

func parseValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, errors.New("JSON nesting is too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		if n, ok := tok.(json.Number); ok {
			if _, err := pythonNumber(n); err != nil {
				return nil, err
			}
		}
		return tok, nil // string, json.Number, bool, nil
	}
	switch d {
	case '{':
		obj := map[string]any{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := kt.(string)
			if !ok {
				return nil, errors.New("object key is not a string")
			}
			if _, dup := obj[key]; dup {
				return nil, fmt.Errorf("duplicate object key %q", key)
			}
			val, err := parseValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			obj[key] = val
		}
		if _, err := dec.Token(); err != nil { // closing brace
			return nil, err
		}
		return obj, nil
	case '[':
		arr := []any{}
		for dec.More() {
			val, err := parseValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return arr, nil
	}
	return nil, fmt.Errorf("unexpected delimiter %q", d)
}

// Canonical matches Python json.dumps(v, sort_keys=True, separators=(",", ":"),
// ensure_ascii=False).encode() for values from ParseKeepingNumbers.
func Canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		out, err := pythonNumber(t)
		if err != nil {
			return err
		}
		buf.WriteString(out)
	case string:
		return writeString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// Byte order of valid UTF-8 equals code point order, which is how Python sorts str.
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported value type %T", v)
	}
	return nil
}

func writeString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("string is not valid UTF-8")
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r < 0x20:
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			buf.WriteString(string(r))
		}
	}
	buf.WriteByte('"')
	return nil
}

// checkSurrogates refuses unpaired UTF-16 surrogate escapes. Go's decoder turns
// them into U+FFFD while Python keeps them and then fails to encode, so the
// two would disagree on the bytes. Malformed escapes are left to the decoder.
func checkSurrogates(data []byte) error {
	hex4 := func(i int) (rune, bool) {
		if i+4 > len(data) {
			return 0, false
		}
		var r rune
		for _, c := range data[i : i+4] {
			switch {
			case c >= '0' && c <= '9':
				r = r<<4 | rune(c-'0')
			case c >= 'a' && c <= 'f':
				r = r<<4 | rune(c-'a'+10)
			case c >= 'A' && c <= 'F':
				r = r<<4 | rune(c-'A'+10)
			default:
				return 0, false
			}
		}
		return r, true
	}
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(data) {
				return nil
			}
			if data[i+1] != 'u' {
				i++ // skip the escaped character, so \" does not end the string
				continue
			}
			r, ok := hex4(i + 2)
			if !ok {
				return nil
			}
			i += 5
			switch {
			case r >= 0xDC00 && r <= 0xDFFF:
				return errors.New("unpaired low surrogate escape in string")
			case r >= 0xD800 && r <= 0xDBFF:
				low, ok := rune(0), false
				if i+2 < len(data) && data[i+1] == '\\' && data[i+2] == 'u' {
					low, ok = hex4(i + 3)
				}
				if !ok || low < 0xDC00 || low > 0xDFFF {
					return errors.New("unpaired high surrogate escape in string")
				}
				i += 6
			}
		}
	}
	return nil
}

// maxIntDigits is Python's default int string conversion limit: json.loads
// fails on an integer literal with more digits.
const maxIntDigits = 4300

// pythonNumber returns what json.dumps(json.loads(literal)) prints. An integer
// literal stays an integer (-0 becomes 0). A literal with ".", "e" or "E" is a
// float, printed with Python's repr. Overflow to infinity is refused here;
// Python would print Infinity, so this is stricter.
func pythonNumber(n json.Number) (string, error) {
	lit := string(n)
	if lit == "" {
		return "", errors.New("empty number")
	}
	if !strings.ContainsAny(lit, ".eE") {
		digits := strings.TrimPrefix(lit, "-")
		if len(digits) > maxIntDigits {
			return "", fmt.Errorf("integer literal has %d digits, more than %d", len(digits), maxIntDigits)
		}
		if lit == "-0" {
			return "0", nil
		}
		return lit, nil
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return "", fmt.Errorf("number %q does not fit a float: %v", lit, err)
	}
	return pythonFloatRepr(f), nil
}

// pythonFloatRepr follows repr(float): shortest round-trip digits; scientific
// form when the decimal exponent is below -4 or at least 16, with at least two
// exponent digits; otherwise fixed form with ".0" when there is no fraction.
func pythonFloatRepr(f float64) string {
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	exp, _ := strconv.Atoi(sci[strings.IndexByte(sci, 'e')+1:])
	if exp < -4 || exp >= 16 {
		return sci
	}
	fixed := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(fixed, ".") {
		fixed += ".0"
	}
	return fixed
}
