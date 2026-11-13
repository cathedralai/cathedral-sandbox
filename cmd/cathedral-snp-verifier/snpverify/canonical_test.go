package snpverify

import (
	"encoding/json"
	"strings"
	"testing"
)

// Expected bytes come from python3:
// json.dumps(json.loads(in), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
func TestCanonical(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"nested unsorted", `{"b":1,"a":{"z":null,"y":[true,false]}}`, `{"a":{"y":[true,false],"z":null},"b":1}`},
		{"unicode", `{"k":"é 日本 😀"}`, `{"k":"é 日本 😀"}`},
		{"control chars", `{"c":"a\u0000b\u001f\n\r\t\b\f\"\\/"}`, `{"c":"a\u0000b\u001f\n\r\t\b\f\"\\/"}`},
		{"html and separators not escaped", `{"s":"<>&  \u007f"}`, "{\"s\":\"<>&  \x7f\"}"},
		{"numbers as Python prints them", `[1,1.0,1e-05,0,12345678901234567890123,2.5]`, `[1,1.0,1e-05,0,12345678901234567890123,2.5]`},
		{"floats rewritten", `[1E5,1.50,1e5]`, `[100000.0,1.5,100000.0]`},
		{"negative zero int", `[-0]`, `[0]`},
		{"empty object", `{}`, `{}`},
		{"empty array", `[]`, `[]`},
		{"empty members", `{"a":{},"b":[]}`, `{"a":{},"b":[]}`},
		{"code point key order", `{"é":1,"z":2,"a":3,"日":4,"😀":5,"￿":6}`, "{\"a\":3,\"z\":2,\"é\":1,\"日\":4,\"￿\":6,\"😀\":5}"},
		{"arrays of objects", `{"nested":[{"b":2,"a":1},[{"d":4,"c":3}]]}`, `{"nested":[{"a":1,"b":2},[{"c":3,"d":4}]]}`},
		{"string", `"plain"`, `"plain"`},
		{"null", `null`, `null`},
		{"true", `true`, `true`},
		{"surrogate pair emoji", `{"e":"\ud83d\ude00"}`, "{\"e\":\"\U0001F600\"}"},
		{"escaped backslash before u", `{"e":"\\ud800"}`, `{"e":"\\ud800"}`},
		{"whitespace ignored", " { \"b\" : 1 ,\n \"a\" : 2 } ", `{"a":2,"b":1}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := ParseKeepingNumbers([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Canonical(v)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct{ name, in string }{
		{"duplicate key", `{"a":1,"a":2}`},
		{"nested duplicate key", `{"x":{"a":1,"a":2}}`},
		{"invalid utf8", "{\"a\":\"\xff\"}"},
		{"trailing data", `{"a":1} {"b":2}`},
		{"lone high surrogate", `{"a":"\ud800"}`},
		{"lone high surrogate then text", `{"a":"\ud800x"}`},
		{"lone low surrogate", `{"a":"\udc00"}`},
		{"reversed pair", `{"a":"\ude00\ud83d"}`},
		{"high then non-low escape", `{"a":"\ud800\u0041"}`},
		{"surrogate in key", `{"\ud800":1}`},
		{"empty", ``},
		{"truncated", `{"a":`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseKeepingNumbers([]byte(tc.in)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestSurrogatePairKeepsRawUTF8(t *testing.T) {
	v, err := ParseKeepingNumbers([]byte(`["\ud83d\ude00"]`))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Canonical(v)
	if want := []byte{'[', '"', 0xF0, 0x9F, 0x98, 0x80, '"', ']'}; string(got) != string(want) {
		t.Fatalf("got % x", got)
	}
}

// Expected strings come from python3: json.dumps(json.loads(literal)).
func TestPythonNumbers(t *testing.T) {
	tests := [][2]string{
		{`0.0`, `0.0`},
		{`-0.0`, `-0.0`},
		{`1.0`, `1.0`},
		{`1.50`, `1.5`},
		{`1E5`, `100000.0`},
		{`1e5`, `100000.0`},
		{`1e-4`, `0.0001`},
		{`1e-5`, `1e-05`},
		{`1e15`, `1000000000000000.0`},
		{`1e16`, `1e+16`},
		{`1e17`, `1e+17`},
		{`123456789012345680.0`, `1.2345678901234568e+17`},
		{`0.1`, `0.1`},
		{`0.30000000000000004`, `0.30000000000000004`},
		{`5e-324`, `5e-324`},
		{`1.7976931348623157e308`, `1.7976931348623157e+308`},
		{`2.5e-7`, `2.5e-07`},
		{`1e22`, `1e+22`},
		{`1e23`, `1e+23`},
		{`9007199254740993`, `9007199254740993`},
		{`-1`, `-1`},
		{`12345678901234567890`, `12345678901234567890`},
		{`-0`, `0`},
		{`0`, `0`},
		{`1.5e-07`, `1.5e-07`},
		{`1.2345e20`, `1.2345e+20`},
		{`100`, `100`},
		{`-1.0e2`, `-100.0`},
		{`0.000123456789012345678`, `0.00012345678901234567`},
		{`3.141592653589793238462643`, `3.141592653589793`},
		{`123456789.123456789`, `123456789.12345679`},
		{`1e0`, `1.0`},
		{`1E+2`, `100.0`},
		{`2e-3`, `0.002`},
		{`0.00001`, `1e-05`},
		{`99999999999999999999.5`, `1e+20`},
		{`-5e-324`, `-5e-324`},
		{`4.35`, `4.35`},
		{`1e-400`, `0.0`},
		{`10000000000000000.0`, `1e+16`},
		{`999999999999999.9`, `999999999999999.9`},
	}
	for _, tc := range tests {
		got, err := pythonNumber(json.Number(tc[0]))
		if err != nil || got != tc[1] {
			t.Errorf("%s: got %q (%v), want %q", tc[0], got, err, tc[1])
		}
		// The same through the document path.
		v, err := ParseKeepingNumbers([]byte("[" + tc[0] + "]"))
		if err != nil {
			t.Fatal(err)
		}
		if out, _ := Canonical(v); string(out) != "["+tc[1]+"]" {
			t.Errorf("%s: canonical %s", tc[0], out)
		}
	}
}

func TestNumberLimits(t *testing.T) {
	if _, err := ParseKeepingNumbers([]byte("[" + strings.Repeat("7", 4300) + "]")); err != nil {
		t.Fatalf("4300 digits: %v", err)
	}
	if _, err := ParseKeepingNumbers([]byte("[-" + strings.Repeat("7", 4300) + "]")); err != nil {
		t.Fatalf("sign is not a digit: %v", err)
	}
	for name, in := range map[string]string{
		"4301 digits":  "[" + strings.Repeat("7", 4301) + "]",
		"overflow":     "[1e999]",
		"neg overflow": "[-1e999]",
		"NaN":          "[NaN]",
		"Infinity":     "[Infinity]",
		"too deep":     strings.Repeat("[", 150) + strings.Repeat("]", 150),
	} {
		if _, err := ParseKeepingNumbers([]byte(in)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := ParseKeepingNumbers([]byte(strings.Repeat("[", 50) + strings.Repeat("]", 50))); err != nil {
		t.Fatalf("depth 50: %v", err)
	}
}
