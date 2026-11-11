package snpverify

import "testing"

// Expected bytes come from python3:
// json.dumps(json.loads(in), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
func TestCanonical(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"nested unsorted", `{"b":1,"a":{"z":null,"y":[true,false]}}`, `{"a":{"y":[true,false],"z":null},"b":1}`},
		{"unicode", `{"k":"é 日本 😀"}`, `{"k":"é 日本 😀"}`},
		{"control chars", `{"c":"a\u0000b\u001f\n\r\t\b\f\"\\/"}`, `{"c":"a\u0000b\u001f\n\r\t\b\f\"\\/"}`},
		{"html and separators not escaped", `{"s":"<>&  \u007f"}`, "{\"s\":\"<>&  \x7f\"}"},
		{"numbers kept as literals", `[1,1.0,1e-05,0,12345678901234567890123,2.5]`, `[1,1.0,1e-05,0,12345678901234567890123,2.5]`},
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
