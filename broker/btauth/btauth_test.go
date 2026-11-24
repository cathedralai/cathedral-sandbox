package btauth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

// Vectors signed on the Python side (polariscomputer primitives/btauth.py
// sign_headers with //Alice and //Bob), so these tests pin byte-for-byte
// agreement with the API's verifier.
type vectorFile struct {
	Scheme        string `json:"scheme"`
	ServiceHotkey string `json:"service_hotkey"`
	Cases         []struct {
		Name          string            `json:"name"`
		Valid         bool              `json:"valid"`
		Method        string            `json:"method"`
		Path          string            `json:"path"`
		BodyHex       string            `json:"body_hex"`
		Headers       map[string]string `json:"headers"`
		SignedMessage string            `json:"signed_message"`
	} `json:"cases"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/btauth_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Scheme != Protocol || len(f.Cases) == 0 {
		t.Fatalf("unexpected vector file: scheme %q, %d cases", f.Scheme, len(f.Cases))
	}
	return f
}

func toHeader(m map[string]string) http.Header {
	h := http.Header{}
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

func verifierAt(service string, nonceNS int64) *Verifier {
	return &Verifier{
		Receivers: map[string]bool{service: true},
		Nonces:    NewMemoryNonceStore(),
		Now:       func() time.Time { return time.Unix(0, nonceNS) },
	}
}

func TestVectorsMatchPython(t *testing.T) {
	f := loadVectors(t)
	valid, invalid := 0, 0
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			body, err := hex.DecodeString(c.BodyHex)
			if err != nil {
				t.Fatal(err)
			}
			nonce, _ := strconv.ParseInt(c.Headers[HeaderNonce], 10, 64)
			if c.SignedMessage != "" {
				got := string(BuildPayload(SR25519, c.Method, c.Path, body, nonce,
					c.Headers[HeaderHotkey], c.Headers[HeaderReceiver]))
				// Only cases whose signed message is the request's own payload
				// must match; tampered cases sign something else on purpose.
				if c.Valid && got != c.SignedMessage {
					t.Fatalf("payload differs from Python:\n got %q\nwant %q", got, c.SignedMessage)
				}
			}
			_, err = verifierAt(f.ServiceHotkey, nonce).Verify(toHeader(c.Headers), body, c.Method, c.Path)
			if c.Valid && err != nil {
				t.Fatalf("valid vector refused: %v", err)
			}
			if !c.Valid {
				if err == nil {
					t.Fatal("invalid vector accepted")
				}
				if !errors.Is(err, ErrBadSignature) {
					t.Fatalf("invalid vector refused for the wrong reason: %v", err)
				}
			}
		})
		if c.Valid {
			valid++
		} else {
			invalid++
		}
	}
	// Positive and negative controls must both be present.
	if valid == 0 || invalid == 0 {
		t.Fatalf("need both kinds of vectors, got %d valid and %d invalid", valid, invalid)
	}
}

func firstValid(t *testing.T) (vectorFile, http.Header, []byte, string, string, int64) {
	f := loadVectors(t)
	for _, c := range f.Cases {
		if c.Valid {
			body, _ := hex.DecodeString(c.BodyHex)
			nonce, _ := strconv.ParseInt(c.Headers[HeaderNonce], 10, 64)
			return f, toHeader(c.Headers), body, c.Method, c.Path, nonce
		}
	}
	t.Fatal("no valid vector")
	return f, nil, nil, "", "", 0
}

func TestReplayRefused(t *testing.T) {
	f, h, body, method, path, nonce := firstValid(t)
	v := verifierAt(f.ServiceHotkey, nonce)
	if _, err := v.Verify(h, body, method, path); err != nil {
		t.Fatalf("first use refused: %v", err)
	}
	if _, err := v.Verify(h, body, method, path); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay: got %v, want ErrReplayed", err)
	}
}

func TestFreshnessWindow(t *testing.T) {
	f, h, body, method, path, nonce := firstValid(t)
	tooOld := verifierAt(f.ServiceHotkey, nonce+int64(MaxAge)+1)
	if _, err := tooOld.Verify(h, body, method, path); !errors.Is(err, ErrStale) {
		t.Fatalf("old nonce: got %v, want ErrStale", err)
	}
	tooNew := verifierAt(f.ServiceHotkey, nonce-int64(AllowedSkew)-1)
	if _, err := tooNew.Verify(h, body, method, path); !errors.Is(err, ErrStale) {
		t.Fatalf("future nonce: got %v, want ErrStale", err)
	}
	edge := verifierAt(f.ServiceHotkey, nonce+int64(MaxAge))
	if _, err := edge.Verify(h, body, method, path); err != nil {
		t.Fatalf("nonce exactly 10 s old must pass, as in Python: %v", err)
	}
}

func TestWrongReceiverBeforeSignature(t *testing.T) {
	_, h, body, method, path, nonce := firstValid(t)
	v := verifierAt("5SomeoneElse", nonce)
	if _, err := v.Verify(h, body, method, path); !errors.Is(err, ErrWrongReceiver) {
		t.Fatalf("got %v, want ErrWrongReceiver", err)
	}
}

func TestHeaderShape(t *testing.T) {
	f, base, body, method, path, nonce := firstValid(t)
	cases := []struct {
		name string
		edit func(h http.Header)
		want error
	}{
		{"no version", func(h http.Header) { h.Del(HeaderVersion) }, ErrMalformed},
		{"version 2", func(h http.Header) { h.Set(HeaderVersion, "2") }, ErrMalformed},
		{"no hotkey", func(h http.Header) { h.Del(HeaderHotkey) }, ErrMalformed},
		{"nonce not decimal", func(h http.Header) { h.Set(HeaderNonce, "12a") }, ErrMalformed},
		{"nonce 26 digits", func(h http.Header) { h.Set(HeaderNonce, "12345678901234567890123456") }, ErrMalformed},
		{"hashed scheme", func(h http.Header) { h.Set(HeaderCrypto, "hashed") }, ErrUnsupported},
		{"unknown scheme", func(h http.Header) { h.Set(HeaderCrypto, "ecdsa") }, ErrMalformed},
		{"no signature", func(h http.Header) { h.Del(HeaderSignature) }, ErrMalformed},
		{"signature not hex", func(h http.Header) { h.Set(HeaderSignature, "0xzz") }, ErrMalformed},
		{"short signature", func(h http.Header) { h.Set(HeaderSignature, "0xabcd") }, ErrMalformed},
		{"no receiver", func(h http.Header) { h.Del(HeaderReceiver) }, ErrWrongReceiver},
		{"bad hotkey checksum", func(h http.Header) {
			hk := h.Get(HeaderHotkey)
			last := hk[len(hk)-1]
			repl := byte('A')
			if last == 'A' {
				repl = 'B'
			}
			h.Set(HeaderHotkey, hk[:len(hk)-1]+string(repl))
		}, ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := base.Clone()
			c.edit(h)
			_, err := verifierAt(f.ServiceHotkey, nonce).Verify(h, body, method, path)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

func TestProtectedSenderNoncesNotStored(t *testing.T) {
	f, h, body, method, path, nonce := firstValid(t)
	v := verifierAt(f.ServiceHotkey, nonce)
	v.IsProtected = func(string) (bool, error) { return true, nil }
	if _, err := v.Verify(h, body, method, path); !errors.Is(err, ErrProtectedSender) {
		t.Fatalf("got %v, want ErrProtectedSender", err)
	}
	v.IsProtected = nil
	if _, err := v.Verify(h, body, method, path); err != nil {
		t.Fatalf("nonce of a refused protected request must not be stored: %v", err)
	}
}

func TestSS58KnownKey(t *testing.T) {
	// //Alice: 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
	key, err := SS58PublicKey("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY")
	if err != nil {
		t.Fatal(err)
	}
	const want = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
	if hex.EncodeToString(key[:]) != want {
		t.Fatalf("got %x, want %s", key, want)
	}
}
