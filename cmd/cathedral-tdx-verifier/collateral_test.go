package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/go-tdx-guest/abi"
	tdxtesting "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/verify"
)

type deniedTransport struct{ t *testing.T }

func (d deniedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	d.t.Error("offline verification attempted an HTTP request")
	return nil, errors.New("network denied")
}

func fixtureBundle(t *testing.T, quote []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(quote)
	bundle := collateralBundle{collateralSchema, hex.EncodeToString(digest[:]), map[string]collateralResponse{}}
	for rawURL, response := range tdxtesting.TestGetter.Responses {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			t.Fatal(err)
		}
		if err := prepareIntelCollateralURL(parsed); err != nil {
			t.Fatal(err)
		}
		bundle.Responses[parsed.String()] = collateralResponse{response.Header, response.Body}
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestOfflineReplayPreservesVendorAndTCBChecks(t *testing.T) {
	old := http.DefaultTransport
	http.DefaultTransport = deniedTransport{t}
	defer func() { http.DefaultTransport = old }()
	raw := canonicalQuoteV4Fixture(t)
	encoded := fixtureBundle(t, raw)
	options, err := offlineVerifyOptions(encoded, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !options.CheckRevocations || !options.GetCollateral || options.DisableTcbStatusCheck || options.TrustedRoots != nil || options.Now != nil {
		t.Fatal("offline options weakened verification")
	}
	// The upstream 2023 fixture is stale today. Even at its historical time,
	// strict TCB policy must not be disabled to manufacture a passing replay.
	options.Now = fixtureTimeSet()
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := launchQuoteV4(parsed)
	if err != nil {
		t.Fatal(err)
	}
	vendorError := verify.TdxQuoteContext(context.Background(), parsed, options)
	t.Logf("exact upstream strict verification result: %v", vendorError)
	options, err = offlineVerifyOptions(encoded, raw)
	if err != nil {
		t.Fatal(err)
	}
	options.Now = fixtureTimeSet()
	result, err := verifyAndBuildClaims(context.Background(), raw, body.GetReportData(), options)
	t.Logf("unmodified upstream fixture under strict offline policy: result=%v error=%v", result, err)
	if err == nil || result != nil {
		t.Fatal("historical fixture unexpectedly satisfied strict offline policy")
	}
	raw[100] ^= 1
	options, err = offlineVerifyOptions(fixtureBundle(t, raw), raw)
	if err != nil {
		t.Fatal(err)
	}
	options.Now = fixtureTimeSet()
	if result, err := verifyAndBuildClaims(context.Background(), raw, body.GetReportData(), options); err == nil || result != nil {
		t.Fatal("tampered quote passed offline verification")
	}
}

func TestOfflineBundleRejectsWrongQuoteAndMissingResponse(t *testing.T) {
	raw := canonicalQuoteV4Fixture(t)
	encoded := fixtureBundle(t, raw)
	wrong := bytes.Clone(raw)
	wrong[100] ^= 1
	if _, err := offlineVerifyOptions(encoded, wrong); err == nil {
		t.Fatal("wrong quote accepted")
	}
	options, err := offlineVerifyOptions(encoded, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := options.Getter.Get("https://api.trustedservices.intel.com/missing"); err == nil {
		t.Fatal("missing collateral accepted")
	}
	if _, _, err := options.Getter.Get("https://attacker.invalid/tcb"); err == nil {
		t.Fatal("untrusted host accepted")
	}
}

func TestOfflineBundleRejectsMalformedInputs(t *testing.T) {
	raw := canonicalQuoteV4Fixture(t)
	for _, encoded := range [][]byte{nil, []byte("{}"), []byte("null"), bytes.Repeat([]byte("x"), maxBundleBytes+1), append(fixtureBundle(t, raw), []byte("{}")...)} {
		if _, err := offlineVerifyOptions(encoded, raw); err == nil {
			t.Fatal("malformed bundle accepted")
		}
	}
}
