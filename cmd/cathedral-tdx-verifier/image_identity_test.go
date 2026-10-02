package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

// The v2 image identity (docs/MRTD.md, "Image identity"; cathedral-sandbox
// #265). The quotes in testdata/gcp-mrowner are real GCP TDX quotes; the
// Python suite (tests/test_tdx_image_identity.py) checks the same files
// against the same vectors, so both verifiers share one contract.

type identityVector struct {
	Quote            string `json:"quote"`
	Measurement      string `json:"measurement"`
	ImageMeasurement string `json:"image_measurement"`
	MrOwner          string `json:"mr_owner"`
}

func loadIdentityVectors(t *testing.T) []identityVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "gcp-mrowner", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Vectors []identityVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Vectors) == 0 {
		t.Fatal("no identity vectors")
	}
	return document.Vectors
}

func fixtureBody(t *testing.T, name string) launchBody {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "gcp-mrowner", name))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	_, body, err := launchQuoteV4(parsed)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return body
}

func TestImageMeasurementMatchesPythonContractVector(t *testing.T) {
	body := &tdxpb.TDQuoteBody{
		TdAttributes:  bytes.Repeat([]byte("T"), 8),
		Xfam:          bytes.Repeat([]byte("X"), 8),
		MrTd:          bytes.Repeat([]byte("M"), 48),
		MrConfigId:    bytes.Repeat([]byte("C"), 48),
		MrOwner:       bytes.Repeat([]byte("O"), 48),
		MrOwnerConfig: bytes.Repeat([]byte("o"), 48),
		Rtmrs: [][]byte{
			bytes.Repeat([]byte("0"), 48),
			bytes.Repeat([]byte("1"), 48),
			bytes.Repeat([]byte("2"), 48),
			bytes.Repeat([]byte("3"), 48),
		},
	}
	got, err := imageMeasurementID(body)
	if err != nil {
		t.Fatal(err)
	}
	want := "tdx-image-sha256:5c1e249b50fa545864ca0f4e3f58c7c40114fb4afa7e59ac79714f9c5bb3856c"
	if got != want {
		t.Errorf("imageMeasurementID() = %q, want Python contract vector %q", got, want)
	}
	// The launcher-set fields are not part of the image identity.
	body.MrConfigId = bytes.Repeat([]byte("c"), 48)
	body.MrOwner = bytes.Repeat([]byte("P"), 48)
	body.MrOwnerConfig = bytes.Repeat([]byte("p"), 48)
	if again, _ := imageMeasurementID(body); again != want {
		t.Errorf("owner fields changed the image identity: %q", again)
	}
	body.Rtmrs[1] = bytes.Repeat([]byte("9"), 48)
	if changed, _ := imageMeasurementID(body); changed == want {
		t.Error("RTMR1 did not change the image identity")
	}
}

func TestIdentityVectorsFromRealGCPQuotes(t *testing.T) {
	for _, vector := range loadIdentityVectors(t) {
		body := fixtureBody(t, vector.Quote)
		measurement, err := measurementID(body)
		if err != nil {
			t.Fatal(err)
		}
		image, err := imageMeasurementID(body)
		if err != nil {
			t.Fatal(err)
		}
		if measurement != vector.Measurement {
			t.Errorf("%s: measurement = %q, want %q", vector.Quote, measurement, vector.Measurement)
		}
		if image != vector.ImageMeasurement {
			t.Errorf("%s: image measurement = %q, want %q", vector.Quote, image, vector.ImageMeasurement)
		}
	}
}

func TestTwoVMsFromOneImageShareOnlyTheImageIdentity(t *testing.T) {
	for _, pair := range [][2]string{
		{"same-image-a.quote", "same-image-b.quote"},
		{"clean-image-a.quote", "clean-image-b.quote"},
	} {
		a, b := fixtureBody(t, pair[0]), fixtureBody(t, pair[1])
		if bytes.Equal(a.GetMrOwner(), b.GetMrOwner()) {
			t.Fatalf("%v: fixture VMs share MROWNER", pair)
		}
		launchA, _ := measurementID(a)
		launchB, _ := measurementID(b)
		imageA, _ := imageMeasurementID(a)
		imageB, _ := imageMeasurementID(b)
		if launchA == launchB {
			t.Errorf("%v: v1 measurement unexpectedly equal", pair)
		}
		if imageA != imageB {
			t.Errorf("%v: image identity differs: %q vs %q", pair, imageA, imageB)
		}
	}
}

func TestVerifiedClaimsCarryTheImageIdentity(t *testing.T) {
	got := fixtureClaims(t)
	parsed, err := abi.QuoteToProto(canonicalQuoteV4Fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	_, body, err := launchQuoteV4(parsed)
	if err != nil {
		t.Fatal(err)
	}
	want, err := imageMeasurementID(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.ImageMeasurement != want {
		t.Errorf("image_measurement = %q, want %q", got.ImageMeasurement, want)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"image_measurement":"tdx-image-sha256:`)) {
		t.Errorf("claims JSON lacks image_measurement: %s", encoded)
	}
}

func TestImageMeasurementRejectsMalformedFields(t *testing.T) {
	valid := func() *tdxpb.TDQuoteBody {
		return &tdxpb.TDQuoteBody{
			TdAttributes: make([]byte, 8),
			Xfam:         make([]byte, 8),
			MrTd:         make([]byte, 48),
			Rtmrs:        [][]byte{make([]byte, 48), make([]byte, 48), make([]byte, 48), make([]byte, 48)},
		}
	}
	if _, err := imageMeasurementID(valid()); err != nil {
		t.Fatalf("valid body rejected: %v", err)
	}
	for name, mutate := range map[string]func(*tdxpb.TDQuoteBody){
		"short attributes": func(b *tdxpb.TDQuoteBody) { b.TdAttributes = make([]byte, 7) },
		"short xfam":       func(b *tdxpb.TDQuoteBody) { b.Xfam = make([]byte, 9) },
		"short mrtd":       func(b *tdxpb.TDQuoteBody) { b.MrTd = make([]byte, 47) },
		"three rtmrs":      func(b *tdxpb.TDQuoteBody) { b.Rtmrs = b.Rtmrs[:3] },
		"short rtmr":       func(b *tdxpb.TDQuoteBody) { b.Rtmrs[2] = make([]byte, 47) },
	} {
		body := valid()
		mutate(body)
		if _, err := imageMeasurementID(body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
