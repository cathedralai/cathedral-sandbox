package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-tdx-guest/verify"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func stubResponse(req *http.Request, status int, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader("{}")),
		Request:    req,
	}
}

func stubGetter(transport roundTripFunc) *intelHTTPSGetter {
	getter := newIntelHTTPSGetter()
	getter.client.Transport = transport
	return getter
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (failingBody) Close() error             { return nil }

const stubCollateralURL = "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity"

func TestCollateralOutagesAreRecordedAsUnavailable(t *testing.T) {
	for name, transport := range map[string]roundTripFunc{
		"network error": func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial tcp: connection refused")
		},
		"deadline": func(*http.Request) (*http.Response, error) {
			return nil, context.DeadlineExceeded
		},
		"HTTP 500": func(req *http.Request) (*http.Response, error) {
			return stubResponse(req, http.StatusInternalServerError, nil), nil
		},
		"HTTP 503": func(req *http.Request) (*http.Response, error) {
			return stubResponse(req, http.StatusServiceUnavailable, nil), nil
		},
		"HTTP 408": func(req *http.Request) (*http.Response, error) {
			return stubResponse(req, http.StatusRequestTimeout, nil), nil
		},
		"HTTP 425": func(req *http.Request) (*http.Response, error) {
			return stubResponse(req, http.StatusTooEarly, nil), nil
		},
		"HTTP 429": func(req *http.Request) (*http.Response, error) {
			return stubResponse(req, http.StatusTooManyRequests, nil), nil
		},
		"body read error": func(req *http.Request) (*http.Response, error) {
			response := stubResponse(req, http.StatusOK, nil)
			response.Body = failingBody{}
			return response, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			getter := stubGetter(transport)
			if _, _, err := getter.GetContext(context.Background(), stubCollateralURL); err == nil {
				t.Fatal("failed collateral request unexpectedly succeeded")
			}
			if !getter.collateralUnavailable() {
				t.Fatal("collateral outage was not recorded")
			}
		})
	}
}

func TestTerminalCollateralAnswersAreNotOutages(t *testing.T) {
	for name, status := range map[string]int{
		"HTTP 400": http.StatusBadRequest,
		"HTTP 401": http.StatusUnauthorized,
		"HTTP 403": http.StatusForbidden,
		"HTTP 404": http.StatusNotFound,
		"HTTP 410": http.StatusGone,
		"HTTP 304": http.StatusNotModified,
	} {
		t.Run(name, func(t *testing.T) {
			getter := stubGetter(func(req *http.Request) (*http.Response, error) {
				return stubResponse(req, status, nil), nil
			})
			if _, _, err := getter.GetContext(context.Background(), stubCollateralURL); err == nil {
				t.Fatal("non-2xx collateral answer unexpectedly succeeded")
			}
			if getter.collateralUnavailable() {
				t.Fatalf("terminal %d answer was recorded as an outage", status)
			}
		})
	}

	t.Run("refused redirect", func(t *testing.T) {
		getter := stubGetter(func(req *http.Request) (*http.Response, error) {
			return stubResponse(req, http.StatusFound, http.Header{
				"Location": {"https://collateral.example.invalid/tdx/certification/v4/qe/identity"},
			}), nil
		})
		if _, _, err := getter.GetContext(context.Background(), stubCollateralURL); err == nil {
			t.Fatal("unsafe redirect unexpectedly followed")
		}
		if getter.collateralUnavailable() {
			t.Fatal("refused redirect was recorded as an outage")
		}
	})

	t.Run("disallowed URL", func(t *testing.T) {
		called := false
		getter := stubGetter(func(req *http.Request) (*http.Response, error) {
			called = true
			return nil, errors.New("unreachable")
		})
		if _, _, err := getter.GetContext(
			context.Background(), "https://collateral.example.invalid/tdx/certification/v4/tcb",
		); err == nil {
			t.Fatal("disallowed collateral host unexpectedly accepted")
		}
		if called || getter.collateralUnavailable() {
			t.Fatal("disallowed URL reached the network or was recorded as an outage")
		}
	})
}

func productionOptionsWith(getter *intelHTTPSGetter) *verify.Options {
	options := productionVerifyOptions()
	options.Getter = getter
	return options
}

func TestVerificationDuringIntelOutageReportsUnavailable(t *testing.T) {
	getter := stubGetter(func(req *http.Request) (*http.Response, error) {
		return stubResponse(req, http.StatusServiceUnavailable, nil), nil
	})
	_, err := verifyAndBuildClaims(
		context.Background(), canonicalQuoteV4Fixture(t), make([]byte, 64), productionOptionsWith(getter),
	)
	if !errors.Is(err, errCollateralUnavailable) {
		t.Fatalf("verifyAndBuildClaims() error = %v, want collateral unavailable", err)
	}
	if got := exitCode(err); got != exitCollateralUnavailable {
		t.Fatalf("exitCode() = %d, want %d", got, exitCollateralUnavailable)
	}
}

func TestVerificationWithTerminalCollateralAnswerStaysInvalid(t *testing.T) {
	for name, transport := range map[string]roundTripFunc{
		"HTTP 404": func(req *http.Request) (*http.Response, error) {
			return stubResponse(req, http.StatusNotFound, nil), nil
		},
		"malformed collateral": func(req *http.Request) (*http.Response, error) {
			return stubResponse(req, http.StatusOK, nil), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := verifyAndBuildClaims(
				context.Background(), canonicalQuoteV4Fixture(t), make([]byte, 64),
				productionOptionsWith(stubGetter(transport)),
			)
			if err == nil {
				t.Fatal("quote verified against unusable collateral")
			}
			if !strings.Contains(err.Error(), "Intel quote, collateral") {
				t.Fatalf("failed before collateral verification: %v", err)
			}
			if errors.Is(err, errCollateralUnavailable) {
				t.Fatalf("terminal collateral answer reported as an outage: %v", err)
			}
			if got := exitCode(err); got != exitInvalid {
				t.Fatalf("exitCode() = %d, want %d", got, exitInvalid)
			}
		})
	}
}

func TestInvalidInputNeverReportsUnavailable(t *testing.T) {
	for _, err := range []error{
		errors.New("quote path must be absolute"),
		errors.New("Intel quote, collateral, revocation, or TCB verification failed"),
	} {
		if got := exitCode(err); got != exitInvalid {
			t.Fatalf("exitCode(%v) = %d, want %d", err, got, exitInvalid)
		}
	}
}
