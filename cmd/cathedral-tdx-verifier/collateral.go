package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/go-tdx-guest/pcs"
	"github.com/google/go-tdx-guest/verify"
)

const maxBundleBytes = 24 * 1024 * 1024
const collateralSchema = "cathedral_tdx_collateral_v1"

type collateralResponse struct {
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body_base64"`
}

type collateralBundle struct {
	Schema      string                        `json:"schema"`
	QuoteSHA256 string                        `json:"quote_sha256"`
	Responses   map[string]collateralResponse `json:"responses"`
}

// There is no network client or fallback in this getter. All inputs are copied
// before verification and the vendor library still verifies every signature,
// certificate validity interval, revocation list and TCB level.
type offlineGetter struct {
	mu          sync.Mutex
	responses   map[string]collateralResponse
	tcbInfoBody []byte
}

func (g *offlineGetter) Get(rawURL string) (map[string][]string, []byte, error) {
	return g.GetContext(context.Background(), rawURL)
}

func (g *offlineGetter) GetContext(ctx context.Context, rawURL string) (map[string][]string, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, errors.New("invalid collateral URL")
	}
	if err := prepareIntelCollateralURL(parsed); err != nil {
		return nil, nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := g.responses[parsed.String()]
	if !ok {
		return nil, nil, errors.New("offline collateral bundle lacks a required response")
	}
	if parsed.Path == tdxTcbInfoPath {
		g.tcbInfoBody = bytes.Clone(entry.Body)
	}
	return http.Header(entry.Headers).Clone(), bytes.Clone(entry.Body), nil
}

func (g *offlineGetter) tcbInfoSnapshot() (pcs.TdxTcbInfo, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var snapshot pcs.TdxTcbInfo
	if len(g.tcbInfoBody) == 0 {
		return snapshot, errors.New("offline TCB collateral was not consumed")
	}
	err := json.Unmarshal(g.tcbInfoBody, &snapshot)
	return snapshot, err
}

func offlineVerifyOptions(encoded, quote []byte) (*verify.Options, error) {
	if len(encoded) == 0 || len(encoded) > maxBundleBytes {
		return nil, errors.New("collateral bundle exceeds size limit")
	}
	var bundle collateralBundle
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return nil, errors.New("invalid collateral bundle")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("collateral bundle has trailing JSON")
	}
	digest := sha256.Sum256(quote)
	if bundle.Schema != collateralSchema || bundle.QuoteSHA256 != hex.EncodeToString(digest[:]) {
		return nil, errors.New("collateral bundle schema or quote binding is invalid")
	}
	if len(bundle.Responses) == 0 || len(bundle.Responses) > 16 {
		return nil, errors.New("invalid collateral response count")
	}
	for rawURL, entry := range bundle.Responses {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return nil, errors.New("invalid collateral URL")
		}
		if err := prepareIntelCollateralURL(parsed); err != nil {
			return nil, err
		}
		if parsed.String() != rawURL || parsed.Fragment != "" {
			return nil, errors.New("noncanonical collateral URL")
		}
		if len(entry.Body) == 0 || len(entry.Body) > maxCollateralBytes {
			return nil, errors.New("invalid collateral body size")
		}
		encodedHeaders, err := json.Marshal(entry.Headers)
		if err != nil || len(encodedHeaders) > 32*1024 {
			return nil, errors.New("invalid collateral header size")
		}
	}
	return &verify.Options{
		CheckRevocations: true, GetCollateral: true,
		DisableTcbStatusCheck: false,
		Getter:                &offlineGetter{responses: bundle.Responses},
	}, nil
}

func readCollateralBundle(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("collateral bundle path must be absolute")
	}
	handle, err := openQuoteFile(path)
	if err != nil {
		return nil, errors.New("collateral bundle is not readable")
	}
	defer handle.Close()
	metadata, err := handle.Stat()
	if err != nil || !metadata.Mode().IsRegular() || metadata.Size() <= 0 || metadata.Size() > maxBundleBytes {
		return nil, errors.New("collateral bundle must be a bounded regular file")
	}
	body, err := io.ReadAll(io.LimitReader(handle, maxBundleBytes+1))
	if err != nil || len(body) > maxBundleBytes {
		return nil, errors.New("collateral bundle exceeds size limit")
	}
	return body, nil
}

func writeCollateralBundle(path string, quote []byte, getter *intelHTTPSGetter) error {
	if !filepath.IsAbs(path) {
		return errors.New("capture path must be absolute")
	}
	digest := sha256.Sum256(quote)
	getter.mu.Lock()
	body, err := json.Marshal(collateralBundle{collateralSchema, hex.EncodeToString(digest[:]), getter.responses})
	getter.mu.Unlock()
	if err != nil || len(body) > maxBundleBytes {
		return errors.New("captured collateral exceeds size limit")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".collateral-*")
	if err != nil {
		return errors.New("could not create collateral capture")
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(body); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
