package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// getRaw returns status and raw body of a GET with a bearer key ("" sends none).
func (tc *testChain) getRaw(t *testing.T, key, path string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", tc.srv.URL+path, nil)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func joinedBindingSHA(t *testing.T, tc *testChain, id string) string {
	t.Helper()
	_, doc := tc.call(t, "operator-key", "GET", "/v1/broker/hotels/"+id, nil)
	adm, _ := doc["admission"].(map[string]any)
	s, _ := adm["binding_sha256"].(string)
	if len(s) != 64 {
		t.Fatalf("hotel %s has no binding_sha256: %v", id, doc)
	}
	return s
}

func TestBindingArchivedAndServedByOperator(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 1, nil)
	sha := joinedBindingSHA(t, tc, "m1")
	status, raw := tc.getRaw(t, "operator-key", "/v1/broker/bindings/"+sha)
	if status != 200 {
		t.Fatalf("operator GET binding: %d %s", status, raw)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != sha {
		t.Fatalf("served bytes do not hash to %s", sha)
	}
}

func TestBindingSurvivesRestart(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 1, nil)
	sha := joinedBindingSHA(t, tc, "m1")
	tc.start(t)
	status, raw := tc.getRaw(t, "operator-key", "/v1/broker/bindings/"+sha)
	if status != 200 {
		t.Fatalf("after restart: %d %s", status, raw)
	}
}

func TestBindingRouteIsOperatorOnly(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 1, nil)
	sha := joinedBindingSHA(t, tc, "m1")
	for _, key := range []string{"", "reader-key", "enroller-key", "key1", "wrong"} {
		status, _ := tc.getRaw(t, key, "/v1/broker/bindings/"+sha)
		if status != 401 && status != 403 && status != 404 {
			t.Fatalf("key %q got %d, want a refusal", key, status)
		}
		if status == 200 {
			t.Fatalf("key %q read a binding", key)
		}
	}
}

func TestBindingGetRefusesBadAndUnknownSHA(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	if status, _ := tc.getRaw(t, "operator-key", "/v1/broker/bindings/"+strings.Repeat("0", 64)); status != 404 {
		t.Fatalf("unknown sha: %d", status)
	}
	for _, bad := range []string{"..", "abc", strings.Repeat("g", 64), "..%2f..%2fclient-state"} {
		if status, _ := tc.getRaw(t, "operator-key", "/v1/broker/bindings/"+bad); status != 400 {
			t.Fatalf("bad sha %q: %d", bad, status)
		}
	}
}

func TestBindingArchiveHoldsBindingOnly(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	joinMiner(t, tc, "m1", true, 1, nil)
	sha := joinedBindingSHA(t, tc, "m1")
	files, _ := filepath.Glob(filepath.Join(dir, "bindings", "*"))
	if len(files) == 0 {
		t.Fatal("nothing archived")
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		if strings.Contains(string(raw), "report_b64") {
			t.Fatalf("%s holds the report", f)
		}
		if info, _ := os.Stat(f); info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", f, info.Mode().Perm())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "bindings", sha+".json")); err != nil {
		t.Fatal(err)
	}
}
