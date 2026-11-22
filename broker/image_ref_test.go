package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// AB#868: the broker refuses an image reference no hotel accepts, at once,
// with a hint, instead of after placement (create), as a failed pull on every
// hotel (prefetch) or never (compat import answered "ready").

var digest64 = strings.Repeat("a", 64)

func TestImageRefGrammar(t *testing.T) {
	for _, ref := range []string{"alpine:3.20", "ghcr.io/a/b:1", "localhost:5000/x:1", "x@sha256:" + digest64,
		"docker.io/library/ubuntu:24.04", "a/b/c:v1.2-rc_3"} {
		if e := imageRefRefusal(ref, false); e != nil {
			t.Errorf("%q refused: %v", ref, e)
		}
	}
	if e := imageRefRefusal("sbt-foo-1a2b", true); e != nil {
		t.Errorf("a create may name a template uid: %v", e)
	}
	if e := imageRefRefusal("sbt-foo-1a2b", false); e == nil || e.code != "invalid_image_reference" {
		t.Errorf("a prefetch may not name a template uid: %v", e)
	}
	untagged := []string{"alpine", "ghcr.io/a/b", "localhost:5000/x", "library/alpine"}
	for _, ref := range untagged {
		e := imageRefRefusal(ref, false)
		if e == nil || e.status != 400 || e.code != "invalid_image_reference" || !strings.Contains(e.msg, "add :tag or @sha256:<digest>") {
			t.Errorf("%q: want 400 invalid_image_reference with the tag hint, got %v", ref, e)
		}
	}
	for _, ref := range []string{"Alpine:1", "Alpine", "x:1@sha256:" + digest64, "-x:1", "x:", "https://x/y:1", " x:1", "x:1 ", "x@sha256:abc"} {
		e := imageRefRefusal(ref, true)
		if e == nil || e.status != 400 || e.code != "invalid_image_reference" || strings.Contains(e.msg, "add :tag") {
			t.Errorf("%q: want 400 invalid_image_reference with the grammar message, got %v", ref, e)
		}
	}
	// The older refusals keep their codes.
	if e := imageRefRefusal("sha256:"+digest64, true); e == nil || e.code != "image_reference_refused" {
		t.Errorf("image id: %v", e)
	}
	if e := imageRefRefusal("cathedral-snap-abc", true); e == nil || e.code != "snapshot_image_by_name" {
		t.Errorf("snapshot image: %v", e)
	}
}

// The broker grammar is the hotel's, byte for byte, so the two cannot drift.
func TestImageRefGrammarIsTheHotels(t *testing.T) {
	src, err := os.ReadFile("../cathedral/sandbox_api.py")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)_IMAGE_REF_RE = re\.compile\(\s*r"([^"]*)"\s*r"([^"]*)"\s*\)`).FindSubmatch(src)
	if m == nil {
		t.Fatal("_IMAGE_REF_RE not found as two raw string literals in cathedral/sandbox_api.py")
	}
	if got := string(m[1]) + string(m[2]); got != imageRefPattern {
		t.Fatalf("hotel grammar changed:\nhotel  %s\nbroker %s", got, imageRefPattern)
	}
	tm := regexp.MustCompile(`_TEMPLATE_UID_RE = re\.compile\(r"([^"]*)"\)`).FindSubmatch(src)
	if tm == nil || string(tm[1]) != templateUIDRE.String() {
		t.Fatalf("hotel template uid grammar changed: %q vs %q", tm, templateUIDRE.String())
	}
}

func TestCreateRefusesAnUntaggedImageBeforePlacement(t *testing.T) {
	tc := newChain(t)
	for _, body := range []map[string]any{
		{"image": "alpine"},
		{"image": map[string]any{"image": "alpine"}},
		{"image": "alpine", "count": 5},
	} {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", body)
		e, _ := doc["error"].(map[string]any)
		msg, _ := e["message"].(string)
		if status != 400 || errCode(doc) != "invalid_image_reference" || !strings.Contains(msg, "add :tag") {
			t.Fatalf("create %v: %d %v", body, status, doc)
		}
	}
	if on := createsOn(tc); on["a"]+on["b"]+on["c"] != 0 {
		t.Fatalf("a hotel got a create for an untagged image: %v", on)
	}
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20"}); status != 202 {
		t.Fatalf("tagged create: %d %v", status, doc)
	}
}

func TestPrefetchRefusesTheWholeListAtOnce(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.call(t, "key1", "POST", "/v1/images/prefetch", map[string]any{"images": []any{"alpine:3.20", "ubuntu"}})
	if status != 400 || errCode(doc) != "invalid_image_reference" {
		t.Fatalf("prefetch: %d %v", status, doc)
	}
	time.Sleep(100 * time.Millisecond)
	for id, f := range tc.hotels {
		if n := callsTo(f, "POST /v1/images/prefetch"); n != 0 {
			t.Fatalf("hotel %s got a prefetch for a list with an untagged image", id)
		}
	}
	tc.b.prefetch.mu.Lock()
	jobs := len(tc.b.prefetch.jobs)
	tc.b.prefetch.mu.Unlock()
	if jobs != 0 {
		t.Fatalf("a refused prefetch left %d jobs", jobs)
	}
}

func TestCompatImportAndCreateRefuseAnUntaggedImage(t *testing.T) {
	tc := newChain(t)
	for _, path := range []string{"/v1/images/import", "/v1/sandboxes"} {
		status, doc := tc.clientCall(t, "POST", path, mustMarshal(map[string]any{"image": "alpine"}), nil)
		d, _ := doc["detail"].(map[string]any)
		msg, _ := d["message"].(string)
		if status != 400 || d["error"] != "invalid_image_reference" || !strings.Contains(msg, "add :tag") {
			t.Fatalf("compat %s: %d %v", path, status, doc)
		}
	}
	time.Sleep(100 * time.Millisecond)
	for id, f := range tc.hotels {
		if n := callsTo(f, "POST /v1/images/prefetch"); n != 0 {
			t.Fatalf("compat import warmed hotel %s with an untagged image", id)
		}
	}
}
