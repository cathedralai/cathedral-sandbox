package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// TestMain lets a test run main() in a child process (BROKER_TEST_MAIN_ARGS),
// so the -print-catalog-digest flag is checked on the real entry point
// without a toolchain build.
func TestMain(m *testing.M) {
	if args, ok := os.LookupEnv("BROKER_TEST_MAIN_ARGS"); ok {
		os.Args = append([]string{os.Args[0]}, strings.Fields(args)...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var digestFormat = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func TestCatalogDigestFileMatchesCatalog(t *testing.T) {
	b, err := os.ReadFile("catalog.digest")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(b)), catalogDigest(); got != want {
		t.Fatalf("broker/catalog.digest is %s but the catalog is %s: a pin change must update catalog.digest "+
			"(go run . -print-catalog-digest > catalog.digest); swaps compare binaries against it", got, want)
	}
	if string(b) != catalogDigest()+"\n" {
		t.Fatalf("catalog.digest must be the digest and one newline: %q", b)
	}
}

func TestCatalogDigestFormatAndStable(t *testing.T) {
	d := catalogDigest()
	if !digestFormat.MatchString(d) {
		t.Fatalf("digest %q", d)
	}
	if catalogDigest() != d {
		t.Fatal("digest is not stable")
	}
}

func TestCatalogDigestChangesWithEveryCreateField(t *testing.T) {
	base := catalogDigestOf(catalogTemplates)
	mutations := map[string]func(*catalogTemplate){
		"image": func(c *catalogTemplate) {
			c.Image = "ghcr.io/cathedralai/room-lfm3-vl-2b@sha256:" + strings.Repeat("0", 64)
		},
		"live":        func(c *catalogTemplate) { c.Live = !c.Live },
		"sealed":      func(c *catalogTemplate) { c.Sealed = sealedPending },
		"sealed_only": func(c *catalogTemplate) { c.SealedOnly = !c.SealedOnly },
		"cpu":         func(c *catalogTemplate) { c.CPU++ },
		"memory":      func(c *catalogTemplate) { c.MemoryGiB++ },
		"disk":        func(c *catalogTemplate) { c.DiskGiB++ },
		"name":        func(c *catalogTemplate) { c.Name += "-x" },
	}
	for field, mutate := range mutations {
		ts := append([]catalogTemplate(nil), catalogTemplates...)
		mutate(&ts[len(ts)-1])
		if catalogDigestOf(ts) == base {
			t.Errorf("changing %s did not change the digest", field)
		}
	}
	swapped := append([]catalogTemplate(nil), catalogTemplates...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if catalogDigestOf(swapped) == base {
		t.Error("reordering the catalog did not change the digest")
	}
}

// The readback script recomputes the digest from GET /v1/sandboxes/catalog.
// Recompute it here from the JSON the route writes, the way the script does.
func TestCatalogDigestRecomputesFromCatalogResponse(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"templates": catalogTemplateViews()})
	if err != nil {
		t.Fatal(err)
	}
	var resp struct {
		Templates []struct {
			Name       string `json:"name"`
			Image      string `json:"image"`
			Live       bool   `json:"live"`
			Sealed     string `json:"sealed"`
			SealedOnly bool   `json:"sealed_only"`
			DiskGiB    int    `json:"disk_gib"`
			Resources  struct {
				CPU       int `json:"cpu"`
				MemoryGiB int `json:"memory_gib"`
			} `json:"resources"`
		} `json:"templates"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	ts := make([]catalogTemplate, 0, len(resp.Templates))
	for _, v := range resp.Templates {
		ts = append(ts, catalogTemplate{Name: v.Name, Image: v.Image, Live: v.Live, Sealed: sealedOffer(v.Sealed),
			SealedOnly: v.SealedOnly, CPU: v.Resources.CPU, MemoryGiB: v.Resources.MemoryGiB, DiskGiB: v.DiskGiB})
	}
	if got := catalogDigestOf(ts); got != catalogDigest() {
		t.Fatalf("digest from the catalog response %s, compiled %s", got, catalogDigest())
	}
}

func TestPrintCatalogDigestIsOneLine(t *testing.T) {
	var out bytes.Buffer
	if err := printCatalogDigest(&out); err != nil {
		t.Fatal(err)
	}
	if out.String() != catalogDigest()+"\n" {
		t.Fatalf("output %q", out.String())
	}
}

// The flag exits before the config is read: a swap check can run the new
// binary anywhere without its config, keys or state.
func TestPrintCatalogDigestFlagNeedsNoConfig(t *testing.T) {
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "BROKER_TEST_MAIN_ARGS=-config "+t.TempDir()+"/missing.json -print-catalog-digest")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("exit: %v stderr %q", err, stderr.String())
	}
	if stdout.String() != catalogDigest()+"\n" {
		t.Fatalf("stdout %q stderr %q", stdout.String(), stderr.String())
	}
}
