// AMD chain check of a sealed hotel's attestation (admission.go).
//
// The broker does not verify the VCEK, ASK, ARK chain or the report
// signature itself. It runs the verifier this repository already ships,
// room-kit/verify_receipts.py, on the attestation document exactly as the
// hotel served it:
//
//	<command...> --attestation <file> --require-sealed --ark-sha256 <pin> [--kds-cache <dir>]
//
// verify_receipts.py fetches ASK, ARK and the VCEK from AMD KDS (or its
// cache), checks the ARK against the pin, the ASK and VCEK signatures, the
// VCEK hwID and TCB against the report, and the report's ECDSA P-384
// signature. Its JSON verdict decides: PASS admits, FAIL refuses with its
// reason. A verifier that does not run or prints no verdict (KDS down, no
// Python) refuses too. The verifier runs only for a binding it has not
// passed, so an outage never takes out a hotel that already passed.
//
// Config:
//
//	"amd_verifier": {
//	  "command": ["python3", "/opt/room-kit/verify_receipts.py"],
//	  "ark_sha256": "<sha256 of the AMD ARK DER>",   required: the chain is pinned
//	  "kds_cache": "/var/lib/thin-broker/amd-kds",   optional
//	  "timeout_seconds": 120                          optional
//	}
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type amdVerifierConfig struct {
	Command        []string `json:"command"`
	ARKSHA256      string   `json:"ark_sha256"`
	KDSCache       string   `json:"kds_cache,omitempty"`
	TimeoutSeconds float64  `json:"timeout_seconds,omitempty"`
}

const (
	defaultAMDTimeout = 2 * time.Minute
	amdParallel       = 4 // verifier processes at one time; many miners may join at once
)

var hex64RE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

func (c *amdVerifierConfig) validate() error {
	if c == nil {
		return nil
	}
	if len(c.Command) == 0 || c.Command[0] == "" {
		return errors.New("command must name the verifier, e.g. [\"python3\", \"/opt/room-kit/verify_receipts.py\"]")
	}
	if !hex64RE.MatchString(c.ARKSHA256) {
		return errors.New("ark_sha256 must be the SHA-256 (64 hex) of the AMD ARK certificate: an unpinned chain proves nothing")
	}
	return nil
}

// amdSlots limits verifier processes across the broker.
var amdSlots = make(chan struct{}, amdParallel)

// verifyAMDChain runs the configured verifier on raw, the attestation
// document as served. It returns the verifier's "amd" result.
func (b *broker) verifyAMDChain(ctx context.Context, raw []byte) (map[string]any, error) {
	c := b.cfg.AMDVerifier
	timeout := defaultAMDTimeout
	if c.TimeoutSeconds > 0 {
		timeout = time.Duration(c.TimeoutSeconds * float64(time.Second))
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case amdSlots <- struct{}{}:
		defer func() { <-amdSlots }()
	case <-ctx.Done():
		return nil, errors.New("AMD chain verifier is busy")
	}
	f, err := os.CreateTemp(b.cfg.StateDir, "attestation-*.json")
	if err != nil {
		return nil, fmt.Errorf("AMD chain verifier: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return nil, fmt.Errorf("AMD chain verifier: %v", err)
	}
	f.Close()
	args := append(append([]string{}, c.Command[1:]...), "--attestation", f.Name(), "--require-sealed", "--ark-sha256", strings.ToLower(c.ARKSHA256))
	if c.KDSCache != "" {
		args = append(args, "--kds-cache", c.KDSCache)
	}
	cmd := exec.CommandContext(ctx, c.Command[0], args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	var out struct {
		Verdict     string `json:"verdict"`
		Reason      string `json:"reason"`
		Attestation struct {
			AMD map[string]any `json:"amd"`
		} `json:"attestation"`
	}
	if json.Unmarshal(stdout.Bytes(), &out) != nil || (out.Verdict != "PASS" && out.Verdict != "FAIL") {
		return nil, fmt.Errorf("AMD chain verifier gave no verdict: %v %s", runErr, lastLine(stderr.String()))
	}
	switch {
	case out.Verdict == "FAIL":
		return nil, fmt.Errorf("AMD chain: %s", out.Reason)
	case runErr != nil:
		return nil, fmt.Errorf("AMD chain verifier said PASS but exited with %v", runErr)
	case out.Attestation.AMD == nil:
		return nil, errors.New("AMD chain: the verifier did not check the chain")
	}
	return out.Attestation.AMD, nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
