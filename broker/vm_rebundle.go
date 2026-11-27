// Rebundle route for sealed customer VMs (AB#999 VM6, VM runtime spec r3 7.5 step 1).
// Operator key only, like every VM route; off with vms_enabled.
//
//	POST /v1/broker/vms/{id}/rebundle  {"generation": G, "expect_revision": N, "op_id": X, "to": B2}
//
// rebundle selects another bundle for a stopped VM on its host (a restore is
// the same call back). The host is the authority: it fences by the closed
// generation and by the VM's bundle_selection_revision (GET host_status), and
// an op_id it already applied answers its stored result. So the broker keeps
// no state for it (vms.json is unchanged), and a call whose answer was lost is
// repeated with the same op_id.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

const vmRevisionMax = 1 << 53

var (
	vmBundleIDRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	vmOpIDRE      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	vmHostErrorRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// vmHostRefusal is one host refusal a route shows the client as its own
// error. The host's exit code and the "error" token of its JSON line must
// both match, so an exit code never stands for another command's refusal:
// 17 and 18 are start's gate refusals (vm_gates.py) and stay 502 there.
type vmHostRefusal struct {
	exit   int
	status int
	msg    string
}

var vmRebundleRefusals = map[string]vmHostRefusal{
	"stale_generation":    {3, 409, "the generation is not the VM's current, closed run, or the VM runs"},
	"stale_selection":     {19, 409, "expect_revision is not the VM's bundle_selection_revision, or the op_id was used for another request: read GET host_status"},
	"bundle_incompatible": {20, 409, "the target bundle cannot start this VM on its host"},
}

// vmHostRefusalOf is the "error" and "reason" tokens of the host's last JSON
// line, each "" unless it is a plain token. Only a token in a route's table
// reaches the client.
func vmHostRefusalOf(out []byte) (string, string) {
	line := bytes.TrimSpace(out)
	if i := bytes.LastIndexByte(line, '\n'); i >= 0 {
		line = line[i+1:]
	}
	var doc struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal(line, &doc) != nil || !vmHostErrorRE.MatchString(doc.Error) {
		return "", ""
	}
	if !vmHostErrorRE.MatchString(doc.Reason) {
		doc.Reason = ""
	}
	return doc.Error, doc.Reason
}

// callMapped is call for a route whose host refusals each have their own
// answer: a refusal in known answers its status with the host's token as the
// code (and the host's reason token in the message); any other refusal is
// 502 vm_host_refused. A host that did not answer is 502 vm_host_unreachable
// with the outcome unknown, as in call.
func (s *vmStore) callMapped(ctx context.Context, h vmHostConfig, timeout time.Duration, stdin []byte,
	known map[string]vmHostRefusal, args ...string) (map[string]any, *vmCallErr) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, code, err := s.exec.Run(ctx, h, stdin, args...)
	if err != nil {
		log.Printf("vms: host %s: %s: %v", h.ID, args[0], err)
		return nil, &vmCallErr{502, "vm_host_unreachable", "the VM host did not answer; the outcome is unknown", true}
	}
	if code != 0 {
		token, reason := vmHostRefusalOf(out)
		if r, ok := known[token]; ok && r.exit == code {
			msg := r.msg
			if reason != "" {
				msg += " (reason: " + reason + ")"
			}
			return nil, &vmCallErr{r.status, token, msg, false}
		}
		log.Printf("vms: host %s: %s: exit %d", h.ID, args[0], code)
		return nil, &vmCallErr{502, "vm_host_refused", fmt.Sprintf("the VM host refused %s (exit %d)", args[0], code), false}
	}
	return vmHostDoc(h, args[0], out)
}

func (b *broker) rebundleVM(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Generation     *uint64 `json:"generation"`
		ExpectRevision *uint64 `json:"expect_revision"`
		OpID           string  `json:"op_id"`
		To             string  `json:"to"`
	}
	if !readVMBody(w, r, &req, false) {
		return
	}
	switch {
	case req.Generation == nil || *req.Generation > vmRevisionMax:
		writeErr(w, 400, "invalid_generation", "generation is required: the VM's current, closed run (0 if it never ran)")
		return
	case req.ExpectRevision == nil || *req.ExpectRevision > vmRevisionMax:
		writeErr(w, 400, "invalid_expect_revision", "expect_revision is required: bundle_selection_revision from GET host_status")
		return
	case !vmOpIDRE.MatchString(req.OpID):
		writeErr(w, 400, "invalid_op_id", "op_id is 32 lowercase hex: 128 random bits, the same on every retry")
		return
	case !vmBundleIDRE.MatchString(req.To):
		writeErr(w, 400, "invalid_bundle", "to is a bundle id (64 lowercase hex)")
		return
	}
	s := b.vms
	s.mu.Lock()
	rec, h, ok := s.begin(w, id)
	if !ok {
		s.mu.Unlock()
		return
	}
	var code, refuse string
	switch {
	case rec.DesiredState != vmStateStopped:
		code, refuse = "vm_not_stopped", "only a stopped VM changes bundle (state "+rec.DesiredState+")"
	case *req.Generation != rec.Generation:
		code, refuse = "stale_generation", fmt.Sprintf("the current generation is %d", rec.Generation)
	case rec.AuthorizedGeneration > rec.Generation:
		// The host holds the next run open and would refuse either generation.
		code, refuse = "stale_generation", fmt.Sprintf("generation %d is authorized: run or cancel it first", rec.AuthorizedGeneration)
	}
	if refuse != "" {
		delete(s.busy, id)
		s.mu.Unlock()
		writeErr(w, 409, code, refuse)
		return
	}
	s.mu.Unlock()

	doc, cerr := s.callMapped(r.Context(), h, 3*time.Minute, nil, vmRebundleRefusals, "rebundle", id,
		"--generation", strconv.FormatUint(*req.Generation, 10),
		"--expect-revision", strconv.FormatUint(*req.ExpectRevision, 10), "--op-id", req.OpID, "--to", req.To)

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.busy, id)
	if cerr != nil {
		cerr.write(w)
		return
	}
	v := s.view(rec)
	v["rebundle"] = doc
	writeJSON(w, 200, v)
}
