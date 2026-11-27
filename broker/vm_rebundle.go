// Re-wrap routes for sealed customer VMs (AB#999 VM6, VM runtime spec r3 7.5).
// Operator key only, like every VM route; off with vms_enabled.
//
//	POST /v1/broker/vms/{id}/rebundle  {"generation": G, "from": B1, "to": B2, "expect_revision": R, "op_id": X}
//	POST /v1/broker/vms/{id}/rewrap    {"generation": G, "answer": {...}}
//
// rebundle moves a stopped VM to another bundle on its host (a restore is the
// same call back). The host is the authority: it fences by the closed
// generation and by the VM's bundle_selection_revision (GET host_status), and
// an op_id it already applied answers its stored result. So the broker keeps
// no state for it (vms.json is unchanged) and a call whose answer was lost is
// repeated with the same op_id.
//
// rewrap relays the customer's answer to the offer a running guest waits
// with. The answer travels on stdin, never on the remote command line:
// vmArgRE allows 64 characters an argument, and the host's forced command
// reads at most vmRewrapAnswerMax bytes. host_status.rewrap_offer, the offer
// itself, is guest-controlled data: the broker passes it on and trusts none of it.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

const (
	// vmRewrapAnswerMax is what vm-ctl.sh rewrap reads from stdin (room-kit/vm/vm_mailbox.py ANSWER_MAX).
	vmRewrapAnswerMax = 4096
	vmRewrapSchema    = "cathedral.vm.rewrap-answer/v1"
	vmRewrapAlgorithm = "x25519-hkdf-sha256-aes-256-gcm"
	vmRevisionMax     = 1 << 53
)

var (
	vmSHA256HexRE = regexp.MustCompile(`^[0-9a-f]{64}$`) // a bundle id, an offer's report digest
	vmOpIDRE      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	vmHostErrorRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// vmHostRefusal is one host refusal a route shows the client as its own
// error: the host's exit code and the "error" token of its JSON line must
// both match (vm-ctl.sh's contract), so an exit code never stands for another
// command's refusal (exit 17 is rebundle's stale_selection and nothing else).
type vmHostRefusal struct {
	exit   int
	status int
	msg    string
}

var vmRebundleRefusals = map[string]vmHostRefusal{
	"op_id_conflict":      {2, 409, "this op_id was applied to another request"},
	"stale_generation":    {3, 409, "the host's current generation is not this one"},
	"generation_open":     {3, 409, "the generation is open on the host: stop or cancel the run first"},
	"stale_selection":     {17, 409, "expect_revision is not the VM's bundle_selection_revision: read it from GET host_status"},
	"bundle_changed":      {3, 409, "from is not the VM's current bundle"},
	"vm_not_stopped":      {3, 409, "the VM's unit is active on the host"},
	"bundle_not_enabled":  {1, 409, "the target bundle is not enabled on the VM's host"},
	"no_bundle":           {1, 409, "the target bundle is not on the VM's host"},
	"bundle_incompatible": {1, 409, "the target bundle has another base root than the VM's identity"},
}

var vmRewrapRefusals = map[string]vmHostRefusal{
	"invalid_rewrap_answer": {2, 400, "the host refused the answer's shape"},
	"stale_generation":      {3, 409, "the host's current generation is not this one"},
	"generation_closed":     {3, 409, "the run was stopped: no guest waits for an answer"},
	"no_rewrap_offer":       {3, 409, "no guest waits with an offer"},
	"rewrap_offer_changed":  {3, 409, "the answer is for another offer than the one waiting (the guest restarted)"},
}

// vmHostErrorToken is the "error" of the host's last JSON line when it is a
// plain token, else "". Only a token in a route's table reaches the client.
func vmHostErrorToken(out []byte) string {
	line := bytes.TrimSpace(out)
	if i := bytes.LastIndexByte(line, '\n'); i >= 0 {
		line = line[i+1:]
	}
	var doc struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(line, &doc) != nil || !vmHostErrorRE.MatchString(doc.Error) {
		return ""
	}
	return doc.Error
}

// callMapped is call for the routes whose host refusals each have their own
// answer: a refusal in known answers its status with the host's token as the
// code; any other refusal is 502 vm_host_refused. A host that did not answer
// is 502 vm_host_unreachable with the outcome unknown, as in call.
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
		token := vmHostErrorToken(out)
		if r, ok := known[token]; ok && r.exit == code {
			return nil, &vmCallErr{r.status, token, r.msg, false}
		}
		log.Printf("vms: host %s: %s: exit %d", h.ID, args[0], code)
		return nil, &vmCallErr{502, "vm_host_refused", fmt.Sprintf("the VM host refused %s (exit %d)", args[0], code), false}
	}
	return vmHostDoc(h, args[0], out)
}

func (b *broker) rebundleVM(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Generation     *uint64 `json:"generation"`
		From           string  `json:"from"`
		To             string  `json:"to"`
		ExpectRevision *uint64 `json:"expect_revision"`
		OpID           string  `json:"op_id"`
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
	case !vmSHA256HexRE.MatchString(req.From) || !vmSHA256HexRE.MatchString(req.To) || req.From == req.To:
		writeErr(w, 400, "invalid_bundle", "from and to are two different bundle ids (64 lowercase hex)")
		return
	case !vmOpIDRE.MatchString(req.OpID):
		writeErr(w, 400, "invalid_op_id", "op_id is 32 lowercase hex: 128 random bits, the same on every retry")
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
		// The host holds the next run open: it would refuse the change either way.
		code, refuse = "generation_open", fmt.Sprintf("generation %d is authorized: run or cancel it first", rec.AuthorizedGeneration)
	}
	if refuse != "" {
		delete(s.busy, id)
		s.mu.Unlock()
		writeErr(w, 409, code, refuse)
		return
	}
	s.mu.Unlock()

	doc, cerr := s.callMapped(r.Context(), h, 3*time.Minute, nil, vmRebundleRefusals, "rebundle", id,
		"--generation", strconv.FormatUint(*req.Generation, 10), "--from", req.From, "--to", req.To,
		"--expect-revision", strconv.FormatUint(*req.ExpectRevision, 10), "--op-id", req.OpID)

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

func (b *broker) rewrapVM(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Generation *uint64         `json:"generation"`
		Answer     json.RawMessage `json:"answer"`
	}
	if !readVMBody(w, r, &req, false) {
		return
	}
	if req.Generation == nil || *req.Generation == 0 || *req.Generation > vmRevisionMax {
		writeErr(w, 400, "invalid_generation", "generation is required: the run whose guest waits")
		return
	}
	answer, err := vmRewrapAnswer(req.Answer)
	if err != nil {
		writeErr(w, 400, "invalid_rewrap_answer", err.Error())
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
	case rec.DesiredState != vmStateRunning:
		code, refuse = "vm_not_running", "only a running VM's guest waits for an answer (state "+rec.DesiredState+")"
	case *req.Generation != rec.Generation:
		code, refuse = "stale_generation", fmt.Sprintf("the current generation is %d", rec.Generation)
	}
	if refuse != "" {
		delete(s.busy, id)
		s.mu.Unlock()
		writeErr(w, 409, code, refuse)
		return
	}
	s.mu.Unlock()

	doc, cerr := s.callMapped(r.Context(), h, 2*time.Minute, answer, vmRewrapRefusals, "rewrap", id,
		"--generation", strconv.FormatUint(*req.Generation, 10))

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.busy, id)
	if cerr != nil {
		cerr.write(w)
		return
	}
	v := s.view(rec)
	v["rewrap"] = doc
	writeJSON(w, 200, v)
}

// vmRewrapAnswer checks the answer's shape as the host will
// (room-kit/vm/vm_mailbox.py parse_answer) and returns it compacted: the
// bytes the host reads on stdin. The host checks it again and decides.
func vmRewrapAnswer(raw json.RawMessage) ([]byte, error) {
	var a struct {
		Schema             *string `json:"schema"`
		Algorithm          *string `json:"algorithm"`
		OfferSHA256        *string `json:"offer_sha256"`
		EphemeralPublicB64 *string `json:"ephemeral_public_b64"`
		NonceB64           *string `json:"nonce_b64"`
		CiphertextB64      *string `json:"ciphertext_b64"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if len(bytes.TrimSpace(raw)) == 0 || raw[0] != '{' || dec.Decode(&a) != nil || dec.More() {
		return nil, errors.New("answer must be one JSON object with only the answer fields")
	}
	for _, f := range []*string{a.Schema, a.Algorithm, a.OfferSHA256, a.EphemeralPublicB64, a.NonceB64, a.CiphertextB64} {
		if f == nil {
			return nil, errors.New("answer needs schema, algorithm, offer_sha256, ephemeral_public_b64, nonce_b64 and ciphertext_b64")
		}
	}
	switch {
	case *a.Schema != vmRewrapSchema:
		return nil, errors.New("answer schema must be " + vmRewrapSchema)
	case *a.Algorithm != vmRewrapAlgorithm:
		return nil, errors.New("answer algorithm must be " + vmRewrapAlgorithm)
	case !vmSHA256HexRE.MatchString(*a.OfferSHA256):
		return nil, errors.New("answer offer_sha256 is 64 lowercase hex: the sha256 of the offer's report")
	}
	for _, f := range []struct {
		name  string
		value string
		size  int
	}{{"ephemeral_public_b64", *a.EphemeralPublicB64, 32}, {"nonce_b64", *a.NonceB64, 12}, {"ciphertext_b64", *a.CiphertextB64, 48}} {
		b, err := base64.StdEncoding.Strict().DecodeString(f.value)
		if err != nil || len(b) != f.size {
			return nil, fmt.Errorf("answer %s must be the padded base64 of %d bytes", f.name, f.size)
		}
	}
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil || out.Len() > vmRewrapAnswerMax {
		return nil, fmt.Errorf("answer must be at most %d bytes", vmRewrapAnswerMax)
	}
	return out.Bytes(), nil
}
