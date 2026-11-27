// Rewrap route for sealed customer VMs (AB#999 VM6, VM runtime spec r3 7.5 step 4).
// Operator key only, like every VM route; off with vms_enabled.
//
//	POST /v1/broker/vms/{id}/rewrap  {"generation": G, "answer": {"schema", "offer_sha256", "epk", "nonce", "ct"}}
//
// rewrap relays the customer's answer to the offer a running guest waits
// with (host_status.rewrap_offer). The answer travels on stdin, never on the
// remote command line: vmArgRE allows 64 characters an argument, and the
// host's forced command reads at most vmRewrapAnswerMax + 1 bytes for it.
// host_status.rewrap_offer and guest_status are guest-controlled data: the
// broker passes them on and trusts none of it; the customer's tool verifies.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	// vmRewrapAnswerMax is room-kit/vm/vm_mailbox.py ANSWER_MAX.
	vmRewrapAnswerMax = 4096
	vmRewrapSchema    = "cathedral.vm.rewrap-answer/v1"
)

var vmRewrapRefusals = map[string]vmHostRefusal{
	"invalid_rewrap_answer": {2, 400, "the host refused the answer envelope"},
	"stale_generation":      {3, 409, "the host's current generation is not this one"},
	"generation_closed":     {3, 409, "the run was stopped: no guest waits for an answer"},
	"no_rewrap_offer":       {3, 409, "no guest waits with an offer"},
	"rewrap_offer_changed":  {3, 409, "the answer is for another offer than the one waiting (the guest restarted)"},
	"mailbox_invalid":       {3, 409, "the VM's mailbox file failed the host's checks"},
}

// vmRewrapEnvelope is the answer envelope with its fields in sorted order, so
// json.Marshal writes the canonical bytes the host requires (sorted keys, no
// spaces; none of these values has a character Go escapes).
type vmRewrapEnvelope struct {
	Ct          string `json:"ct"`
	Epk         string `json:"epk"`
	Nonce       string `json:"nonce"`
	OfferSHA256 string `json:"offer_sha256"`
	Schema      string `json:"schema"`
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

// vmRewrapAnswer checks the envelope's shape as the host will
// (room-kit/vm/vm_mailbox.py, schema KIND_ANSWER) and returns its canonical
// bytes, the exact bytes the host reads on stdin and writes as the record
// body. The host checks it again and decides.
func vmRewrapAnswer(raw json.RawMessage) ([]byte, error) {
	var a struct {
		Schema      *string `json:"schema"`
		OfferSHA256 *string `json:"offer_sha256"`
		Epk         *string `json:"epk"`
		Nonce       *string `json:"nonce"`
		Ct          *string `json:"ct"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if len(bytes.TrimSpace(raw)) == 0 || raw[0] != '{' || dec.Decode(&a) != nil || dec.More() {
		return nil, errors.New("answer must be one JSON object with only schema, offer_sha256, epk, nonce and ct")
	}
	if a.Schema == nil || a.OfferSHA256 == nil || a.Epk == nil || a.Nonce == nil || a.Ct == nil {
		return nil, errors.New("answer needs schema, offer_sha256, epk, nonce and ct")
	}
	if *a.Schema != vmRewrapSchema {
		return nil, errors.New("answer schema must be " + vmRewrapSchema)
	}
	if !vmBundleIDRE.MatchString(*a.OfferSHA256) { // 64 lowercase hex, as a bundle id
		return nil, errors.New("answer offer_sha256 is 64 lowercase hex: the sha256 of the offer body")
	}
	for _, f := range []struct {
		name, value string
		size        int
	}{{"epk", *a.Epk, 32}, {"nonce", *a.Nonce, 12}, {"ct", *a.Ct, 48}} {
		if b, err := base64.StdEncoding.Strict().DecodeString(f.value); err != nil || len(b) != f.size {
			return nil, fmt.Errorf("answer %s must be the padded base64 of %d bytes", f.name, f.size)
		}
	}
	out, err := json.Marshal(vmRewrapEnvelope{Ct: *a.Ct, Epk: *a.Epk, Nonce: *a.Nonce, OfferSHA256: *a.OfferSHA256, Schema: *a.Schema})
	if err != nil || len(out) > vmRewrapAnswerMax {
		return nil, fmt.Errorf("answer must be at most %d bytes", vmRewrapAnswerMax)
	}
	return out, nil
}
