package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

const releaseChallengeMax = 2048
const releaseProofAnswerMax = 8192

// handleRoomReleaseProof runs after handleRoom's guest/room ownership check.
// The body is only the RS challenge. The local room comes solely from the
// owned URL, so no body field can point the proof request at another room.
// Guest checks/signs; RS authenticates the challenge and verifies the proof.
func (b *broker) handleRoomReleaseProof(w http.ResponseWriter, r *http.Request, g *guestState, h *hotel, room, tail string) {
	if tail != "release-proof" || r.URL.RawQuery != "" || !g.limitsAllow(b, h.cfg.ID) {
		writeErr(w, 404, "route_not_found", "no such proof route")
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		writeErr(w, 405, "method_not_allowed", "proof requires POST")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, releaseChallengeMax))
	if err != nil {
		writeErr(w, 413, "body_too_large", "proof challenge is too large")
		return
	}
	raw := bytes.TrimSpace(body)
	if len(raw) == 0 || raw[0] != '{' || !json.Valid(raw) {
		writeErr(w, 400, "release_proof_request_invalid", "proof challenge must be a JSON object")
		return
	}
	wrapped, err := json.Marshal(struct {
		Room      string          `json:"sandbox_id"`
		Challenge json.RawMessage `json:"challenge"`
	}{room, raw})
	if err != nil {
		writeErr(w, 400, "release_proof_request_invalid", "invalid proof challenge")
		return
	}
	// Uses the existing hotel credential, miner attested-TLS gate and context.
	// One call, bounded body and deadline, no replay after an uncertain result.
	status, hdr, out, release, err := h.doHeadersMax(
		r.Context(), h.cfg.Health, "POST", "/room/release-proof", nil, wrapped,
		10*time.Second, http.Header{guestHeader: {g.cfg.ID}},
		answerRead{maxBytes: releaseProofAnswerMax, noRedirect: true},
	)
	defer release()
	if err != nil {
		writeErr(w, 502, "release_proof_unconfirmed", "guest proof could not be read")
		return
	}
	if ct := hdr.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(status)
	_, _ = w.Write(out)
}
