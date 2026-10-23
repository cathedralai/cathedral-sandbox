// Capability probe: one sample room per hotel answers "what is a room?".
// POST /v1/broker/probe (guest key) starts one room per hotel, runs the checks,
// stores the results on the hotel (shown on the live view) and deletes the room.
// Add "dind": true to the JSON body to also try Docker inside a room.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type probeResult struct {
	Isolation   string  `json:"isolation"`    // e.g. "gVisor 4.19.0-gvisor"
	GuestKernel string  `json:"guest_kernel"` // uname -r inside the room
	Sealed      bool    `json:"sealed"`       // room memory encrypted by a TEE (SEV-SNP, TDX)
	SealedNote  string  `json:"sealed_note"`
	Internet    *bool   `json:"internet"`
	InternetMs  float64 `json:"internet_ms,omitempty"`
	Dind        string  `json:"dind"` // "yes", "not yet", "not tested"
	DindNote    string  `json:"dind_note,omitempty"`
	ProbedAt    string  `json:"probed_at"`
	Error       string  `json:"error,omitempty"`
}

func (b *broker) probeCreate(ctx context.Context, h *hotel, g *guestState, image string) (string, error) {
	body, _ := json.Marshal(map[string]any{"image": image, "ttl_seconds": 900,
		"resources": map[string]any{"vcpu": 1, "memory_gib": 4, "disk_gib": 10},
		"labels":    map[string]string{guestLabel: g.cfg.ID, "kind": "probe"}})
	status, _, out, err := h.do(ctx, "POST", "/v1/sandboxes", nil, body, 5*time.Minute)
	if err != nil {
		// The transport error names the hotel's private URL, and the result
		// goes to every live board: say only that the hotel did not answer.
		return "", fmt.Errorf("hotel %s did not answer", h.cfg.ID)
	}
	var doc map[string]any
	_ = json.Unmarshal(out, &doc)
	id, _ := doc["id"].(string)
	if (status != 202 && status != 200) || id == "" {
		return "", fmt.Errorf("create answered %d: %.200s", status, out)
	}
	return id, nil
}

func (b *broker) probeExec(ctx context.Context, h *hotel, id string, script string, timeout int) (map[string]any, error) {
	body, _ := json.Marshal(map[string]any{"cmd": []string{"sh", "-c", script}, "timeout_seconds": timeout})
	status, _, out, err := h.do(ctx, "POST", "/v1/sandboxes/"+url.PathEscape(id)+"/exec", nil, body, time.Duration(timeout+30)*time.Second)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	_ = json.Unmarshal(out, &doc)
	if status != 200 {
		return doc, fmt.Errorf("exec answered %d", status)
	}
	return doc, nil
}

func (b *broker) probeHotel(ctx context.Context, h *hotel, g *guestState, dind bool) probeResult {
	res := probeResult{Dind: "not tested", Sealed: false, ProbedAt: time.Now().UTC().Format(time.RFC3339),
		SealedNote: "rooms run on the host under gVisor, not inside an SEV-SNP or TDX guest"}
	id, err := b.probeCreate(ctx, h, g, "alpine:3.20")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer h.do(context.Background(), "DELETE", "/v1/sandboxes/"+url.PathEscape(id), nil, nil, 2*time.Minute)
	if doc, err := b.probeExec(ctx, h, id, "uname -r; dmesg 2>/dev/null | grep -c gVisor", 30); err == nil {
		lines := strings.Fields(fmt.Sprint(doc["stdout"]))
		if len(lines) > 0 {
			res.GuestKernel = lines[0]
		}
		if len(lines) > 1 && lines[1] != "0" && strings.Contains(res.GuestKernel, "gvisor") {
			res.Isolation = "gVisor " + res.GuestKernel
		} else {
			res.Isolation = "unproven"
		}
	}
	// busybox wget; duration_ms is measured by the hotel around the command.
	if doc, err := b.probeExec(ctx, h, id, "wget -q -T 10 -O /dev/null https://www.cloudflare.com/cdn-cgi/trace && echo egress-ok", 30); err == nil {
		ok := strings.Contains(fmt.Sprint(doc["stdout"]), "egress-ok")
		res.Internet = &ok
		if d, isNum := doc["duration_ms"].(float64); isNum && ok {
			res.InternetMs = d
		}
	}
	if dind {
		res.Dind, res.DindNote = b.probeDind(ctx, h, g)
	}
	if h.cfg.Sealed {
		res.Sealed, res.SealedNote = b.probeSealed(ctx, h)
	}
	return res
}

// probeSealed reads a sealed hotel's attestation. The broker does not check
// the AMD signature chain; a guest checks it offline with verify_receipts.py.
func (b *broker) probeSealed(ctx context.Context, h *hotel) (bool, string) {
	var att struct {
		Binding struct {
			Measurement string `json:"measurement"`
		} `json:"binding"`
		Report string `json:"report_b64"`
	}
	if err := h.getJSON(ctx, h.cfg.Health, "/room/attestation", nil, &att); err != nil || att.Report == "" || len(att.Binding.Measurement) != 96 {
		return false, "configured as sealed, but the hotel gives no SEV-SNP attestation"
	}
	return true, "rooms run under gVisor inside an AMD SEV-SNP guest (measurement " + att.Binding.Measurement[:16] +
		"...); report and receipts at /v1/hotels/" + h.cfg.ID + "/attestation, verify offline with verify_receipts.py"
}

func (b *broker) probeDind(ctx context.Context, h *hotel, g *guestState) (string, string) {
	id, err := b.probeCreate(ctx, h, g, "docker:28-dind")
	if err != nil {
		return "not yet", "Docker-in-Docker room did not start: " + err.Error()
	}
	defer h.do(context.Background(), "DELETE", "/v1/sandboxes/"+url.PathEscape(id), nil, nil, 2*time.Minute)
	doc, err := b.probeExec(ctx, h, id, "docker run --rm --network host alpine:3.20 echo dind-ok 2>&1 | tail -3", 240)
	if err == nil && strings.Contains(fmt.Sprint(doc["stdout"]), "dind-ok") {
		return "yes", "docker run inside the room works (host network for inner containers)"
	}
	return "not yet", fmt.Sprintf("inner docker run failed: %.200v", doc["stdout"])
}

func (b *broker) handleProbe(w http.ResponseWriter, r *http.Request, g *guestState) {
	var req struct {
		Dind bool `json:"dind"`
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<12))
	_ = json.Unmarshal(raw, &req)
	out := map[string]probeResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range b.hotelList() {
		// A hotel outside the guest's list may be dedicated to another
		// guest: the probe must not start a room there.
		if !g.limitsAllow(b, h.cfg.ID) {
			mu.Lock()
			out[h.cfg.ID] = probeResult{ProbedAt: time.Now().UTC().Format(time.RFC3339),
				Error: "skipped: hotel is not in this guest's hotel list"}
			mu.Unlock()
			continue
		}
		b.mu.Lock()
		resting := h.drain() || time.Now().Before(h.backoffUntil)
		b.mu.Unlock()
		if resting {
			// Drain means no new rooms here; a probe room would block the
			// hotel's removal and a kit update.
			mu.Lock()
			out[h.cfg.ID] = probeResult{ProbedAt: time.Now().UTC().Format(time.RFC3339),
				Error: "skipped: hotel is draining or resting"}
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(h *hotel) {
			defer wg.Done()
			res := b.probeHotel(r.Context(), h, g, req.Dind)
			mu.Lock()
			out[h.cfg.ID] = res
			mu.Unlock()
			raw, _ := json.Marshal(res)
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			b.mu.Lock()
			if !req.Dind && h.caps != nil { // keep an earlier Docker-inside answer
				m["dind"], m["dind_note"] = h.caps["dind"], h.caps["dind_note"]
			}
			h.caps = m
			b.mu.Unlock()
		}(h)
	}
	wg.Wait()
	b.saveCaps()
	writeJSON(w, 200, map[string]any{"hotels": out})
}

// saveCaps and loadCaps keep probe results in state_dir across restarts.
func (b *broker) saveCaps() {
	if b.cfg.StateDir == "" {
		return
	}
	b.mu.Lock()
	m := map[string]any{}
	for id, c := range b.capsOnDisk { // a hotel not loaded yet keeps its entry
		m[id] = c
	}
	for _, h := range b.hotelList() {
		if h.caps != nil {
			m[h.cfg.ID] = h.caps
		}
	}
	b.mu.Unlock()
	raw, _ := json.MarshalIndent(m, "", " ")
	_ = os.WriteFile(filepath.Join(b.cfg.StateDir, "caps.json"), raw, 0o640)
}

func (b *broker) loadCaps() {
	if b.cfg.StateDir == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(b.cfg.StateDir, "caps.json"))
	if err != nil {
		return
	}
	var m map[string]map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	b.mu.Lock()
	b.capsOnDisk = m // hotels added after this (runtime joins) take theirs in addHotel
	b.mu.Unlock()
	for id, c := range m {
		if h := b.hotelByID(id); h != nil {
			h.caps = c
		}
	}
}
