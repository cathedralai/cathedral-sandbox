// Guest secrets through central booking (issue #304).
//
// A secret is a named value that the hotel egress proxy adds as a header to
// plain HTTP requests from a room to one allowed host. The room never holds
// the value. The broker keeps no value: it sends a put or a delete to every
// hotel the guest may use and answers with the state on each hotel. No
// broker answer carries a value. The broker logs no request data.
//
// The broker sends the guest id to the hotel in the X-Cathedral-Guest header
// and copies no guest header, so a guest cannot read, list or delete the
// secrets of another guest. The hotel answers 404 for those.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var secretNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// secretFanout runs one call on every hotel the guest may use and returns
// the status of each hotel (0: the hotel did not answer).
func (b *broker) secretFanout(ctx context.Context, g *guestState, method, path string, body []byte) (map[string]int, map[string][]byte) {
	statuses := map[string]int{}
	bodies := map[string][]byte{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range b.hotelList() {
		if !g.limitsAllow(b, h.cfg.ID) {
			continue
		}
		wg.Add(1)
		go func(h *hotel) {
			defer wg.Done()
			status, _, out, err := h.doGuest(ctx, g, method, path, nil, body, 30*time.Second)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				statuses[h.cfg.ID] = 0
				return
			}
			statuses[h.cfg.ID] = status
			bodies[h.cfg.ID] = out
		}(h)
	}
	wg.Wait()
	return statuses, bodies
}

// secretState names the result on one hotel. It never echoes a hotel body,
// so no part of a request reaches the answer.
func secretState(status int) string {
	switch {
	case status == 200 || status == 204:
		return "done"
	case status == 404:
		return "not_found"
	case status == 501:
		return "no_secrets"
	case status == 0:
		return "unreachable"
	case status >= 400 && status < 500:
		return "refused"
	}
	return "failed"
}

// /v1/secrets and /v1/secrets/<NAME>.
func (b *broker) handleSecrets(w http.ResponseWriter, r *http.Request, g *guestState, name string) {
	if name == "" {
		if r.Method != "GET" {
			writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+r.URL.Path)
			return
		}
		b.listSecrets(w, r, g)
		return
	}
	if !secretNameRe.MatchString(name) {
		writeErr(w, 400, "invalid_secret_name", "secret name must be 1 to 64 characters: A-Z, 0-9 and '_', starting with a letter")
		return
	}
	path := "/v1/secrets/" + url.PathEscape(name)
	switch r.Method {
	case "PUT":
		raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		var doc struct {
			Value *string `json:"value"`
		}
		if err != nil || json.Unmarshal(raw, &doc) != nil || doc.Value == nil {
			writeErr(w, 400, "invalid_secret_value", "body must be JSON {\"value\": \"...\"}")
			return
		}
		body, _ := json.Marshal(map[string]string{"value": *doc.Value})
		statuses, _ := b.secretFanout(r.Context(), g, "PUT", path, body)
		b.secretAnswer(w, name, statuses, 200)
	case "DELETE":
		statuses, _ := b.secretFanout(r.Context(), g, "DELETE", path, nil)
		b.secretAnswer(w, name, statuses, 204)
	default:
		writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+r.URL.Path)
	}
}

func (b *broker) secretAnswer(w http.ResponseWriter, name string, statuses map[string]int, okStatus int) {
	hotels := map[string]string{}
	done, notFound, refused, bad := 0, 0, 0, 0
	for id, s := range statuses {
		st := secretState(s)
		hotels[id] = st
		switch st {
		case "done":
			done++
		case "not_found", "no_secrets":
			notFound++
		case "refused":
			refused++
		default:
			bad++ // unreachable or failed
		}
	}
	switch {
	// DELETE must not return 204 when any hotel failed: the guest would think
	// every hotel cleared the secret (Bugbot P1).
	case done > 0 && okStatus == 204 && bad == 0:
		w.WriteHeader(204)
	case done > 0 && bad > 0 && okStatus == 204:
		writeJSON(w, 502, map[string]any{
			"error":  map[string]string{"code": "secrets_partial", "message": "some hotels did not delete the secret"},
			"hotels": hotels,
		})
	case done > 0:
		writeJSON(w, 200, map[string]any{"name": name, "hotels": hotels})
	case notFound > 0:
		writeJSON(w, 404, map[string]any{"error": map[string]string{"code": "secret_not_found", "message": "no secret " + name}, "hotels": hotels})
	case refused > 0:
		writeJSON(w, 400, map[string]any{"error": map[string]string{"code": "invalid_secret_value", "message": "the hotels refused the secret"}, "hotels": hotels})
	default:
		writeJSON(w, 502, map[string]any{"error": map[string]string{"code": "secrets_unavailable", "message": "no hotel stored the secret"}, "hotels": hotels})
	}
}

func (b *broker) listSecrets(w http.ResponseWriter, r *http.Request, g *guestState) {
	statuses, bodies := b.secretFanout(r.Context(), g, "GET", "/v1/secrets", nil)
	on := map[string][]string{}
	errs := map[string]string{}
	for id, s := range statuses {
		if s == 501 {
			continue
		}
		var doc struct {
			Secrets []struct {
				Name string `json:"name"`
			} `json:"secrets"`
		}
		if s != 200 || json.Unmarshal(bodies[id], &doc) != nil {
			errs[id] = "unavailable"
			continue
		}
		for _, sec := range doc.Secrets {
			if secretNameRe.MatchString(sec.Name) {
				on[sec.Name] = append(on[sec.Name], id)
			}
		}
	}
	out := []map[string]any{}
	for name, ids := range on {
		sort.Strings(ids)
		out = append(out, map[string]any{"name": name, "hotels": ids})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
	writeJSON(w, 200, map[string]any{"secrets": out, "hotel_errors": errs})
}

func secretRoute(p string) (string, bool) {
	if p == "/v1/secrets" {
		return "", true
	}
	if rest, ok := strings.CutPrefix(p, "/v1/secrets/"); ok && rest != "" && !strings.Contains(rest, "/") {
		return rest, true
	}
	return "", false
}
