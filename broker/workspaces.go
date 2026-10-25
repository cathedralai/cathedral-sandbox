// Persistent workspaces through central booking (issue #305).
//
// A workspace lives on one hotel. The broker gives it the id
// "<hotel>.<name>", like a snapshot. A bare name works when one hotel has it.
// The broker sends the guest id to the hotel in the X-Cathedral-Guest header
// on every workspace call. The broker builds each hotel request itself and
// copies no guest header, so a guest cannot set that header. The hotel keeps
// guests apart by that id: a workspace of another guest answers 404
// workspace_not_found, the same as a workspace that does not exist.
//
// A create with "workspace" goes to the hotel that holds the workspace, like
// a fork goes to the hotel of its snapshot.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// workspaceName reads the name of the "workspace" field of a create: a name
// or {"name": ...}.
func workspaceName(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case map[string]any:
		s, ok := x["name"].(string)
		return s, ok
	}
	return "", false
}

// setWorkspaceName puts the hotel name back into the "workspace" field.
func setWorkspaceName(payload map[string]any, name string) {
	if m, ok := payload["workspace"].(map[string]any); ok {
		m["name"] = name
		return
	}
	payload["workspace"] = name
}

// findWorkspace finds the hotel and hotel name of a guest workspace. ref is
// "<hotel>.<name>" or a bare name. Only hotels the guest may use count.
func (b *broker) findWorkspace(ctx context.Context, g *guestState, ref string) (*hotel, string, *apiErr) {
	notFound := &apiErr{404, "workspace_not_found", "no workspace " + ref}
	probe := func(h *hotel, name string) (bool, error) {
		status, _, _, err := h.doGuest(ctx, g, "GET", "/v1/workspaces/"+url.PathEscape(name), nil, nil, 30*time.Second)
		if err != nil {
			return false, err
		}
		switch status {
		case 200:
			return true, nil
		case 404, 400, 501, 503:
			return false, nil
		}
		return false, fmt.Errorf("HTTP %d", status)
	}
	if hotelID, name, ok := strings.Cut(ref, "."); ok {
		h := b.hotelByID(hotelID)
		if h == nil || !g.limitsAllow(b, hotelID) {
			return nil, "", notFound
		}
		found, err := probe(h, name)
		if err != nil {
			return nil, "", &apiErr{502, "hotel_unreachable", "hotel " + h.cfg.ID + " did not answer"}
		}
		if !found {
			return nil, "", notFound
		}
		return h, name, nil
	}
	var mu sync.Mutex
	var hits []*hotel
	var wg sync.WaitGroup
	for _, h := range b.hotelList() {
		if !g.limitsAllow(b, h.cfg.ID) {
			continue
		}
		wg.Add(1)
		go func(h *hotel) {
			defer wg.Done()
			if found, _ := probe(h, ref); found {
				mu.Lock()
				hits = append(hits, h)
				mu.Unlock()
			}
		}(h)
	}
	wg.Wait()
	switch len(hits) {
	case 1:
		return hits[0], ref, nil
	case 0:
		return nil, "", notFound
	default:
		return nil, "", &apiErr{409, "workspace_ambiguous", "several hotels have a workspace " + ref + "; use the id <hotel>.<name>"}
	}
}

// workspacePlacement sends a create with "workspace" to the hotel that holds
// it. It runs after the snapshot placement, so a fork and a workspace on two
// hotels conflict.
func (b *broker) workspacePlacement(ctx context.Context, g *guestState, payload map[string]any, pl placement) (placement, *apiErr) {
	raw, ok := payload["workspace"]
	if !ok || raw == nil {
		return pl, nil
	}
	ref, ok := workspaceName(raw)
	if !ok || ref == "" {
		return pl, &apiErr{400, "invalid_workspace", "workspace must be a name or an object with a name"}
	}
	h, name, e := b.findWorkspace(ctx, g, ref)
	if e != nil {
		return pl, e
	}
	if pl.only != nil && pl.only != h {
		return pl, &apiErr{409, "workspace_snapshot_conflict", "the snapshot and the workspace are on different hotels"}
	}
	// Like a fork: the guest's sealed default does not stop a room next to
	// a workspace on an unsealed hotel.
	if pl.sealedByDefault && h.cfg.Labels["sealed"] != "true" {
		delete(pl.match, "sealed")
		pl.sealedByDefault = false
	}
	if !pl.selects(h) {
		return pl, &apiErr{409, "workspace_hotel_excluded", "the hotel that holds this workspace does not match the hotel selection"}
	}
	pl.only, pl.hotelWorkspace = h, name
	return pl, nil
}

func workspaceDoc(h *hotel, doc map[string]any) {
	if name, ok := doc["name"].(string); ok {
		doc["id"] = h.cfg.ID + "." + name
		doc["hotel"] = h.cfg.ID
	}
}

// GET and POST /v1/workspaces.
func (b *broker) handleWorkspaces(w http.ResponseWriter, r *http.Request, g *guestState) {
	if r.Method == "GET" {
		b.listWorkspaces(w, r, g)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, 400, "bad_body", "cannot read body")
		return
	}
	payload := map[string]any{}
	if len(raw) > 0 && json.Unmarshal(raw, &payload) != nil {
		writeErr(w, 400, "invalid_json", "request body is not JSON")
		return
	}
	name, _ := payload["name"].(string)
	if name == "" || strings.Contains(name, ".") {
		writeErr(w, 400, "invalid_workspace_name", "workspace name must be 1 to 63 characters: a-z, 0-9, '-' and '_'")
		return
	}
	pl, e := b.parseSelection(g, payload)
	if e != nil {
		writeErr(w, e.status, e.code, e.msg)
		return
	}
	// One name for each guest across the chain, so a bare name finds one hotel.
	if _, _, e := b.findWorkspace(r.Context(), g, name); e == nil {
		writeErr(w, 409, "workspace_exists", "workspace "+name+" exists")
		return
	}
	b.mu.Lock()
	h := b.pick(nil, pl)
	b.mu.Unlock()
	if h == nil {
		writeErr(w, 503, "no_hotel_available", "no hotel in the selection takes new rooms now; retry later")
		return
	}
	body, _ := json.Marshal(map[string]any{"name": name})
	status, _, out, err := h.doGuest(r.Context(), g, "POST", "/v1/workspaces", nil, body, time.Minute)
	if err != nil {
		writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
		return
	}
	writeWorkspace(w, h, status, out)
}

func (b *broker) listWorkspaces(w http.ResponseWriter, r *http.Request, g *guestState) {
	all := []map[string]any{}
	errs := map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, h := range b.hotelList() {
		if !g.limitsAllow(b, h.cfg.ID) {
			continue
		}
		wg.Add(1)
		go func(h *hotel) {
			defer wg.Done()
			status, _, out, err := h.doGuest(r.Context(), g, "GET", "/v1/workspaces", nil, nil, 30*time.Second)
			var doc struct {
				Workspaces []map[string]any `json:"workspaces"`
			}
			mu.Lock()
			defer mu.Unlock()
			if status == 501 {
				return // this hotel has no workspaces
			}
			if err != nil || status != 200 || json.Unmarshal(out, &doc) != nil {
				errs[h.cfg.ID] = "unavailable"
				return
			}
			for _, d := range doc.Workspaces {
				workspaceDoc(h, d)
				all = append(all, d)
			}
		}(h)
	}
	wg.Wait()
	sort.Slice(all, func(i, j int) bool { return fmt.Sprint(all[i]["id"]) < fmt.Sprint(all[j]["id"]) })
	writeJSON(w, 200, map[string]any{"workspaces": all, "count": len(all), "hotel_errors": errs})
}

// /v1/workspaces/<ref>[/versions|/rollback] go to the hotel that holds it.
func (b *broker) handleWorkspace(w http.ResponseWriter, r *http.Request, g *guestState, rest string) {
	ref, tail, _ := strings.Cut(rest, "/")
	ok := ref != "" && ((tail == "" && (r.Method == "GET" || r.Method == "DELETE")) ||
		(tail == "versions" && (r.Method == "GET" || r.Method == "POST")) ||
		(tail == "rollback" && r.Method == "POST"))
	if !ok {
		writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+r.URL.Path)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	h, name, e := b.findWorkspace(r.Context(), g, ref)
	if e != nil {
		writeErr(w, e.status, e.code, e.msg)
		return
	}
	path := "/v1/workspaces/" + url.PathEscape(name)
	if tail != "" {
		path += "/" + tail
	}
	var arg []byte
	if r.Method == "POST" {
		arg = body
		if len(arg) == 0 {
			arg = []byte("{}")
		}
	}
	status, _, out, err := h.doGuest(r.Context(), g, r.Method, path, nil, arg, 30*time.Minute)
	if err != nil {
		writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
		return
	}
	if status == 204 {
		w.WriteHeader(204)
		return
	}
	writeWorkspace(w, h, status, out)
}

func writeWorkspace(w http.ResponseWriter, h *hotel, status int, out []byte) {
	var doc map[string]any
	if json.Unmarshal(out, &doc) == nil && doc["error"] == nil {
		workspaceDoc(h, doc)
		writeJSON(w, status, doc)
		return
	}
	writeRaw(w, status, out)
}
