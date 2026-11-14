// Share links for the live view (AB#584). No live view is public. A guest
// mints a short-lived, revocable, read-only link to its own live view for one
// run and hands it to the people it wants to drop in. The long-lived view
// token never leaves the guest.
//
// The broker keeps only sha256 of each share token, in memory. A broker
// restart ends every link, which fails closed.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	liveShareDefaultTTL = 4 * time.Hour
	liveShareMinTTL     = time.Minute
	liveShareMaxTTL     = 7 * 24 * time.Hour
	liveShareMaxActive  = 50 // unexpired links per guest
	liveShareLabelMax   = 80
	liveShareTokenPfx   = "bvs_"
	liveShareCookiePfx  = "bvs_" // bvs_<guest>; the view-token cookie is bv_<guest>
)

type liveShare struct {
	ID      string
	Guest   string
	Label   string
	Created time.Time
	Expires time.Time
}

func (s *liveShare) doc() map[string]any {
	return map[string]any{"id": s.ID, "label": s.Label, "created_at": s.Created.UTC().Format(time.RFC3339), "expires_at": s.Expires.UTC().Format(time.RFC3339)}
}

// pruneSharesLocked drops expired links. Caller holds b.mu.
func (b *broker) pruneSharesLocked(now time.Time) {
	for k, s := range b.shares {
		if !now.Before(s.Expires) {
			delete(b.shares, k)
		}
	}
}

// shareFor returns the live link with this token hash if it is unexpired and
// belongs to guestID. It takes b.mu, so it must not be called under it.
func (b *broker) shareFor(hash, guestID string) *liveShare {
	if hash == "" {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.shares[hash]
	if s == nil {
		return nil
	}
	if !time.Now().Before(s.Expires) {
		delete(b.shares, hash)
		return nil
	}
	if s.Guest != guestID { // a link for one guest never opens another
		return nil
	}
	cp := *s
	return &cp
}

// handleLiveShares serves POST and GET /v1/live/shares and DELETE /v1/live/shares/<id>.
func (b *broker) handleLiveShares(w http.ResponseWriter, r *http.Request, g *guestState, id string) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case id == "" && r.Method == "POST":
		b.mintShare(w, r, g)
	case id == "" && r.Method == "GET":
		b.mu.Lock()
		b.pruneSharesLocked(time.Now())
		list := []*liveShare{}
		for _, s := range b.shares {
			if s.Guest == g.cfg.ID {
				list = append(list, s)
			}
		}
		b.mu.Unlock()
		sort.Slice(list, func(i, j int) bool { return list[i].Created.Before(list[j].Created) })
		docs := make([]map[string]any, 0, len(list))
		for _, s := range list {
			docs = append(docs, s.doc())
		}
		writeJSON(w, 200, map[string]any{"shares": docs})
	case id != "" && !strings.Contains(id, "/") && r.Method == "DELETE":
		b.mu.Lock()
		found := false
		for k, s := range b.shares {
			if s.ID == id && s.Guest == g.cfg.ID {
				delete(b.shares, k)
				found = true
				break
			}
		}
		b.mu.Unlock()
		if !found {
			writeErr(w, 404, "not_found", "no live share link with that id")
			return
		}
		w.WriteHeader(204)
	default:
		writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+r.URL.Path)
	}
}

func (b *broker) mintShare(w http.ResponseWriter, r *http.Request, g *guestState) {
	var req struct {
		TTLS  *int   `json:"ttl_s"`
		Label string `json:"label"`
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		writeErr(w, 400, "bad_request", "could not read the body")
		return
	}
	if len(strings.TrimSpace(string(raw))) > 0 {
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeErr(w, 400, "bad_request", "body must be JSON {ttl_s, label}")
			return
		}
	}
	ttl := liveShareDefaultTTL
	if req.TTLS != nil {
		ttl = time.Duration(*req.TTLS) * time.Second
		if *req.TTLS < int(liveShareMinTTL/time.Second) || *req.TTLS > int(liveShareMaxTTL/time.Second) {
			writeErr(w, 400, "bad_request", "ttl_s must be from 60 to 604800 seconds")
			return
		}
	}
	label := strings.TrimSpace(req.Label)
	if len(label) > liveShareLabelMax || strings.ContainsAny(label, "\r\n") {
		writeErr(w, 400, "bad_request", "label must be one line of at most 80 bytes")
		return
	}
	var tb [32]byte
	if _, err := rand.Read(tb[:]); err != nil {
		writeErr(w, 500, "internal", "could not make a token")
		return
	}
	token := liveShareTokenPfx + hex.EncodeToString(tb[:])
	now := time.Now()
	s := &liveShare{ID: newID("lsh_"), Guest: g.cfg.ID, Label: label, Created: now, Expires: now.Add(ttl)}
	b.mu.Lock()
	if b.shares == nil {
		b.shares = map[string]*liveShare{}
	}
	b.pruneSharesLocked(now)
	active := 0
	for _, o := range b.shares {
		if o.Guest == g.cfg.ID {
			active++
		}
	}
	if active >= liveShareMaxActive {
		b.mu.Unlock()
		writeErr(w, 429, "too_many_shares", "this guest has 50 live share links; revoke one first")
		return
	}
	b.shares[sha(token)] = s
	b.mu.Unlock()
	doc := s.doc()
	// Relative: the broker does not know the public host name it is served under.
	doc["url"] = "/" + url.PathEscape(g.cfg.ID) + "/live?share=" + token
	writeJSON(w, 201, doc)
}

// setShareCookie keeps the share token for this guest path until the link expires.
func (b *broker) setShareCookie(w http.ResponseWriter, guestID, token string, expires time.Time) {
	age := int(math.Ceil(time.Until(expires).Seconds()))
	if age < 1 {
		age = 1 // MaxAge 0 would make a session cookie; the server rechecks every request anyway
	}
	http.SetCookie(w, &http.Cookie{Name: liveShareCookiePfx + guestID, Value: token, Path: "/" + guestID + "/", MaxAge: age,
		HttpOnly: true, Secure: !b.cfg.InsecureCookie, SameSite: http.SameSiteLaxMode})
}
