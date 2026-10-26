// Image build for the published clients (#290). Harbor sends a Dockerfile and
// a build context to POST /v1/images/build and polls GET /v1/images/<id>.
//
// The broker keeps the Dockerfile and the context and asks every hotel that
// takes new rooms to build them (POST /v1/images/build on the hotel). The
// hotel tags the image by a hash of the content, so the tag is the same on
// every hotel. The image is ready when one hotel has it. A create with the
// image goes only to hotels that have it.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const buildContextMaxBytes = 256 << 20

type buildHotel struct {
	State string `json:"state"` // building, ready, failed
	Tag   string `json:"tag,omitempty"`
	Err   string `json:"error,omitempty"`
}

func (b *broker) compatBuild(w http.ResponseWriter, r *http.Request, g *guestState) {
	r.Body = http.MaxBytesReader(w, r.Body, buildContextMaxBytes+(1<<20))
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		compatErr(w, 400, "invalid_build", "the build needs a multipart form with a dockerfile and a context: "+err.Error(), 0)
		return
	}
	dockerfile := r.FormValue("dockerfile")
	if strings.TrimSpace(dockerfile) == "" {
		compatErr(w, 400, "invalid_build", "dockerfile is required", 0)
		return
	}
	var buildCtx []byte
	if f, _, err := r.FormFile("context"); err == nil {
		buildCtx, err = io.ReadAll(io.LimitReader(f, buildContextMaxBytes+1))
		f.Close()
		if err != nil || len(buildCtx) > buildContextMaxBytes {
			compatErr(w, 413, "build_context_too_large", "the build context is larger than 256 MiB", 0)
			return
		}
	}
	num := func(k string, d float64) float64 {
		if v, err := strconv.ParseFloat(r.FormValue(k), 64); err == nil && v > 0 {
			return v
		}
		return d
	}
	img := &compatImage{CPU: num("cpu", 1), MemoryGiB: num("memory_gib", 4), DiskGiB: num("minimum_free_disk_gib", 10),
		Build: true, Dockerfile: dockerfile, buildCtx: buildCtx, builds: map[string]*buildHotel{}}
	ctxSum := sha256.Sum256(buildCtx)
	sum := sha256.Sum256([]byte(fmt.Sprintf("build|%s|%s|%x|%v|%v|%v", g.cfg.ID, dockerfile, ctxSum, img.CPU, img.MemoryGiB, img.DiskGiB)))
	h := hex.EncodeToString(sum[:16])
	img.ID = h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	b.compat.mu.Lock()
	if old := b.compat.images[img.ID]; old != nil && old.Build {
		img = old // the same build again: keep its state
		if img.ctxMissing || !bytes.Equal(img.buildCtx, buildCtx) {
			// The context was lost or cut short (a crash while it was saved).
			// The id is a hash of the context, so this request's copy is right.
			img.buildCtx, img.ctxMissing = buildCtx, false
			// New entries: a build in flight used the old context, and its
			// result is dropped when it returns (buildOn checks its entry).
			img.builds = map[string]*buildHotel{}
			b.saveBuildContext(img)
		}
	} else {
		b.compat.images[img.ID] = img
		b.saveBuildContext(img)
	}
	b.compat.mu.Unlock()
	b.markDirty()
	b.ensureBuilds(img, g)
	writeJSON(w, 200, b.imageView(img, g))
}

// ensureBuilds starts a build on each hotel that takes new rooms and has no
// build state for img yet. A failed hotel is tried again after a minute.
func (b *broker) ensureBuilds(img *compatImage, g *guestState) {
	b.mu.Lock()
	var hotels []*hotel
	for _, h := range b.hotelList() {
		if !h.drain() && g.allowsHotel(h) {
			hotels = append(hotels, h)
		}
	}
	b.mu.Unlock()
	b.compat.mu.Lock()
	defer b.compat.mu.Unlock()
	if img.builds == nil {
		img.builds = map[string]*buildHotel{}
	}
	if img.ctxMissing {
		return
	}
	for _, h := range hotels {
		st := img.builds[h.cfg.ID]
		if st != nil && (st.State != "failed" || time.Since(img.failedAt[h.cfg.ID]) < time.Minute) {
			continue
		}
		entry := &buildHotel{State: "building"}
		img.builds[h.cfg.ID] = entry
		go b.buildOn(h, img, entry)
	}
}

// buildOn runs one build on h and records the result in st, the entry it was
// started for. A newer entry means a newer build replaced this one: its
// result is stale and is dropped.
func (b *broker) buildOn(h *hotel, img *compatImage, st *buildHotel) {
	b.compat.mu.Lock()
	payload := map[string]any{"dockerfile": img.Dockerfile}
	if len(img.buildCtx) > 0 {
		payload["context_tar_b64"] = base64.StdEncoding.EncodeToString(img.buildCtx)
	}
	b.compat.mu.Unlock()
	body, _ := json.Marshal(payload)
	status, _, out, err := h.do(context.Background(), "POST", "/v1/images/build", nil, body, 30*time.Minute)
	var doc map[string]any
	_ = json.Unmarshal(out, &doc)
	b.compat.mu.Lock()
	defer b.compat.mu.Unlock()
	if img.builds[h.cfg.ID] != st {
		return
	}
	tag, _ := doc["image"].(string)
	switch {
	case err != nil:
		st.State, st.Err = "failed", "hotel "+h.cfg.ID+" did not answer"
	case status == 200 && tag != "":
		st.State, st.Tag = "ready", tag
	default:
		st.State, st.Err = "failed", fmt.Sprintf("hotel answered %d", status)
		if e, ok := doc["error"].(map[string]any); ok {
			st.Err = fmt.Sprint(e["code"], ": ", e["message"])
		}
	}
	if st.State == "failed" {
		if img.failedAt == nil {
			img.failedAt = map[string]time.Time{}
		}
		img.failedAt[h.cfg.ID] = time.Now()
	}
}

// builtOn returns the hotels that have the image and its tag. Caller holds b.compat.mu.
func (img *compatImage) builtOn() (map[string]bool, string) {
	ids, tag := map[string]bool{}, ""
	for id, st := range img.builds {
		if st.State == "ready" {
			ids[id], tag = true, st.Tag
		}
	}
	return ids, tag
}

// imageView is the client view of an image.
// A built image is ready for g when a hotel that g's plain create may use
// (its hotel set and sealed default) holds it.
func (b *broker) imageView(img *compatImage, g *guestState) map[string]any {
	var pl placement
	b.scope(g, &pl, false, false)
	b.compat.mu.Lock()
	defer b.compat.mu.Unlock()
	if !img.Build {
		return map[string]any{"image_id": img.ID, "state": "ready", "image": img.Ref}
	}
	ids, tag := img.builtOn()
	for id := range ids {
		if h := b.hotelByID(id); h != nil && pl.selects(h) {
			return map[string]any{"image_id": img.ID, "state": "ready", "image": tag}
		}
	}
	if img.ctxMissing {
		return map[string]any{"image_id": img.ID, "state": "failed", "error": "image_build_failed",
			"message": "the build context was lost; submit the build again"}
	}
	building, firstErr := false, ""
	for _, st := range img.builds {
		if st.State == "building" {
			building = true
		} else if firstErr == "" {
			firstErr = st.Err
		}
	}
	if building || len(img.builds) == 0 {
		return map[string]any{"image_id": img.ID, "state": "pending"}
	}
	return map[string]any{"image_id": img.ID, "state": "failed", "error": "image_build_failed", "message": firstErr}
}
