// Catalog templates for self-serve sandbox create.
//
// GET /v1/sandboxes/catalog lists these. POST /v1/sandboxes with
// "template": "<name>" maps to the template's image and size, the same
// path Harbor and ctcli already use for room-1x4 / room-2x8 / room-4x16.
//
// LFM3 names and images match cathedralai/cathedral sandbox_models/catalog.py.
// Only live templates create a room. Sealed LFM3 is pending: the image is
// not available on sealed hotels yet, so a sealed create is refused and a
// standard create is kept off sealed hotels.
package main

import (
	"fmt"
	"regexp"
	"strings"
)

// sealedOffer is whether a template may run on a sealed hotel.
type sealedOffer string

const (
	sealedReady   sealedOffer = "ready"
	sealedPending sealedOffer = "pending"
)

// catalogTemplate is one self-serve offer. Name is the create "template" field.
type catalogTemplate struct {
	Name        string
	DisplayName string
	Description string
	CPU         int
	MemoryGiB   int
	DiskGiB     int
	Rate        string
	// Image is the hotel create image. Live model templates are pinned by
	// digest (repository@sha256:hex) when the published digest is known.
	// Until then they use the published tag hotels already run.
	Image  string
	Live   bool        // standard create is open
	Sealed sealedOffer // sealed create: ready or pending
}

// LFM3-1.7B image. Tag matches cathedralai/cathedral LFM3_IMAGE_REF.
// Standard hotels already run this tag. Prefer repository@sha256:hex via
// pinnedImage once the published digest is recorded.
const (
	lfm31_7bRepo = "cathedral/lfm3-1.7b"
	lfm31_7bTag  = "q4_k_m"
)

var digestPin = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// catalogTemplates is the catalog in listing order. Room sizes stay first so
// existing Harbor clients keep seeing them at the front.
var catalogTemplates = []catalogTemplate{
	{
		Name: "room-1x4", DisplayName: "room-1x4",
		Description: "1 vCPU, 4 GiB room",
		CPU:         1, MemoryGiB: 4, DiskGiB: 10, Rate: "0.05",
		Image: "alpine:3.20", Live: true, Sealed: sealedReady,
	},
	{
		Name: "room-2x8", DisplayName: "room-2x8",
		Description: "2 vCPU, 8 GiB room",
		CPU:         2, MemoryGiB: 8, DiskGiB: 10, Rate: "0.10",
		Image: "alpine:3.20", Live: true, Sealed: sealedReady,
	},
	{
		Name: "room-4x16", DisplayName: "room-4x16",
		Description: "4 vCPU, 16 GiB room",
		CPU:         4, MemoryGiB: 16, DiskGiB: 10, Rate: "0.20",
		Image: "alpine:3.20", Live: true, Sealed: sealedReady,
	},
	{
		Name: "lfm3-1.7b", DisplayName: "LFM3 1.7B (CPU)",
		Description: "LFM3 1.73B on CPU via llama.cpp (LFM3-1.7B-Q4_K_M.gguf). Sandbox inputs: text. Sandbox outputs: text. GPU is not required.",
		CPU:         1, MemoryGiB: 4, DiskGiB: 10, Rate: "0.05",
		Image: lfm31_7bRepo + ":" + lfm31_7bTag, Live: true, Sealed: sealedPending,
	},
	{
		Name: "lfm3-1.7b-base", DisplayName: "LFM3 1.7B Base (CPU)",
		Description: "LFM3 1.73B on CPU via transformers (safetensors LiquidAI/LFM3-1.7B-Base). Image is not published yet.",
		CPU:         2, MemoryGiB: 8, DiskGiB: 16, Rate: "0.10",
		Image: "cathedral/lfm3-1.7b-base:bf16", Live: false, Sealed: sealedPending,
	},
	{
		Name: "lfm3-vl-2b", DisplayName: "LFM3 VL 2B (CPU)",
		Description: "LFM3 1.92B on CPU via llama.cpp. Sandbox inputs: text, image. Image is not published yet.",
		CPU:         2, MemoryGiB: 6, DiskGiB: 12, Rate: "0.10",
		Image: "cathedral/lfm3-vl-2b:q4_k_m", Live: false, Sealed: sealedPending,
	},
	{
		Name: "lfm3-audio-2b", DisplayName: "LFM3 Audio 2B (CPU)",
		Description: "LFM3 2B on CPU via llama.cpp. Sandbox inputs: text, audio. Image is not published yet.",
		CPU:         2, MemoryGiB: 6, DiskGiB: 12, Rate: "0.10",
		Image: "cathedral/lfm3-audio-2b:q4_k_m", Live: false, Sealed: sealedPending,
	},
	{
		Name: "lfm3-omni-2b", DisplayName: "LFM3 Omni 2B (CPU)",
		Description: "LFM3 2.17B on CPU via llama.cpp. Sandbox inputs: text, image, audio. Image is not published yet.",
		CPU:         2, MemoryGiB: 8, DiskGiB: 14, Rate: "0.10",
		Image: "cathedral/lfm3-omni-2b:q4_k_m", Live: false, Sealed: sealedPending,
	},
	{
		Name: "d1-2b", DisplayName: "d1 2B (CPU)",
		Description: "d1 1.92B on CPU via transformers. Sandbox outputs: decision. Image is not published yet.",
		CPU:         2, MemoryGiB: 12, DiskGiB: 16, Rate: "0.10",
		Image: "cathedral/d1-2b:bf16", Live: false, Sealed: sealedPending,
	},
	{
		Name: "d1-omni-2b", DisplayName: "d1 Omni 2B (CPU)",
		Description: "d1 2.17B on CPU via transformers. Sandbox outputs: decision. Image is not published yet.",
		CPU:         2, MemoryGiB: 14, DiskGiB: 18, Rate: "0.10",
		Image: "cathedral/d1-omni-2b:bf16", Live: false, Sealed: sealedPending,
	},
}

// pinnedImage is repository@sha256:hex. The hotel image grammar is a tag or a
// digest, not both. Live model templates should use this once the published
// digest is known.
func pinnedImage(repo, digest string) string {
	if !digestPin.MatchString(digest) {
		panic("catalog image digest must be sha256: and 64 lowercase hex digits")
	}
	if repo == "" || strings.ContainsAny(repo, "@:") {
		panic("catalog image repository must be a name without a tag or digest")
	}
	return repo + "@" + digest
}

func templateByName(name string) (catalogTemplate, bool) {
	for _, t := range catalogTemplates {
		if t.Name == name {
			return t, true
		}
	}
	return catalogTemplate{}, false
}

func (t catalogTemplate) catalogView() map[string]any {
	return map[string]any{
		"name":            t.Name,
		"display_name":    t.DisplayName,
		"description":     t.Description,
		"image":           t.Image,
		"resources":       map[string]any{"cpu": t.CPU, "memory_gib": t.MemoryGiB},
		"disk_gib":        t.DiskGiB,
		"hourly_rate_usd": t.Rate,
		"network_modes":   []string{"internet", "deny_all", "allowlist"},
		"egress_allow":    []string{},
		"live":            t.Live,
		"sealed":          string(t.Sealed),
	}
}

func catalogTemplateViews() []any {
	out := make([]any, 0, len(catalogTemplates))
	for _, t := range catalogTemplates {
		out = append(out, t.catalogView())
	}
	return out
}

func (t catalogTemplate) resources() map[string]any {
	return map[string]any{"vcpu": t.CPU, "memory_gib": t.MemoryGiB, "disk_gib": t.DiskGiB}
}

// templateCreateErr is the refusal for a template create, or nil when it may run.
func templateCreateErr(t catalogTemplate, sealedAsked bool) *apiErr {
	if !t.Live {
		return &apiErr{503, "template_unavailable",
			"template " + t.Name + " is not published for self-serve create yet"}
	}
	if sealedAsked {
		switch t.Sealed {
		case sealedReady:
		case sealedPending:
			return &apiErr{503, "template_sealed_pending",
				"sealed create for " + t.Name + " is pending; the image is not available on sealed hotels yet. Create without sealed, or with \"sealed\": false, for the standard path"}
		default:
			return &apiErr{503, "template_unavailable",
				"template " + t.Name + " has no sealed offer"}
		}
	}
	return nil
}

// applyCatalogTemplate turns a create body that names a catalog template into
// an image create at that template's size. Image and image_id already in the
// body win, as on the existing Harbor path. A live template whose sealed
// offer is pending is kept on unsealed hotels (sealed: false).
func applyCatalogTemplate(req map[string]any) *apiErr {
	if id, _ := req["image_id"].(string); id != "" {
		return nil
	}
	if ref, _ := req["image"].(string); ref != "" {
		return nil
	}
	name, _ := req["template"].(string)
	if name == "" {
		return nil
	}
	t, ok := templateByName(name)
	if !ok {
		return &apiErr{404, "template_not_found", "no template " + name + "; see /v1/sandboxes/catalog"}
	}
	sealed, sealedField := req["sealed"].(bool)
	if e := templateCreateErr(t, sealedField && sealed); e != nil {
		return e
	}
	req["image"] = t.Image
	if req["resources"] == nil {
		req["resources"] = t.resources()
	}
	if t.Sealed == sealedPending && !(sealedField && sealed) {
		req["sealed"] = false
	}
	delete(req, "template")
	return nil
}

func (t catalogTemplate) String() string {
	return fmt.Sprintf("%s image=%s live=%v sealed=%s", t.Name, t.Image, t.Live, t.Sealed)
}
