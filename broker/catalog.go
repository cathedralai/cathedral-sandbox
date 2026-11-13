// Catalog templates for self-serve sandbox create.
//
// GET /v1/sandboxes/catalog lists these. POST /v1/sandboxes with
// "template": "<name>" maps to the template's image and size, the same
// path Harbor and ctcli already use for room-1x4 / room-2x8 / room-4x16.
//
// LFM3 names and images match cathedralai/cathedral sandbox_models/catalog.py. Suite digests
// from cathedral-sandbox #361 (each proven sealed on prod at 2 vCPU / 4 GiB, 29 Oct 2026);
// All six are the main 3339b9f builds (publish run 43467170286, 13 Nov 2026): lfm3-agent
// --events streaming chat events (#440, ADO 541) and the static Go chat gateway (#478, ADO 539)
// on top of per-model sampling and the loop guard (#392, ADO 523), liquid --speak one sentence
// per /tts request (#407, ADO 552), the warm cache saved in the image (#403, #405), liquid
// --json for Audio (ADO 547) and --swa-full with sampled answers for Omni (ADO 549, 550).
// Each image must be prefetched on c46-sealed-2, nc-sealed-2 and nc-sealed-3 before this pin
// ships in a broker (ADO 732).
// A suite model is sealed ready only once its image is prefetched on every shared sealed hotel
// (all six: c46-sealed-2, nc-sealed-2, nc-sealed-3, 6 of 6 each, 29 Oct 2026 11:40Z).
// LFM templates are sealed-only (AMD SEV-SNP). A pending sealed offer refuses
// every create. There is no unsealed path and no Standard path.
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

	// Live sealed hotels are AMD SEV-SNP.
	sealedHardwareClass = "amd_sev_snp"
)

// catalogTemplate is one self-serve offer. Name is the create "template" field.
type catalogTemplate struct {
	Name        string
	DisplayName string
	Description string
	CPU         int
	MemoryGiB   int
	DiskGiB     int
	// Image is the hotel create image. Live model templates are pinned by
	// digest (repository@sha256:hex). Unpublished suite templates keep a
	// GHCR tag until those images exist.
	Image  string
	Live   bool        // listed and, for room sizes, creatable
	Sealed sealedOffer // sealed create: ready or pending
	// SealedOnly is true for LFM. Creates always go to the sealed pool.
	// If Sealed is not ready, every create is refused.
	SealedOnly bool
}

// LFM3-1.7B image. Same GHCR digest as cathedralai/cathedral PR #446
// (sandbox_models LFM3_IMAGE_REF). llama.cpp b11960, Q4_K_M GGUF.
const (
	lfm31_7bRepo   = "ghcr.io/cathedralai/room-lfm3-1.7b"
	lfm31_7bDigest = "sha256:b1ba8837ea388c8c98720772b0f41af5813d4cebf214637fde20aae58a1ea761"
)

var digestPin = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// catalogTemplates is the catalog in listing order. Room sizes stay first so
// existing Harbor clients keep seeing them at the front.
//
// Any change here also updates broker/catalog.digest (go run . -print-catalog-digest >
// catalog.digest); swaps refuse a binary whose catalog differs from it (AB#546).
//
// LFM rollout order (publish, then pin the digest, then flip Sealed to ready):
// 1.7B, VL, Omni, d1, Audio, d1-Omni, Base.
var catalogTemplates = []catalogTemplate{
	{
		Name: "room-1x4", DisplayName: "room-1x4",
		Description: "1 vCPU, 4 GiB room",
		CPU:         1, MemoryGiB: 4, DiskGiB: 10,
		Image: "alpine:3.20", Live: true, Sealed: sealedReady,
	},
	{
		Name: "room-2x8", DisplayName: "room-2x8",
		Description: "2 vCPU, 8 GiB room",
		CPU:         2, MemoryGiB: 8, DiskGiB: 10,
		Image: "alpine:3.20", Live: true, Sealed: sealedReady,
	},
	{
		Name: "room-4x16", DisplayName: "room-4x16",
		Description: "4 vCPU, 16 GiB room",
		CPU:         4, MemoryGiB: 16, DiskGiB: 10,
		Image: "alpine:3.20", Live: true, Sealed: sealedReady,
	},
	{
		Name: "lfm3-1.7b", DisplayName: "LFM3 1.7B (CPU)",
		Description: "LFM3 1.73B on CPU via llama.cpp (LFM3-1.7B-Q4_K_M.gguf). Sandbox inputs: text. Sandbox outputs: text. GPU is not required. Sealed AMD SEV-SNP only.",
		CPU:         2, MemoryGiB: 8, DiskGiB: 10,
		Image: pinnedImage(lfm31_7bRepo, lfm31_7bDigest), Live: true, Sealed: sealedReady, SealedOnly: true,
	},
	{
		Name: "lfm3-vl-2b", DisplayName: "LFM3 VL 2B (CPU)",
		Description: "LFM3 1.92B on CPU via llama.cpp b11960 (LFM3-VL-2B-Q4_K_M.gguf). Sandbox inputs: text, image. Sandbox outputs: text. Sealed AMD SEV-SNP only.",
		CPU:         2, MemoryGiB: 4, DiskGiB: 10,
		Image: pinnedImage("ghcr.io/cathedralai/room-lfm3-vl-2b", "sha256:d787ed7937cf0b1dad424bb614fd655ccd66ec635d21ac85f72d7a6f77c6583d"), Live: true, Sealed: sealedReady, SealedOnly: true,
	},
	{
		Name: "lfm3-omni-2b", DisplayName: "LFM3 Omni 2B (CPU)",
		Description: "LFM3 2.17B on CPU via llama.cpp b11960 (LFM3-Omni-2B-Q4_K_M.gguf). Sandbox inputs: text, image, audio. Sandbox outputs: text. Sealed AMD SEV-SNP only.",
		CPU:         2, MemoryGiB: 4, DiskGiB: 10,
		Image: pinnedImage("ghcr.io/cathedralai/room-lfm3-omni-2b", "sha256:4fc6e0682a2f563c5e0fb862c7a4968cdfd509a4d7bc73fee860c3592d214b41"), Live: true, Sealed: sealedReady, SealedOnly: true,
	},
	{
		Name: "d1-2b", DisplayName: "d1 2B (CPU)",
		Description: "d1 1.92B on CPU via llama.cpp b11960 (d1-2B-Q8_0.gguf). Sandbox outputs: decision (yes/no, choice, score). Sealed AMD SEV-SNP only.",
		CPU:         2, MemoryGiB: 4, DiskGiB: 10,
		Image: pinnedImage("ghcr.io/cathedralai/room-d1-2b", "sha256:4aed662bc5292e6c8813fefb178a471630d6122994b0cb2e4371f2439e18895f"), Live: true, Sealed: sealedReady, SealedOnly: true,
	},
	{
		Name: "lfm3-audio-2b", DisplayName: "LFM3 Audio 2B (CPU)",
		Description: "LFM3 2B on CPU via llama.cpp b11960 (LFM3-Audio-2B-Q4_K_M.gguf). Sandbox inputs: text, audio. Sandbox outputs: text. Sealed AMD SEV-SNP only.",
		CPU:         2, MemoryGiB: 4, DiskGiB: 10,
		Image: pinnedImage("ghcr.io/cathedralai/room-lfm3-audio-2b", "sha256:b91ef21e68d17fbafcdc2b2eb9d195f02c00a9b5325c7711680eaf1b2d0df336"), Live: true, Sealed: sealedReady, SealedOnly: true,
	},
	{
		Name: "d1-omni-2b", DisplayName: "d1 Omni 2B (CPU)",
		Description: "d1 2.17B on CPU via llama.cpp b11960 (d1-Omni-2B-Q8_0.gguf). Sandbox outputs: decision (yes/no, choice, score). Sealed AMD SEV-SNP only.",
		CPU:         2, MemoryGiB: 4, DiskGiB: 10,
		Image: pinnedImage("ghcr.io/cathedralai/room-d1-omni-2b", "sha256:57f9038bf8198e6a9fa52e37260a48b56ddf6b6a89c83dbf84b9b74838168cfd"), Live: true, Sealed: sealedReady, SealedOnly: true,
	},
	{
		Name: "lfm3-1.7b-base", DisplayName: "LFM3 1.7B Base (CPU)",
		Description: "LFM3 1.73B on CPU via llama.cpp b11960 (converted from LiquidAI/LFM3-1.7B-Base safetensors to Q4_K_M). Sealed AMD SEV-SNP only.",
		CPU:         2, MemoryGiB: 4, DiskGiB: 10,
		Image: pinnedImage("ghcr.io/cathedralai/room-lfm3-1.7b-base", "sha256:b48013ae60249c18cc756d6b449e3320ec63e5861dd0e3cb87c38be11e775e08"), Live: true, Sealed: sealedReady, SealedOnly: true,
	},
}

// pinnedImage is repository@sha256:hex. The hotel image grammar is a tag or a
// digest, not both. Live model templates use this for the published digest.
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
	view := map[string]any{
		"name":          t.Name,
		"display_name":  t.DisplayName,
		"description":   t.Description,
		"image":         t.Image,
		"resources":     map[string]any{"cpu": t.CPU, "memory_gib": t.MemoryGiB},
		"disk_gib":      t.DiskGiB,
		"network_modes": []string{"internet", "deny_all", "allowlist"},
		"egress_allow":  []string{},
		"live":          t.Live,
		"sealed":        string(t.Sealed),
	}
	if t.SealedOnly {
		view["sealed_only"] = true
		view["hardware_class"] = sealedHardwareClass
	}
	return view
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
func templateCreateErr(t catalogTemplate, sealedField, sealed bool) *apiErr {
	if t.SealedOnly {
		if sealedField && !sealed {
			return &apiErr{409, "template_sealed_only",
				"template " + t.Name + " runs only on the sealed pool; do not send sealed: false"}
		}
		if t.Sealed != sealedReady {
			return &apiErr{503, "template_sealed_pending",
				"sealed sandbox for " + t.Name + " is not available yet. Cathedral runs this model only on the sealed pool. There is no unsealed path"}
		}
		if !t.Live {
			return &apiErr{503, "template_unavailable",
				"template " + t.Name + " is not published for self-serve create yet"}
		}
		return nil
	}
	if !t.Live {
		return &apiErr{503, "template_unavailable",
			"template " + t.Name + " is not published for self-serve create yet"}
	}
	if sealedField && sealed {
		switch t.Sealed {
		case sealedReady:
		case sealedPending:
			return &apiErr{503, "template_sealed_pending",
				"sealed sandbox for " + t.Name + " is not available yet"}
		default:
			return &apiErr{503, "template_unavailable",
				"template " + t.Name + " has no sealed offer"}
		}
	}
	return nil
}

// applyCatalogTemplate turns a create body that names a catalog template into
// an image create at that template's size. Image and image_id already in the
// body win, as on the existing Harbor path.
//
// LFM templates are sealed-only. A pending sealed offer refuses the create.
// There is no fallback to an unsealed hotel.
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
	if e := templateCreateErr(t, sealedField, sealed); e != nil {
		return e
	}
	req["image"] = t.Image
	if req["resources"] == nil {
		req["resources"] = t.resources()
	}
	if t.SealedOnly {
		req["sealed"] = true
	}
	delete(req, "template")
	return nil
}

func (t catalogTemplate) String() string {
	return fmt.Sprintf("%s image=%s live=%v sealed=%s sealed_only=%v", t.Name, t.Image, t.Live, t.Sealed, t.SealedOnly)
}
