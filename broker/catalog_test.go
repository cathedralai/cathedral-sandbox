package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCatalogListsRoomSizesThenLFM3(t *testing.T) {
	names := make([]string, 0, len(catalogTemplates))
	for _, tpl := range catalogTemplates {
		names = append(names, tpl.Name)
	}
	if names[0] != "room-1x4" || names[1] != "room-2x8" || names[2] != "room-4x16" {
		t.Fatalf("room sizes must stay at the front of the catalog: %v", names[:3])
	}
	lfm, ok := templateByName("lfm3-1.7b")
	if !ok || !lfm.Live || lfm.Sealed != sealedReady || !lfm.SealedOnly {
		t.Fatalf("lfm3-1.7b: %+v", lfm)
	}
	want := pinnedImage(lfm31_7bRepo, lfm31_7bDigest)
	if lfm.Image != want {
		t.Fatalf("lfm3-1.7b image %q want %q", lfm.Image, want)
	}
	if strings.HasSuffix(lfm.Image, ":latest") {
		t.Fatalf("lfm3-1.7b must not use a floating latest tag")
	}
}

func TestPinnedImageIsDigestOnly(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	got := pinnedImage(lfm31_7bRepo, digest)
	want := lfm31_7bRepo + "@" + digest
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("pinnedImage accepted a tag")
		}
	}()
	_ = pinnedImage(lfm31_7bRepo+":q4_k_m", digest)
}

func TestUnknownTemplateIs404OnCompatAndNative(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "no-such-template"}), nil)
	if status != 404 || errDetail(doc) != "template_not_found" {
		t.Fatalf("compat unknown: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"template": "no-such-template"})
	if status != 404 || errCode(doc) != "template_not_found" {
		t.Fatalf("native unknown: %d %v", status, doc)
	}
	if n := createsOn(tc); n["a"]+n["b"]+n["c"] != 0 {
		t.Fatalf("unknown template reached a hotel: %v", n)
	}
}

func TestLFM3CreateHasNoUnsealedPath(t *testing.T) {
	tc := newChain(t)
	// sealed: false is refused before any hotel.
	body := map[string]any{"template": "lfm3-1.7b", "sealed": false}
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(body), nil)
	if status != 409 || errDetail(doc) != "template_sealed_only" {
		t.Fatalf("compat %v: %d %v", body, status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", body)
	if status != 409 || errCode(doc) != "template_sealed_only" {
		t.Fatalf("native %v: %d %v", body, status, doc)
	}
	if n := createsOn(tc); n["a"]+n["b"]+n["c"] != 0 {
		t.Fatalf("refused LFM create reached a hotel: %v", n)
	}
	// Ready and sealed only: with or without sealed: true it lands on the sealed hotel, never elsewhere.
	for _, body := range []map[string]any{{"template": "lfm3-1.7b"}, {"template": "lfm3-1.7b", "sealed": true}} {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", body)
		if status >= 300 {
			t.Fatalf("native %v: %d %v", body, status, doc)
		}
	}
	if n := createsOn(tc); n["a"] != 2 || n["b"]+n["c"] != 0 {
		t.Fatalf("LFM creates must land on the sealed hotel only: %v", n)
	}
}

func TestLFM3PendingErrorDoesNotOfferUnsealed(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "lfm3-vl-2b"}), nil)
	if status != 503 || errDetail(doc) != "template_sealed_pending" {
		t.Fatalf("pending: %d %v", status, doc)
	}
	msg := errMessage(doc)
	if strings.Contains(strings.ToLower(msg), "standard") || strings.Contains(msg, "sealed\": false") || strings.Contains(msg, "without sealed") {
		t.Fatalf("pending error still offers an unsealed path: %q", msg)
	}
	if !strings.Contains(msg, "no unsealed path") {
		t.Fatalf("pending error must say there is no unsealed path: %q", msg)
	}
}

func TestUnpublishedLFM3SuiteIsNotCreated(t *testing.T) {
	tc := newChain(t)
	for _, name := range []string{"lfm3-1.7b-base", "lfm3-vl-2b", "lfm3-audio-2b", "lfm3-omni-2b", "d1-2b", "d1-omni-2b"} {
		status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": name}), nil)
		if status != 503 {
			t.Fatalf("%s: %d %v", name, status, doc)
		}
		if errDetail(doc) != "template_unavailable" && errDetail(doc) != "template_sealed_pending" {
			t.Fatalf("%s: %d %v", name, status, doc)
		}
	}
	if n := createsOn(tc); n["a"]+n["b"]+n["c"] != 0 {
		t.Fatalf("unpublished template reached a hotel: %v", n)
	}
}

func TestLFM3SuiteCatalogIsSealedOnlyAndGHCR(t *testing.T) {
	wantImages := map[string]string{
		"lfm3-1.7b":      pinnedImage(lfm31_7bRepo, lfm31_7bDigest),
		"lfm3-vl-2b":     pinnedImage("ghcr.io/cathedralai/room-lfm3-vl-2b", "sha256:ad586f04ff7aca83d82355ee5df960497b569c6a4ca198741a25b054627140f5"),
		"lfm3-omni-2b":   pinnedImage("ghcr.io/cathedralai/room-lfm3-omni-2b", "sha256:3b1f0900656856de8511adb09b9816c740cd33f4df5b5c32a6596b794b2611ff"),
		"d1-2b":          pinnedImage("ghcr.io/cathedralai/room-d1-2b", "sha256:2e92f09e8572f34d1ef27b8f7835410dba9f221ad994f8f3e004c5c4f4512f3c"),
		"lfm3-audio-2b":  pinnedImage("ghcr.io/cathedralai/room-lfm3-audio-2b", "sha256:6058d091f4ed9f3770da38b68ce5237a33e05bcf3037f5a2e5eef2b45d212a49"),
		"d1-omni-2b":     pinnedImage("ghcr.io/cathedralai/room-d1-omni-2b", "sha256:17791b80a0e21005321754439c219712274541561bcb83848794a33c16f90002"),
		"lfm3-1.7b-base": pinnedImage("ghcr.io/cathedralai/room-lfm3-1.7b-base", "sha256:c7fc0f7f5ee18e915b1086fab27d076c391a408085efdd89cb89cb10e4623278"),
	}
	for name, image := range wantImages {
		tpl, ok := templateByName(name)
		if !ok {
			t.Fatalf("missing template %s", name)
		}
		wantSealed := sealedPending
		if name == "lfm3-1.7b" {
			wantSealed = sealedReady // prefetched on every shared sealed hotel, 29 Oct 2026
		}
		if !tpl.SealedOnly || tpl.Sealed != wantSealed || !tpl.Live {
			t.Fatalf("%s: sealed_only=%v sealed=%s live=%v", name, tpl.SealedOnly, tpl.Sealed, tpl.Live)
		}
		if name != "lfm3-1.7b" && (tpl.CPU != 2 || tpl.MemoryGiB != 4 || tpl.Rate != "0.035") {
			t.Fatalf("%s must use the sealed 2 vCPU / 4 GiB shape at $0.035: %+v", name, tpl)
		}
		if tpl.Image != image {
			t.Fatalf("%s image %q want %q", name, tpl.Image, image)
		}
		if strings.Contains(tpl.Description, "Standard") || strings.Contains(tpl.Description, "tdx_cpu") {
			t.Fatalf("%s description still names Standard or tdx_cpu: %q", name, tpl.Description)
		}
	}
	d1, _ := templateByName("d1-2b")
	if d1.MemoryGiB != 4 || !strings.Contains(d1.Description, "llama.cpp") {
		t.Fatalf("d1-2b should be GGUF on llama.cpp at 4 GiB: %+v", d1)
	}
}

func TestCatalogAdvertisesLFM3LiveAndSealedPending(t *testing.T) {
	tc := newChain(t)
	_, cat := tc.clientCall(t, "GET", "/v1/sandboxes/catalog", nil, nil)
	byName := catalogByName(t, cat)
	lfm := byName["lfm3-1.7b"]
	if lfm["live"] != true || lfm["sealed"] != "ready" || lfm["sealed_only"] != true {
		t.Fatalf("lfm3 catalog: %v", lfm)
	}
	if lfm["hardware_class"] != sealedHardwareClass {
		t.Fatalf("lfm3 hardware_class: %v", lfm["hardware_class"])
	}
	if lfm["image"] != pinnedImage(lfm31_7bRepo, lfm31_7bDigest) {
		t.Fatalf("catalog image: %v", lfm["image"])
	}
	if byName["lfm3-vl-2b"]["live"] != true || byName["lfm3-vl-2b"]["sealed"] != "pending" {
		t.Fatalf("published but not prefetched catalog: %v", byName["lfm3-vl-2b"])
	}
	if byName["room-1x4"]["sealed_only"] != nil {
		t.Fatalf("room-1x4 must not be sealed-only: %v", byName["room-1x4"])
	}
	status, native := tc.call(t, "key1", "GET", "/v1/sandboxes/catalog", nil)
	if status != 200 {
		t.Fatalf("native catalog: %d %v", status, native)
	}
	if _, ok := catalogByName(t, native)["lfm3-1.7b"]; !ok {
		t.Fatalf("native catalog missing lfm3-1.7b: %v", native)
	}
}

func TestLFM3ReadyCreateForcesSealedAndStaysOnSealedHotels(t *testing.T) {
	idx := lfm31_7bIndex(t)
	old := catalogTemplates[idx]
	catalogTemplates[idx].Sealed = sealedReady
	t.Cleanup(func() { catalogTemplates[idx] = old })

	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "lfm3-1.7b"}), nil)
	if status != 201 {
		t.Fatalf("ready create: %d %v", status, doc)
	}
	created := lastLFM3Create(t, tc)
	if created["image"] != pinnedImage(lfm31_7bRepo, lfm31_7bDigest) {
		t.Fatalf("hotel image: %v", created["image"])
	}
	if _, ok := created["template"]; ok {
		t.Fatalf("hotel must not see template: %v", created)
	}
	res := created["resources"].(map[string]any)
	if res["vcpu"].(float64) != 2 || res["memory_gib"].(float64) != 8 {
		t.Fatalf("lfm3 resources: %v", res)
	}
	if len(tc.hotels["a"].creates) == 0 {
		t.Fatal("ready LFM did not land on the sealed hotel")
	}
	if len(tc.hotels["b"].creates)+len(tc.hotels["c"].creates) != 0 {
		t.Fatalf("ready LFM leaked to an unsealed hotel: b=%v c=%v", tc.hotels["b"].creates, tc.hotels["c"].creates)
	}
}

func TestLFM3ReadyCreateRefusesSealedFalse(t *testing.T) {
	idx := lfm31_7bIndex(t)
	old := catalogTemplates[idx]
	catalogTemplates[idx].Sealed = sealedReady
	t.Cleanup(func() { catalogTemplates[idx] = old })

	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "lfm3-1.7b", "sealed": false}), nil)
	if status != 409 || errDetail(doc) != "template_sealed_only" {
		t.Fatalf("compat sealed false: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"template": "lfm3-1.7b", "sealed": false})
	if status != 409 || errCode(doc) != "template_sealed_only" {
		t.Fatalf("native sealed false: %d %v", status, doc)
	}
	if n := createsOn(tc); n["a"]+n["b"]+n["c"] != 0 {
		t.Fatalf("sealed=false LFM reached a hotel: %v", n)
	}
}

func TestRoomTemplateStillCreatesWithoutSealed(t *testing.T) {
	tc := newChain(t)
	status, room := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("room-1x4: %d %v", status, room)
	}
	if n := createsOn(tc); n["a"]+n["b"]+n["c"] != 1 {
		t.Fatalf("room-1x4 should create one sandbox: %v", n)
	}
}

func TestHotelCreateTimeoutCoversHotelImagePull(t *testing.T) {
	// Hotel docker pull is 600s (sandbox_guest.py). A cold LFM3 pull on a
	// sealed hotel (GHCR, about 1.2 GiB, LUKS scratch) was dying as
	// hotel_unreachable when the broker gave up at 5 minutes.
	if hotelCreateTimeout < 10*time.Minute {
		t.Fatalf("hotelCreateTimeout %s is shorter than the hotel docker pull (600s)", hotelCreateTimeout)
	}
}

func catalogByName(t *testing.T, cat map[string]any) map[string]map[string]any {
	t.Helper()
	raw, _ := json.Marshal(cat["templates"])
	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("templates: %v %v", cat["templates"], err)
	}
	out := map[string]map[string]any{}
	for _, item := range items {
		name, _ := item["name"].(string)
		out[name] = item
	}
	return out
}

func lastLFM3Create(t *testing.T, tc *testChain) map[string]any {
	t.Helper()
	var last map[string]any
	for _, h := range tc.hotels {
		for _, c := range h.creates {
			img, _ := c["image"].(string)
			if img == pinnedImage(lfm31_7bRepo, lfm31_7bDigest) {
				last = c
			}
		}
	}
	if last == nil {
		t.Fatal("no lfm3 hotel create")
	}
	return last
}

func lfm31_7bIndex(t *testing.T) int {
	t.Helper()
	for i, tpl := range catalogTemplates {
		if tpl.Name == "lfm3-1.7b" {
			return i
		}
	}
	t.Fatal("lfm3-1.7b missing")
	return -1
}

func errDetail(doc map[string]any) string {
	d, _ := doc["detail"].(map[string]any)
	e, _ := d["error"].(string)
	return e
}

func errMessage(doc map[string]any) string {
	if e, _ := doc["error"].(map[string]any); e != nil {
		msg, _ := e["message"].(string)
		if msg != "" {
			return msg
		}
	}
	d, _ := doc["detail"].(map[string]any)
	msg, _ := d["message"].(string)
	if msg != "" {
		return msg
	}
	msg, _ = doc["message"].(string)
	return msg
}
