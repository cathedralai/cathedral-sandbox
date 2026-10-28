package main

import (
	"encoding/json"
	"strings"
	"testing"
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
	if !ok || !lfm.Live || lfm.Sealed != sealedPending {
		t.Fatalf("lfm3-1.7b: %+v", lfm)
	}
	if lfm.Image != lfm31_7bRepo+":"+lfm31_7bTag && !strings.HasPrefix(lfm.Image, lfm31_7bRepo+"@sha256:") {
		t.Fatalf("lfm3-1.7b image %q is not the published tag or a digest pin", lfm.Image)
	}
	if strings.HasSuffix(lfm.Image, ":latest") {
		t.Fatalf("lfm3-1.7b must not use a floating latest tag")
	}
}

func TestPinnedImageIsDigestOnly(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	got := pinnedImage("cathedral/lfm3-1.7b", digest)
	want := "cathedral/lfm3-1.7b@" + digest
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("pinnedImage accepted a tag")
		}
	}()
	_ = pinnedImage("cathedral/lfm3-1.7b:q4_k_m", digest)
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

func TestLFM3CreateUsesTheSameCompatPathAsRoom1x4(t *testing.T) {
	tc := newChain(t)
	status, room := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "room-1x4"}), nil)
	if status != 201 {
		t.Fatalf("room-1x4: %d %v", status, room)
	}
	status, lfm := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "lfm3-1.7b"}), nil)
	if status != 201 {
		t.Fatalf("lfm3-1.7b: %d %v", status, lfm)
	}
	if lfm["id"] == nil || lfm["id"] == room["id"] {
		t.Fatalf("lfm3 create id: %v", lfm["id"])
	}
	var found map[string]any
	for _, h := range tc.hotels {
		for _, c := range h.creates {
			if img, _ := c["image"].(string); img == lfm31_7bRepo+":"+lfm31_7bTag || strings.HasPrefix(img, lfm31_7bRepo+"@sha256:") {
				found = c
			}
		}
	}
	if found == nil {
		t.Fatal("lfm3-1.7b create never reached a hotel")
	}
	if found["image"] == "alpine:3.20" {
		t.Fatal("lfm3-1.7b must not fall through to the alpine room image")
	}
	res := found["resources"].(map[string]any)
	if res["vcpu"].(float64) != 1 || res["memory_gib"].(float64) != 4 {
		t.Fatalf("lfm3 resources: %v", res)
	}
}

func TestNativeLFM3TemplateCreateSucceedsLikeAnImageCreate(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"template": "lfm3-1.7b"})
	if status != 202 {
		t.Fatalf("native lfm3: %d %v", status, doc)
	}
	created := lastLFM3Create(t, tc)
	if created["image"] != lfm31_7bRepo+":"+lfm31_7bTag && !strings.HasPrefix(created["image"].(string), lfm31_7bRepo+"@sha256:") {
		t.Fatalf("hotel image: %v", created["image"])
	}
	if _, ok := created["template"]; ok {
		t.Fatalf("hotel must not see template: %v", created)
	}
}

func TestUnpublishedLFM3SuiteIsNotCreated(t *testing.T) {
	tc := newChain(t)
	for _, name := range []string{"lfm3-1.7b-base", "lfm3-vl-2b", "lfm3-audio-2b", "lfm3-omni-2b", "d1-2b", "d1-omni-2b"} {
		status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": name}), nil)
		if status != 503 || errDetail(doc) != "template_unavailable" {
			t.Fatalf("%s: %d %v", name, status, doc)
		}
	}
	if n := createsOn(tc); n["a"]+n["b"]+n["c"] != 0 {
		t.Fatalf("unpublished template reached a hotel: %v", n)
	}
}

func TestLFM3SealedCreateIsPending(t *testing.T) {
	tc := newChain(t)
	status, doc := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "lfm3-1.7b", "sealed": true}), nil)
	if status != 503 || errDetail(doc) != "template_sealed_pending" {
		t.Fatalf("compat sealed: %d %v", status, doc)
	}
	status, doc = tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"template": "lfm3-1.7b", "sealed": true})
	if status != 503 || errCode(doc) != "template_sealed_pending" {
		t.Fatalf("native sealed: %d %v", status, doc)
	}
	if n := createsOn(tc); n["a"]+n["b"]+n["c"] != 0 {
		t.Fatalf("sealed lfm3 reached a hotel: %v", n)
	}
}

func TestLFM3StandardCreateStaysOffSealedHotels(t *testing.T) {
	tc := newChain(t)
	status, _ := tc.clientCall(t, "POST", "/v1/sandboxes", mustMarshal(map[string]any{"template": "lfm3-1.7b"}), nil)
	if status != 201 {
		t.Fatalf("create: %d", status)
	}
	created := lastLFM3Create(t, tc)
	if created == nil {
		t.Fatal("no lfm3 create")
	}
	// Hotel "a" carries the sealed label. A standard LFM3 create must not land there.
	if len(tc.hotels["a"].creates) != 0 {
		t.Fatalf("standard lfm3 landed on the sealed-labelled hotel: %v", tc.hotels["a"].creates)
	}
	if len(tc.hotels["b"].creates)+len(tc.hotels["c"].creates) == 0 {
		t.Fatal("standard lfm3 did not land on an unsealed hotel")
	}
}

func TestCatalogAdvertisesLFM3LiveAndSealedPending(t *testing.T) {
	tc := newChain(t)
	_, cat := tc.clientCall(t, "GET", "/v1/sandboxes/catalog", nil, nil)
	byName := catalogByName(t, cat)
	lfm := byName["lfm3-1.7b"]
	if lfm["live"] != true || lfm["sealed"] != "pending" {
		t.Fatalf("lfm3 catalog: %v", lfm)
	}
	if lfm["image"] != lfm31_7bRepo+":"+lfm31_7bTag && !strings.HasPrefix(lfm["image"].(string), lfm31_7bRepo+"@sha256:") {
		t.Fatalf("catalog image: %v", lfm["image"])
	}
	if byName["lfm3-vl-2b"]["live"] != false || byName["lfm3-vl-2b"]["sealed"] != "pending" {
		t.Fatalf("unpublished catalog: %v", byName["lfm3-vl-2b"])
	}
	if _, ok := byName["room-1x4"]; !ok {
		t.Fatal("room-1x4 missing from catalog")
	}
	status, native := tc.call(t, "key1", "GET", "/v1/sandboxes/catalog", nil)
	if status != 200 {
		t.Fatalf("native catalog: %d %v", status, native)
	}
	if _, ok := catalogByName(t, native)["lfm3-1.7b"]; !ok {
		t.Fatalf("native catalog missing lfm3-1.7b: %v", native)
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
			if img == lfm31_7bRepo+":"+lfm31_7bTag || strings.HasPrefix(img, lfm31_7bRepo+"@sha256:") {
				last = c
			}
		}
	}
	if last == nil {
		t.Fatal("no lfm3 hotel create")
	}
	return last
}

func errDetail(doc map[string]any) string {
	d, _ := doc["detail"].(map[string]any)
	e, _ := d["error"].(string)
	return e
}
