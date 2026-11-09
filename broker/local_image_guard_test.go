package main

import (
	"strings"
	"testing"
)

const snapRef = "cathedral-snap-snap_79b76a76a7d3"

var hexID = strings.Repeat("ab", 32)

func hotelCreates(tc *testChain) int {
	n := 0
	for _, f := range tc.hotels {
		f.mu.Lock()
		n += len(f.creates)
		f.mu.Unlock()
	}
	return n
}

// A snapshot image lives in the hotel's one Docker image store for every
// guest. Named in image, a create would start the snapshot whoever made it,
// so every spelling Docker resolves to the local image is refused, and
// nothing reaches a hotel.
func TestCreateRefusesASnapshotImageByAnyName(t *testing.T) {
	tc := r6Chain(t, "", nil)
	for _, ref := range []string{
		snapRef + ":latest",
		snapRef,
		strings.ToUpper(snapRef) + ":latest",
		"docker.io/library/" + snapRef + ":latest",
		"library/" + snapRef,
		"localhost:5000/" + snapRef + ":latest",
		snapRef + "@sha256:" + hexID,
		"  " + snapRef + ":latest ",
	} {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": ref, "hotels": []string{"b"}})
		if status != 422 || errCode(doc) != "snapshot_image_by_name" {
			t.Fatalf("image %q: want 422 snapshot_image_by_name, got %d %v", ref, status, doc)
		}
	}
	if n := hotelCreates(tc); n != 0 {
		t.Fatalf("a refused create reached a hotel %d times", n)
	}
}

// An image id names any local image the same way.
func TestCreateRefusesAnImageID(t *testing.T) {
	tc := r6Chain(t, "", nil)
	for _, ref := range []string{"sha256:" + hexID, "SHA256:" + hexID, hexID, hexID[:12]} {
		status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": ref, "hotels": []string{"b"}})
		if status != 422 || errCode(doc) != "image_reference_refused" {
			t.Fatalf("image %q: want 422 image_reference_refused, got %d %v", ref, status, doc)
		}
	}
	if n := hotelCreates(tc); n != 0 {
		t.Fatalf("a refused create reached a hotel %d times", n)
	}
}

// Registry images keep working, digest-pinned ones included.
func TestCreateStillTakesRegistryImages(t *testing.T) {
	tc := r6Chain(t, "", nil)
	for i, ref := range []string{
		"alpine:3.20",
		"docker:27-dind",
		"ghcr.io/acme/app@sha256:" + hexID,
		"registry.example:5000/team/app:1",
		"acme/cathedral-snapshotter:2",
	} {
		key := []string{"key1", "key2"}[i%2]
		status, doc := tc.call(t, key, "POST", "/v1/sandboxes", map[string]any{"image": ref, "hotels": []string{"b"}})
		if status != 202 {
			t.Fatalf("image %q: want 202, got %d %v", ref, status, doc)
		}
	}
}

func TestLocalImageRefusalNames(t *testing.T) {
	cases := map[string]string{
		snapRef + ":latest":                "snapshot_image_by_name",
		"docker.io/library/" + snapRef:     "snapshot_image_by_name",
		"sha256:" + hexID:                  "image_reference_refused",
		hexID:                              "image_reference_refused",
		"alpine:3.20":                      "",
		"ghcr.io/acme/app@sha256:" + hexID: "",
		"cafe:1":                           "",
		"deadbeefcafe:latest":              "",
		"acme/cathedral-snapshotter:2":     "",
		"registry.example:5000/team/app:1": "",
	}
	for ref, want := range cases {
		got := ""
		if e := localImageRefusal(ref); e != nil {
			got = e.code
		}
		if got != want {
			t.Fatalf("localImageRefusal(%q) = %q, want %q", ref, got, want)
		}
	}
}
