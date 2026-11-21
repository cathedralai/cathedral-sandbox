// Image build for the published clients (#290). Harbor sends a Dockerfile and
// a build context to POST /v1/images/build and polls GET /v1/images/<id>.
//
// No hotel builds. AB#650 Option A: a shared sealed hotel never builds,
// because a Dockerfile can FROM or COPY --from a foreign local snapshot on the
// hotel's one Docker store. Every hotel is a shared sealed hotel (AB#776), so
// every build answers shared_hotel_build_refused and guests push a registry
// image instead. A built image left in older state reads as failed with the
// same code, and a create from it is refused the same way.
package main

import "net/http"

const buildRefusedMsg = "Cathedral hotels are shared sealed hotels and do not build images (AB#650); push the image to a registry and create from that image"

func (b *broker) compatBuild(w http.ResponseWriter, r *http.Request, g *guestState) {
	compatErr(w, 409, "shared_hotel_build_refused", buildRefusedMsg, 0)
}

// imageView is the client view of an image. A built image (older state) can
// never be ready: no hotel builds.
func (b *broker) imageView(img *compatImage) map[string]any {
	if !img.Build {
		return map[string]any{"image_id": img.ID, "state": "ready", "image": img.Ref}
	}
	return map[string]any{"image_id": img.ID, "state": "failed", "error": "shared_hotel_build_refused", "message": buildRefusedMsg}
}
