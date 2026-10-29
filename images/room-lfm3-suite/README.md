# LFM3 suite images (sealed pool)

CPU-only llama.cpp images for the LFM3 models that are not yet published.
The live 1.7B image stays in `images/room-lfm3` and is already on GHCR.

Weights are in the image so a sealed sandbox can run with network `deny_all`.
llama.cpp is `b11960` (commit `8642541b255bfb5dc39cd351a178be09013a55d6`),
the first release with LFM3, video, and d1.

## Models

Publish in this order. Pin the digest in `broker/catalog.go` after each
successful run, then flip `Sealed` to ready once a sealed hotel has the image.

| Order | Template | Image | Weights |
|---|---|---|---|
| 2 | lfm3-vl-2b | ghcr.io/cathedralai/room-lfm3-vl-2b | Q4_K_M + mmproj Q8 |
| 3 | lfm3-omni-2b | ghcr.io/cathedralai/room-lfm3-omni-2b | Q4_K_M + mmproj Q8 |
| 4 | d1-2b | ghcr.io/cathedralai/room-d1-2b | Q4_K_M + mmproj Q8 |
| 5 | lfm3-audio-2b | ghcr.io/cathedralai/room-lfm3-audio-2b | Q4_K_M + mmproj Q8 |
| 6 | d1-omni-2b | ghcr.io/cathedralai/room-d1-omni-2b | Q8_0 + mmproj Q8 |
| 7 | lfm3-1.7b-base | ghcr.io/cathedralai/room-lfm3-1.7b-base | BF16 safetensors (no GGUF) |

1.7B is already published as `ghcr.io/cathedralai/room-lfm3-1.7b@sha256:b1ba8837...`.

## Publish

Do not run this from a pull request. It is `workflow_dispatch` only, so a
merge does not spend CI building five 1 GiB-plus images.

In GitHub Actions, run **Publish LFM3 suite images** and pick one model
(or `all`). The job prints the digest to pin.

Local one-model build (example: VL):

```sh
set -a
. images/room-lfm3-suite/models/lfm3-vl-2b.env
set +a
docker build -f images/room-lfm3-suite/Dockerfile images/room-lfm3-suite \
  --build-arg GGUF_REPO="$GGUF_REPO" \
  --build-arg GGUF_REVISION="$GGUF_REVISION" \
  --build-arg GGUF_FILE="$GGUF_FILE" \
  --build-arg GGUF_SHA256="$GGUF_SHA256" \
  --build-arg MMPROJ_FILE="$MMPROJ_FILE" \
  --build-arg MMPROJ_SHA256="$MMPROJ_SHA256" \
  --build-arg LICENSE_SHA256="$LICENSE_SHA256" \
  --build-arg LFM3_ALIAS="$LFM3_ALIAS" \
  --build-arg LFM3_REASONING="$LFM3_REASONING"
```

## After publish

1. Put the digest in `broker/catalog.go` with `pinnedImage`.
2. On each sealed hotel, prefetch so a create does not hit the pull deadline:

```sh
curl -sS -X POST "$BROKER/v1/images/prefetch" \
  -H "Authorization: Bearer $CATHEDRAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{\"images\":[\"ghcr.io/cathedralai/room-lfm3-vl-2b@sha256:...\"],\"sealed\":true}"
```

3. Flip that template to `Sealed: sealedReady` only after prefetch is `done`.
4. A paid sealed create waits for Fred.
