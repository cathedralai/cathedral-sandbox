# LFM3 sealed benchmark baseline, 16 Nov 2026 (AB#445)

Status: harness inputs frozen, results pending. The six result JSONs and their
evidence bundles are added to this folder by the PR that records the runs.
Nothing below is a measurement.

## What is measured

Omni, VL and Audio, each on the two sealed room sizes, with
`scripts/sealed_bench.py` (harness `sealed-bench-2`, in-room `lfm3-bench-1`,
AB#444). One call per cell creates one sealed sandbox and repeats the prompt
set 3 times inside it (`--runs 3`), so each cell has 3 repeats x 3 prompts = 9
samples. The call also fetches the sandbox evidence bundle, deletes the
sandbox, and passes only on an offline `ctcli receipt verify` PASS. Each cell
is reported as the median with the min to max range of its 9 samples.

| Template | Room |
|---|---|
| `sealed-2x4` | 2 vCPU, 4 GiB |
| `sealed-8x16` | 8 vCPU, 16 GiB |

## Images

Published from cathedral-sandbox main `62686dd` (publish-room-lfm3-suite run
43862309556, which includes #520, #534, #551 and #559, so `lfm3-bench` is in
the image). Compressed size is the sum of the linux/amd64 layers.

| Model | Image | Compressed |
|---|---|---|
| Omni | `ghcr.io/cathedralai/room-lfm3-omni-2b@sha256:965eea18e7301796c94f00825479b312884277a51437615f97b28523622a6ffb` | 1.64 GB |
| VL | `ghcr.io/cathedralai/room-lfm3-vl-2b@sha256:96779101571ca96f11b39fbce22f3a6a92da6769d4dab406c36e554cfd35f435` | 1.32 GB |
| Audio | `ghcr.io/cathedralai/room-lfm3-audio-2b@sha256:4f9ab1457d67d8fba8c9890a612c81ad4274e5f83ea1903becafc5c51a14d5f9` | 1.45 GB |

## Prompt set

`scripts/bench/prompts.json`, three text prompts, `prompt_set_sha256`
`3f87a7d83e6b637ffa72c976fd9647c82c44769fd67a03a566eaba85b3b493ab`
(sha256 of the compact JSON of the list, as the harness computes it).
Text prompts only: VL and Audio are measured on their text path here, not on
image or audio input.

## Reproduce

```
CATHEDRAL_API_KEY=... python3 scripts/sealed_bench.py \
  --image <image above> --template sealed-2x4 \
  --prompts scripts/bench/prompts.json --out-dir out/omni-sealed-2x4 --runs 3 \
  --cathedral-key <receipt public key hex> --expected-measurement <96 hex>
```

Repeat for the six cells (omni, vl, audio by `sealed-2x4`, `sealed-8x16`).

## Results

| Model | Template | Result JSON | Bundle | Prompt tok/s | Decode tok/s | First token (ms) |
|---|---|---|---|---|---|---|
| Omni | sealed-2x4 | pending | pending | pending | pending | pending |
| Omni | sealed-8x16 | pending | pending | pending | pending | pending |
| VL | sealed-2x4 | pending | pending | pending | pending | pending |
| VL | sealed-8x16 | pending | pending | pending | pending | pending |
| Audio | sealed-2x4 | pending | pending | pending | pending | pending |
| Audio | sealed-8x16 | pending | pending | pending | pending | pending |

The 4 Nov hand numbers (Omni, `sealed-2x4`, c46-sealed-2: prompt 75 to 79,
decode 23 to 25 tokens/s) are not receipted and are superseded by this table
once filled.
