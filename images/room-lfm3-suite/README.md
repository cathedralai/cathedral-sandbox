# Room images: the Liquid AI LFM3 suite

Liquid AI's LFM3 family on llama.cpp, CPU only, one room image per model. The
weights are in the image, so each runs in a sealed room (network `deny_all`)
with nothing to download. Published by
`.github/workflows/publish-room-lfm3-suite.yml` as
`ghcr.io/cathedralai/room-<model>`; pin the digest from the run summary,
never a tag.

LFM3-1.7B itself is `ghcr.io/cathedralai/room-lfm3-1.7b` (`images/room-lfm3`
on `eng/room-lfm3-image`) and is not rebuilt here.

## Models

Every model is under the LFM Open License v1.0. Sizes are the files baked in.
"Sealed" is the 2 vCPU / 4 GiB / 10 GiB sealed room.

| Model | Params | Input, output | Weights in the image | Size | Sealed |
|---|---|---|---|---|---|
| `lfm3-1.7b-base` | 1.73B | text, text | `LFM3-1.7B-Base-Q4_K_M.gguf`, converted here (no official GGUF) | 1.1 GB | yes |
| `lfm3-vl-2b` | 1.92B | text and image, text | `LFM3-VL-2B-Q4_K_M.gguf` + `mmproj-LFM3-VL-2B-Q8_0.gguf` | 1.3 GB | yes |
| `lfm3-audio-2b` | 2.0B | text and audio, text | `LFM3-Audio-2B-Q4_K_M.gguf` + `mmproj-LFM3-Audio-2B-Q8_0.gguf` | 1.4 GB | yes |
| `lfm3-omni-2b` | 2.17B | text, image and audio, text | `LFM3-Omni-2B-Q4_K_M.gguf` + `mmproj-LFM3-Omni-2B-Q8_0.gguf` | 1.6 GB | yes |
| `d1-2b` | 1.92B | text and image, decisions | `d1-2B-Q8_0.gguf` + `mmproj-d1-2B-Q8_0.gguf` | 2.0 GB | yes |
| `d1-omni-2b` | 2.17B | text, image and audio, decisions | `d1-Omni-2B-Q8_0.gguf` + `mmproj-d1-Omni-2B-Q8_0.gguf` | 2.2 GB | yes |

Pins (Hugging Face revision and sha256 of every file) are in the workflow
matrix. The build fails if a download does not match.

What a 4 GiB room does not give: the BF16 checkpoints (3.5 GB of weights
before any cache), the full 128K or 256K context (the server runs 4096
tokens, 8192 for d1), video input (llama.cpp needs `ffmpeg`, not in the
image) and speech output (`llama-tts`, `/v1/realtime`), which are not
shipped or tested here.

## Pins and sealed proof

Published from commit `08a476a` (run summary has the commit tags). All six
packages are public; anonymous pull checked.

| Model | Pin |
|---|---|
| `lfm3-1.7b-base` | `ghcr.io/cathedralai/room-lfm3-1.7b-base@sha256:c7fc0f7f5ee18e915b1086fab27d076c391a408085efdd89cb89cb10e4623278` |
| `lfm3-vl-2b` | `ghcr.io/cathedralai/room-lfm3-vl-2b@sha256:ad586f04ff7aca83d82355ee5df960497b569c6a4ca198741a25b054627140f5` |
| `lfm3-audio-2b` | `ghcr.io/cathedralai/room-lfm3-audio-2b@sha256:6058d091f4ed9f3770da38b68ce5237a33e05bcf3037f5a2e5eef2b45d212a49` |
| `lfm3-omni-2b` | `ghcr.io/cathedralai/room-lfm3-omni-2b@sha256:3b1f0900656856de8511adb09b9816c740cd33f4df5b5c32a6596b794b2611ff` |
| `d1-2b` | `ghcr.io/cathedralai/room-d1-2b@sha256:2e92f09e8572f34d1ef27b8f7835410dba9f221ad994f8f3e004c5c4f4512f3c` |
| `d1-omni-2b` | `ghcr.io/cathedralai/room-d1-omni-2b@sha256:17791b80a0e21005321754439c219712274541561bcb83848794a33c16f90002` |

The converted `LFM3-1.7B-Base-Q4_K_M.gguf` in that image has sha256
`d4c9ebb5aa08999083bf939042087b6379547c5729163ce556902d8c06111fd5`.

One sealed room per image on prod, 29 Oct: `amd_sev_snp`, `deny_all`,
`sealed-2x4` (2 vCPU, 4 GiB, 10 GiB), `max_spend_usd` 0.1, created and
deleted through the public API, no prefetch. Each ran `lfm3-selftest` check by
check and one request to the endpoint contract from inside the room.
Generation rate is a 256-token `/v1/chat/completions` answer; d1 times are
`lfm3-decide` wall time. Receipts are create, each exec, and delete.

| Model | Create to running | Rate or decision time | Sample answer | Server RSS | Receipts |
|---|---|---|---|---|---|
| `lfm3-1.7b-base` | 4.9 s (23.3 s on the first pull) | 23.7 tok/s | raw "The capital of France is" gives " Paris."; 2+2 gives "4" | 1.9 GB | 8 |
| `lfm3-vl-2b` | 84.4 s | 19.9 tok/s; picture answered in 4.2 s | test picture: "Blue" | 2.3 GB | 8 |
| `lfm3-audio-2b` | 40.2 s | 23.5 tok/s; clip in 1.7 s | clip: "The train to Paris leaves at 9 in the morning." | 2.4 GB | 8 |
| `lfm3-omni-2b` | 102.6 s | 19.4 tok/s; picture 4.5 s, clip 2.2 s | picture "Blue"; clip transcribed exactly | 2.7 GB | 9 |
| `d1-2b` | 60.6 s | text 0.8 s, picture 4.4 s | refund 0.996, picture "blue" 0.9996 | 2.3 GB | 8 |
| `d1-omni-2b` | 60.0 s | text 0.8 s, picture 4.4 s, clip 1.5 s | refund 0.95, picture "blue" 0.97, clip "paris" 0.95 | 2.5 GB | 9 |

At least 1.5 GB of the 4 GiB stayed available after the checks in every room.
The first two `d1-2b` creates failed at the API ("Sealed pool did not answer:
ReadTimeout", while the image pulled); the third ran.

## What runs in the room

The entrypoint is `lfm3-serve`. It starts `llama-server` on `127.0.0.1:8080`,
OpenAI-compatible at `/v1`, then runs the sandbox command (the keepalive
`sleep infinity`); with no command the server runs in the foreground. The
log is `/tmp/lfm3/server.log`; `/health` answers 200 once the model is
loaded. The image sets the variables an agent reads to find its model, as the
LFM3-1.7B images do:

```
MODEL_BASE_URL=http://127.0.0.1:8080/v1
MODEL=<model>            # for example lfm3-omni-2b
MODEL_API_KEY=local
```

The server does not check the key; OpenAI clients need a non-empty one.

`lfm3-ask` asks the running server (no second copy of the model) and prints
the answer and the same timing line as in the LFM3-1.7B room:

```sh
lfm3-ask "What is 2+2? Answer in one word."
lfm3-ask --image photo.png "What is in this picture?"            # VL, Omni
lfm3-ask --system "Perform ASR in English." --audio clip.wav     # Audio, Omni
lfm3-ask --raw "The capital of France is"                        # plain completion
```

```
lfm3-timing load_ms=812 prompt_tok_s=118.0 gen_tok_s=52.8 wall_ms=1530 threads=2 max_tokens=256 reasoning=off
```

Over HTTP, a picture is an `image_url` part with a data URI and a clip an
`input_audio` part (base64 WAV or MP3), in `/v1/chat/completions`.

LFM3-Audio-2B reasons before a text answer even with `LFM3_REASONING=off`:
its chat template has no switch for it. The reasoning comes back in
`reasoning_content`; leave room for it in `max_tokens` (about 60 tokens for
"What is 2+2?"). Speech recognition (system prompt `Perform ASR in
English.`) answers directly.

d1 does not generate text. It answers typed questions (`noul`, `choice`,
`score`) about a state in one forward pass at `$MODEL_BASE_URL/systemone`;
`/v1/chat/completions` answers 501. `lfm3-decide` wraps it:

```sh
lfm3-decide '{"state": "I was charged twice, please refund one.",
  "questions": {"refund": {"type": "noul", "instructions": "Is this a refund request?"}}}'
lfm3-decide --image photo.png '{"state": null, "questions": {...}}'
lfm3-decide --audio clip.wav '{"state": null, "questions": {...}}'   # d1-Omni
```

`lfm3-selftest` asks the model questions with known answers, using the
bundled `/opt/lfm3/test/test-image.png` (a blue circle on red) and
`/opt/lfm3/test/test-speech.wav` ("The train to Paris leaves at nine in the
morning."). With no argument it runs the checks set for the model
(`$LFM3_CHECKS`).

`LFM3_THREADS`, `LFM3_SERVER_CTX`, `LFM3_REASONING`, `LFM3_CACHE_RAM` and,
for d1, `LFM3_BATCH` change the server (see `lfm3-serve`). The prompt cache
defaults to 256 MiB: llama-server's own default (8 GiB) does not fit the room.

## Build

`Dockerfile` builds llama.cpp at the LFM3-1.7B room's commit (`b11960`,
`8642541b255bfb5dc39cd351a178be09013a55d6`) with the same flags (every
x86-64 CPU variant as a module, the AMX variant removed), then adds one
model:

- `WEIGHTS=download`: Liquid AI's GGUF and projector from the `-GGUF` repo
  at a fixed revision, each checked by sha256.
- `WEIGHTS=convert`: LFM3-1.7B-Base has no official GGUF. The build fetches
  its safetensors at a fixed revision (every file by sha256), converts them
  with that llama.cpp commit's `convert_hf_to_gguf.py` and quantizes to
  Q4_K_M with `llama-quantize`. The checkpoint needs transformers 5.12.1 for
  its tokenizer. `/opt/lfm3/NOTICE` says the file was converted, and
  `/opt/lfm3/SHA256SUMS` records the result.

Each job smoke tests the published digest like a sealed room: network none,
2 CPUs, 4 GiB, keepalive command. `lfm3-selftest` must pass and the endpoint
contract must answer (`/v1/chat/completions`, or `/v1/systemone` for d1).
The run summary has the pin, the unpacked size, the memory used and the
checksums.

## Visibility

A sealed hotel pulls with no credentials, so every package must be public. If
a new one comes up private, an owner makes it public, then runs the workflow
by hand with the pins to check anonymous pull.

## License

The LFM3 models are under the LFM Open License v1.0 (`/opt/lfm3/LICENSE`,
attribution in `/opt/lfm3/NOTICE`). It allows commercial use, including
running the model as a service, only while the licensee and its affiliates
have annual revenue under USD 10 million (Section 5). llama.cpp is MIT
(`/opt/lfm3/licenses/llama.cpp-LICENSE`). The test files were made for this
image (see `NOTICE.in`).
