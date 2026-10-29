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
