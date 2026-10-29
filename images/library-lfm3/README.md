# Library images with LFM3-1.7B

Every Library environment runs with a language model in the same sandbox.
This directory adds Liquid AI LFM3-1.7B (Q4_K_M, CPU only) to a Library
environment image. The environment and the model share one sealed sandbox
with network `deny_all`; the weights are in the image, so nothing downloads.

Published by `.github/workflows/publish-library-lfm3.yml`, one image per
environment:

| Library entry | Base image | Published as |
|---|---|---|
| `openenv-echo` | `ghcr.io/huggingface/openenv-echo-env` | `ghcr.io/cathedralai/library-openenv-echo-lfm3` |
| `openenv-coding` | `ghcr.io/huggingface/openenv-coding-env` | `ghcr.io/cathedralai/library-openenv-coding-lfm3` |
| `openenv-wordle` | `ghcr.io/huggingface/openenv-textarena-env` | `ghcr.io/cathedralai/library-openenv-wordle-lfm3` |
| `openenv-openspiel` | `ghcr.io/huggingface/openenv-openspiel-env` | `ghcr.io/cathedralai/library-openenv-openspiel-lfm3` |

Bases are pinned by digest in the workflow. Pin the digest from the run
summary, never a tag.

## What runs in the sandbox

The entrypoint is `with-lfm3`. It starts:

- the model: `llama-server` on `127.0.0.1:8080`, OpenAI-compatible at
  `/v1` (`/v1/chat/completions`, `/v1/completions`, `/v1/models`), model name
  `lfm3-1.7b`. Its `/health` answers 200 once the model is loaded.
- the environment: the base image's own command (`$LIBRARY_ENV_CMD`), on
  port 8000.

Then it runs the sandbox command. With no command the environment runs in
the foreground, as in the base image. A command that starts the environment
itself (it names `uvicorn`) runs as given. Any other command, such as the
sandbox keepalive `sleep infinity`, runs after the environment starts in the
background. Logs are in `/tmp/library/lfm3.log` and `/tmp/library/env.log`.

The image sets the variables an agent reads to find its model:

```
MODEL_BASE_URL=http://127.0.0.1:8080/v1
MODEL=lfm3-1.7b
MODEL_API_KEY=local
```

The server does not check the key; OpenAI clients need a non-empty one.

`lfm3-ask` from the LFM3 room image is here too:

```sh
lfm3-ask "What is 2+2? Answer in one word."
```

`LFM3_THREADS`, `LFM3_SERVER_CTX` (default 4096) and `LFM3_REASONING`
(default `off`) change the server.

## Build

`Dockerfile` takes `BASE_IMAGE` (the environment, by digest) and `ENV_CMD`
(its command as one `sh -c` string; the workflow reads it from the base
image). The weights, `lfm3-ask`, `NOTICE` and licenses are copied from
`ghcr.io/cathedralai/room-lfm3-1.7b` by digest, so they are the bytes the LFM3
room runs. That image has `llama-cli` only, so llama.cpp is built here at the
same commit (`b11960`, `8642541b255bfb5dc39cd351a178be09013a55d6`) with the
same flags, adding `llama-server`. The build stage is Debian bookworm (glibc
2.36); the OpenEnv bases are Debian trixie (glibc 2.41) and run it unchanged.
The build fails if a library does not resolve on the base or the weights do
not match their sha256.

Each job smoke tests the published digest with network none and the keepalive
command: both servers must answer, `lfm3-ask` must say 4, and so must
`/v1/chat/completions`, and the environment must answer `/reset`.

Wordle (TextArena) downloads two NLTK packages every time it starts, so the
plain OpenEnv image does not start with network `deny_all`. Its matrix entry
sets `TEXTARENA_OFFLINE=1`: the build bakes `words` and
`averaged_perceptron_tagger_eng` into `/usr/share/nltk_data` and sets
TextArena's "already downloaded" flag. The build fails if that flag is gone.

## Visibility

New GHCR packages start private. A sealed hotel pulls with no credentials, so
an owner makes each package public, then runs the workflow by hand with the
pins to check anonymous pull.

## Adding an environment

Add a matrix entry with the Library slug and its base image by digest. The
base must be Debian based (the model libraries come from apt) and start its
server with `uvicorn` on port 8000.

## License

The environment wrapper keeps its own license (OpenEnv is BSD-3-Clause; the
game or tool inside keeps its own). LFM3 is under the LFM Open License v1.0
(`/opt/lfm3/LICENSE`, attribution in `/opt/lfm3/NOTICE`). llama.cpp is MIT
(`/opt/lfm3/licenses/llama.cpp-LICENSE`).
