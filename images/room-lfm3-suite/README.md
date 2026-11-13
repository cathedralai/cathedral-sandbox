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
image) and live speech (`/v1/realtime`), which are not shipped or tested
here. Spoken answers are: `liquid --speak` in Audio and Omni rooms (below).

## Pins and sealed proof

All six are published from commit `3339b9f` (run 43467170286, 13 Nov
2026): `lfm3-agent --events` streaming chat events (#440, ADO 541) and the
static Go chat gateway (#478, ADO 539), on top of per-model sampling, the
loop guard and tool-call markup parsed (#392, ADO 523), `liquid --speak` one
sentence per `/tts` request with its blocking `speak` gate (#407, ADO 552),
the warm cache saved in the image (#403, #405), `liquid --json` and greedy
plus frequency penalty 0.3 for Audio (ADO 547) and `--swa-full` with answers
sampled after a greedy tool check for Omni (ADO 549, 550). Run
summaries have the commit tags. All six packages are public; anonymous pull
checked.

| Model | Pin |
|---|---|
| `lfm3-1.7b-base` | `ghcr.io/cathedralai/room-lfm3-1.7b-base@sha256:b48013ae60249c18cc756d6b449e3320ec63e5861dd0e3cb87c38be11e775e08` |
| `lfm3-vl-2b` | `ghcr.io/cathedralai/room-lfm3-vl-2b@sha256:d787ed7937cf0b1dad424bb614fd655ccd66ec635d21ac85f72d7a6f77c6583d` |
| `lfm3-audio-2b` | `ghcr.io/cathedralai/room-lfm3-audio-2b@sha256:b91ef21e68d17fbafcdc2b2eb9d195f02c00a9b5325c7711680eaf1b2d0df336` |
| `lfm3-omni-2b` | `ghcr.io/cathedralai/room-lfm3-omni-2b@sha256:4fc6e0682a2f563c5e0fb862c7a4968cdfd509a4d7bc73fee860c3592d214b41` |
| `d1-2b` | `ghcr.io/cathedralai/room-d1-2b@sha256:4aed662bc5292e6c8813fefb178a471630d6122994b0cb2e4371f2439e18895f` |
| `d1-omni-2b` | `ghcr.io/cathedralai/room-d1-omni-2b@sha256:57f9038bf8198e6a9fa52e37260a48b56ddf6b6a89c83dbf84b9b74838168cfd` |

The converted `LFM3-1.7B-Base-Q4_K_M.gguf` in that image has sha256
`d4c9ebb5aa08999083bf939042087b6379547c5729163ce556902d8c06111fd5`.

The table below is the 29 Oct proof of the `08a476a` images. One sealed room per image on prod, 29 Oct: `amd_sev_snp`, `deny_all`,
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
`sleep infinity`); with no command the server runs in the foreground. For a
chat model it also puts `lfm3-agent`'s system prompt and tools in the
server's cache once the model is loaded (`lfm3-agent --warm`, log
`/tmp/lfm3/warm.log`). The image carries that cache, saved at build by
`lfm3-prewarm` in `/opt/lfm3/cache`, and the warm-up restores it in about
15 ms when its request is the same (the request's sha256 is saved beside it).
Otherwise it reads the prompt, about 4.7 s on 2 vCPUs. Measured in a sealed
room (5 Nov 2026): ready 2.4 s after the server starts instead of 7 to 10 s. The
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

### Talk to it: `lfm3-agent`

`lfm3-ask` is one question with no memory. `lfm3-agent` is the harness for a
conversation: each call is one turn of the same conversation, so the console's
one-command-at-a-time terminal works as a chat, and with no message on a
terminal (SSH or a PTY) it is an interactive chat.

```sh
lfm3-agent "What files are in /work?"
lfm3-agent "Which of those is the largest?"              # remembers the last turn
lfm3-agent --image photo.png "What is in this picture?"  # VL, Omni
lfm3-agent "And in the background?"                      # the picture is sent again
lfm3-agent --audio clip.wav "Transcribe this."           # Audio, Omni
lfm3-agent --new "Write a haiku about the sea."          # starts over
lfm3-agent --history                                     # the conversation so far
```

`liquid` is the short name for the same harness, installed beside it. Its
words are the message, so quotes are not needed:

```sh
liquid                          # on a terminal: the chat; in the console terminal: a greeting
liquid what is in /work         # one turn of the same conversation
liquid hey, what can you do     # a leading "hey" is just part of the message
liquid --new                    # starts over
liquid --json list 5 fruits     # JSON only, held to JSON syntax by the server; no tools
liquid --speak reply.wav hello  # the answer in text, then spoken into reply.wav (Audio, Omni)
```

Quote the message when it has characters the shell reads itself, such as an
apostrophe, `?` or `*`: `liquid "what's in /work?"`. The greeting's
attachment example follows `MODEL`: `--image` in VL and Omni rooms, `--audio`
in Audio rooms.

### Chat events: `--events` (AB#541, AB#542)

`liquid --events --turn <uuid> "message"` writes the turn as chat events for
the console instead of text, and streams the model (`stream: true` to
llama-server) so words arrive as they are written. One ASCII JSON object per
line on stdout: `start`, `thinking`, `delta`, `tool_call`, `tool_result`, then
exactly one `answer` or `error`. Each line carries `version`, `turn_id` and a
`seq` from 1. Tool events show a redacted one-line summary, status, exit code,
duration and output size, never raw arguments, output, env or keys. Nothing
else goes to stdout, and stderr gets at most one line after an `error`. The
`--json`, `--speak`, `--history` and `--reset` options are refused with
`bad_request` in this mode, and without the flag nothing changes. The contract
is `AB#542` (liquid chat stream contract v1); its room-side conformance
fixtures are in `test/chat-events/` (`<name>.json` scripts a fake model,
`<name>.stdout` is the expected stdout, with `duration_ms` set to 0).

### Chat gateway: `lfm3-gateway` (AB#539)

Chat rooms (not base, not d1) also serve the chat contract Polaris agents
speak, on `127.0.0.1:8642` only: `POST /v1/chat/completions` and `GET
/health`. `lfm3-serve` starts it; `LFM3_GATEWAY=off` leaves it out. It is one
static Go binary (`gateway/`, standard library only), so the room gains no
interpreter. Each request is one turn of `lfm3-agent --events`, with the last
user message on stdin; the room keeps the conversation, as it does for the
console. The events become OpenAI `chat.completion.chunk` frames over SSE,
`event: hermes.tool.progress` for each tool start and end (the redacted
summary as `arguments`, `output` always empty), a finish chunk, then
`data: [DONE]`. A failed turn ends with `event: error` and no `[DONE]`.
Redaction stays in `lfm3-agent`, so the console and Polaris see the same safe
fields.

- `/health`: 200 once llama-server is up, 503 while it loads.
- One turn at a time; a second request gets 429. A console turn and a gateway
  turn queue on lfm3-agent's lock.
- `stream: false` returns the final `answer` text. With `stream: true`, text
  already streamed stays: a tool round's narration is kept (a new round starts
  a new paragraph), and repeats cut by the loop guard are not taken back.
- `LFM3_GATEWAY_TOKEN`, if set, is required as a Bearer token. The room runs
  with network none, so by default the gateway is open on loopback only.
- `liquid --events` still calls lfm3-agent directly; the console wire does not
  change.

`liquid` and `lfm3-agent` refuse with exit 2 and a one-line pointer in two
kinds of room:

- **d1.** It answers typed questions; use `lfm3-decide`.
- **LFM3-1.7B-Base.** It only continues text; use `lfm3-ask --raw`. Checked on
  the published GGUF through `lfm3-agent`: it called no tool for any of 8
  questions about the sandbox, answered them from nothing ("the sandbox ...
  doesn't have CPUs") and leaked a `</think>` tag.

- **Tools.** The model may call `run` (a bash command in `/work`, else
  `/workspace` or `/tmp`, 60 s timeout) and `read_file` (the start of a text
  file). Each call is printed on stderr as it runs (`$ ls -la`); the output
  the model reads is cut at 2,000 characters. At most 4 tool rounds a
  message, then the model must answer. `--no-tools` answers without them.
- **JSON.** `--json` sends a JSON schema (an object or an array) as
  `response_format`, which llama-server turns into a grammar, plus one system
  line asking for valid JSON with no comments, and no tools. The grammar fixes
  the syntax, not the count: Audio, which comments repeated list items
  (ADO 547), wrote a number in place of a comment and closed the list early
  until the line was added. A reply cut at the token cap does not parse. The
  loop guard leaves a `--json` answer that parses whole.
- **Speech.** `--speak FILE` answers in text as usual, then sends the answer
  to llama-server's `/tts` and writes the WAV to FILE: RIFF, PCM 16-bit,
  mono, 24,000 Hz, default (female) voice. Markdown marks are taken out
  first: Audio read a `## ` heading as made-up words. Each sentence is its own
  `/tts` request and the pieces are joined into one WAV with real sizes: spoken
  in one request, Omni's 138-word rap came back 71% heard and cut at 60 s,
  against 98% heard and 51 s one sentence at a time. If speech fails, FILE
  is removed, one line `liquid: no speech: <reason>` goes to stderr, and the
  text answer and exit code stand. VL and the text-only models cannot speak
  and say so on that line. Speech stops at `LFM3_SPEAK_FRAMES` 80 ms frames
  for the whole answer (default 750, 60 s). Measured in sealed 2 vCPU rooms (5 Nov 2026): one
  sentence (about 3 s of speech) took 5.5 to 6.2 s on Audio and 4.5 to 5.2 s
  on Omni, three sentences (about 9 s) 15.7 s and 11.1 s, plus 65 to 85 MB of
  memory while it runs. Audio heard every WAV back as the words sent.
- **System prompt.** A short default says what the sandbox is, when to use a
  tool and when not to, and never to claim a command it did not run.
  `--system` replaces it.
- **Memory.** The conversation is kept in `/tmp/lfm3/agent`. Older turns are
  dropped whole once the conversation passes 4,000 characters. The last
  picture or clip is sent again with later turns while its turn is kept;
  older ones stay as a note only.
- **The prompt cache.** A turn reads only what is new since the last request:
  the system prompt, the tools and the kept turns come from llama-server's
  cache. LFM3 attends over a 256-token sliding window, and with the default
  window-sized cache llama-server b11960 judged every saved state unusable,
  so each request re-read the whole prompt (`cache_n` 0 even for a request
  sent twice). `lfm3-serve` runs the server with `--swa-full`, which keeps
  those states usable, and runs `lfm3-agent --warm` once at boot so the first
  message starts from the cached system prompt and tools. Measured in a
  sealed 2 vCPU room (4 Nov 2026), reading runs at about 65 tok/s and
  generation at about 22 tok/s: a repeated 385-token prompt went from 5 s to
  0.1 s, a follow-up turn from about 7 s to 1 s, and the first turn after boot
  reads 14 tokens instead of 287. The server takes about 340 MB more memory
  (2.94 GB resident against 2.60 GB). Once old turns are dropped past 4,000
  characters the prefix changes and that turn reads the conversation again.
- **Sampling**, per model, from Liquid AI's `generation_config.json` for each
  model, with one measured exception. 512 tokens a reply.
  `LFM3_AGENT_SAMPLING` (a JSON object) replaces it.
  - VL (and any other): temperature 0.1, top_k 50, repetition penalty 1.1 (the
    LFM3-VL-2B and LFM3-1.7B cards).
  - Audio: greedy (its card config) plus Omni's frequency penalty of 0.3. The
    card settings made it call a tool instead of answering what a clip says;
    the penalty answered the clip question 3 of 3 (greedy alone 1 of 3) and
    hit the token cap less often on rhyme requests. Its JSON lists can carry
    `//` comments (ADO 547), so ask Audio for JSON with `--json`.
  - Omni: greedy (its card config) plus a frequency penalty of 0.3. Greedy
    alone looped on rhyme requests until the token cap (ADO 523): 4 of 30
    rhyme prompts locally, 1 of 30 with the penalty, and the loop guard cuts
    what is left. Sampling at temperature 0.1 also stopped loops but made
    Omni's tool choice vary (it ran `hostname -I` for the hostname in 4 of 8
    runs and made the answer up). A JSON array of 30 objects and a 31-line
    script came out identical with and without the penalty.
  - llama.cpp's DRY sampler also stopped loops, but with the repetition penalty
    it broke verbatim copies (a hostname or ID came back with its last
    character changed), so it is not used.
- **Loops.** An answer in which one clause repeats 6 times, or one 4-word run
  10 times, and the repeats fill at least 40% of it, is cut at the second
  copy, followed by one line: "(Stopped: the model kept repeating itself. ...)".
  A short refrain is left alone.
- **Tool-call markup.** A tool call the server did not parse (raw
  `<tool_call>` text, in Liquid AI's documented format or as JSON) is parsed
  and run like any call. Markup that cannot be read is never shown; it becomes
  one clean line.
- d1 rooms refuse it: use `lfm3-decide`.

`LFM3_AGENT_DIR`, `LFM3_AGENT_CWD`, `LFM3_AGENT_STEPS`,
`LFM3_AGENT_CMD_TIMEOUT`, `LFM3_AGENT_OUTPUT_CHARS`,
`LFM3_AGENT_CONTEXT_CHARS` and `LFM3_MAX_TOKENS` change those defaults.
`lfm3-selftest agent` asks for the hostname, which the model can only learn by
calling `run`. `lfm3-selftest rhyme` sends three rhyme requests that looped
under greedy decoding, with `--no-tools`, and fails if one loops twice.
`lfm3-selftest agent-audio` sends the test clip with no message (tools on; no
raw tool-call markup allowed), then with "What is said in this clip?" (it must
answer Paris). `lfm3-selftest json` asks for a JSON array of 15 objects and
fails unless it parses; `json-flag` sends the same request through
`liquid --json` and fails unless the whole answer parses. `speak` has the
model say one fixed sentence through `liquid --speak` and hear the WAV back
(ASR); 90% of the words must match both ways. The publish matrix
says which image gates on which check.

### Which model to talk to

Omni is the default chat model. Its language model is LFM3-1.7B (same 1.10 GB
Q4_K_M weights size), with Liquid AI's vision and audio encoders on top, so it
takes text, pictures and clips in one room. Checked locally on the pinned
GGUFs and llama.cpp commit (Apple M4, not a sealed host), greedy, reasoning
off:

| Check | `lfm3-omni-2b` | `lfm3-1.7b` |
|---|---|---|
| 16 short questions with a known answer | 15 | 15 |
| `lfm3-agent` tool choice (8 need the sandbox, 6 do not) | 14 of 14 | 13 of 14 |
| Tokens for six short answers | 71 | 763 (two hit the 256 cap) |

LFM3-1.7B is a reasoning model; with reasoning off it thinks out loud in the
answer ("17 * 23, number only" runs to the token cap). Omni is not a
reasoning model and answers in a few tokens. On a sealed room Omni generates
19.4 tok/s, holds 2.7 GB and pulls 1.6 GB (table above), more than the text
models. Omni in this image does not watch video (see above); it speaks
through `liquid --speak`.

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
