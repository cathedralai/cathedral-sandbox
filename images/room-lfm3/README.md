# Room image: LFM3-1.7B

Liquid AI LFM3-1.7B (Q4_K_M) on llama.cpp, CPU only, as a Cathedral room image.
The weights are in the image, so it runs in a sealed room (network `deny_all`)
with nothing to download. Published as `ghcr.io/cathedralai/room-lfm3-1.7b`
by `.github/workflows/publish-room-lfm3.yml`; pin the digest from the run
summary, never a tag.

## Use

```sh
lfm3-ask "What is 2+2? Answer in one word."
```

Prints the answer, then one line:

```
lfm3-timing load_ms=1203 prompt_tok_s=118.0 gen_tok_s=52.8 wall_ms=1530 threads=2 max_tokens=256 reasoning=off
```

`load_ms` is the model load inside llama-cli, `wall_ms` the whole run.
`LFM3_MAX_TOKENS` (default 256), `LFM3_REASONING=on` (LFM3 thinks before it
answers; the default `off` gives short answers), `LFM3_THREADS` and `LFM3_CTX`
change the run. `llama-cli` is on `PATH` for anything else.

## Pins

| What | Pin |
|---|---|
| llama.cpp | `b11960` (v0.8.0), commit `8642541b255bfb5dc39cd351a178be09013a55d6`; the first release with LFM3 |
| Weights | `LiquidAI/LFM3-1.7B-GGUF` revision `4b423c332fd97961416f2e8b69467758fd27370d`, `LFM3-1.7B-Q4_K_M.gguf`, sha256 `3793e1e6e2266919d6e015287221b41100175a98eddaba92e111aed3b05c93c4` |
| Base | `debian:bookworm-slim` by digest |

The build fails if a download does not match its sha256.

## CPU support

Built with `GGML_NATIVE=OFF`, `GGML_BACKEND_DL=ON` and `GGML_CPU_ALL_VARIANTS=ON`:
every x86-64 CPU variant (sse42 up to zen4) is a loadable module and ggml
picks the best one the CPU reports when it starts. One image runs on any
x86-64 host, including AMD EPYC Genoa under gVisor or in an SEV-SNP guest.
The Intel AMX variant (`sapphirerapids`) is removed from the image: on an
Intel Xeon that reports AMX inside a container it kills llama-cli with SIGILL,
and a 1.7B Q4 model does not need it.

## License

LFM3 is under the LFM Open License v1.0, which allows commercial use below
USD 10 million annual revenue. The license text is in the image at
`/opt/lfm3/LICENSE` and the attribution in `/opt/lfm3/NOTICE`. llama.cpp is MIT
(`/opt/lfm3/licenses/llama.cpp-LICENSE`). The weights are redistributed
unmodified.

## Update

Change the pins in `Dockerfile`, merge, then pin the new digest where it is
used. Never reuse a tag: the workflow refuses to overwrite `sha-<commit>`.
