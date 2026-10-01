# Sandbox conformance suite

One test suite for the sandbox API. It turns the measurable requirements a
large evaluation customer set for a sandbox provider (Affine, SN120, sandbox
API requirements of 2026-09-22) into checks with fixed thresholds, runs them
against a live API, and writes one JSON report.

The same report is used three ways:

1. **Merge gate.** Sandbox work in this repository is filed as "make check X
   pass". A pull request merges when the suite passes on that commit.
2. **Compute source admission.** A source behind cathedral.computer gets
   traffic only while it passes.
3. **Customer proof.** The report is the evidence we hand Affine for each
   acceptance step.

## Run it

```bash
pip install -e .
export CATHEDRAL_API_KEY=cat_sk_...   # a key with the sandboxes:control scope
cathedral-conformance --report report.json
```

`cathedral-conformance --list` prints every check, its tier, the spec section
it comes from, and its threshold. `--only exec.latency,files.tar` runs a
subset. `--strict` makes later-tier checks gate the result too.

Exit status is 0 when every mvp check passes, 1 when any fails, 2 for a usage
error. Everything the run creates carries the label `conformance_run=<run_id>`
and is deleted at the end, also after a crash, then swept again by label.

## Checks

| Check | Tier | Spec | Passes when |
|---|---|---|---|
| `create.first` | mvp | §3.1 | a sandbox from a public image reaches running in under 300 s |
| `create.cached` | mvp | §3.9, §3.15 | creates from that image again: p50 < 10 s, p95 < 60 s |
| `create.idempotent` | mvp | §3.12 | the same Idempotency-Key returns the same sandbox |
| `exec.latency` | mvp | §3.15 | `true` round trip p50 < 200 ms, p95 < 1 s |
| `exec.forms` | mvp | §3.2 | argv and shell string both run |
| `exec.timeout` | mvp | §3.2 | the server stops a command at its timeout, reports `timed_out`, and the sandbox lives |
| `exec.output` | mvp | §3.2 | at least 10 MiB of stdout comes back |
| `process.background` | mvp | §3.2 | a process outlives the call that started it and stops on DELETE |
| `files.roundtrip` | mvp | §3.3 | bytes, parent directories and mode survive put and get; stat agrees |
| `files.tar` | mvp | §3.3 | tar in and out keeps modes and symlinks |
| `lifecycle.extend` | mvp | §3.4 | a heartbeat moves the lifetime deadline |
| `lifecycle.labels` | mvp | §3.4 | sandboxes list by label |
| `lifecycle.delete` | mvp | §3.4 | deleting twice answers 2xx both times |
| `quota.visible` | mvp | §3.8 | quota shows limits, usage and room for sandboxes, vCPU and memory |
| `quota.minimum` | mvp | §3.8 | limits reach 500 sandboxes, 1,000 vCPU, 3,000 GiB |
| `usage.by_label` | mvp | §3.13 | usage groups by a label and carries a cost |
| `docker.nested` | mvp | §3.10, §3.17 | dockerd starts, `docker run -v` bind-mounts, 50 networks create |
| `snapshot.fork` | later | §3.5, §4 test 4 | snapshot ready in 30 s, 8 forks running in 15 s each, identical pre-fork bytes, independent writes, forks survive the parent's delete |
| `create.burst_tti` | later | [ComputeSDK Burst TTI](https://www.computesdk.com/benchmarks/sandboxes/burst-tti/) | `--burst` concurrent creates (ComputeSDK runs 100), timed to the first successful command; all succeed and median < 1 s. Reports ComputeSDK's composite score so we know our board position before we list |
| `quota.full_429` | later | §3.8 | a create past quota answers 429 with Retry-After in under 1 s |

`quota.full_429` fills the remaining quota first, so it runs only when that
takes at most `--max-fill` sandboxes (default 10) and is skipped otherwise.

## Reading a report

Every result carries its threshold, the measured values, and the sample count.
A latency from five samples is five samples, not a p95. Raise `--samples` and
`--exec-samples` before quoting a number. A check that could not run is a
`skip` with the reason; it is never counted as a pass.

## Not covered yet

- Affine's end-to-end tests (Harbor SWE-bench Verified at 100 in flight,
  Terminal-Bench 2 at 89, verifiers datagen, the 1,000-sandbox load test).
  Those run through `cathedral-harbor` and `cathedral-verifiers`; this suite is
  the per-behavior layer under them.
- Create from a Dockerfile, image prefetch, digest pinning, network allowlists,
  and runtime network policy changes.
- Isolation strength and data handling. A probe cannot prove these; they need
  attestation or a trusted operator.
- A signed receipt over the report, so CI can accept a run it did not perform.
