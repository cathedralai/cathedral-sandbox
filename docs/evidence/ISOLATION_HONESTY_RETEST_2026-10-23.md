# Isolation honesty: claims re-tested, fixes landed — 2026-10-23

Each of the "where it is weaker" statements from the client review was re-tested against the live broker and the code, then either fixed in code or made visible in the answer and the docs. Nothing below claims more than the test showed.

## 1. Broker rooms: a missing `network` fell open, and the answer never said how isolated the room was

**Claim.** A client that omits `network` on the broker gets internet; a client that omits `sealed` lands where the guest default sends it; nothing in the answer says whether the hotel is sealed or what runtime separates rooms.

**Re-test (live, `const` guest, both rooms deleted, 204).** `BROKER_ISOLATION_BASELINE_20261023T173448Z.md`.

| Create | Hotel | `network.mode` | `runtime` | `isolation` in answer |
| --- | --- | --- | --- | --- |
| no `network`, no `sealed` | `nc-sealed` | `public` (internet) | `docker` | absent |
| no `network`, `sealed: false` | `c48` | `public` (internet) | `docker` | absent |

Confirmed on both counts. One new finding: rooms on `nc-sealed` report `runtime: "docker"`, so the earlier handoff wording "rooms isolated by gVisor only" was not what the hotel reports.

**Fix (cathedral-sandbox, branch `fix/broker-isolation-honesty`).**

- `broker/compat.go`: a client create that names no network now fails closed to `deny_all`. `internet` / `public` / allowlist still work when asked for. A live `PUT .../network` without a mode stays a 400.
- `broker/isolation.go` (new): every room answer on create, get and list, native and client routes, carries

  ```json
  "isolation": {
    "hotel_sealed": true,
    "hotel_tee": "amd_sev_snp",
    "room_runtime": "docker",
    "attested_per_room": false,
    "network_mode": "deny_all",
    "attestation_of_host": "/v1/hotels/nc-sealed/attestation"
  }
  ```

  `hotel_sealed` / `hotel_tee` come from the hotel config and label, `room_runtime` from the hotel's own room document, `attested_per_room` is always `false`.
- Tests: `TestCompatCreateWithoutNetworkIsDenyAll`, `TestRoomAnswersCarryIsolation`, `TestClientCreateMapsNetworkModes` updated. `go vet`, `gofmt`, `go test -race -short ./...` green; full `-race` suite green on re-run (one timing flake, `TestFinishedExecsKeepOutputAfterRoomDeletion`, passed 3/3 on rerun).
- Docs: `broker/README.md` (network default, isolation object), `CONST_SANDBOX_ACCESS_2026-10-21.md` (default, runtime finding, how to read `isolation`).

**Not yet live.** The thin broker on `live.cathedral.computer` still runs the pre-change build. The baseline file is the "before"; re-run the same two creates after deploy and both must show `network.mode: deny_all` and an `isolation` object.

**Still open from #313.** B7 (client path ignores hotel choice) and B16 (a fork of a `deny_all` room gets internet unless reset) are unchanged by this; `isolation.network_mode` on the fork now at least shows it.

## 2. Affine's workload is Kata / Docker-in-Docker, not hardware attestation

**Claim.** The Affine pilot and the planned fleet run on Kata (pilots) or gVisor/Docker hotels (fleet), with DinD for compose tasks; the sealed `custom.v1` catalog cannot carry 500 trials at 100 concurrent (no 1/4 SKU, 6 concurrent cap).

**Re-test.** Code and docs only; pilots `.56` / `.231` were unreachable from Eng today, so no live run. `AFFINE_SEALED_VS_UNSEALED_ANSWERS_2026-10-20.md` still describes the lane accurately. Nothing to fix in code. The public page now states the DinD point directly: a privileged DinD room is a privileged container inside its runtime; the TEE boundary, where one exists, is the hotel machine.

## 3. Reserved Workers route returns no signed receipt

**Claim.** `POST /v1/workers/run` returns the grader's result bytes; there is no signed receipt or independent host-attestation claim on that route.

**Re-test.** `polariscomputer/docs/workers/EXECUTION.md` line 9 says exactly this. Not changed in code today (Polaris, not broker). The public page now says it in one sentence instead of leaving it implicit.

## 4. Gittensor: TEE in the design, paid run not yet exercised

**Claim.** `POST /v1/challenge-runs` requires a TEE JobIntent; `GITTENSOR_BENCHMARK_ENABLED=false`, bench route 405, no paid miner run.

**Re-test.** Unchanged since `ESCAPE_DRYRUN_PASS_2026-10-22.md` (dry run green, n=25). No code change; this stays a go-live gate, not a docs gap.

## 5. The public docs never stated the sealed / unsealed boundary on one page

**Claim.** The boundary between the sealed `/v1/workers` catalog and broker rooms was split across `docs/sandboxes` and `other-products/evals`.

**Fix (cathedral-site, branch `docs/isolation-levels`).**

- New page `/docs/sandboxes/isolation/` ("Isolation levels"), second item in the Sandboxes group: a three-level table (sealed sandbox / room on a sealed hotel / room on an unsealed hotel or Standard), the `isolation` object with a `curl ... | jq .isolation` help note and a field table, the rules the broker enforces, and "What this does not prove".
- `/docs/sandboxes/` links to it from "What sealed does and does not mean"; `/docs/other-products/evals/` documents the `deny_all` default and the `isolation` object for the Harbor provider.
- Constraints kept: no partner names (test `the closed lanes come last, and the public docs name no partner`), no `amd_sev_snp` literal in docs (test `API docs publish access...`), prose vocabulary rules (test `the docs say sandbox and receipt...`), no em/en dashes. `node --test` on `docs-site`, `one-offering`, `public-homepage`: 57 pass, 0 fail. `astro build`: 53 pages, `/docs/sandboxes/isolation/` and its `.md` twin emitted. Remaining failures in the full site suite are the same download/upload harness and build-gate tests that fail on a clean `main`.

## Net

Sealed is still sealed where we claimed it. The broker now refuses to open egress by omission, tells every client in the answer whether its room is on a TEE and what runtime separates it from its neighbours, and the site states the three levels on one page a buyer reaches from "What you get". The one thing to say to CONST and Fred directly: `nc-sealed` rooms are Docker containers inside one SEV-SNP guest today, not gVisor; the answer now says so.
