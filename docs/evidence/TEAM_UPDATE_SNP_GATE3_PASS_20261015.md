# Team update — SNP staging Gate 3 PASS (sealed customer journey)

| | |
| --- | --- |
| **Date** | 2026-10-15 |
| **From** | Toby (SNP staging / Cherry host executor) |
| **To** | Technical lead · Fred (`@wallscaler`) · `ai_hpc` · `@skyrocket2026` |
| **Tracking** | [PR #1449](https://github.com/bigailabs/polariscomputer/pull/1449) · [#1452](https://github.com/bigailabs/polariscomputer/pull/1452) tip `d4d87704` |

---

## Bottom line

| Verdict | Detail |
| --- | --- |
| **Gate 3 (staging)** | **PASS** |
| **Repeatability** | **PASS** (second clean run ~22 min later) |
| **What that means** | Sealed AMD SNP customer create → run → Affine known-output exec → delete is proven on staging |
| **No longer the blocker** | Staging SNP create/exec on our own sealed guest |
| **Next focus** | Production readiness + deferred M0 cleanup/settlement (not reinventing overnight path) |

---

## Audience

| Person / seat | Role in this update |
| --- | --- |
| **Technical lead** | Decision: staging Gate 3 closed; greenlight production |
| **Fred (`@wallscaler`)** | Release/grant owner; overnight orchestration; next grant/release |
| **`ai_hpc`** | Host/capacity; keep proven image baseline; fences untouched |
| **`@skyrocket2026`** | Image / measurement-list owner; pin awareness |

---

## What was done (2026-10-14 → 2026-10-15 UTC)

### Outcome pins

| Field | Value |
| --- | --- |
| Image tip | `d4d87704` (customer SNP profile) |
| Policy | **Release 7** |
| Grant | **17** (lapsed `01:24:50Z` after closeout) |
| Host | Cherry `84.32.220.48` |
| Slot | `snp-d4d87704-g1` |
| Serving | Railway `a529c48a` (+ healthy same-context redeploys) |
| Wrapper | `e2276a63` |
| Protected fences | `:2222` / `:2224` / `:2225` untouched |

### Two clean customer runs

| | Run 1 (Gate 3) | Run 2 (repeatability) |
| --- | --- | --- |
| **Result** | **PASS** | **PASS** |
| **Wall clock** | ~00:08 UTC | ~00:30 UTC |
| **Boot / incarnation** | `3562d205…` | `30547cdb…` |
| **Guest (Toby)** | `584028` | `585445` |
| **Create** | HTTP 202 | HTTP 202 |
| **Running on** | `amd_sev_snp` (~3 s) | `amd_sev_snp` |
| **Sandbox** | `07801587-4040-4a1d-a328-2b1de1157bb3` | `d2226a8e-9f26-47cf-aa12-3b81a506ecfd` |
| **Exec** | HTTP 200, exit 0 | HTTP 200, exit 0 |
| **Stdout SHA256** | `3c380da3…5543` (exact) | `3c380da3…5543` (exact) |
| **Affine** | 19/20 known-output | same recipe |
| **DELETE** | HTTP 202; native delete verified | HTTP 202; native delete verified |
| **Native evidence** | create → running, exec → exit 0, delete → deleted | same shape |

Full stdout pin (both PASS runs):

| | |
| --- | --- |
| **stdout SHA256** | `3c380da3a13909de2da5c5f979226c83e7a423f824c74640ceb02927f1ae5543` |

### Known-good journey steps

| Step | Actor | Action | Gate |
| --- | --- | --- | --- |
| 1 | Toby | Fresh boot + complete identity post; **no** Toby `:8444` | Identity up |
| 2 | Backend | Native verify → admission (first TLS) → GET `/v1/box` → Alpine import | Box + import |
| 3 | Backend | Fill inputs → same-context Railway redeploy → healthy serving | Step 3 |
| 4a | Backend | Create HTTP 202 → sandbox running on SNP | Create |
| 4b | Backend | Exec HTTP 200, exit 0, exact stdout hash | Exec |
| 4c | Backend | Receipts + usage + DELETE 202; native delete readback | Teardown |

### Image / host fixes that unblocked create

Earlier failure: worker `POST /v1/sandboxes` → **HTTP 502** (`sandbox start failed`).

| # | Symptom | Root cause | Fix (commit / tip) |
| --- | --- | --- | --- |
| 1 | Networkd / units unreadable | umask `077` on ExtraTrees | finalize chmod (`f90e1a00` → …) |
| 2 | Finalize mode check broke in mkosi | dash no `8#` octal | `faef5556` |
| 3 | OCI import 502 | pilot-oci not world-readable | `28c226bf` |
| 4 | Create errors invisible on serial | journal not on console | diag oneshot + `ForwardToConsole=yes` (`feb11aa6`) |
| 5 | Docker refused `--storage-opt` | scratch mount had `nodev` | **`d4d87704`**: `rw,nosuid,pquota` |

### Who did what

| Who | Contribution |
| --- | --- |
| **Fred** | Build lists; release 7 / grant 17; Railway/policy/slot; exec-503 root cause (heartbeat second truncation); capacity/debt reconciliation; Gate 3 + repeat PASS |
| **Toby** | Cherry builds/boots; identity posts; guest hold/stop; diag serial; no unauthorized `:8444` |
| **Backend owner** | Admission-first journey; step 3/4 runner; evidence readbacks |

---

## What is ending / standing down

| Item | Status | Note |
| --- | --- | --- |
| Overnight Gate 3 push | **Closed** | Two clean runs; Fred stood down ~00:40 UTC |
| Grant 17 | **Ended** `01:24:50Z` | Morning/production needs a **fresh grant** |
| Create-502 firefighting (`28c226bf` / `feb11aa6`) | **Superseded** | Signed baseline is **`d4d87704` + release 7** |
| Toby overnight watch | **Ended** | Per Fred closeout; no assumed live guest now |

### Deferred by design (M0) — not a Gate 3 fail

| Item | Status |
| --- | --- |
| Independent absence / cleanup receipt (settlement) | Deferred |
| Cleanup-debt rows from earlier ambiguous creates | Operator-reconciled for capacity; not cryptographic settlement |

---

## Asks by person

| Person | Ask |
| --- | --- |
| **Technical lead** | Treat staging Gate 3 as **closed** for SNP sealed create/exec. Greenlight **production** (fresh grant + policy/checkpoint per Fred). Keep M0 absence-receipt/settlement on explicit backlog (journey PASS ≠ full settlement closed). |
| **Fred** | Confirm production next step (grant / release / host) when ready. Own any further capacity/debt or API freshness follow-ups from #1449. |
| **`ai_hpc`** | No fence/`2222`/`2224`/`2225` change from this work. For next SNP capacity: use **`d4d87704` + release 7** baseline — do not rewind to pre-`pquota` images. Preserve `docs/evidence/` + Cherry archives if forensics needed. |
| **`@skyrocket2026`** | Staging tip for this pass: **`d4d87704`** on #1452. Pins on #1449: raw `d338d357…`, roothash `206f6814…`. No change requested to Sky protected tee-box / snp-guest fences. |

---

## Pins (release 7 / `d4d87704`)

| Pin | Value |
| --- | --- |
| **source_ref** | `d4d877045915276b600bbed4730aeb73c878a08f` |
| **raw SHA256** | `d338d3576e12b5ae1bc2a209437b3b028755eec5de9718e5d6cf4edba173a2cc` |
| **roothash** | `206f6814251233ccbf70215b57eced1fa98831fbd650d2ad74508f81c6529398` |

---

## Pointers

| Resource | Link / path |
| --- | --- |
| Narrative + timestamps | [PR #1449](https://github.com/bigailabs/polariscomputer/pull/1449) (Gate 3 ~00:10 · repeat ~00:34 · close ~00:46 UTC) |
| Image source | [PR #1452](https://github.com/bigailabs/polariscomputer/pull/1452) @ `d4d87704` |
| Local evidence | `cathedral-sandbox/docs/evidence/DISCORD_FRED_*_20261014.md` / `*_20261015.md` |

---

## One-line for Slack / Discord

| | |
| --- | --- |
| **Blurb** | **SNP staging Gate 3 PASS (×2 overnight on `d4d87704` / release 7): sealed create → SNP run → Affine known-output exec → delete. Staging journey done; production + M0 settlement next.** |
| **cc** | Fred · `ai_hpc` · skyrocket · tech lead |
