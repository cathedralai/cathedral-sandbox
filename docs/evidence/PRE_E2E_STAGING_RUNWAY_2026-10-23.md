# Pre–subnet-e2e staging runway — 2026-10-23

Goal: finish staging/code work before #1504 G1–G4. Pay stays **false**.

## 1. Land stack (cathedral-sandbox)

| PR | Result |
| --- | --- |
| **#310** | **MERGED** `dca1da39` (already live on thin-broker earlier) |
| **#311** | **MERGED** `a71cc715` |
| **#312** | **MERGED** `1363af4d` (retargeted to `main` then merged) |

These PRs harden the **broker / hotel / room-kit** tree. They do **not** change Polaris `api-staging` by themselves. Staging tip unchanged:

| Field | Value |
| --- | --- |
| `deployment_id` | `bd8272aa-c39e-40c4-a49c-a69992fa805c` |
| `deployed_sha` | `95b8061f58923ab4c1cdb89046fb347faa264606` |
| Health | `healthy` |

## 2. Re-smoke Join + IDE (+ Ditto / Reliquary labels)

**Blocked** at create: `503 snp_capacity_unavailable` / `no_verified_supply`.

| Check | Result |
| --- | --- |
| Cherry guest | Restarted; boot `e223e4ac-f885-4314-9c15-668ea16d5e8a`; `:8444` → HTTP 404 from Eng |
| Roster | POSTED (UID5 / `.46`) |
| Supply `listed_at` | Bumped |
| Discovery | Logs: `snp join discovery skipped a roster row: JoinRejected` (message not logged at INFO) |
| Identity fetch from Railway | **OK** (`fetch_identity` returns boot `e223e4ac…`) |
| Waiting offers | None after clear of ended `f2933548…` |

Earlier today IDE was **GREEN** on this same tip (`AGENT_IDE_SMOKE_RERUN_2026-10-23.md`) before the sealed offer aged out. Re-seal is required before G5 Reliquary/Ditto/IDE can re-run.

## 3. Staging G5 leftovers

| Client | Status |
| --- | --- |
| IDE | Prior GREEN on `bd8272aa`; **re-run blocked** until join supply returns |
| Ditto / Reliquary labels | Same 503 — not executed |
| Affine | Pilots dark (host) — skipped |
| Claims (broker/dice) | Covered by job-reward observe below + prior GREEN docs |

## 4. job_reward observe (pay false)

On staging process via Railway SSH:

| Flag | Value |
| --- | --- |
| `cathedral_job_reward_enabled` | `true` |
| `cathedral_job_reward_pay_enabled` | **`false`** |

| Call | Result |
| --- | --- |
| `observe_verified_receipt(verified=True, …)` | `would_score=True`, reasons `()` |
| `observe_verified_receipt(verified=False, …)` | `would_score=False`, reasons `('receipt_not_verified',)` |

**GREEN** observe-only. Pay not flipped.

## 5. #313 triage

See `ISSUE_313_TRIAGE_PRE_E2E_2026-10-23.md`.

E2e-risk (waive or fix before claiming full pass): **B53, B70, B16, B7, B42, B47/B128**. Rest can wait.

## Next before subnet e2e

1. Fix join discovery `JoinRejected` (need reject **reason** in logs or Spock/Fred policy/chip/static-guest check) until a `waiting` offer appears for boot `e223e4ac…`.
2. Re-run Join + IDE (+ ditto/reliquary labels) create→exec→delete.
3. Then call #1504 G1–G4.
