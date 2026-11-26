# VM execution history for billing settlement (AB#992)

Status: spec r3 (Astra r1: 10 findings; r2: 2 BLOCKER and 6 SHOULD, all addressed below). Owner: Spock.
Consumer: the inactive VM billing worker in polariscomputer (PR 2296 stack, `ExecutionReader`
in `polaris/services/vm_credit_settlement.py`). Rates and thresholds are not touched here
(Toby, Core 26 Nov: contract defaults, frozen catalog quote).

## The question it answers

After a paid run (one VM generation) is closed, settlement needs one durable fact about it:
the time it started, or affirmative proof that it never started. A never-started run is
refunded in full; a started run is billed from its start. Unknown history stays pending and
never refunds. The consumer already enforces that: a reader answer of `None` means
`history_pending`.

## What exists today (main, 26 Nov)

- Host `room-kit/vm/vm_ctl.py`:
  - `authorization.json` holds `{generation, paid_through, closed_generation}`.
  - `stop_locked` closes a generation and writes `stop.json` (the last stop only). Its
    `was_running` flag says whether the VM was up at stop time, not whether it ever started.
  - `cmd_start` records no start time.
  - The enabled unit relaunches after a host reboot through `check-paid`, without
    `cmd_start`.
  - `cmd_delete` removes the VM directory.
- Broker `broker/vms.go`:
  - `vms.json` keeps the current record only (`Generation`, `Ran`, `StoppedAt`).
  - `cancelVMRun` treats host exit 3 `stale_authorization` as closed and invents `StoppedAt`
    from broker time.
  - The VM routes take the global operator key. There is no per-account scoping.

## Host: one history file per VM name, outside the VM directory

File `<root>/history/<name>.jsonl`, mode 0600, append-only, one JSON object per line. Every
write appends one line, then fsyncs the file and `<root>/history/`, and only then does
anything that depends on it (H2, H5). Delete never removes it.

| Line | Meaning |
|---|---|
| `{"event":"tracked_from","generation":N}` | The first line. Generations below N are `history_unknown` forever. |
| `{"event":"start","generation":G,"wall_us":W,"boot_id":B,"mono_ns":M,"synced":S}` | Written before G is launched (H2). |
| `{"event":"close","generation":G,"stopped_at":S,"wall_us":W,"boot_id":B,"mono_ns":M,"reason":R}` | The canonical close of G (H4). |

- **H1. Coverage boundary (r1 BLOCKER 1).** The first command after the upgrade, any command,
  under the VM lock, writes `tracked_from` before anything else:
  - `N = 1` for a VM created by the new code.
  - Otherwise `N = authorization.generation + 1`. The generation open or running at upgrade
    is never tracked, including its retries.
  - A missing or unparseable first line means "no coverage": every query answers
    `history_unknown`.
- **H2. Start line before launch (r1 BLOCKER 2, SHOULD 8).**
  - `cmd_start`, under the VM lock and after its existing checks, appends `start` for G
    (unless one exists) and fsyncs it before `systemctl enable` or `start`.
  - `check-paid`, the unit's launch gate on every launch including reboot relaunch, refuses
    when the current generation has no `start` line.
  - So no launch of G can happen without a durable start line. That makes "G closed, no
    start line, G >= N" a certified never-started.
  - A start line whose launch then failed bills from it. That is conservative, and launch
    failures are logged with the generation.
- **H3. Generation advancement (r1 BLOCKER 2).** `cmd_authorize` for G' > current G, when G
  is open:
  - If G has a `start` line, it refuses with `generation_open`. A run that may have executed
    must be stopped first.
  - If G has no `start` line, it first closes G as never started (H4, reason `superseded`).
    This keeps today's broker flow working, where a refused or abandoned start leaves an
    authorized, unlaunched G.
- **H4. The close line is authoritative (r1 BLOCKER 3).**
  - `stop_locked` stops the unit, then:
    - If a `close` line for G exists, it reuses its `stopped_at`.
    - Otherwise it appends `close` first and fsyncs it.
  - Only then does it write `authorization.closed_generation` and `stop.json`. Both are
    rebuilt from the close line on every retry, so Stop and history always give the same
    `stopped_at`.
  - `stopped_at` stays integer unix seconds, as today, because it is the Stop evidence.
- **H4a. Closure is recovered before every decision (r2 BLOCKER 1).**
  - `cmd_start`, `cmd_authorize`, `cancel` and `stop_locked` first recover closure under
    the VM lock: if the file has a `close` line above `authorization.closed_generation`,
    they raise it and rewrite `authorization.json` before deciding.
  - `check-paid`, which only reads, refuses to launch a generation that has a `close` line.
  - So a crash between a durable close and `authorization.json` can never let G start.
- **H5. Cancel closes G in any state (r1 BLOCKER 5, r2 SHOULD 3, 4).** New idempotent
  `vm-ctl.sh cancel <name> <G>`. Its check, fence and durable close all run under the same
  VM lock as `cmd_start` and `cmd_authorize`:
  - **G above the authorized generation:** it fences G by raising `closed_generation` to G
    and appends `close`, reason `cancelled`.
  - **G authorized with no start line:** it closes G the same way, as never started.
  - **G with a start line** (including a launch that failed after its start line): it does a
    generation-fenced stop. It stops the unit if running, then closes through `stop_locked`,
    reason `cancelled`. History then bills from the start line, which is conservative.
  - In every case it answers with the close record, and later calls return the same record.
  - The broker closes generations only through `stop` or `cancel` and never invents a time
    (B0).
- **H6. Torn lines (r1 SHOULD 8).**
  - A final line with no newline is a write that never finished. Nothing depended on it
    (H2, H4), so readers ignore it and the next writer truncates it under the lock.
  - Any other malformed line makes the whole file `history_unknown`.
- **H7. Names are not reused (r1 SHOULD 9).** `cmd_create` refuses a name that has a history
  file.
- **H8. Time (r1 SHOULD 10).**
  - Each line records the wall clock in microseconds, `boot_id`, `CLOCK_MONOTONIC`
    nanoseconds and `synced` (from `adjtimex`, the kernel's NTP sync state).
  - `history` derives `started_at` only when both lines are `synced` (r2 BLOCKER 2).
    Otherwise it answers `history_unknown`:
    - **Same boot** for start and close: `started_at = close.wall_us - (close.mono_ns -
      start.mono_ns) / 1000`. The duration is exact, and the anchor is the close line's
      microsecond wall time, not the integer `stopped_at`.
    - **Different boots** (a reboot during the run): `start.wall_us`.
  - `started_at` is never later than the close time.
- **H9. `vm-ctl.sh history <name> <G>`**, read-only, works after delete:
  - Closed G with G >= N answers `{"generation":G,"closed":true,"started_at":ISO-us|null,
    "stopped_at":S,"tracked_from":N,"close_reason":R,"history":"v2"}`.
  - Exit 3 `history_open` while G is open.
  - Exit 3 `history_unknown` when G < N, the file is corrupt, or H8 cannot bound the start.

## Broker: per-generation receipts, eager history, tombstones

Every append below is followed by fsync of the file and the state dir before the next step.

- **B0. No invented times (r2 SHOULD 5).**
  - `stopVM` and `cancelVMRun` stop using broker time for a host refusal
    (`stale_authorization` or `generation_closed`).
  - They call host `cancel` for that generation. It returns the canonical close, whether
    the close was just made or made earlier (for example an H3 `superseded` close).
- **B1. Stop receipts before anything else (r1 SHOULD 6, r2 SHOULD 6).**
  - Once the host returns a close record, the broker appends
    `{"vm","account","host","generation","stopped_at","kind"}` to `vm-runs.jsonl` and
    makes it durable.
  - Only then does it write the stopped state to `vms.json` and answer 200. A failed
    append answers 500 `state_not_saved`, and `vms.json` is unchanged.
  - Authorize and start of G+1 refuse with 409 `receipt_missing` while G is closed on
    record without a B1 receipt.
  - At broker start, a reconcile pass replays any VM whose `vms.json` shows a closed G
    without a receipt by calling host `cancel G`, which returns the same close.
- **B2. Eager history.**
  - Right after B1, the broker calls the host `history` once and appends the closed answer
    to `vm-history.jsonl`, keyed by `(vm, generation)`. It is never overwritten.
  - If that call fails, Stop still answers 200. The generation stays `pending` in
    `vm-runs.jsonl`, and the next GET or the existing reconcile pass retries it.
  - An answer whose `stopped_at` differs from the B1 receipt is refused with
    `vm_history_mismatch` and logged. After H4 this means a bug or tampering.
- **B3. Delete (r1 SHOULD 7, r2 SHOULD 7, 8).**
  - `deleteVM` first works out the outstanding set: `Generation`, `AuthorizedGeneration`
    and any unresolved start intent.
  - It closes every member through host `cancel` (B0, B1), and stores history for every
    generation with a B1 receipt (B2).
  - It refuses with 409 `history_not_stored` until every receipt has history or the host
    says `history_unknown`.
  - Then it deletes on the host and appends a tombstone `{"vm","account","host",
    "deleted_at"}` to `vm-runs.jsonl` durably. Only after that does it remove the VM from
    `vms.json`.
  - A delete interrupted at any step replays from the start: cancel and history are
    idempotent, and a host delete of a gone VM answers `existed:false`.
- **B4. IDs are not reused (r1 SHOULD 9).** `newVMID` also checks `vm-runs.jsonl` (receipts
  and tombstones).
- **B5. Route.**
  - `GET /v1/vms/{id}/runs/{G}` takes the operator key, the same trust as Stop. It is
    served from `vm-history.jsonl`, and from the host when still pending. It works for
    tombstoned VMs.
  - Answer: `{"vm","account","host","generation","started_at","stopped_at","close_reason",
    "history_id"}`, where `history_id` is `"<vm>:<G>:<host>"`.
  - Errors:
    - 404 when there is no B1 receipt for (vm, G).
    - 409 `history_open` or `history_unknown`.
    - 502 or 504 when the host is unreachable.
  - The routes have no account scoping (r1 corrected), so the reader's account check below
    is the guard.

## polariscomputer: the reader

- `execution_reader(binding, stop)` calls B5 with the existing `VmCreditBroker` operator
  client. No new credential.
- It requires `vm`, `account` and `generation` to equal the binding's `broker_vm_id`,
  `broker_account` and `generation`, and `stopped_at` to equal `stop.stopped_at`.
- It returns `VmExecutionProof(binding, stop, VmExecutionEvidence(started_at), history_id)`.
  `started_at` keeps its microseconds, so the funded-time comparison at
  `vm_credit_ledger.py:219` does not see a floored time (r1 SHOULD 10).
- 409 and 404 return `None`, which leaves it pending. Transport errors raise
  `VmBrokerError`, which the consumer reads as `history_unavailable`.

## Tests (each r1 finding has one)

- **Host:**
  - A crash after the close line and before `authorization.json`: start G, authorize and
    `check-paid` all refuse.
  - Cancel and start racing in both orders.
  - A start line, then a failed launch, then cancel G: it closes, and history bills from the
    start line.
  - Unsynced lines give `history_unknown` in both time branches.
  - Rollout with a running G: stop G, then `history` is `history_unknown`, and a retried
    start of G stays unknown.
  - Authorize G+1 over a started G is refused; over an unstarted G it closes G as never
    started.
  - Reboot relaunch without a start line is refused by `check-paid`.
  - Crash after the close line and before `stop.json`: the retry returns the same
    `stopped_at`, and history agrees.
  - Delete, then `history` still answers. Create with the same name is refused.
  - Cancel of an undelivered G fences it and is idempotent. Cancel of a started G is
    refused.
  - A torn final line is ignored and repaired. A torn middle line makes the file unknown.
  - Same-boot derivation; cross-boot with unsynced clocks is unknown.
  - Ordinary start and stop retries keep the first times.
- **Broker:**
  - A host refusal on stop or cancel stores the host's canonical close, never broker time.
  - A crash between the B1 append and `vms.json` replays at start. G+1 is refused while G
    has no receipt.
  - Delete with an authorized, unstarted G2 cancels and records G2 first.
  - An interrupted delete replays.
  - The B1 receipt is written before 200, and a failed write is 500.
  - A history fetch failure, then G+1 starts, then the G history read still matches the B1
    receipt.
  - A mismatch is refused.
  - Delete refuses until history is stored, then leaves a tombstone. A reused ID is
    refused.
  - The route serves a tombstoned VM.
- **Reader:** a binding, account or stop mismatch raises the consumer's conflict. Open or
  unknown history stays pending. Never-started refunds in full. A started run bills from
  the microsecond `started_at`. All against the 2296 settlement tests.
- **Live,** on an idle test host with no customer VMs, witnessed by SpockChaser: one started
  run, one cancelled before start, one host reboot during a run, and one delete. All four
  are read through B5.

## Risks and limits

- Generations open at rollout, and any before, stay `history_unknown`. Count them at
  rollout. They need operator settlement.
- A start line whose launch failed bills from it, which is conservative. Measure the rate
  before changing the rule.
- History is not signed separately: it relies on the operator API and the SSH forced
  command, the same trust as Stop. Signed host history is a follow-up if review wants it.

## Work packages

1. Host H1 to H9 and tests (cathedral-sandbox, room-kit/vm).
2. Broker B1 to B5, `cancelVMRun` on H5, and tests (cathedral-sandbox, broker).
3. Reader adapter and tests (polariscomputer, on the 2296 stack).
4. Install on an idle test host, live proof, witness.
