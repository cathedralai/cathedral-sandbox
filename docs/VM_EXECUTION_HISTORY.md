# VM execution history for billing settlement (AB#992)

Status: spec r1, for review before code. Owner: Spock. Consumer: the inactive VM billing
worker in polariscomputer (PR 2296 stack, `ExecutionReader` in
`polaris/services/vm_credit_settlement.py`).

## The question it answers

After a paid run (one VM generation) is stopped, settlement needs one durable fact about
that generation: the time it started, or affirmative proof that it never started. A
never-started run is refunded in full; a started run is billed from its start. Unknown
history must stay pending and never refunds (the consumer already enforces this: a reader
answer of `None` is `history_pending`).

## What exists today (main, 26 Nov)

- Host `room-kit/vm/vm_ctl.py`:
  - `authorization.json` holds `{generation, paid_through, closed_generation}`.
  - `stop_locked` closes a generation for good and writes `stop.json` with
    `{stopped_at, generation, was_running, ...}`. Only the last stop is kept.
  - `cmd_start` records no start time.
  - `was_running` says whether the VM was up at stop time, not whether it ever started.
    A VM that booted and then crashed reads `was_running: false`.
- Broker `broker/vms.go`: `vms.json` keeps the current record only (`Generation`, `Ran`,
  `StoppedAt`). There is no per-generation history and no start time.

So no component can tell "never started" from "started and died" after the fact, and no
history survives the next generation. The gap is on the host.

## Design

### 1. Host: a start record written before launch

- New file per VM: `runs.jsonl`, append-only, mode 0600, one JSON line per event, fsync'd
  file and directory before the call answers.
- `cmd_start`, under the VM's own lock (`<dir>/.lock`, as today), after the paid and generation
  checks and BEFORE `systemctl enable/start`: append `{"event":"start","generation":G,"at":T}` unless a start line
  for G already exists (an idempotent retry keeps the first T).
- `stop_locked`, after closing G: append `{"event":"close","generation":G,"at":stopped_at}`
  unless a close line for G exists.
- Why before launch: the record then over-approximates. If the start line exists, the
  generation may have run, and it is billed from T. If G is closed and no start line exists,
  the VM process was never launched for G. That makes `started_at: None` a certified
  never-started, as the consumer's `VmExecutionEvidence` requires. A start line followed
  by a failed launch bills from T. That is conservative for us and is counted (see Risks).
- New subcommand `vm-ctl.sh history <name> <generation>`, read-only, answering:
  - `{"generation":G,"closed":true,"started_at":T|null,"stopped_at":S,"history":"v1"}` when
    G is closed. `stopped_at` is the close line's time and equals `stop.json` for that
    generation.
  - Exit 3 `history_open` when G is not closed yet.
  - Exit 3 `history_unknown` when G is closed but older than the first line in
    `runs.jsonl`. This covers generations that ran before this change, which stay pending.
- `cmd_delete` moves `runs.jsonl` to `<root>/history/<name>.jsonl` before removing the VM
  directory, so a late read still works. The broker copy below is the primary store.
- A host reboot that brings an enabled VM back is the same generation. Its start line
  already exists, so nothing is appended.

### 2. Broker: relay and keep

- `GET /v1/vms/{id}/runs/{generation}`, under the same operator authentication and
  account scoping as the other VM routes. It calls the host `history` once.
- The broker appends each closed answer to `vm-history.jsonl` in its state dir, keyed by
  `(vm id, generation)`. Later reads are served from that file, so history survives host
  loss and VM delete.
- The broker also fetches history eagerly: right after each confirmed stop or cancelled run
  it calls the host `history` once. On failure it keeps going, and the next GET retries.
  `deleteVM` fetches any missing closed generation first and refuses with
  `409 history_not_stored` until it has it.
- The broker refuses to store an answer whose `stopped_at` differs from the `StoppedAt` it
  recorded for that generation (`502 vm_history_mismatch`).
- Answer: `{"vm_id","account","generation","host","started_at","stopped_at","closed":true,
  "history_id"}`.
  - `history_id` is `"<vm id>:<generation>:<host>"`. It is stable across retries and
    restarts, as `VmExecutionProof.history_id` requires.
- Errors:
  - 404 for an unknown VM or a generation that never existed (above the current one).
  - 409 `history_open` while the generation is open.
  - 409 `history_unknown` for a pre-change generation.
  - 502 or 504 when the host is unreachable.

### 3. polariscomputer: the reader

- `execution_reader(binding, stop)` calls the broker route with the operator client that
  `VmCreditBroker` already uses. No new credential.
- It checks that the answer's `vm_id`, `account` and `generation` equal the binding's
  `broker_vm_id`, `broker_account` and `generation`.
- It checks that `stopped_at` equals `stop.stopped_at`.
- It returns `VmExecutionProof(binding, stop, VmExecutionEvidence(started_at), history_id)`.
- 409 `history_open`/`history_unknown`, 404 and transport errors return `None` or raise
  `VmBrokerError`. Both leave settlement pending.
- Authentication: the source is the broker operator API (TLS plus operator bearer) relaying
  the host over its SSH forced command. That is the same trust path as Stop itself. The
  history is not signed separately in v1.

## Tests

- **Host:**
  - Start then stop gives `started_at=T`.
  - A generation closed before any start (cancelVMRun) gives `started_at: null`.
  - A retried start keeps the first T.
  - A start line with a failed launch still gives T.
  - `history` on an open generation gives `history_open`.
  - A pre-change generation gives `history_unknown`.
  - A crash between the start line and launch leaves T (conservative).
  - `runs.jsonl` survives the next generation.
- **Broker:**
  - Relay, store, then serve after the host is gone.
  - A mismatched `stopped_at` is refused.
  - Account scoping holds.
  - A stored entry is never overwritten.
- **Reader:**
  - Binding or stop mismatch raises the consumer's conflict.
  - Open or unknown history stays pending.
  - Never started refunds; started bills from T.
  - Run against the 2296 settlement tests.
- **Live:** on a test host with no customer VMs, run one generation that starts and one
  cancelled before start, then read both through the broker.

## Risks and limits

- Pre-change generations stay `history_unknown` and need operator settlement. Count them at
  rollout.
- A start line whose launch failed bills from T. Log launch failures with the generation so
  support can refund by hand. Measure the rate before changing the rule.
- No separate signature in v1. Signed host history, so the broker is not trusted for it,
  is a follow-up if Reviewbot or the auditors want it.

## Work packages

1. Host `runs.jsonl`, `history` subcommand, and tests (cathedral-sandbox).
2. Broker route, `vm-history.jsonl`, and tests (cathedral-sandbox).
3. Reader adapter and tests (polariscomputer, on the 2296 stack).
4. Test host and live proof, witnessed by SpockChaser.
