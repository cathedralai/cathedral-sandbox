# Plan AB#748: bound the memory the broker keeps for finished background execs

**Status:** built, 13 Nov 2026. Four plan review rounds (rounds 1 to 3 NOT SOLID, round 4 SOLID) and a code review; section 8 has the record, section 9 lists where the code differs from the plan. Author: Mr Spock (Mac session).
**Source of the finding:** outside review of the last 20 merged PRs, pasted by Fred 13 Nov. I checked it against source before writing this.
**Tags:** [V] I opened the line. [M] measured or reproduced. [R] settled by the reviewer from source. [H] inferred, not opened. [U] not verified.
**Read at:** cathedralai/cathedral-sandbox `21dc8ef`.

## 1. Problem

- The broker keeps every native background exec in a map in memory. [V] `broker/nativeexec.go:49-56`.
- Limits exist only inside `saveNativeExecs`: age 24 h, count 256 for the whole broker, and 64 MiB of result text for the saved file. [V] `:26-31, 100-118`. Running entries are never deleted but do take places in the count window, and age pruning only happens when something saves. [R]
- The 64 MiB limit only decides what is written to the file. An entry over it is skipped and stays in the map. [V] `:119-134`.
- A result holds stdout and stderr, each clipped at 16 MiB. [V] `broker/main.go:1403-1410`, applied at `nativeexec.go:196`.
- So 256 finished results of up to 32 MiB each can sit in memory for 24 h: about 8 GiB of output, from repeated commands by one signed-in guest. [R] from the constants and the exec path; this is not measured memory and no broker was crashed.
- When `StateDir` is empty, `saveNativeExecs` returns before any pruning. [V] `:92-95`.
- No per-guest cap on running native execs in this path. [R] Limits in the API in front are [U].
- Three more faults found in review, all in the same code: a restart turns an over-budget result into "not found" because it was never written [R] `:129`; a stopped exec gets no finish time and can be pruned as ancient [R] `:104, 226`; ordering is by start time, so a long command that just finished counts as oldest [R] `:110`.
- The broker serves every customer of its hotels. If it is killed for memory, all of them fail.

## 2. Goal and what customers can rely on

1. **The bound always wins.** Result output held in memory never passes 64 MiB per guest and 256 MiB for the broker (settings, not constants).
2. **Newest is evicted last.** Within a guest, older results are evicted before newer ones. A guest's newest finished result loses its output only when every guest's older results are already gone and the broker bound is still passed. One result is at most 32 MiB, so that needs nine or more guests each holding a large newest result at once.
3. **Evicted, not missing.** An evicted result keeps its entry: state, exit code, timing and receipt, with a clear reason. It does not become "not found" before the age or count rule removes it.
4. **Across a restart** only the newest 64 MiB of output survives (the file budget, unchanged). Everything else comes back evicted. So "kept in full" is a promise for a running broker, not across a restart.
5. Pruning runs with or without a state directory.

What a customer should do: poll soon after the command ends. The docs line (W2) says exactly this and no more.

Scope: native background execs only. The compat exec handlers keep their own map. [R] `broker/compat.go:100, 867-868`. W0 reads that map for the same fault and files a card if it is there.

## 3. Design

One function, `pruneLocked(now)`, called with the map lock held. It rescans the map each time: up to 256 finished entries plus the running ones (at most 32 per guest); no running counters to drift. Every loop below ends: each pass removes an entry or removes output from a result that has some, and while a payload bound is passed at least one result has output.

1. **Finish time.** Every terminal change sets `DoneAt` once: exited, timed out, lost and killed. A later write never changes it (today the worker overwrites it after a DELETE [R] `:188-190, 224-227`).
2. **Age.** Finished and older than 24 h: delete (as now).
3. **Count, per guest.** More than 64 finished entries for a guest (evicted ones included): delete that guest's oldest by finish time.
4. **Count, broker.** More than 256 finished entries: delete the oldest entry of the guest holding the most. A guest with one entry loses it only when there are more than 256 guests. Running entries are never deleted; they do not count here (today they take places in the count window and can push finished results out [R] `:108-117`).
5. **Payload, per guest.** While a guest's finished output is over 64 MiB: evict its oldest result that still has output. Its newest alone is at most 32 MiB, so this never reaches it.
6. **Payload, broker.** While the total is over 256 MiB: look only at results that still have output. Among guests that have an older (non-newest) result with output, take the guest whose older results hold the most, and evict its oldest such result. If no guest has an older result with output, evict the oldest of the newest results that has output.
7. **Evict** means: remove stdout and stderr, set `evicted: true`, `reason: "result_evicted"`, and a plain message. Keep state, exit code, timing and the receipt headers. The receipt signs the hotel's original answer (`result_sha256`, [R] `room-kit/room_receipts.py:2723`, signed at `:2095`), so the entry also carries `receipt_covers: "original_result"`: the receipt proves what ran, it does not match the shortened body.

Where it runs:
- In the finishing goroutine, the result is installed and `pruneLocked` runs in the same locked section, before any file work. Today the save lock can hold finished results back. [R] `:98, 197, 204`.
- At start, under the same lock as the insert: a guest with 32 running execs gets 429 `exec_capacity`.
- In `saveNativeExecs`, then the write. With no state directory it still prunes.

File: every kept entry is written. Newest first, output is written until the 64 MiB file budget; past it, the entry is written **as an evicted copy**. The copy is a separate value: the live entry in memory keeps its output. The budget is on output text, not on encoded file size; stated.

## 4. Work packages

- **W0.** Read the compat exec map for the same fault. Read how the API uses native exec polling in production (the comment at `nativeexec.go:19` says it stores the id and polls; cadence unknown). Ask Toby for the broker host's memory so the two numbers can be set.
- **W1.** One PR in `broker/nativeexec.go`. Budgets and caps become package variables so tests can set small values; no multi-GiB test. CI runs `go test -race -short`. [R]
  Tests in `broker/nativeexec_test.go`:
  - one guest finishing many results never holds more than its output bound; its newest is always full;
  - five guests at their bound: the broker bound holds; each guest's newest is full;
  - nine guests with one 32 MiB result each: the loop ends, the bound holds, exactly one newest result (the oldest) is evicted;
  - eight guests with one 32 MiB result each, and a ninth with an older 1 MiB result and a newer empty one (257 MiB): the loop ends and the 1 MiB result is the one evicted;
  - four guests with 64 entries each and a fifth with one: the fifth guest's entry survives the broker count rule;
  - zero-output results: the count cap deletes the oldest;
  - a long command that finishes last is the newest, not the first evicted;
  - three results finishing close together while a poll waits on the first: the newest stays full; the documented best-effort case is asserted, not hidden;
  - an evicted entry polls 200 with `evicted`, `reason`, `receipt_covers` and its receipt headers;
  - restart: three guests' single 32 MiB results; before the restart all three poll in full **after a save has run** (the save did not strip live entries); after it the newest two are full and the third is evicted, not 404;
  - old state file from before this change loads and is pruned;
  - DELETE then poll, with the worker's finish delayed: the entry is still there as killed, and its finish time and its place in the order do not change when the worker returns;
  - no state directory: pruning still runs;
  - the 33rd running exec of a guest is 429; after one finishes, a start works; two starts racing at 31 give exactly one success;
  - many results finishing at once while a save is blocked: the bound holds;
  - the existing fixture that expects 256 entries from one guest (`:209, 226`) is updated to the new per-guest cap.
- **W2.** One line in the exec docs: poll soon after a command ends; the broker keeps a bounded amount of output per customer and an older result can come back with its output evicted (and after a broker restart, more of them).

## 5. Options not taken

- **Delete over-budget entries.** A poll would say 404 for a command that ran.
- **Spill results to disk.** Larger change; the bound comes first.
- **Lower the 16 MiB clip.** Changes the customer contract.
- **Hold back a finish until the customer polls.** Lets a customer who never polls pin memory.
- **Incremental byte counters.** More state to get wrong than one scan.

## 6. Open points

- The two numbers against the broker host's real memory. [U] Needs the host figure and a baseline.
- Whether production polls soon enough that eviction is ever seen. [U] W0.

## 7. Severity

High for availability is fair on source: one guest, ordinary commands, shared process. An actual out-of-memory kill was not shown.

## 8. Review record

- Round 1, 13 Nov, second model (Astra), read-only at `21dc8ef`. Verdict: NOT SOLID. Blockers taken: (1) the per-guest and broker numbers contradicted the "no guest affects another" goal, and stripping could not satisfy a count cap, now separate count and payload rules and an honest promise; (2) a result could be stripped before its waiting poll woke, and ordering by start time was wrong, now "newest is always kept" and finish-time order; (3) a restart turned skipped entries into 404, now saved as evicted; (4) pruning outside the lock let results pile up behind a blocked save, now one locked section; (5) a stopped exec had no finish time. Notes taken: what the receipt covers, the file budget wording, the conflicting fixture, small injected budgets, native-only scope.
- Round 2, 13 Nov, same reviewer. Verdict: NOT SOLID again. Two blockers taken: (1) "newest is never evicted" cannot hold with a hard bound (nine guests with 32 MiB each is 288 MiB and the loop had no legal victim), so the bound now always wins and newest is evicted last; the broker count rule could delete a guest's only result, now it takes from the guest holding the most; (2) the promise ignored the 64 MiB file budget on restart, now stated. Notes taken: saving must not strip live entries, the finish time is set once, count wording, two citations.
- Round 3, 13 Nov, same reviewer. Verdict: NOT SOLID, one blocker: the broker payload rule could pick a guest with nothing eligible to evict and stall (eight guests at 32 MiB plus one guest with an older 1 MiB result). Taken: victims are chosen only among results that still have output. One note taken: the scan size wording.
- Round 4, 13 Nov, same reviewer. Verdict: SOLID. The reviewer tried to build a counterexample to the pruning rules and ran its own small model of them (390,625 small states plus 10,000 varied ones): every loop ends with the bounds met.
- Code review, 13 Nov, same reviewer, on the staged diff. Verdict: fix first. One blocker taken: my code ignored strings of 256 bytes or less, so the "hard" bound could be passed by a few bytes; it now counts every byte of stdout and stderr, as the plan said. Notes taken: the largest-holder choice no longer confuses "none chosen" with an empty guest id; the blocked-save test asserts every command exited with two full and six evicted; a waiting-poll test was added; test teardown now fails if a worker does not end.

## 9. As built

- **Output** is stdout and stderr, every byte, as planned. They are the only strings in a hotel exec answer and each is clipped at 16 MiB.
- **Per-guest output step.** It evicts oldest first until the guest is under its bound, the newest last. With the real numbers (32 MiB at most per result, 64 MiB per guest) the newest is never reached by this step; with other settings the bound still wins.
- **The running cap answers** 429 `exec_capacity` with `Retry-After: 5`. A start with the same Idempotency-Key can be retried: the idempotency layer does not keep a 429.
- **A waiting poll** on an older result can get the evicted answer when two newer results finish at the same moment. It is a 200 with the reason and the receipt, never an empty success. Tested.
- **W0, compat map.** The compat background execs (`broker/compat.go:100, 861-886`) keep results until their room is deleted, with no age, count or size bound, and that path does not clip output. Same class of fault, limited by room lifetime. Not changed here; card filed.
- **W2, customer docs.** The background exec route has no customer page in this repo. The line belongs with the API docs; noted on the card.
- **Not done:** the two numbers are not checked against the broker host's memory, and how production polls is not read. They are package variables today, not config keys.
