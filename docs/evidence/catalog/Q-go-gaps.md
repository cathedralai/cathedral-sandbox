# Q. Tests for the broker fixes reader O found unguarded (PR #312)

Artifact: broker/ in the worktree cathedral-sandbox-pr308 (fix/review-round-6,
head 6b7dd62, uncommitted). Partition: broker/ only. Nothing committed, pushed
or stashed. No live host, broker or credential touched.

Files changed
- broker/hardening_r6gaps_test.go (new): 13 tests.
- broker/hardening_r6core_test.go: TestLongExecsStarveHealthAndTakeTheHotelDown
  rewritten as TestLongExecsDoNotStarveTheSyncLoop (plus the helper
  saturateDataPool); TestConfigLoaderFailsOpenOnTypos rewritten as
  TestConfigLoaderRefusesTyposAndDuplicates; skip message of
  TestCompatExecIsForgottenAtRestart.
- broker/hardening_r6compat_test.go: TestCompatCreateDropsEnvAndShape is now
  TestCompatCreateForwardsEnvAndShape; skip message of
  TestBackgroundExecIsLostOnBrokerRestart.
- broker/hardening_r6_test.go: TestLabelsPatchRacesWithHotelSelection extended.
- broker/main.go: the create call's 5 minute literal is now
  `var hotelCreateTimeout = 5 * time.Minute` (next to hotelFailBackoff), so a
  test can shorten it. Same value, no behaviour change.

Method
- Head: `gofmt -l .` prints nothing; `go vet ./...` clean;
  `go test -race -short -count=1 ./...` ok in 24.4 s (O's baseline 20 s; the
  two pool tests add about 4 s, the other new tests under 0.5 s together).
- Base proof: `git worktree add /private/tmp/claude-501/r6go-base 22e7824`,
  the four r6 test files copied in (they compile against the base), the gaps
  file with two blocks dropped that name identifiers the base does not have
  (`ex.doneAt`, `hotelCreateTimeout`; script q-base-variant.py beside this
  file), `go test -short -count=1 -run <Name> .` per test, the race test with
  `-race`. Worktree removed at the end. Logs: Q-base-run.txt, Q-base-run2.txt,
  Q-base-race.txt.
- Hunk proof: a copy of the head broker dir with one fix hunk reverted at a
  time (script q-mutations.py, log Q-mutations.txt). Used where the base
  fails for a weaker reason, or where the fix guards a change made in the
  same PR (O9) and 22e7824 cannot show it.
- Wall times are from one `-race -short -v` run on an idle machine.

## One row per item

| O item | test | guards (plain terms) | failing assertion on 22e7824 (or on head with the hunk reverted) | head | wall |
|---|---|---|---|---|---|
| 1 (weak test; main H8, ctl pool) | TestLongExecsDoNotStarveTheSyncLoop (rewrite, hardening_r6core_test.go; runs under -short, no skip) | One guest's 68 never-ending execs hold every data connection to the hotel (Concurrency 4 + 64). The sync loop's health, quota and room list, and the attestation document the probe reads, still answer within 2 s: the hotel stays up with no error. | base: `sync behind 68 held data connections: ok=false listOK=false lastErr="Get .../room/health: context deadline exceeded\nGet .../v1/quota: ...\nGet .../v1/sandboxes: ..." after 2.00s` and `hotel document behind the held data connections: ... context deadline exceeded (measurement 0 chars)`. Hunk H8 (getJSON back on h.client): same two lines. | PASS | 0.03 s |
| 1 (second test, observed) | TestCreateWaitsBehindAnotherGuestsExecs (hardening_r6gaps_test.go) | Pins what O saw: with the sync loop keeping the hotel up, another guest's create on that hotel waits for a data connection until the hotel create timeout, answers 502 hotel_unreachable, never reaches the hotel, and the hotel is rested; once the execs end the same create is 202. Timeout shortened to 1 s through hotelCreateTimeout. | base: `precondition: hotel b went down behind the held data connections; the sync loop must keep it up` (after 2.01 s; the base has no timeout variable, so the variant drops that block). Hunk H8: same. | PASS | 4.03 s |
| 2 (O5; main H11, single hotel) | TestLostCreateAnswerOnTheOnlyHotelIsReaped | Guest with hotels ["b"] only; the hotel starts the room and the answer is lost: 502 hotel_unreachable, the hotel got exactly one DELETE before the guest's answer, the guest lists 0 rooms and quota says 0 running after the next sync. | base: `hotel b got 0 DELETE calls after the lost answer; want 1, for the orphan room` and `after the 502 the guest lists 1 rooms ([... id:b.sbx_1 ...]) and quota says 1 running; want 0`. Hunk H11 (`return last` on the no-hotel-left path): `hotel b got 0 DELETE calls ...`. | PASS | 0.01 s |
| 2 (O5; main H15, 4xx no retry) | TestLostCreateAnswerIsReapedWhenTheRetryIsRefused | Answer lost on b (the proxy strips the allowlist so b starts the room), retry on c refused with 400 invalid_network_allowlist: no further retry, and b's room is still reaped (1 DELETE, list 0). | base: `hotel b got 0 DELETE calls; want 1, for the room it started before its answer was lost` and `after the 400 the guest lists 1 rooms`. Hunk H15: `hotel b got 0 DELETE calls ...`. | PASS | 0.01 s |
| 2 (O5; main H12, 499 client gone) | TestLostCreateAnswerIsReapedWhenTheGuestGoesAway | Answer lost on b, the retry waits for a create slot on c (slots full), the guest cancels: the 499 path still reaps b's room (the proxy signals the DELETE; list 0). | base: `hotel b was not asked to delete the room it started for a guest that went away` (after the 5 s wait). Hunk H12: same. | PASS | 0.01 s |
| 3 (O9; main H19, deleteSent) | TestGuestDeleteOutlivesALateList | The sync loop holds a room list the hotel built before the guest's DELETE (the proxy parks it on a channel); when the late list lands the room stays deleting and quota counts 0 running. | Hunk H19 (`rm.deleteSent = true` removed): `room b.sbx_1 after the guest's delete and a late list that still names it: state 'r', quota running_sandboxes 1; want 'd' and 0`. On 22e7824 the test fails for a harness reason only (`delete: 404 route_not_found`, the base fake hotel has no DELETE route); the base also lacks H21, the flip-back this guard exists for, so the hunk run is the proof. | PASS | 0.01 s |
| 4 (O10; compat H11 + state H1) | TestFinishedExecResultsExpire | A finished background exec answers 200 right after it ends; with doneAt set two hours back, saveCompat's sweep drops it and the poll is 404 exec_not_found; an exec still running (held by the fake hotel) survives the sweep. | base (variant without the doneAt line, the base has no such field): `finished exec two hours after its end: 200 map[... state:exited ...]; want 404 exec_not_found`. Hunk (sweep disabled): same. | PASS | 0.01 s |
| 5 (O11; images H1) | TestSnapshotIDOnAHotelOutsideTheListIs404 | Guest limited to ["b"], a g1-labelled snapshot sits on hotel a: fork with "a.snap_x", DELETE /v1/snapshots/a.snap_x and its push are all 404 snapshot_not_found and hotel a sees no request. | base: `POST /v1/sandboxes: 409 ... snapshot_hotel_excluded`, `DELETE /v1/snapshots/a.snap_x: 200 map[deleted:true]; want 404`, `hotel a, outside g1's list, received 4 request(s)`. Hunk: `POST /v1/sandboxes: 409 ... snapshot_hotel_excluded`. | PASS | 0.00 s |
| 6 (O14; lock reads) | TestLabelsPatchRacesWithHotelSelection (extended, hardening_r6_test.go; -race) | Two PATCH loops on hotel b (labels z0/z1, drain true/false) against 100 rounds of: create by hotel_labels, create by hotels ["b"], GET /v1/broker/hotels, GET /v1/broker/stats, GET /v1/images/<id> (ensureBuilds), a fork by a default-sealed guest (placementFor), and the live view snapshot. | base with -race: FAIL, 5 data race reports: images.go:253 (placementFor) and images.go:71 (selects) vs hotels.go:239 (patchHotel labels write); hotels.go:279 and :283 (hotelDoc) vs hotels.go:236/239 (drain and labels writes). Per hunk: hotels H4 hotelDoc caught (2 reports), images H3 placementFor caught (2), images H1 selects caught (1). NOT caught: main H9 pick, H20 handleStats, H22 snapshot, images H2 noRoomReason, images H4 handleHotels, build H1 ensureBuilds. Those six readers run under b.mu, which patchHotel also holds while it writes, so the unlocked variant has no race for the detector or any test to see; the accessor there is consistency, not a fix. | PASS | 0.26 s |
| 7 (wrong reason) | TestConfigLoaderRefusesTyposAndDuplicates (rewrite of TestConfigLoaderFailsOpenOnTypos) | Seven refused files, each asserted `err != nil`: duplicate hotel id; "hotel" for "hotels"; "listen_addr"; two guests with one id; two guests with one key hash; "guest_id"; "seald". Plus the control: a valid file loads. | base: six lines `<case>: accepted; want an error` (all but the duplicate hotel id, which the base already refused). | PASS | 0.00 s |
| 8 (wrong reason; compat H7) | TestCompatCreateForwardsEnvAndShape (rename of TestCompatCreateDropsEnvAndShape) | shape {vcpus 2, memory_mib 6000, disk_gib 20} reaches the hotel as resources {vcpu 2, memory_gib 6 (rounded up), disk_gib 20}; env forwarded. | base: `resources=map[disk_gib:10 memory_gib:4 vcpu:1]` (and env nil). Hunk memory branch off: `map[disk_gib:20 memory_gib:4 vcpu:2]`; disk branch off: `map[disk_gib:10 memory_gib:6 vcpu:2]`. The cloud API's field name (disk_gib, as compat.go reads it) was not verified from the cloud API's source; the test follows the code. | PASS | 0.00 s |
| 9 (low; compat H10 sub g1, 48 h cap) | TestLifetimeRouteCapsAt48Hours | lifetime_seconds 100 h sends the hotel ttl_seconds 172800; 47 h left plus extend_by_seconds 5 h also sends 172800. | base: `ttl_seconds=3600; want the 48 h cap, 172800` (the base ignored lifetime_seconds) and `extend_by_seconds:18000: ttl_seconds=18000`. Hunk g1 (cap removed): `ttl_seconds=360000; want the 48 h cap, 172800`. | PASS | 0.00 s |
| 9 (low; compat H10 sub g2, 502) | TestExtendWithoutAnExpiryFromTheHotelIs502 | The hotel's room document has no expires_at: extend_by_seconds is 502 hotel_unreachable and no heartbeat is sent. | base: `200 , 1 heartbeat(s) sent [600]; want 502 hotel_unreachable and no heartbeat`. Hunk g2 (check disabled): `200 , 1 heartbeat(s) sent [599]`. | PASS | 0.00 s |
| 9 (low; probe H2 sub, resting) | TestProbeSkipsARestingHotel | backoffUntil in the future: the probe starts no room on b and its result says skipped. | base: `probe on a resting hotel: 1 room(s) created, result map[dind:not tested ... isolation:unproven ...]; want none and a skipped note`. Hunk: same. | PASS | 0.00 s |
| 9 (low; probe H3, saveCaps) | TestSaveCapsKeepsHotelsNotLoaded | A caps.json entry of a hotel the broker did not load ("zz") survives loadCaps then saveCaps, beside the loaded hotel's entry. | base: `caps.json after a save: hotels [b]; want zz (not loaded) kept beside b`. Hunk: same. | PASS | 0.00 s |
| 9 (low; main H5, savedUUIDs) | TestSavedUUIDIsConsumedWhenTheRoomIsListed | After a restart, the sync listing the room hands it its saved client id (GET by that id is 200) and savedUUIDs is empty. | base: `GET by the saved id 200, 1 saved id(s) still held; want 200 and 0`. Hunk: same. | PASS | 0.01 s |
| 9 (low; skips) | TestCompatExecIsForgottenAtRestart, TestBackgroundExecIsLostOnBrokerRestart | Skip messages now name the design item: "pending design: compat exec results across a broker restart" and "pending design: background execs across a broker restart". | n/a (still unconditional skips) | SKIP | 0.00 s |

## Observed, not changed

Measured by TestCreateWaitsBehindAnotherGuestsExecs (two runs, -race):
- Data pool held: 68 connections (hotel Concurrency 4 + 64, MaxConnsPerHost
  in newHotel). The sync loop, on its own pool, kept the hotel up (ok=true).
- Another guest's create on that hotel: 502 hotel_unreachable after 4.00 s
  and 4.01 s with hotelCreateTimeout shortened to 1 s. Of that: 1.00 s waiting
  for a data connection until the create timeout, then 3.00 s for the orphan
  reaper's first pass (reapOrphans, `pass(3 * time.Second)`: GET
  /v1/sandboxes?label=... on the same saturated pool), which runs before the
  guest gets its answer. The create never reached the hotel (0 new creates).
- The hotel was then resting (backoffUntil set: hotelFailBackoff, 10 s), so
  every guest's next create on it is 503 for 10 s.
- After the execs ended and the rest was cleared by hand, the same create
  answered 202: the wait was the pool, not the hotel.
- Projected with the production constant (5 min): 300 s + 3 s = 303 s to the
  502, which matches O's measurement ("after 303 s").
- The reaper's background passes (1, 2, 4, 8, 16 s apart, 10 s timeout each)
  also use the data pool, so behind held connections orphans cannot be seen
  or removed for about 31 s more.
- One-off, not kept as a test: GET /v1/hotels/b/attestation by another guest
  goes through handleHotelDoc -> doBase -> h.client (the data pool), so it
  waits too; the guest's client gave up at its own 3.00 s timeout, the
  broker's timeout there is 1 min, then 502. The ctl pool serves getJSON only
  (sync loop, join verify, the probe's attestation read).

Other observations
- The six accessor hunks listed under item 6 (pick, handleStats, snapshot,
  noRoomReason, handleHotels, ensureBuilds) read under b.mu, the lock
  patchHotel writes under. They cannot race with a PATCH and no test can fail
  when they are reverted. The three readers outside b.mu (selects,
  placementFor, hotelDoc) were the real races and are now guarded.
- TestGuestDeleteOutlivesALateList on 22e7824 fails at the DELETE itself
  (404 route_not_found: the base's fake hotel has no DELETE route, the PR
  added it), not on the deleteSent assertion; the base also predates H21.
  Its guard is proven by the H19 hunk run.
- The base variant of the gaps file hangs if a step fails before the parked
  list is released (httptest.Server.Close waits for active handlers); the
  head test releases the proxy in t.Cleanup. The first base run hit this and
  was cut at the 10 min test timeout; the second run (Q-base-run2.txt)
  covers the tests the first did not reach.
- The hotelCreateTimeout variable is the only production code change. Tests
  that set it restore it in t.Cleanup; no test in the package uses
  t.Parallel.

## Real bugs found

None. Every new and rewritten test passes on head without a code change
other than the timeout variable. The create-behind-execs wait and the hotel
document read behind execs are the pool design item O named, left for the
owner.
